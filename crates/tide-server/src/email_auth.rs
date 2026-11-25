use std::collections::hash_map::DefaultHasher;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::BufReader;
use std::net::IpAddr;
use std::sync::Arc;

use hickory_resolver::Resolver;
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RData;
use mail_auth::{
    AuthenticatedMessage, AuthenticationResults, DmarcResult, MessageAuthenticator, SpfResult,
    crypto::{RsaKey, Sha256},
    dkim::{DkimResult, DkimSigner},
    dmarc::verify::DmarcParameters,
    headers::HeaderWriter,
    spf::verify::SpfParameters,
};
use tokio::runtime::Builder;

use crate::config::DkimSettings;

pub struct Verification {
    pub header: String,
    pub spf_fail: bool,
    pub dkim_fail: bool,
    pub dmarc_fail: bool,
    pub dmarc: Option<DmarcInfo>,
}

#[derive(Debug, Clone, Default)]
pub struct DmarcInfo {
    pub domain: String,
    pub rua: Vec<String>,
    pub ruf: Vec<String>,
    pub policy: String,
    pub adkim: String,
    pub aspf: String,
    pub disposition: String,
    pub dkim: String,
    pub spf: String,
    pub header_from: String,
    pub pct: u8,
    pub sampled_out: bool,
}

pub fn verify(
    authenticator: Arc<MessageAuthenticator>,
    hostname: String,
    peer: IpAddr,
    helo: String,
    mail_from: String,
    recipients: Vec<String>,
    raw: Vec<u8>,
) -> Result<Verification, String> {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    runtime.block_on(async move {
        let resolver = Resolver::builder_tokio()
            .map_err(|error| error.to_string())?
            .build()
            .map_err(|error| error.to_string())?;
        let message =
            AuthenticatedMessage::parse(&raw).ok_or_else(|| "message parse failed".to_string())?;
        let dkim = authenticator.verify_dkim(&message).await;
        let spf_params = SpfParameters::mail_from(peer, &helo, &hostname, &mail_from);
        let spf = authenticator.verify_spf(spf_params).await;
        let mail_from_domain = mail_from
            .rsplit_once('@')
            .map(|(_, domain)| domain)
            .or_else(|| {
                message
                    .first_from_address()
                    .rsplit_once('@')
                    .map(|(_, domain)| domain)
            })
            .unwrap_or("");
        let arc = authenticator.verify_arc(&message).await;
        let dkim2 = authenticator
            .verify_dkim2(
                &message,
                mail_auth::dkim2::Envelope::new(mail_from.clone(), recipients),
            )
            .await;
        let dmarc = if mail_from_domain.is_empty() {
            None
        } else {
            Some(
                authenticator
                    .verify_dmarc(
                        DmarcParameters::new(&message, &dkim, mail_from_domain, &spf)
                            .with_dkim2_output(&dkim2),
                    )
                    .await,
            )
        };
        let mut header = AuthenticationResults::new(&hostname)
            .with_dkim_results(&dkim, message.first_from_address())
            .with_spf_result(&spf, &spf_params);
        header = header.with_arc_result(&arc, peer);
        let dkim2_label = match dkim2.result() {
            mail_auth::dkim2::output::Dkim2Result::Pass => "pass",
            mail_auth::dkim2::output::Dkim2Result::Fail(_) => "fail",
            mail_auth::dkim2::output::Dkim2Result::PermError(_) => "permerror",
            mail_auth::dkim2::output::Dkim2Result::TempError(_) => "temperror",
            mail_auth::dkim2::output::Dkim2Result::None => "none",
        };
        let mut dmarc_info = None;
        if let Some(output) = dmarc.as_ref() {
            if let Some(record) = output.record() {
                let policy_domain = output.domain();
                let header_from = message
                    .first_from_address()
                    .rsplit_once('@')
                    .map(|(_, domain)| domain.to_string())
                    .unwrap_or_else(|| mail_from_domain.to_string());
                let pct = dmarc_pct(&resolver, policy_domain).await;
                let enforce = policy_applies(&raw, pct);
                let failed = matches!(output.result(), DmarcResult::Fail(_));
                let policy = record.p.to_string();
                let disposition = match (failed, enforce) {
                    (true, true) => policy.clone(),
                    (true, false) if policy == "reject" => "quarantine".to_string(),
                    _ => "none".to_string(),
                };
                let rua = authorized_destinations(
                    &resolver,
                    policy_domain,
                    record.rua.iter().map(|uri| uri.uri().to_string()),
                )
                .await;
                let ruf = authorized_destinations(
                    &resolver,
                    policy_domain,
                    record.ruf.iter().map(|uri| uri.uri().to_string()),
                )
                .await;
                dmarc_info = Some(DmarcInfo {
                    domain: policy_domain.to_string(),
                    rua,
                    ruf,
                    policy,
                    adkim: record.adkim.to_string(),
                    aspf: record.aspf.to_string(),
                    disposition,
                    dkim: result_label(output.dkim_result()),
                    spf: result_label(output.spf_result()),
                    header_from,
                    pct,
                    sampled_out: failed && !enforce,
                });
            }
        }

        if let Some(dmarc) = dmarc.as_ref() {
            header = header.with_dmarc_result(dmarc);
        }
        let mut rendered = header.to_header();
        if dkim2_label != "none" {
            rendered.push_str(&format!("\r\nAuthentication-Results-DKIM2: {dkim2_label}"));
        }
        Ok(Verification {
            header: rendered,
            spf_fail: matches!(spf.result(), SpfResult::Fail | SpfResult::SoftFail),
            dkim_fail: !dkim
                .iter()
                .any(|output| matches!(output.result(), DkimResult::Pass)),
            dmarc_fail: dmarc_info
                .as_ref()
                .is_some_and(|info| info.disposition == "reject"),
            dmarc: dmarc_info,
        })
    })
}

pub fn sign_outbound(
    settings: &DkimSettings,
    hostname: &str,
    from: &str,
    recipients: &[String],
    raw: &[u8],
) -> Result<Vec<u8>, String> {
    let mut signed = if settings.is_enabled() {
        sign_dkim(settings, raw).unwrap_or_else(|error| {
            eprintln!("dkim signing {from}: {error}");
            raw.to_vec()
        })
    } else {
        raw.to_vec()
    };
    if settings.arc {
        match sign_arc(settings, hostname, &signed) {
            Ok(value) => signed = value,
            Err(error) => eprintln!("arc sealing {from}: {error}"),
        }
    }
    if settings.dkim2 {
        match sign_dkim2(settings, from, recipients, &signed) {
            Ok(value) => signed = value,
            Err(error) => eprintln!("dkim2 signing {from}: {error}"),
        }
    }
    Ok(signed)
}

fn signing_key(settings: &DkimSettings) -> Result<RsaKey<Sha256>, String> {
    let key_path = settings
        .private_key_path
        .as_ref()
        .ok_or_else(|| "private key is not configured".to_string())?;
    let file = File::open(key_path).map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "no private key in PEM".to_string())?;
    RsaKey::<Sha256>::from_key_der(key).map_err(|error| error.to_string())
}

fn sign_arc(settings: &DkimSettings, hostname: &str, raw: &[u8]) -> Result<Vec<u8>, String> {
    use mail_auth::arc::{ArcOutput, ArcSealer};
    use mail_auth::headers::HeaderWriter;
    let selector = if settings.arc_selector.is_empty() {
        &settings.selector
    } else {
        &settings.arc_selector
    };
    let message =
        AuthenticatedMessage::parse(raw).ok_or_else(|| "message parse failed".to_string())?;
    let results = AuthenticationResults::new(hostname);
    let sealed = ArcSealer::from_key(signing_key(settings)?)
        .domain(&settings.domain)
        .selector(selector)
        .headers([
            "From",
            "To",
            "Cc",
            "Subject",
            "Date",
            "Message-ID",
            "MIME-Version",
            "Content-Type",
            "DKIM-Signature",
        ])
        .seal(&message, &results, &ArcOutput::default())
        .map_err(|error| error.to_string())?;
    let mut out = sealed.to_header().into_bytes();
    out.extend_from_slice(raw);
    Ok(out)
}

fn sign_dkim2(
    settings: &DkimSettings,
    from: &str,
    recipients: &[String],
    raw: &[u8],
) -> Result<Vec<u8>, String> {
    use mail_auth::dkim2::{Dkim2Signer, Hop};
    let selector = if settings.dkim2_selector.is_empty() {
        &settings.selector
    } else {
        &settings.dkim2_selector
    };
    let signer = Dkim2Signer::from_key(mail_auth::crypto::DkimKey::from(signing_key(settings)?))
        .domain(&settings.domain)
        .selector(selector);
    let signed = signer
        .sign(raw, Hop::real(from, recipients), None)
        .map_err(|error| error.to_string())?;
    let mut out = signed.to_header().into_bytes();
    out.extend_from_slice(raw);
    Ok(out)
}

pub fn sign_dkim(settings: &DkimSettings, raw: &[u8]) -> Result<Vec<u8>, String> {
    let key_path = settings
        .private_key_path
        .as_ref()
        .ok_or_else(|| "DKIM private key is not configured".to_string())?;
    let file = File::open(key_path).map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "no private key in DKIM PEM".to_string())?;
    let key = RsaKey::<Sha256>::from_key_der(key).map_err(|error| error.to_string())?;
    let signature = DkimSigner::from_key(key)
        .domain(&settings.domain)
        .selector(&settings.selector)
        .headers([
            "From",
            "To",
            "Cc",
            "Subject",
            "Date",
            "Message-ID",
            "MIME-Version",
            "Content-Type",
        ])
        .sign(raw)
        .map_err(|error| error.to_string())?;
    let mut signed = signature.to_header().into_bytes();
    signed.extend_from_slice(raw);
    Ok(signed)
}

async fn txt_records(resolver: &TokioResolver, name: &str) -> Vec<String> {
    let Ok(lookup) = resolver.txt_lookup(name).await else {
        return Vec::new();
    };
    lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::TXT(value) => Some(
                value
                    .txt_data
                    .iter()
                    .map(|part| String::from_utf8_lossy(part).to_string())
                    .collect::<Vec<_>>()
                    .join(""),
            ),
            _ => None,
        })
        .collect()
}

async fn dmarc_pct(resolver: &TokioResolver, domain: &str) -> u8 {
    let name = format!("_dmarc.{domain}");
    for record in txt_records(resolver, &name).await {
        let lower = record.to_ascii_lowercase();
        if !lower.starts_with("v=dmarc1") {
            continue;
        }
        for tag in record.split(';') {
            if let Some(value) = tag.trim().strip_prefix("pct=") {
                if let Ok(pct) = value.trim().parse::<u8>() {
                    return pct.min(100);
                }
            }
        }
    }
    100
}

async fn authorized_destinations(
    resolver: &TokioResolver,
    policy_domain: &str,
    destinations: impl Iterator<Item = String>,
) -> Vec<String> {
    let mut allowed = Vec::new();
    for destination in destinations {
        if let Some((_, destination_domain)) = destination.rsplit_once('@') {
            allowed.extend(
                authorize_destination(resolver, policy_domain, &destination, destination_domain)
                    .await,
            );
        }
    }
    allowed
}

async fn authorize_destination(
    resolver: &TokioResolver,
    policy_domain: &str,
    destination: &str,
    destination_domain: &str,
) -> Vec<String> {
    if organizational_domain(policy_domain) == organizational_domain(destination_domain) {
        return vec![destination.to_string()];
    }
    let name = format!("{policy_domain}._report._dmarc.{destination_domain}");
    for record in txt_records(resolver, &name).await {
        let normalized = record.trim_start();
        if !normalized.to_ascii_lowercase().starts_with("v=dmarc1") {
            continue;
        }
        let overrides = override_destinations(normalized);
        if overrides.is_empty() {
            return vec![destination.to_string()];
        }
        if overrides.iter().all(|uri| {
            uri.rsplit_once('@')
                .is_some_and(|(_, host)| host.eq_ignore_ascii_case(destination_domain))
        }) {
            return overrides;
        }
        return Vec::new();
    }
    Vec::new()
}

fn organizational_domain(domain: &str) -> String {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    psl::domain_str(&domain).unwrap_or(&domain).to_string()
}

fn override_destinations(record: &str) -> Vec<String> {
    let mut result = Vec::new();
    for tag in record.split(';') {
        let tag = tag.trim();
        let value = tag
            .strip_prefix("rua=")
            .or_else(|| tag.strip_prefix("ruf="));
        let Some(value) = value else {
            continue;
        };
        for uri in value.split(',') {
            let uri = uri.trim();
            let Some(address) = uri.strip_prefix("mailto:") else {
                continue;
            };
            let address = address.split('!').next().unwrap_or(address).trim();
            if address.contains('@') {
                result.push(address.to_string());
            }
        }
    }
    result
}

fn policy_applies(raw: &[u8], pct: u8) -> bool {
    if pct >= 100 {
        return true;
    }
    if pct == 0 {
        return false;
    }
    let mut hasher = DefaultHasher::new();
    raw.hash(&mut hasher);
    hasher.finish() % 100 < u64::from(pct)
}

fn result_label(result: &DmarcResult) -> String {
    match result {
        DmarcResult::Pass => "pass".to_string(),
        DmarcResult::Fail(_) => "fail".to_string(),
        DmarcResult::TempError(_) => "temperror".to_string(),
        DmarcResult::PermError(_) => "permerror".to_string(),
        DmarcResult::None => "none".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DkimSettings;

    #[test]
    fn signs_message_with_dkim() {
        let settings = DkimSettings {
            domain: "mail.local".into(),
            selector: "default".into(),
            private_key_path: Some(
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/data/dkim_test.key"),
            ),
            arc: false,
            arc_selector: String::new(),
            dkim2: false,
            dkim2_selector: String::new(),
        };
        let raw = b"From: alice@mail.local\r\nTo: bob@example.com\r\nSubject: DKIM\r\nDate: Tue, 25 Nov 2025 12:00:00 +0000\r\nMessage-ID: <dkim@mail.local>\r\n\r\nHello\r\n";
        let signed = sign_dkim(&settings, raw).unwrap();
        let text = String::from_utf8_lossy(&signed);
        assert!(text.starts_with("DKIM-Signature:"));
        assert!(text.contains("d=mail.local"));
        assert!(text.ends_with("Hello\r\n"));
    }

    fn signing_settings() -> DkimSettings {
        DkimSettings {
            domain: "mail.local".into(),
            selector: "default".into(),
            private_key_path: Some(
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/data/dkim_test.key"),
            ),
            arc: true,
            arc_selector: "arc".into(),
            dkim2: true,
            dkim2_selector: "dkim2".into(),
        }
    }

    #[test]
    fn resolves_organizational_domains() {
        assert_eq!(organizational_domain("mail.example.co.uk"), "example.co.uk");
        assert_eq!(organizational_domain("example.com"), "example.com");
        assert_eq!(organizational_domain("a.b.example.com."), "example.com");
    }

    #[test]
    fn parses_external_report_overrides() {
        let record = "v=DMARC1; rua=mailto:one@reports.example,mailto:two@reports.example";
        assert_eq!(
            override_destinations(record),
            vec![
                "one@reports.example".to_string(),
                "two@reports.example".to_string()
            ]
        );
        assert!(override_destinations("v=DMARC1; p=reject").is_empty());
    }

    #[test]
    fn applies_pct_sampling() {
        assert!(policy_applies(b"message", 100));
        assert!(!policy_applies(b"message", 0));
        let sampled = (0..1000)
            .filter(|index| policy_applies(index.to_string().as_bytes(), 50))
            .count();
        assert!((400..600).contains(&sampled));
    }

    #[test]
    fn seals_message_with_arc() {
        let raw = b"From: alice@mail.local\r\nTo: bob@example.com\r\nSubject: ARC\r\nDate: Tue, 25 Nov 2025 12:00:00 +0000\r\nMessage-ID: <arc@mail.local>\r\n\r\nHello\r\n";
        let signed = sign_outbound(
            &signing_settings(),
            "mail.local",
            "alice@mail.local",
            &["bob@example.com".to_string()],
            raw,
        )
        .unwrap();
        let text = String::from_utf8_lossy(&signed);
        assert!(text.contains("ARC-Seal:"));
        assert!(text.contains("ARC-Message-Signature:"));
        assert!(text.contains("ARC-Authentication-Results:"));
        assert!(text.ends_with("Hello\r\n"));
    }

    #[test]
    fn signs_message_with_dkim2() {
        let raw = b"From: alice@mail.local\r\nTo: bob@example.com\r\nSubject: DKIM2\r\nDate: Tue, 25 Nov 2025 12:00:00 +0000\r\nMessage-ID: <dkim2@mail.local>\r\n\r\nHello\r\n";
        let signed = sign_outbound(
            &signing_settings(),
            "mail.local",
            "alice@mail.local",
            &["bob@example.com".to_string()],
            raw,
        )
        .unwrap();
        let text = String::from_utf8_lossy(&signed);
        assert!(text.contains("DKIM2-Signature:"));
        assert!(text.contains("Message-Instance:"));
        assert!(text.ends_with("Hello\r\n"));
    }
}
