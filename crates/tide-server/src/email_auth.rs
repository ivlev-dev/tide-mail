use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::sync::Arc;

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
        let dmarc_info = dmarc.as_ref().and_then(|output| {
            let record = output.record()?;
            let header_from = message
                .first_from_address()
                .rsplit_once('@')
                .map(|(_, domain)| domain.to_string())
                .unwrap_or_else(|| mail_from_domain.to_string());
            let disposition = match output.result() {
                DmarcResult::Pass
                | DmarcResult::None
                | DmarcResult::TempError(_)
                | DmarcResult::PermError(_) => "none".to_string(),
                DmarcResult::Fail(_) => record.p.to_string(),
            };
            Some(DmarcInfo {
                domain: output.domain().to_string(),
                rua: record.rua.iter().map(|uri| uri.uri().to_string()).collect(),
                ruf: record.ruf.iter().map(|uri| uri.uri().to_string()).collect(),
                policy: record.p.to_string(),
                adkim: record.adkim.to_string(),
                aspf: record.aspf.to_string(),
                disposition,
                dkim: result_label(output.dkim_result()),
                spf: result_label(output.spf_result()),
                header_from,
            })
        });
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
            dmarc_fail: dmarc
                .as_ref()
                .map(|output| {
                    matches!(output.result(), DmarcResult::Fail(_))
                        && matches!(output.policy(), mail_auth::dmarc::Policy::Reject)
                })
                .unwrap_or(false),
            dmarc: dmarc_info,
        })
    })
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
        };
        let raw = b"From: alice@mail.local\r\nTo: bob@example.com\r\nSubject: DKIM\r\nDate: Tue, 25 Nov 2025 12:00:00 +0000\r\nMessage-ID: <dkim@mail.local>\r\n\r\nHello\r\n";
        let signed = sign_dkim(&settings, raw).unwrap();
        let text = String::from_utf8_lossy(&signed);
        assert!(text.starts_with("DKIM-Signature:"));
        assert!(text.contains("d=mail.local"));
        assert!(text.ends_with("Hello\r\n"));
    }
}
