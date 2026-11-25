use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::Resolver;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::proto::rr::RecordType;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MtaStsMode {
    Enforce,
    Testing,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Policy {
    mode: MtaStsMode,
    mx: Vec<String>,
    expires_at: i64,
}

pub struct MtaStsCache {
    enabled: bool,
    policies: RwLock<HashMap<String, Policy>>,
    cache_dir: Option<PathBuf>,
}

impl MtaStsCache {
    pub fn new(enabled: bool, cache_dir: Option<PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            enabled,
            policies: RwLock::new(HashMap::new()),
            cache_dir,
        })
    }

    pub fn check(&self, domain: &str, mx_hosts: &[String], tls: bool) -> Result<bool, String> {
        if !self.enabled {
            return Ok(false);
        }
        let policy = self.policy(domain)?;
        let Some(policy) = policy else {
            return Ok(false);
        };
        if policy.mode == MtaStsMode::None {
            return Ok(false);
        }
        if !tls {
            return Err(format!("MTA-STS policy for {domain} requires TLS"));
        }
        if policy.mode == MtaStsMode::Enforce
            && !mx_hosts.iter().any(|host| matches_mx(&policy.mx, host))
        {
            return Err(format!(
                "MTA-STS policy for {domain} does not authorize MX hosts"
            ));
        }
        Ok(policy.mode == MtaStsMode::Enforce)
    }

    fn policy(&self, domain: &str) -> Result<Option<Policy>, String> {
        let now = now_secs();
        if let Some(policy) = self.policies.read().get(domain) {
            if policy.expires_at > now {
                return Ok(Some(policy.clone()));
            }
        }
        if let Some(policy) = self.load_disk(domain) {
            if policy.expires_at > now {
                self.policies
                    .write()
                    .insert(domain.to_string(), policy.clone());
                return Ok(Some(policy));
            }
        }
        let policy = fetch_policy(domain)?;
        if let Some(policy) = &policy {
            self.policies
                .write()
                .insert(domain.to_string(), policy.clone());
            self.store_disk(domain, policy);
        }
        Ok(policy)
    }

    fn cache_path(&self, domain: &str) -> Option<PathBuf> {
        let dir = self.cache_dir.as_ref()?;
        let name = domain
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                    ch
                } else {
                    '_'
                }
            })
            .collect::<String>();
        Some(dir.join(format!("{name}.json")))
    }

    fn load_disk(&self, domain: &str) -> Option<Policy> {
        let path = self.cache_path(domain)?;
        let raw = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&raw).ok()
    }

    fn store_disk(&self, domain: &str, policy: &Policy) {
        let Some(path) = self.cache_path(domain) else {
            return;
        };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let Ok(raw) = serde_json::to_vec(policy) else {
            return;
        };
        let temp = path.with_extension("tmp");
        if std::fs::write(&temp, raw).is_ok() {
            let _ = std::fs::rename(temp, path);
        }
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn matches_mx(patterns: &[String], host: &str) -> bool {
    patterns.iter().any(|pattern| {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            host.ends_with(suffix)
        } else {
            pattern.eq_ignore_ascii_case(host)
        }
    })
}

fn fetch_policy(domain: &str) -> Result<Option<Policy>, String> {
    let txt = match lookup_txt(&format!("_mta-sts.{domain}")) {
        Ok(txt) => txt,
        Err(_) => return Ok(None),
    };
    if !txt.iter().any(|value| value.contains("v=STSv1")) {
        return Ok(None);
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        .get(format!("https://mta-sts.{domain}/.well-known/mta-sts.txt"))
        .send()
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("MTA-STS HTTP {}", response.status()));
    }
    let body = response.text().map_err(|error| error.to_string())?;
    let mut mode = MtaStsMode::None;
    let mut mx = Vec::new();
    let mut max_age = 3600u64;
    for line in body.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("mode:") {
            mode = match value.trim() {
                "enforce" => MtaStsMode::Enforce,
                "testing" => MtaStsMode::Testing,
                _ => MtaStsMode::None,
            };
        } else if let Some(value) = line.strip_prefix("mx:") {
            mx.push(value.trim().trim_end_matches('.').to_ascii_lowercase());
        } else if let Some(value) = line.strip_prefix("max_age:") {
            max_age = value.trim().parse().unwrap_or(3600).max(60);
        }
    }
    Ok(Some(Policy {
        mode,
        mx,
        expires_at: now_secs() + max_age.min(2_592_000) as i64,
    }))
}

fn lookup_txt(name: &str) -> Result<Vec<String>, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let resolver = Resolver::builder_tokio()
        .map_err(|error| error.to_string())?
        .build()
        .map_err(|error| error.to_string())?;
    let lookup = runtime
        .block_on(resolver.txt_lookup(name))
        .map_err(|error| error.to_string())?;
    Ok(lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::TXT(txt) => Some(txt.to_string()),
            _ => None,
        })
        .collect())
}

#[derive(Debug, Clone)]
pub struct DaneRecord {
    pub usage: u8,
    pub selector: u8,
    pub matching: u8,
    pub data: Vec<u8>,
}

pub fn lookup_dane(host: &str) -> Result<Vec<DaneRecord>, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let resolver = Resolver::builder_tokio()
        .map_err(|error| error.to_string())?
        .build()
        .map_err(|error| error.to_string())?;
    let lookup = runtime
        .block_on(resolver.lookup(host, RecordType::TLSA))
        .map_err(|error| error.to_string())?;
    Ok(lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::TLSA(record) => Some(DaneRecord {
                usage: record.cert_usage.into(),
                selector: record.selector.into(),
                matching: record.matching.into(),
                data: record.cert_data.to_vec(),
            }),
            _ => None,
        })
        .collect())
}

#[cfg(test)]
pub fn dane_matches(records: &[DaneRecord], certificate: &[u8]) -> bool {
    dane_chain_matches(records, &[certificate])
}

#[derive(Debug, Default)]
struct DaneMatch {
    end_entity: bool,
    authorities: Vec<Vec<u8>>,
}

fn dane_match(records: &[DaneRecord], certificates: &[&[u8]]) -> Option<DaneMatch> {
    use sha2::{Digest, Sha256, Sha512};
    use x509_parser::parse_x509_certificate;
    let mut matched = DaneMatch::default();
    for record in records {
        if !matches!(record.usage, 2 | 3) {
            continue;
        }
        let candidates: &[&[u8]] = if record.usage == 3 {
            &certificates[..certificates.len().min(1)]
        } else {
            certificates
        };
        for certificate in candidates {
            let Ok((_, parsed)) = parse_x509_certificate(certificate) else {
                continue;
            };
            let material = match record.selector {
                0 => *certificate,
                1 => parsed.tbs_certificate.subject_pki.raw,
                _ => continue,
            };
            let matches = match record.matching {
                0 => material == record.data.as_slice(),
                1 => Sha256::digest(material).as_slice() == record.data.as_slice(),
                2 => Sha512::digest(material).as_slice() == record.data.as_slice(),
                _ => false,
            };
            if !matches {
                continue;
            }
            if record.usage == 3 {
                matched.end_entity = true;
            } else {
                matched.authorities.push(certificate.to_vec());
            }
        }
    }
    if matched.end_entity || !matched.authorities.is_empty() {
        Some(matched)
    } else {
        None
    }
}

#[cfg(test)]
pub fn dane_chain_matches(records: &[DaneRecord], certificates: &[&[u8]]) -> bool {
    dane_match(records, certificates).is_some()
}

#[allow(dead_code)]
pub fn tls_rpt_policy(domain: &str) -> Option<String> {
    let txt = lookup_txt(&format!("_smtp._tls.{domain}")).ok()?;
    txt.into_iter().find_map(|value| {
        if !value.contains("v=TLSRPTv1") {
            return None;
        }
        value
            .split(';')
            .find_map(|part| part.trim().strip_prefix("rua=").map(str::to_string))
    })
}

#[derive(Debug)]
struct DaneVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    records: Vec<DaneRecord>,
}

impl rustls::client::danger::ServerCertVerifier for DaneVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let mut chain = vec![end_entity.as_ref()];
        chain.extend(_intermediates.iter().map(|cert| cert.as_ref()));
        let Some(matched) = dane_match(&self.records, &chain) else {
            return Err(rustls::Error::General("DANE TLSA mismatch".into()));
        };
        if matched.end_entity || matched.authorities.is_empty() {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }
        let mut roots = rustls::RootCertStore::empty();
        for authority in matched.authorities {
            roots
                .add(rustls::pki_types::CertificateDer::from(authority))
                .map_err(|error| rustls::Error::General(error.to_string()))?;
        }
        let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|error| rustls::Error::General(error.to_string()))?;
        verifier.verify_server_cert(
            end_entity,
            _intermediates,
            _server_name,
            _ocsp_response,
            _now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

pub fn client_config(records: &[DaneRecord]) -> Result<rustls::ClientConfig, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if records.is_empty() {
        return Ok(rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth());
    }
    let inner = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|error| error.to_string())?;
    Ok(rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DaneVerifier {
            inner,
            records: records.to_vec(),
        }))
        .with_no_client_auth())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256, Sha512};

    #[test]
    fn matches_wildcard_mx() {
        assert!(matches_mx(&["mx.example.com".into()], "MX.EXAMPLE.COM"));
        assert!(matches_mx(&["*.example.com".into()], "mx.example.com"));
        assert!(!matches_mx(&["mx.example.com".into()], "evil.example.com"));
    }

    #[test]
    fn persists_mta_sts_policy() {
        let dir = tempfile::tempdir().unwrap();
        let cache = MtaStsCache::new(true, Some(dir.path().to_path_buf()));
        let policy = Policy {
            mode: MtaStsMode::Enforce,
            mx: vec!["mx.example.com".into()],
            expires_at: now_secs() + 60,
        };
        cache.store_disk("example.com", &policy);
        let loaded = cache.load_disk("example.com").unwrap();
        assert_eq!(loaded.mode, MtaStsMode::Enforce);
        assert_eq!(loaded.mx, vec!["mx.example.com".to_string()]);
        assert!(loaded.expires_at > now_secs());
    }

    #[test]
    fn checks_dane_sha256_certificate() {
        let cert = rcgen::generate_simple_self_signed(vec!["mail.example.com".into()]).unwrap();
        let der = cert.cert.der().to_vec();
        let digest = Sha256::digest(&der).to_vec();
        let records = vec![DaneRecord {
            usage: 3,
            selector: 0,
            matching: 1,
            data: digest,
        }];
        assert!(dane_matches(&records, &der));
        assert!(!dane_matches(
            &[DaneRecord {
                usage: 3,
                selector: 0,
                matching: 1,
                data: vec![0; 32],
            }],
            &der
        ));
    }

    #[test]
    fn checks_dane_sha512_and_ta() {
        let cert = rcgen::generate_simple_self_signed(vec!["mail.example.com".into()]).unwrap();
        let der = cert.cert.der().to_vec();
        let digest = Sha512::digest(&der).to_vec();
        let records = vec![DaneRecord {
            usage: 2,
            selector: 0,
            matching: 2,
            data: digest,
        }];
        assert!(dane_matches(&records, &der));
    }
}
