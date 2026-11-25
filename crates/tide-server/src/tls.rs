use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use monoio_rustls::TlsAcceptor;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::config::TlsSettings;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("ошибка TLS: {0}")]
    Io(#[from] std::io::Error),
    #[error("ошибка сертификата: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("ошибка генерации сертификата: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("в PEM нет приватного ключа")]
    MissingKey,
}

pub fn build_acceptor(
    settings: &TlsSettings,
    hostname: &str,
) -> Result<Option<TlsAcceptor>, TlsError> {
    let (certificates, key) = match (&settings.cert_path, &settings.key_path) {
        (Some(cert_path), Some(key_path)) => {
            let cert_file = File::open(cert_path)?;
            let mut cert_reader = BufReader::new(cert_file);
            let certificates =
                rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
            let key_file = File::open(key_path)?;
            let mut key_reader = BufReader::new(key_file);
            let key = rustls_pemfile::private_key(&mut key_reader)?.ok_or(TlsError::MissingKey)?;
            (certificates, key)
        }
        _ if settings.self_signed => {
            let CertifiedKey { cert, signing_key } =
                generate_simple_self_signed(vec![hostname.to_string()])?;
            let certificate: CertificateDer<'static> = cert.der().clone();
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
            (vec![certificate], key)
        }
        _ => return Ok(None),
    };
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec(), b"tide-sync/1".to_vec()];
    Ok(Some(TlsAcceptor::from(Arc::new(config))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_self_signed_acceptor() {
        let settings = TlsSettings {
            self_signed: true,
            ..TlsSettings::default()
        };
        let acceptor = build_acceptor(&settings, "localhost").unwrap();
        assert!(acceptor.is_some());
    }

    #[test]
    fn disabled_tls_returns_none() {
        let acceptor = build_acceptor(&TlsSettings::default(), "localhost").unwrap();
        assert!(acceptor.is_none());
    }
}
