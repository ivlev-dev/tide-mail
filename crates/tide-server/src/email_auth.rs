use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::sync::Arc;

use mail_auth::{
    AuthenticatedMessage, AuthenticationResults, DmarcResult, MessageAuthenticator, SpfResult,
    crypto::{RsaKey, Sha256},
    dkim::DkimSigner,
    dmarc::verify::DmarcParameters,
    headers::HeaderWriter,
    spf::verify::SpfParameters,
};
use tokio::runtime::Builder;

use crate::config::DkimSettings;

pub struct Verification {
    pub header: String,
    pub spf_fail: bool,
    pub dmarc_fail: bool,
}

pub fn verify(
    authenticator: Arc<MessageAuthenticator>,
    hostname: String,
    peer: IpAddr,
    helo: String,
    mail_from: String,
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
        let dmarc = if mail_from_domain.is_empty() {
            None
        } else {
            Some(
                authenticator
                    .verify_dmarc(DmarcParameters::new(
                        &message,
                        &dkim,
                        mail_from_domain,
                        &spf,
                    ))
                    .await,
            )
        };
        let mut header = AuthenticationResults::new(&hostname)
            .with_dkim_results(&dkim, message.first_from_address())
            .with_spf_result(&spf, &spf_params);
        if let Some(dmarc) = dmarc.as_ref() {
            header = header.with_dmarc_result(dmarc);
        }
        Ok(Verification {
            header: header.to_header(),
            spf_fail: matches!(spf.result(), SpfResult::Fail | SpfResult::SoftFail),
            dmarc_fail: dmarc
                .as_ref()
                .map(|output| {
                    matches!(output.result(), DmarcResult::Fail(_))
                        && matches!(output.policy(), mail_auth::dmarc::Policy::Reject)
                })
                .unwrap_or(false),
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
