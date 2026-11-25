use std::sync::Arc;

use mail_auth::MessageAuthenticator;
use monoio_rustls::TlsAcceptor;
use tide_spam::SpamEngine;
use tide_store::Db;

use crate::auth::Registry;
use crate::config::Config;
use crate::outbound::OutboundQueue;
use crate::reporting::Reports;
use crate::scan_queue::ScanQueue;
use crate::virus_scan::VirusScanner;

pub struct App {
    pub config: Config,
    pub db: Db,
    pub registry: Arc<Registry>,
    pub tls: Option<TlsAcceptor>,
    pub outbound: Option<Arc<OutboundQueue>>,
    pub email_auth: Option<Arc<MessageAuthenticator>>,
    pub spam: Option<Arc<SpamEngine>>,
    pub antivirus: Option<Arc<VirusScanner>>,
    pub scan_queue: Option<Arc<ScanQueue>>,
    pub reports: Option<Arc<Reports>>,
}

impl App {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Config,
        db: Db,
        registry: Arc<Registry>,
        tls: Option<TlsAcceptor>,
        outbound: Option<Arc<OutboundQueue>>,
        email_auth: Option<Arc<MessageAuthenticator>>,
        spam: Option<Arc<SpamEngine>>,
        antivirus: Option<Arc<VirusScanner>>,
        scan_queue: Option<Arc<ScanQueue>>,
        reports: Option<Arc<Reports>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            config,
            db,
            registry,
            tls,
            outbound,
            email_auth,
            spam,
            antivirus,
            scan_queue,
            reports,
        })
    }
}
