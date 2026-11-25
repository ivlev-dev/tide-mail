use std::sync::Arc;

use mail_auth::MessageAuthenticator;
use monoio_rustls::TlsAcceptor;
use tide_store::Db;

use crate::auth::Registry;
use crate::config::Config;
use crate::outbound::OutboundQueue;

pub struct App {
    pub config: Config,
    pub db: Db,
    pub registry: Arc<Registry>,
    pub tls: Option<TlsAcceptor>,
    pub outbound: Option<Arc<OutboundQueue>>,
    pub email_auth: Option<Arc<MessageAuthenticator>>,
}

impl App {
    pub fn new(
        config: Config,
        db: Db,
        registry: Arc<Registry>,
        tls: Option<TlsAcceptor>,
        outbound: Option<Arc<OutboundQueue>>,
        email_auth: Option<Arc<MessageAuthenticator>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            config,
            db,
            registry,
            tls,
            outbound,
            email_auth,
        })
    }
}
