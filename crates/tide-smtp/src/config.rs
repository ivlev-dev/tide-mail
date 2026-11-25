#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMechanism {
    Plain,
    Login,
}

impl AuthMechanism {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "PLAIN",
            Self::Login => "LOGIN",
        }
    }

    pub fn parse_mechanism(value: &str) -> Option<Self> {
        match value.to_ascii_uppercase().as_str() {
            "PLAIN" => Some(Self::Plain),
            "LOGIN" => Some(Self::Login),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub hostname: String,
    pub lmtp: bool,
    pub max_message_size: usize,
    pub max_recipients: usize,
    pub max_line_size: usize,
    pub require_auth: bool,
    pub allow_insecure_auth: bool,
    pub enable_starttls: bool,
    pub enable_smtputf8: bool,
    pub enable_8bitmime: bool,
    pub enable_pipelining: bool,
    pub enable_chunking: bool,
    pub enable_binarymime: bool,
    pub enable_dsn: bool,
    pub enable_require_tls: bool,
    pub enable_future_release: bool,
    pub max_future_release_secs: u64,
    pub enable_deliver_by: bool,
    pub enable_burl: bool,
    pub enable_burl_imap: bool,
    pub max_hops: usize,
    pub auth_mechanisms: Vec<AuthMechanism>,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            hostname: "localhost".into(),
            lmtp: false,
            max_message_size: 25 * 1024 * 1024,
            max_recipients: 100,
            max_line_size: 4096,
            require_auth: false,
            allow_insecure_auth: false,
            enable_starttls: true,
            enable_smtputf8: true,
            enable_8bitmime: true,
            enable_pipelining: true,
            enable_chunking: true,
            enable_binarymime: true,
            enable_dsn: true,
            enable_require_tls: true,
            enable_future_release: false,
            max_future_release_secs: 2_592_000,
            enable_deliver_by: true,
            enable_burl: false,
            enable_burl_imap: false,
            max_hops: 50,
            auth_mechanisms: vec![AuthMechanism::Plain, AuthMechanism::Login],
        }
    }
}

impl SmtpConfig {
    pub fn submission(hostname: impl Into<String>) -> Self {
        Self {
            hostname: hostname.into(),
            require_auth: true,
            enable_future_release: true,
            enable_burl: true,
            ..Self::default()
        }
    }

    pub fn auth_allowed(&self, tls_active: bool) -> bool {
        tls_active || self.allow_insecure_auth
    }

    pub fn supports(&self, mechanism: AuthMechanism) -> bool {
        self.auth_mechanisms.contains(&mechanism)
    }
}
