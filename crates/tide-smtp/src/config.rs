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

    pub fn from_str(value: &str) -> Option<Self> {
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
    pub max_message_size: usize,
    pub max_recipients: usize,
    pub max_line_size: usize,
    pub require_auth: bool,
    pub allow_insecure_auth: bool,
    pub enable_starttls: bool,
    pub enable_smtputf8: bool,
    pub enable_8bitmime: bool,
    pub enable_pipelining: bool,
    pub auth_mechanisms: Vec<AuthMechanism>,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            hostname: "localhost".into(),
            max_message_size: 25 * 1024 * 1024,
            max_recipients: 100,
            max_line_size: 4096,
            require_auth: false,
            allow_insecure_auth: false,
            enable_starttls: true,
            enable_smtputf8: true,
            enable_8bitmime: true,
            enable_pipelining: true,
            auth_mechanisms: vec![AuthMechanism::Plain, AuthMechanism::Login],
        }
    }
}

impl SmtpConfig {
    pub fn submission(hostname: impl Into<String>) -> Self {
        Self {
            hostname: hostname.into(),
            require_auth: true,
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
