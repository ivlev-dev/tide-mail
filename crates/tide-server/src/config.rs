use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerSettings,
    #[serde(default)]
    pub tls: TlsSettings,
    #[serde(default)]
    pub accounts: Vec<AccountConfig>,
    #[serde(default)]
    pub email_auth: EmailAuthSettings,
    #[serde(default)]
    pub dkim: DkimSettings,
    #[serde(default)]
    pub spam: SpamSettings,
    #[serde(default)]
    pub antivirus: AntivirusSettings,
    #[serde(default)]
    pub blob: BlobSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    pub hostname: String,
    pub data_path: PathBuf,
    #[serde(default)]
    pub blob_dir: Option<PathBuf>,
    pub data_lanes: u16,
    pub lane_capacity_mb: u64,
    pub workers: usize,
    pub http_addr: String,
    #[serde(default)]
    pub http_tls: bool,
    pub smtp_addr: Option<String>,
    #[serde(default)]
    pub smtps_addr: Option<String>,
    #[serde(default)]
    pub lmtp_addr: Option<String>,
    #[serde(default)]
    pub report_dir: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub dmarc_reports: bool,
    #[serde(default = "default_true")]
    pub tls_rpt: bool,
    pub submission_addr: Option<String>,
    pub sync_addr: Option<String>,
    pub token_ttl_hours: u64,
    pub outbound_enabled: bool,
    #[serde(default = "default_true")]
    pub outbound_tls: bool,
    #[serde(default)]
    pub outbound_dir: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub dsn_enabled: bool,
    #[serde(default = "default_true")]
    pub mta_sts: bool,
    #[serde(default)]
    pub dane: bool,
    #[serde(default = "default_snapshot_interval")]
    pub snapshot_interval_secs: u64,
    #[serde(default)]
    pub admin_token: Option<String>,
    #[serde(default)]
    pub backup_dir: Option<PathBuf>,
    #[serde(default)]
    pub standby: bool,
    #[serde(default = "default_standby_retry")]
    pub standby_retry_secs: u64,
    #[serde(default = "default_blob_gc_grace")]
    pub blob_gc_grace_secs: u64,
}

fn default_true() -> bool {
    true
}

fn default_standby_retry() -> u64 {
    2
}

fn default_blob_gc_grace() -> u64 {
    3600
}

fn default_snapshot_interval() -> u64 {
    300
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            hostname: "mail.local".into(),
            data_path: PathBuf::from("./data/mail.tide"),
            blob_dir: None,
            data_lanes: 8,
            lane_capacity_mb: 512,
            workers: std::thread::available_parallelism()
                .map(|value| value.get().min(8))
                .unwrap_or(2),
            http_addr: "127.0.0.1:8080".into(),
            http_tls: false,
            smtp_addr: Some("127.0.0.1:2525".into()),
            smtps_addr: None,
            lmtp_addr: None,
            report_dir: None,
            dmarc_reports: true,
            tls_rpt: true,
            submission_addr: Some("127.0.0.1:5870".into()),
            sync_addr: Some("127.0.0.1:9093".into()),
            token_ttl_hours: 24 * 7,
            outbound_enabled: false,
            outbound_tls: true,
            outbound_dir: None,
            dsn_enabled: true,
            mta_sts: true,
            dane: false,
            snapshot_interval_secs: 300,
            admin_token: None,
            backup_dir: None,
            standby: false,
            standby_retry_secs: default_standby_retry(),
            blob_gc_grace_secs: default_blob_gc_grace(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmailAuthSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub reject_spf_fail: bool,
    #[serde(default)]
    pub reject_dmarc_fail: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DkimSettings {
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub selector: String,
    #[serde(default)]
    pub private_key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpamSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_spam_threshold")]
    pub threshold: f32,
    #[serde(default = "default_reject_threshold")]
    pub reject_threshold: f32,
    #[serde(default)]
    pub dnsbl_zones: Vec<String>,
    #[serde(default)]
    pub external_command: Option<String>,
}

fn default_spam_threshold() -> f32 {
    5.0
}

fn default_reject_threshold() -> f32 {
    15.0
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AntivirusSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub async_scan: bool,
    #[serde(default)]
    pub clamav_addr: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default = "default_quarantine_folder")]
    pub quarantine_folder: String,
    #[serde(default = "default_infected_folder")]
    pub infected_folder: String,
}

fn default_quarantine_folder() -> String {
    "Quarantine".into()
}

fn default_infected_folder() -> String {
    "Virus".into()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlobSettings {
    #[serde(default)]
    pub backend: String,
    #[serde(default)]
    pub bucket: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub access_key_id: Option<String>,
    #[serde(default)]
    pub secret_access_key: Option<String>,
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub allow_http: bool,
}

impl Default for SpamSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_spam_threshold(),
            reject_threshold: default_reject_threshold(),
            dnsbl_zones: Vec::new(),
            external_command: None,
        }
    }
}

impl DkimSettings {
    pub fn is_enabled(&self) -> bool {
        !self.domain.is_empty() && !self.selector.is_empty() && self.private_key_path.is_some()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsSettings {
    #[serde(default)]
    pub cert_path: Option<PathBuf>,
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    #[serde(default)]
    pub self_signed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountConfig {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub name: String,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)?;
        let mut config: Self = toml::from_str(&text)?;
        config.normalize();
        config.validate()?;
        Ok(config)
    }

    fn normalize(&mut self) {
        if self.server.smtp_addr.as_deref() == Some("") {
            self.server.smtp_addr = None;
        }
        if self.server.lmtp_addr.as_deref() == Some("") {
            self.server.lmtp_addr = None;
        }
        if self.server.smtps_addr.as_deref() == Some("") {
            self.server.smtps_addr = None;
        }
        if self.server.submission_addr.as_deref() == Some("") {
            self.server.submission_addr = None;
        }
        if self.server.sync_addr.as_deref() == Some("") {
            self.server.sync_addr = None;
        }
    }

    pub fn load_or_create(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        if !path.exists() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, SAMPLE_CONFIG)?;
            return Err(ConfigError::Created(path.display().to_string()));
        }
        Self::load(path)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.hostname.trim().is_empty() {
            return Err(ConfigError::Invalid("hostname is empty".into()));
        }
        if self.server.data_lanes == 0 || self.server.data_lanes > 128 {
            return Err(ConfigError::Invalid("data_lanes must be 1..=128".into()));
        }
        if self.server.lane_capacity_mb < 4 {
            return Err(ConfigError::Invalid("lane_capacity_mb must be >= 4".into()));
        }
        if self.server.workers == 0 {
            return Err(ConfigError::Invalid("workers must be >= 1".into()));
        }
        if self.dkim.is_enabled()
            && self
                .dkim
                .private_key_path
                .as_ref()
                .is_some_and(|path| !path.exists())
        {
            return Err(ConfigError::Invalid(
                "DKIM private key does not exist".into(),
            ));
        }
        for account in &self.accounts {
            if !account.email.contains('@') || account.password.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "invalid account {}",
                    account.email
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("ошибка файла конфигурации: {0}")]
    Io(#[from] std::io::Error),
    #[error("ошибка TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("некорректная конфигурация: {0}")]
    Invalid(String),
    #[error("создан пример конфигурации {0}; заполните аккаунты и запустите снова")]
    Created(String),
}

pub const SAMPLE_CONFIG: &str = r#"# Tide Mail configuration
[server]
hostname = "mail.local"
data_path = "./data/mail.tide"
# blob_dir = "./data/blobs"
data_lanes = 8
lane_capacity_mb = 512
workers = 2
http_addr = "127.0.0.1:8080"
http_tls = false
smtp_addr = "127.0.0.1:2525"
# smtps_addr = "127.0.0.1:4650"
# lmtp_addr = "127.0.0.1:2424"
# report_dir = "./data/reports"
submission_addr = "127.0.0.1:5870"
sync_addr = "127.0.0.1:9093"
token_ttl_hours = 168
outbound_enabled = false
outbound_tls = true
dsn_enabled = true
mta_sts = true
dane = false
# outbound_dir = "./data/outbound"
snapshot_interval_secs = 300
# admin_token = "change-me"
# backup_dir = "./backups"
blob_gc_grace_secs = 3600
standby = false
standby_retry_secs = 2

[tls]
# Оставьте пустым для самоподписанного сертификата.
self_signed = true
# cert_path = "./certs/fullchain.pem"
# key_path = "./certs/privkey.pem"

[email_auth]
enabled = false
reject_spf_fail = false
reject_dmarc_fail = false

[blob]
backend = "local"
# bucket = "tide-mail"
# region = "us-east-1"
# endpoint = "https://s3.example.com"
# access_key_id = "..."
# secret_access_key = "..."
# prefix = "blobs"
# allow_http = false

[antivirus]
enabled = false
async_scan = false
# clamav_addr = "127.0.0.1:3310"
# command = "clamdscan"

[spam]
enabled = false
threshold = 5.0
reject_threshold = 15.0
# dnsbl_zones = ["zen.spamhaus.org"]
# external_command = "spamassassin"

[dkim]
# domain = "mail.local"
# selector = "default"
# private_key_path = "./certs/dkim.key"

[[accounts]]
email = "alice@mail.local"
password = "change-me"
name = "Alice"
"#;
