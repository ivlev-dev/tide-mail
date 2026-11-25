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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    pub hostname: String,
    pub data_path: PathBuf,
    pub data_lanes: u16,
    pub lane_capacity_mb: u64,
    pub workers: usize,
    pub http_addr: String,
    pub smtp_addr: Option<String>,
    pub submission_addr: Option<String>,
    pub sync_addr: Option<String>,
    pub token_ttl_hours: u64,
    pub outbound_enabled: bool,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            hostname: "mail.local".into(),
            data_path: PathBuf::from("./data/mail.tide"),
            data_lanes: 8,
            lane_capacity_mb: 512,
            workers: std::thread::available_parallelism()
                .map(|value| value.get().min(8))
                .unwrap_or(2),
            http_addr: "127.0.0.1:8080".into(),
            smtp_addr: Some("127.0.0.1:2525".into()),
            submission_addr: Some("127.0.0.1:5870".into()),
            sync_addr: Some("127.0.0.1:9093".into()),
            token_ttl_hours: 24 * 7,
            outbound_enabled: false,
        }
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
        let config: Self = toml::from_str(&text)?;
        config.validate()?;
        Ok(config)
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
data_lanes = 8
lane_capacity_mb = 512
workers = 2
http_addr = "127.0.0.1:8080"
smtp_addr = "127.0.0.1:2525"
submission_addr = "127.0.0.1:5870"
sync_addr = "127.0.0.1:9093"
token_ttl_hours = 168
outbound_enabled = false

[tls]
# Оставьте пустым для самоподписанного сертификата.
self_signed = true
# cert_path = "./certs/fullchain.pem"
# key_path = "./certs/privkey.pem"

[[accounts]]
email = "alice@mail.local"
password = "change-me"
name = "Alice"
"#;
