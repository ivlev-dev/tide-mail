use std::collections::HashMap;
use std::sync::Arc;

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use parking_lot::RwLock;
use rand_core::OsRng;
use uuid::Uuid;

use crate::config::AccountConfig;

#[derive(Debug, Clone)]
pub struct Account {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub password_hash: String,
}

#[derive(Debug, Clone)]
struct Token {
    account_id: String,
    expires_at: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("неверный email или пароль")]
    InvalidCredentials,
    #[error("токен недействителен или истёк")]
    InvalidToken,
    #[error("ошибка хеширования пароля: {0}")]
    Hash(String),
}

pub struct Registry {
    accounts: Vec<Account>,
    by_email: HashMap<String, usize>,
    tokens: RwLock<HashMap<String, Token>>,
    token_ttl_seconds: i64,
}

impl Registry {
    pub fn new(configs: &[AccountConfig], token_ttl_hours: u64) -> Result<Arc<Self>, AuthError> {
        let mut accounts = Vec::with_capacity(configs.len());
        let mut by_email = HashMap::new();
        for (index, config) in configs.iter().enumerate() {
            let salt = SaltString::generate(&mut OsRng);
            let password_hash = Argon2::default()
                .hash_password(config.password.as_bytes(), &salt)
                .map_err(|error| AuthError::Hash(error.to_string()))?
                .to_string();
            let email = config.email.to_ascii_lowercase();
            accounts.push(Account {
                id: email.clone(),
                email: email.clone(),
                display_name: if config.name.is_empty() {
                    email.clone()
                } else {
                    config.name.clone()
                },
                password_hash,
            });
            by_email.insert(email, index);
        }
        Ok(Arc::new(Self {
            accounts,
            by_email,
            tokens: RwLock::new(HashMap::new()),
            token_ttl_seconds: (token_ttl_hours as i64).saturating_mul(3600),
        }))
    }

    pub fn account(&self, email: &str) -> Option<&Account> {
        self.by_email
            .get(&email.to_ascii_lowercase())
            .and_then(|index| self.accounts.get(*index))
    }

    pub fn account_by_id(&self, id: &str) -> Option<&Account> {
        self.by_email
            .get(&id.to_ascii_lowercase())
            .and_then(|index| self.accounts.get(*index))
    }

    pub fn accounts(&self) -> &[Account] {
        &self.accounts
    }

    #[cfg(test)]
    pub fn is_local(&self, email: &str) -> bool {
        self.account(email).is_some()
    }

    pub fn authenticate(&self, email: &str, password: &str) -> Result<Account, AuthError> {
        let account = self.account(email).ok_or(AuthError::InvalidCredentials)?;
        let parsed = PasswordHash::new(&account.password_hash)
            .map_err(|error| AuthError::Hash(error.to_string()))?;
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .map_err(|_| AuthError::InvalidCredentials)?;
        Ok(account.clone())
    }

    pub fn issue_token(&self, account_id: &str) -> String {
        let token = Uuid::new_v4().to_string();
        let expires_at = now_millis() / 1000 + self.token_ttl_seconds;
        self.tokens.write().insert(
            token.clone(),
            Token {
                account_id: account_id.to_string(),
                expires_at,
            },
        );
        token
    }

    pub fn validate_token(&self, token: &str) -> Result<Account, AuthError> {
        let tokens = self.tokens.read();
        let entry = tokens.get(token).ok_or(AuthError::InvalidToken)?;
        if entry.expires_at < now_millis() / 1000 {
            return Err(AuthError::InvalidToken);
        }
        self.account_by_id(&entry.account_id)
            .cloned()
            .ok_or(AuthError::InvalidToken)
    }

    pub fn revoke_token(&self, token: &str) {
        self.tokens.write().remove(token);
    }

    pub fn token_ttl_seconds(&self) -> i64 {
        self.token_ttl_seconds
    }
}

pub fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> Arc<Registry> {
        Registry::new(
            &[AccountConfig {
                email: "alice@example.com".into(),
                password: "secret".into(),
                name: "Alice".into(),
            }],
            1,
        )
        .unwrap()
    }

    #[test]
    fn authenticates_and_issues_tokens() {
        let registry = registry();
        let account = registry
            .authenticate("alice@example.com", "secret")
            .unwrap();
        assert_eq!(account.id, "alice@example.com");
        assert!(registry.authenticate("alice@example.com", "wrong").is_err());
        let token = registry.issue_token(&account.id);
        assert_eq!(
            registry.validate_token(&token).unwrap().email,
            "alice@example.com"
        );
        registry.revoke_token(&token);
        assert!(registry.validate_token(&token).is_err());
    }

    #[test]
    fn is_local_is_case_insensitive() {
        let registry = registry();
        assert!(registry.is_local("ALICE@example.com"));
        assert!(!registry.is_local("bob@example.com"));
    }
}
