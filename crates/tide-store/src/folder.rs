use serde::{Deserialize, Serialize};
use silent_protocol::SilentProto;

pub const DEFAULT_FOLDERS: &[(&str, &str)] = &[
    ("INBOX", "inbox"),
    ("Sent", "sent"),
    ("Drafts", "drafts"),
    ("Trash", "trash"),
    ("Archive", "archive"),
    ("Junk", "junk"),
    ("Quarantine", "quarantine"),
    ("Virus", "virus"),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Folder {
    pub name: String,
    pub role: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, SilentProto)]
pub struct FolderRecord {
    pub account_id: String,
    #[proto(date)]
    pub created_at: i64,
    pub deleted: bool,
    pub name: String,
    pub role: String,
    #[proto(date)]
    pub updated_at: i64,
}

impl FolderRecord {
    pub fn create(account_id: &str, name: &str, role: &str) -> Self {
        let now = crate::batch::now_millis();
        Self {
            account_id: account_id.to_string(),
            created_at: now,
            deleted: false,
            name: name.to_string(),
            role: role.to_string(),
            updated_at: now,
        }
    }

    pub fn delete(account_id: &str, name: &str, role: &str) -> Self {
        let now = crate::batch::now_millis();
        Self {
            account_id: account_id.to_string(),
            created_at: now,
            deleted: true,
            name: name.to_string(),
            role: role.to_string(),
            updated_at: now,
        }
    }

    pub fn to_folder(&self) -> Folder {
        Folder {
            name: self.name.clone(),
            role: self.role.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

pub fn validate_folder_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 128 {
        return Err("folder name must be 1..=128 bytes".into());
    }
    if name.contains('/') || name.contains('\\') || name.contains(':') {
        return Err("folder name must not contain /, \\ or :".into());
    }
    if name.chars().any(char::is_control) {
        return Err("folder name contains control characters".into());
    }
    Ok(())
}
