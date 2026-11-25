pub mod mime;

pub use mime::{MimeError, parse_message};

use silent_protocol::SilentProto;

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct Address {
    pub email: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct Attachment {
    pub content_type: String,
    pub data: Vec<u8>,
    pub filename: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct Message {
    pub account_id: String,
    pub attachments: Vec<Attachment>,
    pub bcc: Vec<Address>,
    pub body_html: Option<String>,
    pub body_text: String,
    pub cc: Vec<Address>,
    pub date: i64,
    pub flags: u64,
    pub from: Vec<Address>,
    pub id: String,
    pub in_reply_to: Option<String>,
    pub mailbox: String,
    pub message_id: String,
    pub raw: Vec<u8>,
    pub references: Vec<String>,
    pub size: u64,
    pub subject: String,
    pub thread_id: String,
    pub to: Vec<Address>,
}

impl Message {
    pub fn is_read(&self) -> bool {
        self.flags & flags::SEEN != 0
    }

    pub fn is_deleted(&self) -> bool {
        self.flags & flags::DELETED != 0
    }

    pub fn normalized_subject(&self) -> String {
        let mut value = self.subject.trim();
        loop {
            let lower = value.to_ascii_lowercase();
            let mut stripped = false;
            for prefix in ["re:", "fw:", "fwd:", "aw:", "sv:"] {
                if let Some(rest) = lower.strip_prefix(prefix) {
                    value = value[value.len() - rest.len()..].trim();
                    stripped = true;
                    break;
                }
            }
            if !stripped {
                break;
            }
        }
        value.to_string()
    }
}

pub mod flags {
    pub const SEEN: u64 = 1 << 0;
    pub const ANSWERED: u64 = 1 << 1;
    pub const FLAGGED: u64 = 1 << 2;
    pub const DELETED: u64 = 1 << 3;
    pub const DRAFT: u64 = 1 << 4;
    pub const RECENT: u64 = 1 << 5;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModelError {
    #[error("message id must not be empty")]
    EmptyId,
    #[error("account id must not be empty")]
    EmptyAccount,
}

impl Message {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.id.is_empty() {
            return Err(ModelError::EmptyId);
        }
        if self.account_id.is_empty() {
            return Err(ModelError::EmptyAccount);
        }
        Ok(())
    }
}

pub fn thread_subject(subject: &str) -> String {
    let mut value = subject.trim();
    loop {
        let lower = value.to_ascii_lowercase();
        let mut stripped = false;
        for prefix in ["re:", "fw:", "fwd:", "aw:", "sv:"] {
            if let Some(rest) = lower.strip_prefix(prefix) {
                value = value[value.len() - rest.len()..].trim();
                stripped = true;
                break;
            }
        }
        if !stripped {
            break;
        }
    }
    value.to_ascii_lowercase()
}
