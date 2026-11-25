use serde::{Deserialize, Serialize};
use tide_core::{Address, Message};

use crate::index::Doc;

pub mod kind {
    pub const UPSERT: u32 = 1;
    pub const DELETE: u32 = 2;
    pub const FLAGS: u32 = 3;
    pub const MOVE: u32 = 4;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeEntry {
    pub seq: u64,
    pub kind: u32,
    pub message_id: String,
    pub account_id: String,
    pub mailbox: String,
    pub thread_id: String,
    pub message_id_header: String,
    pub subject: String,
    pub from: Vec<Address>,
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
    pub date: i64,
    pub flags: u64,
    pub size: u64,
    pub snippet: String,
    pub deleted: bool,
}

impl ChangeEntry {
    pub fn from_doc(seq: u64, kind: u32, doc: &Doc) -> Self {
        Self {
            seq,
            kind,
            message_id: doc.id.clone(),
            account_id: doc.account_id.clone(),
            mailbox: doc.mailbox.clone(),
            thread_id: doc.thread_id.clone(),
            message_id_header: doc.message_id_header.clone(),
            subject: doc.subject.clone(),
            from: doc.from_addresses.clone(),
            to: doc.to_addresses.clone(),
            cc: doc.cc_addresses.clone(),
            date: doc.date,
            flags: doc.flags,
            size: doc.size,
            snippet: doc.body.chars().take(160).collect(),
            deleted: kind == kind::DELETE,
        }
    }

    pub fn from_message(seq: u64, message: &Message) -> Self {
        Self {
            seq,
            kind: kind::UPSERT,
            message_id: message.id.clone(),
            account_id: message.account_id.clone(),
            mailbox: message.mailbox.clone(),
            thread_id: message.thread_id.clone(),
            message_id_header: message.message_id.clone(),
            subject: message.subject.clone(),
            from: message.from.clone(),
            to: message.to.clone(),
            cc: message.cc.clone(),
            date: message.date,
            flags: message.flags,
            size: message.size,
            snippet: message.body_text.chars().take(160).collect(),
            deleted: false,
        }
    }

    pub fn from_message_with_kind(seq: u64, kind: u32, message: &Message) -> Self {
        let mut entry = Self::from_message(seq, message);
        entry.kind = kind;
        entry.deleted = kind == kind::DELETE;
        entry
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangesPage {
    pub entries: Vec<ChangeEntry>,
    pub next_seq: u64,
    pub has_more: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncCursor {
    pub lane: u16,
    pub seq: u64,
}
