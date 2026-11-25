use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use silent_protocol::SilentProto;
use tide_proto::{
    BlobChunk, Cursor, MessageMeta, SyncChange, SyncChanges, SyncOperation, SyncPushResult,
    SyncReject, change_kind, op_kind,
};

use crate::SyncError;

pub trait SyncBackend: Send + Sync {
    fn cursor(&self, account_id: &str) -> Result<Cursor, SyncError>;

    fn pull(
        &self,
        account_id: &str,
        cursor: Cursor,
        limit: u32,
        mailbox: Option<&str>,
        include_deleted: bool,
        include_bodies: bool,
    ) -> Result<SyncChanges, SyncError>;

    fn push(
        &self,
        account_id: &str,
        txn_id: &str,
        operations: Vec<SyncOperation>,
    ) -> Result<SyncPushResult, SyncError>;

    fn fetch_blob(
        &self,
        account_id: &str,
        message_id: &str,
        attachment_id: &str,
        offset: u64,
        length: u32,
    ) -> Result<BlobChunk, SyncError>;
}

pub trait SyncAuth: Send + Sync {
    fn authenticate(
        &self,
        account_id: &str,
        token: &str,
        device_id: &str,
    ) -> Result<(), String>;
}

#[derive(Default)]
pub struct AllowAllAuth;

impl SyncAuth for AllowAllAuth {
    fn authenticate(
        &self,
        _account_id: &str,
        _token: &str,
        _device_id: &str,
    ) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Default)]
struct Inner {
    changes: HashMap<String, Vec<SyncChange>>,
    txns: HashMap<String, SyncPushResult>,
    blobs: HashMap<String, Vec<u8>>,
}

#[derive(Clone, Default)]
pub struct InMemoryBackend {
    inner: Arc<RwLock<Inner>>,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed_message(&self, account_id: &str, meta: MessageMeta) -> Result<Cursor, SyncError> {
        let mut inner = self.inner.write();
        let changes = inner.changes.entry(account_id.to_string()).or_default();
        let seq = changes.last().map_or(1, |change| change.seq + 1);
        changes.push(SyncChange {
            kind: change_kind::UPSERT,
            message_id: meta.id.clone(),
            seq,
            meta: Some(meta),
            flags: None,
            mailbox: None,
            deleted: false,
            payload: Vec::new(),
        });
        Ok(Cursor { lane: 1, seq })
    }

    pub fn store_blob(
        &self,
        account_id: &str,
        message_id: &str,
        attachment_id: &str,
        data: Vec<u8>,
    ) {
        let key = format!("{account_id}/{message_id}/{attachment_id}");
        self.inner.write().blobs.insert(key, data);
    }

    pub fn cursor_value(&self, account_id: &str) -> Cursor {
        let inner = self.inner.read();
        let seq = inner
            .changes
            .get(account_id)
            .and_then(|changes| changes.last())
            .map_or(0, |change| change.seq);
        Cursor { lane: 1, seq }
    }
}

impl SyncBackend for InMemoryBackend {
    fn cursor(&self, account_id: &str) -> Result<Cursor, SyncError> {
        Ok(self.cursor_value(account_id))
    }

    fn pull(
        &self,
        account_id: &str,
        cursor: Cursor,
        limit: u32,
        mailbox: Option<&str>,
        include_deleted: bool,
        _include_bodies: bool,
    ) -> Result<SyncChanges, SyncError> {
        let inner = self.inner.read();
        let changes = inner.changes.get(account_id);
        let mut selected = Vec::new();
        let mut next_cursor = cursor;
        let mut has_more = false;
        if let Some(changes) = changes {
            for change in changes.iter().filter(|change| change.seq > cursor.seq) {
                if selected.len() >= limit.max(1) as usize {
                    has_more = true;
                    break;
                }
                next_cursor = Cursor {
                    lane: cursor.lane,
                    seq: change.seq,
                };
                if !include_deleted && change.deleted {
                    continue;
                }
                if let Some(mailbox) = mailbox {
                    let change_mailbox = change
                        .mailbox
                        .as_deref()
                        .or_else(|| change.meta.as_ref().map(|meta| meta.mailbox.as_str()));
                    if change_mailbox != Some(mailbox) {
                        continue;
                    }
                }
                selected.push(change.clone());
            }
        }
        Ok(SyncChanges {
            next_cursor,
            changes: selected,
            has_more,
        })
    }

    fn push(
        &self,
        account_id: &str,
        txn_id: &str,
        operations: Vec<SyncOperation>,
    ) -> Result<SyncPushResult, SyncError> {
        let key = format!("{account_id}/{txn_id}");
        let mut inner = self.inner.write();
        if let Some(result) = inner.txns.get(&key) {
            return Ok(result.clone());
        }
        let mut changes = inner.changes.remove(account_id).unwrap_or_default();
        let mut rejected = Vec::new();
        let mut applied = 0u32;
        for operation in operations {
            let seq = changes.last().map_or(1, |change| change.seq + 1);
            let mut change = match operation.kind {
                op_kind::PUT_MESSAGE => match MessageMeta::decode(&operation.payload) {
                    Ok(meta) => SyncChange {
                        kind: change_kind::UPSERT,
                        message_id: operation.message_id,
                        seq,
                        meta: Some(meta),
                        flags: None,
                        mailbox: None,
                        deleted: false,
                        payload: Vec::new(),
                    },
                    Err(error) => {
                        rejected.push(SyncReject {
                            message_id: operation.message_id,
                            code: 400,
                            message: format!("invalid message meta: {error}"),
                        });
                        continue;
                    }
                },
                op_kind::FLAGS => {
                    let meta = find_meta(&changes, &operation.message_id).cloned();
                    SyncChange {
                        kind: change_kind::FLAGS,
                        message_id: operation.message_id,
                        seq,
                        meta,
                        flags: Some(operation.flags),
                        mailbox: None,
                        deleted: false,
                        payload: Vec::new(),
                    }
                }
                op_kind::DELETE => SyncChange {
                    kind: change_kind::DELETE,
                    message_id: operation.message_id,
                    seq,
                    meta: None,
                    flags: None,
                    mailbox: None,
                    deleted: true,
                    payload: Vec::new(),
                },
                op_kind::MOVE => {
                    let meta = find_meta(&changes, &operation.message_id).cloned();
                    SyncChange {
                        kind: change_kind::MOVE,
                        message_id: operation.message_id,
                        seq,
                        meta,
                        flags: None,
                        mailbox: Some(operation.mailbox),
                        deleted: false,
                        payload: Vec::new(),
                    }
                }
                _ => {
                    rejected.push(SyncReject {
                        message_id: operation.message_id,
                        code: 400,
                        message: "unknown operation kind".into(),
                    });
                    continue;
                }
            };
            if change.kind == change_kind::UPSERT {
                if let Some(meta) = change.meta.as_mut() {
                    if meta.id.is_empty() {
                        meta.id = change.message_id.clone();
                    }
                }
            }
            changes.push(change);
            applied += 1;
        }
        let cursor = Cursor {
            lane: 1,
            seq: changes.last().map_or(0, |change| change.seq),
        };
        inner.changes.insert(account_id.to_string(), changes);
        let result = SyncPushResult {
            txn_id: txn_id.to_string(),
            applied,
            rejected,
            cursor,
        };
        inner.txns.insert(key, result.clone());
        Ok(result)
    }

    fn fetch_blob(
        &self,
        account_id: &str,
        message_id: &str,
        attachment_id: &str,
        offset: u64,
        length: u32,
    ) -> Result<BlobChunk, SyncError> {
        let key = format!("{account_id}/{message_id}/{attachment_id}");
        let inner = self.inner.read();
        let data = inner
            .blobs
            .get(&key)
            .ok_or_else(|| SyncError::Backend("blob not found".into()))?;
        let start = usize::try_from(offset).map_err(|_| SyncError::Backend("offset overflow".into()))?;
        if start > data.len() {
            return Err(SyncError::Backend("offset out of range".into()));
        }
        let end = start
            .saturating_add(length as usize)
            .min(data.len());
        Ok(BlobChunk {
            message_id: message_id.to_string(),
            attachment_id: attachment_id.to_string(),
            offset,
            data: data[start..end].to_vec(),
            eof: end == data.len(),
        })
    }
}

fn find_meta<'a>(changes: &'a [SyncChange], message_id: &str) -> Option<&'a MessageMeta> {
    changes
        .iter()
        .rev()
        .find(|change| change.message_id == message_id)
        .and_then(|change| change.meta.as_ref())
}
