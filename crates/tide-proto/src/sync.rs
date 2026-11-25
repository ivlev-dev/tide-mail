use silent_protocol::SilentProto;

use crate::api::{ErrorResponse, MessageMeta};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, SilentProto)]
pub struct Cursor {
    pub lane: u32,
    pub seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SyncHello {
    pub protocol_version: u32,
    pub client_id: String,
    pub client_name: String,
    pub capabilities: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SyncHelloOk {
    pub protocol_version: u32,
    pub server_id: String,
    pub capabilities: u64,
    #[proto(date)]
    pub server_time: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SyncAuth {
    pub account_id: String,
    pub token: String,
    pub device_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SyncAuthOk {
    pub account_id: String,
    pub cursor: Cursor,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SyncPull {
    pub account_id: String,
    pub cursor: Cursor,
    pub limit: u32,
    pub mailbox: Option<String>,
    pub include_deleted: bool,
    pub include_bodies: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SyncChange {
    pub kind: u32,
    pub message_id: String,
    pub seq: u64,
    pub meta: Option<MessageMeta>,
    pub flags: Option<u64>,
    pub mailbox: Option<String>,
    pub deleted: bool,
    pub payload: Vec<u8>,
}

pub mod change_kind {
    pub const UPSERT: u32 = 1;
    pub const DELETE: u32 = 2;
    pub const FLAGS: u32 = 3;
    pub const MOVE: u32 = 4;
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SyncChanges {
    pub next_cursor: Cursor,
    pub changes: Vec<SyncChange>,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SyncOperation {
    pub kind: u32,
    pub message_id: String,
    pub flags: u64,
    pub mailbox: String,
    pub payload: Vec<u8>,
}

pub mod op_kind {
    pub const PUT_MESSAGE: u32 = 1;
    pub const FLAGS: u32 = 2;
    pub const DELETE: u32 = 3;
    pub const MOVE: u32 = 4;
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct PutMessagePayload {
    pub account_id: String,
    pub flags: u64,
    pub mailbox: String,
    pub message_id: String,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SyncPush {
    pub account_id: String,
    pub txn_id: String,
    pub operations: Vec<SyncOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SyncReject {
    pub message_id: String,
    pub code: u32,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SyncPushResult {
    pub txn_id: String,
    pub applied: u32,
    pub rejected: Vec<SyncReject>,
    pub cursor: Cursor,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SyncAck {
    pub account_id: String,
    pub cursor: Cursor,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SyncWatch {
    pub account_id: String,
    pub cursor: Cursor,
    pub timeout_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SyncEvent {
    pub cursor: Cursor,
    pub change: SyncChange,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct BlobRequest {
    pub account_id: String,
    pub message_id: String,
    pub attachment_id: String,
    pub offset: u64,
    pub length: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct BlobChunk {
    pub message_id: String,
    pub attachment_id: String,
    pub offset: u64,
    pub data: Vec<u8>,
    pub eof: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SyncError {
    pub error: ErrorResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SyncPing {
    pub nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SyncPong {
    pub nonce: u64,
}

pub mod capability {
    pub const PUSH: u64 = 1 << 0;
    pub const WATCH: u64 = 1 << 1;
    pub const BLOBS: u64 = 1 << 2;
    pub const THREADS: u64 = 1 << 3;
    pub const COMPRESSION: u64 = 1 << 4;
}
