use silent_protocol::SilentProto;

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct Address {
    pub email: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct Account {
    pub id: String,
    pub email: String,
    pub display_name: String,
    #[proto(date)]
    pub created_at: i64,
    pub quota_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct Mailbox {
    pub id: String,
    pub account_id: String,
    pub name: String,
    pub role: String,
    pub total: u64,
    pub unread: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct AttachmentMeta {
    pub id: String,
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    pub inline: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct MessageMeta {
    pub id: String,
    pub account_id: String,
    pub mailbox: String,
    pub thread_id: String,
    pub message_id: String,
    pub subject: String,
    pub from: Vec<Address>,
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
    #[proto(date)]
    pub date: i64,
    pub flags: u64,
    pub size: u64,
    pub snippet: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct MessageBody {
    pub id: String,
    pub text: String,
    pub html: Option<String>,
    pub attachments: Vec<AttachmentMeta>,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct AuthRequest {
    pub account_id: String,
    pub password: String,
    pub device_id: String,
    pub device_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct AuthResponse {
    pub token: String,
    pub refresh_token: Option<String>,
    #[proto(date)]
    pub expires_at: i64,
    pub account: Account,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct ListRequest {
    pub account_id: String,
    pub mailbox: Option<String>,
    pub limit: u32,
    pub offset: u32,
    pub unread_only: bool,
    pub include_deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct ListResponse {
    pub messages: Vec<MessageMeta>,
    pub total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct GetMessageRequest {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct GetMessageResponse {
    pub meta: MessageMeta,
    pub body: MessageBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SearchRequest {
    pub account_id: String,
    pub query: String,
    pub subject: Option<String>,
    pub body: Option<String>,
    pub from: Option<String>,
    pub mailbox: Option<String>,
    pub include_deleted: bool,
    pub limit: u32,
    pub offset: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SearchHit {
    pub message: MessageMeta,
    pub score: u64,
    pub snippet: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SearchResponse {
    pub hits: Vec<SearchHit>,
    pub total: u64,
    pub took_micros: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct MailboxListRequest {
    pub account_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct MailboxListResponse {
    pub mailboxes: Vec<Mailbox>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct FolderListRequest {
    pub account_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct FolderCreateRequest {
    pub account_id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct FolderRenameRequest {
    pub account_id: String,
    pub new_name: String,
    pub old_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct FolderDeleteRequest {
    pub account_id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct FlagsRequest {
    pub account_id: String,
    pub ids: Vec<String>,
    pub flags: u64,
    pub mode: u32,
}

pub mod flags_mode {
    pub const SET: u32 = 0;
    pub const ADD: u32 = 1;
    pub const REMOVE: u32 = 2;
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct DeleteRequest {
    pub account_id: String,
    pub ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct MoveRequest {
    pub account_id: String,
    pub ids: Vec<String>,
    pub mailbox: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct AttachmentData {
    pub content_type: String,
    pub data: Vec<u8>,
    pub filename: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SendWithAttachmentsRequest {
    pub account_id: String,
    pub attachments: Vec<AttachmentData>,
    pub envelope_from: String,
    pub envelope_to: Vec<String>,
    pub html: Option<String>,
    pub subject: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SendRequest {
    pub account_id: String,
    pub envelope_from: String,
    pub envelope_to: Vec<String>,
    pub raw: Vec<u8>,
    pub mailbox: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct SendResponse {
    pub message_id: String,
    pub queued: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct AckResponse {
    pub affected: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SilentProto)]
pub struct ErrorResponse {
    pub code: u32,
    pub message: String,
    pub retryable: bool,
}

pub mod error_code {
    pub const BAD_REQUEST: u32 = 400;
    pub const UNAUTHORIZED: u32 = 401;
    pub const FORBIDDEN: u32 = 403;
    pub const NOT_FOUND: u32 = 404;
    pub const CONFLICT: u32 = 409;
    pub const TOO_LARGE: u32 = 413;
    pub const INTERNAL: u32 = 500;
    pub const UNAVAILABLE: u32 = 503;
}
