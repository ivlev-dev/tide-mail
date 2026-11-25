use silent_protocol::SilentProto;
use tide_proto::{
    BlobChunk, BlobRequest, Cursor, ErrorResponse, Frame, SyncAck, SyncAuth, SyncAuthOk,
    SyncChanges, SyncEvent, SyncHello, SyncHelloOk, SyncPing, SyncPong, SyncPull, SyncPush,
    SyncPushResult, SyncWatch, frame::kind, sync::SyncError as SyncErrorPayload,
};

use crate::SyncError;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEvent {
    Hello(SyncHelloOk),
    Auth(SyncAuthOk),
    Changes(SyncChanges),
    Push(SyncPushResult),
    Event(SyncEvent),
    Blob(BlobChunk),
    Pong(SyncPong),
    Error(ErrorResponse),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientState {
    AwaitHello,
    AwaitAuth,
    Ready,
}

pub struct ClientSession {
    client_id: String,
    state: ClientState,
    cursor: Cursor,
    server_id: Option<String>,
    account_id: Option<String>,
}

impl ClientSession {
    pub fn new(client_id: impl Into<String>, client_name: impl Into<String>) -> (Self, Frame) {
        let client_id = client_id.into();
        let hello = SyncHello {
            protocol_version: super::session::PROTOCOL_VERSION,
            client_id: client_id.clone(),
            client_name: client_name.into(),
            capabilities: tide_proto::capability::PUSH
                | tide_proto::capability::WATCH
                | tide_proto::capability::BLOBS,
        };
        let frame = match hello.encode() {
            Ok(payload) => Frame::new(kind::HELLO, payload),
            Err(_) => Frame::new(kind::HELLO, Vec::new()),
        };
        (
            Self {
                client_id,
                state: ClientState::AwaitHello,
                cursor: Cursor::default(),
                server_id: None,
                account_id: None,
            },
            frame,
        )
    }

    pub fn cursor(&self) -> Cursor {
        self.cursor
    }

    pub fn server_id(&self) -> Option<&str> {
        self.server_id.as_deref()
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn auth_frame(
        &mut self,
        account_id: impl Into<String>,
        token: impl Into<String>,
        device_id: impl Into<String>,
    ) -> Result<Frame, SyncError> {
        if self.state != ClientState::AwaitAuth {
            return Err(SyncError::InvalidState("expected HELLO_OK first".into()));
        }
        let account_id = account_id.into();
        self.account_id = Some(account_id.clone());
        let auth = SyncAuth {
            account_id,
            token: token.into(),
            device_id: device_id.into(),
        };
        Ok(Frame::new(kind::AUTH, auth.encode()?))
    }

    pub fn pull_frame(&self, limit: u32) -> Result<Frame, SyncError> {
        self.require_ready()?;
        let request = SyncPull {
            account_id: self.account_id.clone().unwrap_or_default(),
            cursor: self.cursor,
            limit,
            mailbox: None,
            include_deleted: false,
            include_bodies: false,
        };
        Ok(Frame::new(kind::PULL, request.encode()?))
    }

    pub fn pull_frame_for(
        &self,
        account_id: impl Into<String>,
        limit: u32,
        mailbox: Option<String>,
    ) -> Result<Frame, SyncError> {
        self.pull_frame_at(account_id, self.cursor, limit, mailbox)
    }

    pub fn pull_frame_at(
        &self,
        account_id: impl Into<String>,
        cursor: Cursor,
        limit: u32,
        mailbox: Option<String>,
    ) -> Result<Frame, SyncError> {
        self.require_ready()?;
        let request = SyncPull {
            account_id: account_id.into(),
            cursor,
            limit,
            mailbox,
            include_deleted: false,
            include_bodies: false,
        };
        Ok(Frame::new(kind::PULL, request.encode()?))
    }

    pub fn push_frame(
        &self,
        account_id: impl Into<String>,
        txn_id: impl Into<String>,
        operations: Vec<tide_proto::SyncOperation>,
    ) -> Result<Frame, SyncError> {
        self.require_ready()?;
        let request = SyncPush {
            account_id: account_id.into(),
            txn_id: txn_id.into(),
            operations,
        };
        Ok(Frame::new(kind::PUSH, request.encode()?))
    }

    pub fn ack_frame(&self, account_id: impl Into<String>) -> Result<Frame, SyncError> {
        self.require_ready()?;
        let request = SyncAck {
            account_id: account_id.into(),
            cursor: self.cursor,
        };
        Ok(Frame::new(kind::ACK, request.encode()?))
    }

    pub fn watch_frame(
        &self,
        account_id: impl Into<String>,
        timeout_ms: u32,
    ) -> Result<Frame, SyncError> {
        self.require_ready()?;
        let request = SyncWatch {
            account_id: account_id.into(),
            cursor: self.cursor,
            timeout_ms,
        };
        Ok(Frame::new(kind::WATCH, request.encode()?))
    }

    pub fn blob_frame(
        &self,
        account_id: impl Into<String>,
        message_id: impl Into<String>,
        attachment_id: impl Into<String>,
        offset: u64,
        length: u32,
    ) -> Result<Frame, SyncError> {
        self.require_ready()?;
        let request = BlobRequest {
            account_id: account_id.into(),
            message_id: message_id.into(),
            attachment_id: attachment_id.into(),
            offset,
            length,
        };
        Ok(Frame::new(kind::BLOB_REQUEST, request.encode()?))
    }

    pub fn ping_frame(&self, nonce: u64) -> Result<Frame, SyncError> {
        self.require_ready()?;
        Ok(Frame::new(kind::PING, SyncPing { nonce }.encode()?))
    }

    pub fn handle(&mut self, frame: Frame) -> Result<ClientEvent, SyncError> {
        if frame.kind == kind::ERROR {
            let payload = SyncErrorPayload::decode(&frame.payload)?;
            return Ok(ClientEvent::Error(payload.error));
        }
        match self.state {
            ClientState::AwaitHello => {
                if frame.kind != kind::HELLO_OK {
                    return Err(SyncError::InvalidState("expected HELLO_OK".into()));
                }
                let hello = SyncHelloOk::decode(&frame.payload)?;
                self.server_id = Some(hello.server_id.clone());
                self.state = ClientState::AwaitAuth;
                Ok(ClientEvent::Hello(hello))
            }
            ClientState::AwaitAuth => {
                if frame.kind != kind::AUTH_OK {
                    return Err(SyncError::InvalidState("expected AUTH_OK".into()));
                }
                let auth = SyncAuthOk::decode(&frame.payload)?;
                self.cursor = auth.cursor;
                self.state = ClientState::Ready;
                Ok(ClientEvent::Auth(auth))
            }
            ClientState::Ready => match frame.kind {
                kind::CHANGES => {
                    let changes = SyncChanges::decode(&frame.payload)?;
                    self.cursor = changes.next_cursor;
                    Ok(ClientEvent::Changes(changes))
                }
                kind::PUSH_OK => {
                    let result = SyncPushResult::decode(&frame.payload)?;
                    self.cursor = result.cursor;
                    Ok(ClientEvent::Push(result))
                }
                kind::EVENT => {
                    let event = SyncEvent::decode(&frame.payload)?;
                    self.cursor = event.cursor;
                    Ok(ClientEvent::Event(event))
                }
                kind::BLOB_CHUNK => {
                    let chunk = BlobChunk::decode(&frame.payload)?;
                    Ok(ClientEvent::Blob(chunk))
                }
                kind::PONG => {
                    let pong = SyncPong::decode(&frame.payload)?;
                    Ok(ClientEvent::Pong(pong))
                }
                _ => Err(SyncError::UnknownFrame(frame.kind)),
            },
        }
    }

    fn require_ready(&self) -> Result<(), SyncError> {
        if self.state == ClientState::Ready {
            Ok(())
        } else {
            Err(SyncError::InvalidState("not authenticated".into()))
        }
    }
}
