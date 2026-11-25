use std::sync::Arc;

use silent_protocol::SilentProto;
use tide_proto::{
    BlobRequest, Cursor, ErrorResponse, Frame, SyncAck, SyncAuth, SyncAuthOk, SyncHello,
    SyncHelloOk, SyncPing, SyncPong, SyncPull, SyncPush, SyncWatch, capability, error_code,
    frame::kind, sync::SyncError as SyncErrorPayload,
};

use crate::SyncError;
use crate::backend::{SyncAuth as AuthProvider, SyncBackend};

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerState {
    AwaitHello,
    AwaitAuth,
    Ready,
    Closed,
}

pub struct ServerSession {
    backend: Arc<dyn SyncBackend>,
    auth: Arc<dyn AuthProvider>,
    server_id: String,
    state: ServerState,
    account_id: Option<String>,
    cursor: Cursor,
}

impl ServerSession {
    pub fn new(
        backend: Arc<dyn SyncBackend>,
        auth: Arc<dyn AuthProvider>,
        server_id: impl Into<String>,
    ) -> Self {
        Self {
            backend,
            auth,
            server_id: server_id.into(),
            state: ServerState::AwaitHello,
            account_id: None,
            cursor: Cursor::default(),
        }
    }

    pub fn state(&self) -> &'static str {
        match self.state {
            ServerState::AwaitHello => "await_hello",
            ServerState::AwaitAuth => "await_auth",
            ServerState::Ready => "ready",
            ServerState::Closed => "closed",
        }
    }

    pub fn account_id(&self) -> Option<&str> {
        self.account_id.as_deref()
    }

    pub fn handle(&mut self, frame: Frame) -> Vec<Frame> {
        match self.handle_inner(frame) {
            Ok(frames) => frames,
            Err(error) => {
                let (code, message) = match &error {
                    SyncError::Unauthorized(_) => (error_code::UNAUTHORIZED, error.to_string()),
                    SyncError::InvalidState(_) => (error_code::CONFLICT, error.to_string()),
                    SyncError::Backend(_) => (error_code::UNAVAILABLE, error.to_string()),
                    _ => (error_code::BAD_REQUEST, error.to_string()),
                };
                vec![error_frame(code, message)]
            }
        }
    }

    fn handle_inner(&mut self, frame: Frame) -> Result<Vec<Frame>, SyncError> {
        if self.state == ServerState::Closed {
            return Err(SyncError::InvalidState("session is closed".into()));
        }
        match self.state {
            ServerState::AwaitHello => {
                if frame.kind != kind::HELLO {
                    return Err(SyncError::InvalidState("expected HELLO".into()));
                }
                let hello = SyncHello::decode(&frame.payload)?;
                if hello.protocol_version != PROTOCOL_VERSION {
                    return Err(SyncError::InvalidState(format!(
                        "unsupported protocol version {}",
                        hello.protocol_version
                    )));
                }
                self.state = ServerState::AwaitAuth;
                let reply = SyncHelloOk {
                    protocol_version: PROTOCOL_VERSION,
                    server_id: self.server_id.clone(),
                    capabilities: capability::PUSH
                        | capability::WATCH
                        | capability::BLOBS
                        | capability::THREADS,
                    server_time: now_millis(),
                };
                Ok(vec![Frame::new(kind::HELLO_OK, reply.encode()?)])
            }
            ServerState::AwaitAuth => {
                if frame.kind != kind::AUTH {
                    return Err(SyncError::InvalidState("expected AUTH".into()));
                }
                let auth = SyncAuth::decode(&frame.payload)?;
                self.auth
                    .authenticate(&auth.account_id, &auth.token, &auth.device_id)
                    .map_err(SyncError::Unauthorized)?;
                self.account_id = Some(auth.account_id.clone());
                self.cursor = self.backend.cursor(&auth.account_id)?;
                self.state = ServerState::Ready;
                let reply = SyncAuthOk {
                    account_id: auth.account_id,
                    cursor: self.cursor,
                };
                Ok(vec![Frame::new(kind::AUTH_OK, reply.encode()?)])
            }
            ServerState::Ready => self.handle_ready(frame),
            ServerState::Closed => unreachable!(),
        }
    }

    fn handle_ready(&mut self, frame: Frame) -> Result<Vec<Frame>, SyncError> {
        let account_id = self
            .account_id
            .clone()
            .ok_or_else(|| SyncError::InvalidState("not authenticated".into()))?;
        match frame.kind {
            kind::PULL => {
                let request = SyncPull::decode(&frame.payload)?;
                if request.account_id != account_id {
                    return Err(SyncError::Unauthorized("account mismatch".into()));
                }
                let changes = self.backend.pull(
                    &account_id,
                    request.cursor,
                    request.limit.clamp(1, 500),
                    request.mailbox.as_deref(),
                    request.include_deleted,
                    request.include_bodies,
                )?;
                self.cursor = changes.next_cursor;
                Ok(vec![Frame::new(kind::CHANGES, changes.encode()?)])
            }
            kind::PUSH => {
                let request = SyncPush::decode(&frame.payload)?;
                if request.account_id != account_id {
                    return Err(SyncError::Unauthorized("account mismatch".into()));
                }
                let result = self
                    .backend
                    .push(&account_id, &request.txn_id, request.operations)?;
                self.cursor = result.cursor;
                Ok(vec![Frame::new(kind::PUSH_OK, result.encode()?)])
            }
            kind::ACK => {
                let ack = SyncAck::decode(&frame.payload)?;
                if ack.account_id != account_id {
                    return Err(SyncError::Unauthorized("account mismatch".into()));
                }
                if ack.cursor.seq > self.cursor.seq {
                    self.cursor = ack.cursor;
                }
                Ok(Vec::new())
            }
            kind::WATCH => {
                let request = SyncWatch::decode(&frame.payload)?;
                if request.account_id != account_id {
                    return Err(SyncError::Unauthorized("account mismatch".into()));
                }
                let changes =
                    self.backend
                        .pull(&account_id, request.cursor, 1, None, false, false)?;
                if let Some(change) = changes.changes.first() {
                    let event = tide_proto::SyncEvent {
                        cursor: changes.next_cursor,
                        change: change.clone(),
                    };
                    Ok(vec![Frame::new(kind::EVENT, event.encode()?)])
                } else {
                    Ok(vec![Frame::new(kind::CHANGES, changes.encode()?)])
                }
            }
            kind::BLOB_REQUEST => {
                let request = BlobRequest::decode(&frame.payload)?;
                if request.account_id != account_id {
                    return Err(SyncError::Unauthorized("account mismatch".into()));
                }
                let chunk = self.backend.fetch_blob(
                    &account_id,
                    &request.message_id,
                    &request.attachment_id,
                    request.offset,
                    request.length,
                )?;
                Ok(vec![Frame::new(kind::BLOB_CHUNK, chunk.encode()?)])
            }
            kind::PING => {
                let ping = SyncPing::decode(&frame.payload)?;
                let pong = SyncPong { nonce: ping.nonce };
                Ok(vec![Frame::new(kind::PONG, pong.encode()?)])
            }
            _ => Err(SyncError::UnknownFrame(frame.kind)),
        }
    }
}

pub fn error_frame(code: u32, message: impl Into<String>) -> Frame {
    let payload = SyncErrorPayload {
        error: ErrorResponse {
            code,
            message: message.into(),
            retryable: false,
        },
    };
    match payload.encode() {
        Ok(bytes) => Frame::new(kind::ERROR, bytes),
        Err(_) => Frame::new(kind::ERROR, Vec::new()),
    }
}

fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}
