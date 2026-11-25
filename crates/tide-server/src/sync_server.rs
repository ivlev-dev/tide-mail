use silent_protocol::SilentProto;
use std::sync::Arc;

use monoio::net::{TcpListener, TcpStream};
use parking_lot::RwLock;
use tide_proto::{
    BlobChunk, Cursor, Frame, PutMessagePayload, SyncChanges, SyncOperation, SyncPushResult,
    SyncReject, frame::frame_length, op_kind,
};
use tide_store::Db;
use tide_sync::{ServerSession, SyncBackend, SyncError, backend::SyncAuth as AuthProvider};

use crate::app::App;
use crate::convert::change_to_sync;
use crate::net::{BufferedConn, Conn};
use crate::virus_scan::VirusScanner;

pub struct StoreSyncBackend {
    db: Db,
    antivirus: Option<Arc<VirusScanner>>,
    transactions: RwLock<std::collections::HashMap<String, SyncPushResult>>,
}

impl StoreSyncBackend {
    pub fn new(db: Db, antivirus: Option<Arc<VirusScanner>>) -> Arc<Self> {
        Arc::new(Self {
            db,
            antivirus,
            transactions: RwLock::new(std::collections::HashMap::new()),
        })
    }
}

impl SyncBackend for StoreSyncBackend {
    fn cursor(&self, account_id: &str) -> Result<Cursor, SyncError> {
        let cursor = self.db.sync_cursor(account_id);
        Ok(Cursor {
            lane: u32::from(cursor.lane),
            seq: cursor.seq,
        })
    }

    fn pull(
        &self,
        account_id: &str,
        cursor: Cursor,
        limit: u32,
        _mailbox: Option<&str>,
        _include_deleted: bool,
        _include_bodies: bool,
    ) -> Result<SyncChanges, SyncError> {
        let page = self.db.sync_changes(account_id, cursor.seq, limit);
        let changes = page
            .entries
            .iter()
            .filter(|entry| {
                if !_include_deleted && entry.deleted {
                    return false;
                }
                if let Some(mailbox) = _mailbox {
                    if entry.mailbox != mailbox {
                        return false;
                    }
                }
                true
            })
            .map(change_to_sync)
            .collect();
        Ok(SyncChanges {
            next_cursor: Cursor {
                lane: cursor.lane,
                seq: page.next_seq,
            },
            changes,
            has_more: page.has_more,
        })
    }

    fn push(
        &self,
        account_id: &str,
        txn_id: &str,
        operations: Vec<SyncOperation>,
    ) -> Result<SyncPushResult, SyncError> {
        let key = format!("{account_id}/{txn_id}");
        if let Some(result) = self.transactions.read().get(&key) {
            return Ok(result.clone());
        }
        let mut applied = 0u32;
        let mut rejected = Vec::new();
        for operation in operations {
            if operation.kind == op_kind::PUT_MESSAGE {
                let result = PutMessagePayload::decode(&operation.payload)
                    .map_err(|error| SyncError::Backend(error.to_string()))
                    .and_then(|payload| {
                        if payload.account_id != account_id {
                            return Err(SyncError::Unauthorized("account mismatch".into()));
                        }
                        if let Some(scanner) = &self.antivirus {
                            scanner.scan(&payload.raw).map_err(SyncError::Backend)?;
                        }
                        let message_id = if payload.message_id.is_empty() {
                            uuid::Uuid::new_v4().to_string()
                        } else {
                            payload.message_id
                        };
                        let mut message = tide_core::parse_message(
                            &payload.raw,
                            account_id,
                            &payload.mailbox,
                            message_id,
                        )
                        .map_err(|error| SyncError::Backend(error.to_string()))?;
                        message.flags = payload.flags;
                        futures::executor::block_on(self.db.append_message_with_blobs(message))
                            .map(|_| ())
                            .map_err(|error| SyncError::Backend(error.to_string()))
                    });
                match result {
                    Ok(()) => applied += 1,
                    Err(error) => rejected.push(SyncReject {
                        message_id: operation.message_id,
                        code: if matches!(error, SyncError::Unauthorized(_)) {
                            403
                        } else {
                            400
                        },
                        message: error.to_string(),
                    }),
                }
                continue;
            }
            if operation.kind != op_kind::PUT_MESSAGE {
                match self.db.get_message(&operation.message_id) {
                    Ok(Some(message)) if message.account_id == account_id => {}
                    Ok(Some(_)) => {
                        rejected.push(SyncReject {
                            message_id: operation.message_id,
                            code: 403,
                            message: "message belongs to another account".into(),
                        });
                        continue;
                    }
                    Ok(None) => {
                        rejected.push(SyncReject {
                            message_id: operation.message_id,
                            code: 404,
                            message: "message not found".into(),
                        });
                        continue;
                    }
                    Err(error) => {
                        rejected.push(SyncReject {
                            message_id: operation.message_id,
                            code: 500,
                            message: error.to_string(),
                        });
                        continue;
                    }
                }
            }
            let result = match operation.kind {
                op_kind::FLAGS => futures::executor::block_on(
                    self.db.update_flags(&operation.message_id, operation.flags),
                )
                .map(|_| ()),
                op_kind::DELETE => {
                    futures::executor::block_on(self.db.delete_message(&operation.message_id))
                        .map(|_| ())
                }
                op_kind::MOVE => futures::executor::block_on(self.db.move_message(
                    &operation.message_id,
                    account_id,
                    &operation.mailbox,
                ))
                .map(|_| ()),
                _ => {
                    rejected.push(SyncReject {
                        message_id: operation.message_id,
                        code: 501,
                        message: "operation is not supported by this backend".into(),
                    });
                    continue;
                }
            };
            match result {
                Ok(()) => applied += 1,
                Err(error) => rejected.push(SyncReject {
                    message_id: operation.message_id,
                    code: 400,
                    message: error.to_string(),
                }),
            }
        }
        let cursor = self.cursor(account_id)?;
        let result = SyncPushResult {
            txn_id: txn_id.to_string(),
            applied,
            rejected,
            cursor,
        };
        self.transactions.write().insert(key, result.clone());
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
        let message = self
            .db
            .get_message(message_id)
            .map_err(|error| SyncError::Backend(error.to_string()))?
            .ok_or_else(|| SyncError::Backend("message not found".into()))?;
        if message.account_id != account_id {
            return Err(SyncError::Unauthorized("account mismatch".into()));
        }
        let index = attachment_id
            .parse::<usize>()
            .map_err(|_| SyncError::Backend("invalid attachment id".into()))?;
        let attachment = message
            .attachments
            .get(index)
            .ok_or_else(|| SyncError::Backend("attachment not found".into()))?;
        let start =
            usize::try_from(offset).map_err(|_| SyncError::Backend("offset overflow".into()))?;
        if start > attachment.data.len() {
            return Err(SyncError::Backend("offset out of range".into()));
        }
        let end = start
            .saturating_add(length as usize)
            .min(attachment.data.len());
        Ok(BlobChunk {
            message_id: message_id.to_string(),
            attachment_id: attachment_id.to_string(),
            offset,
            data: attachment.data[start..end].to_vec(),
            eof: end == attachment.data.len(),
        })
    }
}

impl AuthProvider for crate::auth::Registry {
    fn authenticate(&self, account_id: &str, token: &str, _device_id: &str) -> Result<(), String> {
        let account = self
            .validate_token(token)
            .map_err(|error| error.to_string())?;
        if account.id.eq_ignore_ascii_case(account_id) {
            Ok(())
        } else {
            Err("account mismatch".into())
        }
    }
}

pub async fn serve_sync(app: Arc<App>, listener: TcpListener, use_tls: bool) {
    let backend = StoreSyncBackend::new(app.db.clone(), app.antivirus.clone());
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let app = Arc::clone(&app);
                let backend = Arc::clone(&backend);
                monoio::spawn(async move {
                    if let Err(error) = handle_connection(app, backend, stream, use_tls).await {
                        eprintln!("sync {peer}: {error}");
                    }
                });
            }
            Err(error) => {
                eprintln!("sync accept: {error}");
                monoio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle_connection(
    app: Arc<App>,
    backend: Arc<StoreSyncBackend>,
    stream: TcpStream,
    use_tls: bool,
) -> std::io::Result<()> {
    let conn = if use_tls {
        let Some(acceptor) = app.tls.as_ref() else {
            return Err(std::io::Error::other("TLS is not configured"));
        };
        Conn::Tls(Box::new(
            acceptor
                .accept(stream)
                .await
                .map_err(|error| std::io::Error::other(error.to_string()))?,
        ))
    } else {
        Conn::Plain(stream)
    };
    let mut conn = BufferedConn::new(conn);
    let auth: Arc<dyn AuthProvider> = app.registry.clone();
    let mut session = ServerSession::new(backend, auth, app.config.server.hostname.clone());
    loop {
        let Some(frame) = read_frame(&mut conn).await? else {
            return Ok(());
        };
        let handle = monoio::spawn_blocking(move || {
            let frames = session.handle(frame);
            (session, frames)
        });
        let (returned, frames) = handle
            .await
            .map_err(|_| std::io::Error::other("blocking task canceled"))?;
        session = returned;
        for frame in frames {
            let encoded = frame
                .encode()
                .map_err(|_| std::io::Error::other("blocking task canceled"))?;
            conn.write_all(&encoded).await?;
        }
    }
}

async fn read_frame(conn: &mut BufferedConn) -> std::io::Result<Option<Frame>> {
    let header = match conn.read_exact(16, 16).await {
        Ok(header) => header,
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    };
    let length = frame_length(&header)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    let mut bytes = header;
    if length > 16 {
        bytes.extend_from_slice(&conn.read_exact(length - 16, 16 * 1024 * 1024).await?);
    }
    let frame = Frame::decode(&bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    Ok(Some(frame))
}
