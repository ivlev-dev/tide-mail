use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use monoio::net::TcpListener;
use silent_protocol::SilentProto;
use tide_core::parse_message;
use tide_proto::{
    Account as ProtoAccount, AckResponse, AuthRequest, AuthResponse, DeleteRequest, ErrorResponse,
    FlagsRequest, FolderCreateRequest, FolderDeleteRequest, FolderListRequest, FolderRenameRequest,
    GetMessageRequest, GetMessageResponse, ListRequest, ListResponse, Mailbox, MailboxListRequest,
    MailboxListResponse, MoveRequest, SearchHit as ProtoSearchHit, SearchRequest, SearchResponse,
    SendRequest, SendResponse, SendWithAttachmentsRequest, flags_mode,
};
use tide_store::{SearchQuery, StoreError};
use uuid::Uuid;

use crate::app::App;
use crate::auth::{Account, AuthError};
use crate::convert::{message_to_body, message_to_meta};
use crate::net::{BufferedConn, Conn};

const MAX_BODY: usize = 64 * 1024 * 1024;
const MAX_HEADERS: usize = 64 * 1024;

pub async fn serve_http(app: Arc<App>, listener: TcpListener, use_tls: bool) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let app = Arc::clone(&app);
                monoio::spawn(async move {
                    let conn = if use_tls {
                        match app.tls.as_ref() {
                            Some(acceptor) => match acceptor.accept(stream).await {
                                Ok(stream) => Conn::Tls(Box::new(stream)),
                                Err(error) => {
                                    eprintln!("http tls {peer}: {error}");
                                    return;
                                }
                            },
                            None => return,
                        }
                    } else {
                        Conn::plain(stream)
                    };
                    if let Err(error) = handle_connection(app, conn).await {
                        eprintln!("http {peer}: {error}");
                    }
                });
            }
            Err(error) => {
                eprintln!("http accept: {error}");
                monoio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

async fn handle_connection(app: Arc<App>, conn: Conn) -> std::io::Result<()> {
    let mut conn = BufferedConn::new(conn);
    loop {
        let Some(request) = read_request(&mut conn).await? else {
            return Ok(());
        };
        if let Err(error) = route(&app, &mut conn, &request).await {
            send_error(&mut conn, error.status, error.code, &error.message).await?;
        }
        if !conn.keep_alive() {
            return Ok(());
        }
    }
}

async fn read_request(conn: &mut BufferedConn) -> std::io::Result<Option<HttpRequest>> {
    let headers_bytes = match conn.read_headers(MAX_HEADERS).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    request
        .parse(&headers_bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    let method = request.method.unwrap_or("GET").to_string();
    let path = request.path.unwrap_or("/").to_string();
    let version = request.version.unwrap_or(1);
    let mut header_map = HashMap::new();
    for header in request.headers {
        let value = String::from_utf8_lossy(header.value).to_string();
        header_map.insert(header.name.to_ascii_lowercase(), value);
    }
    let content_length = header_map
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    if content_length > MAX_BODY {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request body too large",
        ));
    }
    let connection = header_map
        .get("connection")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let keep_alive = if version >= 1 {
        connection != "close"
    } else {
        connection == "keep-alive"
    };
    conn.set_keep_alive(keep_alive);
    let body = conn.read_exact(content_length, MAX_BODY).await?;
    Ok(Some(HttpRequest {
        method,
        path: path.split('?').next().unwrap_or("/").to_string(),
        headers: header_map,
        body,
    }))
}

#[derive(Debug)]
struct ApiError {
    status: u16,
    code: u32,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: 400,
            code: 400,
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: 401,
            code: 401,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: 404,
            code: 404,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: 500,
            code: 500,
            message: message.into(),
        }
    }

    fn too_large(message: impl Into<String>) -> Self {
        Self {
            status: 413,
            code: 413,
            message: message.into(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: 403,
            code: 403,
            message: message.into(),
        }
    }
}

impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::NotFound(message) => Self::not_found(message),
            other => Self::internal(other.to_string()),
        }
    }
}

impl From<AuthError> for ApiError {
    fn from(error: AuthError) -> Self {
        Self::unauthorized(error.to_string())
    }
}

async fn route(app: &App, conn: &mut BufferedConn, request: &HttpRequest) -> Result<(), ApiError> {
    if request.method == "GET" && request.path == "/health" {
        let body = format!(
            "{{\"status\":\"ok\",\"messages\":{},\"accounts\":{}}}",
            app.db.index_size(),
            app.registry.accounts().len()
        );
        return send_response(conn, 200, "application/json", body.as_bytes())
            .await
            .map_err(|error| ApiError::internal(error.to_string()));
    }

    if request.path == "/v1/auth/login" && request.method == "POST" {
        let auth = AuthRequest::decode(&request.body)
            .map_err(|error| ApiError::bad_request(error.to_string()))?;
        let account = app
            .registry
            .authenticate(&auth.account_id, &auth.password)?;
        let token = app.registry.issue_token(&account.id);
        let response = AuthResponse {
            token,
            refresh_token: None,
            expires_at: crate::auth::now_millis() + app.registry.token_ttl_seconds() * 1000,
            account: to_proto_account(&account),
        };
        return send_proto(conn, 200, response)
            .await
            .map_err(|error| ApiError::internal(error.to_string()));
    }

    if request.path.starts_with("/v1/admin/") {
        let Some(expected) = app.config.server.admin_token.as_deref() else {
            return Err(ApiError::forbidden("admin API is disabled"));
        };
        let provided = request
            .headers
            .get("x-admin-token")
            .map(String::as_str)
            .unwrap_or("");
        if !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
            return Err(ApiError::forbidden("invalid admin token"));
        }
        return match request.path.as_str() {
            "/v1/admin/snapshot" => {
                app.db
                    .snapshot()
                    .await
                    .map_err(|error| ApiError::internal(error.to_string()))?;
                send_proto(conn, 200, AckResponse { affected: 1 })
                    .await
                    .map_err(|error| ApiError::internal(error.to_string()))
            }
            "/v1/admin/compact" => {
                let stats = app
                    .db
                    .compact()
                    .await
                    .map_err(|error| ApiError::internal(error.to_string()))?;
                send_proto(
                    conn,
                    200,
                    AckResponse {
                        affected: stats.messages as u64,
                    },
                )
                .await
                .map_err(|error| ApiError::internal(error.to_string()))
            }
            _ => Err(ApiError::not_found("unknown admin endpoint")),
        };
    }

    let token = bearer_token(request).ok_or_else(|| ApiError::unauthorized("missing token"))?;
    let account = app.registry.validate_token(&token)?;

    if request.method == "GET" && request.path.starts_with("/v1/attachments/") {
        let mut parts = request
            .path
            .trim_start_matches("/v1/attachments/")
            .splitn(2, '/');
        let message_id = parts.next().unwrap_or_default();
        let attachment_id = parts.next().unwrap_or_default();
        let message = app
            .db
            .get_message(message_id)?
            .ok_or_else(|| ApiError::not_found("message not found"))?;
        if message.account_id != account.id {
            return Err(ApiError::not_found("message not found"));
        }
        let index = attachment_id
            .parse::<usize>()
            .map_err(|_| ApiError::bad_request("invalid attachment id"))?;
        let attachment = message
            .attachments
            .get(index)
            .ok_or_else(|| ApiError::not_found("attachment not found"))?;
        return send_attachment(conn, attachment)
            .await
            .map_err(|error| ApiError::internal(error.to_string()));
    }

    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/v1/auth/logout") => {
            app.registry.revoke_token(&token);
            send_proto(conn, 200, AckResponse { affected: 1 })
                .await
                .map_err(|error| ApiError::internal(error.to_string()))
        }
        ("POST", "/v1/mailboxes") => {
            let request = MailboxListRequest::decode(&request.body)
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            ensure_account(&account, &request.account_id)?;
            app.db
                .ensure_default_folders(&account.id)
                .await
                .map_err(|error| ApiError::internal(error.to_string()))?;
            let stats = app.db.account_stats(&account.id);
            let mailboxes = app
                .db
                .list_folders(&account.id)
                .into_iter()
                .map(|folder| {
                    let mailbox = stats
                        .mailboxes
                        .get(&folder.name)
                        .cloned()
                        .unwrap_or_default();
                    Mailbox {
                        id: folder.name.to_ascii_lowercase(),
                        account_id: account.id.clone(),
                        name: folder.name,
                        role: folder.role,
                        total: mailbox.total,
                        unread: mailbox.unread,
                    }
                })
                .collect();
            send_proto(conn, 200, MailboxListResponse { mailboxes })
                .await
                .map_err(|error| ApiError::internal(error.to_string()))
        }
        ("POST", "/v1/folders/list") => {
            let request = FolderListRequest::decode(&request.body)
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            ensure_account(&account, &request.account_id)?;
            app.db
                .ensure_default_folders(&account.id)
                .await
                .map_err(|error| ApiError::internal(error.to_string()))?;
            let stats = app.db.account_stats(&account.id);
            let mailboxes = app
                .db
                .list_folders(&account.id)
                .into_iter()
                .map(|folder| {
                    let mailbox = stats
                        .mailboxes
                        .get(&folder.name)
                        .cloned()
                        .unwrap_or_default();
                    Mailbox {
                        id: folder.name.to_ascii_lowercase(),
                        account_id: account.id.clone(),
                        name: folder.name,
                        role: folder.role,
                        total: mailbox.total,
                        unread: mailbox.unread,
                    }
                })
                .collect();
            send_proto(conn, 200, MailboxListResponse { mailboxes })
                .await
                .map_err(|error| ApiError::internal(error.to_string()))
        }
        ("POST", "/v1/folders/create") => {
            let request = FolderCreateRequest::decode(&request.body)
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            ensure_account(&account, &request.account_id)?;
            app.db
                .create_folder(&account.id, &request.name)
                .await
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            send_proto(conn, 200, AckResponse { affected: 1 })
                .await
                .map_err(|error| ApiError::internal(error.to_string()))
        }
        ("POST", "/v1/folders/rename") => {
            let request = FolderRenameRequest::decode(&request.body)
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            ensure_account(&account, &request.account_id)?;
            let affected = app
                .db
                .rename_folder(&account.id, &request.old_name, &request.new_name)
                .await
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            send_proto(
                conn,
                200,
                AckResponse {
                    affected: affected as u64,
                },
            )
            .await
            .map_err(|error| ApiError::internal(error.to_string()))
        }
        ("POST", "/v1/folders/delete") => {
            let request = FolderDeleteRequest::decode(&request.body)
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            ensure_account(&account, &request.account_id)?;
            let affected = app
                .db
                .delete_folder(&account.id, &request.name)
                .await
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            send_proto(
                conn,
                200,
                AckResponse {
                    affected: affected as u64,
                },
            )
            .await
            .map_err(|error| ApiError::internal(error.to_string()))
        }
        ("POST", "/v1/messages/list") => {
            let request = ListRequest::decode(&request.body)
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            ensure_account(&account, &request.account_id)?;
            let mut query = SearchQuery::new()
                .account(account.id.clone())
                .limit(request.limit.clamp(1, 500) as usize)
                .offset(request.offset as usize)
                .include_deleted(request.include_deleted);
            if let Some(ref mailbox) = request.mailbox {
                query = query.mailbox(mailbox.clone());
            }
            let stats = app.db.account_stats(&account.id);
            let total = request
                .mailbox
                .as_deref()
                .and_then(|mailbox| stats.mailboxes.get(mailbox))
                .map_or(stats.total, |mailbox| mailbox.total);
            let hits = app.db.search(&query);
            let messages = hits
                .iter()
                .filter_map(|hit| app.db.get_message(&hit.id).ok().flatten())
                .map(|message| message_to_meta(&message))
                .collect::<Vec<_>>();
            send_proto(conn, 200, ListResponse { messages, total })
                .await
                .map_err(|error| ApiError::internal(error.to_string()))
        }
        ("POST", "/v1/messages/get") => {
            let request = GetMessageRequest::decode(&request.body)
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            let message = app
                .db
                .get_message(&request.id)?
                .ok_or_else(|| ApiError::not_found("message not found"))?;
            if message.account_id != account.id {
                return Err(ApiError::not_found("message not found"));
            }
            send_proto(
                conn,
                200,
                GetMessageResponse {
                    meta: message_to_meta(&message),
                    body: message_to_body(&message),
                },
            )
            .await
            .map_err(|error| ApiError::internal(error.to_string()))
        }
        ("POST", "/v1/search") => {
            let started = Instant::now();
            let request = SearchRequest::decode(&request.body)
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            ensure_account(&account, &request.account_id)?;
            let mut query = SearchQuery::new()
                .account(account.id.clone())
                .limit(request.limit.clamp(1, 500) as usize)
                .offset(request.offset as usize)
                .include_deleted(request.include_deleted);
            if !request.query.is_empty() {
                query = query.text(request.query);
            }
            if let Some(subject) = request.subject {
                query = query.subject(subject);
            }
            if let Some(body) = request.body {
                query = query.body(body);
            }
            if let Some(from) = request.from {
                query = query.from(from);
            }
            if let Some(mailbox) = request.mailbox {
                query = query.mailbox(mailbox);
            }
            let hits = app.db.search(&query);
            let mut proto_hits = Vec::new();
            for hit in &hits {
                if let Ok(Some(message)) = app.db.get_message(&hit.id) {
                    proto_hits.push(ProtoSearchHit {
                        message: message_to_meta(&message),
                        score: hit.score,
                        snippet: hit.snippet.clone(),
                    });
                }
            }
            send_proto(
                conn,
                200,
                SearchResponse {
                    total: proto_hits.len() as u64,
                    took_micros: started.elapsed().as_micros() as u64,
                    hits: proto_hits,
                },
            )
            .await
            .map_err(|error| ApiError::internal(error.to_string()))
        }
        ("POST", "/v1/messages/flags") => {
            let request = FlagsRequest::decode(&request.body)
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            ensure_account(&account, &request.account_id)?;
            let mut affected = 0u64;
            for id in request.ids {
                let Some(message) = app.db.get_message(&id)? else {
                    continue;
                };
                if message.account_id != account.id {
                    continue;
                }
                let flags = match request.mode {
                    flags_mode::ADD => message.flags | request.flags,
                    flags_mode::REMOVE => message.flags & !request.flags,
                    _ => request.flags,
                };
                app.db.update_flags(&id, flags).await?;
                affected += 1;
            }
            send_proto(conn, 200, AckResponse { affected })
                .await
                .map_err(|error| ApiError::internal(error.to_string()))
        }
        ("POST", "/v1/messages/delete") => {
            let request = DeleteRequest::decode(&request.body)
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            ensure_account(&account, &request.account_id)?;
            let mut affected = 0u64;
            for id in request.ids {
                if let Some(message) = app.db.get_message(&id)? {
                    if message.account_id == account.id {
                        app.db.delete_message(&id).await?;
                        affected += 1;
                    }
                }
            }
            send_proto(conn, 200, AckResponse { affected })
                .await
                .map_err(|error| ApiError::internal(error.to_string()))
        }
        ("POST", "/v1/messages/move") => {
            let request = MoveRequest::decode(&request.body)
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            ensure_account(&account, &request.account_id)?;
            let mut affected = 0u64;
            for id in request.ids {
                if let Some(message) = app.db.get_message(&id)? {
                    if message.account_id == account.id {
                        app.db
                            .move_message(&id, &account.id, &request.mailbox)
                            .await?;
                        affected += 1;
                    }
                }
            }
            send_proto(conn, 200, AckResponse { affected })
                .await
                .map_err(|error| ApiError::internal(error.to_string()))
        }
        ("POST", "/v1/send") => {
            let request = SendRequest::decode(&request.body)
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            ensure_account(&account, &request.account_id)?;
            if request.raw.is_empty() {
                return Err(ApiError::bad_request("empty message"));
            }
            let (message_id, queued) = send_raw(
                app,
                &account,
                &request.envelope_from,
                &request.envelope_to,
                request.mailbox.as_deref().unwrap_or("Sent"),
                request.raw,
            )
            .await?;
            send_proto(conn, 200, SendResponse { message_id, queued })
                .await
                .map_err(|error| ApiError::internal(error.to_string()))
        }
        ("POST", "/v1/send/attachments") => {
            let request = SendWithAttachmentsRequest::decode(&request.body)
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            ensure_account(&account, &request.account_id)?;
            let attachment_bytes = request
                .attachments
                .iter()
                .map(|attachment| attachment.data.len() as u64)
                .sum::<u64>();
            if attachment_bytes > 64 * 1024 * 1024 {
                return Err(ApiError::too_large("attachments are too large"));
            }
            let raw = crate::mime_build::build_message(
                &account.email,
                &request.envelope_to,
                &request.subject,
                &request.text,
                request.html.as_deref(),
                &request.attachments,
            )
            .map_err(ApiError::bad_request)?;
            let (message_id, queued) = send_raw(
                app,
                &account,
                &request.envelope_from,
                &request.envelope_to,
                "Sent",
                raw,
            )
            .await?;
            send_proto(conn, 200, SendResponse { message_id, queued })
                .await
                .map_err(|error| ApiError::internal(error.to_string()))
        }
        _ => Err(ApiError::not_found("unknown endpoint")),
    }
}

async fn send_raw(
    app: &App,
    account: &Account,
    envelope_from: &str,
    envelope_to: &[String],
    mailbox: &str,
    raw: Vec<u8>,
) -> Result<(String, bool), ApiError> {
    let id = Uuid::new_v4().to_string();
    let message = parse_message(&raw, account.id.clone(), mailbox, id.clone())
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    app.db.append_message(message).await?;
    let mut queued = false;
    if let Some(outbound) = app.outbound.as_ref() {
        for recipient in envelope_to {
            let mut job = crate::outbound::OutboundQueue::job(
                envelope_from.to_string(),
                recipient.clone(),
                raw.clone(),
            );
            job.message_id = id.clone();
            if app.registry.account(recipient).is_none() && outbound.enqueue(job) {
                queued = true;
            }
        }
    }
    for recipient in envelope_to {
        if let Some(target) = app.registry.account(recipient) {
            if target.id != account.id {
                let copy =
                    parse_message(&raw, target.id.clone(), "INBOX", Uuid::new_v4().to_string())
                        .map_err(|error| ApiError::bad_request(error.to_string()))?;
                app.db.append_message(copy).await?;
            }
        }
    }
    Ok((id, queued))
}

async fn send_attachment(
    conn: &mut BufferedConn,
    attachment: &tide_core::Attachment,
) -> std::io::Result<()> {
    let filename = attachment
        .filename
        .chars()
        .filter(|ch| !matches!(ch, '"' | '\\' | '\r' | '\n'))
        .collect::<String>();
    let content_type = if attachment.content_type.is_empty() {
        "application/octet-stream"
    } else {
        &attachment.content_type
    };
    let content_type = content_type
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '+' | '-' | '.'))
        .collect::<String>();
    let content_type = if content_type.is_empty() {
        "application/octet-stream"
    } else {
        &content_type
    };
    let connection = if conn.keep_alive() {
        "keep-alive"
    } else {
        "close"
    };
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nContent-Disposition: attachment; filename=\"{filename}\"\r\nConnection: {connection}\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
        attachment.data.len()
    );
    conn.write_all(headers.as_bytes()).await?;
    conn.write_all(&attachment.data).await
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn ensure_account(account: &Account, requested: &str) -> Result<(), ApiError> {
    if account.id.eq_ignore_ascii_case(requested) {
        Ok(())
    } else {
        Err(ApiError::unauthorized("account mismatch"))
    }
}

fn bearer_token(request: &HttpRequest) -> Option<String> {
    request
        .headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_string)
}

fn to_proto_account(account: &Account) -> ProtoAccount {
    ProtoAccount {
        id: account.id.clone(),
        email: account.email.clone(),
        display_name: account.display_name.clone(),
        created_at: 0,
        quota_bytes: 0,
    }
}

async fn send_proto<T: SilentProto>(
    conn: &mut BufferedConn,
    status: u16,
    value: T,
) -> std::io::Result<()> {
    let body = value
        .encode()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    send_response(conn, status, "application/silent", &body).await
}

async fn send_error(
    conn: &mut BufferedConn,
    status: u16,
    code: u32,
    message: &str,
) -> std::io::Result<()> {
    let error = ErrorResponse {
        code,
        message: message.to_string(),
        retryable: status >= 500,
    };
    let body = error
        .encode()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    send_response(conn, status, "application/silent", &body).await
}

async fn send_response(
    conn: &mut BufferedConn,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = status_text(status);
    let connection = if conn.keep_alive() {
        "keep-alive"
    } else {
        "close"
    };
    let headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: {connection}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: Authorization, Content-Type, X-Admin-Token\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\n\r\n",
        body.len()
    );
    conn.write_all(headers.as_bytes()).await?;
    if !body.is_empty() {
        conn.write_all(body).await?;
    }
    Ok(())
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        204 => "No Content",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}
