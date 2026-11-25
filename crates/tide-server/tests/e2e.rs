use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use silent_protocol::SilentProto;
use tide_proto::{
    AttachmentData, AuthRequest, AuthResponse, Cursor, FlagsRequest, FolderCreateRequest,
    FolderListRequest, GetMessageRequest, GetMessageResponse, ListRequest, ListResponse,
    MailboxListResponse, PutMessagePayload, SearchRequest, SearchResponse, SendResponse,
    SendWithAttachmentsRequest, SyncOperation, flags_mode, op_kind,
};
use tide_smtp::SmtpClient;
use tide_sync::{ClientEvent, ClientSession};

struct Server {
    child: Child,
    http: String,
    smtp: String,
    sync: String,
    _directory: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start_server() -> Server {
    let directory = tempfile::tempdir().unwrap();
    let http_port = free_port();
    let smtp_port = free_port();
    let sync_port = free_port();
    let config = format!(
        r#"
[server]
hostname = "mail.local"
data_path = "{data}"
data_lanes = 2
lane_capacity_mb = 8
workers = 1
http_addr = "127.0.0.1:{http_port}"
smtp_addr = "127.0.0.1:{smtp_port}"
submission_addr = ""
sync_addr = "127.0.0.1:{sync_port}"
token_ttl_hours = 24
outbound_enabled = false
admin_token = "admin"

[tls]
self_signed = false

[email_auth]
enabled = false

[spam]
enabled = true
threshold = 1.0
reject_threshold = 100.0

[[accounts]]
email = "alice@mail.local"
password = "secret"
name = "Alice"
"#,
        data = directory.path().join("mail.tide").display()
    );
    let config_path = directory.path().join("tide.toml");
    std::fs::write(&config_path, config).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_tide"))
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let server = Server {
        child,
        http: format!("127.0.0.1:{http_port}"),
        smtp: format!("127.0.0.1:{smtp_port}"),
        sync: format!("127.0.0.1:{sync_port}"),
        _directory: directory,
    };
    for _ in 0..100 {
        if TcpStream::connect(&server.http).is_ok() {
            return server;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("server did not start");
}

fn http_request(
    address: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &[u8],
) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(address).unwrap();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(token) = token {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let headers = String::from_utf8_lossy(&response[..split]);
    let status = headers
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<u16>()
        .unwrap();
    (status, response[split + 4..].to_vec())
}

fn admin_request(address: &str, path: &str) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(address).unwrap();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nX-Admin-Token: admin\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let headers = String::from_utf8_lossy(&response[..split]);
    let status = headers
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<u16>()
        .unwrap();
    (status, response[split + 4..].to_vec())
}

fn login(server: &Server) -> (String, AuthResponse) {
    let request = AuthRequest {
        account_id: "alice@mail.local".into(),
        password: "secret".into(),
        device_id: "e2e".into(),
        device_name: "E2E".into(),
    };
    let (status, body) = http_request(
        &server.http,
        "POST",
        "/v1/auth/login",
        None,
        &request.encode().unwrap(),
    );
    assert_eq!(status, 200);
    let response = AuthResponse::decode(&body).unwrap();
    (response.token.clone(), response)
}

fn write_frame(stream: &mut TcpStream, frame: tide_proto::Frame) {
    stream.write_all(&frame.encode().unwrap()).unwrap();
}

fn read_frame(stream: &mut TcpStream) -> tide_proto::Frame {
    let mut header = [0u8; 16];
    stream.read_exact(&mut header).unwrap();
    let length = tide_proto::frame::frame_length(&header).unwrap();
    let mut bytes = header.to_vec();
    bytes.resize(length, 0);
    stream.read_exact(&mut bytes[16..]).unwrap();
    tide_proto::Frame::decode(&bytes).unwrap()
}

#[test]
fn smtp_http_and_sync_end_to_end() {
    let server = start_server();
    let (token, _) = login(&server);
    let create = FolderCreateRequest {
        account_id: "alice@mail.local".into(),
        name: "Projects".into(),
    };
    assert_eq!(
        http_request(
            &server.http,
            "POST",
            "/v1/folders/create",
            Some(&token),
            &create.encode().unwrap(),
        )
        .0,
        200
    );
    let list = FolderListRequest {
        account_id: "alice@mail.local".into(),
    };
    let (status, body) = http_request(
        &server.http,
        "POST",
        "/v1/folders/list",
        Some(&token),
        &list.encode().unwrap(),
    );
    assert_eq!(status, 200);
    let folders = MailboxListResponse::decode(&body).unwrap();
    assert!(
        folders
            .mailboxes
            .iter()
            .any(|folder| folder.name == "Projects")
    );
    assert!(folders.mailboxes.iter().any(|folder| folder.name == "Junk"));

    let mut smtp = SmtpClient::connect(server.smtp.as_str()).unwrap();
    assert_eq!(smtp.read_reply().unwrap().code, 220);
    smtp.ehlo("client.local").unwrap();
    let raw = b"From: bob@example.com\r\nTo: alice@mail.local\r\nSubject: E2E sync\r\nDate: Tue, 25 Nov 2025 12:00:00 +0000\r\nMessage-ID: <e2e@example.com>\r\n\r\nHello E2E body\r\n";
    smtp.send_message("bob@example.com", &["alice@mail.local".into()], raw)
        .unwrap();
    smtp.quit().unwrap();

    let search = SearchRequest {
        account_id: "alice@mail.local".into(),
        query: "e2e".into(),
        limit: 10,
        ..SearchRequest::default()
    };
    let (status, body) = http_request(
        &server.http,
        "POST",
        "/v1/search",
        Some(&token),
        &search.encode().unwrap(),
    );
    assert_eq!(
        status,
        200,
        "search body: {:?}",
        String::from_utf8_lossy(&body)
    );
    let results = SearchResponse::decode(&body).unwrap();
    assert_eq!(results.hits.len(), 1);
    assert_eq!(results.hits[0].message.subject, "E2E sync");
    let id = results.hits[0].message.id.clone();

    let get = GetMessageRequest { id: id.clone() };
    let (status, body) = http_request(
        &server.http,
        "POST",
        "/v1/messages/get",
        Some(&token),
        &get.encode().unwrap(),
    );
    assert_eq!(status, 200);
    let message = GetMessageResponse::decode(&body).unwrap();
    let raw = String::from_utf8_lossy(&message.body.raw);
    assert!(raw.contains("Hello E2E body"));
    assert!(raw.contains("Received: from"));
    assert!(raw.contains("Return-Path: <bob@example.com>"));
    assert!(raw.contains("Delivered-To: alice@mail.local"));

    let spam_raw = b"From: spam@example.com\r\nTo: alice@mail.local\r\nSubject: WINNER\r\nDate: Tue, 25 Nov 2025 12:10:00 +0000\r\nMessage-ID: <spam@example.com>\r\n\r\nclick here to claim your prize\r\n";
    smtp = SmtpClient::connect(server.smtp.as_str()).unwrap();
    assert_eq!(smtp.read_reply().unwrap().code, 220);
    smtp.ehlo("client.local").unwrap();
    smtp.send_message("spam@example.com", &["alice@mail.local".into()], spam_raw)
        .unwrap();
    smtp.quit().unwrap();
    let junk = ListRequest {
        account_id: "alice@mail.local".into(),
        mailbox: Some("Junk".into()),
        limit: 10,
        ..ListRequest::default()
    };
    let (status, body) = http_request(
        &server.http,
        "POST",
        "/v1/messages/list",
        Some(&token),
        &junk.encode().unwrap(),
    );
    assert_eq!(status, 200);
    let junk = ListResponse::decode(&body).unwrap();
    assert_eq!(junk.messages.len(), 1);
    assert_eq!(junk.messages[0].subject, "WINNER");

    let list = ListRequest {
        account_id: "alice@mail.local".into(),
        mailbox: Some("INBOX".into()),
        limit: 10,
        ..ListRequest::default()
    };
    let (status, body) = http_request(
        &server.http,
        "POST",
        "/v1/messages/list",
        Some(&token),
        &list.encode().unwrap(),
    );
    assert_eq!(status, 200);
    let list = ListResponse::decode(&body).unwrap();
    assert_eq!(list.messages.len(), 1);

    let flags = FlagsRequest {
        account_id: "alice@mail.local".into(),
        ids: vec![id.clone()],
        flags: tide_core::flags::SEEN,
        mode: flags_mode::ADD,
    };
    let (status, _) = http_request(
        &server.http,
        "POST",
        "/v1/messages/flags",
        Some(&token),
        &flags.encode().unwrap(),
    );
    assert_eq!(status, 200);

    let mut stream = TcpStream::connect(server.sync.as_str()).unwrap();
    let (mut client, hello) = ClientSession::new("e2e-device", "e2e");
    write_frame(&mut stream, hello);
    let event = client.handle(read_frame(&mut stream)).unwrap();
    assert!(matches!(event, ClientEvent::Hello(_)));
    let auth = client
        .auth_frame("alice@mail.local", token.clone(), "e2e-device")
        .unwrap();
    write_frame(&mut stream, auth);
    let event = client.handle(read_frame(&mut stream)).unwrap();
    assert!(matches!(event, ClientEvent::Auth(_)));
    let pull = client
        .pull_frame_at("alice@mail.local", Cursor { lane: 1, seq: 0 }, 100, None)
        .unwrap();
    write_frame(&mut stream, pull);
    let event = client.handle(read_frame(&mut stream)).unwrap();
    match event {
        ClientEvent::Changes(changes) => {
            assert!(!changes.changes.is_empty());
            let change = changes
                .changes
                .iter()
                .find(|change| change.message_id == id)
                .expect("message change");
            assert_eq!(
                change.meta.as_ref().map(|meta| meta.subject.as_str()),
                Some("E2E sync")
            );
        }
        other => panic!("unexpected sync event: {other:?}"),
    }

    let push = client
        .push_frame(
            "alice@mail.local",
            "e2e-flags",
            vec![SyncOperation {
                kind: op_kind::FLAGS,
                message_id: id.clone(),
                flags: tide_core::flags::FLAGGED,
                mailbox: String::new(),
                payload: Vec::new(),
            }],
        )
        .unwrap();
    write_frame(&mut stream, push);
    match client.handle(read_frame(&mut stream)).unwrap() {
        ClientEvent::Push(result) => {
            assert_eq!(result.applied, 1);
            assert!(result.rejected.is_empty());
        }
        other => panic!("unexpected push event: {other:?}"),
    }
    let (status, body) = http_request(
        &server.http,
        "POST",
        "/v1/messages/get",
        Some(&token),
        &GetMessageRequest { id: id.clone() }.encode().unwrap(),
    );
    assert_eq!(status, 200);
    let message = GetMessageResponse::decode(&body).unwrap();
    assert_ne!(message.meta.flags & tide_core::flags::FLAGGED, 0);

    let raw = b"From: push@example.com\r\nTo: alice@mail.local\r\nSubject: Sync pushed\r\nDate: Tue, 25 Nov 2025 13:00:00 +0000\r\nMessage-ID: <push@example.com>\r\n\r\nPushed via sync\r\n";
    let payload = PutMessagePayload {
        account_id: "alice@mail.local".into(),
        flags: 0,
        mailbox: "INBOX".into(),
        message_id: String::new(),
        raw: raw.to_vec(),
    };
    let push = client
        .push_frame(
            "alice@mail.local",
            "e2e-put",
            vec![SyncOperation {
                kind: op_kind::PUT_MESSAGE,
                message_id: String::new(),
                flags: 0,
                mailbox: "INBOX".into(),
                payload: payload.encode().unwrap(),
            }],
        )
        .unwrap();
    write_frame(&mut stream, push);
    match client.handle(read_frame(&mut stream)).unwrap() {
        ClientEvent::Push(result) => {
            assert_eq!(result.applied, 1);
            assert!(result.rejected.is_empty());
        }
        other => panic!("unexpected put event: {other:?}"),
    }
    let search = SearchRequest {
        account_id: "alice@mail.local".into(),
        query: "pushed".into(),
        limit: 10,
        ..SearchRequest::default()
    };
    let (status, body) = http_request(
        &server.http,
        "POST",
        "/v1/search",
        Some(&token),
        &search.encode().unwrap(),
    );
    assert_eq!(status, 200);
    let results = SearchResponse::decode(&body).unwrap();
    assert_eq!(results.hits.len(), 1);
    assert_eq!(results.hits[0].message.subject, "Sync pushed");

    let attachment = SendWithAttachmentsRequest {
        account_id: "alice@mail.local".into(),
        attachments: vec![AttachmentData {
            filename: "report.txt".into(),
            content_type: "text/plain".into(),
            data: b"attachment-bytes".to_vec(),
        }],
        envelope_from: "alice@mail.local".into(),
        envelope_to: vec!["alice@mail.local".into()],
        html: None,
        subject: "With attachment".into(),
        text: "See attached".into(),
    };
    let (status, body) = http_request(
        &server.http,
        "POST",
        "/v1/send/attachments",
        Some(&token),
        &attachment.encode().unwrap(),
    );
    assert_eq!(status, 200);
    let sent = SendResponse::decode(&body).unwrap();
    let (status, body) = http_request(
        &server.http,
        "GET",
        &format!("/v1/attachments/{}/0", sent.message_id),
        Some(&token),
        b"",
    );
    assert_eq!(status, 200);
    assert_eq!(body, b"attachment-bytes");

    assert_eq!(admin_request(&server.http, "/v1/admin/snapshot").0, 200);
    assert_eq!(admin_request(&server.http, "/v1/admin/compact").0, 200);
    let (status, body) = http_request(
        &server.http,
        "POST",
        "/v1/search",
        Some(&token),
        &search.encode().unwrap(),
    );
    assert_eq!(status, 200);
    assert_eq!(SearchResponse::decode(&body).unwrap().hits.len(), 1);
}
