use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use silent_protocol::SilentProto;
use tide_proto::{
    AuthRequest, AuthResponse, Cursor, FlagsRequest, GetMessageRequest, GetMessageResponse,
    ListRequest, ListResponse, SearchRequest, SearchResponse, SyncOperation, flags_mode, op_kind,
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

[tls]
self_signed = false

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
        .stderr(Stdio::null())
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
    assert!(String::from_utf8_lossy(&message.body.raw).contains("Hello E2E body"));

    let list = ListRequest {
        account_id: "alice@mail.local".into(),
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
}
