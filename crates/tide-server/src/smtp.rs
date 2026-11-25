use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::Arc;

use monoio::net::{TcpListener, TcpStream};
use rustls::{ClientConnection, StreamOwned};
use tide_core::parse_message;
use tide_smtp::{Action, SmtpConfig, SmtpSession};
use uuid::Uuid;

use crate::app::App;
use crate::config::BurlSettings;
use crate::net::{BufferedConn, Conn};

pub async fn serve_smtp(
    app: Arc<App>,
    listener: TcpListener,
    submission: bool,
    implicit_tls: bool,
    lmtp: bool,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let app = Arc::clone(&app);
                monoio::spawn(async move {
                    if let Err(error) =
                        handle_connection(app, stream, submission, implicit_tls, lmtp, peer.ip())
                            .await
                    {
                        eprintln!("smtp {peer}: {error}");
                    }
                });
            }
            Err(error) => {
                eprintln!("smtp accept: {error}");
                monoio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle_connection(
    app: Arc<App>,
    stream: TcpStream,
    submission: bool,
    implicit_tls: bool,
    lmtp: bool,
    peer: IpAddr,
) -> std::io::Result<()> {
    let conn = if implicit_tls {
        let Some(acceptor) = app.tls.as_ref() else {
            return Ok(());
        };
        Conn::Tls(Box::new(
            acceptor
                .accept(stream)
                .await
                .map_err(|error| std::io::Error::other(error.to_string()))?,
        ))
    } else {
        Conn::plain(stream)
    };
    let mut conn = BufferedConn::new(conn);
    let mut config = if submission {
        SmtpConfig::submission(app.config.server.hostname.clone())
    } else {
        SmtpConfig {
            hostname: app.config.server.hostname.clone(),
            lmtp,
            require_auth: false,
            ..SmtpConfig::default()
        }
    };
    config.enable_burl_imap = app.config.burl.imap_enabled;
    config.enable_starttls = app.tls.is_some() && !implicit_tls;
    config.allow_insecure_auth = app.tls.is_none();
    let (mut session, greeting) = SmtpSession::new(config);
    if implicit_tls {
        session.tls_established();
    }
    conn.write_all(&greeting.to_wire()).await?;

    loop {
        let Some(line) = conn.read_line(64 * 1024).await? else {
            return Ok(());
        };
        let mut actions = VecDeque::from(session.feed_line(&line));
        while let Some(action) = actions.pop_front() {
            match action {
                Action::Reply(reply) => {
                    conn.write_all(&reply.to_wire()).await?;
                }
                Action::StartTls => {
                    let Some(acceptor) = app.tls.as_ref() else {
                        return Ok(());
                    };
                    if let Err(error) = conn.start_tls(acceptor).await {
                        eprintln!("smtp starttls: {error}");
                        return Ok(());
                    }
                    session.tls_established();
                }
                Action::AuthChallenge { challenge, .. } => {
                    conn.write_all(format!("334 {challenge}\r\n").as_bytes())
                        .await?;
                }
                Action::AuthComplete {
                    username, secret, ..
                } => {
                    let reply = match app.registry.authenticate(&username, &secret) {
                        Ok(account) => session.auth_success(account.email),
                        Err(_) => session.auth_failure(),
                    };
                    conn.write_all(&reply.to_wire()).await?;
                }
                Action::FetchBurl { url, last } => {
                    let limit = 64 * 1024 * 1024;
                    let burl = app.config.burl.clone();
                    let result =
                        monoio::spawn_blocking(move || fetch_burl(&url, limit, &burl)).await;
                    match result {
                        Ok(Ok(chunk)) => {
                            actions.extend(session.feed_burl_chunk(&chunk, last));
                        }
                        Ok(Err((code, message))) => {
                            let reply = tide_smtp::Reply::new(code, message);
                            conn.write_all(&reply.to_wire()).await?;
                        }
                        Err(_) => {
                            let reply =
                                tide_smtp::Reply::new(451, "4.4.1 BURL fetch was cancelled");
                            conn.write_all(&reply.to_wire()).await?;
                        }
                    }
                }
                Action::ReadBdat { size, last } => {
                    let chunk = conn.read_exact(size, 64 * 1024 * 1024).await?;
                    actions.extend(session.feed_bdat_chunk(&chunk, last));
                }
                Action::Deliver { envelope, data } => {
                    let helo = session.helo().unwrap_or("unknown").to_string();
                    if lmtp {
                        let replies =
                            deliver_lmtp(&app, submission, peer, helo, envelope, data).await;
                        for reply in replies {
                            conn.write_all(&reply.to_wire()).await?;
                        }
                    } else {
                        let reply = deliver(&app, submission, peer, helo, envelope, data).await;
                        conn.write_all(&reply.to_wire()).await?;
                    }
                }
                Action::Close => return Ok(()),
            }
        }
    }
}

fn received_hops(raw: &[u8]) -> usize {
    raw.split(|byte| *byte == b'\n')
        .filter(|line| {
            line.get(..9)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"Received:"))
        })
        .count()
}

fn add_trace_headers(
    raw: &[u8],
    hostname: &str,
    helo: &str,
    peer: IpAddr,
    from: &str,
    recipient: &str,
    id: &str,
) -> Vec<u8> {
    let date = mail_parser::DateTime::from_timestamp(crate::auth::now_millis() / 1000).to_rfc822();
    let clean = |value: &str| value.replace(['\r', '\n'], " ");
    let header = format!(
        "Received: from {} ([{}]) by {} with ESMTP id {} for <{}>; {}\r\n         Return-Path: <{}>\r\n         Delivered-To: {}\r\n",
        clean(helo),
        peer,
        clean(hostname),
        clean(id),
        clean(recipient),
        date,
        clean(from),
        clean(recipient)
    );
    let mut out = header.into_bytes();
    out.extend_from_slice(raw);
    out
}

struct ImapTarget {
    host: String,
    port: u16,
    mailbox: String,
    uid: u32,
}

fn parse_imap_url(url: &str, burl: &BurlSettings) -> Result<ImapTarget, (u16, String)> {
    if !burl.imap_enabled {
        return Err((554, "5.7.8 IMAP BURL is disabled".to_string()));
    }
    if burl.imap_user.is_empty() {
        return Err((
            554,
            "5.7.8 IMAP BURL credentials are not configured".to_string(),
        ));
    }
    let parsed =
        reqwest::Url::parse(url).map_err(|_| (554, "5.7.1 Invalid BURL URL".to_string()))?;
    if parsed.scheme() != "imap" {
        return Err((554, "5.7.1 BURL requires imap or https".to_string()));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| (554, "5.7.1 BURL has no host".to_string()))?
        .to_ascii_lowercase();
    if !burl
        .imap_hosts
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&host))
    {
        return Err((554, "5.7.8 BURL IMAP host is not trusted".to_string()));
    }
    let decoded = percent_encoding::percent_decode_str(parsed.path())
        .decode_utf8_lossy()
        .to_string();
    if decoded.to_ascii_lowercase().contains("urlauth=") {
        return Err((554, "5.7.8 URLAUTH is not supported".to_string()));
    }
    let lower = decoded.to_ascii_lowercase();
    let uid_pos = lower
        .find("uid=")
        .ok_or_else(|| (554, "5.6.6 IMAP URL has no UID".to_string()))?;
    let uid = decoded[uid_pos + 4..]
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>()
        .parse::<u32>()
        .map_err(|_| (554, "5.6.6 IMAP URL has an invalid UID".to_string()))?;
    let mailbox = decoded[..uid_pos]
        .split('/')
        .filter(|segment| !segment.is_empty())
        .filter_map(|segment| segment.split(';').next())
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("/");
    let mailbox = if mailbox.is_empty() {
        "INBOX".to_string()
    } else {
        mailbox
    };
    if mailbox.contains(['\r', '\n']) || burl.imap_user.contains(['\r', '\n']) {
        return Err((554, "5.7.1 Invalid IMAP command input".to_string()));
    }
    Ok(ImapTarget {
        host,
        port: parsed.port().unwrap_or(burl.imap_port),
        mailbox,
        uid,
    })
}

enum ImapStream {
    Tls(StreamOwned<ClientConnection, std::net::TcpStream>),
}

impl Read for ImapStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tls(stream) => stream.read(buffer),
        }
    }
}

impl Write for ImapStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tls(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tls(stream) => stream.flush(),
        }
    }
}

struct ImapClient {
    stream: ImapStream,
    tag: u32,
}

impl ImapClient {
    fn new(stream: ImapStream) -> Self {
        Self { stream, tag: 0 }
    }

    fn read_greeting(&mut self) -> Result<(), String> {
        let line = self.read_line()?;
        let text = String::from_utf8_lossy(&line).to_ascii_uppercase();
        if text.starts_with("* OK") {
            Ok(())
        } else {
            Err(format!("IMAP greeting rejected: {text}"))
        }
    }

    fn command(&mut self, command: &str) -> Result<Vec<u8>, String> {
        self.tag += 1;
        let tag = format!("a{}", self.tag);
        write!(self.stream, "{tag} {command}\r\n").map_err(|error| error.to_string())?;
        self.stream.flush().map_err(|error| error.to_string())?;
        self.read_until_tag(&tag)
    }

    fn read_until_tag(&mut self, tag: &str) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        loop {
            let line = self.read_line()?;
            let text = String::from_utf8_lossy(&line).to_string();
            out.extend_from_slice(&line);
            if let Some(size) = imap_literal_size(&text) {
                let mut body = vec![0u8; size];
                self.stream
                    .read_exact(&mut body)
                    .map_err(|error| error.to_string())?;
                out.extend_from_slice(&body);
            }
            if text.starts_with(tag) {
                if text.to_ascii_uppercase().contains("OK") {
                    return Ok(out);
                }
                return Err(text.trim().to_string());
            }
        }
    }

    fn read_line(&mut self) -> Result<Vec<u8>, String> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            self.stream
                .read_exact(&mut byte)
                .map_err(|error| error.to_string())?;
            line.push(byte[0]);
            if byte[0] == b'\n' {
                return Ok(line);
            }
            if line.len() > 1024 * 1024 {
                return Err("IMAP line is too long".to_string());
            }
        }
    }
}

fn imap_literal_size(line: &str) -> Option<usize> {
    let trimmed = line.trim_end();
    if !trimmed.ends_with('}') {
        return None;
    }
    let open = trimmed.rfind('{')?;
    trimmed[open + 1..trimmed.len() - 1].parse().ok()
}

fn imap_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn extract_imap_body(response: &[u8]) -> Option<Vec<u8>> {
    let marker = b"BODY[]";
    let start = response
        .windows(marker.len())
        .position(|window| window == marker)?;
    let rest = &response[start + marker.len()..];
    let open = rest.iter().position(|byte| *byte == b'{')?;
    let close = rest[open + 1..].iter().position(|byte| *byte == b'}')? + open + 1;
    let size = std::str::from_utf8(&rest[open + 1..close])
        .ok()?
        .parse::<usize>()
        .ok()?;
    let body_start = rest[close + 1..]
        .windows(2)
        .position(|window| window == b"\r\n")?
        + close
        + 3;
    response
        .get(start + marker.len() + body_start..start + marker.len() + body_start + size)
        .map(|body| body.to_vec())
}

fn fetch_imap(url: &str, limit: usize, burl: &BurlSettings) -> Result<Vec<u8>, (u16, String)> {
    let target = parse_imap_url(url, burl)?;
    let socket = std::net::TcpStream::connect((target.host.as_str(), target.port))
        .map_err(|error| (451, format!("4.4.1 IMAP connect failed: {error}")))?;
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .map_err(|error| (451, error.to_string()))?;
    socket
        .set_write_timeout(Some(std::time::Duration::from_secs(30)))
        .map_err(|error| (451, error.to_string()))?;
    let stream = if burl.imap_starttls {
        let mut plain = socket;
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            plain
                .read_exact(&mut byte)
                .map_err(|error| (451, error.to_string()))?;
            line.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        if !String::from_utf8_lossy(&line)
            .to_ascii_uppercase()
            .starts_with("* OK")
        {
            return Err((451, "4.4.1 IMAP greeting rejected".to_string()));
        }
        plain
            .write_all(b"a0 STARTTLS\r\n")
            .map_err(|error| (451, error.to_string()))?;
        plain.flush().map_err(|error| (451, error.to_string()))?;
        let mut response = Vec::new();
        loop {
            response.clear();
            let mut byte = [0u8; 1];
            loop {
                plain
                    .read_exact(&mut byte)
                    .map_err(|error| (451, error.to_string()))?;
                response.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            if String::from_utf8_lossy(&response).starts_with("a0 ") {
                break;
            }
        }
        if !String::from_utf8_lossy(&response)
            .to_ascii_uppercase()
            .contains("OK")
        {
            return Err((451, "4.4.1 IMAP STARTTLS rejected".to_string()));
        }
        ImapStream::Tls(imap_tls(plain, &target.host)?)
    } else {
        ImapStream::Tls(imap_tls(socket, &target.host)?)
    };
    let mut client = ImapClient::new(stream);
    if !burl.imap_starttls {
        client.read_greeting().map_err(|error| (451, error))?;
    }
    imap_fetch_with_client(&mut client, &target, burl, limit)
}

fn imap_fetch_with_client(
    client: &mut ImapClient,
    target: &ImapTarget,
    burl: &BurlSettings,
    limit: usize,
) -> Result<Vec<u8>, (u16, String)> {
    client
        .command(&format!(
            "LOGIN {} {}",
            imap_quote(&burl.imap_user),
            imap_quote(&burl.imap_password)
        ))
        .map_err(|error| (554, format!("5.7.8 IMAP login failed: {error}")))?;
    client
        .command(&format!("SELECT {}", imap_quote(&target.mailbox)))
        .map_err(|error| (554, format!("5.6.6 IMAP SELECT failed: {error}")))?;
    let response = client
        .command(&format!("UID FETCH {} (BODY.PEEK[])", target.uid))
        .map_err(|error| (554, format!("5.6.6 IMAP FETCH failed: {error}")))?;
    let body = extract_imap_body(&response)
        .ok_or_else(|| (554, "5.6.6 IMAP URL returned no data".to_string()))?;
    if body.len() > limit {
        return Err((554, "5.3.4 BURL content is too large".to_string()));
    }
    let _ = client.command("LOGOUT");
    Ok(body)
}

fn imap_tls(
    stream: std::net::TcpStream,
    host: &str,
) -> Result<StreamOwned<ClientConnection, std::net::TcpStream>, (u16, String)> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| (451, "4.4.1 invalid IMAP host name".to_string()))?;
    let connection =
        ClientConnection::new(Arc::new(config), name).map_err(|error| (451, error.to_string()))?;
    Ok(StreamOwned::new(connection, stream))
}

fn fetch_burl(url: &str, limit: usize, burl: &BurlSettings) -> Result<Vec<u8>, (u16, String)> {
    if url.to_ascii_lowercase().starts_with("imap://") {
        return fetch_imap(url, limit, burl);
    }
    let parsed =
        reqwest::Url::parse(url).map_err(|_| (554, "5.7.1 Invalid BURL URL".to_string()))?;
    if parsed.scheme() != "https" {
        return Err((554, "5.7.1 BURL requires https".to_string()));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err((554, "5.7.1 BURL credentials are not allowed".to_string()));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| (554, "5.7.1 BURL has no host".to_string()))?;
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|_| (451, "4.4.1 BURL host cannot be resolved".to_string()))?;
    let mut resolved = false;
    for address in addresses {
        resolved = true;
        if blocked_ip(address.ip()) {
            return Err((554, "5.7.1 BURL points to a private address".to_string()));
        }
    }
    if !resolved {
        return Err((451, "4.4.1 BURL host cannot be resolved".to_string()));
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .build()
        .map_err(|error| (451, format!("4.4.1 BURL client: {error}")))?;
    let response = client
        .get(parsed)
        .send()
        .map_err(|error| (451, format!("4.4.1 BURL fetch failed: {error}")))?;
    if !response.status().is_success() {
        return Err((554, format!("5.6.6 BURL returned {}", response.status())));
    }
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err((554, "5.3.4 BURL content is too large".to_string()));
    }
    let mut body = Vec::new();
    response
        .take(limit as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|error| (451, format!("4.4.1 BURL read failed: {error}")))?;
    if body.len() > limit {
        return Err((554, "5.3.4 BURL content is too large".to_string()));
    }
    Ok(body)
}

fn blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => blocked_ipv4(ip),
        IpAddr::V6(ip) => blocked_ipv6(ip),
    }
}

fn blocked_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || octets[0] == 0
        || (octets[0] == 100 && (64..128).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 198 && (18..20).contains(&octets[1]))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
}

fn blocked_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return blocked_ipv4(mapped);
    }
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
}

async fn deliver_lmtp(
    app: &App,
    submission: bool,
    peer: IpAddr,
    helo: String,
    envelope: tide_smtp::Envelope,
    data: Vec<u8>,
) -> Vec<tide_smtp::Reply> {
    let mut replies = Vec::new();
    for recipient in &envelope.to {
        let mut one = envelope.clone();
        one.to = vec![recipient.clone()];
        one.recipients = envelope
            .recipients
            .iter()
            .filter(|entry| &entry.address == recipient)
            .cloned()
            .collect();
        replies.push(deliver(app, submission, peer, helo.clone(), one, data.clone()).await);
    }
    replies
}

async fn deliver(
    app: &App,
    submission: bool,
    peer: IpAddr,
    helo: String,
    envelope: tide_smtp::Envelope,
    mut data: Vec<u8>,
) -> tide_smtp::Reply {
    let mut spf_fail = false;
    let mut dkim_fail = false;
    let mut dmarc_fail = false;
    let mut dmarc_quarantine = false;
    if !submission && app.config.email_auth.enabled {
        if let Some(authenticator) = app.email_auth.clone() {
            let hostname = app.config.server.hostname.clone();
            let mail_from = envelope.from.clone();
            let raw = data.clone();
            let auth_helo = helo.clone();
            let recipients = envelope.to.clone();
            let handle = monoio::spawn_blocking(move || {
                crate::email_auth::verify(
                    authenticator,
                    hostname,
                    peer,
                    auth_helo,
                    mail_from,
                    recipients,
                    raw,
                )
            });
            match handle.await {
                Ok(Ok(verification)) => {
                    spf_fail = verification.spf_fail;
                    dkim_fail = verification.dkim_fail;
                    dmarc_fail = verification.dmarc_fail;
                    dmarc_quarantine = verification
                        .dmarc
                        .as_ref()
                        .is_some_and(|info| info.disposition == "quarantine");
                    if app.config.email_auth.reject_spf_fail && verification.spf_fail {
                        return tide_smtp::Reply::new(550, "5.7.23 SPF policy rejection");
                    }
                    if app.config.email_auth.reject_dmarc_fail && verification.dmarc_fail {
                        return tide_smtp::Reply::new(550, "5.7.1 DMARC policy rejection");
                    }
                    if let (Some(info), Some(reports)) =
                        (verification.dmarc.clone(), app.reports.as_ref())
                    {
                        reports.record_dmarc(
                            &info.domain,
                            &info.rua,
                            &peer.to_string(),
                            &info.disposition,
                            &info.dkim,
                            &info.spf,
                            &info.header_from,
                            &info.policy,
                            &info.adkim,
                            &info.aspf,
                            info.pct,
                            info.sampled_out,
                        );
                        if info.disposition != "none" && !info.ruf.is_empty() {
                            if let Some(outbound) = app.outbound.as_ref() {
                                let raw = crate::reporting::dmarc_failure_message(
                                    &info,
                                    &app.config.server.hostname,
                                    &peer.to_string(),
                                    &envelope.from,
                                    &data,
                                );
                                for destination in &info.ruf {
                                    let mut job = crate::outbound::OutboundQueue::job(
                                        "",
                                        destination.clone(),
                                        raw.clone(),
                                    );
                                    job.message_id = format!("dmarc-failure-{}", peer);
                                    let _ = outbound.enqueue(job);
                                }
                            }
                        }
                    }
                    let mut augmented = verification.header.into_bytes();
                    augmented.extend_from_slice(&data);
                    data = augmented;
                }
                Ok(Err(error)) => eprintln!("email auth: {error}"),
                Err(_) => eprintln!("email auth: verification task cancelled"),
            }
        }
    }
    let async_quarantine =
        !submission && app.config.antivirus.async_scan && app.scan_queue.is_some();
    if !async_quarantine {
        if let Some(scanner) = app.antivirus.clone() {
            let raw = data.clone();
            let handle = monoio::spawn_blocking(move || scanner.scan(&raw));
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    eprintln!("antivirus rejected message: {error}");
                    return tide_smtp::Reply::new(
                        550,
                        "5.7.1 Message rejected by antivirus scanner",
                    );
                }
                Err(_) => eprintln!("antivirus task cancelled"),
            }
        }
    }
    if !submission && crate::dsn::is_dsn(&data) {
        let mut augmented = b"X-Tide-DSN: yes\r\n".to_vec();
        augmented.extend_from_slice(&data);
        data = augmented;
    }
    let mut spam = dmarc_quarantine;
    if !submission {
        if let Some(engine) = app.spam.clone() {
            let raw = data.clone();
            let helo = helo.clone();
            let mail_from = envelope.from.clone();
            let handle = monoio::spawn_blocking(move || {
                let context = tide_spam::SpamContext::new(
                    peer, &helo, &mail_from, &raw, spf_fail, dkim_fail, dmarc_fail,
                );
                let verdict = engine.check(&context);
                let is_spam = engine.is_spam(&verdict);
                (verdict, is_spam)
            });
            match handle.await {
                Ok((verdict, is_spam)) => {
                    if verdict.reject {
                        return tide_smtp::Reply::new(550, "5.7.1 Message rejected as spam");
                    }
                    spam = spam || is_spam;
                    let status = if spam { "Yes" } else { "No" };
                    let mut header = format!(
                        "X-Spam-Score: {:.1}\r\nX-Spam-Status: {status}\r\n",
                        verdict.score
                    );
                    if !verdict.rules.is_empty() {
                        header.push_str(&format!("X-Spam-Rules: {}\r\n", verdict.rules.join(", ")));
                    }
                    let mut augmented = header.into_bytes();
                    augmented.extend_from_slice(&data);
                    data = augmented;
                }
                Err(_) => eprintln!("spam filter: task cancelled"),
            }
        }
    }
    if received_hops(&data) >= 50 {
        return tide_smtp::Reply::new(554, "5.4.6 Too many hops");
    }
    let mut local = Vec::new();
    let mut remote = Vec::new();
    for recipient in &envelope.to {
        if let Some(account) = app.registry.account(recipient) {
            local.push(account.email.clone());
        } else {
            remote.push(recipient.clone());
        }
    }
    if !remote.is_empty() {
        if !submission {
            return tide_smtp::Reply::new(550, "5.7.1 Relay access denied");
        }
        let Some(outbound) = app.outbound.as_ref() else {
            return tide_smtp::Reply::new(
                550,
                "5.7.1 Outbound delivery is not enabled on this server",
            );
        };
        for recipient in &remote {
            let mut job = crate::outbound::OutboundQueue::job(
                envelope.from.clone(),
                recipient.clone(),
                data.clone(),
            );
            job.require_tls = envelope.require_tls;
            job.dsn_ret = envelope.dsn_ret.clone();
            job.envid = envelope.envid.clone();
            if let Some(recipient_params) = envelope
                .recipients
                .iter()
                .find(|entry| entry.address == *recipient)
            {
                job.notify = recipient_params.notify.clone();
                job.orcpt = recipient_params.orcpt.clone();
                job.future_release = envelope.future_release.clone();
                job.deliver_by = envelope.deliver_by.clone();
            }
            if !outbound.enqueue(job) {
                return tide_smtp::Reply::new(451, "4.3.0 Outbound queue is unavailable");
            }
        }
    }
    if local.is_empty() {
        return if remote.is_empty() {
            tide_smtp::Reply::new(550, "5.1.1 No valid recipients")
        } else {
            SmtpSession::message_accepted()
        };
    }
    for recipient in local {
        if let Err(error) = app.db.ensure_default_folders(&recipient).await {
            eprintln!("folders: {error}");
        }
        let mailbox = if spam {
            "Junk"
        } else if async_quarantine {
            "Quarantine"
        } else {
            "INBOX"
        };
        let id = Uuid::new_v4().to_string();
        let traced = add_trace_headers(
            &data,
            &app.config.server.hostname,
            &helo,
            peer,
            &envelope.from,
            &recipient,
            &id,
        );
        let message = match parse_message(&traced, recipient.clone(), mailbox, id.clone()) {
            Ok(message) => message,
            Err(error) => {
                eprintln!("smtp parse: {error}");
                return tide_smtp::Reply::new(554, "5.6.0 Message could not be parsed");
            }
        };
        if let Err(error) = app.db.append_message_with_blobs(message).await {
            eprintln!("smtp store: {error}");
            return tide_smtp::Reply::new(451, "4.3.0 Temporary storage failure");
        }
        if async_quarantine {
            if let Some(queue) = app.scan_queue.as_ref() {
                queue.enqueue(id, recipient.clone(), true);
            }
        }
    }
    SmtpSession::message_accepted()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_private_burl_targets() {
        assert!(blocked_ip("127.0.0.1".parse().unwrap()));
        assert!(blocked_ip("10.1.2.3".parse().unwrap()));
        assert!(blocked_ip("169.254.169.254".parse().unwrap()));
        assert!(blocked_ip("::1".parse().unwrap()));
        assert!(blocked_ip("fc00::1".parse().unwrap()));
        assert!(!blocked_ip("93.184.216.34".parse().unwrap()));
        assert!(!blocked_ip("2606:2800:220:1::1".parse().unwrap()));
    }

    #[test]
    fn parses_imap_burl() {
        let burl = BurlSettings {
            imap_enabled: true,
            imap_hosts: vec!["imap.example.com".into()],
            imap_user: "submit".into(),
            imap_password: "secret".into(),
            imap_port: 993,
            imap_starttls: false,
        };
        let target = parse_imap_url(
            "imap://user@imap.example.com/outbox;UIDVALIDITY=1/;UID=25",
            &burl,
        )
        .unwrap();
        assert_eq!(target.mailbox, "outbox");
        assert_eq!(target.uid, 25);
        assert_eq!(target.port, 993);
        assert!(parse_imap_url("imap://user@evil.example.com/INBOX/;UID=1", &burl).is_err());
        assert!(
            parse_imap_url(
                "imap://user@imap.example.com/INBOX/;UID=1;URLAUTH=submit+user",
                &burl
            )
            .is_err()
        );
        assert_eq!(imap_quote("a\"b"), "\"a\\\"b\"");
    }

    #[test]
    fn extracts_imap_literal() {
        let response = b"* 1 FETCH (UID 25 BODY[] {5}\r\nhello)\r\na2 OK done\r\n";
        assert_eq!(extract_imap_body(response).unwrap(), b"hello");
    }

    #[test]
    fn rejects_non_https_burl() {
        let burl = BurlSettings::default();
        assert!(fetch_burl("http://example.com/message", 1024, &burl).is_err());
        assert!(fetch_burl("file:///etc/passwd", 1024, &burl).is_err());
    }
}
