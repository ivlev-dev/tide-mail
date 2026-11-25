use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;

use monoio::net::{TcpListener, TcpStream};
use tide_core::parse_message;
use tide_smtp::{Action, SmtpConfig, SmtpSession};
use uuid::Uuid;

use crate::app::App;
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
    let mut spam = false;
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
                    spam = is_spam;
                    let status = if is_spam { "Yes" } else { "No" };
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
