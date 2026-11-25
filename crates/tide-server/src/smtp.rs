use std::sync::Arc;

use monoio::net::{TcpListener, TcpStream};
use tide_core::parse_message;
use tide_smtp::{Action, SmtpConfig, SmtpSession};
use uuid::Uuid;

use crate::app::App;
use crate::net::{BufferedConn, Conn};

pub async fn serve_smtp(app: Arc<App>, listener: TcpListener, submission: bool) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let app = Arc::clone(&app);
                monoio::spawn(async move {
                    if let Err(error) = handle_connection(app, stream, submission).await {
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
) -> std::io::Result<()> {
    let mut conn = BufferedConn::new(Conn::plain(stream));
    let mut config = if submission {
        SmtpConfig::submission(app.config.server.hostname.clone())
    } else {
        SmtpConfig {
            hostname: app.config.server.hostname.clone(),
            require_auth: false,
            ..SmtpConfig::default()
        }
    };
    config.enable_starttls = app.tls.is_some();
    config.allow_insecure_auth = app.tls.is_none();
    let (mut session, greeting) = SmtpSession::new(config);
    conn.write_all(&greeting.to_wire()).await?;

    loop {
        let Some(line) = conn.read_line(64 * 1024).await? else {
            return Ok(());
        };
        let actions = session.feed_line(&line);
        for action in actions {
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
                Action::Deliver { envelope, data } => {
                    let reply = deliver(&app, submission, envelope, data).await;
                    conn.write_all(&reply.to_wire()).await?;
                }
                Action::Close => return Ok(()),
            }
        }
    }
}

async fn deliver(
    app: &App,
    submission: bool,
    envelope: tide_smtp::Envelope,
    data: Vec<u8>,
) -> tide_smtp::Reply {
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
            if !outbound.enqueue(crate::outbound::OutboundJob {
                from: envelope.from.clone(),
                to: recipient.clone(),
                raw: data.clone(),
            }) {
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
        let id = Uuid::new_v4().to_string();
        let message = match parse_message(&data, recipient.clone(), "INBOX", id) {
            Ok(message) => message,
            Err(error) => {
                eprintln!("smtp parse: {error}");
                return tide_smtp::Reply::new(554, "5.6.0 Message could not be parsed");
            }
        };
        if let Err(error) = app.db.append_message(message).await {
            eprintln!("smtp store: {error}");
            return tide_smtp::Reply::new(451, "4.3.0 Temporary storage failure");
        }
    }
    SmtpSession::message_accepted()
}
