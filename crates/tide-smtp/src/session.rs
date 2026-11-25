use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::command::{Command, parse_command};
use crate::config::{AuthMechanism, SmtpConfig};
use crate::reply::Reply;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub from: String,
    pub to: Vec<String>,
    pub size: Option<u64>,
    pub smtputf8: bool,
    pub body_8bitmime: bool,
}

impl Envelope {
    pub fn new(from: String) -> Self {
        Self {
            from,
            to: Vec::new(),
            size: None,
            smtputf8: false,
            body_8bitmime: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Reply(Reply),
    StartTls,
    AuthChallenge {
        mechanism: String,
        challenge: String,
    },
    AuthComplete {
        mechanism: String,
        username: String,
        secret: String,
    },
    Deliver {
        envelope: Envelope,
        data: Vec<u8>,
    },
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Command,
    Data,
    AuthPlain,
    AuthLoginUser,
    AuthLoginPass,
}

pub struct SmtpSession {
    config: SmtpConfig,
    state: State,
    tls_active: bool,
    helo: Option<String>,
    authenticated: Option<String>,
    envelope: Option<Envelope>,
    data: Vec<u8>,
    data_too_large: bool,
    auth_username: Option<String>,
}

impl SmtpSession {
    pub fn new(config: SmtpConfig) -> (Self, Reply) {
        let greeting = Reply::new(
            220,
            format!("{} ESMTP Tide Mail", config.hostname),
        );
        let session = Self {
            config,
            state: State::Command,
            tls_active: false,
            helo: None,
            authenticated: None,
            envelope: None,
            data: Vec::new(),
            data_too_large: false,
            auth_username: None,
        };
        (session, greeting)
    }

    pub fn config(&self) -> &SmtpConfig {
        &self.config
    }

    pub fn is_tls(&self) -> bool {
        self.tls_active
    }

    pub fn authenticated_user(&self) -> Option<&str> {
        self.authenticated.as_deref()
    }

    pub fn helo(&self) -> Option<&str> {
        self.helo.as_deref()
    }

    pub fn in_data(&self) -> bool {
        self.state == State::Data
    }

    pub fn feed_line(&mut self, line: &[u8]) -> Vec<Action> {
        if line.len() > self.config.max_line_size && self.state != State::Data {
            return vec![Action::Reply(Reply::new(500, "Line too long"))];
        }
        match self.state {
            State::Data => self.feed_data_line(line),
            State::AuthPlain => self.feed_auth_plain(line),
            State::AuthLoginUser => self.feed_auth_login_user(line),
            State::AuthLoginPass => self.feed_auth_login_pass(line),
            State::Command => self.feed_command(line),
        }
    }

    pub fn tls_established(&mut self) {
        self.tls_active = true;
        self.helo = None;
        self.authenticated = None;
        self.envelope = None;
        self.state = State::Command;
        self.auth_username = None;
    }

    pub fn auth_success(&mut self, username: impl Into<String>) -> Reply {
        self.authenticated = Some(username.into());
        self.envelope = None;
        self.state = State::Command;
        Reply::new(235, "2.7.0 Authentication successful")
    }

    pub fn auth_failure(&mut self) -> Reply {
        self.state = State::Command;
        Reply::new(535, "5.7.8 Authentication credentials invalid")
    }

    pub fn message_accepted() -> Reply {
        Reply::new(250, "2.0.0 Message accepted for delivery")
    }

    fn feed_command(&mut self, line: &[u8]) -> Vec<Action> {
        let command = match parse_command(line) {
            Ok(command) => command,
            Err(error) => return vec![Action::Reply(Reply::new(501, error))],
        };
        match command {
            Command::Ehlo(name) => {
                if self.helo.is_some() {
                    self.envelope = None;
                }
                self.helo = Some(name);
                vec![Action::Reply(self.ehlo_reply())]
            }
            Command::Helo(name) => {
                self.helo = Some(name);
                self.envelope = None;
                vec![Action::Reply(Reply::new(
                    250,
                    format!("{} Hello", self.config.hostname),
                ))]
            }
            Command::Mail(mail) => {
                if !self.require_helo() {
                    return vec![Action::Reply(Reply::new(503, "5.5.1 Send EHLO first"))];
                }
                if self.config.require_auth && self.authenticated.is_none() {
                    return vec![Action::Reply(Reply::new(
                        530,
                        "5.7.0 Authentication required",
                    ))];
                }
                if self.envelope.is_some() {
                    return vec![Action::Reply(Reply::new(
                        503,
                        "5.5.1 Nested MAIL command",
                    ))];
                }
                let size = match mail.param("SIZE").map(str::parse::<u64>) {
                    Some(Ok(value)) => Some(value),
                    Some(Err(_)) => {
                        return vec![Action::Reply(Reply::new(
                            501,
                            "5.5.4 Invalid SIZE parameter",
                        ))];
                    }
                    None => None,
                };
                if let Some(size) = size {
                    if size > self.config.max_message_size as u64 {
                        return vec![Action::Reply(Reply::new(
                            552,
                            "5.3.4 Message size exceeds fixed maximum",
                        ))];
                    }
                }
                let smtputf8 = mail.has_param("SMTPUTF8");
                if smtputf8 && !self.config.enable_smtputf8 {
                    return vec![Action::Reply(Reply::new(
                        504,
                        "5.5.4 SMTPUTF8 is not supported",
                    ))];
                }
                let body_8bitmime = mail
                    .param("BODY")
                    .map(|value| value.eq_ignore_ascii_case("8BITMIME"))
                    .unwrap_or(false);
                if body_8bitmime && !self.config.enable_8bitmime {
                    return vec![Action::Reply(Reply::new(
                        504,
                        "5.5.4 8BITMIME is not supported",
                    ))];
                }
                let mut envelope = Envelope::new(mail.from);
                envelope.size = size;
                envelope.smtputf8 = smtputf8;
                envelope.body_8bitmime = body_8bitmime;
                self.envelope = Some(envelope);
                vec![Action::Reply(Reply::new(250, "2.1.0 Sender accepted"))]
            }
            Command::Rcpt(rcpt) => {
                if self.envelope.is_none() {
                    return vec![Action::Reply(Reply::new(
                        503,
                        "5.5.1 Send MAIL first",
                    ))];
                }
                if rcpt.to.is_empty() {
                    return vec![Action::Reply(Reply::new(
                        501,
                        "5.1.3 Bad recipient address syntax",
                    ))];
                }
                let envelope = self.envelope.as_mut().expect("checked above");
                if envelope.to.len() >= self.config.max_recipients {
                    return vec![Action::Reply(Reply::new(
                        452,
                        "4.5.3 Too many recipients",
                    ))];
                }
                envelope.to.push(rcpt.to);
                vec![Action::Reply(Reply::new(250, "2.1.5 Recipient accepted"))]
            }
            Command::Data => {
                let Some(envelope) = &self.envelope else {
                    return vec![Action::Reply(Reply::new(
                        503,
                        "5.5.1 Send MAIL first",
                    ))];
                };
                if envelope.to.is_empty() {
                    return vec![Action::Reply(Reply::new(
                        503,
                        "5.5.1 Send RCPT first",
                    ))];
                }
                self.state = State::Data;
                self.data.clear();
                self.data_too_large = false;
                vec![Action::Reply(Reply::new(
                    354,
                    "End data with <CR><LF>.<CR><LF>",
                ))]
            }
            Command::Rset => {
                self.envelope = None;
                self.state = State::Command;
                vec![Action::Reply(Reply::new(250, "2.0.0 Reset"))]
            }
            Command::Noop => vec![Action::Reply(Reply::new(250, "2.0.0 OK"))],
            Command::Quit => vec![
                Action::Reply(Reply::new(221, "2.0.0 Bye")),
                Action::Close,
            ],
            Command::StartTls => {
                if !self.config.enable_starttls {
                    return vec![Action::Reply(Reply::new(
                        502,
                        "5.5.1 STARTTLS is not supported",
                    ))];
                }
                if self.tls_active {
                    return vec![Action::Reply(Reply::new(
                        503,
                        "5.5.1 TLS is already active",
                    ))];
                }
                if self.helo.is_none() {
                    return vec![Action::Reply(Reply::new(
                        503,
                        "5.5.1 Send EHLO first",
                    ))];
                }
                vec![
                    Action::Reply(Reply::new(220, "2.0.0 Ready to start TLS")),
                    Action::StartTls,
                ]
            }
            Command::Auth {
                mechanism,
                initial,
            } => self.start_auth(&mechanism, initial),
            Command::Vrfy(_) => vec![Action::Reply(Reply::new(
                252,
                "2.5.2 Cannot verify user, but will accept message",
            ))],
            Command::Help(_) => vec![Action::Reply(Reply::new(
                214,
                "2.0.0 EHLO HELO MAIL RCPT DATA RSET NOOP QUIT STARTTLS AUTH VRFY HELP",
            ))],
            Command::Unknown(verb) => vec![Action::Reply(Reply::new(
                500,
                format!("5.5.2 Command unrecognized: {verb}"),
            ))],
        }
    }

    fn require_helo(&self) -> bool {
        self.helo.is_some()
    }

    fn ehlo_reply(&self) -> Reply {
        let mut lines = vec![self.config.hostname.clone()];
        lines.push(format!("SIZE {}", self.config.max_message_size));
        if self.config.enable_8bitmime {
            lines.push("8BITMIME".into());
        }
        if self.config.enable_smtputf8 {
            lines.push("SMTPUTF8".into());
        }
        if self.config.enable_pipelining {
            lines.push("PIPELINING".into());
        }
        if self.config.enable_starttls && !self.tls_active {
            lines.push("STARTTLS".into());
        }
        if self.config.auth_allowed(self.tls_active) && !self.config.auth_mechanisms.is_empty() {
            let mechanisms = self
                .config
                .auth_mechanisms
                .iter()
                .map(|mechanism| mechanism.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            lines.push(format!("AUTH {mechanisms}"));
        }
        lines.push("ENHANCEDSTATUSCODES".into());
        lines.push("HELP".into());
        Reply::multi(250, lines)
    }

    fn start_auth(&mut self, mechanism: &str, initial: Option<String>) -> Vec<Action> {
        if self.helo.is_none() {
            return vec![Action::Reply(Reply::new(503, "5.5.1 Send EHLO first"))];
        }
        if self.authenticated.is_some() {
            return vec![Action::Reply(Reply::new(
                503,
                "5.5.1 Already authenticated",
            ))];
        }
        if !self.config.auth_allowed(self.tls_active) {
            return vec![Action::Reply(Reply::new(
                538,
                "5.7.11 Encryption required for requested authentication mechanism",
            ))];
        }
        let Some(mechanism) = AuthMechanism::from_str(mechanism) else {
            return vec![Action::Reply(Reply::new(
                504,
                "5.5.4 Unrecognized authentication mechanism",
            ))];
        };
        if !self.config.supports(mechanism) {
            return vec![Action::Reply(Reply::new(
                504,
                "5.5.4 Unsupported authentication mechanism",
            ))];
        }
        match mechanism {
            AuthMechanism::Plain => {
                if let Some(initial) = initial {
                    match decode_plain(&initial) {
                        Some((username, secret)) => {
                            self.state = State::Command;
                            vec![Action::AuthComplete {
                                mechanism: "PLAIN".into(),
                                username,
                                secret,
                            }]
                        }
                        None => {
                            self.state = State::Command;
                            vec![Action::Reply(Reply::new(
                                501,
                                "5.5.2 Invalid AUTH PLAIN response",
                            ))]
                        }
                    }
                } else {
                    self.state = State::AuthPlain;
                    vec![Action::AuthChallenge {
                        mechanism: "PLAIN".into(),
                        challenge: String::new(),
                    }]
                }
            }
            AuthMechanism::Login => {
                self.state = State::AuthLoginUser;
                self.auth_username = None;
                vec![Action::AuthChallenge {
                    mechanism: "LOGIN".into(),
                    challenge: BASE64.encode("Username:"),
                }]
            }
        }
    }

    fn feed_auth_plain(&mut self, line: &[u8]) -> Vec<Action> {
        self.state = State::Command;
        let value = String::from_utf8_lossy(trim_crlf(line));
        match decode_plain(&value) {
            Some((username, secret)) => vec![Action::AuthComplete {
                mechanism: "PLAIN".into(),
                username,
                secret,
            }],
            None => vec![Action::Reply(Reply::new(
                501,
                "5.5.2 Invalid AUTH PLAIN response",
            ))],
        }
    }

    fn feed_auth_login_user(&mut self, line: &[u8]) -> Vec<Action> {
        let value = String::from_utf8_lossy(trim_crlf(line));
        let username = match BASE64.decode(value.trim()) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            Err(_) => {
                self.state = State::Command;
                return vec![Action::Reply(Reply::new(
                    501,
                    "5.5.2 Invalid base64 in AUTH LOGIN",
                ))];
            }
        };
        self.auth_username = Some(username);
        self.state = State::AuthLoginPass;
        vec![Action::AuthChallenge {
            mechanism: "LOGIN".into(),
            challenge: BASE64.encode("Password:"),
        }]
    }

    fn feed_auth_login_pass(&mut self, line: &[u8]) -> Vec<Action> {
        self.state = State::Command;
        let value = String::from_utf8_lossy(trim_crlf(line));
        let secret = match BASE64.decode(value.trim()) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            Err(_) => {
                self.auth_username = None;
                return vec![Action::Reply(Reply::new(
                    501,
                    "5.5.2 Invalid base64 in AUTH LOGIN",
                ))];
            }
        };
        let username = self.auth_username.take().unwrap_or_default();
        vec![Action::AuthComplete {
            mechanism: "LOGIN".into(),
            username,
            secret,
        }]
    }

    fn feed_data_line(&mut self, line: &[u8]) -> Vec<Action> {
        if line == b"." {
            self.state = State::Command;
            let Some(envelope) = self.envelope.take() else {
                return vec![Action::Reply(Reply::new(
                    503,
                    "5.5.1 No active transaction",
                ))];
            };
            if self.data_too_large || self.data.len() > self.config.max_message_size {
                self.data.clear();
                self.data_too_large = false;
                return vec![Action::Reply(Reply::new(
                    552,
                    "5.3.4 Message size exceeds fixed maximum",
                ))];
            }
            let data = std::mem::take(&mut self.data);
            self.data_too_large = false;
            return vec![Action::Deliver { envelope, data }];
        }
        if self.data_too_large {
            return Vec::new();
        }
        if line.len() > self.config.max_line_size {
            self.data_too_large = true;
            self.data.clear();
            return Vec::new();
        }
        let unstuffed = if line.first() == Some(&b'.') {
            &line[1..]
        } else {
            line
        };
        if self.data.len() + unstuffed.len() + 2 > self.config.max_message_size {
            self.data_too_large = true;
            self.data.clear();
            return Vec::new();
        }
        self.data.extend_from_slice(unstuffed);
        self.data.extend_from_slice(b"\r\n");
        Vec::new()
    }
}

fn trim_crlf(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r\n")
        .or_else(|| line.strip_suffix(b"\n"))
        .unwrap_or(line)
}

fn decode_plain(value: &str) -> Option<(String, String)> {
    let decoded = BASE64.decode(value.trim()).ok()?;
    let parts: Vec<&[u8]> = decoded.split(|byte| *byte == 0).collect();
    if parts.len() < 3 {
        return None;
    }
    let username = parts
        .iter()
        .take(parts.len() - 1)
        .find(|part| !part.is_empty())?;
    let secret = parts.last()?;
    Some((
        String::from_utf8_lossy(username).to_string(),
        String::from_utf8_lossy(secret).to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> SmtpSession {
        SmtpSession::new(SmtpConfig {
            allow_insecure_auth: true,
            ..SmtpConfig::default()
        })
        .0
    }

    fn replies(actions: &[Action]) -> Vec<Reply> {
        actions
            .iter()
            .filter_map(|action| match action {
                Action::Reply(reply) => Some(reply.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn greets_and_ehlo() {
        let (_, greeting) = SmtpSession::new(SmtpConfig::default());
        assert_eq!(greeting.code, 220);
        let mut session = session();
        let actions = session.feed_line(b"EHLO client.example");
        let reply = &replies(&actions)[0];
        assert_eq!(reply.code, 250);
        assert!(reply.lines.iter().any(|line| line == "STARTTLS"));
        assert!(reply
            .lines
            .iter()
            .any(|line| line.starts_with("AUTH")));
        assert_eq!(session.helo(), Some("client.example"));
    }

    #[test]
    fn accepts_mail_transaction() {
        let mut session = session();
        session.feed_line(b"EHLO client");
        assert_eq!(replies(&session.feed_line(b"MAIL FROM:<a@example.com>"))[0].code, 250);
        assert_eq!(replies(&session.feed_line(b"RCPT TO:<b@example.com>"))[0].code, 250);
        assert_eq!(replies(&session.feed_line(b"DATA"))[0].code, 354);
        assert!(session.feed_line(b"Subject: test").is_empty());
        assert!(session.feed_line(b"").is_empty());
        assert!(session.feed_line(b"..dot-stuffed").is_empty());
        let actions = session.feed_line(b".");
        match &actions[0] {
            Action::Deliver { data, envelope } => {
                assert_eq!(envelope.to, vec!["b@example.com"]);
                let text = String::from_utf8_lossy(data);
                assert!(text.contains("Subject: test\r\n\r\n.dot-stuffed\r\n"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rejects_message_too_large() {
        let mut session = SmtpSession::new(SmtpConfig {
            max_message_size: 8,
            ..SmtpConfig::default()
        })
        .0;
        session.feed_line(b"EHLO client");
        session.feed_line(b"MAIL FROM:<a@example.com>");
        session.feed_line(b"RCPT TO:<b@example.com>");
        session.feed_line(b"DATA");
        session.feed_line(b"0123456789");
        let actions = session.feed_line(b".");
        assert_eq!(replies(&actions)[0].code, 552);
    }

    #[test]
    fn auth_plain_with_initial_response() {
        let mut session = session();
        session.feed_line(b"EHLO client");
        let encoded = BASE64.encode("\0alice\0secret");
        let actions = session.feed_line(format!("AUTH PLAIN {encoded}").as_bytes());
        assert_eq!(
            actions[0],
            Action::AuthComplete {
                mechanism: "PLAIN".into(),
                username: "alice".into(),
                secret: "secret".into()
            }
        );
        assert_eq!(session.auth_success("alice").code, 235);
        assert_eq!(session.authenticated_user(), Some("alice"));
    }

    #[test]
    fn auth_login_flow() {
        let mut session = session();
        session.feed_line(b"EHLO client");
        let actions = session.feed_line(b"AUTH LOGIN");
        assert!(matches!(actions[0], Action::AuthChallenge { .. }));
        session.feed_line(&BASE64.encode("alice").into_bytes());
        let actions = session.feed_line(&BASE64.encode("secret").into_bytes());
        assert_eq!(
            actions[0],
            Action::AuthComplete {
                mechanism: "LOGIN".into(),
                username: "alice".into(),
                secret: "secret".into()
            }
        );
    }

    #[test]
    fn requires_auth_for_submission() {
        let mut session = SmtpSession::new(SmtpConfig::submission("mx.local")).0;
        session.feed_line(b"EHLO client");
        let actions = session.feed_line(b"MAIL FROM:<a@example.com>");
        assert_eq!(replies(&actions)[0].code, 530);
    }

    #[test]
    fn starttls_transition() {
        let mut session = session();
        session.feed_line(b"EHLO client");
        let actions = session.feed_line(b"STARTTLS");
        assert_eq!(replies(&actions)[0].code, 220);
        assert_eq!(actions[1], Action::StartTls);
        session.tls_established();
        assert!(session.is_tls());
        assert_eq!(session.helo(), None);
    }

    #[test]
    fn enforces_command_order() {
        let mut session = session();
        assert_eq!(replies(&session.feed_line(b"MAIL FROM:<a@example.com>"))[0].code, 503);
        session.feed_line(b"EHLO client");
        assert_eq!(replies(&session.feed_line(b"RCPT TO:<b@example.com>"))[0].code, 503);
        session.feed_line(b"MAIL FROM:<a@example.com>");
        assert_eq!(replies(&session.feed_line(b"DATA"))[0].code, 503);
    }
}
