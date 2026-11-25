#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailCommand {
    pub from: String,
    pub params: Vec<(String, Option<String>)>,
}

impl MailCommand {
    pub fn param(&self, key: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
            .and_then(|(_, value)| value.as_deref())
    }

    pub fn has_param(&self, key: &str) -> bool {
        self.params
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(key))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RcptCommand {
    pub to: String,
    pub params: Vec<(String, Option<String>)>,
}

impl RcptCommand {
    pub fn param(&self, key: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
            .and_then(|(_, value)| value.as_deref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Ehlo(String),
    Helo(String),
    Mail(MailCommand),
    Rcpt(RcptCommand),
    Data,
    Bdat {
        size: u64,
        last: bool,
    },
    Rset,
    Noop,
    Quit,
    StartTls,
    Auth {
        mechanism: String,
        initial: Option<String>,
    },
    Vrfy(String),
    Help(Option<String>),
    Unknown(String),
}

impl Command {
    pub fn verb(&self) -> &'static str {
        match self {
            Self::Ehlo(_) => "EHLO",
            Self::Helo(_) => "HELO",
            Self::Mail(_) => "MAIL",
            Self::Rcpt(_) => "RCPT",
            Self::Data => "DATA",
            Self::Bdat { .. } => "BDAT",
            Self::Rset => "RSET",
            Self::Noop => "NOOP",
            Self::Quit => "QUIT",
            Self::StartTls => "STARTTLS",
            Self::Auth { .. } => "AUTH",
            Self::Vrfy(_) => "VRFY",
            Self::Help(_) => "HELP",
            Self::Unknown(_) => "UNKNOWN",
        }
    }
}

pub fn parse_command(line: &[u8]) -> Result<Command, String> {
    let line = std::str::from_utf8(line).map_err(|_| "команда должна быть в UTF-8".to_string())?;
    let line = line.trim_end_matches(['\r', '\n']);
    let line = line.trim_start();
    if line.is_empty() {
        return Ok(Command::Unknown(String::new()));
    }
    let (verb, rest) = split_verb(line);
    let upper = verb.to_ascii_uppercase();
    match upper.as_str() {
        "EHLO" => {
            let value = rest.trim();
            if value.is_empty() {
                return Err("EHLO требует имя клиента".into());
            }
            Ok(Command::Ehlo(value.to_string()))
        }
        "HELO" => {
            let value = rest.trim();
            if value.is_empty() {
                return Err("HELO требует имя клиента".into());
            }
            Ok(Command::Helo(value.to_string()))
        }
        "MAIL" => {
            let rest = rest.trim();
            let rest =
                strip_prefix_ci(rest, "FROM:").ok_or_else(|| "MAIL требует FROM:".to_string())?;
            let (from, params) = parse_path_and_params(rest)?;
            Ok(Command::Mail(MailCommand { from, params }))
        }
        "RCPT" => {
            let rest = rest.trim();
            let rest =
                strip_prefix_ci(rest, "TO:").ok_or_else(|| "RCPT требует TO:".to_string())?;
            let (to, params) = parse_path_and_params(rest)?;
            Ok(Command::Rcpt(RcptCommand { to, params }))
        }
        "DATA" => Ok(Command::Data),
        "BDAT" => {
            let mut parts = rest.split_whitespace();
            let size = parts
                .next()
                .ok_or_else(|| "BDAT требует размер".to_string())?
                .parse::<u64>()
                .map_err(|_| "некорректный BDAT size".to_string())?;
            let last = parts
                .next()
                .map(|value| value.eq_ignore_ascii_case("LAST"))
                .unwrap_or(false);
            Ok(Command::Bdat { size, last })
        }
        "RSET" => Ok(Command::Rset),
        "NOOP" => Ok(Command::Noop),
        "QUIT" => Ok(Command::Quit),
        "STARTTLS" => Ok(Command::StartTls),
        "AUTH" => {
            let mut parts = rest.split_whitespace();
            let mechanism = parts
                .next()
                .ok_or_else(|| "AUTH требует механизм".to_string())?
                .to_ascii_uppercase();
            let initial = parts.next().map(str::to_string);
            Ok(Command::Auth { mechanism, initial })
        }
        "VRFY" => Ok(Command::Vrfy(rest.trim().to_string())),
        "HELP" => Ok(Command::Help(if rest.trim().is_empty() {
            None
        } else {
            Some(rest.trim().to_string())
        })),
        _ => Ok(Command::Unknown(verb.to_string())),
    }
}

fn split_verb(line: &str) -> (&str, &str) {
    match line.find([' ', '\t']) {
        Some(index) => (&line[..index], &line[index..]),
        None => (line, ""),
    }
}

fn strip_prefix_ci<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    if value.len() < prefix.len() {
        return None;
    }
    if value[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&value[prefix.len()..])
    } else {
        None
    }
}

type Params = Vec<(String, Option<String>)>;

fn parse_path_and_params(value: &str) -> Result<(String, Params), String> {
    let value = value.trim_start();
    let (path, rest) = if let Some(stripped) = value.strip_prefix('<') {
        let end = stripped
            .find('>')
            .ok_or_else(|| "незакрытый адрес в угловых скобках".to_string())?;
        (stripped[..end].to_string(), &stripped[end + 1..])
    } else {
        let end = value
            .find(|character: char| character.is_whitespace())
            .unwrap_or(value.len());
        (value[..end].to_string(), &value[end..])
    };
    let mut params = Vec::new();
    for token in rest.split_whitespace() {
        let (name, value) = match token.split_once('=') {
            Some((name, value)) => (name.to_ascii_uppercase(), Some(value.to_string())),
            None => (token.to_ascii_uppercase(), None),
        };
        if name.is_empty() {
            return Err("пустой параметр".into());
        }
        params.push((name, value));
    }
    Ok((path, params))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mail_with_params() {
        let command =
            parse_command(b"MAIL FROM:<alice@example.com> SIZE=1024 BODY=8BITMIME").unwrap();
        match command {
            Command::Mail(mail) => {
                assert_eq!(mail.from, "alice@example.com");
                assert_eq!(mail.param("SIZE"), Some("1024"));
                assert!(mail.has_param("BODY"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parses_rcpt() {
        let command = parse_command(b"RCPT TO: <bob@example.com>").unwrap();
        match command {
            Command::Rcpt(rcpt) => assert_eq!(rcpt.to, "bob@example.com"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parses_auth_initial() {
        let command = parse_command(b"AUTH PLAIN AHRlc3QAcGFzcw==").unwrap();
        assert_eq!(
            command,
            Command::Auth {
                mechanism: "PLAIN".into(),
                initial: Some("AHRlc3QAcGFzcw==".into())
            }
        );
    }

    #[test]
    fn parses_bdat() {
        assert_eq!(
            parse_command(b"BDAT 1024 LAST").unwrap(),
            Command::Bdat {
                size: 1024,
                last: true
            }
        );
    }

    #[test]
    fn rejects_broken_mail() {
        assert!(parse_command(b"MAIL alice@example.com").is_err());
    }
}
