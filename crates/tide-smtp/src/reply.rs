use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub lines: Vec<String>,
}

impl Reply {
    pub fn new(code: u16, text: impl Into<String>) -> Self {
        Self {
            code,
            lines: vec![text.into()],
        }
    }

    pub fn multi(code: u16, lines: Vec<String>) -> Self {
        Self { code, lines }
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let count = self.lines.len().max(1);
        for (index, line) in self.lines.iter().enumerate() {
            let sanitized = sanitize(line);
            let separator = if index + 1 == count { ' ' } else { '-' };
            out.extend_from_slice(format!("{}{separator}{sanitized}\r\n", self.code).as_bytes());
        }
        if self.lines.is_empty() {
            out.extend_from_slice(format!("{} \r\n", self.code).as_bytes());
        }
        out
    }

    pub fn is_positive(&self) -> bool {
        (200..400).contains(&self.code)
    }
}

impl fmt::Display for Reply {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}", self.code, self.lines.join(" / "))
    }
}

fn sanitize(line: &str) -> String {
    line.chars()
        .map(|character| {
            if character == '\r' || character == '\n' {
                ' '
            } else {
                character
            }
        })
        .collect()
}

#[derive(Debug, thiserror::Error)]
pub enum SmtpError {
    #[error("ошибка ввода-вывода: {0}")]
    Io(#[from] std::io::Error),
    #[error("ошибка протокола: {0}")]
    Protocol(String),
    #[error("ошибка аутентификации: {0}")]
    Auth(String),
    #[error("TLS: {0}")]
    Tls(String),
    #[error("сообщение слишком большое")]
    TooLarge,
}
