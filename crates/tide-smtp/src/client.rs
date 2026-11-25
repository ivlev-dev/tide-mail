use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::reply::{Reply, SmtpError};

pub struct SmtpClient<S> {
    stream: S,
    read_buffer: Vec<u8>,
    timeout: Duration,
}

impl SmtpClient<TcpStream> {
    pub fn connect(address: impl ToSocketAddrs) -> Result<Self, SmtpError> {
        let stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        Ok(Self::new(stream))
    }
}

impl<S: Read + Write> SmtpClient<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            read_buffer: Vec::new(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn stream(&self) -> &S {
        &self.stream
    }

    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn read_reply(&mut self) -> Result<Reply, SmtpError> {
        let mut lines = Vec::new();
        let mut expected_code = None;
        loop {
            let line = self.read_line()?;
            if line.len() < 4 {
                return Err(SmtpError::Protocol(format!(
                    "short SMTP reply line: {line:?}"
                )));
            }
            let code = line[..3]
                .parse::<u16>()
                .map_err(|_| SmtpError::Protocol(format!("bad reply code: {line:?}")))?;
            if let Some(expected) = expected_code {
                if code != expected {
                    return Err(SmtpError::Protocol(format!(
                        "multiline reply code changed: {expected} != {code}"
                    )));
                }
            } else {
                expected_code = Some(code);
            }
            let separator = line.as_bytes()[3];
            let text = line[4..].to_string();
            lines.push(text);
            match separator {
                b' ' => break,
                b'-' => continue,
                _ => {
                    return Err(SmtpError::Protocol(format!(
                        "bad reply separator in {line:?}"
                    )));
                }
            }
        }
        Ok(Reply {
            code: expected_code.unwrap_or(0),
            lines,
        })
    }

    pub fn command(&mut self, command: &str) -> Result<Reply, SmtpError> {
        self.write_all(command.as_bytes())?;
        self.write_all(b"\r\n")?;
        self.stream.flush()?;
        self.read_reply()
    }

    pub fn ehlo(&mut self, name: &str) -> Result<Reply, SmtpError> {
        let reply = self.command(&format!("EHLO {name}"))?;
        ensure_code(&reply, 250)?;
        Ok(reply)
    }

    pub fn helo(&mut self, name: &str) -> Result<Reply, SmtpError> {
        let reply = self.command(&format!("HELO {name}"))?;
        ensure_code(&reply, 250)?;
        Ok(reply)
    }

    pub fn auth_plain(&mut self, username: &str, secret: &str) -> Result<Reply, SmtpError> {
        let payload = format!("\0{username}\0{secret}");
        let encoded = BASE64.encode(payload);
        let reply = self.command(&format!("AUTH PLAIN {encoded}"))?;
        ensure_code(&reply, 235)?;
        Ok(reply)
    }

    pub fn send_message(
        &mut self,
        from: &str,
        recipients: &[String],
        data: &[u8],
    ) -> Result<Reply, SmtpError> {
        let reply = self.command(&format!("MAIL FROM:<{from}>"))?;
        ensure_code(&reply, 250)?;
        for recipient in recipients {
            let reply = self.command(&format!("RCPT TO:<{recipient}>"))?;
            if !(250..260).contains(&reply.code) {
                return Err(SmtpError::Protocol(format!(
                    "recipient {recipient} rejected: {reply}"
                )));
            }
        }
        let reply = self.command("DATA")?;
        ensure_code(&reply, 354)?;
        self.write_data(data)?;
        let reply = self.read_reply()?;
        ensure_code(&reply, 250)?;
        Ok(reply)
    }

    pub fn write_data(&mut self, data: &[u8]) -> Result<(), SmtpError> {
        let mut start = 0usize;
        while start < data.len() {
            let end = data[start..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|offset| start + offset + 1)
                .unwrap_or(data.len());
            let line = &data[start..end];
            let line = line.strip_suffix(b"\n").unwrap_or(line);
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.first() == Some(&b'.') {
                self.write_all(b".")?;
            }
            self.write_all(line)?;
            self.write_all(b"\r\n")?;
            start = end;
        }
        if data.is_empty() || !data.ends_with(b"\n") {
            self.write_all(b"\r\n")?;
        }
        self.write_all(b".\r\n")?;
        self.stream.flush()?;
        Ok(())
    }

    pub fn quit(&mut self) -> Result<Reply, SmtpError> {
        self.command("QUIT")
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), SmtpError> {
        self.stream.write_all(bytes)?;
        Ok(())
    }

    fn read_line(&mut self) -> Result<String, SmtpError> {
        let mut bytes = Vec::new();
        loop {
            if let Some(position) = self.read_buffer.iter().position(|byte| *byte == b'\n') {
                bytes.extend_from_slice(&self.read_buffer[..=position]);
                self.read_buffer.drain(..=position);
                break;
            }
            let mut chunk = [0u8; 1024];
            let read = self.stream.read(&mut chunk)?;
            if read == 0 {
                return Err(SmtpError::Protocol("connection closed".into()));
            }
            self.read_buffer.extend_from_slice(&chunk[..read]);
            if self.read_buffer.len() > self.timeout.as_secs() as usize * 1024 * 64 {
                return Err(SmtpError::Protocol("reply line too long".into()));
            }
        }
        while bytes
            .last()
            .is_some_and(|byte| *byte == b'\n' || *byte == b'\r')
        {
            bytes.pop();
        }
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}

fn ensure_code(reply: &Reply, expected: u16) -> Result<(), SmtpError> {
    if reply.code == expected {
        Ok(())
    } else {
        Err(SmtpError::Protocol(format!(
            "expected {expected}, got {reply}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::Cursor;

    struct MockStream {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for MockStream {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buffer)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn client_with_replies(replies: VecDeque<&str>) -> SmtpClient<MockStream> {
        let input = replies.into_iter().collect::<String>().into_bytes();
        SmtpClient::new(MockStream {
            input: Cursor::new(input),
            output: Vec::new(),
        })
    }

    #[test]
    fn reads_multiline_reply() {
        let mut client = client_with_replies(VecDeque::from([
            "250-localhost\r\n",
            "250-SIZE 1024\r\n",
            "250 AUTH PLAIN\r\n",
        ]));
        let reply = client.read_reply().unwrap();
        assert_eq!(reply.code, 250);
        assert_eq!(reply.lines.len(), 3);
        assert_eq!(reply.lines[2], "AUTH PLAIN");
    }

    #[test]
    fn sends_dot_stuffed_message() {
        let mut client = client_with_replies(VecDeque::from([
            "220 hello\r\n",
            "250 ok\r\n",
            "250 ok\r\n",
            "354 go\r\n",
            "250 accepted\r\n",
        ]));
        assert_eq!(client.read_reply().unwrap().code, 220);
        let reply = client
            .send_message(
                "a@example.com",
                &["b@example.com".into()],
                b".hello\r\nworld",
            )
            .unwrap();
        assert_eq!(reply.code, 250);
        let output = String::from_utf8_lossy(&client.stream().output);
        assert!(output.contains("MAIL FROM:<a@example.com>"));
        assert!(output.contains("..hello\r\n"));
        assert!(output.ends_with(".\r\n"));
    }
}
