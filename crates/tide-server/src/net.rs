use std::io;

use monoio::io::{AsyncReadRent, AsyncWriteRentExt};
use monoio::net::TcpStream;
use monoio_rustls::{ServerTlsStream, TlsAcceptor};

pub enum Conn {
    Plain(TcpStream),
    Tls(Box<ServerTlsStream<TcpStream>>),
    Empty,
}

impl Conn {
    pub fn plain(stream: TcpStream) -> Self {
        Self::Plain(stream)
    }

    pub async fn read(&mut self, buffer: Vec<u8>) -> (io::Result<usize>, Vec<u8>) {
        match self {
            Self::Plain(stream) => stream.read(buffer).await,
            Self::Tls(stream) => stream.read(buffer).await,
            Self::Empty => (
                Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "connection closed",
                )),
                buffer,
            ),
        }
    }

    pub async fn write_all(&mut self, buffer: Vec<u8>) -> io::Result<()> {
        match self {
            Self::Plain(stream) => {
                let (result, _) = stream.write_all(buffer).await;
                result.map(|_| ())
            }
            Self::Tls(stream) => {
                let (result, _) = stream.write_all(buffer).await;
                result.map(|_| ())
            }
            Self::Empty => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection closed",
            )),
        }
    }
}

pub struct BufferedConn {
    conn: Conn,
    buffer: Vec<u8>,
    eof: bool,
}

impl BufferedConn {
    pub fn new(conn: Conn) -> Self {
        Self {
            conn,
            buffer: Vec::new(),
            eof: false,
        }
    }

    pub async fn fill(&mut self) -> io::Result<usize> {
        if self.eof {
            return Ok(0);
        }
        let mut chunk = vec![0u8; 16 * 1024];
        let (result, returned) = self.conn.read(chunk).await;
        let read = result?;
        chunk = returned;
        if read == 0 {
            self.eof = true;
        } else {
            self.buffer.extend_from_slice(&chunk[..read]);
        }
        Ok(read)
    }

    pub async fn read_line(&mut self, max: usize) -> io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(position) = self.buffer.iter().position(|byte| *byte == b'\n') {
                let mut line: Vec<u8> = self.buffer.drain(..=position).collect();
                while line
                    .last()
                    .is_some_and(|byte| *byte == b'\n' || *byte == b'\r')
                {
                    line.pop();
                }
                return Ok(Some(line));
            }
            if self.buffer.len() > max {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
            }
            if self.eof {
                if self.buffer.is_empty() {
                    return Ok(None);
                }
                let line = std::mem::take(&mut self.buffer);
                return Ok(Some(line));
            }
            self.fill().await?;
        }
    }

    pub async fn read_exact(&mut self, length: usize, max: usize) -> io::Result<Vec<u8>> {
        if length > max {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
        }
        while self.buffer.len() < length {
            if self.eof {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected eof",
                ));
            }
            self.fill().await?;
        }
        Ok(self.buffer.drain(..length).collect())
    }

    pub async fn read_headers(&mut self, max: usize) -> io::Result<Vec<u8>> {
        loop {
            if let Some(position) = find_header_end(&self.buffer) {
                return Ok(self.buffer.drain(..position).collect());
            }
            if self.buffer.len() > max {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "headers too large",
                ));
            }
            if self.eof {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before headers",
                ));
            }
            self.fill().await?;
        }
    }

    pub async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.conn.write_all(bytes.to_vec()).await
    }

    pub async fn start_tls(&mut self, acceptor: &TlsAcceptor) -> io::Result<()> {
        self.buffer.clear();
        let conn = std::mem::replace(&mut self.conn, Conn::Empty);
        match conn {
            Conn::Plain(stream) => {
                let tls = acceptor
                    .accept(stream)
                    .await
                    .map_err(|error| io::Error::other(error.to_string()))?;
                self.conn = Conn::Tls(Box::new(tls));
                Ok(())
            }
            other => {
                self.conn = other;
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TLS already active",
                ))
            }
        }
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
        return Some(position + 4);
    }
    bytes
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|position| position + 2)
}
