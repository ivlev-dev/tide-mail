use byteorder::{ByteOrder, LittleEndian};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: u8,
    pub flags: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("frame too short")]
    TooShort,
    #[error("invalid frame magic")]
    BadMagic,
    #[error("unsupported frame version {0}")]
    BadVersion(u8),
    #[error("frame is too large: {0}")]
    TooLarge(u32),
    #[error("frame length mismatch: expected {expected}, got {actual}")]
    LengthMismatch { expected: usize, actual: usize },
    #[error("frame payload crc mismatch")]
    CrcMismatch,
}

pub const FRAME_MAGIC: &[u8; 4] = b"TDS1";
pub const FRAME_VERSION: u8 = 1;
pub const FRAME_HEADER_SIZE: usize = 16;
pub const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

pub mod kind {
    pub const HELLO: u8 = 1;
    pub const HELLO_OK: u8 = 2;
    pub const AUTH: u8 = 3;
    pub const AUTH_OK: u8 = 4;
    pub const PULL: u8 = 5;
    pub const CHANGES: u8 = 6;
    pub const PUSH: u8 = 7;
    pub const PUSH_OK: u8 = 8;
    pub const ACK: u8 = 9;
    pub const WATCH: u8 = 10;
    pub const EVENT: u8 = 11;
    pub const BLOB_REQUEST: u8 = 12;
    pub const BLOB_CHUNK: u8 = 13;
    pub const ERROR: u8 = 14;
    pub const PING: u8 = 15;
    pub const PONG: u8 = 16;
}

impl Frame {
    pub fn new(kind: u8, payload: Vec<u8>) -> Self {
        Self {
            kind,
            flags: 0,
            payload,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let length =
            u32::try_from(self.payload.len()).map_err(|_| FrameError::TooLarge(u32::MAX))?;
        if length > MAX_FRAME_SIZE {
            return Err(FrameError::TooLarge(length));
        }
        let mut out = vec![0u8; FRAME_HEADER_SIZE + self.payload.len()];
        out[0..4].copy_from_slice(FRAME_MAGIC);
        out[4] = FRAME_VERSION;
        out[5] = self.kind;
        LittleEndian::write_u16(&mut out[6..8], self.flags);
        LittleEndian::write_u32(&mut out[8..12], length);
        LittleEndian::write_u32(&mut out[12..16], crc32c::crc32c(&self.payload));
        out[FRAME_HEADER_SIZE..].copy_from_slice(&self.payload);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < FRAME_HEADER_SIZE {
            return Err(FrameError::TooShort);
        }
        if &bytes[0..4] != FRAME_MAGIC {
            return Err(FrameError::BadMagic);
        }
        if bytes[4] != FRAME_VERSION {
            return Err(FrameError::BadVersion(bytes[4]));
        }
        let kind = bytes[5];
        let flags = LittleEndian::read_u16(&bytes[6..8]);
        let length = LittleEndian::read_u32(&bytes[8..12]);
        if length > MAX_FRAME_SIZE {
            return Err(FrameError::TooLarge(length));
        }
        let expected = FRAME_HEADER_SIZE + length as usize;
        if bytes.len() != expected {
            return Err(FrameError::LengthMismatch {
                expected,
                actual: bytes.len(),
            });
        }
        let payload = &bytes[FRAME_HEADER_SIZE..];
        let stored_crc = LittleEndian::read_u32(&bytes[12..16]);
        if crc32c::crc32c(payload) != stored_crc {
            return Err(FrameError::CrcMismatch);
        }
        Ok(Self {
            kind,
            flags,
            payload: payload.to_vec(),
        })
    }

    pub fn encoded_len(&self) -> usize {
        FRAME_HEADER_SIZE + self.payload.len()
    }
}

pub fn frame_length(header: &[u8]) -> Result<usize, FrameError> {
    if header.len() < FRAME_HEADER_SIZE {
        return Err(FrameError::TooShort);
    }
    if &header[0..4] != FRAME_MAGIC {
        return Err(FrameError::BadMagic);
    }
    if header[4] != FRAME_VERSION {
        return Err(FrameError::BadVersion(header[4]));
    }
    let length = LittleEndian::read_u32(&header[8..12]);
    if length > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge(length));
    }
    Ok(FRAME_HEADER_SIZE + length as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let frame = Frame::new(kind::PING, vec![1, 2, 3]);
        let encoded = frame.encode().unwrap();
        assert_eq!(Frame::decode(&encoded).unwrap(), frame);
        assert_eq!(
            frame_length(&encoded[..FRAME_HEADER_SIZE]).unwrap(),
            encoded.len()
        );
    }

    #[test]
    fn rejects_corrupted_frame() {
        let frame = Frame::new(kind::PULL, vec![1, 2, 3, 4]);
        let mut encoded = frame.encode().unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 0xFF;
        assert_eq!(Frame::decode(&encoded), Err(FrameError::CrcMismatch));
    }

    #[test]
    fn rejects_oversized_frame() {
        let mut header = vec![0u8; FRAME_HEADER_SIZE];
        header[0..4].copy_from_slice(FRAME_MAGIC);
        header[4] = FRAME_VERSION;
        LittleEndian::write_u32(&mut header[8..12], MAX_FRAME_SIZE + 1);
        assert!(matches!(
            frame_length(&header),
            Err(FrameError::TooLarge(_))
        ));
    }
}
