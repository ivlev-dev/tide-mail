use byteorder::{ByteOrder, LittleEndian};

use crate::error::StoreError;
use crate::format::{
    BATCH_ALIGN, BATCH_FOOTER_SIZE, BATCH_HEADER_SIZE, MAGIC_BATCH, MAGIC_FOOTER, MAGIC_RECORD,
    MAX_BATCH_SIZE, MAX_RECORDS_PER_BATCH, PROTOCOL_VERSION, RECORD_HEADER_SIZE, align_up,
    read_u32, read_u64, write_u32, write_u64,
};

pub const KIND_MESSAGE: u16 = 1;
pub const KIND_DELETE: u16 = 2;
pub const KIND_FLAGS: u16 = 3;
pub const KIND_MOVE: u16 = 4;
pub const KIND_META: u16 = 5;
pub const KIND_NOTE: u16 = 6;

pub const RECORD_FLAG_ZSTD: u32 = 1 << 0;

const ZSTD_THRESHOLD: usize = 1024;
const ZSTD_MAX_DECOMPRESSED: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub kind: u16,
    pub flags: u32,
    pub key: String,
    pub payload: Vec<u8>,
}

impl Record {
    pub fn new(kind: u16, key: impl Into<String>, payload: Vec<u8>) -> Self {
        Self {
            kind,
            flags: 0,
            key: key.into(),
            payload,
        }
    }

    pub fn message(key: impl Into<String>, payload: Vec<u8>) -> Self {
        Self::new(KIND_MESSAGE, key, payload)
    }

    pub fn delete(key: impl Into<String>) -> Self {
        Self::new(KIND_DELETE, key, Vec::new())
    }

    pub fn flags(key: impl Into<String>, flags: u64) -> Self {
        Self::new(KIND_FLAGS, key, flags.to_le_bytes().to_vec())
    }

    pub fn note(key: impl Into<String>, payload: Vec<u8>) -> Self {
        Self::new(KIND_NOTE, key, payload)
    }

    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewBatch {
    pub txn_id: u64,
    pub records: Vec<Record>,
}

impl NewBatch {
    pub fn new(records: Vec<Record>) -> Self {
        Self {
            txn_id: new_txn_id(),
            records,
        }
    }

    pub fn single(record: Record) -> Self {
        Self::new(vec![record])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBatch {
    pub lane_id: u16,
    pub seq: u64,
    pub txn_id: u64,
    pub total_len: u64,
    pub records: Vec<Record>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BatchHeaderFields {
    lane_id: u16,
    flags: u32,
    total_len: u32,
    txn_id: u64,
    seq: u64,
    created_at: i64,
    record_count: u32,
}

pub fn encode_batch(lane_id: u16, seq: u64, batch: &NewBatch) -> Result<Vec<u8>, StoreError> {
    if batch.records.is_empty() {
        return Err(StoreError::invalid_batch("empty batch"));
    }
    if batch.records.len() > MAX_RECORDS_PER_BATCH as usize {
        return Err(StoreError::invalid_batch(format!(
            "too many records: {}",
            batch.records.len()
        )));
    }

    let mut records_buf = Vec::new();
    for record in &batch.records {
        encode_record(record, &mut records_buf)?;
    }

    let unaligned = BATCH_HEADER_SIZE as u64 + records_buf.len() as u64 + BATCH_FOOTER_SIZE as u64;
    let total_len = align_up(unaligned, BATCH_ALIGN);
    if total_len > MAX_BATCH_SIZE {
        return Err(StoreError::invalid_batch(format!(
            "batch is too large: {total_len} bytes"
        )));
    }
    let total_len_usize =
        usize::try_from(total_len).map_err(|_| StoreError::invalid_batch("batch size overflow"))?;
    let mut out = vec![0u8; total_len_usize];
    let total_len_u32 =
        u32::try_from(total_len).map_err(|_| StoreError::invalid_batch("batch size overflow"))?;
    let record_count_u32 = u32::try_from(batch.records.len())
        .map_err(|_| StoreError::invalid_batch("record count overflow"))?;
    let created_at = now_millis();

    let header = BatchHeaderFields {
        lane_id,
        flags: 0,
        total_len: total_len_u32,
        txn_id: batch.txn_id,
        seq,
        created_at,
        record_count: record_count_u32,
    };
    write_batch_header(&mut out[..BATCH_HEADER_SIZE], &header);
    out[BATCH_HEADER_SIZE..BATCH_HEADER_SIZE + records_buf.len()].copy_from_slice(&records_buf);

    let footer_offset = total_len_usize - BATCH_FOOTER_SIZE;
    let batch_crc = crc32c::crc32c(&out[..footer_offset]);
    write_batch_footer(
        &mut out[footer_offset..],
        total_len_u32,
        record_count_u32,
        batch_crc,
    );
    Ok(out)
}

pub fn peek_batch_len(bytes: &[u8]) -> Result<u64, StoreError> {
    if bytes.len() < BATCH_HEADER_SIZE {
        return Err(StoreError::invalid_batch("batch header too short"));
    }
    if &bytes[0..4] != MAGIC_BATCH {
        return Err(StoreError::invalid_batch("batch magic mismatch"));
    }
    if LittleEndian::read_u16(&bytes[4..6]) != PROTOCOL_VERSION {
        return Err(StoreError::invalid_batch("batch version mismatch"));
    }
    let stored_crc = read_u32(bytes, 44);
    let mut copy = bytes[..BATCH_HEADER_SIZE].to_vec();
    write_u32(&mut copy, 44, 0);
    if crc32c::crc32c(&copy) != stored_crc {
        return Err(StoreError::invalid_batch("batch header crc mismatch"));
    }
    let total_len = u64::from(read_u32(bytes, 12));
    if total_len < (BATCH_HEADER_SIZE + BATCH_FOOTER_SIZE) as u64 {
        return Err(StoreError::invalid_batch("batch too short"));
    }
    if total_len > MAX_BATCH_SIZE {
        return Err(StoreError::invalid_batch("batch too large"));
    }
    if total_len % BATCH_ALIGN != 0 {
        return Err(StoreError::invalid_batch("batch is not aligned"));
    }
    Ok(total_len)
}

pub fn decode_batch(bytes: &[u8]) -> Result<DecodedBatch, StoreError> {
    let total_len = peek_batch_len(bytes)?;
    let total_len_usize =
        usize::try_from(total_len).map_err(|_| StoreError::invalid_batch("batch size overflow"))?;
    if bytes.len() != total_len_usize {
        return Err(StoreError::invalid_batch(format!(
            "batch length mismatch: expected {total_len}, got {}",
            bytes.len()
        )));
    }
    let header = read_batch_header(&bytes[..BATCH_HEADER_SIZE])?;
    let footer_offset = total_len_usize - BATCH_FOOTER_SIZE;
    let footer = &bytes[footer_offset..];
    if &footer[0..4] != MAGIC_FOOTER {
        return Err(StoreError::invalid_batch("footer magic mismatch"));
    }
    if LittleEndian::read_u16(&footer[4..6]) != PROTOCOL_VERSION {
        return Err(StoreError::invalid_batch("footer version mismatch"));
    }
    let footer_total = read_u32(footer, 8);
    let footer_count = read_u32(footer, 12);
    let footer_batch_crc = read_u32(footer, 16);
    let footer_crc = read_u32(footer, 20);
    let mut footer_copy = footer[..BATCH_FOOTER_SIZE].to_vec();
    write_u32(&mut footer_copy, 20, 0);
    if crc32c::crc32c(&footer_copy) != footer_crc {
        return Err(StoreError::invalid_batch("footer crc mismatch"));
    }
    if footer_total != header.total_len {
        return Err(StoreError::invalid_batch("footer length mismatch"));
    }
    if footer_count != header.record_count {
        return Err(StoreError::invalid_batch("footer record count mismatch"));
    }
    let actual_batch_crc = crc32c::crc32c(&bytes[..footer_offset]);
    if actual_batch_crc != footer_batch_crc {
        return Err(StoreError::invalid_batch("batch crc mismatch"));
    }
    if header.lane_id >= 4096 {
        return Err(StoreError::invalid_batch("invalid lane id"));
    }
    if header.record_count > MAX_RECORDS_PER_BATCH {
        return Err(StoreError::invalid_batch("too many records"));
    }

    let mut records = Vec::with_capacity(header.record_count as usize);
    let mut offset = BATCH_HEADER_SIZE;
    for index in 0..header.record_count {
        if offset + RECORD_HEADER_SIZE > footer_offset {
            return Err(StoreError::invalid_batch(format!(
                "record {index} header out of bounds"
            )));
        }
        let record = decode_record(&bytes[offset..footer_offset])?;
        offset += record.0;
        records.push(record.1);
    }

    Ok(DecodedBatch {
        lane_id: header.lane_id,
        seq: header.seq,
        txn_id: header.txn_id,
        total_len,
        records,
    })
}

fn encode_record(record: &Record, out: &mut Vec<u8>) -> Result<(), StoreError> {
    let mut flags = record.flags;
    let mut payload = record.payload.clone();
    if payload.len() >= ZSTD_THRESHOLD {
        let compressed = zstd::bulk::compress(&payload, 3)
            .map_err(|err| StoreError::invalid_batch(format!("zstd compress: {err}")))?;
        if compressed.len() + 32 < payload.len() {
            payload = compressed;
            flags |= RECORD_FLAG_ZSTD;
        }
    }

    let key = record.key.as_bytes();
    let key_len =
        u32::try_from(key.len()).map_err(|_| StoreError::invalid_batch("record key too long"))?;
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| StoreError::invalid_batch("record payload too long"))?;
    let record_len = RECORD_HEADER_SIZE
        .checked_add(key.len())
        .and_then(|value| value.checked_add(payload.len()))
        .ok_or_else(|| StoreError::invalid_batch("record length overflow"))?;
    let record_len =
        u32::try_from(record_len).map_err(|_| StoreError::invalid_batch("record too large"))?;

    let start = out.len();
    out.resize(start + RECORD_HEADER_SIZE, 0);
    let header = &mut out[start..start + RECORD_HEADER_SIZE];
    header[0..4].copy_from_slice(MAGIC_RECORD);
    LittleEndian::write_u16(&mut header[4..6], PROTOCOL_VERSION);
    LittleEndian::write_u16(&mut header[6..8], record.kind);
    write_u32(header, 8, flags);
    write_u32(header, 12, key_len);
    write_u32(header, 16, payload_len);
    write_u32(header, 20, record_len);
    write_u32(header, 24, crc32c::crc32c(key));
    write_u32(header, 28, crc32c::crc32c(&payload));
    let header_crc = crc32c::crc32c(header);
    write_u32(header, 32, header_crc);
    out.extend_from_slice(key);
    out.extend_from_slice(&payload);
    Ok(())
}

fn decode_record(bytes: &[u8]) -> Result<(usize, Record), StoreError> {
    if bytes.len() < RECORD_HEADER_SIZE {
        return Err(StoreError::invalid_batch("record header too short"));
    }
    if &bytes[0..4] != MAGIC_RECORD {
        return Err(StoreError::invalid_batch("record magic mismatch"));
    }
    if LittleEndian::read_u16(&bytes[4..6]) != PROTOCOL_VERSION {
        return Err(StoreError::invalid_batch("record version mismatch"));
    }
    let kind = LittleEndian::read_u16(&bytes[6..8]);
    let flags = read_u32(bytes, 8);
    let key_len = read_u32(bytes, 12) as usize;
    let payload_len = read_u32(bytes, 16) as usize;
    let record_len = read_u32(bytes, 20) as usize;
    let key_crc = read_u32(bytes, 24);
    let payload_crc = read_u32(bytes, 28);
    let header_crc = read_u32(bytes, 32);
    let mut header_copy = bytes[..RECORD_HEADER_SIZE].to_vec();
    write_u32(&mut header_copy, 32, 0);
    if crc32c::crc32c(&header_copy) != header_crc {
        return Err(StoreError::invalid_batch("record header crc mismatch"));
    }
    if key_len > 1024 * 1024 {
        return Err(StoreError::invalid_batch("record key too long"));
    }
    if payload_len > ZSTD_MAX_DECOMPRESSED {
        return Err(StoreError::invalid_batch("record payload too long"));
    }
    let expected = RECORD_HEADER_SIZE
        .checked_add(key_len)
        .and_then(|value| value.checked_add(payload_len))
        .ok_or_else(|| StoreError::invalid_batch("record length overflow"))?;
    if record_len != expected || record_len > bytes.len() {
        return Err(StoreError::invalid_batch("record length mismatch"));
    }
    let key_bytes = &bytes[RECORD_HEADER_SIZE..RECORD_HEADER_SIZE + key_len];
    let payload_bytes =
        &bytes[RECORD_HEADER_SIZE + key_len..RECORD_HEADER_SIZE + key_len + payload_len];
    if crc32c::crc32c(key_bytes) != key_crc {
        return Err(StoreError::invalid_batch("record key crc mismatch"));
    }
    if crc32c::crc32c(payload_bytes) != payload_crc {
        return Err(StoreError::invalid_batch("record payload crc mismatch"));
    }
    let key = String::from_utf8(key_bytes.to_vec())
        .map_err(|_| StoreError::invalid_batch("record key is not utf-8"))?;
    let payload = if flags & RECORD_FLAG_ZSTD != 0 {
        zstd::bulk::decompress(payload_bytes, ZSTD_MAX_DECOMPRESSED)
            .map_err(|err| StoreError::invalid_batch(format!("zstd decompress: {err}")))?
    } else {
        payload_bytes.to_vec()
    };
    Ok((
        record_len,
        Record {
            kind,
            flags,
            key,
            payload,
        },
    ))
}

fn write_batch_header(out: &mut [u8], header: &BatchHeaderFields) {
    out.fill(0);
    out[0..4].copy_from_slice(MAGIC_BATCH);
    LittleEndian::write_u16(&mut out[4..6], PROTOCOL_VERSION);
    LittleEndian::write_u16(&mut out[6..8], header.lane_id);
    write_u32(out, 8, header.flags);
    write_u32(out, 12, header.total_len);
    write_u64(out, 16, header.txn_id);
    write_u64(out, 24, header.seq);
    LittleEndian::write_i64(&mut out[32..40], header.created_at);
    write_u32(out, 40, header.record_count);
    let crc = crc32c::crc32c(out);
    write_u32(out, 44, crc);
}

fn read_batch_header(bytes: &[u8]) -> Result<BatchHeaderFields, StoreError> {
    if &bytes[0..4] != MAGIC_BATCH {
        return Err(StoreError::invalid_batch("batch magic mismatch"));
    }
    if LittleEndian::read_u16(&bytes[4..6]) != PROTOCOL_VERSION {
        return Err(StoreError::invalid_batch("batch protocol version mismatch"));
    }
    let stored_crc = read_u32(bytes, 44);
    let mut copy = bytes[..BATCH_HEADER_SIZE].to_vec();
    write_u32(&mut copy, 44, 0);
    if crc32c::crc32c(&copy) != stored_crc {
        return Err(StoreError::invalid_batch("batch header crc mismatch"));
    }
    Ok(BatchHeaderFields {
        lane_id: LittleEndian::read_u16(&bytes[6..8]),
        flags: read_u32(bytes, 8),
        total_len: read_u32(bytes, 12),
        txn_id: read_u64(bytes, 16),
        seq: read_u64(bytes, 24),
        created_at: LittleEndian::read_i64(&bytes[32..40]),
        record_count: read_u32(bytes, 40),
    })
}

fn write_batch_footer(out: &mut [u8], total_len: u32, record_count: u32, batch_crc: u32) {
    out.fill(0);
    out[0..4].copy_from_slice(MAGIC_FOOTER);
    LittleEndian::write_u16(&mut out[4..6], PROTOCOL_VERSION);
    write_u32(out, 8, total_len);
    write_u32(out, 12, record_count);
    write_u32(out, 16, batch_crc);
    let crc = crc32c::crc32c(out);
    write_u32(out, 20, crc);
}

pub fn new_txn_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let base = now_millis() as u64;
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    (base << 16) | (counter & 0xFFFF)
}

pub fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_batch() -> NewBatch {
        NewBatch {
            txn_id: 7,
            records: vec![
                Record::message("msg-1", vec![1, 2, 3, 4]),
                Record::flags("msg-1", tide_core::flags::SEEN),
                Record::delete("msg-2"),
            ],
        }
    }

    #[test]
    fn roundtrip_batch() {
        let batch = sample_batch();
        let encoded = encode_batch(3, 11, &batch).unwrap();
        let decoded = decode_batch(&encoded).unwrap();
        assert_eq!(decoded.lane_id, 3);
        assert_eq!(decoded.seq, 11);
        assert_eq!(decoded.txn_id, 7);
        assert_eq!(decoded.records, batch.records);
        assert_eq!(decoded.total_len as usize, encoded.len());
    }

    #[test]
    fn compresses_large_payload() {
        let payload = vec![b'a'; 64 * 1024];
        let batch = NewBatch {
            txn_id: 1,
            records: vec![Record::message("big", payload.clone())],
        };
        let encoded = encode_batch(2, 1, &batch).unwrap();
        assert!(encoded.len() < payload.len());
        let decoded = decode_batch(&encoded).unwrap();
        assert_eq!(decoded.records[0].payload, payload);
        assert_ne!(decoded.records[0].flags & RECORD_FLAG_ZSTD, 0);
    }

    #[test]
    fn rejects_corrupted_payload() {
        let batch = sample_batch();
        let mut encoded = encode_batch(3, 11, &batch).unwrap();
        let index = encoded.len() / 2;
        encoded[index] ^= 0xFF;
        assert!(decode_batch(&encoded).is_err());
    }

    #[test]
    fn rejects_torn_batch() {
        let batch = sample_batch();
        let encoded = encode_batch(3, 11, &batch).unwrap();
        let torn = &encoded[..encoded.len() / 2];
        assert!(decode_batch(torn).is_err());
    }

    #[test]
    fn peeks_length_without_full_batch() {
        let batch = sample_batch();
        let encoded = encode_batch(3, 11, &batch).unwrap();
        assert_eq!(
            peek_batch_len(&encoded[..BATCH_HEADER_SIZE]).unwrap(),
            encoded.len() as u64
        );
    }
}
