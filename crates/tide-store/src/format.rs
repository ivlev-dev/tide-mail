use byteorder::{ByteOrder, LittleEndian};

use crate::error::StoreError;

pub const SUPERBLOCK_SIZE: usize = 4096;
pub const SUPERBLOCK_A_OFFSET: u64 = 0;
pub const SUPERBLOCK_B_OFFSET: u64 = 4096;
pub const LANES_OFFSET: u64 = 65536;
pub const LANE_HEADER_SIZE: u64 = 4096;
pub const BATCH_HEADER_SIZE: usize = 64;
pub const BATCH_FOOTER_SIZE: usize = 64;
pub const RECORD_HEADER_SIZE: usize = 40;
pub const BATCH_ALIGN: u64 = 64;

pub const MAGIC_SUPERBLOCK: &[u8; 8] = b"TIDEMAIL";
pub const MAGIC_LANE: &[u8; 4] = b"TDLH";
pub const MAGIC_BATCH: &[u8; 4] = b"TDBB";
pub const MAGIC_FOOTER: &[u8; 4] = b"TDBE";
pub const MAGIC_RECORD: &[u8; 4] = b"TDBR";

pub const FORMAT_VERSION: u32 = 1;
pub const PROTOCOL_VERSION: u16 = 1;

pub const META_LANE: u16 = 0;
pub const INDEX_LANE: u16 = 1;
pub const FIRST_DATA_LANE: u16 = 2;

pub const DEFAULT_LANE_CAPACITY: u64 = 512 * 1024 * 1024;
pub const DEFAULT_DATA_LANES: u16 = 16;
pub const MIN_LANE_CAPACITY: u64 = 4 * 1024 * 1024;
pub const MAX_LANE_CAPACITY: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_BATCH_SIZE: u64 = 64 * 1024 * 1024;
pub const MAX_RECORDS_PER_BATCH: u32 = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Superblock {
    pub version: u32,
    pub page_size: u32,
    pub uuid: [u8; 16],
    pub generation: u64,
    pub lane_capacity: u64,
    pub lane_count: u16,
    pub data_lanes: u16,
    pub created_at: i64,
    pub checkpoint_seq: u64,
}

impl Superblock {
    pub fn encode(&self) -> [u8; SUPERBLOCK_SIZE] {
        let mut out = [0u8; SUPERBLOCK_SIZE];
        out[0..8].copy_from_slice(MAGIC_SUPERBLOCK);
        LittleEndian::write_u32(&mut out[8..12], self.version);
        LittleEndian::write_u32(&mut out[12..16], self.page_size);
        out[16..32].copy_from_slice(&self.uuid);
        LittleEndian::write_u64(&mut out[32..40], self.generation);
        LittleEndian::write_u64(&mut out[40..48], self.lane_capacity);
        LittleEndian::write_u16(&mut out[48..50], self.lane_count);
        LittleEndian::write_u16(&mut out[50..52], self.data_lanes);
        LittleEndian::write_i64(&mut out[52..60], self.created_at);
        LittleEndian::write_u64(&mut out[60..68], self.checkpoint_seq);
        let crc = crc32c::crc32c(&out);
        LittleEndian::write_u32(&mut out[68..72], crc);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() < SUPERBLOCK_SIZE {
            return Err(StoreError::corrupt("superblock too short"));
        }
        if &bytes[0..8] != MAGIC_SUPERBLOCK {
            return Err(StoreError::corrupt("superblock magic mismatch"));
        }
        let stored_crc = LittleEndian::read_u32(&bytes[68..72]);
        let mut copy = bytes[..SUPERBLOCK_SIZE].to_vec();
        copy[68..72].fill(0);
        if crc32c::crc32c(&copy) != stored_crc {
            return Err(StoreError::corrupt("superblock crc mismatch"));
        }
        let version = LittleEndian::read_u32(&bytes[8..12]);
        if version != FORMAT_VERSION {
            return Err(StoreError::corrupt(format!(
                "unsupported format version {version}"
            )));
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&bytes[16..32]);
        let superblock = Self {
            version,
            page_size: LittleEndian::read_u32(&bytes[12..16]),
            uuid,
            generation: LittleEndian::read_u64(&bytes[32..40]),
            lane_capacity: LittleEndian::read_u64(&bytes[40..48]),
            lane_count: LittleEndian::read_u16(&bytes[48..50]),
            data_lanes: LittleEndian::read_u16(&bytes[50..52]),
            created_at: LittleEndian::read_i64(&bytes[52..60]),
            checkpoint_seq: LittleEndian::read_u64(&bytes[60..68]),
        };
        superblock.validate()?;
        Ok(superblock)
    }

    pub fn validate(&self) -> Result<(), StoreError> {
        if self.page_size != SUPERBLOCK_SIZE as u32 {
            return Err(StoreError::Config(format!(
                "unsupported page size {}",
                self.page_size
            )));
        }
        if self.data_lanes == 0 {
            return Err(StoreError::Config("at least one data lane required".into()));
        }
        if self.lane_count != self.data_lanes.saturating_add(FIRST_DATA_LANE) {
            return Err(StoreError::Config("lane count mismatch".into()));
        }
        if !(MIN_LANE_CAPACITY..=MAX_LANE_CAPACITY).contains(&self.lane_capacity) {
            return Err(StoreError::Config(format!(
                "lane capacity {} outside supported range",
                self.lane_capacity
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneHeader {
    pub lane_id: u16,
    pub capacity: u64,
    pub head: u64,
    pub seq: u64,
    pub checkpoint_seq: u64,
    pub checkpoint_head: u64,
}

impl LaneHeader {
    pub fn encode(&self) -> [u8; LANE_HEADER_SIZE as usize] {
        let mut out = [0u8; LANE_HEADER_SIZE as usize];
        out[0..4].copy_from_slice(MAGIC_LANE);
        LittleEndian::write_u16(&mut out[4..6], PROTOCOL_VERSION);
        LittleEndian::write_u16(&mut out[6..8], self.lane_id);
        LittleEndian::write_u64(&mut out[8..16], self.capacity);
        LittleEndian::write_u64(&mut out[16..24], self.head);
        LittleEndian::write_u64(&mut out[24..32], self.seq);
        LittleEndian::write_u64(&mut out[32..40], self.checkpoint_seq);
        LittleEndian::write_u64(&mut out[40..48], self.checkpoint_head);
        let crc = crc32c::crc32c(&out);
        LittleEndian::write_u32(&mut out[48..52], crc);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() < LANE_HEADER_SIZE as usize {
            return Err(StoreError::corrupt("lane header too short"));
        }
        if &bytes[0..4] != MAGIC_LANE {
            return Err(StoreError::corrupt("lane header magic mismatch"));
        }
        let stored_crc = LittleEndian::read_u32(&bytes[48..52]);
        let mut copy = bytes[..LANE_HEADER_SIZE as usize].to_vec();
        copy[48..52].fill(0);
        if crc32c::crc32c(&copy) != stored_crc {
            return Err(StoreError::corrupt("lane header crc mismatch"));
        }
        Ok(Self {
            lane_id: LittleEndian::read_u16(&bytes[6..8]),
            capacity: LittleEndian::read_u64(&bytes[8..16]),
            head: LittleEndian::read_u64(&bytes[16..24]),
            seq: LittleEndian::read_u64(&bytes[24..32]),
            checkpoint_seq: LittleEndian::read_u64(&bytes[32..40]),
            checkpoint_head: LittleEndian::read_u64(&bytes[40..48]),
        })
    }
}

pub fn lane_base(superblock: &Superblock, lane_id: u16) -> Result<u64, StoreError> {
    if lane_id >= superblock.lane_count {
        return Err(StoreError::Config(format!("lane {lane_id} out of range")));
    }
    let offset = LANES_OFFSET
        .checked_add(u64::from(lane_id).saturating_mul(superblock.lane_capacity))
        .ok_or_else(|| StoreError::Config("lane offset overflow".into()))?;
    Ok(offset)
}

pub fn lane_data_start(superblock: &Superblock, lane_id: u16) -> Result<u64, StoreError> {
    Ok(lane_base(superblock, lane_id)? + LANE_HEADER_SIZE)
}

pub fn lane_data_end(superblock: &Superblock, lane_id: u16) -> Result<u64, StoreError> {
    Ok(lane_base(superblock, lane_id)? + superblock.lane_capacity)
}

pub fn file_size(superblock: &Superblock) -> Result<u64, StoreError> {
    let body = u64::from(superblock.lane_count)
        .checked_mul(superblock.lane_capacity)
        .ok_or_else(|| StoreError::Config("file size overflow".into()))?;
    LANES_OFFSET
        .checked_add(body)
        .ok_or_else(|| StoreError::Config("file size overflow".into()))
}

pub fn align_up(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

pub fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    LittleEndian::read_u32(&bytes[offset..offset + 4])
}

pub fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    LittleEndian::read_u64(&bytes[offset..offset + 8])
}

pub fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    LittleEndian::write_u32(&mut bytes[offset..offset + 4], value);
}

pub fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    LittleEndian::write_u64(&mut bytes[offset..offset + 8], value);
}
