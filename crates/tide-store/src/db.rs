use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use memmap2::{Mmap, MmapOptions};
use parking_lot::RwLock;
use silent_protocol::SilentProto;
use tide_core::Message;
use uuid::Uuid;

use crate::batch::{
    DecodedBatch, KIND_DELETE, KIND_FLAGS, KIND_MESSAGE, KIND_MOVE, NewBatch, Record, decode_batch,
};
use crate::error::StoreError;
use crate::format::{
    DEFAULT_DATA_LANES, DEFAULT_LANE_CAPACITY, FIRST_DATA_LANE, FORMAT_VERSION, LANE_HEADER_SIZE,
    LaneHeader, MAX_LANE_CAPACITY, MIN_LANE_CAPACITY, SUPERBLOCK_A_OFFSET, SUPERBLOCK_B_OFFSET,
    SUPERBLOCK_SIZE, Superblock, file_size, lane_base, lane_data_start,
};
use crate::index::{SearchHit, SearchIndex, SearchQuery};
use crate::lane::{Durability, LaneWriter, Receipt, replay_lane, spawn_lane, write_all_at};

const MAX_DATA_LANES: u16 = 128;

#[derive(Debug, Clone)]
pub struct StoreOptions {
    pub data_lanes: u16,
    pub lane_capacity: u64,
    pub durability: Durability,
}

impl Default for StoreOptions {
    fn default() -> Self {
        Self {
            data_lanes: DEFAULT_DATA_LANES,
            lane_capacity: DEFAULT_LANE_CAPACITY,
            durability: Durability::DataSync,
        }
    }
}

impl StoreOptions {
    pub fn with_data_lanes(mut self, lanes: u16) -> Self {
        self.data_lanes = lanes;
        self
    }

    pub fn with_lane_capacity(mut self, capacity: u64) -> Self {
        self.lane_capacity = capacity;
        self
    }

    pub fn with_durability(mut self, durability: Durability) -> Self {
        self.durability = durability;
        self
    }

    fn validate(&self) -> Result<(), StoreError> {
        if self.data_lanes == 0 || self.data_lanes > MAX_DATA_LANES {
            return Err(StoreError::Config(format!(
                "data_lanes must be in 1..={MAX_DATA_LANES}"
            )));
        }
        if !(MIN_LANE_CAPACITY..=MAX_LANE_CAPACITY).contains(&self.lane_capacity) {
            return Err(StoreError::Config(format!(
                "lane_capacity must be in {MIN_LANE_CAPACITY}..={MAX_LANE_CAPACITY}"
            )));
        }
        if self.lane_capacity % 64 != 0 {
            return Err(StoreError::Config(
                "lane_capacity must be aligned to 64 bytes".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct Location {
    lane_id: u16,
    batch_offset: u64,
    batch_len: u64,
    record_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreStats {
    pub path: PathBuf,
    pub generation: u64,
    pub data_lanes: u16,
    pub lane_capacity: u64,
    pub messages: usize,
}

struct DbInner {
    path: PathBuf,
    mmap: Mmap,
    file: Arc<File>,
    superblock: Superblock,
    generation: AtomicU64,
    lanes: Vec<LaneWriter>,
    index: RwLock<SearchIndex>,
    catalog: RwLock<HashMap<String, Location>>,
}

#[derive(Clone)]
pub struct Db {
    inner: Arc<DbInner>,
}

#[derive(Debug, Clone, PartialEq, Eq, SilentProto)]
struct MovePayload {
    account_id: String,
    mailbox: String,
}

impl Db {
    pub fn open(path: impl AsRef<Path>, options: StoreOptions) -> Result<Self, StoreError> {
        options.validate()?;
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        lock_file(&file)?;

        let length = file.metadata()?.len();
        if length == 0 {
            initialize_file(&file, &options)?;
        } else if length < crate::format::LANES_OFFSET {
            return Err(StoreError::corrupt(format!(
                "file is too short: {length} bytes"
            )));
        }

        let file = Arc::new(file);
        let file_length = file.metadata()?.len();
        let superblock = read_superblock(&file)?;
        let required = file_size(&superblock)?;
        if file_length < required {
            return Err(StoreError::corrupt(format!(
                "file is truncated: {file_length} < {required}"
            )));
        }

        let mmap = unsafe {
            MmapOptions::new()
                .len(usize::try_from(required).map_err(|_| {
                    StoreError::Config("file is too large for this platform".into())
                })?)
                .map(&file)?
        };

        let mut index = SearchIndex::new();
        let mut catalog = HashMap::new();
        let mut lanes = Vec::with_capacity(superblock.lane_count as usize);
        let mut init_ring =
            io_uring::IoUring::new(8).map_err(StoreError::Io)?;

        for lane_id in 0..superblock.lane_count {
            let base = lane_base(&superblock, lane_id)?;
            let data_start = lane_data_start(&superblock, lane_id)?;
            let _header = read_lane_header(&file, &superblock, lane_id, base, data_start)?;
            let (head, seq, batches) =
                replay_lane(&mmap, base, superblock.lane_capacity, data_start, 1)?;
            let mut offset = data_start;
            for batch in &batches {
                apply_batch_to_maps(
                    lane_id,
                    batch,
                    offset,
                    &mut index,
                    &mut catalog,
                )?;
                offset += batch.total_len;
            }
            let recovered = LaneHeader {
                lane_id,
                capacity: superblock.lane_capacity,
                head,
                seq,
                checkpoint_seq: seq.saturating_sub(1),
                checkpoint_head: head,
            };
            write_all_at(
                &mut init_ring,
                file.as_raw_fd(),
                &recovered.encode(),
                base,
                true,
            )?;
            let writer = spawn_lane(
                lane_id,
                Arc::clone(&file),
                base,
                superblock.lane_capacity,
                head,
                seq,
                options.durability,
            )?;
            lanes.push(writer);
        }

        let generation = superblock.generation;
        let inner = DbInner {
            path,
            mmap,
            file,
            superblock,
            generation: AtomicU64::new(generation),
            lanes,
            index: RwLock::new(index),
            catalog: RwLock::new(catalog),
        };
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    pub fn stats(&self) -> StoreStats {
        StoreStats {
            path: self.inner.path.clone(),
            generation: self.inner.generation.load(Ordering::Relaxed),
            data_lanes: self.inner.superblock.data_lanes,
            lane_capacity: self.inner.superblock.lane_capacity,
            messages: self.inner.index.read().len(),
        }
    }

    pub fn lane_for_account(&self, account_id: &str) -> LaneWriter {
        let data_lanes = self.inner.superblock.data_lanes;
        let slot = (fnv1a(account_id.as_bytes()) % u64::from(data_lanes)) as u16;
        let lane_id = FIRST_DATA_LANE + slot;
        self.inner.lanes[lane_id as usize].clone()
    }

    pub async fn append_message(&self, message: Message) -> Result<Receipt, StoreError> {
        message.validate()?;
        let payload = message.encode()?;
        let batch = NewBatch::single(Record::message(message.id.clone(), payload));
        self.append_batch(&message.account_id, batch).await
    }

    pub fn append_message_blocking(&self, message: Message) -> Result<Receipt, StoreError> {
        futures::executor::block_on(self.append_message(message))
    }

    pub async fn append_batch(
        &self,
        account_id: &str,
        batch: NewBatch,
    ) -> Result<Receipt, StoreError> {
        if account_id.is_empty() {
            return Err(StoreError::Config("empty account id".into()));
        }
        validate_batch(account_id, &batch)?;
        let records = batch.records.clone();
        let lane = self.lane_for_account(account_id);
        let receipt = lane.append(batch).await?;
        self.apply_committed_records(
            receipt.lane_id,
            receipt.offset,
            receipt.total_len,
            &records,
        )?;
        Ok(receipt)
    }

    pub fn append_batch_blocking(
        &self,
        account_id: &str,
        batch: NewBatch,
    ) -> Result<Receipt, StoreError> {
        futures::executor::block_on(self.append_batch(account_id, batch))
    }

    pub fn get_message(&self, id: &str) -> Result<Option<Message>, StoreError> {
        let location = match self.inner.catalog.read().get(id).copied() {
            Some(location) => location,
            None => return Ok(None),
        };
        let start = usize::try_from(location.batch_offset)
            .map_err(|_| StoreError::corrupt("batch offset overflow"))?;
        let length = usize::try_from(location.batch_len)
            .map_err(|_| StoreError::corrupt("batch length overflow"))?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| StoreError::corrupt("batch end overflow"))?;
        if end > self.inner.mmap.len() {
            return Err(StoreError::corrupt("batch outside mmap"));
        }
        let decoded = decode_batch(&self.inner.mmap[start..end])?;
        let record = decoded
            .records
            .get(location.record_index)
            .ok_or_else(|| StoreError::corrupt("record index out of bounds"))?;
        let mut message = Message::decode(&record.payload)?;
        if let Some(doc) = self.inner.index.read().get(id) {
            message.flags = doc.flags;
            message.account_id = doc.account_id.clone();
            message.mailbox = doc.mailbox.clone();
        }
        Ok(Some(message))
    }

    pub fn search(&self, query: &SearchQuery) -> Vec<SearchHit> {
        self.inner.index.read().search(query)
    }

    pub fn index_size(&self) -> usize {
        self.inner.index.read().len()
    }

    pub async fn delete_message(&self, id: &str) -> Result<Receipt, StoreError> {
        let location = self.location(id)?;
        let lane = self
            .inner
            .lanes
            .get(location.lane_id as usize)
            .ok_or_else(|| StoreError::corrupt("lane out of bounds"))?
            .clone();
        let receipt = lane.append(NewBatch::single(Record::delete(id))).await?;
        self.inner.index.write().delete(id);
        self.inner.catalog.write().remove(id);
        Ok(receipt)
    }

    pub async fn update_flags(&self, id: &str, flags: u64) -> Result<Receipt, StoreError> {
        let location = self.location(id)?;
        let lane = self
            .inner
            .lanes
            .get(location.lane_id as usize)
            .ok_or_else(|| StoreError::corrupt("lane out of bounds"))?
            .clone();
        let receipt = lane
            .append(NewBatch::single(Record::flags(id, flags)))
            .await?;
        self.inner.index.write().update_flags(id, flags);
        Ok(receipt)
    }

    pub async fn move_message(
        &self,
        id: &str,
        account_id: &str,
        mailbox: &str,
    ) -> Result<Receipt, StoreError> {
        let location = self.location(id)?;
        let lane = self
            .inner
            .lanes
            .get(location.lane_id as usize)
            .ok_or_else(|| StoreError::corrupt("lane out of bounds"))?
            .clone();
        let payload = MovePayload {
            account_id: account_id.to_string(),
            mailbox: mailbox.to_string(),
        }
        .encode()?;
        let receipt = lane
            .append(NewBatch::single(Record::new(
                KIND_MOVE,
                id,
                payload,
            )))
            .await?;
        self.inner
            .index
            .write()
            .move_message(id, account_id, mailbox);
        Ok(receipt)
    }

    pub async fn flush(&self) -> Result<(), StoreError> {
        for lane in &self.inner.lanes {
            lane.checkpoint().await?;
        }
        self.persist_superblock()
    }

    fn location(&self, id: &str) -> Result<Location, StoreError> {
        self.inner
            .catalog
            .read()
            .get(id)
            .copied()
            .ok_or_else(|| StoreError::NotFound(id.to_string()))
    }

    fn apply_committed_records(
        &self,
        lane_id: u16,
        batch_offset: u64,
        batch_len: u64,
        records: &[Record],
    ) -> Result<(), StoreError> {
        let mut index = self.inner.index.write();
        let mut catalog = self.inner.catalog.write();
        for (record_index, record) in records.iter().enumerate() {
            match record.kind {
                KIND_MESSAGE => {
                    let message = Message::decode(&record.payload)?;
                    index.insert(&message);
                    catalog.insert(
                        record.key.clone(),
                        Location {
                            lane_id,
                            batch_offset,
                            batch_len,
                            record_index,
                        },
                    );
                }
                KIND_DELETE => {
                    index.delete(&record.key);
                    catalog.remove(&record.key);
                }
                KIND_FLAGS => {
                    if let Some(flags) = decode_flags(&record.payload) {
                        index.update_flags(&record.key, flags);
                    }
                }
                KIND_MOVE => {
                    let payload = MovePayload::decode(&record.payload)?;
                    index.move_message(&record.key, &payload.account_id, &payload.mailbox);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn persist_superblock(&self) -> Result<(), StoreError> {
        let generation = self
            .inner
            .generation
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        let mut superblock = self.inner.superblock.clone();
        superblock.generation = generation;
        let bytes = superblock.encode();
        let mut ring = io_uring::IoUring::new(8).map_err(StoreError::Io)?;
        write_all_at(
            &mut ring,
            self.inner.file.as_raw_fd(),
            &bytes,
            SUPERBLOCK_A_OFFSET,
            true,
        )?;
        write_all_at(
            &mut ring,
            self.inner.file.as_raw_fd(),
            &bytes,
            SUPERBLOCK_B_OFFSET,
            true,
        )?;
        Ok(())
    }
}

fn initialize_file(file: &File, options: &StoreOptions) -> Result<(), StoreError> {
    let data_lanes = options.data_lanes;
    let lane_count = data_lanes
        .checked_add(FIRST_DATA_LANE)
        .ok_or_else(|| StoreError::Config("lane count overflow".into()))?;
    let superblock = Superblock {
        version: FORMAT_VERSION,
        page_size: SUPERBLOCK_SIZE as u32,
        uuid: *Uuid::new_v4().as_bytes(),
        generation: 1,
        lane_capacity: options.lane_capacity,
        lane_count,
        data_lanes,
        created_at: crate::batch::now_millis(),
        checkpoint_seq: 0,
    };
    superblock.validate()?;
    file.set_len(file_size(&superblock)?)?;
    let mut ring = io_uring::IoUring::new(8).map_err(StoreError::Io)?;
    for lane_id in 0..lane_count {
        let base = lane_base(&superblock, lane_id)?;
        let header = LaneHeader {
            lane_id,
            capacity: superblock.lane_capacity,
            head: base + LANE_HEADER_SIZE,
            seq: 1,
            checkpoint_seq: 0,
            checkpoint_head: base + LANE_HEADER_SIZE,
        };
        write_all_at(
            &mut ring,
            file.as_raw_fd(),
            &header.encode(),
            base,
            true,
        )?;
    }
    let bytes = superblock.encode();
    write_all_at(
        &mut ring,
        file.as_raw_fd(),
        &bytes,
        SUPERBLOCK_A_OFFSET,
        true,
    )?;
    write_all_at(
        &mut ring,
        file.as_raw_fd(),
        &bytes,
        SUPERBLOCK_B_OFFSET,
        true,
    )?;
    Ok(())
}

fn read_superblock(file: &File) -> Result<Superblock, StoreError> {
    let mut a = [0u8; SUPERBLOCK_SIZE];
    let mut b = [0u8; SUPERBLOCK_SIZE];
    file.read_exact_at(&mut a, SUPERBLOCK_A_OFFSET)?;
    file.read_exact_at(&mut b, SUPERBLOCK_B_OFFSET)?;
    let decoded_a = Superblock::decode(&a);
    let decoded_b = Superblock::decode(&b);
    match (decoded_a, decoded_b) {
        (Ok(a), Ok(b)) => Ok(if a.generation >= b.generation { a } else { b }),
        (Ok(a), Err(_)) => Ok(a),
        (Err(_), Ok(b)) => Ok(b),
        (Err(a), Err(b)) => Err(StoreError::corrupt(format!(
            "both superblocks are invalid: {a}; {b}"
        ))),
    }
}

fn read_lane_header(
    file: &File,
    superblock: &Superblock,
    lane_id: u16,
    base: u64,
    data_start: u64,
) -> Result<LaneHeader, StoreError> {
    let mut bytes = [0u8; LANE_HEADER_SIZE as usize];
    file.read_exact_at(&mut bytes, base)?;
    let header = LaneHeader::decode(&bytes).unwrap_or(LaneHeader {
        lane_id,
        capacity: superblock.lane_capacity,
        head: data_start,
        seq: 1,
        checkpoint_seq: 0,
        checkpoint_head: data_start,
    });
    if header.lane_id != lane_id {
        return Err(StoreError::corrupt(format!(
            "lane header id mismatch: {} != {lane_id}",
            header.lane_id
        )));
    }
    if header.capacity != superblock.lane_capacity {
        return Err(StoreError::corrupt("lane capacity mismatch"));
    }
    Ok(header)
}

fn apply_batch_to_maps(
    lane_id: u16,
    batch: &DecodedBatch,
    offset: u64,
    index: &mut SearchIndex,
    catalog: &mut HashMap<String, Location>,
) -> Result<(), StoreError> {
    for (record_index, record) in batch.records.iter().enumerate() {
        match record.kind {
            KIND_MESSAGE => {
                let message = Message::decode(&record.payload)?;
                index.insert(&message);
                catalog.insert(
                    record.key.clone(),
                    Location {
                        lane_id,
                        batch_offset: offset,
                        batch_len: batch.total_len,
                        record_index,
                    },
                );
            }
            KIND_DELETE => {
                index.delete(&record.key);
                catalog.remove(&record.key);
            }
            KIND_FLAGS => {
                if let Some(flags) = decode_flags(&record.payload) {
                    index.update_flags(&record.key, flags);
                }
            }
            KIND_MOVE => {
                let payload = MovePayload::decode(&record.payload)?;
                index.move_message(&record.key, &payload.account_id, &payload.mailbox);
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_batch(account_id: &str, batch: &NewBatch) -> Result<(), StoreError> {
    if batch.records.is_empty() {
        return Err(StoreError::invalid_batch("empty batch"));
    }
    for record in &batch.records {
        if record.kind == KIND_MESSAGE {
            let message = Message::decode(&record.payload)?;
            if message.account_id != account_id {
                return Err(StoreError::Config(
                    "message account does not match batch account".into(),
                ));
            }
            if message.id != record.key {
                return Err(StoreError::Config(
                    "message id does not match record key".into(),
                ));
            }
        }
        if record.kind == KIND_MOVE {
            let _ = MovePayload::decode(&record.payload)?;
        }
    }
    Ok(())
}

fn decode_flags(payload: &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = payload.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn lock_file(file: &File) -> Result<(), StoreError> {
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(StoreError::Locked);
        }
        return Err(StoreError::Io(error));
    }
    Ok(())
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use tide_core::{Address, Message, flags};

    fn options() -> StoreOptions {
        StoreOptions::default()
            .with_data_lanes(4)
            .with_lane_capacity(4 * 1024 * 1024)
            .with_durability(Durability::DataSync)
    }

    fn message(id: &str, account: &str, subject: &str, body: &str) -> Message {
        Message {
            id: id.into(),
            account_id: account.into(),
            mailbox: "INBOX".into(),
            message_id: format!("<{id}@example.com>"),
            subject: subject.into(),
            body_text: body.into(),
            from: vec![Address {
                email: "sender@example.com".into(),
                name: Some("Sender".into()),
            }],
            to: vec![Address {
                email: "user@example.com".into(),
                name: None,
            }],
            date: 1_700_000_000_000,
            size: body.len() as u64,
            ..Message::default()
        }
    }

    #[test]
    fn stores_and_reopens() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mail.tide");
        let db = Db::open(&path, options()).unwrap();
        db.append_message_blocking(message("1", "alice", "Hello", "world"))
            .unwrap();
        db.append_message_blocking(message("2", "alice", "Second", "body"))
            .unwrap();
        futures::executor::block_on(db.flush()).unwrap();
        drop(db);

        let db = Db::open(&path, options()).unwrap();
        let first = db.get_message("1").unwrap().unwrap();
        assert_eq!(first.subject, "Hello");
        assert_eq!(db.index_size(), 2);
        assert_eq!(
            db.search(&SearchQuery::new().account("alice").text("hello"))
                .len(),
            1
        );
    }

    #[test]
    fn concurrent_writers_to_different_accounts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mail.tide");
        let db = Db::open(&path, options().with_lane_capacity(16 * 1024 * 1024)).unwrap();
        let mut handles = Vec::new();
        for thread in 0..8u64 {
            let db = db.clone();
            handles.push(std::thread::spawn(move || {
                for index in 0..50u64 {
                    let id = format!("{thread}-{index}");
                    let account = format!("account-{thread}");
                    db.append_message_blocking(message(
                        &id,
                        &account,
                        &format!("subject {index}"),
                        &format!("body {thread} {index}"),
                    ))
                    .unwrap();
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(db.index_size(), 400);
        assert_eq!(
            db.search(&SearchQuery::new().account("account-3").text("body"))
                .len(),
            50
        );
        drop(db);
        let db = Db::open(&path, options()).unwrap();
        assert_eq!(db.index_size(), 400);
    }

    #[test]
    fn delete_and_flags_roundtrip() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mail.tide");
        let db = Db::open(&path, options()).unwrap();
        db.append_message_blocking(message("1", "alice", "Hello", "world"))
            .unwrap();
        futures::executor::block_on(db.update_flags("1", flags::SEEN))
            .unwrap();
        assert!(db.get_message("1").unwrap().unwrap().is_read());
        futures::executor::block_on(db.delete_message("1")).unwrap();
        assert!(db.get_message("1").unwrap().is_none());
        drop(db);

        let db = Db::open(&path, options()).unwrap();
        assert!(db.get_message("1").unwrap().is_none());
        assert_eq!(db.index_size(), 0);
    }

    #[test]
    fn only_one_process_can_open() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mail.tide");
        let first = Db::open(&path, options()).unwrap();
        let second = Db::open(&path, options());
        assert!(matches!(second, Err(StoreError::Locked)));
        drop(first);
        let third = Db::open(&path, options());
        assert!(third.is_ok());
    }

    #[test]
    fn survives_torn_tail() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mail.tide");
        let db = Db::open(&path, options()).unwrap();
        db.append_message_blocking(message("1", "alice", "Hello", "world"))
            .unwrap();
        let second = db
            .append_message_blocking(message("2", "alice", "Second", "body"))
            .unwrap();
        drop(db);

        let bytes = std::fs::read(&path).unwrap();
        let mut corrupt = bytes;
        let start = second.offset as usize;
        let end = (second.offset + second.total_len) as usize;
        assert!(end <= corrupt.len());
        corrupt[start + 80..start + 120].fill(0);
        std::fs::write(&path, &corrupt).unwrap();

        let db = Db::open(&path, options()).unwrap();
        assert!(db.get_message("1").unwrap().is_some());
        assert!(db.get_message("2").unwrap().is_none());
    }
}
