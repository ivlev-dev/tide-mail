use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use memmap2::{Mmap, MmapOptions};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use silent_protocol::SilentProto;
use std::collections::BTreeMap;
use tide_core::Message;
use uuid::Uuid;

use crate::batch::{
    DecodedBatch, KIND_DELETE, KIND_FLAGS, KIND_MESSAGE, KIND_META, KIND_MOVE, NewBatch, Record,
    decode_batch,
};
use crate::change::{ChangeEntry, ChangesPage, SyncCursor, kind as change_kind};
use crate::error::StoreError;
use crate::format::{
    DEFAULT_DATA_LANES, DEFAULT_LANE_CAPACITY, FIRST_DATA_LANE, FORMAT_VERSION, INDEX_LANE,
    LANE_HEADER_SIZE, LaneHeader, MAX_LANE_CAPACITY, MIN_LANE_CAPACITY, SUPERBLOCK_A_OFFSET,
    SUPERBLOCK_B_OFFSET, SUPERBLOCK_SIZE, Superblock, file_size, lane_base, lane_data_start,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct Location {
    lane_id: u16,
    batch_offset: u64,
    batch_len: u64,
    record_index: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MailboxStats {
    pub total: u64,
    pub unread: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountStats {
    pub total: u64,
    pub unread: u64,
    pub mailboxes: HashMap<String, MailboxStats>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreStats {
    pub path: PathBuf,
    pub generation: u64,
    pub data_lanes: u16,
    pub lane_capacity: u64,
    pub messages: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct LanePosition {
    lane: u16,
    head: u64,
    seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Snapshot {
    version: u32,
    index: SearchIndex,
    catalog: HashMap<String, Location>,
    changes: HashMap<String, Vec<ChangeEntry>>,
    lanes: Vec<LanePosition>,
}

const SNAPSHOT_VERSION: u32 = 1;
const SNAPSHOT_CHUNK_SIZE: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, SilentProto)]
struct LanePositionWire {
    head: u64,
    lane: u32,
    seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, SilentProto)]
struct SnapshotManifest {
    chunks: u32,
    #[proto(date)]
    created_at: i64,
    id: u64,
    lanes: Vec<LanePositionWire>,
}

impl Snapshot {
    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let bytes = bincode::serialize(self)
            .map_err(|error| StoreError::Internal(format!("snapshot encode: {error}")))?;
        zstd::bulk::compress(&bytes, 3)
            .map_err(|error| StoreError::Internal(format!("snapshot compress: {error}")))
    }

    fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        let decompressed = zstd::bulk::decompress(bytes, 1024 * 1024 * 1024)
            .map_err(|error| StoreError::Internal(format!("snapshot decompress: {error}")))?;
        let snapshot: Self = bincode::deserialize(&decompressed)
            .map_err(|error| StoreError::Internal(format!("snapshot decode: {error}")))?;
        if snapshot.version != SNAPSHOT_VERSION {
            return Err(StoreError::corrupt(format!(
                "unsupported snapshot version {}",
                snapshot.version
            )));
        }
        Ok(snapshot)
    }
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
    changes: RwLock<HashMap<String, Vec<ChangeEntry>>>,
    lane_locks: Vec<Arc<futures::lock::Mutex<()>>>,
    options: StoreOptions,
}

#[derive(Clone)]
pub struct Db {
    inner: Arc<arc_swap::ArcSwap<DbInner>>,
    gate: Arc<async_lock::RwLock<()>>,
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

        let mut headers = Vec::with_capacity(superblock.lane_count as usize);
        for lane_id in 0..superblock.lane_count {
            let base = lane_base(&superblock, lane_id)?;
            let data_start = lane_data_start(&superblock, lane_id)?;
            headers.push(read_lane_header(
                &file,
                &superblock,
                lane_id,
                base,
                data_start,
            )?);
        }

        let index_base = lane_base(&superblock, INDEX_LANE)?;
        let index_start = lane_data_start(&superblock, INDEX_LANE)?;
        let (_, _, index_batches) =
            replay_lane(&mmap, index_base, superblock.lane_capacity, index_start, 1)?;
        let snapshot = load_snapshot(&index_batches)?;
        let snapshot_positions: HashMap<u16, LanePosition> = snapshot
            .as_ref()
            .map(|snapshot| {
                snapshot
                    .lanes
                    .iter()
                    .map(|position| (position.lane, *position))
                    .collect()
            })
            .unwrap_or_default();

        let mut index = snapshot
            .as_ref()
            .map(|snapshot| snapshot.index.clone())
            .unwrap_or_default();
        let mut catalog = snapshot
            .as_ref()
            .map(|snapshot| snapshot.catalog.clone())
            .unwrap_or_default();
        let mut changes = snapshot
            .as_ref()
            .map(|snapshot| snapshot.changes.clone())
            .unwrap_or_default();
        let mut lanes = Vec::with_capacity(superblock.lane_count as usize);
        let mut init_ring = io_uring::IoUring::new(8).map_err(StoreError::Io)?;

        for lane_id in 0..superblock.lane_count {
            let base = lane_base(&superblock, lane_id)?;
            let data_start = lane_data_start(&superblock, lane_id)?;
            let header = &headers[lane_id as usize];
            let position = snapshot_positions.get(&lane_id).copied();
            let start = if lane_id == INDEX_LANE {
                data_start
            } else if lane_id >= FIRST_DATA_LANE {
                match position {
                    Some(position) => {
                        if header.checkpoint_head >= data_start {
                            header.checkpoint_head.min(position.head).max(data_start)
                        } else {
                            position.head.max(data_start)
                        }
                    }
                    None => data_start,
                }
            } else {
                data_start
            };
            let start_seq = header
                .seq
                .max(
                    position
                        .map(|position| position.seq.saturating_add(1))
                        .unwrap_or(1),
                )
                .max(1);
            let (head, seq, batches) =
                replay_lane(&mmap, base, superblock.lane_capacity, start, start_seq)?;
            if lane_id >= FIRST_DATA_LANE {
                let mut offset = start;
                for batch in &batches {
                    let already_present = position
                        .map(|position| batch.seq <= position.seq)
                        .unwrap_or(false);
                    if !already_present {
                        apply_batch_to_maps(
                            lane_id,
                            batch,
                            offset,
                            &mut index,
                            &mut catalog,
                            &mut changes,
                        )?;
                    }
                    offset += batch.total_len;
                }
            }
            let (checkpoint_head, checkpoint_seq) = position
                .filter(|_| lane_id >= FIRST_DATA_LANE)
                .map(|position| (position.head, position.seq))
                .unwrap_or((header.checkpoint_head, header.checkpoint_seq));
            let recovered = LaneHeader {
                lane_id,
                capacity: superblock.lane_capacity,
                head,
                seq,
                checkpoint_seq,
                checkpoint_head,
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
                checkpoint_head,
                checkpoint_seq,
                options.durability,
            )?;
            lanes.push(writer);
        }

        let generation = superblock.generation;
        let lane_locks = (0..superblock.lane_count)
            .map(|_| Arc::new(futures::lock::Mutex::new(())))
            .collect();
        let inner = DbInner {
            path,
            mmap,
            file,
            superblock,
            generation: AtomicU64::new(generation),
            lanes,
            index: RwLock::new(index),
            catalog: RwLock::new(catalog),
            changes: RwLock::new(changes),
            lane_locks,
            options,
        };
        Ok(Self {
            inner: Arc::new(arc_swap::ArcSwap::from_pointee(inner)),
            gate: Arc::new(async_lock::RwLock::new(())),
        })
    }

    fn state(&self) -> Arc<DbInner> {
        self.inner.load_full()
    }

    pub fn path(&self) -> PathBuf {
        self.state().path.clone()
    }

    pub fn stats(&self) -> StoreStats {
        StoreStats {
            path: self.state().path.clone(),
            generation: self.state().generation.load(Ordering::Relaxed),
            data_lanes: self.state().superblock.data_lanes,
            lane_capacity: self.state().superblock.lane_capacity,
            messages: self.state().index.read().len(),
        }
    }

    pub fn lane_for_account(&self, account_id: &str) -> LaneWriter {
        let data_lanes = self.state().superblock.data_lanes;
        let slot = (fnv1a(account_id.as_bytes()) % u64::from(data_lanes)) as u16;
        let lane_id = FIRST_DATA_LANE + slot;
        self.state().lanes[lane_id as usize].clone()
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
        let _gate = self.gate.read().await;
        if account_id.is_empty() {
            return Err(StoreError::Config("empty account id".into()));
        }
        validate_batch(account_id, &batch)?;
        let records = batch.records.clone();
        let lane = self.lane_for_account(account_id);
        let lock = self.state().lane_locks[lane.lane_id() as usize].clone();
        let _guard = lock.lock().await;
        let receipt = lane.append(batch).await?;
        self.apply_committed_records(
            receipt.lane_id,
            receipt.offset,
            receipt.total_len,
            receipt.seq,
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
        let location = match self.state().catalog.read().get(id).copied() {
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
        if end > self.state().mmap.len() {
            return Err(StoreError::corrupt("batch outside mmap"));
        }
        let decoded = decode_batch(&self.state().mmap[start..end])?;
        let record = decoded
            .records
            .get(location.record_index)
            .ok_or_else(|| StoreError::corrupt("record index out of bounds"))?;
        let mut message = Message::decode(&record.payload)?;
        if let Some(doc) = self.state().index.read().get(id) {
            message.flags = doc.flags;
            message.account_id = doc.account_id.clone();
            message.mailbox = doc.mailbox.clone();
        }
        Ok(Some(message))
    }

    pub fn search(&self, query: &SearchQuery) -> Vec<SearchHit> {
        self.state().index.read().search(query)
    }

    pub fn index_size(&self) -> usize {
        self.state().index.read().len()
    }

    pub fn account_stats(&self, account_id: &str) -> AccountStats {
        let inner = self.state();
        let index = inner.index.read();
        let mut stats = AccountStats::default();
        for doc in index.iter().filter(|doc| doc.account_id == account_id) {
            stats.total += 1;
            if doc.flags & tide_core::flags::SEEN == 0 {
                stats.unread += 1;
            }
            let mailbox = stats.mailboxes.entry(doc.mailbox.clone()).or_default();
            mailbox.total += 1;
            if doc.flags & tide_core::flags::SEEN == 0 {
                mailbox.unread += 1;
            }
        }
        stats
    }

    pub fn sync_cursor(&self, account_id: &str) -> SyncCursor {
        let lane = self.lane_for_account(account_id).lane_id();
        let inner = self.state();
        let seq = inner
            .changes
            .read()
            .get(account_id)
            .and_then(|entries| entries.last())
            .map_or(0, |entry| entry.seq);
        SyncCursor { lane, seq }
    }

    pub fn sync_changes(&self, account_id: &str, since_seq: u64, limit: u32) -> ChangesPage {
        let inner = self.state();
        let changes = inner.changes.read();
        let entries = match changes.get(account_id) {
            Some(entries) => entries,
            None => {
                return ChangesPage {
                    entries: Vec::new(),
                    next_seq: since_seq,
                    has_more: false,
                };
            }
        };
        let limit = limit.max(1) as usize;
        let mut selected = Vec::new();
        let mut next_seq = since_seq;
        let mut has_more = false;
        for entry in entries.iter().filter(|entry| entry.seq > since_seq) {
            if selected.len() >= limit {
                has_more = true;
                break;
            }
            next_seq = entry.seq;
            selected.push(entry.clone());
        }
        ChangesPage {
            entries: selected,
            next_seq,
            has_more,
        }
    }

    pub fn all_changes(&self, account_id: &str) -> Vec<ChangeEntry> {
        let inner = self.state();
        inner
            .changes
            .read()
            .get(account_id)
            .cloned()
            .unwrap_or_default()
    }

    pub async fn delete_message(&self, id: &str) -> Result<Receipt, StoreError> {
        let _gate = self.gate.read().await;
        let location = self.location(id)?;
        let inner = self.state();
        let lane = inner
            .lanes
            .get(location.lane_id as usize)
            .ok_or_else(|| StoreError::corrupt("lane out of bounds"))?
            .clone();
        let lock = self.state().lane_locks[lane.lane_id() as usize].clone();
        let _guard = lock.lock().await;
        let receipt = lane.append(NewBatch::single(Record::delete(id))).await?;
        self.state().index.write().delete(id);
        self.state().catalog.write().remove(id);
        Ok(receipt)
    }

    pub async fn update_flags(&self, id: &str, flags: u64) -> Result<Receipt, StoreError> {
        let _gate = self.gate.read().await;
        let location = self.location(id)?;
        let inner = self.state();
        let lane = inner
            .lanes
            .get(location.lane_id as usize)
            .ok_or_else(|| StoreError::corrupt("lane out of bounds"))?
            .clone();
        let lock = self.state().lane_locks[lane.lane_id() as usize].clone();
        let _guard = lock.lock().await;
        let receipt = lane
            .append(NewBatch::single(Record::flags(id, flags)))
            .await?;
        self.state().index.write().update_flags(id, flags);
        Ok(receipt)
    }

    pub async fn move_message(
        &self,
        id: &str,
        account_id: &str,
        mailbox: &str,
    ) -> Result<Receipt, StoreError> {
        let _gate = self.gate.read().await;
        let location = self.location(id)?;
        let inner = self.state();
        let lane = inner
            .lanes
            .get(location.lane_id as usize)
            .ok_or_else(|| StoreError::corrupt("lane out of bounds"))?
            .clone();
        let lock = self.state().lane_locks[lane.lane_id() as usize].clone();
        let _guard = lock.lock().await;
        let payload = MovePayload {
            account_id: account_id.to_string(),
            mailbox: mailbox.to_string(),
        }
        .encode()?;
        let receipt = lane
            .append(NewBatch::single(Record::new(KIND_MOVE, id, payload)))
            .await?;
        inner.index.write().move_message(id, account_id, mailbox);
        Ok(receipt)
    }

    pub async fn flush(&self) -> Result<(), StoreError> {
        self.snapshot().await
    }

    pub async fn snapshot(&self) -> Result<(), StoreError> {
        let _guard = self.gate.write().await;
        let mut positions = Vec::new();
        for lane_id in FIRST_DATA_LANE..self.state().superblock.lane_count {
            let lane = &self.state().lanes[lane_id as usize];
            let info = lane.info().await?;
            positions.push(LanePosition {
                lane: lane_id,
                head: info.head,
                seq: info.seq.saturating_sub(1),
            });
        }
        let snapshot = Snapshot {
            version: SNAPSHOT_VERSION,
            index: self.state().index.read().clone(),
            catalog: self.state().catalog.read().clone(),
            changes: self.state().changes.read().clone(),
            lanes: positions.clone(),
        };
        let bytes = snapshot.encode()?;
        let id = next_snapshot_id();
        let index_lane = self.state().lanes[INDEX_LANE as usize].clone();
        let chunk_count = bytes.len().div_ceil(SNAPSHOT_CHUNK_SIZE).max(1) as u32;
        for (index, chunk) in bytes.chunks(SNAPSHOT_CHUNK_SIZE).enumerate() {
            index_lane
                .append(NewBatch::single(Record::new(
                    KIND_META,
                    format!("snap:{id}:{index}"),
                    chunk.to_vec(),
                )))
                .await?;
        }
        let manifest = SnapshotManifest {
            chunks: chunk_count,
            created_at: crate::batch::now_millis(),
            id,
            lanes: positions
                .iter()
                .map(|position| LanePositionWire {
                    head: position.head,
                    lane: u32::from(position.lane),
                    seq: position.seq,
                })
                .collect(),
        };
        index_lane
            .append(NewBatch::single(Record::new(
                KIND_META,
                format!("snap:{id}"),
                manifest.encode()?,
            )))
            .await?;
        for position in &positions {
            self.state().lanes[position.lane as usize]
                .set_checkpoint(position.head, position.seq)
                .await?;
        }
        self.persist_superblock()
    }

    pub async fn compact(&self) -> Result<StoreStats, StoreError> {
        let _gate = self.gate.write().await;
        let old = self.state();
        let path = old.path.clone();
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| StoreError::Config("invalid database path".into()))?;
        let temp = path.with_file_name(format!("{file_name}.compact"));
        if temp.exists() {
            std::fs::remove_file(&temp)?;
        }
        let new_db = Db::open(&temp, old.options.clone())?;
        let ids = old
            .index
            .read()
            .iter()
            .map(|doc| doc.id.clone())
            .collect::<Vec<_>>();
        for id in ids {
            if let Some(message) = self.get_message(&id)? {
                new_db.append_message(message).await?;
            }
        }
        new_db.flush().await?;
        drop(new_db);
        std::fs::rename(&temp, &path)?;
        let reopened = Db::open(&path, old.options.clone())?;
        let new_inner = reopened.state();
        self.inner.store(new_inner);
        drop(old);
        Ok(self.stats())
    }

    fn location(&self, id: &str) -> Result<Location, StoreError> {
        let inner = self.state();
        inner
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
        seq: u64,
        records: &[Record],
    ) -> Result<(), StoreError> {
        let inner = self.state();
        let mut index = inner.index.write();
        let mut catalog = inner.catalog.write();
        let mut changes = inner.changes.write();
        for (record_index, record) in records.iter().enumerate() {
            match record.kind {
                KIND_MESSAGE => {
                    let message = Message::decode(&record.payload)?;
                    push_change(&mut changes, ChangeEntry::from_message(seq, &message));
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
                    if let Some(doc) = index.get(&record.key) {
                        push_change(
                            &mut changes,
                            ChangeEntry::from_doc(seq, change_kind::DELETE, doc),
                        );
                    }
                    index.delete(&record.key);
                    catalog.remove(&record.key);
                }
                KIND_FLAGS => {
                    if let Some(flags) = decode_flags(&record.payload) {
                        index.update_flags(&record.key, flags);
                        if let Some(doc) = index.get(&record.key) {
                            let mut entry = ChangeEntry::from_doc(seq, change_kind::FLAGS, doc);
                            entry.flags = flags;
                            push_change(&mut changes, entry);
                        }
                    }
                }
                KIND_MOVE => {
                    let payload = MovePayload::decode(&record.payload)?;
                    index.move_message(&record.key, &payload.account_id, &payload.mailbox);
                    if let Some(doc) = index.get(&record.key) {
                        let mut entry = ChangeEntry::from_doc(seq, change_kind::MOVE, doc);
                        entry.mailbox = payload.mailbox.clone();
                        push_change(&mut changes, entry);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn persist_superblock(&self) -> Result<(), StoreError> {
        let inner = self.state();
        let generation = inner
            .generation
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        let mut superblock = inner.superblock.clone();
        superblock.generation = generation;
        let bytes = superblock.encode();
        let mut ring = io_uring::IoUring::new(8).map_err(StoreError::Io)?;
        write_all_at(
            &mut ring,
            inner.file.as_raw_fd(),
            &bytes,
            SUPERBLOCK_A_OFFSET,
            true,
        )?;
        write_all_at(
            &mut ring,
            inner.file.as_raw_fd(),
            &bytes,
            SUPERBLOCK_B_OFFSET,
            true,
        )?;
        Ok(())
    }
}

fn load_snapshot(batches: &[DecodedBatch]) -> Result<Option<Snapshot>, StoreError> {
    let mut manifests: BTreeMap<u64, SnapshotManifest> = BTreeMap::new();
    let mut chunks: BTreeMap<u64, BTreeMap<u32, Vec<u8>>> = BTreeMap::new();
    for batch in batches {
        for record in &batch.records {
            if record.kind != KIND_META {
                continue;
            }
            let Some(rest) = record.key.strip_prefix("snap:") else {
                continue;
            };
            let mut parts = rest.split(':');
            let Some(id) = parts.next().and_then(|value| value.parse::<u64>().ok()) else {
                continue;
            };
            match parts.next() {
                None => {
                    if let Ok(manifest) = SnapshotManifest::decode(&record.payload) {
                        manifests.insert(id, manifest);
                    }
                }
                Some(index) => {
                    if let Ok(index) = index.parse::<u32>() {
                        chunks
                            .entry(id)
                            .or_default()
                            .insert(index, record.payload.clone());
                    }
                }
            }
        }
    }
    for (id, manifest) in manifests.iter().rev() {
        let Some(chunk_map) = chunks.get(id) else {
            continue;
        };
        if chunk_map.len() != manifest.chunks as usize {
            continue;
        }
        let mut payload = Vec::new();
        for index in 0..manifest.chunks {
            let Some(chunk) = chunk_map.get(&index) else {
                payload.clear();
                break;
            };
            payload.extend_from_slice(chunk);
        }
        if payload.is_empty() {
            continue;
        }
        match Snapshot::decode(&payload) {
            Ok(snapshot) => return Ok(Some(snapshot)),
            Err(error) => {
                eprintln!("snapshot {id} is invalid: {error}");
            }
        }
    }
    Ok(None)
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
        write_all_at(&mut ring, file.as_raw_fd(), &header.encode(), base, true)?;
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
    changes: &mut HashMap<String, Vec<ChangeEntry>>,
) -> Result<(), StoreError> {
    let seq = batch.seq;
    for (record_index, record) in batch.records.iter().enumerate() {
        match record.kind {
            KIND_MESSAGE => {
                let message = Message::decode(&record.payload)?;
                push_change(changes, ChangeEntry::from_message(seq, &message));
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
                if let Some(doc) = index.get(&record.key) {
                    push_change(
                        changes,
                        ChangeEntry::from_doc(seq, change_kind::DELETE, doc),
                    );
                }
                index.delete(&record.key);
                catalog.remove(&record.key);
            }
            KIND_FLAGS => {
                if let Some(flags) = decode_flags(&record.payload) {
                    index.update_flags(&record.key, flags);
                    if let Some(doc) = index.get(&record.key) {
                        let mut entry = ChangeEntry::from_doc(seq, change_kind::FLAGS, doc);
                        entry.flags = flags;
                        push_change(changes, entry);
                    }
                }
            }
            KIND_MOVE => {
                let payload = MovePayload::decode(&record.payload)?;
                index.move_message(&record.key, &payload.account_id, &payload.mailbox);
                if let Some(doc) = index.get(&record.key) {
                    let mut entry = ChangeEntry::from_doc(seq, change_kind::MOVE, doc);
                    entry.mailbox = payload.mailbox.clone();
                    push_change(changes, entry);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn push_change(changes: &mut HashMap<String, Vec<ChangeEntry>>, entry: ChangeEntry) {
    changes
        .entry(entry.account_id.clone())
        .or_default()
        .push(entry);
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

fn next_snapshot_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let millis = crate::batch::now_millis().max(0) as u64;
    (millis << 16) | (COUNTER.fetch_add(1, Ordering::Relaxed) & 0xFFFF)
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
        futures::executor::block_on(db.update_flags("1", flags::SEEN)).unwrap();
        assert!(db.get_message("1").unwrap().unwrap().is_read());
        futures::executor::block_on(db.delete_message("1")).unwrap();
        assert!(db.get_message("1").unwrap().is_none());
        drop(db);

        let db = Db::open(&path, options()).unwrap();
        assert!(db.get_message("1").unwrap().is_none());
        assert_eq!(db.index_size(), 0);
    }

    #[test]
    fn sync_changes_are_incremental() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mail.tide");
        let db = Db::open(&path, options()).unwrap();
        db.append_message_blocking(message("1", "alice", "Hello", "world"))
            .unwrap();
        let cursor = db.sync_cursor("alice");
        assert_eq!(cursor.seq, 1);
        let page = db.sync_changes("alice", 0, 10);
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].subject, "Hello");
        assert_eq!(page.next_seq, 1);
        db.append_message_blocking(message("2", "alice", "Second", "body"))
            .unwrap();
        let page = db.sync_changes("alice", page.next_seq, 10);
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].message_id, "2");
        drop(db);
        let db = Db::open(&path, options()).unwrap();
        let page = db.sync_changes("alice", 0, 10);
        assert_eq!(page.entries.len(), 2);
        assert_eq!(db.sync_cursor("alice").seq, 2);
    }

    #[test]
    fn snapshot_replays_only_new_batches() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mail.tide");
        let db = Db::open(&path, options()).unwrap();
        db.append_message_blocking(message("1", "alice", "Snapshot", "old body"))
            .unwrap();
        futures::executor::block_on(db.flush()).unwrap();
        db.append_message_blocking(message("2", "alice", "After snapshot", "new body"))
            .unwrap();
        drop(db);

        let db = Db::open(&path, options()).unwrap();
        assert_eq!(db.index_size(), 2);
        assert_eq!(db.get_message("1").unwrap().unwrap().subject, "Snapshot");
        assert_eq!(
            db.get_message("2").unwrap().unwrap().subject,
            "After snapshot"
        );
        assert_eq!(
            db.search(&SearchQuery::new().account("alice").text("snapshot"))
                .len(),
            2
        );
    }

    #[test]
    fn compaction_preserves_messages_and_allows_new_writes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mail.tide");
        let db = Db::open(&path, options()).unwrap();
        for index in 0..20 {
            db.append_message_blocking(message(
                &format!("m{index}"),
                "alice",
                &format!("Subject {index}"),
                "body for compaction",
            ))
            .unwrap();
        }
        futures::executor::block_on(db.delete_message("m0")).unwrap();
        futures::executor::block_on(db.update_flags("m1", tide_core::flags::SEEN)).unwrap();
        futures::executor::block_on(db.flush()).unwrap();
        let stats = futures::executor::block_on(db.compact()).unwrap();
        assert_eq!(stats.messages, 19);
        assert!(db.get_message("m0").unwrap().is_none());
        assert!(db.get_message("m1").unwrap().unwrap().is_read());
        db.append_message_blocking(message("m-new", "alice", "After compact", "body"))
            .unwrap();
        assert_eq!(db.index_size(), 20);
        drop(db);
        let db = Db::open(&path, options()).unwrap();
        assert_eq!(db.index_size(), 20);
        assert!(db.get_message("m-new").unwrap().is_some());
    }

    #[test]
    fn compaction_waits_for_concurrent_writes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mail.tide");
        let db = Db::open(&path, options()).unwrap();
        let writer = db.clone();
        let handle = std::thread::spawn(move || {
            for index in 0..100 {
                writer
                    .append_message_blocking(message(
                        &format!("c{index}"),
                        "alice",
                        &format!("Concurrent {index}"),
                        "body",
                    ))
                    .unwrap();
            }
        });
        futures::executor::block_on(db.compact()).unwrap();
        handle.join().unwrap();
        assert_eq!(db.index_size(), 100);
        drop(db);
        let db = Db::open(&path, options()).unwrap();
        assert_eq!(db.index_size(), 100);
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
