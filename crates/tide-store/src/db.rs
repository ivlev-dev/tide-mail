use crossbeam_channel::{Receiver, Sender, unbounded};
use std::collections::{BTreeMap, HashMap};
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
use tide_core::Message;
use uuid::Uuid;

use crate::batch::{
    DecodedBatch, KIND_DELETE, KIND_FLAGS, KIND_MESSAGE, KIND_META, KIND_MOVE, NewBatch, Record,
    decode_batch,
};
use crate::blob::{BlobStore, S3Config};
use crate::change::{ChangeEntry, ChangesPage, SyncCursor, kind as change_kind};
use crate::error::StoreError;
use crate::folder::{DEFAULT_FOLDERS, Folder, FolderRecord, validate_folder_name};
use crate::format::{
    DEFAULT_DATA_LANES, DEFAULT_LANE_CAPACITY, FIRST_DATA_LANE, FORMAT_VERSION, INDEX_LANE,
    LANE_HEADER_SIZE, LaneHeader, MAX_LANE_CAPACITY, MIN_LANE_CAPACITY, SUPERBLOCK_A_OFFSET,
    SUPERBLOCK_B_OFFSET, SUPERBLOCK_SIZE, Superblock, file_size, lane_base, lane_data_start,
};
use crate::index::{SearchHit, SearchQuery, ShardedIndex, ShardedIndexSnapshot};
use crate::lane::{Durability, LaneWriter, Receipt, replay_lane, spawn_lane, write_all_at};

const MAX_DATA_LANES: u16 = 128;

#[derive(Debug, Clone)]
pub struct StoreOptions {
    pub data_lanes: u16,
    pub lane_capacity: u64,
    pub durability: Durability,
    pub blob_dir: Option<PathBuf>,
    pub blob_s3: Option<S3Config>,
}

impl Default for StoreOptions {
    fn default() -> Self {
        Self {
            data_lanes: DEFAULT_DATA_LANES,
            lane_capacity: DEFAULT_LANE_CAPACITY,
            durability: Durability::DataSync,
            blob_dir: None,
            blob_s3: None,
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

    pub fn with_blob_dir(mut self, blob_dir: impl Into<PathBuf>) -> Self {
        self.blob_dir = Some(blob_dir.into());
        self
    }

    pub fn with_s3(mut self, config: S3Config) -> Self {
        self.blob_s3 = Some(config);
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
    index: ShardedIndexSnapshot,
    catalog: HashMap<String, Location>,
    changes: HashMap<String, Vec<ChangeEntry>>,
    folders: HashMap<String, BTreeMap<String, Folder>>,
    blob_refs: HashMap<String, String>,
    lanes: Vec<LanePosition>,
}

const SNAPSHOT_VERSION: u32 = 5;
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

#[derive(Clone)]
struct ApplyContext {
    index: Arc<ShardedIndex>,
    catalog: Arc<RwLock<HashMap<String, Location>>>,
    changes: Arc<RwLock<HashMap<String, Vec<ChangeEntry>>>>,
    folders: Arc<RwLock<HashMap<String, BTreeMap<String, Folder>>>>,
    blob_refs: Arc<RwLock<HashMap<String, String>>>,
}

struct ApplyJob {
    lane_id: u16,
    seq: u64,
    batch_offset: u64,
    batch_len: u64,
    records: Vec<Record>,
    decoded_messages: Vec<Option<Message>>,
    reply: futures_channel::oneshot::Sender<Result<(), StoreError>>,
}

enum ApplyCommand {
    Job(ApplyJob),
    Shutdown,
}

struct ApplyHandle {
    tx: Sender<ApplyCommand>,
    join: parking_lot::Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl ApplyHandle {
    async fn submit(
        &self,
        lane_id: u16,
        seq: u64,
        batch_offset: u64,
        batch_len: u64,
        records: Vec<Record>,
        decoded_messages: Vec<Option<Message>>,
    ) -> Result<(), StoreError> {
        let (reply, receiver) = futures_channel::oneshot::channel();
        self.tx
            .send(ApplyCommand::Job(ApplyJob {
                lane_id,
                seq,
                batch_offset,
                batch_len,
                records,
                decoded_messages,
                reply,
            }))
            .map_err(|_| StoreError::Internal("apply worker stopped".into()))?;
        receiver
            .await
            .map_err(|_| StoreError::Internal("apply worker stopped".into()))?
    }
}

impl Drop for ApplyHandle {
    fn drop(&mut self) {
        let _ = self.tx.send(ApplyCommand::Shutdown);
        if let Some(join) = self.join.lock().take() {
            let _ = join.join();
        }
    }
}

struct DbInner {
    path: PathBuf,
    mmap: Mmap,
    file: Arc<File>,
    superblock: Superblock,
    generation: AtomicU64,
    lanes: Vec<LaneWriter>,
    index: Arc<ShardedIndex>,
    catalog: Arc<RwLock<HashMap<String, Location>>>,
    changes: Arc<RwLock<HashMap<String, Vec<ChangeEntry>>>>,
    folders: Arc<RwLock<HashMap<String, BTreeMap<String, Folder>>>>,
    blob_refs: Arc<RwLock<HashMap<String, String>>>,
    blobs: Arc<BlobStore>,
    apply: ApplyHandle,
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

#[derive(Debug, Clone, PartialEq, Eq, SilentProto)]
struct BlobRefRecord {
    attachment_id: u32,
    blob_id: String,
    message_id: String,
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
        let blob_root = options
            .blob_dir
            .clone()
            .unwrap_or_else(|| path.with_file_name("blobs"));
        let blobs = Arc::new(if let Some(config) = options.blob_s3.clone() {
            BlobStore::s3(config)?
        } else {
            BlobStore::new(blob_root)?
        });
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

        let index = snapshot
            .as_ref()
            .map(|snapshot| ShardedIndex::from_snapshot(snapshot.index.clone()))
            .unwrap_or_else(|| ShardedIndex::new(16));
        let mut catalog = snapshot
            .as_ref()
            .map(|snapshot| snapshot.catalog.clone())
            .unwrap_or_default();
        let mut changes = snapshot
            .as_ref()
            .map(|snapshot| snapshot.changes.clone())
            .unwrap_or_default();
        let mut folders = snapshot
            .as_ref()
            .map(|snapshot| snapshot.folders.clone())
            .unwrap_or_default();
        let mut blob_refs = snapshot
            .as_ref()
            .map(|snapshot| snapshot.blob_refs.clone())
            .unwrap_or_default();
        let mut lanes = Vec::with_capacity(superblock.lane_count as usize);
        let mut lane_seqs = HashMap::new();
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
                            &index,
                            &mut catalog,
                            &mut changes,
                            &mut folders,
                            &mut blob_refs,
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
            if lane_id >= FIRST_DATA_LANE {
                lane_seqs.insert(lane_id, seq);
            }
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
        let index = Arc::new(index);
        let catalog = Arc::new(RwLock::new(catalog));
        let changes = Arc::new(RwLock::new(changes));
        let folders = Arc::new(RwLock::new(folders));
        let blob_refs = Arc::new(RwLock::new(blob_refs));
        let apply = spawn_apply_worker(
            ApplyContext {
                index: Arc::clone(&index),
                catalog: Arc::clone(&catalog),
                changes: Arc::clone(&changes),
                folders: Arc::clone(&folders),
                blob_refs: Arc::clone(&blob_refs),
            },
            lane_seqs,
        );
        let inner = DbInner {
            path,
            mmap,
            file,
            superblock,
            generation: AtomicU64::new(generation),
            lanes,
            index,
            catalog,
            changes,
            folders,
            blob_refs,
            blobs,
            apply,
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
            messages: self.state().index.len(),
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
        let account_id = message.account_id.clone();
        let payload = message.encode()?;
        let batch = NewBatch::single(Record::message(message.id.clone(), payload));
        self.append_prepared(&account_id, batch, vec![Some(message)])
            .await
    }

    pub fn append_message_blocking(&self, message: Message) -> Result<Receipt, StoreError> {
        futures::executor::block_on(self.append_message(message))
    }

    pub async fn append_message_with_blobs(
        &self,
        mut message: Message,
    ) -> Result<Receipt, StoreError> {
        message.validate()?;
        let account_id = message.account_id.clone();
        let message_id = message.id.clone();
        let mut records = Vec::new();
        let mut decoded = Vec::new();
        let mut references = Vec::new();
        for (index, attachment) in message.attachments.iter_mut().enumerate() {
            if !attachment.data.is_empty() {
                let blob_id = self.state().blobs.put(&attachment.data)?;
                attachment.data.clear();
                references.push((index, blob_id));
            }
        }
        records.push(Record::message(message_id.clone(), message.encode()?));
        decoded.push(Some(message));
        for (index, blob_id) in references {
            records.push(Record::new(
                KIND_META,
                format!("blobref:{message_id}:{index}"),
                BlobRefRecord {
                    attachment_id: index as u32,
                    blob_id,
                    message_id: message_id.clone(),
                }
                .encode()?,
            ));
            decoded.push(None);
        }
        let batch = NewBatch::new(records);
        self.append_prepared(&account_id, batch, decoded).await
    }

    pub async fn get_attachment(
        &self,
        message_id: &str,
        attachment_id: usize,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let Some(message) = self.get_message(message_id)? else {
            return Ok(None);
        };
        let Some(attachment) = message.attachments.get(attachment_id) else {
            return Ok(None);
        };
        if !attachment.data.is_empty() {
            return Ok(Some(attachment.data.clone()));
        }
        let key = format!("{message_id}:{attachment_id}");
        let blob_id = self.state().blob_refs.read().get(&key).cloned();
        let Some(blob_id) = blob_id else {
            return Ok(None);
        };
        Ok(Some(self.state().blobs.get(&blob_id)?))
    }

    pub async fn append_messages(
        &self,
        messages: Vec<Message>,
    ) -> Result<Vec<Receipt>, StoreError> {
        let mut groups: HashMap<String, Vec<Message>> = HashMap::new();
        for message in messages {
            message.validate()?;
            groups
                .entry(message.account_id.clone())
                .or_default()
                .push(message);
        }
        let mut receipts = Vec::new();
        for (account_id, mut messages) in groups {
            while !messages.is_empty() {
                let chunk = messages
                    .drain(..messages.len().min(1000))
                    .collect::<Vec<_>>();
                let mut records = Vec::with_capacity(chunk.len());
                let mut decoded = Vec::with_capacity(chunk.len());
                for message in chunk {
                    let payload = message.encode()?;
                    records.push(Record::message(message.id.clone(), payload));
                    decoded.push(Some(message));
                }
                let batch = NewBatch::new(records);
                receipts.push(self.append_prepared(&account_id, batch, decoded).await?);
            }
        }
        Ok(receipts)
    }

    pub fn append_messages_blocking(
        &self,
        messages: Vec<Message>,
    ) -> Result<Vec<Receipt>, StoreError> {
        futures::executor::block_on(self.append_messages(messages))
    }

    pub async fn append_batch(
        &self,
        account_id: &str,
        batch: NewBatch,
    ) -> Result<Receipt, StoreError> {
        if account_id.is_empty() {
            return Err(StoreError::Config("empty account id".into()));
        }
        let decoded_messages = validate_batch(account_id, &batch)?;
        self.append_prepared(account_id, batch, decoded_messages)
            .await
    }

    async fn append_prepared(
        &self,
        account_id: &str,
        batch: NewBatch,
        decoded_messages: Vec<Option<Message>>,
    ) -> Result<Receipt, StoreError> {
        let _gate = self.gate.read().await;
        let lane = self.lane_for_account(account_id);
        self.commit_lane_locked(lane, batch, decoded_messages).await
    }

    async fn commit_lane_locked(
        &self,
        lane: LaneWriter,
        batch: NewBatch,
        decoded_messages: Vec<Option<Message>>,
    ) -> Result<Receipt, StoreError> {
        let records = batch.records.clone();
        let receipt = lane.append(batch).await?;
        self.state()
            .apply
            .submit(
                receipt.lane_id,
                receipt.seq,
                receipt.offset,
                receipt.total_len,
                records,
                decoded_messages,
            )
            .await?;
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
        if let Some(doc) = self.state().index.get(id) {
            message.flags = doc.flags;
            message.account_id = doc.account_id.clone();
            message.mailbox = doc.mailbox.clone();
        }
        Ok(Some(message))
    }

    pub fn search(&self, query: &SearchQuery) -> Vec<SearchHit> {
        self.state().index.search(query)
    }

    pub fn message_ids(&self) -> Vec<String> {
        self.state().index.ids()
    }

    pub fn index_size(&self) -> usize {
        self.state().index.len()
    }

    pub fn list_folders(&self, account_id: &str) -> Vec<Folder> {
        self.state()
            .folders
            .read()
            .get(account_id)
            .map(|folders| folders.values().cloned().collect())
            .unwrap_or_default()
    }

    pub async fn ensure_default_folders(&self, account_id: &str) -> Result<(), StoreError> {
        let existing = self
            .state()
            .folders
            .read()
            .get(account_id)
            .cloned()
            .unwrap_or_default();
        let records = DEFAULT_FOLDERS
            .iter()
            .filter(|(name, _)| !existing.contains_key(*name))
            .map(|(name, role)| {
                Record::new(
                    KIND_META,
                    format!("folder:{name}"),
                    FolderRecord::create(account_id, name, role)
                        .encode()
                        .unwrap_or_default(),
                )
            })
            .collect::<Vec<_>>();
        if records.is_empty() {
            return Ok(());
        }
        self.append_batch(account_id, NewBatch::new(records))
            .await?;
        Ok(())
    }

    pub async fn create_folder(&self, account_id: &str, name: &str) -> Result<Receipt, StoreError> {
        validate_folder_name(name).map_err(StoreError::Config)?;
        if self
            .state()
            .folders
            .read()
            .get(account_id)
            .is_some_and(|folders| folders.contains_key(name))
        {
            return Err(StoreError::Config("folder already exists".into()));
        }
        let record = FolderRecord::create(account_id, name, "custom");
        self.append_batch(
            account_id,
            NewBatch::single(Record::new(
                KIND_META,
                format!("folder:{name}"),
                record.encode()?,
            )),
        )
        .await
    }

    pub async fn delete_folder(&self, account_id: &str, name: &str) -> Result<usize, StoreError> {
        if DEFAULT_FOLDERS.iter().any(|(default, _)| *default == name) {
            return Err(StoreError::Config("cannot delete a default folder".into()));
        }
        self.ensure_default_folders(account_id).await?;
        let ids = self.state().index.ids_in_folder(account_id, name);
        self.move_many(account_id, &ids, "Trash").await?;
        let record = FolderRecord::delete(account_id, name, "custom");
        self.append_batch(
            account_id,
            NewBatch::single(Record::new(
                KIND_META,
                format!("folder:{name}"),
                record.encode()?,
            )),
        )
        .await?;
        Ok(ids.len())
    }

    pub async fn rename_folder(
        &self,
        account_id: &str,
        old_name: &str,
        new_name: &str,
    ) -> Result<usize, StoreError> {
        validate_folder_name(new_name).map_err(StoreError::Config)?;
        if DEFAULT_FOLDERS
            .iter()
            .any(|(default, _)| *default == old_name)
        {
            return Err(StoreError::Config("cannot rename a default folder".into()));
        }
        let exists = self
            .state()
            .folders
            .read()
            .get(account_id)
            .is_some_and(|folders| folders.contains_key(old_name));
        if !exists {
            return Err(StoreError::NotFound(old_name.into()));
        }
        let conflict = self
            .state()
            .folders
            .read()
            .get(account_id)
            .is_some_and(|folders| folders.contains_key(new_name));
        if conflict {
            return Err(StoreError::Config("folder already exists".into()));
        }
        let ids = self.state().index.ids_in_folder(account_id, old_name);
        self.move_many(account_id, &ids, new_name).await?;
        let mut records = vec![Record::new(
            KIND_META,
            format!("folder:{new_name}"),
            FolderRecord::create(account_id, new_name, "custom").encode()?,
        )];
        records.push(Record::new(
            KIND_META,
            format!("folder:{old_name}"),
            FolderRecord::delete(account_id, old_name, "custom").encode()?,
        ));
        self.append_batch(account_id, NewBatch::new(records))
            .await?;
        Ok(ids.len())
    }

    async fn move_many(
        &self,
        account_id: &str,
        ids: &[String],
        mailbox: &str,
    ) -> Result<(), StoreError> {
        for chunk in ids.chunks(500) {
            let records = chunk
                .iter()
                .map(|id| {
                    let payload = MovePayload {
                        account_id: account_id.to_string(),
                        mailbox: mailbox.to_string(),
                    }
                    .encode()?;
                    Ok(Record::new(KIND_MOVE, id.clone(), payload))
                })
                .collect::<Result<Vec<_>, StoreError>>()?;
            if !records.is_empty() {
                self.append_batch(account_id, NewBatch::new(records))
                    .await?;
            }
        }
        Ok(())
    }

    pub fn account_stats(&self, account_id: &str) -> AccountStats {
        let inner = self.state();
        let index = &*inner.index;
        let mut stats = AccountStats::default();
        for doc in index.docs_for_account(account_id).iter() {
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
        let lane = self
            .state()
            .lanes
            .get(location.lane_id as usize)
            .ok_or_else(|| StoreError::corrupt("lane out of bounds"))?
            .clone();
        self.commit_lane_locked(lane, NewBatch::single(Record::delete(id)), vec![None])
            .await
    }

    pub async fn update_flags(&self, id: &str, flags: u64) -> Result<Receipt, StoreError> {
        let _gate = self.gate.read().await;
        let location = self.location(id)?;
        let lane = self
            .state()
            .lanes
            .get(location.lane_id as usize)
            .ok_or_else(|| StoreError::corrupt("lane out of bounds"))?
            .clone();
        self.commit_lane_locked(lane, NewBatch::single(Record::flags(id, flags)), vec![None])
            .await
    }

    pub async fn move_message(
        &self,
        id: &str,
        account_id: &str,
        mailbox: &str,
    ) -> Result<Receipt, StoreError> {
        let _gate = self.gate.read().await;
        let location = self.location(id)?;
        let lane = self
            .state()
            .lanes
            .get(location.lane_id as usize)
            .ok_or_else(|| StoreError::corrupt("lane out of bounds"))?
            .clone();
        let payload = MovePayload {
            account_id: account_id.to_string(),
            mailbox: mailbox.to_string(),
        }
        .encode()?;
        self.commit_lane_locked(
            lane,
            NewBatch::single(Record::new(KIND_MOVE, id, payload)),
            vec![None],
        )
        .await
    }

    pub async fn flush(&self) -> Result<(), StoreError> {
        self.snapshot().await
    }

    pub async fn snapshot(&self) -> Result<(), StoreError> {
        let _guard = self.gate.write().await;
        self.snapshot_locked().await
    }

    async fn snapshot_locked(&self) -> Result<(), StoreError> {
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
            index: self.state().index.snapshot(),
            catalog: self.state().catalog.read().clone(),
            changes: self.state().changes.read().clone(),
            folders: self.state().folders.read().clone(),
            blob_refs: self.state().blob_refs.read().clone(),
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

    pub async fn gc_blobs(&self, grace: std::time::Duration) -> Result<usize, StoreError> {
        let _guard = self.gate.write().await;
        let referenced = self
            .state()
            .blob_refs
            .read()
            .values()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        let mut removed = 0;
        let now = std::time::SystemTime::now();
        for id in self.state().blobs.list_ids()? {
            if referenced.contains(&id) {
                continue;
            }
            let modified = self.state().blobs.modified(&id)?;
            if now.duration_since(modified).unwrap_or_default() >= grace {
                self.state().blobs.remove(&id)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    pub async fn backup_to(&self, target: impl AsRef<Path>) -> Result<StoreStats, StoreError> {
        let _guard = self.gate.write().await;
        self.snapshot_locked().await?;
        let target = target.as_ref();
        std::fs::create_dir_all(target)?;
        let source = self.state();
        std::fs::copy(source.path.as_path(), target.join("mail.tide"))?;
        source.blobs.copy_to(&target.join("blobs"))?;
        let manifest = format!(
            "{{\"format\":\"tide-backup\",\"generation\":{},\"messages\":{},\"created_at\":{}}}\n",
            source.generation.load(Ordering::Relaxed),
            source.index.len(),
            crate::batch::now_millis()
        );
        std::fs::write(target.join("manifest.json"), manifest)?;
        Ok(StoreStats {
            path: target.to_path_buf(),
            generation: source.generation.load(Ordering::Relaxed),
            data_lanes: source.superblock.data_lanes,
            lane_capacity: source.superblock.lane_capacity,
            messages: source.index.len(),
        })
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
        let ids = old.index.ids();
        for id in ids {
            if let Some(mut message) = self.get_message(&id)? {
                for index in 0..message.attachments.len() {
                    if message.attachments[index].data.is_empty() {
                        if let Ok(Some(data)) = self.get_attachment(&id, index).await {
                            message.attachments[index].data = data;
                        }
                    }
                }
                new_db.append_message_with_blobs(message).await?;
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

fn spawn_apply_worker(context: ApplyContext, next_seqs: HashMap<u16, u64>) -> ApplyHandle {
    let (tx, rx) = unbounded();
    let join = std::thread::Builder::new()
        .name("tide-index-apply".into())
        .spawn(move || run_apply_worker(context, next_seqs, rx))
        .expect("apply worker");
    ApplyHandle {
        tx,
        join: parking_lot::Mutex::new(Some(join)),
    }
}

fn run_apply_worker(
    context: ApplyContext,
    mut next_seqs: HashMap<u16, u64>,
    rx: Receiver<ApplyCommand>,
) {
    let mut pending: HashMap<u16, BTreeMap<u64, ApplyJob>> = HashMap::new();
    while let Ok(command) = rx.recv() {
        match command {
            ApplyCommand::Job(job) => {
                pending.entry(job.lane_id).or_default().insert(job.seq, job);
                process_apply_ready(&context, &mut next_seqs, &mut pending);
            }
            ApplyCommand::Shutdown => break,
        }
    }
}

fn process_apply_ready(
    context: &ApplyContext,
    next_seqs: &mut HashMap<u16, u64>,
    pending: &mut HashMap<u16, BTreeMap<u64, ApplyJob>>,
) {
    loop {
        let mut progressed = false;
        let lanes = next_seqs.keys().copied().collect::<Vec<_>>();
        for lane in lanes {
            let next = next_seqs.get(&lane).copied().unwrap_or(0);
            let Some(jobs) = pending.get_mut(&lane) else {
                continue;
            };
            let Some(job) = jobs.remove(&next) else {
                continue;
            };
            let result = apply_job(context, &job);
            let _ = job.reply.send(result);
            next_seqs.insert(lane, next.saturating_add(1));
            progressed = true;
            if jobs.is_empty() {
                pending.remove(&lane);
            }
            break;
        }
        if !progressed {
            break;
        }
    }
}

fn apply_job(context: &ApplyContext, job: &ApplyJob) -> Result<(), StoreError> {
    let index = &*context.index;
    let mut catalog = context.catalog.write();
    let mut changes = context.changes.write();
    let mut folders = context.folders.write();
    let mut blob_refs = context.blob_refs.write();
    for (record_index, record) in job.records.iter().enumerate() {
        match record.kind {
            KIND_MESSAGE => {
                let message = job
                    .decoded_messages
                    .get(record_index)
                    .and_then(Option::as_ref)
                    .ok_or_else(|| StoreError::corrupt("message was not decoded"))?;
                push_change(&mut changes, ChangeEntry::from_message(job.seq, message));
                index.insert(message);
                catalog.insert(
                    record.key.clone(),
                    Location {
                        lane_id: job.lane_id,
                        batch_offset: job.batch_offset,
                        batch_len: job.batch_len,
                        record_index,
                    },
                );
            }
            KIND_DELETE => {
                if let Some(doc) = index.get(&record.key) {
                    push_change(
                        &mut changes,
                        ChangeEntry::from_doc(job.seq, change_kind::DELETE, &doc),
                    );
                }
                index.delete(&record.key);
                catalog.remove(&record.key);
                blob_refs.retain(|key, _| !key.starts_with(&format!("{}:", record.key)));
            }
            KIND_FLAGS => {
                if let Some(flags) = decode_flags(&record.payload) {
                    index.update_flags(&record.key, flags);
                    if let Some(doc) = index.get(&record.key) {
                        let mut entry = ChangeEntry::from_doc(job.seq, change_kind::FLAGS, &doc);
                        entry.flags = flags;
                        push_change(&mut changes, entry);
                    }
                }
            }
            KIND_MOVE => {
                let payload = MovePayload::decode(&record.payload)?;
                index.move_message(&record.key, &payload.account_id, &payload.mailbox);
                if let Some(doc) = index.get(&record.key) {
                    let mut entry = ChangeEntry::from_doc(job.seq, change_kind::MOVE, &doc);
                    entry.mailbox = payload.mailbox.clone();
                    push_change(&mut changes, entry);
                }
            }
            KIND_META if record.key.starts_with("folder:") => {
                if let Ok(folder) = FolderRecord::decode(&record.payload) {
                    apply_folder(&mut folders, folder);
                }
            }
            KIND_META if record.key.starts_with("blobref:") => {
                if let Ok(reference) = BlobRefRecord::decode(&record.payload) {
                    blob_refs.insert(
                        format!("{}:{}", reference.message_id, reference.attachment_id),
                        reference.blob_id,
                    );
                }
            }
            _ => {}
        }
    }
    Ok(())
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
            Err(error) => eprintln!("snapshot {id} is invalid: {error}"),
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

#[allow(clippy::too_many_arguments)]
fn apply_batch_to_maps(
    lane_id: u16,
    batch: &DecodedBatch,
    offset: u64,
    index: &ShardedIndex,
    catalog: &mut HashMap<String, Location>,
    changes: &mut HashMap<String, Vec<ChangeEntry>>,
    folders: &mut HashMap<String, BTreeMap<String, Folder>>,
    blob_refs: &mut HashMap<String, String>,
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
                        ChangeEntry::from_doc(seq, change_kind::DELETE, &doc),
                    );
                }
                index.delete(&record.key);
                catalog.remove(&record.key);
                blob_refs.retain(|key, _| !key.starts_with(&format!("{}:", record.key)));
            }
            KIND_FLAGS => {
                if let Some(flags) = decode_flags(&record.payload) {
                    index.update_flags(&record.key, flags);
                    if let Some(doc) = index.get(&record.key) {
                        let mut entry = ChangeEntry::from_doc(seq, change_kind::FLAGS, &doc);
                        entry.flags = flags;
                        push_change(changes, entry);
                    }
                }
            }
            KIND_MOVE => {
                let payload = MovePayload::decode(&record.payload)?;
                index.move_message(&record.key, &payload.account_id, &payload.mailbox);
                if let Some(doc) = index.get(&record.key) {
                    let mut entry = ChangeEntry::from_doc(seq, change_kind::MOVE, &doc);
                    entry.mailbox = payload.mailbox.clone();
                    push_change(changes, entry);
                }
            }
            KIND_META if record.key.starts_with("folder:") => {
                if let Ok(folder) = FolderRecord::decode(&record.payload) {
                    apply_folder(folders, folder);
                }
            }
            KIND_META if record.key.starts_with("blobref:") => {
                if let Ok(reference) = BlobRefRecord::decode(&record.payload) {
                    blob_refs.insert(
                        format!("{}:{}", reference.message_id, reference.attachment_id),
                        reference.blob_id,
                    );
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn apply_folder(folders: &mut HashMap<String, BTreeMap<String, Folder>>, folder: FolderRecord) {
    let entry = folders.entry(folder.account_id.clone()).or_default();
    if folder.deleted {
        entry.remove(&folder.name);
    } else {
        entry.insert(folder.name.clone(), folder.to_folder());
    }
}

fn push_change(changes: &mut HashMap<String, Vec<ChangeEntry>>, entry: ChangeEntry) {
    changes
        .entry(entry.account_id.clone())
        .or_default()
        .push(entry);
}

fn validate_batch(account_id: &str, batch: &NewBatch) -> Result<Vec<Option<Message>>, StoreError> {
    if batch.records.is_empty() {
        return Err(StoreError::invalid_batch("empty batch"));
    }
    let mut messages = Vec::with_capacity(batch.records.len());
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
            messages.push(Some(message));
        } else {
            if record.kind == KIND_MOVE {
                let _ = MovePayload::decode(&record.payload)?;
            }
            messages.push(None);
        }
    }
    Ok(messages)
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
    fn externalizes_attachments_to_blob_store() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mail.tide");
        let db = Db::open(&path, options()).unwrap();
        let mut message = message("blob1", "alice", "Attachment", "body");
        message.attachments.push(tide_core::Attachment {
            filename: "file.bin".into(),
            content_type: "application/octet-stream".into(),
            size: 5,
            data: b"hello".to_vec(),
        });
        futures::executor::block_on(db.append_message_with_blobs(message)).unwrap();
        assert_eq!(
            futures::executor::block_on(db.get_attachment("blob1", 0)).unwrap(),
            Some(b"hello".to_vec())
        );
        assert!(
            db.get_message("blob1").unwrap().unwrap().attachments[0]
                .data
                .is_empty()
        );
        drop(db);
        let db = Db::open(&path, options()).unwrap();
        assert_eq!(
            futures::executor::block_on(db.get_attachment("blob1", 0)).unwrap(),
            Some(b"hello".to_vec())
        );
        futures::executor::block_on(db.compact()).unwrap();
        assert_eq!(
            futures::executor::block_on(db.get_attachment("blob1", 0)).unwrap(),
            Some(b"hello".to_vec())
        );
    }

    #[test]
    fn garbage_collects_unreferenced_blobs() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mail.tide");
        let db = Db::open(&path, options()).unwrap();
        let referenced = db.state().blobs.put(b"keep").unwrap();
        let orphan = db.state().blobs.put(b"orphan").unwrap();
        let mut message = message("gc1", "alice", "GC", "body");
        message.attachments.push(tide_core::Attachment {
            filename: "file".into(),
            content_type: "text/plain".into(),
            size: 4,
            data: b"keep".to_vec(),
        });
        futures::executor::block_on(db.append_message_with_blobs(message)).unwrap();
        assert_eq!(
            futures::executor::block_on(db.gc_blobs(std::time::Duration::ZERO)).unwrap(),
            1
        );
        assert_eq!(
            futures::executor::block_on(db.get_attachment("gc1", 0)).unwrap(),
            Some(b"keep".to_vec())
        );
        assert!(db.state().blobs.get(&orphan).is_err());
        assert_eq!(db.state().blobs.get(&referenced).unwrap(), b"keep");
    }

    #[test]
    fn backup_copies_database_and_blobs() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mail.tide");
        let db = Db::open(&path, options()).unwrap();
        let mut message = message("backup1", "alice", "Backup", "body");
        message.attachments.push(tide_core::Attachment {
            filename: "file.bin".into(),
            content_type: "application/octet-stream".into(),
            size: 5,
            data: b"hello".to_vec(),
        });
        futures::executor::block_on(db.append_message_with_blobs(message)).unwrap();
        let target = directory.path().join("backup");
        futures::executor::block_on(db.backup_to(&target)).unwrap();
        drop(db);
        let restored = Db::open(target.join("mail.tide"), options()).unwrap();
        assert_eq!(restored.index_size(), 1);
        assert_eq!(
            futures::executor::block_on(restored.get_attachment("backup1", 0)).unwrap(),
            Some(b"hello".to_vec())
        );
    }

    #[test]
    fn bulk_append_uses_large_batches() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mail.tide");
        let db = Db::open(&path, options().with_lane_capacity(32 * 1024 * 1024)).unwrap();
        let messages = (0..2000)
            .map(|index| message(&format!("b{index}"), "bulk", "Bulk", "bulk body"))
            .collect::<Vec<_>>();
        let receipts = futures::executor::block_on(db.append_messages(messages)).unwrap();
        assert!(!receipts.is_empty());
        assert_eq!(db.index_size(), 2000);
        drop(db);
        let db = Db::open(&path, options()).unwrap();
        assert_eq!(db.index_size(), 2000);
    }

    #[test]
    fn concurrent_writers_same_account_keep_order() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mail.tide");
        let db = Db::open(&path, options().with_lane_capacity(32 * 1024 * 1024)).unwrap();
        let mut handles = Vec::new();
        for thread in 0..8u64 {
            let db = db.clone();
            handles.push(std::thread::spawn(move || {
                for index in 0..50u64 {
                    db.append_message_blocking(message(
                        &format!("s{thread}-{index}"),
                        "same",
                        "Same account",
                        "body",
                    ))
                    .unwrap();
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(db.index_size(), 400);
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
    fn folder_crud_moves_messages() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mail.tide");
        let db = Db::open(&path, options()).unwrap();
        futures::executor::block_on(db.ensure_default_folders("alice")).unwrap();
        assert!(
            db.list_folders("alice")
                .iter()
                .any(|folder| folder.name == "INBOX")
        );
        assert!(
            db.list_folders("alice")
                .iter()
                .any(|folder| folder.name == "Junk")
        );
        futures::executor::block_on(db.create_folder("alice", "Projects")).unwrap();
        db.append_message_blocking(message("1", "alice", "Project", "body"))
            .unwrap();
        futures::executor::block_on(db.move_message("1", "alice", "Projects")).unwrap();
        assert_eq!(
            futures::executor::block_on(db.rename_folder("alice", "Projects", "Work")).unwrap(),
            1
        );
        assert_eq!(db.get_message("1").unwrap().unwrap().mailbox, "Work");
        assert_eq!(
            futures::executor::block_on(db.delete_folder("alice", "Work")).unwrap(),
            1
        );
        assert_eq!(db.get_message("1").unwrap().unwrap().mailbox, "Trash");
        drop(db);
        let db = Db::open(&path, options()).unwrap();
        assert!(
            db.list_folders("alice")
                .iter()
                .any(|folder| folder.name == "INBOX")
        );
        assert!(
            !db.list_folders("alice")
                .iter()
                .any(|folder| folder.name == "Work")
        );
        assert_eq!(db.get_message("1").unwrap().unwrap().mailbox, "Trash");
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
