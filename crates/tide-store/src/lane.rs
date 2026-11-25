use std::fs::File;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::mpsc;

use crossbeam_channel::{Receiver, Sender, unbounded};
use futures_channel::oneshot;
use io_uring::{IoUring, opcode, types};

use crate::batch::{DecodedBatch, NewBatch, encode_batch};
use crate::error::StoreError;
use crate::format::{LANE_HEADER_SIZE, LaneHeader, MAX_BATCH_SIZE};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Durability {
    None,
    #[default]
    DataSync,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub lane_id: u16,
    pub seq: u64,
    pub offset: u64,
    pub total_len: u64,
    pub records: usize,
    pub durable: bool,
}

enum LaneCommand {
    Write {
        batch: NewBatch,
        reply: oneshot::Sender<Result<Receipt, StoreError>>,
    },
    Checkpoint {
        reply: oneshot::Sender<Result<(), StoreError>>,
    },
    Shutdown,
}

pub struct LaneHandle {
    lane_id: u16,
    tx: Sender<LaneCommand>,
    join: parking_lot::Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl LaneHandle {
    pub fn lane_id(&self) -> u16 {
        self.lane_id
    }
}

impl Drop for LaneHandle {
    fn drop(&mut self) {
        let _ = self.tx.send(LaneCommand::Shutdown);
        if let Some(join) = self.join.lock().take() {
            let _ = join.join();
        }
    }
}

#[derive(Clone)]
pub struct LaneWriter {
    handle: Arc<LaneHandle>,
}

impl LaneWriter {
    pub fn lane_id(&self) -> u16 {
        self.handle.lane_id
    }

    pub async fn append(&self, batch: NewBatch) -> Result<Receipt, StoreError> {
        let (reply, receiver) = oneshot::channel();
        self.handle
            .tx
            .send(LaneCommand::Write { batch, reply })
            .map_err(|_| StoreError::LaneClosed {
                lane: self.handle.lane_id,
            })?;
        receiver.await.map_err(|_| StoreError::LaneClosed {
            lane: self.handle.lane_id,
        })?
    }

    pub fn append_blocking(&self, batch: NewBatch) -> Result<Receipt, StoreError> {
        futures::executor::block_on(self.append(batch))
    }

    pub async fn checkpoint(&self) -> Result<(), StoreError> {
        let (reply, receiver) = oneshot::channel();
        self.handle
            .tx
            .send(LaneCommand::Checkpoint { reply })
            .map_err(|_| StoreError::LaneClosed {
                lane: self.handle.lane_id,
            })?;
        receiver.await.map_err(|_| StoreError::LaneClosed {
            lane: self.handle.lane_id,
        })?
    }

    pub fn checkpoint_blocking(&self) -> Result<(), StoreError> {
        futures::executor::block_on(self.checkpoint())
    }
}

pub(crate) fn spawn_lane(
    lane_id: u16,
    file: Arc<File>,
    base: u64,
    capacity: u64,
    head: u64,
    seq: u64,
    durability: Durability,
) -> Result<LaneWriter, StoreError> {
    let (tx, rx) = unbounded();
    let (init_tx, init_rx) = mpsc::channel();
    let thread_name = format!("tide-lane-{lane_id}");
    let join = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            run_lane(
                lane_id, file, base, capacity, head, seq, durability, rx, init_tx,
            )
        })
        .map_err(StoreError::Io)?;
    match init_rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            let _ = join.join();
            return Err(error);
        }
        Err(_) => {
            let _ = join.join();
            return Err(StoreError::Internal(format!(
                "lane {lane_id} failed to start"
            )));
        }
    }
    Ok(LaneWriter {
        handle: Arc::new(LaneHandle {
            lane_id,
            tx,
            join: parking_lot::Mutex::new(Some(join)),
        }),
    })
}

struct LaneState {
    lane_id: u16,
    fd: RawFd,
    base: u64,
    capacity: u64,
    head: u64,
    seq: u64,
    durability: Durability,
    ring: IoUring,
}

#[allow(clippy::too_many_arguments)]
fn run_lane(
    lane_id: u16,
    file: Arc<File>,
    base: u64,
    capacity: u64,
    head: u64,
    seq: u64,
    durability: Durability,
    rx: Receiver<LaneCommand>,
    init_tx: mpsc::Sender<Result<(), StoreError>>,
) {
    let ring = match IoUring::new(32) {
        Ok(ring) => ring,
        Err(error) => {
            let _ = init_tx.send(Err(StoreError::Io(error)));
            return;
        }
    };
    let data_start = base + LANE_HEADER_SIZE;
    let data_end = base + capacity;
    let head = head.clamp(data_start, data_end);
    let mut state = LaneState {
        lane_id,
        fd: file.as_raw_fd(),
        base,
        capacity,
        head,
        seq,
        durability,
        ring,
    };
    if init_tx.send(Ok(())).is_err() {
        return;
    }
    drop(init_tx);

    while let Ok(command) = rx.recv() {
        match command {
            LaneCommand::Write { batch, reply } => {
                let result = state.write_batch(batch);
                let _ = reply.send(result);
            }
            LaneCommand::Checkpoint { reply } => {
                let result = persist_lane_header(&file, &state);
                let _ = reply.send(result);
            }
            LaneCommand::Shutdown => break,
        }
    }
    let _ = persist_lane_header(&file, &state);
}

impl LaneState {
    fn write_batch(&mut self, batch: NewBatch) -> Result<Receipt, StoreError> {
        let encoded = encode_batch(self.lane_id, self.seq, &batch)?;
        let total_len = encoded.len() as u64;
        if total_len > MAX_BATCH_SIZE {
            return Err(StoreError::invalid_batch("batch too large"));
        }
        let available = (self.base + self.capacity).saturating_sub(self.head);
        if total_len > available {
            return Err(StoreError::LaneFull {
                lane: self.lane_id,
                need: total_len,
                available,
            });
        }
        let offset = self.head;
        write_all_at(
            &mut self.ring,
            self.fd,
            &encoded,
            offset,
            self.durability == Durability::DataSync,
        )?;
        self.head += total_len;
        let receipt = Receipt {
            lane_id: self.lane_id,
            seq: self.seq,
            offset,
            total_len,
            records: batch.records.len(),
            durable: self.durability == Durability::DataSync,
        };
        self.seq += 1;
        Ok(receipt)
    }
}

fn persist_lane_header(file: &File, state: &LaneState) -> Result<(), StoreError> {
    let header = LaneHeader {
        lane_id: state.lane_id,
        capacity: state.capacity,
        head: state.head,
        seq: state.seq,
        checkpoint_seq: state.seq,
        checkpoint_head: state.head,
    };
    write_all_at(
        &mut IoUring::new(2).map_err(StoreError::Io)?,
        file.as_raw_fd(),
        &header.encode(),
        state.base,
        true,
    )?;
    Ok(())
}

pub(crate) fn write_all_at(
    ring: &mut IoUring,
    fd: RawFd,
    bytes: &[u8],
    offset: u64,
    durable: bool,
) -> Result<(), StoreError> {
    let mut written = 0usize;
    while written < bytes.len() {
        let slice = &bytes[written..];
        let entry = opcode::Write::new(types::Fd(fd), slice.as_ptr(), slice.len() as u32)
            .offset(offset + written as u64)
            .rw_flags(if durable { libc::RWF_DSYNC } else { 0 })
            .build()
            .user_data(1);
        unsafe {
            ring.submission()
                .push(&entry)
                .map_err(|_| StoreError::Internal("io_uring submission queue full".into()))?;
        }
        ring.submit_and_wait(1).map_err(StoreError::Io)?;
        let completion = ring
            .completion()
            .next()
            .ok_or_else(|| StoreError::Internal("io_uring completion queue empty".into()))?;
        let result = completion.result();
        if result < 0 {
            return Err(StoreError::Io(std::io::Error::from_raw_os_error(-result)));
        }
        let result = result as usize;
        if result == 0 {
            return Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "io_uring write returned zero",
            )));
        }
        written += result;
    }
    Ok(())
}

pub(crate) fn replay_lane(
    mmap: &[u8],
    base: u64,
    capacity: u64,
    start_head: u64,
    start_seq: u64,
) -> Result<(u64, u64, Vec<DecodedBatch>), StoreError> {
    let data_start = base + LANE_HEADER_SIZE;
    let data_end = base + capacity;
    let mut head = start_head.clamp(data_start, data_end);
    let mut seq = start_seq;
    let mut batches = Vec::new();
    while head + 64 <= data_end {
        let offset = usize::try_from(head).map_err(|_| StoreError::corrupt("offset overflow"))?;
        let end = usize::try_from(data_end).map_err(|_| StoreError::corrupt("offset overflow"))?;
        if offset + 64 > mmap.len() || end > mmap.len() {
            return Err(StoreError::corrupt("lane outside mmap"));
        }
        let header = &mmap[offset..offset + 64];
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        let total_len = match crate::batch::peek_batch_len(header) {
            Ok(value) => value,
            Err(_) => break,
        };
        if head + total_len > data_end {
            break;
        }
        let batch_end = usize::try_from(head + total_len)
            .map_err(|_| StoreError::corrupt("batch end overflow"))?;
        if batch_end > mmap.len() {
            break;
        }
        let decoded = match crate::batch::decode_batch(&mmap[offset..batch_end]) {
            Ok(value) => value,
            Err(_) => break,
        };
        head += total_len;
        seq = decoded.seq.saturating_add(1);
        batches.push(decoded);
    }
    Ok((head, seq, batches))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::LANE_HEADER_SIZE;
    use std::os::unix::fs::FileExt;

    #[test]
    fn writes_and_replays_batches() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lane.bin");
        let file = File::create(&path).unwrap();
        file.set_len(LANE_HEADER_SIZE + 1024 * 1024).unwrap();
        let header = LaneHeader {
            lane_id: 2,
            capacity: LANE_HEADER_SIZE + 1024 * 1024,
            head: LANE_HEADER_SIZE,
            seq: 1,
            checkpoint_seq: 0,
            checkpoint_head: LANE_HEADER_SIZE,
        };
        file.write_all_at(&header.encode(), 0).unwrap();
        let file = Arc::new(file);
        let writer = spawn_lane(
            2,
            Arc::clone(&file),
            0,
            LANE_HEADER_SIZE + 1024 * 1024,
            LANE_HEADER_SIZE,
            1,
            Durability::DataSync,
        )
        .unwrap();
        let receipt = writer
            .append_blocking(NewBatch::single(crate::batch::Record::note(
                "key",
                vec![1, 2, 3],
            )))
            .unwrap();
        assert_eq!(receipt.seq, 1);
        assert!(receipt.durable);
        drop(writer);
        let bytes = std::fs::read(&path).unwrap();
        let (head, seq, batches) = replay_lane(
            &bytes,
            0,
            LANE_HEADER_SIZE + 1024 * 1024,
            LANE_HEADER_SIZE,
            1,
        )
        .unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(head, receipt.offset + receipt.total_len);
        assert_eq!(seq, 2);
    }
}
