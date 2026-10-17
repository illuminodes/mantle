use std::collections::BTreeMap;
use std::io;

use super::completions::OwedCompletions;
use super::{pread_exact, uring_err, Bucket, RobinHoodTable, BUCKET_SIZE};

pub(super) const CHUNK_SLOTS: u64 = 64;

struct Chunk {
    bytes: Vec<u8>,
    dirty: bool,
}

/// Contiguous runs of table slots held in memory while a flush rewrites them.
///
/// Chunks named up front are read in one `io_uring` batch; a slot outside
/// them is read with one `pread` of its chunk. Dirty chunks go back to disk
/// in one batch of writes.
pub(super) struct ChunkCache {
    chunk_slots: u64,
    chunks: BTreeMap<u64, Chunk>,
}

impl ChunkCache {
    pub(super) fn new(slot_count: u64) -> Self {
        Self {
            chunk_slots: CHUNK_SLOTS.min(slot_count),
            chunks: BTreeMap::new(),
        }
    }

    fn chunk_bytes(&self) -> usize {
        usize::try_from(self.chunk_slots).expect("chunk fits usize") * BUCKET_SIZE
    }

    fn chunk_len_u32(&self) -> u32 {
        u32::try_from(self.chunk_bytes()).expect("chunk fits u32")
    }

    pub(super) fn chunk_of(&self, slot: u64) -> u64 {
        slot / self.chunk_slots
    }

    fn locate(&self, slot: u64) -> (u64, usize) {
        let index = usize::try_from(slot % self.chunk_slots).expect("index fits usize");
        (self.chunk_of(slot), index * BUCKET_SIZE)
    }

    /// Read every listed chunk that is not already held, in one batch.
    pub(super) fn prefetch(
        &mut self,
        table: &RobinHoodTable,
        ring: &mut ququmatz::IoUring,
        ids: impl IntoIterator<Item = u64>,
    ) -> io::Result<()> {
        let fd = table.uring_fd();
        let len = self.chunk_len_u32();
        let bytes = self.chunk_bytes();
        let mut batch = UringBatch::new(len);
        for id in ids {
            if self.chunks.contains_key(&id) {
                continue;
            }
            let chunk = self.chunks.entry(id).or_insert_with(|| Chunk {
                bytes: vec![0; bytes],
                dirty: false,
            });
            // SAFETY: the chunk's heap buffer is neither freed nor moved
            // until the batch is drained below.
            let sqe = unsafe {
                ququmatz::Sqe::read_ptr(
                    fd,
                    chunk.bytes.as_mut_ptr(),
                    len,
                    RobinHoodTable::slot_offset(id * self.chunk_slots),
                )
            };
            batch.push(table, ring, sqe)?;
        }
        batch.drain(ring)
    }

    fn load(&mut self, table: &RobinHoodTable, id: u64) -> io::Result<&mut Chunk> {
        if !self.chunks.contains_key(&id) {
            let mut bytes = vec![0; self.chunk_bytes()];
            pread_exact(
                &table.file,
                &mut bytes,
                RobinHoodTable::slot_offset(id * self.chunk_slots),
            )?;
            self.chunks.insert(id, Chunk { bytes, dirty: false });
        }
        Ok(self.chunks.get_mut(&id).expect("chunk just loaded"))
    }

    pub(super) fn bucket(&mut self, table: &RobinHoodTable, slot: u64) -> io::Result<Bucket> {
        let (id, start) = self.locate(slot);
        let chunk = self.load(table, id)?;
        Ok(Bucket::decode(
            chunk.bytes[start..start + BUCKET_SIZE]
                .try_into()
                .expect("bucket-aligned slice"),
        ))
    }

    pub(super) fn set(
        &mut self,
        table: &RobinHoodTable,
        slot: u64,
        bucket: Option<&Bucket>,
    ) -> io::Result<()> {
        let (id, start) = self.locate(slot);
        let chunk = self.load(table, id)?;
        let raw: &mut [u8; BUCKET_SIZE] = (&mut chunk.bytes[start..start + BUCKET_SIZE])
            .try_into()
            .expect("bucket-aligned slice");
        match bucket {
            Some(bucket) => bucket.encode(raw),
            None => raw.fill(0),
        }
        chunk.dirty = true;
        Ok(())
    }

    /// Write every dirty chunk below `id` in one batch, then forget every
    /// chunk below `id`.
    pub(super) fn retire_below(
        &mut self,
        table: &RobinHoodTable,
        ring: &mut ququmatz::IoUring,
        id: u64,
    ) -> io::Result<()> {
        let kept = self.chunks.split_off(&id);
        let retired = std::mem::replace(&mut self.chunks, kept);
        let fd = table.uring_fd();
        let mut batch = UringBatch::new(self.chunk_len_u32());
        for (&id, chunk) in retired.iter().filter(|(_, c)| c.dirty) {
            // SAFETY: the chunks stay alive until the batch is drained below.
            let sqe = unsafe {
                ququmatz::Sqe::write_ptr(
                    fd,
                    chunk.bytes.as_ptr(),
                    batch.len,
                    RobinHoodTable::slot_offset(id * self.chunk_slots),
                )
            };
            batch.push(table, ring, sqe)?;
        }
        batch.drain(ring)
    }
}

/// Fixed-length reads or writes pushed onto a ring, submitted when the queue
/// fills and when drained, every completion checked for a full transfer.
struct UringBatch {
    len: u32,
    owed: OwedCompletions,
}

impl UringBatch {
    fn new(len: u32) -> Self {
        Self {
            len,
            owed: OwedCompletions::default(),
        }
    }

    fn push(
        &mut self,
        table: &RobinHoodTable,
        ring: &mut ququmatz::IoUring,
        sqe: ququmatz::Sqe,
    ) -> io::Result<()> {
        loop {
            match ring.push(table.apply_fd_flags(sqe)) {
                Ok(()) => {
                    self.owed.pushed();
                    return Ok(());
                }
                Err(ququmatz::Error::Submit(ququmatz::SubmitError::QueueFull)) => {
                    self.drain(ring)?;
                }
                Err(e) => return Err(uring_err(e)),
            }
        }
    }

    fn drain(&mut self, ring: &mut ququmatz::IoUring) -> io::Result<()> {
        let len = self.len;
        self.owed.drain(ring, |cqe| {
            let res = cqe.raw_result();
            if res < 0 {
                Err(io::Error::from_raw_os_error(-res))
            } else if u32::try_from(res).ok() == Some(len) {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("table chunk transfer of {res} bytes, expected {len}"),
                ))
            }
        })
    }
}
