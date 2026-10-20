use std::collections::BTreeMap;
use std::io;

use crate::background::Extent;

use super::uring_batch::UringBatch;
use super::{pread_exact, Bucket, RobinHoodTable, BUCKET_SIZE};

pub(super) const CHUNK_SLOTS: u64 = 64;

struct Chunk {
    bytes: Vec<u8>,
    dirty: bool,
}

/// Contiguous runs of table slots held in memory while a flush rewrites them.
///
/// Chunks named up front are read in one `io_uring` batch; a slot outside
/// them is read with one `pread` of its chunk. Changed chunks leave as
/// [`Extent`]s for the caller to write. A chunk evicted since the caller
/// last confirmed its writes landed is stale, because reading it back from
/// the file before then could see the old bytes. Eviction only moves
/// forward, so the stale chunks are one range of ids.
pub(super) struct ChunkCache {
    chunk_slots: u64,
    chunks: BTreeMap<u64, Chunk>,
    evicted_below: u64,
    settled_below: u64,
}

impl ChunkCache {
    pub(super) fn new(slot_count: u64) -> Self {
        Self {
            chunk_slots: CHUNK_SLOTS.min(slot_count),
            chunks: BTreeMap::new(),
            evicted_below: 0,
            settled_below: 0,
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

    fn offset_of(&self, id: u64) -> u64 {
        RobinHoodTable::slot_offset(id * self.chunk_slots)
    }

    /// Whether reading chunk `id` from the file now could miss a write
    /// still on its way.
    pub(super) fn is_stale(&self, id: u64) -> bool {
        !self.chunks.contains_key(&id) && (self.settled_below..self.evicted_below).contains(&id)
    }

    /// The caller has confirmed that every extent handed out so far is in
    /// the file.
    pub(super) fn settled(&mut self) {
        self.settled_below = self.evicted_below;
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
        let chunk_slots = self.chunk_slots;
        let mut batch = UringBatch::new();
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
                    RobinHoodTable::slot_offset(id * chunk_slots),
                )
            };
            batch.push(table, ring, sqe, len)?;
        }
        batch.drain(ring)
    }

    fn load(&mut self, table: &RobinHoodTable, id: u64) -> io::Result<&mut Chunk> {
        debug_assert!(!self.is_stale(id), "chunk {id} read before its write settled");
        if !self.chunks.contains_key(&id) {
            let mut bytes = vec![0; self.chunk_bytes()];
            pread_exact(&table.file, &mut bytes, self.offset_of(id))?;
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

    /// Hand out every changed chunk: chunks below `id` are evicted and
    /// leave without a copy, the rest are copied and stay held.
    pub(super) fn take_changes(&mut self, id: u64) -> Vec<Extent> {
        let kept = self.chunks.split_off(&id);
        let evicted = std::mem::replace(&mut self.chunks, kept);
        if let Some((&last, _)) = evicted.last_key_value() {
            self.evicted_below = self.evicted_below.max(last + 1);
        }
        let mut extents: Vec<Extent> = evicted
            .into_iter()
            .filter(|(_, chunk)| chunk.dirty)
            .map(|(id, chunk)| Extent {
                offset: self.offset_of(id),
                bytes: chunk.bytes,
            })
            .collect();
        for (&id, chunk) in self.chunks.iter_mut().filter(|(_, c)| c.dirty) {
            chunk.dirty = false;
            extents.push(Extent {
                offset: RobinHoodTable::slot_offset(id * self.chunk_slots),
                bytes: chunk.bytes.clone(),
            });
        }
        extents
    }
}
