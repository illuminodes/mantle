use std::io;

use crate::background::Extent;

use super::chunk_cache::ChunkCache;
use super::chunk_sink::ChunkSink;
use super::{Bucket, OutPoint, RobinHoodTable, BUCKET_SIZE};

enum FlushOp {
    Delete(OutPoint),
    Insert(Bucket),
}

impl FlushOp {
    /// Deletes sort before inserts at the same ideal slot, so a coin spent
    /// and created again in one flush ends up present.
    const fn kind_rank(&self) -> u8 {
        match self {
            Self::Delete(_) => 0,
            Self::Insert(_) => 1,
        }
    }
}

/// Applies one write-buffer flush in a single sweep over the table.
///
/// Operations run in ascending ideal-slot order, in batches of
/// [`READ_AHEAD_OPS`](Self::READ_AHEAD_OPS). Every probe, insert and
/// backshift only moves forward from its ideal slot, so once the sweep
/// passes a chunk it is final. After each batch every chunk it changed goes
/// to the [`ChunkSink`] as one step, so the file only ever holds the table
/// as it was between two batches. Chunks behind the sweep are evicted, which
/// bounds memory however large the table is. A chain that wraps past the
/// last slot reads the first chunks back once their writes have settled.
pub(super) struct FlushPass<'t, S: ChunkSink> {
    table: &'t mut RobinHoodTable,
    ring: &'t mut ququmatz::IoUring,
    sink: &'t mut S,
    cache: ChunkCache,
    read_ahead_ops: usize,
}

impl<'t, S: ChunkSink> FlushPass<'t, S> {
    const READ_AHEAD_OPS: usize = 1 << 15;
    const SPILL_CHUNKS: u64 = 1;

    pub(super) fn new(
        table: &'t mut RobinHoodTable,
        ring: &'t mut ququmatz::IoUring,
        sink: &'t mut S,
    ) -> Self {
        Self::with_read_ahead(table, ring, sink, Self::READ_AHEAD_OPS)
    }

    pub(super) fn with_read_ahead(
        table: &'t mut RobinHoodTable,
        ring: &'t mut ququmatz::IoUring,
        sink: &'t mut S,
        read_ahead_ops: usize,
    ) -> Self {
        let cache = ChunkCache::new(table.slot_count);
        Self {
            table,
            ring,
            sink,
            cache,
            read_ahead_ops: read_ahead_ops.max(1),
        }
    }

    /// # Errors
    /// Returns an error on I/O failure.
    pub(super) fn apply(mut self, deletes: &[OutPoint], inserts: Vec<Bucket>) -> io::Result<()> {
        let mut ops: Vec<(u64, FlushOp)> = deletes
            .iter()
            .map(|op| (self.table.ideal_slot(op), FlushOp::Delete(*op)))
            .chain(inserts.into_iter().map(|bucket| {
                (self.table.ideal_slot(&bucket.outpoint()), FlushOp::Insert(bucket))
            }))
            .collect();
        ops.sort_unstable_by_key(|(ideal, op)| (*ideal, op.kind_rank()));

        let chunk_count = self.cache.chunk_of(self.table.mask) + 1;
        let mut read_up_to = 0;
        for index in 0..ops.len() {
            let ideal = ops[index].0;
            if index == read_up_to {
                let end = (index + self.read_ahead_ops).min(ops.len());
                self.publish_below(self.cache.chunk_of(ideal))?;
                let ids = self.chunks_for(&ops[index..end], chunk_count);
                if ids.iter().any(|&id| self.cache.is_stale(id)) {
                    self.settle()?;
                }
                self.cache.prefetch(self.table, self.ring, ids)?;
                read_up_to = end;
            }
            match &ops[index].1 {
                FlushOp::Delete(op) => self.remove(op)?,
                FlushOp::Insert(bucket) => self.place(bucket.clone())?,
            }
        }
        let mut extents = self.cache.take_changes(u64::MAX);
        extents.push(self.header_extent());
        self.sink.publish(self.table, self.ring, extents)?;
        self.settle()
    }

    fn publish_below(&mut self, id: u64) -> io::Result<()> {
        let extents = self.cache.take_changes(id);
        if extents.is_empty() {
            return Ok(());
        }
        self.sink.publish(self.table, self.ring, extents)
    }

    fn settle(&mut self) -> io::Result<()> {
        self.sink.settle(self.ring)?;
        self.cache.settled();
        Ok(())
    }

    fn header_extent(&self) -> Extent {
        let mut bytes = vec![0u8; BUCKET_SIZE];
        self.table
            .header()
            .encode((&mut bytes[..]).try_into().expect("header-sized buffer"));
        Extent { offset: 0, bytes }
    }

    fn chunks_for(&self, ops: &[(u64, FlushOp)], chunk_count: u64) -> Vec<u64> {
        let mut ids: Vec<u64> = ops
            .iter()
            .map(|(ideal, _)| self.cache.chunk_of(*ideal))
            .flat_map(|id| (0..=Self::SPILL_CHUNKS).map(move |d| (id + d) % chunk_count))
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    fn bucket(&mut self, slot: u64) -> io::Result<Bucket> {
        if self.cache.is_stale(self.cache.chunk_of(slot)) {
            self.settle()?;
        }
        self.cache.bucket(self.table, slot)
    }

    fn set(&mut self, slot: u64, bucket: Option<&Bucket>) -> io::Result<()> {
        if self.cache.is_stale(self.cache.chunk_of(slot)) {
            self.settle()?;
        }
        self.cache.set(self.table, slot, bucket)
    }

    fn remove(&mut self, op: &OutPoint) -> io::Result<()> {
        let ideal = self.table.ideal_slot(op);
        let mut dist: u16 = 1;
        let mut slot = ideal;
        loop {
            let bucket = self.bucket(slot)?;
            if bucket.is_empty() || bucket.probe_distance < dist {
                return Ok(());
            }
            if bucket.matches(op) {
                self.backshift(slot)?;
                self.table.live_count -= 1;
                return Ok(());
            }
            dist += 1;
            slot = (slot + 1) & self.table.mask;
            if slot == ideal {
                return Ok(());
            }
        }
    }

    fn backshift(&mut self, removed: u64) -> io::Result<()> {
        let mut prev = removed;
        let mut slot = (removed + 1) & self.table.mask;
        loop {
            let mut bucket = self.bucket(slot)?;
            if bucket.is_empty() || bucket.probe_distance == 1 {
                return self.set(prev, None);
            }
            bucket.probe_distance -= 1;
            self.set(prev, Some(&bucket))?;
            prev = slot;
            slot = (slot + 1) & self.table.mask;
        }
    }

    fn place(&mut self, mut current: Bucket) -> io::Result<()> {
        current.probe_distance = 1;
        let ideal = self.table.ideal_slot(&current.outpoint());
        let mut slot = ideal;
        loop {
            let existing = self.bucket(slot)?;
            if existing.is_empty() {
                self.set(slot, Some(&current))?;
                self.table.live_count += 1;
                return Ok(());
            }
            if existing.matches(&current.outpoint()) {
                current.probe_distance = existing.probe_distance;
                return self.set(slot, Some(&current));
            }
            if existing.probe_distance < current.probe_distance {
                self.set(slot, Some(&current))?;
                current = existing;
            }
            current.probe_distance += 1;
            slot = (slot + 1) & self.table.mask;
            assert!(
                slot != ideal,
                "FlushPass::place: table full despite load-factor check"
            );
        }
    }
}

#[cfg(test)]
mod tests;
