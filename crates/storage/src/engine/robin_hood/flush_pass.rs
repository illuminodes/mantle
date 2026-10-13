use std::io;

use super::chunk_cache::ChunkCache;
use super::{Bucket, OutPoint, RobinHoodTable};

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
/// Operations run in ascending ideal-slot order. Every probe, insert and
/// backshift only moves forward from its ideal slot, so once the sweep
/// passes a chunk it is final and can be written back. Chunks are read ahead
/// in batches and retired behind the sweep, which bounds memory to about
/// [`READ_AHEAD_OPS`](Self::READ_AHEAD_OPS) chunks however large the table
/// is. A chain that wraps past the last slot reloads the first chunks from
/// disk after they were written back.
pub(super) struct FlushPass<'t> {
    table: &'t mut RobinHoodTable,
    cache: ChunkCache,
    read_ahead_ops: usize,
}

impl<'t> FlushPass<'t> {
    const READ_AHEAD_OPS: usize = 1 << 16;
    const SPILL_CHUNKS: u64 = 1;

    pub(super) fn new(table: &'t mut RobinHoodTable) -> Self {
        Self::with_read_ahead(table, Self::READ_AHEAD_OPS)
    }

    pub(super) fn with_read_ahead(table: &'t mut RobinHoodTable, read_ahead_ops: usize) -> Self {
        let cache = ChunkCache::new(table.slot_count);
        Self {
            table,
            cache,
            read_ahead_ops: read_ahead_ops.max(1),
        }
    }

    /// # Errors
    /// Returns an error on I/O failure.
    pub(super) fn apply(
        mut self,
        ring: &mut ququmatz::IoUring,
        deletes: &[OutPoint],
        inserts: Vec<Bucket>,
    ) -> io::Result<()> {
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
                self.cache.retire_below(self.table, ring, self.cache.chunk_of(ideal))?;
                let ids = self.chunks_for(&ops[index..end], chunk_count);
                self.cache.prefetch(self.table, ring, ids)?;
                read_up_to = end;
            }
            match &ops[index].1 {
                FlushOp::Delete(op) => self.remove(op)?,
                FlushOp::Insert(bucket) => self.place(bucket.clone())?,
            }
        }
        self.cache.retire_below(self.table, ring, u64::MAX)
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

    fn remove(&mut self, op: &OutPoint) -> io::Result<()> {
        let ideal = self.table.ideal_slot(op);
        let mut dist: u16 = 1;
        let mut slot = ideal;
        loop {
            let bucket = self.cache.bucket(self.table, slot)?;
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
            let mut bucket = self.cache.bucket(self.table, slot)?;
            if bucket.is_empty() || bucket.probe_distance == 1 {
                return self.cache.set(self.table, prev, None);
            }
            bucket.probe_distance -= 1;
            self.cache.set(self.table, prev, Some(&bucket))?;
            prev = slot;
            slot = (slot + 1) & self.table.mask;
        }
    }

    fn place(&mut self, mut current: Bucket) -> io::Result<()> {
        current.probe_distance = 1;
        let ideal = self.table.ideal_slot(&current.outpoint());
        let mut slot = ideal;
        loop {
            let existing = self.cache.bucket(self.table, slot)?;
            if existing.is_empty() {
                self.cache.set(self.table, slot, Some(&current))?;
                self.table.live_count += 1;
                return Ok(());
            }
            if existing.matches(&current.outpoint()) {
                current.probe_distance = existing.probe_distance;
                return self.cache.set(self.table, slot, Some(&current));
            }
            if existing.probe_distance < current.probe_distance {
                self.cache.set(self.table, slot, Some(&current))?;
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
