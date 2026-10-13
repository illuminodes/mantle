use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

use super::placement_stream::PlacementStream;
use super::{
    hash_outpoint, pread_exact, pwrite_all, Bucket, RobinHoodTable, TableHeader, BUCKET_SIZE,
    BUCKET_SIZE_U64,
};

const CHUNK_SLOTS: usize = 1 << 16;

/// Writes a table with twice the slots of `source` in one sequential pass.
///
/// Buckets of a Robin Hood table sit in ascending ideal-slot order, and after
/// doubling each bucket's ideal slot is either its old ideal `i` or `i + N`,
/// so the lower and upper halves can each be filled by an append-only cursor.
/// Buckets that wrapped past the end of the old table, or would spill across
/// a half boundary, come back from [`TableGrowth::write`] for a regular insert.
pub(super) struct TableGrowth<'t> {
    source: &'t RobinHoodTable,
    old_mask: u64,
    new_mask: u64,
    low: PlacementStream,
    high: PlacementStream,
    deferred: Vec<Bucket>,
}

impl<'t> TableGrowth<'t> {
    pub(super) fn new(source: &'t RobinHoodTable) -> Self {
        let old_count = source.slot_count;
        let window = CHUNK_SLOTS.min(usize::try_from(old_count).unwrap_or(CHUNK_SLOTS));
        Self {
            source,
            old_mask: old_count - 1,
            new_mask: old_count * 2 - 1,
            low: PlacementStream::new(0, old_count, window),
            high: PlacementStream::new(old_count, old_count * 2, window),
            deferred: Vec::new(),
        }
    }

    pub(super) fn write(mut self, target: &Path) -> io::Result<Vec<Bucket>> {
        let new_count = self.new_mask + 1;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(target)?;
        file.set_len((new_count + 1) * BUCKET_SIZE_U64)?;

        self.copy_buckets(&file)?;
        self.low.finish(&file)?;
        self.high.finish(&file)?;

        let deferred = u64::try_from(self.deferred.len()).expect("deferred count fits u64");
        let header = TableHeader {
            slot_count: new_count,
            live_count: self.source.live_count - deferred,
        };
        let mut buf = [0u8; BUCKET_SIZE];
        header.encode(&mut buf);
        pwrite_all(&file, &buf, 0)?;
        Ok(self.deferred)
    }

    fn copy_buckets(&mut self, target: &File) -> io::Result<()> {
        let old_count = self.old_mask + 1;
        let chunk_slots = u64::try_from(CHUNK_SLOTS).expect("chunk fits u64");
        let mut chunk = vec![0u8; CHUNK_SLOTS * BUCKET_SIZE];
        let mut start = 0;
        while start < old_count {
            let slots = chunk_slots.min(old_count - start);
            let bytes = usize::try_from(slots).expect("chunk fits usize") * BUCKET_SIZE;
            pread_exact(
                &self.source.file,
                &mut chunk[..bytes],
                RobinHoodTable::slot_offset(start),
            )?;
            for (offset, raw) in (0..slots).zip(chunk[..bytes].chunks_exact(BUCKET_SIZE)) {
                let bucket = Bucket::decode(raw.try_into().expect("bucket-aligned slice"));
                if !bucket.is_empty() {
                    self.route(target, start + offset, bucket)?;
                }
            }
            start += slots;
        }
        Ok(())
    }

    fn route(&mut self, target: &File, old_slot: u64, bucket: Bucket) -> io::Result<()> {
        let hash = hash_outpoint(&bucket.outpoint());
        if hash & self.old_mask > old_slot {
            self.deferred.push(bucket);
            return Ok(());
        }
        let ideal = hash & self.new_mask;
        let stream = if ideal <= self.old_mask {
            &mut self.low
        } else {
            &mut self.high
        };
        if let Some(rejected) = stream.place(target, ideal, bucket)? {
            self.deferred.push(rejected);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
