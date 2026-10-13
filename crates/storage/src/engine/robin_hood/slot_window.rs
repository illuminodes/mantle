use std::fs::File;
use std::io;

use super::{pwrite_all, Bucket, RobinHoodTable, BUCKET_SIZE};

pub(super) struct SlotWindow {
    base: u64,
    used_slots: usize,
    bytes: Vec<u8>,
}

impl SlotWindow {
    pub(super) fn new(slots: usize) -> Self {
        Self {
            base: 0,
            used_slots: 0,
            bytes: vec![0; slots * BUCKET_SIZE],
        }
    }

    fn capacity(&self) -> u64 {
        u64::try_from(self.bytes.len() / BUCKET_SIZE).expect("window fits u64")
    }

    pub(super) fn put(&mut self, file: &File, slot: u64, bucket: &Bucket) -> io::Result<()> {
        if slot < self.base || slot >= self.base + self.capacity() {
            self.flush(file)?;
            self.base = slot;
        }
        let index = usize::try_from(slot - self.base).expect("window index fits usize");
        let start = index * BUCKET_SIZE;
        bucket.encode(
            (&mut self.bytes[start..start + BUCKET_SIZE])
                .try_into()
                .expect("bucket-aligned slice"),
        );
        self.used_slots = self.used_slots.max(index + 1);
        Ok(())
    }

    pub(super) fn flush(&mut self, file: &File) -> io::Result<()> {
        if self.used_slots == 0 {
            return Ok(());
        }
        let used = self.used_slots * BUCKET_SIZE;
        pwrite_all(file, &self.bytes[..used], RobinHoodTable::slot_offset(self.base))?;
        self.bytes[..used].fill(0);
        self.used_slots = 0;
        Ok(())
    }
}
