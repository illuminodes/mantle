use std::fs::File;
use std::io;

use super::slot_window::SlotWindow;
use super::Bucket;

/// Places buckets arriving in ascending ideal-slot order into `[start, limit)`.
/// A bucket that would land at or past `limit`, or arrives out of order, is
/// handed back for a regular insert.
pub(super) struct PlacementStream {
    cursor: u64,
    limit: u64,
    last_ideal: u64,
    window: SlotWindow,
}

impl PlacementStream {
    pub(super) fn new(start: u64, limit: u64, window_slots: usize) -> Self {
        Self {
            cursor: start,
            limit,
            last_ideal: start,
            window: SlotWindow::new(window_slots),
        }
    }

    pub(super) fn place(
        &mut self,
        file: &File,
        ideal: u64,
        mut bucket: Bucket,
    ) -> io::Result<Option<Bucket>> {
        if ideal < self.last_ideal {
            return Ok(Some(bucket));
        }
        let slot = self.cursor.max(ideal);
        if slot >= self.limit {
            return Ok(Some(bucket));
        }
        let Ok(distance) = u16::try_from(slot - ideal + 1) else {
            return Ok(Some(bucket));
        };
        bucket.probe_distance = distance;
        self.window.put(file, slot, &bucket)?;
        self.cursor = slot + 1;
        self.last_ideal = ideal;
        Ok(None)
    }

    pub(super) fn finish(&mut self, file: &File) -> io::Result<()> {
        self.window.flush(file)
    }
}
