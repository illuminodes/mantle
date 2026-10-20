use std::io;

use crate::background::Extent;

use super::extent_writer::ExtentWriter;
use super::RobinHoodTable;

/// Where a flush sends the table bytes it has finished with.
///
/// Every [`publish`](Self::publish) is one consistent step: once it lands,
/// the file holds a valid table. [`settle`](Self::settle) returns once every
/// published step is in the file, so the flush can read it back.
/// [`replaced`](Self::replaced) reports that growth swapped in a new file.
pub(super) trait ChunkSink {
    fn publish(
        &mut self,
        table: &RobinHoodTable,
        ring: &mut ququmatz::IoUring,
        extents: Vec<Extent>,
    ) -> io::Result<()>;

    fn settle(&mut self, ring: &mut ququmatz::IoUring) -> io::Result<()>;

    fn replaced(&mut self, table: &RobinHoodTable, ring: &mut ququmatz::IoUring)
        -> io::Result<()>;
}

/// Writes each step to the table file before returning.
pub(super) struct DirectSink;

impl ChunkSink for DirectSink {
    fn publish(
        &mut self,
        table: &RobinHoodTable,
        ring: &mut ququmatz::IoUring,
        extents: Vec<Extent>,
    ) -> io::Result<()> {
        ExtentWriter::write(table, ring, &extents)
    }

    fn settle(&mut self, _ring: &mut ququmatz::IoUring) -> io::Result<()> {
        Ok(())
    }

    fn replaced(
        &mut self,
        _table: &RobinHoodTable,
        _ring: &mut ququmatz::IoUring,
    ) -> io::Result<()> {
        Ok(())
    }
}
