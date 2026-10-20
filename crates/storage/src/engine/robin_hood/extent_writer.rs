use std::io;

use crate::background::Extent;

use super::uring_batch::UringBatch;
use super::RobinHoodTable;

/// Writes extents into a table file through a ring, returning once every
/// write has completed.
pub(super) struct ExtentWriter;

impl ExtentWriter {
    pub(super) fn write(
        table: &RobinHoodTable,
        ring: &mut ququmatz::IoUring,
        extents: &[Extent],
    ) -> io::Result<()> {
        let fd = table.uring_fd();
        let mut batch = UringBatch::new();
        for extent in extents {
            for (offset, piece) in Self::pieces(extent) {
                let len = u32::try_from(piece.len()).expect("piece fits u32");
                // SAFETY: `extents` outlives the batch, which is drained below.
                let sqe = unsafe { ququmatz::Sqe::write_ptr(fd, piece.as_ptr(), len, offset) };
                batch.push(table, ring, sqe, len)?;
            }
        }
        batch.drain(ring)
    }

    const MAX_PIECE: usize = 1 << 30;

    fn pieces(extent: &Extent) -> impl Iterator<Item = (u64, &[u8])> {
        extent
            .bytes
            .chunks(Self::MAX_PIECE)
            .scan(extent.offset, |offset, piece| {
                let at = *offset;
                *offset += u64::try_from(piece.len()).expect("piece fits u64");
                Some((at, piece))
            })
    }
}
