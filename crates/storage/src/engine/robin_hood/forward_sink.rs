use std::io;

use crate::background::{BackgroundEvent, Extent, Inbox};

use super::chunk_sink::ChunkSink;
use super::table_flusher::{FlusherMsg, FlusherRx};
use super::RobinHoodTable;

/// Sends each step of a flush to the storage thread, which writes it
/// between two lookups and acknowledges it.
///
/// Up to [`MAX_UNACKED`](Self::MAX_UNACKED) steps are in flight: the flush
/// computes the next step while the storage thread writes the last, and no
/// more than one step's bytes wait in memory.
pub(super) struct ForwardSink<'f, 's> {
    inbox: &'f Inbox<'s>,
    acks: &'f mut FlusherRx,
    unacked: usize,
}

impl<'f, 's> ForwardSink<'f, 's> {
    const MAX_UNACKED: usize = 1;

    pub(super) fn new(inbox: &'f Inbox<'s>, acks: &'f mut FlusherRx) -> Self {
        Self {
            inbox,
            acks,
            unacked: 0,
        }
    }

    fn send(&mut self, event: BackgroundEvent) -> io::Result<()> {
        if !self.inbox.send(event) {
            return Err(Self::storage_gone());
        }
        self.unacked += 1;
        Ok(())
    }

    fn await_ack(&mut self) -> io::Result<()> {
        let Some(msg) = self.acks.pop_block() else {
            self.unacked = 0;
            return Err(Self::storage_gone());
        };
        self.unacked -= 1;
        match msg {
            FlusherMsg::Ack(result) => result.map_err(io::Error::other),
            FlusherMsg::Job(_) => Err(io::Error::other("flush job arrived during a flush")),
        }
    }

    /// Wait for every outstanding acknowledgement, even after one fails, so
    /// none is left over for the next flush.
    pub(super) fn settle_all(&mut self) -> io::Result<()> {
        let mut first = Ok(());
        while self.unacked > 0 {
            let result = self.await_ack();
            if first.is_ok() {
                first = result;
            }
        }
        first
    }

    fn storage_gone() -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "storage thread is gone")
    }
}

impl ChunkSink for ForwardSink<'_, '_> {
    fn publish(
        &mut self,
        _table: &RobinHoodTable,
        _ring: &mut ququmatz::IoUring,
        extents: Vec<Extent>,
    ) -> io::Result<()> {
        while self.unacked >= Self::MAX_UNACKED {
            self.await_ack()?;
        }
        self.send(BackgroundEvent::WriteBack(extents))
    }

    fn settle(&mut self, _ring: &mut ququmatz::IoUring) -> io::Result<()> {
        while self.unacked > 0 {
            self.await_ack()?;
        }
        Ok(())
    }

    fn replaced(
        &mut self,
        table: &RobinHoodTable,
        ring: &mut ququmatz::IoUring,
    ) -> io::Result<()> {
        self.settle(ring)?;
        self.send(BackgroundEvent::TableReplaced {
            slot_count: table.slot_count,
        })?;
        self.settle(ring)
    }
}
