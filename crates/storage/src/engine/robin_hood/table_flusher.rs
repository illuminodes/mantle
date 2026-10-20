use std::io;
use std::sync::Arc;

use quetzalcoatl::spsc::Consumer;

use crate::background::{BackgroundEvent, Inbox};
use crate::engine::ring_budget::RingBudget;

use super::forward_sink::ForwardSink;
use super::write_buffer::FrozenBuffer;
use super::RobinHoodTable;

pub(super) struct FlushJob {
    pub(super) epoch: u64,
    pub(super) frozen: Arc<FrozenBuffer>,
}

pub(super) enum FlusherMsg {
    Job(FlushJob),
    /// The storage thread wrote the oldest unacknowledged step, or failed to.
    Ack(Result<(), String>),
}

pub(super) type FlusherRx = Consumer<FlusherMsg>;

/// Applies frozen write buffers to the table on its own thread and ring.
///
/// It reads the table file directly, and only the storage thread writes it:
/// every changed chunk goes to the storage thread as a write-back request
/// through a [`ForwardSink`].
pub(super) struct TableFlusher {
    table: RobinHoodTable,
    msgs: FlusherRx,
}

impl TableFlusher {
    const RING_ENTRIES: u32 = 4096;
    const RING_ENTRIES_MIN: u32 = 64;

    pub(super) fn new(table: RobinHoodTable, msgs: FlusherRx) -> Self {
        Self { table, msgs }
    }

    pub(super) fn run(mut self, inbox: &Inbox<'_>) {
        let mut ring = match RingBudget::new(Self::RING_ENTRIES, Self::RING_ENTRIES_MIN).build() {
            Ok(ring) => ring,
            Err(e) => {
                let _ = inbox.send(BackgroundEvent::Failed(format!("flush ring: {e}")));
                return;
            }
        };
        while let Some(msg) = self.msgs.pop_block() {
            let FlusherMsg::Job(job) = msg else {
                let _ = inbox
                    .send(BackgroundEvent::Failed("write-back ack with no flush running".into()));
                return;
            };
            let outcome = self
                .apply(&mut ring, inbox, &job)
                .map(|()| self.table.live_count)
                .map_err(|e| e.to_string());
            drop(job.frozen);
            if !inbox.send(BackgroundEvent::FlushEnded {
                epoch: job.epoch,
                outcome,
            }) {
                return;
            }
        }
    }

    fn apply(
        &mut self,
        ring: &mut ququmatz::IoUring,
        inbox: &Inbox<'_>,
        job: &FlushJob,
    ) -> io::Result<()> {
        let deletes = job.frozen.deletes();
        let mut sink = ForwardSink::new(inbox, &mut self.msgs);
        let applied = self
            .table
            .apply_flush(ring, &mut sink, &deletes, job.frozen.inserts());
        let settled = sink.settle_all();
        applied.and(settled)
    }
}
