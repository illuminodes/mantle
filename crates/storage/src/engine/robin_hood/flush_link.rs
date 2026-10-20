use std::io;
use std::sync::Arc;

use mantle::primitives::BlockHeight;
use quetzalcoatl::capacity::Capacity;
use quetzalcoatl::spsc::{Producer, RingBuffer};

use crate::background::{BackgroundTask, Extent, FlushOutcome, Inbox};

use super::table_flusher::{FlushJob, FlusherMsg, TableFlusher};
use super::write_buffer::FrozenBuffer;
use super::write_out::{WriteOut, WriteOutJob};
use super::RobinHoodTable;

/// What a flush must achieve once its writes are in the table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum FlushGoal {
    /// Written, not synced, and no checkpoint.
    Written,
    /// Synced, then the checkpoint moves to this height.
    Checkpoint(BlockHeight),
}

impl FlushGoal {
    const fn durable(self) -> bool {
        matches!(self, Self::Checkpoint(_))
    }
}

struct InFlight {
    epoch: u64,
    goal: FlushGoal,
}

/// The storage thread's end of the background flush: the rings to the flush
/// and write-out threads, and which flush is running.
pub(super) struct FlushLink {
    flusher: Producer<FlusherMsg>,
    write_out: Producer<WriteOutJob>,
    in_flight: Option<InFlight>,
    next_epoch: u64,
    failure: Option<String>,
}

impl FlushLink {
    const FLUSHER_RING: usize = 8;
    const WRITE_OUT_RING: usize = 64;

    /// The link plus the bodies of the two threads it talks to.
    pub(super) fn open(storage_table: &RobinHoodTable) -> io::Result<(Self, Vec<BackgroundTask>)> {
        let flusher_table = storage_table.twin()?;
        let (flusher, flusher_rx) = RingBuffer::new(Capacity::exact(Self::FLUSHER_RING)).split();
        let (write_out, write_out_rx) =
            RingBuffer::new(Capacity::exact(Self::WRITE_OUT_RING)).split();
        let link = Self {
            flusher,
            write_out,
            in_flight: None,
            next_epoch: 1,
            failure: None,
        };
        link.share_files(storage_table)?;
        let flush_task: BackgroundTask = Box::new(move |inbox: Inbox<'_>| {
            TableFlusher::new(flusher_table, flusher_rx).run(&inbox);
        });
        let write_out_task: BackgroundTask = Box::new(move |inbox: Inbox<'_>| {
            WriteOut::new(write_out_rx).run(&inbox);
        });
        Ok((link, vec![flush_task, write_out_task]))
    }

    /// Point the write-out thread at the table's current files.
    pub(super) fn share_files(&self, table: &RobinHoodTable) -> io::Result<()> {
        self.send_write_out(WriteOutJob::Files {
            table: table.file.try_clone()?,
            overflow: table.overflow.try_clone()?,
        })
    }

    pub(super) fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }

    pub(super) fn fail(&mut self, reason: String) {
        self.failure.get_or_insert(reason);
        self.in_flight = None;
    }

    pub(super) fn is_busy(&self) -> bool {
        self.in_flight.is_some()
    }

    pub(super) fn start(&mut self, frozen: Arc<FrozenBuffer>, goal: FlushGoal) -> io::Result<()> {
        let epoch = self.next_epoch;
        self.next_epoch += 1;
        self.in_flight = Some(InFlight { epoch, goal });
        self.flusher
            .push_block(FlusherMsg::Job(FlushJob { epoch, frozen }))
            .map_err(|_| Self::thread_gone("flush"))
    }

    /// A write-back step is in the file, or failed: tell the flush, and
    /// start moving the written range to disk.
    pub(super) fn written(&self, extents: &[Extent], result: io::Result<()>) -> io::Result<()> {
        let span = extents
            .iter()
            .map(|e| (e.offset, e.end()))
            .reduce(|(lo, hi), (start, end)| (lo.min(start), hi.max(end)));
        if let (Ok(()), Some((start, end))) = (&result, span) {
            self.send_write_out(WriteOutJob::Range { start, end })?;
        }
        self.acknowledge(result)
    }

    pub(super) fn acknowledge(&self, result: io::Result<()>) -> io::Result<()> {
        self.flusher
            .push_block(FlusherMsg::Ack(result.map_err(|e| e.to_string())))
            .map_err(|_| Self::thread_gone("flush"))
    }

    /// The flush thread finished `epoch`: have the write-out thread sync it
    /// if its goal asks for that.
    pub(super) fn ended(&self, epoch: u64, outcome: FlushOutcome) -> io::Result<()> {
        let durable = self
            .in_flight
            .as_ref()
            .filter(|f| f.epoch == epoch)
            .is_some_and(|f| f.goal.durable());
        self.send_write_out(WriteOutJob::Finish {
            epoch,
            outcome,
            durable,
        })
    }

    /// `epoch` reached the disk as far as its goal asked: returns the goal.
    pub(super) fn settled(&mut self, epoch: u64) -> Option<FlushGoal> {
        match self.in_flight.take() {
            Some(f) if f.epoch == epoch => Some(f.goal),
            other => {
                self.in_flight = other;
                None
            }
        }
    }

    fn send_write_out(&self, job: WriteOutJob) -> io::Result<()> {
        self.write_out
            .push_block(job)
            .map_err(|_| Self::thread_gone("write-out"))
    }

    fn thread_gone(name: &str) -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, format!("{name} thread is gone"))
    }
}
