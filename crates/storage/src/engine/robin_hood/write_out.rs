use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;

use quetzalcoatl::spsc::Consumer;

use crate::background::{BackgroundEvent, FlushOutcome, Inbox};
use crate::engine::ring_budget::RingBudget;

use super::completions::OwedCompletions;
use super::uring_err;

pub(super) enum WriteOutJob {
    /// The files later ranges and syncs apply to.
    Files { table: File, overflow: File },
    /// Bytes `[start, end)` of the table file are written; start sending
    /// them to the disk.
    Range { start: u64, end: u64 },
    /// Flush `epoch` is over: make it durable if asked, then report.
    Finish {
        epoch: u64,
        outcome: FlushOutcome,
        durable: bool,
    },
}

/// Moves written table pages to disk while a flush goes on, so the sync at
/// the end of a flush has little left to wait for.
pub(super) struct WriteOut {
    jobs: Consumer<WriteOutJob>,
    files: Option<(File, File)>,
    write_error: Option<String>,
}

impl WriteOut {
    const MAX_RANGE: u64 = 1 << 30;
    const RING_ENTRIES: u32 = 64;
    const RING_ENTRIES_MIN: u32 = 8;

    pub(super) fn new(jobs: Consumer<WriteOutJob>) -> Self {
        Self {
            jobs,
            files: None,
            write_error: None,
        }
    }

    pub(super) fn run(mut self, inbox: &Inbox<'_>) {
        let mut ring = match RingBudget::new(Self::RING_ENTRIES, Self::RING_ENTRIES_MIN).build() {
            Ok(ring) => ring,
            Err(e) => {
                let _ = inbox.send(BackgroundEvent::Failed(format!("write-out ring: {e}")));
                return;
            }
        };
        while let Some(job) = self.jobs.pop_block() {
            match job {
                WriteOutJob::Files { table, overflow } => self.files = Some((table, overflow)),
                WriteOutJob::Range { start, end } => {
                    if let Err(e) = self.start_writeback(&mut ring, start, end) {
                        self.write_error
                            .get_or_insert_with(|| format!("start writeback: {e}"));
                    }
                }
                WriteOutJob::Finish {
                    epoch,
                    outcome,
                    durable,
                } => {
                    let outcome = self.finish(outcome, durable);
                    if !inbox.send(BackgroundEvent::Settled { epoch, outcome }) {
                        return;
                    }
                }
            }
        }
    }

    fn finish(&mut self, outcome: FlushOutcome, durable: bool) -> FlushOutcome {
        let live = outcome?;
        if let Some(e) = self.write_error.take() {
            return Err(e);
        }
        if durable {
            self.sync()?;
        }
        Ok(live)
    }

    fn start_writeback(
        &self,
        ring: &mut ququmatz::IoUring,
        start: u64,
        end: u64,
    ) -> io::Result<()> {
        let Some((table, _)) = &self.files else {
            return Ok(());
        };
        let fd = ququmatz::types::RawFd::from_raw(
            usize::try_from(table.as_raw_fd()).expect("open fd is non-negative"),
        );
        let mut owed = OwedCompletions::default();
        let mut offset = start;
        while offset < end {
            let len = (end - offset).min(Self::MAX_RANGE);
            let sqe = ququmatz::Sqe::sync_file_range(
                fd,
                offset,
                u32::try_from(len).expect("range piece fits u32"),
                ququmatz::types::SyncFileRangeFlags::WRITE,
            );
            loop {
                match ring.push(sqe) {
                    Ok(()) => break,
                    Err(ququmatz::Error::Submit(ququmatz::SubmitError::QueueFull)) => {
                        owed.drain(ring, Self::check)?;
                    }
                    Err(e) => {
                        let _ = owed.drain(ring, Self::check);
                        return Err(uring_err(e));
                    }
                }
            }
            owed.pushed();
            offset += len;
        }
        owed.drain(ring, Self::check)
    }

    fn check(cqe: &ququmatz::Completion) -> io::Result<()> {
        let res = cqe.raw_result();
        if res < 0 {
            Err(io::Error::from_raw_os_error(-res))
        } else {
            Ok(())
        }
    }

    fn sync(&self) -> Result<(), String> {
        let Some((table, overflow)) = &self.files else {
            return Ok(());
        };
        overflow
            .sync_data()
            .and_then(|()| table.sync_data())
            .map_err(|e| format!("sync table: {e}"))
    }
}
