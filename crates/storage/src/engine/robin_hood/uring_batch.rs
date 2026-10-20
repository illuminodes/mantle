use std::io;

use super::completions::OwedCompletions;
use super::{uring_err, RobinHoodTable};

/// Reads or writes pushed onto a ring, submitted when the queue fills and
/// when drained. Each completion is checked against the length its entry
/// was pushed with.
pub(super) struct UringBatch {
    lengths: Vec<u32>,
    owed: OwedCompletions,
}

impl UringBatch {
    pub(super) fn new() -> Self {
        Self {
            lengths: Vec::new(),
            owed: OwedCompletions::default(),
        }
    }

    /// On any error other than a full queue, every entry already pushed is
    /// reaped before returning, so no transfer outlives its buffer.
    pub(super) fn push(
        &mut self,
        table: &RobinHoodTable,
        ring: &mut ququmatz::IoUring,
        sqe: ququmatz::Sqe,
        len: u32,
    ) -> io::Result<()> {
        let tag = u64::try_from(self.lengths.len()).expect("batch index fits u64");
        self.lengths.push(len);
        let sqe = table.apply_fd_flags(sqe).user_data(tag);
        loop {
            match ring.push(sqe) {
                Ok(()) => {
                    self.owed.pushed();
                    return Ok(());
                }
                Err(ququmatz::Error::Submit(ququmatz::SubmitError::QueueFull)) => {
                    self.drain(ring)?;
                }
                Err(e) => {
                    let _ = self.drain(ring);
                    return Err(uring_err(e));
                }
            }
        }
    }

    pub(super) fn drain(&mut self, ring: &mut ququmatz::IoUring) -> io::Result<()> {
        let lengths = &self.lengths;
        self.owed.drain(ring, |cqe| {
            let res = cqe.raw_result();
            let expected = usize::try_from(cqe.user_data())
                .ok()
                .and_then(|i| lengths.get(i))
                .copied();
            if res < 0 {
                Err(io::Error::from_raw_os_error(-res))
            } else if u32::try_from(res).ok() == expected {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("table transfer of {res} bytes, expected {expected:?}"),
                ))
            }
        })
    }
}
