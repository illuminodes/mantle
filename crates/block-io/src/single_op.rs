use std::io;

use ququmatz::IoUring;

/// One read or write pushed on a ring and waited for until its own
/// completion arrives. A signal during the wait (`EINTR`) only means the
/// wait ended early, so the wait is repeated; the buffer stays borrowed
/// until the operation has really completed.
pub(crate) struct SingleOp;

impl SingleOp {
    const TAG: u64 = u64::MAX;
    const EINTR: i32 = 4;

    /// Push `sqe`, wait for its completion and return its result.
    pub(crate) fn run(ring: &mut IoUring, sqe: ququmatz::Sqe) -> io::Result<u32> {
        ring.push(sqe.user_data(Self::TAG))
            .map_err(|e| io::Error::other(format!("{e:?}")))?;
        loop {
            if let Err(e) = ring.submit_and_wait(1)
                && !Self::is_interrupted(&e)
            {
                return Err(io::Error::other(format!("{e:?}")));
            }
            while let Some(cqe) = ring.complete() {
                if cqe.user_data() == Self::TAG {
                    let res = cqe.raw_result();
                    return u32::try_from(res)
                        .map_err(|_| io::Error::from_raw_os_error(-res));
                }
            }
        }
    }

    fn is_interrupted(e: &ququmatz::Error) -> bool {
        matches!(
            e,
            ququmatz::Error::Syscall(errno)
                | ququmatz::Error::Submit(ququmatz::SubmitError::Syscall(errno))
                if errno.raw() == Self::EINTR
        )
    }
}

#[cfg(test)]
mod tests {
    use super::SingleOp;

    #[test]
    fn a_nop_completes_with_zero() {
        let mut ring = ququmatz::IoUring::new(4).expect("ring");
        assert_eq!(SingleOp::run(&mut ring, ququmatz::Sqe::nop()).unwrap(), 0);
    }
}
