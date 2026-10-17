use std::io;

/// Completions owed by a ring for entries pushed since the last drain.
///
/// `io_uring_enter` may return before `min_complete` completions arrive:
/// a signal during the wait returns early with only the submit count, or
/// with `EINTR` when nothing was submitted. [`drain`](Self::drain) keeps
/// waiting until every owed completion has been reaped, so no read or
/// write is still running when the caller reuses its buffer.
#[derive(Default)]
pub(super) struct OwedCompletions {
    owed: u32,
}

impl OwedCompletions {
    const EINTR: i32 = 4;

    pub(super) fn pushed(&mut self) {
        self.owed += 1;
    }

    pub(super) fn owed(&self) -> u32 {
        self.owed
    }

    /// Wait for and reap every owed completion, handing each to `on_cqe`.
    /// Every completion is reaped even after `on_cqe` fails; the first
    /// failure is returned at the end.
    pub(super) fn drain(
        &mut self,
        ring: &mut ququmatz::IoUring,
        mut on_cqe: impl FnMut(&ququmatz::Completion) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut first_error = None;
        while self.owed > 0 {
            if let Err(e) = ring.submit_and_wait(self.owed)
                && !Self::is_interrupted(&e)
            {
                return Err(io::Error::other(format!("{e:?}")));
            }
            while let Some(cqe) = ring.complete() {
                self.owed = self.owed.saturating_sub(1);
                if let Err(e) = on_cqe(&cqe)
                    && first_error.is_none()
                {
                    first_error = Some(e);
                }
            }
        }
        ring.sync_cq();
        first_error.map_or(Ok(()), Err)
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
    use super::OwedCompletions;
    use std::time::{Duration, Instant};

    /// Delivers SIGUSR1 to one thread after a delay, with a no-op handler
    /// installed without `SA_RESTART`, so a blocking syscall on that thread
    /// returns `EINTR`.
    struct Interrupter;

    impl Interrupter {
        extern "C" fn ignore(_: libc::c_int) {}

        fn install() {
            // SAFETY: the handler is async-signal-safe (it does nothing) and
            // `sigaction` is given a zeroed, then filled, struct.
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = Self::ignore as *const () as usize;
                libc::sigemptyset(&raw mut action.sa_mask);
                action.sa_flags = 0;
                libc::sigaction(libc::SIGUSR1, &raw const action, std::ptr::null_mut());
            }
        }

        fn after(delay: Duration) -> std::thread::JoinHandle<()> {
            // SAFETY: `pthread_self` has no preconditions.
            let target = unsafe { libc::pthread_self() };
            std::thread::spawn(move || {
                std::thread::sleep(delay);
                // SAFETY: `target` is the test thread, alive until it joins us.
                unsafe { libc::pthread_kill(target, libc::SIGUSR1) };
            })
        }
    }

    #[test]
    fn a_signal_during_the_wait_does_not_end_it_early() {
        Interrupter::install();
        let mut ring = ququmatz::IoUring::new(8).expect("ring");
        let ts = ququmatz::types::Timespec::from_millis(300);
        // SAFETY: `ts` outlives the drain below, which waits for the timeout.
        let sqe = unsafe {
            ququmatz::Sqe::timeout(&ts, 0, ququmatz::types::TimeoutFlags::default())
        };
        ring.push(sqe.user_data(1)).expect("push");
        let mut owed = OwedCompletions::default();
        owed.pushed();
        let signaller = Interrupter::after(Duration::from_millis(50));
        let started = Instant::now();
        let mut seen = 0;
        owed.drain(&mut ring, |_| {
            seen += 1;
            Ok(())
        })
        .expect("drain");
        signaller.join().unwrap();
        assert_eq!(seen, 1);
        assert!(started.elapsed() >= Duration::from_millis(250), "{:?}", started.elapsed());
    }

    #[test]
    fn nothing_owed_drains_without_waiting() {
        let mut ring = ququmatz::IoUring::new(8).expect("ring");
        let mut owed = OwedCompletions::default();
        let mut seen = 0;
        owed.drain(&mut ring, |_| {
            seen += 1;
            Ok(())
        })
        .expect("drain");
        assert_eq!(seen, 0);
    }

    #[test]
    fn every_pushed_nop_is_reaped() {
        let mut ring = ququmatz::IoUring::new(64).expect("ring");
        let mut owed = OwedCompletions::default();
        for i in 0..40u64 {
            ring.push(ququmatz::Sqe::nop().user_data(i)).expect("push");
            owed.pushed();
        }
        let mut seen = Vec::new();
        owed.drain(&mut ring, |cqe| {
            seen.push(cqe.user_data());
            Ok(())
        })
        .expect("drain");
        seen.sort_unstable();
        assert_eq!(seen, (0..40).collect::<Vec<_>>());
        assert_eq!(owed.owed(), 0);
    }

    #[test]
    fn a_failing_handler_still_reaps_everything() {
        let mut ring = ququmatz::IoUring::new(16).expect("ring");
        let mut owed = OwedCompletions::default();
        for i in 0..5u64 {
            ring.push(ququmatz::Sqe::nop().user_data(i)).expect("push");
            owed.pushed();
        }
        let mut seen = 0;
        let result = owed.drain(&mut ring, |_| {
            seen += 1;
            Err(std::io::Error::other("boom"))
        });
        assert!(result.is_err());
        assert_eq!(seen, 5);
        assert_eq!(owed.owed(), 0);
    }
}
