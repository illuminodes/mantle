use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread::Thread;
use std::time::Duration;

/// The threads of one pool and how they wake each other.
///
/// Workers park when the job ring is empty and the coordinator unparks them
/// after submitting. The coordinator parks while checks are outstanding and
/// each worker unparks it after reporting an outcome. Every park is bounded
/// by [`BACKSTOP`](Self::BACKSTOP), so a missed wake-up delays a thread
/// instead of stranding it.
#[derive(Default)]
pub(super) struct PoolRoster {
    workers: OnceLock<Vec<Thread>>,
    coordinator: Mutex<Option<Thread>>,
    stopping: AtomicBool,
}

impl PoolRoster {
    pub(super) const BACKSTOP: Duration = Duration::from_millis(1);

    pub(super) fn enroll_workers(&self, threads: Vec<Thread>) {
        if self.workers.set(threads).is_ok() {
            self.wake_workers();
        }
    }

    pub(super) fn wake_workers(&self) {
        for thread in self.workers.get().into_iter().flatten() {
            thread.unpark();
        }
    }

    /// Make the calling thread the one workers wake.
    pub(super) fn enroll_coordinator(&self) {
        *self.coordinator_slot() = Some(std::thread::current());
    }

    pub(super) fn wake_coordinator(&self) {
        if let Some(thread) = self.coordinator_slot().as_ref() {
            thread.unpark();
        }
    }

    pub(super) fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        self.wake_workers();
    }

    pub(super) fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    pub(super) fn park() {
        std::thread::park_timeout(Self::BACKSTOP);
    }

    fn coordinator_slot(&self) -> std::sync::MutexGuard<'_, Option<Thread>> {
        self.coordinator
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Instant;

    #[test]
    fn waking_before_enrollment_is_a_no_op() {
        let roster = PoolRoster::default();
        roster.wake_workers();
        roster.wake_coordinator();
    }

    #[test]
    fn stop_releases_a_parked_worker_promptly() {
        let roster = Arc::new(PoolRoster::default());
        let seen = Arc::clone(&roster);
        let worker = std::thread::spawn(move || {
            while !seen.is_stopping() {
                std::thread::park();
            }
        });
        roster.enroll_workers(vec![worker.thread().clone()]);
        let started = Instant::now();
        roster.stop();
        worker.join().expect("worker exits");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn a_worker_can_wake_the_enrolled_coordinator() {
        let roster = Arc::new(PoolRoster::default());
        roster.enroll_coordinator();
        let waker = Arc::clone(&roster);
        let worker = std::thread::spawn(move || waker.wake_coordinator());
        std::thread::park();
        worker.join().expect("worker exits");
    }
}
