use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Total time the pool's threads spent running script checks, as opposed
/// to waiting for them. Read it before and after a stretch of work to get
/// how busy the workers really were; CPU time also counts the spinning a
/// thread does before it parks on an empty ring.
#[derive(Default)]
pub(super) struct BusyClock {
    nanos: AtomicU64,
}

impl BusyClock {
    pub(super) fn add(&self, spent: Duration) {
        let nanos = u64::try_from(spent.as_nanos()).unwrap_or(u64::MAX);
        self.nanos.fetch_add(nanos, Ordering::Relaxed);
    }

    pub(super) fn total(&self) -> Duration {
        Duration::from_nanos(self.nanos.load(Ordering::Relaxed))
    }
}
