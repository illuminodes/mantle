use std::io;
use std::time::Duration;

use crate::engine::EngineError;

/// Builds an `io_uring` whose queue depth fits the process's locked-memory
/// budget (`RLIMIT_MEMLOCK`).
///
/// The kernel charges each ring's SQ/CQ/SQE mappings against a per-user
/// locked-memory pool, and releases that charge asynchronously after the ring
/// fd is closed. A ring of `n` entries costs roughly `n * 84` bytes, so on a
/// host with the common 8 MiB limit only a handful of deep rings can exist at
/// once — and a ring dropped microseconds ago may still be counted.
///
/// Queue depth is a throughput tuning knob rather than a correctness
/// requirement: submission paths drain and retry when the queue fills. So on
/// `ENOMEM` this retries once to let a recently freed ring settle, then halves
/// the depth and tries again, down to `floor`.
pub struct RingBudget {
    requested: u32,
    floor: u32,
}

impl RingBudget {
    const RECLAIM_DELAY: Duration = Duration::from_millis(50);

    #[must_use]
    pub const fn new(requested: u32, floor: u32) -> Self {
        Self { requested, floor }
    }

    #[must_use]
    pub const fn requested(&self) -> u32 {
        self.requested
    }

    #[must_use]
    pub const fn floor(&self) -> u32 {
        self.floor
    }

    /// The depths this budget will attempt, deepest first.
    pub fn candidates(&self) -> impl Iterator<Item = u32> + '_ {
        let floor = self.floor.max(1);
        std::iter::successors(Some(self.requested.max(floor)), move |&d| {
            (d > floor).then(|| (d / 2).max(floor))
        })
    }

    fn to_engine_error(err: &ququmatz::Error) -> EngineError {
        EngineError::Io(io::Error::other(format!("{err:?}")))
    }

    const ENOMEM: i32 = 12;

    fn is_out_of_memory(err: &ququmatz::Error) -> bool {
        matches!(
            err,
            ququmatz::Error::Setup(ququmatz::SetupError::Syscall(e))
                | ququmatz::Error::Syscall(e)
            if e.raw() == Self::ENOMEM
        )
    }

    /// Build the deepest ring that the locked-memory budget allows.
    ///
    /// # Errors
    ///
    /// Returns the underlying setup error if a ring cannot be created even at
    /// `floor` depth, or if setup fails for any reason other than `ENOMEM`.
    pub fn build(&self) -> Result<ququmatz::IoUring, EngineError> {
        let mut last = None;

        for depth in self.candidates() {
            match ququmatz::IoUringBuilder::new(depth).build() {
                Ok(ring) => return Ok(ring),
                Err(e) if Self::is_out_of_memory(&e) => {
                    std::thread::sleep(Self::RECLAIM_DELAY);
                    match ququmatz::IoUringBuilder::new(depth).build() {
                        Ok(ring) => return Ok(ring),
                        Err(retry) => last = Some(retry),
                    }
                }
                Err(e) => return Err(Self::to_engine_error(&e)),
            }
        }

        Err(last.as_ref().map_or_else(
            || EngineError::Io(io::Error::other("io_uring setup produced no candidates")),
            Self::to_engine_error,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::RingBudget;

    #[test]
    fn candidates_halve_down_to_floor() {
        let budget = RingBudget::new(32768, 4096);
        let got: Vec<u32> = budget.candidates().collect();
        assert_eq!(got, vec![32768, 16384, 8192, 4096]);
    }

    #[test]
    fn candidates_stop_at_floor_when_not_power_of_two() {
        let budget = RingBudget::new(1000, 300);
        let got: Vec<u32> = budget.candidates().collect();
        assert_eq!(got, vec![1000, 500, 300]);
    }

    #[test]
    fn candidates_single_entry_when_requested_below_floor() {
        let budget = RingBudget::new(64, 256);
        let got: Vec<u32> = budget.candidates().collect();
        assert_eq!(got, vec![256]);
    }

    #[test]
    fn candidates_never_empty() {
        let budget = RingBudget::new(1, 1);
        assert_eq!(budget.candidates().next(), Some(1));
    }

    #[test]
    fn accessors_report_configuration() {
        let budget = RingBudget::new(32768, 256);
        assert_eq!(budget.requested(), 32768);
        assert_eq!(budget.floor(), 256);
    }

    #[test]
    fn does_not_classify_other_errors_as_out_of_memory() {
        let full = ququmatz::Error::Submit(ququmatz::SubmitError::QueueFull);
        assert!(!RingBudget::is_out_of_memory(&full));

        let no_completion =
            ququmatz::Error::Cqe(ququmatz::CompletionError::NoCompletion);
        assert!(!RingBudget::is_out_of_memory(&no_completion));
    }

    #[test]
    fn builds_a_usable_ring_under_current_limits() {
        let ring = RingBudget::new(32768, 256)
            .build()
            .expect("a ring should be obtainable at some depth");
        drop(ring);
    }

    #[test]
    fn builds_many_rings_concurrently_by_degrading_depth() {
        let budget = RingBudget::new(4096, 64);
        let rings: Vec<_> = (0..6)
            .map(|i| {
                budget
                    .build()
                    .unwrap_or_else(|e| panic!("ring {i} failed to build: {e}"))
            })
            .collect();
        assert_eq!(rings.len(), 6);
    }
}
