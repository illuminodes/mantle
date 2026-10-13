use std::any::Any;

use mantle_consensus::error::ValidationError;
use mantle_consensus::script::ScriptError;

/// An input's place in its block, ordered the way Bitcoin Core reports the
/// first failing input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct InputPosition {
    pub(super) tx_index: usize,
    pub(super) input_index: usize,
}

#[derive(Debug)]
pub(super) struct ScriptFailure {
    position: InputPosition,
    kind: ScriptError,
}

impl ScriptFailure {
    pub(super) fn new(position: InputPosition, kind: ScriptError) -> Self {
        Self { position, kind }
    }

    fn into_error(self) -> ValidationError {
        ValidationError::ScriptVerifyFailed {
            tx_index: self.position.tx_index,
            input_index: self.position.input_index,
            kind: self.kind,
        }
    }
}

/// What one input check produced.
pub(super) enum JobOutcome {
    Passed,
    Failed(ScriptFailure),
    Panicked(Box<dyn Any + Send>),
}

/// The combined outcome of every input check in one block.
///
/// Checks finish in any order, so the failure kept is the one at the lowest
/// position, which is the one a single-threaded run would have reported.
#[derive(Default)]
pub(super) struct BlockVerdict {
    failure: Option<ScriptFailure>,
    panic: Option<Box<dyn Any + Send>>,
}

impl BlockVerdict {
    pub(super) fn record(&mut self, outcome: JobOutcome) {
        match outcome {
            JobOutcome::Passed => {}
            JobOutcome::Failed(failure) => {
                if self
                    .failure
                    .as_ref()
                    .is_none_or(|kept| failure.position < kept.position)
                {
                    self.failure = Some(failure);
                }
            }
            JobOutcome::Panicked(payload) => {
                self.panic.get_or_insert(payload);
            }
        }
    }

    /// Re-raise a worker panic on the calling thread.
    pub(super) fn resume_panic(&mut self) {
        if let Some(payload) = self.panic.take() {
            std::panic::resume_unwind(payload);
        }
    }

    /// The block's script verdict, clearing it.
    pub(super) fn take(&mut self) -> Result<(), ValidationError> {
        self.resume_panic();
        self.failure.take().map_or(Ok(()), |f| Err(f.into_error()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure(tx_index: usize, input_index: usize) -> JobOutcome {
        JobOutcome::Failed(ScriptFailure::new(
            InputPosition {
                tx_index,
                input_index,
            },
            ScriptError::EvalFalse,
        ))
    }

    #[test]
    fn the_lowest_failing_input_wins_whatever_order_failures_arrive_in() {
        let mut verdict = BlockVerdict::default();
        verdict.record(failure(5, 0));
        verdict.record(JobOutcome::Passed);
        verdict.record(failure(2, 3));
        verdict.record(failure(2, 7));
        assert_eq!(
            verdict.take(),
            Err(ValidationError::ScriptVerifyFailed {
                tx_index: 2,
                input_index: 3,
                kind: ScriptError::EvalFalse,
            })
        );
    }

    #[test]
    fn taking_the_verdict_clears_it() {
        let mut verdict = BlockVerdict::default();
        verdict.record(failure(1, 0));
        assert!(verdict.take().is_err());
        assert_eq!(verdict.take(), Ok(()));
    }

    #[test]
    fn a_worker_panic_is_raised_again_by_take() {
        let mut verdict = BlockVerdict::default();
        verdict.record(JobOutcome::Panicked(Box::new("interpreter bug")));
        let raised = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| verdict.take()));
        assert!(raised.is_err());
    }
}
