use std::ops::Range;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, OnceLock};

use mantle_consensus::script::{ScriptError, ScriptFlags};
use mantle_consensus::tx_view::{InputView, TxView};
use mantle_consensus::validation::{Prevout, TxScriptContext};

use super::verdict::{InputPosition, JobOutcome, JobResult, ScriptFailure};

/// A transaction whose inputs can be verified from another thread.
///
/// The worker threads serve every block whatever its transaction type, so
/// they see the transaction through this object-safe trait.
pub(super) trait SpendingTx: Sync {
    fn context<'v>(&self, prevouts: &[Prevout<'v>], flags: ScriptFlags) -> TxScriptContext<'v>;

    fn verify_input(
        &self,
        context: &TxScriptContext<'_>,
        n_in: usize,
        prevout: &Prevout<'_>,
    ) -> Result<(), ScriptError>;
}

impl<T: TxView + Sync> SpendingTx for T {
    fn context<'v>(&self, prevouts: &[Prevout<'v>], flags: ScriptFlags) -> TxScriptContext<'v> {
        TxScriptContext::uncached(self, prevouts, flags)
    }

    fn verify_input(
        &self,
        context: &TxScriptContext<'_>,
        n_in: usize,
        prevout: &Prevout<'_>,
    ) -> Result<(), ScriptError> {
        context.verify_input(self, n_in, self.input(n_in).script_sig(), prevout, None)
    }
}

/// One transaction's script checks, shared by the jobs that verify its
/// inputs. The first job to run builds the sighash midstate and spent
/// output table; the others wait for it and reuse it.
pub(super) struct TxChecks<'env> {
    tx: &'env (dyn SpendingTx + 'env),
    prevouts: Vec<Prevout<'env>>,
    flags: ScriptFlags,
    context: OnceLock<TxScriptContext<'env>>,
    block: u64,
    tx_index: usize,
}

impl<'env> TxChecks<'env> {
    pub(super) fn new(
        tx: &'env (dyn SpendingTx + 'env),
        prevouts: Vec<Prevout<'env>>,
        flags: ScriptFlags,
        block: u64,
        tx_index: usize,
    ) -> Self {
        Self {
            tx,
            prevouts,
            flags,
            context: OnceLock::new(),
            block,
            tx_index,
        }
    }

    fn verify(&self, inputs: Range<usize>) -> Option<ScriptFailure> {
        let context = self
            .context
            .get_or_init(|| self.tx.context(&self.prevouts, self.flags));
        inputs.into_iter().find_map(|n_in| {
            self.tx
                .verify_input(context, n_in, &self.prevouts[n_in])
                .err()
                .map(|kind| {
                    ScriptFailure::new(
                        InputPosition {
                            tx_index: self.tx_index,
                            input_index: n_in,
                        },
                        kind,
                    )
                })
        })
    }
}

/// The script checks of a run of consecutive inputs of one transaction.
pub(super) struct ScriptJob<'env> {
    checks: Arc<TxChecks<'env>>,
    inputs: Range<usize>,
}

impl<'env> ScriptJob<'env> {
    pub(super) fn new(checks: Arc<TxChecks<'env>>, inputs: Range<usize>) -> Self {
        Self { checks, inputs }
    }

    pub(super) fn block(&self) -> u64 {
        self.checks.block
    }

    /// Forget how long the borrowed block data lives, so the job can cross
    /// into the long-lived worker threads.
    ///
    /// # Safety
    /// The job must be run, and so dropped, before `'env` ends.
    pub(super) unsafe fn erase(self) -> ScriptJob<'static> {
        // SAFETY: only lifetimes differ between the two types, so the layout
        // is identical; the caller keeps the borrowed data alive.
        unsafe { std::mem::transmute::<ScriptJob<'env>, ScriptJob<'static>>(self) }
    }
}

impl ScriptJob<'_> {
    /// Verify the inputs. The job, and with it every borrow of block data, is
    /// dropped before the outcome is returned.
    pub(super) fn run(self) -> JobOutcome {
        let block = self.block();
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            self.checks.verify(self.inputs.clone())
        }));
        drop(self);
        JobOutcome {
            block,
            result: match result {
                Ok(None) => JobResult::Passed,
                Ok(Some(failure)) => JobResult::Failed(failure),
                Err(payload) => JobResult::Panicked(payload),
            },
        }
    }
}
