use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use mantle_consensus::script::ScriptError;
use mantle_consensus::tx_view::{InputView, TxView};
use mantle_consensus::validation::{Prevout, TxScriptContext};

use super::verdict::{InputPosition, JobOutcome, ScriptFailure};

/// A transaction whose inputs can be verified from another thread.
///
/// The worker threads serve every block whatever its transaction type, so
/// they see the transaction through this object-safe trait.
pub(super) trait SpendingTx: Sync {
    fn verify_input(
        &self,
        context: &TxScriptContext<'_>,
        n_in: usize,
        prevout: &Prevout<'_>,
    ) -> Result<(), ScriptError>;
}

impl<T: TxView + Sync> SpendingTx for T {
    fn verify_input(
        &self,
        context: &TxScriptContext<'_>,
        n_in: usize,
        prevout: &Prevout<'_>,
    ) -> Result<(), ScriptError> {
        context.verify_input(self, n_in, self.input(n_in).script_sig(), prevout, None)
    }
}

/// The script check of one input.
pub(super) struct ScriptJob<'env> {
    tx: &'env (dyn SpendingTx + 'env),
    context: Arc<TxScriptContext<'env>>,
    prevout: Prevout<'env>,
    position: InputPosition,
}

impl<'env> ScriptJob<'env> {
    pub(super) fn new(
        tx: &'env (dyn SpendingTx + 'env),
        context: Arc<TxScriptContext<'env>>,
        prevout: Prevout<'env>,
        position: InputPosition,
    ) -> Self {
        Self {
            tx,
            context,
            prevout,
            position,
        }
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
    /// Verify the input. The job, and with it every borrow of block data, is
    /// dropped before the outcome is returned.
    pub(super) fn run(self) -> JobOutcome {
        let position = self.position;
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            self.tx
                .verify_input(&self.context, position.input_index, &self.prevout)
        }));
        drop(self);
        match result {
            Ok(Ok(())) => JobOutcome::Passed,
            Ok(Err(kind)) => JobOutcome::Failed(ScriptFailure::new(position, kind)),
            Err(payload) => JobOutcome::Panicked(payload),
        }
    }
}
