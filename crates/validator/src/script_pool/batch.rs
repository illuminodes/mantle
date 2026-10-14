use std::marker::PhantomData;
use std::sync::Arc;

use mantle_consensus::error::ValidationError;
use mantle_consensus::script::ScriptFlags;
use mantle_consensus::tx_view::TxView;
use mantle_consensus::validation::{Prevout, ScriptChecks, TxScriptContext};

use super::ScriptPool;
use super::job::ScriptJob;
use super::verdict::InputPosition;

/// When a batch waits for the checks it submitted.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Settlement {
    /// `finish` waits and reports the verdict.
    OnFinish,
    /// `finish` returns at once; the verdict stays in the pool until its
    /// owner settles it.
    Deferred,
}

/// The script checks of one block, spread over a [`ScriptPool`].
///
/// [`ScriptPool::scope`] creates a batch that waits for every submitted
/// check before the scope returns. [`ScriptPool::deferred_batch`] creates
/// one whose checks may keep running after [`release`](Self::release).
///
/// Either kind waits for its checks when dropped without being released,
/// so an early return or a panic never leaves a job reading data that is
/// about to be freed.
pub struct ScriptBatch<'p, 'env> {
    pool: &'p mut ScriptPool,
    settlement: Settlement,
    wait_on_drop: bool,
    env: PhantomData<fn(&'env ()) -> &'env ()>,
}

impl<'p> ScriptBatch<'p, '_> {
    pub(super) fn settled_on_finish(pool: &'p mut ScriptPool) -> Self {
        Self {
            pool,
            settlement: Settlement::OnFinish,
            wait_on_drop: true,
            env: PhantomData,
        }
    }

    pub(super) fn deferred(pool: &'p mut ScriptPool) -> Self {
        Self {
            pool,
            settlement: Settlement::Deferred,
            wait_on_drop: true,
            env: PhantomData,
        }
    }

    pub(super) fn settle(&mut self) {
        self.pool.wait_all();
        self.pool.verdict.resume_panic();
    }

    /// Let the submitted checks keep running after the batch is gone.
    ///
    /// The safety contract of [`ScriptPool::deferred_batch`] still applies:
    /// the data borrowed for `'env` must outlive the checks.
    pub(crate) fn release(mut self) {
        self.wait_on_drop = false;
    }
}

impl Drop for ScriptBatch<'_, '_> {
    fn drop(&mut self) {
        if self.wait_on_drop {
            self.pool.wait_all();
        }
    }
}

impl<'env> ScriptChecks<'env> for ScriptBatch<'_, 'env> {
    fn check_tx<T: TxView + Sync + 'env>(
        &mut self,
        tx_index: usize,
        tx: &'env T,
        prevouts: &[Prevout<'env>],
        flags: ScriptFlags,
        _scratch: &mut Vec<u8>,
    ) -> Result<(), ValidationError> {
        self.pool.collect_ready();
        let context = Arc::new(TxScriptContext::uncached(tx, prevouts, flags));
        for (input_index, prevout) in prevouts.iter().enumerate() {
            let job = ScriptJob::new(
                tx,
                Arc::clone(&context),
                *prevout,
                InputPosition {
                    tx_index,
                    input_index,
                },
            );
            // SAFETY: the batch waits in `settle` or in `Drop` before `'env`
            // ends, unless it was released, and only a batch from the unsafe
            // `deferred_batch` can be released; that caller waits instead.
            self.pool.submit(unsafe { job.erase() });
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ValidationError> {
        match self.settlement {
            Settlement::OnFinish => {
                self.pool.wait_all();
                self.pool.verdict.take()
            }
            Settlement::Deferred => Ok(()),
        }
    }
}
