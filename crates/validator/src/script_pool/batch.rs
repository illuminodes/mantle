use std::marker::PhantomData;
use std::sync::Arc;

use mantle_consensus::error::ValidationError;
use mantle_consensus::script::ScriptFlags;
use mantle_consensus::tx_view::TxView;
use mantle_consensus::validation::{Prevout, ScriptChecks};

use super::ScriptPool;
use super::job::{ScriptJob, TxChecks};

/// What happens to a batch's checks when it goes away.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    /// `finish` waits for the checks and reports their verdict.
    SettledOnFinish,
    /// `finish` returns at once; `release` hands the block id to the owner.
    Deferred,
    /// The verdict was collected or the id handed out; nothing to wait for.
    Done,
}

/// The script checks of one block, spread over a [`ScriptPool`].
///
/// [`ScriptPool::scope`] creates a batch that waits for every submitted
/// check before the scope returns. [`ScriptPool::deferred_batch`] creates
/// one whose checks keep running after [`release`](Self::release).
///
/// A batch dropped before either waits for its checks, so an early return
/// or a panic never leaves a job reading data that is about to be freed.
pub struct ScriptBatch<'p, 'env> {
    pool: &'p mut ScriptPool,
    block: u64,
    state: State,
    env: PhantomData<fn(&'env ()) -> &'env ()>,
}

impl<'p> ScriptBatch<'p, '_> {
    /// A transaction's inputs are split into jobs of at most this many, so
    /// a transaction with many inputs still spreads over the workers.
    const INPUTS_PER_JOB: usize = 4;

    pub(super) fn settled_on_finish(pool: &'p mut ScriptPool) -> Self {
        Self::with_state(pool, State::SettledOnFinish)
    }

    pub(super) fn deferred(pool: &'p mut ScriptPool) -> Self {
        Self::with_state(pool, State::Deferred)
    }

    fn with_state(pool: &'p mut ScriptPool, state: State) -> Self {
        let block = pool.open_block();
        Self {
            pool,
            block,
            state,
            env: PhantomData,
        }
    }

    /// Wait for the checks if their verdict was not collected, and re-raise
    /// a worker panic. A script failure is dropped: the scope's caller got
    /// an earlier error from `connect_block`.
    pub(super) fn settle(&mut self) {
        if self.state == State::Done {
            return;
        }
        self.state = State::Done;
        self.pool.discard_block(self.block).resume_panic();
    }

    /// Let the submitted checks keep running after the batch is gone and
    /// return the id to settle them under with [`ScriptPool::settle_block`].
    ///
    /// The safety contract of [`ScriptPool::deferred_batch`] still applies:
    /// the data borrowed for `'env` must outlive the checks.
    pub(crate) fn release(mut self) -> u64 {
        debug_assert!(self.state == State::Deferred, "only deferred batches are released");
        self.state = State::Done;
        self.block
    }
}

impl Drop for ScriptBatch<'_, '_> {
    fn drop(&mut self) {
        if self.state != State::Done {
            drop(self.pool.discard_block(self.block));
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
        let checks = Arc::new(TxChecks::new(
            tx,
            prevouts.to_vec(),
            flags,
            self.block,
            tx_index,
        ));
        let inputs = prevouts.len();
        for start in (0..inputs).step_by(Self::INPUTS_PER_JOB) {
            let end = (start + Self::INPUTS_PER_JOB).min(inputs);
            let job = ScriptJob::new(Arc::clone(&checks), start..end);
            // SAFETY: the batch waits in `settle` or in `Drop` before `'env`
            // ends, unless it was released, and only a batch from the unsafe
            // `deferred_batch` can be released; that caller waits instead.
            self.pool.submit(unsafe { job.erase() });
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ValidationError> {
        match self.state {
            State::SettledOnFinish => {
                self.state = State::Done;
                self.pool.settle_block(self.block)
            }
            State::Deferred | State::Done => Ok(()),
        }
    }
}
