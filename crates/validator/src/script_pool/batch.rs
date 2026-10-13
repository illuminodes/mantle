use std::marker::PhantomData;
use std::sync::Arc;

use mantle_consensus::error::ValidationError;
use mantle_consensus::script::ScriptFlags;
use mantle_consensus::tx_view::TxView;
use mantle_consensus::validation::{Prevout, ScriptChecks, TxScriptContext};

use super::ScriptPool;
use super::job::ScriptJob;
use super::verdict::{BlockVerdict, InputPosition, JobOutcome};

/// The script checks of one block, spread over a [`ScriptPool`].
///
/// Only [`ScriptPool::scope`] creates a batch, and it waits for every
/// submitted check before returning, so block data borrowed for `'env`
/// outlives every job that reads it.
pub struct ScriptBatch<'p, 'env> {
    pool: &'p mut ScriptPool,
    outstanding: usize,
    verdict: BlockVerdict,
    env: PhantomData<fn(&'env ()) -> &'env ()>,
}

impl<'p, 'env> ScriptBatch<'p, 'env> {
    pub(super) fn new(pool: &'p mut ScriptPool) -> Self {
        Self {
            pool,
            outstanding: 0,
            verdict: BlockVerdict::default(),
            env: PhantomData,
        }
    }

    fn submit(&mut self, job: ScriptJob<'env>) {
        // SAFETY: `wait_all` runs before the scope that created this batch
        // returns, from `settle` or from `Drop` while unwinding, and `'env`
        // outlives that scope.
        let job = unsafe { job.erase() };
        self.outstanding += 1;
        let Err(job) = self.pool.jobs.push(job) else {
            return;
        };
        self.collect_ready();
        self.help_once();
        if self.pool.jobs.push_block(job).is_err() {
            unreachable!("the pool owns the only job producer, so the ring stays open");
        }
    }

    fn record(&mut self, outcome: JobOutcome) {
        self.verdict.record(outcome);
        self.outstanding -= 1;
    }

    fn collect_ready(&mut self) {
        while let Some(outcome) = self.pool.outcomes.pop() {
            self.record(outcome);
        }
    }

    /// Collect finished outcomes, then run one queued job on this thread.
    /// Returns `false` when no job was waiting.
    fn help_once(&mut self) -> bool {
        self.collect_ready();
        match self.pool.helper.pop() {
            Some(job) => {
                let outcome = job.run();
                self.record(outcome);
                true
            }
            None => false,
        }
    }

    fn wait_all(&mut self) {
        while self.outstanding > 0 {
            if self.help_once() || self.outstanding == 0 {
                continue;
            }
            let outcome = self
                .pool
                .outcomes
                .pop_block()
                .expect("script workers outlive the pool, so the outcome ring stays open");
            self.record(outcome);
        }
    }

    pub(super) fn settle(&mut self) {
        self.wait_all();
        self.verdict.resume_panic();
    }
}

impl Drop for ScriptBatch<'_, '_> {
    fn drop(&mut self) {
        self.wait_all();
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
        self.collect_ready();
        let context = Arc::new(TxScriptContext::uncached(tx, prevouts, flags));
        for (input_index, prevout) in prevouts.iter().enumerate() {
            self.submit(ScriptJob::new(
                tx,
                Arc::clone(&context),
                *prevout,
                InputPosition {
                    tx_index,
                    input_index,
                },
            ));
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ValidationError> {
        self.wait_all();
        self.verdict.take()
    }
}
