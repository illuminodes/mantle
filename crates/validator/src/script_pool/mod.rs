mod batch;
mod busy_clock;
mod crew;
mod job;
mod ledger;
mod verdict;
mod worker;

#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::{Duration, Instant};

use mantle_consensus::error::ValidationError;
use quetzalcoatl::capacity::Capacity;
use quetzalcoatl::{mpmc, mpsc};

pub use batch::ScriptBatch;

use busy_clock::BusyClock;
use crew::WorkerCrew;
use job::ScriptJob;
use ledger::BlockLedger;
use verdict::{BlockVerdict, JobOutcome};
use worker::ScriptWorker;

/// Worker threads that verify input scripts in parallel.
///
/// The threads live as long as the pool and block on one shared job ring.
/// Each block's checks are tracked under their own id, so checks of several
/// blocks can be queued at once and each block's verdict collected on its
/// own. The thread that owns the pool runs queued checks itself whenever it
/// waits, so a pool of `n` workers keeps `n + 1` cores busy and a pool of
/// zero workers verifies everything on the owning thread. Every wait is a
/// blocking ring operation; nothing polls.
///
/// Field order matters: `jobs` drops first, which closes the job ring and
/// releases the workers before `crew` joins them.
pub struct ScriptPool {
    jobs: mpmc::Producer<ScriptJob<'static>>,
    helper: mpmc::Consumer<ScriptJob<'static>>,
    outcomes: mpsc::Consumer<JobOutcome>,
    ledger: BlockLedger,
    workers_busy: Arc<BusyClock>,
    owner_busy: Duration,
    crew: WorkerCrew,
}

impl ScriptPool {
    const JOB_CAPACITY: usize = 16_384;

    /// The outcome ring must hold every outcome that can arrive between two
    /// drains by the owner: a full job ring plus one in-flight job per
    /// worker. Otherwise a worker blocked on a full outcome ring and the
    /// owner blocked on a full job ring would wait on each other.
    const fn outcome_capacity(workers: usize) -> usize {
        2 * (Self::JOB_CAPACITY + workers + 1)
    }

    /// Start `workers` script threads.
    ///
    /// # Errors
    /// Returns the error from spawning a thread.
    pub fn new(workers: usize) -> std::io::Result<Self> {
        let (jobs, helper) =
            mpmc::RingBuffer::new(Capacity::at_least(Self::JOB_CAPACITY)).split();
        let (outcome_sender, outcomes) =
            mpsc::RingBuffer::new(Capacity::at_least(Self::outcome_capacity(workers))).split();
        let workers_busy = Arc::new(BusyClock::default());
        let mut crew = WorkerCrew::default();
        for index in 0..workers {
            let worker = ScriptWorker {
                jobs: helper.clone(),
                outcomes: outcome_sender.clone(),
                busy: Arc::clone(&workers_busy),
            };
            crew.add(worker.spawn(index)?);
        }
        Ok(Self {
            jobs,
            helper,
            outcomes,
            ledger: BlockLedger::default(),
            workers_busy,
            owner_busy: Duration::ZERO,
            crew,
        })
    }

    /// One worker per available CPU, minus the one the owning thread uses.
    #[must_use]
    pub fn default_workers() -> usize {
        std::thread::available_parallelism().map_or(0, |n| n.get().saturating_sub(1))
    }

    #[must_use]
    pub fn workers(&self) -> usize {
        self.crew.len()
    }

    /// Time spent running checks so far: by all worker threads together,
    /// and by the owning thread while it waited.
    #[must_use]
    pub fn busy(&self) -> PoolBusy {
        PoolBusy {
            workers: self.workers_busy.total(),
            owner: self.owner_busy,
        }
    }

    /// Run `f` with a batch that verifies submitted scripts on the pool.
    ///
    /// Returns only after every check submitted through the batch has
    /// finished, including when `f` returns early or panics.
    pub fn scope<'env, R>(&mut self, f: impl FnOnce(&mut ScriptBatch<'_, 'env>) -> R) -> R {
        let mut batch = ScriptBatch::settled_on_finish(self);
        let result = f(&mut batch);
        batch.settle();
        result
    }

    /// A batch whose checks keep running after [`ScriptBatch::release`],
    /// which hands back the id to settle them under.
    ///
    /// # Safety
    /// The data borrowed for `'env` must stay alive and unchanged until
    /// [`settle_block`](Self::settle_block) returns for the released id, or
    /// the pool is dropped.
    pub(crate) unsafe fn deferred_batch<'env>(&mut self) -> ScriptBatch<'_, 'env> {
        ScriptBatch::deferred(self)
    }

    fn open_block(&mut self) -> u64 {
        self.ledger.open()
    }

    fn submit(&mut self, job: ScriptJob<'static>) {
        self.ledger.add_job(job.block());
        let Err(job) = self.jobs.push(job) else {
            return;
        };
        self.help_once();
        if self.jobs.push_block(job).is_err() {
            unreachable!("the pool owns the only job producer, so the ring stays open");
        }
    }

    /// Record every outcome the workers have already reported.
    pub(crate) fn collect_ready(&mut self) {
        while let Some(outcome) = self.outcomes.pop() {
            self.ledger.record(outcome);
        }
    }

    /// `true` once every check of `block` has finished. Does not wait.
    pub(crate) fn is_done(&mut self, block: u64) -> bool {
        self.collect_ready();
        self.ledger.is_done(block)
    }

    /// Collect finished outcomes, then run one queued job on this thread.
    /// Returns `false` when no job was waiting.
    fn help_once(&mut self) -> bool {
        self.collect_ready();
        match self.helper.pop() {
            Some(job) => {
                let started = Instant::now();
                let outcome = job.run();
                self.owner_busy += started.elapsed();
                self.ledger.record(outcome);
                true
            }
            None => false,
        }
    }

    fn wait_until(&mut self, mut done: impl FnMut(&BlockLedger) -> bool) {
        while !done(&self.ledger) {
            if self.help_once() || done(&self.ledger) {
                continue;
            }
            let outcome = self
                .outcomes
                .pop_block()
                .expect("script workers outlive the pool, so the outcome ring stays open");
            self.ledger.record(outcome);
        }
    }

    fn wait_block(&mut self, block: u64) {
        self.wait_until(|ledger| ledger.is_done(block));
    }

    /// Block until every check of `block` has finished, running queued
    /// checks on this thread meanwhile, then return and forget its verdict.
    /// Re-raises a worker panic.
    ///
    /// # Errors
    /// Returns the failure at the lowest `(tx_index, input_index)`.
    pub(crate) fn settle_block(&mut self, block: u64) -> Result<(), ValidationError> {
        self.wait_block(block);
        self.ledger.close(block).take()
    }

    /// Wait for every check of `block` and forget the block, handing back
    /// its verdict without raising anything.
    fn discard_block(&mut self, block: u64) -> BlockVerdict {
        self.wait_block(block);
        self.ledger.close(block)
    }

    fn wait_all(&mut self) {
        self.wait_until(|ledger| ledger.outstanding() == 0);
    }
}

/// Time spent running script checks, split by who ran them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolBusy {
    pub workers: Duration,
    pub owner: Duration,
}

impl std::ops::Sub for PoolBusy {
    type Output = Self;

    fn sub(self, earlier: Self) -> Self {
        Self {
            workers: self.workers.saturating_sub(earlier.workers),
            owner: self.owner.saturating_sub(earlier.owner),
        }
    }
}

impl Drop for ScriptPool {
    fn drop(&mut self) {
        self.wait_all();
    }
}
