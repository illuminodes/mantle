mod batch;
mod crew;
mod job;
mod verdict;
mod worker;

#[cfg(test)]
mod tests;

use mantle_consensus::error::ValidationError;
use quetzalcoatl::capacity::Capacity;
use quetzalcoatl::{mpmc, mpsc};

pub use batch::ScriptBatch;

use crew::WorkerCrew;
use job::ScriptJob;
use verdict::{BlockVerdict, JobOutcome};
use worker::ScriptWorker;

/// Worker threads that verify input scripts in parallel.
///
/// The threads live as long as the pool and block on one shared job ring.
/// The thread that calls [`scope`](Self::scope) submits a block's checks and
/// runs queued checks itself while it waits, so a pool of `n` workers keeps
/// `n + 1` cores busy and a pool of zero workers verifies everything on the
/// calling thread. Every wait is a blocking ring operation; nothing polls.
///
/// Field order matters: `jobs` drops first, which closes the job ring and
/// releases the workers before `crew` joins them.
pub struct ScriptPool {
    jobs: mpmc::Producer<ScriptJob<'static>>,
    helper: mpmc::Consumer<ScriptJob<'static>>,
    outcomes: mpsc::Consumer<JobOutcome>,
    outstanding: usize,
    verdict: BlockVerdict,
    crew: WorkerCrew,
}

impl ScriptPool {
    const JOB_CAPACITY: usize = 1024;

    /// The outcome ring must hold every outcome that can arrive between two
    /// drains by the coordinator: a full job ring plus one in-flight job per
    /// worker. Otherwise a worker blocked on a full outcome ring and the
    /// coordinator blocked on a full job ring would wait on each other.
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
        let mut crew = WorkerCrew::default();
        for index in 0..workers {
            let worker = ScriptWorker {
                jobs: helper.clone(),
                outcomes: outcome_sender.clone(),
            };
            crew.add(worker.spawn(index)?);
        }
        Ok(Self {
            jobs,
            helper,
            outcomes,
            outstanding: 0,
            verdict: BlockVerdict::default(),
            crew,
        })
    }

    /// One worker per available CPU, minus the one the calling thread uses.
    #[must_use]
    pub fn default_workers() -> usize {
        std::thread::available_parallelism().map_or(0, |n| n.get().saturating_sub(1))
    }

    #[must_use]
    pub fn workers(&self) -> usize {
        self.crew.len()
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

    /// A batch whose checks keep running after it is dropped and after its
    /// `finish` returns.
    ///
    /// # Safety
    /// The caller must call [`wait_all`](Self::wait_all), or drop the pool,
    /// before any data borrowed for `'env` is freed or mutated.
    pub(crate) unsafe fn deferred_batch<'env>(&mut self) -> ScriptBatch<'_, 'env> {
        ScriptBatch::deferred(self)
    }

    fn submit(&mut self, job: ScriptJob<'static>) {
        self.outstanding += 1;
        let Err(job) = self.jobs.push(job) else {
            return;
        };
        self.help_once();
        if self.jobs.push_block(job).is_err() {
            unreachable!("the pool owns the only job producer, so the ring stays open");
        }
    }

    fn record(&mut self, outcome: JobOutcome) {
        self.verdict.record(outcome);
        self.outstanding -= 1;
    }

    fn collect_ready(&mut self) {
        while let Some(outcome) = self.outcomes.pop() {
            self.record(outcome);
        }
    }

    /// Collect finished outcomes, then run one queued job on this thread.
    /// Returns `false` when no job was waiting.
    fn help_once(&mut self) -> bool {
        self.collect_ready();
        match self.helper.pop() {
            Some(job) => {
                let outcome = job.run();
                self.record(outcome);
                true
            }
            None => false,
        }
    }

    /// Block until every submitted check has finished, running queued checks
    /// on this thread meanwhile.
    pub(crate) fn wait_all(&mut self) {
        while self.outstanding > 0 {
            if self.help_once() || self.outstanding == 0 {
                continue;
            }
            let outcome = self
                .outcomes
                .pop_block()
                .expect("script workers outlive the pool, so the outcome ring stays open");
            self.record(outcome);
        }
    }

    /// Wait for every submitted check, then return and clear their combined
    /// verdict. Re-raises a worker panic.
    ///
    /// # Errors
    /// Returns the failure at the lowest `(tx_index, input_index)`.
    pub(crate) fn settle_verdict(&mut self) -> Result<(), ValidationError> {
        self.wait_all();
        self.verdict.take()
    }

    /// Wait for every submitted check and forget their verdict.
    pub(crate) fn discard(&mut self) {
        self.wait_all();
        self.verdict.resume_panic();
        self.verdict = BlockVerdict::default();
    }
}

impl Drop for ScriptPool {
    fn drop(&mut self) {
        self.wait_all();
    }
}
