mod batch;
mod crew;
mod job;
mod verdict;
mod worker;

#[cfg(test)]
mod tests;

use quetzalcoatl::capacity::Capacity;
use quetzalcoatl::{mpmc, mpsc};

pub use batch::ScriptBatch;

use crew::WorkerCrew;
use job::ScriptJob;
use verdict::JobOutcome;
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
        let mut batch = ScriptBatch::new(self);
        let result = f(&mut batch);
        batch.settle();
        result
    }
}
