mod batch;
mod job;
mod roster;
mod verdict;
mod worker;

#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::thread::JoinHandle;

use quetzalcoatl::capacity::Capacity;
use quetzalcoatl::{mpmc, mpsc};

pub use batch::ScriptBatch;

use job::ScriptJob;
use roster::PoolRoster;
use verdict::JobOutcome;
use worker::ScriptWorker;

/// Worker threads that verify input scripts in parallel.
///
/// The threads live as long as the pool and take jobs from one shared ring.
/// The thread that calls [`scope`](Self::scope) submits a block's checks and
/// runs queued checks itself while it waits, so a pool of `n` workers keeps
/// `n + 1` cores busy and a pool of zero workers verifies everything on the
/// calling thread.
pub struct ScriptPool {
    jobs: mpmc::Producer<ScriptJob<'static>>,
    helper: mpmc::Consumer<ScriptJob<'static>>,
    outcomes: mpsc::Consumer<JobOutcome>,
    roster: Arc<PoolRoster>,
    workers: Vec<JoinHandle<()>>,
}

impl ScriptPool {
    const JOB_CAPACITY: usize = 1024;
    const OUTCOME_CAPACITY: usize = 4096;

    /// Start `workers` script threads.
    ///
    /// # Errors
    /// Returns the error from spawning a thread.
    pub fn new(workers: usize) -> std::io::Result<Self> {
        let (jobs, helper) =
            mpmc::RingBuffer::new(Capacity::at_least(Self::JOB_CAPACITY)).split();
        let (outcome_sender, outcomes) =
            mpsc::RingBuffer::new(Capacity::at_least(Self::OUTCOME_CAPACITY)).split();
        let mut pool = Self {
            jobs,
            helper,
            outcomes,
            roster: Arc::new(PoolRoster::default()),
            workers: Vec::with_capacity(workers),
        };
        for index in 0..workers {
            let worker = ScriptWorker {
                jobs: pool.helper.clone(),
                outcomes: outcome_sender.clone(),
                roster: Arc::clone(&pool.roster),
            };
            pool.workers.push(worker.spawn(index)?);
        }
        pool.roster.enroll_workers(
            pool.workers
                .iter()
                .map(|handle| handle.thread().clone())
                .collect(),
        );
        Ok(pool)
    }

    /// One worker per available CPU, minus the one the calling thread uses.
    #[must_use]
    pub fn default_workers() -> usize {
        std::thread::available_parallelism().map_or(0, |n| n.get().saturating_sub(1))
    }

    #[must_use]
    pub fn workers(&self) -> usize {
        self.workers.len()
    }

    /// Run `f` with a batch that verifies submitted scripts on the pool.
    ///
    /// Returns only after every check submitted through the batch has
    /// finished, including when `f` returns early or panics.
    pub fn scope<'env, R>(&mut self, f: impl FnOnce(&mut ScriptBatch<'_, 'env>) -> R) -> R {
        self.roster.enroll_coordinator();
        let mut batch = ScriptBatch::new(self);
        let result = f(&mut batch);
        batch.settle();
        result
    }
}

impl Drop for ScriptPool {
    fn drop(&mut self) {
        self.roster.stop();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}
