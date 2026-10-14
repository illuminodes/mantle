use std::sync::Arc;
use std::thread::JoinHandle;

use mantle::primitives::{BlockHeight, Hash256};
use mantle_consensus::validation::Clock;
use quetzalcoatl::capacity::Capacity;
use quetzalcoatl::{mpmc, mpsc};

use super::in_order::InOrder;
use super::{BlockPreparer, Prepared};
use crate::connect_pipeline::BlockJob;

/// Block bytes waiting to be prepared.
pub struct RawBlock {
    pub height: BlockHeight,
    pub hash: Hash256,
    pub bytes: Vec<u8>,
}

struct PrepOutcome {
    height: BlockHeight,
    result: Result<Prepared, String>,
}

/// Threads that prepare blocks in parallel, handed back in height order.
///
/// [`submit`](Self::submit) queues raw blocks; [`take_next`](Self::take_next) blocks
/// until the next height is prepared. The owner keeps at most
/// [`depth`](Self::depth) blocks queued, which bounds memory and keeps the
/// threads busy while it connects earlier blocks. Every wait is a blocking
/// ring operation.
///
/// Dropping the pool closes the job ring, so the threads leave their
/// blocking pop, and then joins them.
pub struct PrepPool {
    jobs: Option<mpmc::Producer<RawBlock>>,
    outcomes: mpsc::Consumer<PrepOutcome>,
    order: InOrder<Result<Prepared, String>>,
    queued: usize,
    depth: usize,
    threads: Vec<JoinHandle<()>>,
}

impl PrepPool {
    /// # Errors
    /// Returns the error from spawning a thread.
    pub fn new<C: Clock + Send + Sync + 'static>(
        preparer: BlockPreparer<C>,
        threads: usize,
        depth: usize,
        first: BlockHeight,
    ) -> std::io::Result<Self> {
        let depth = depth.max(1);
        let (jobs, job_rx) = mpmc::RingBuffer::<RawBlock>::new(Capacity::at_least(depth)).split();
        let (outcome_tx, outcomes) =
            mpsc::RingBuffer::<PrepOutcome>::new(Capacity::at_least(depth)).split();
        let preparer = Arc::new(preparer);
        let mut handles = Vec::with_capacity(threads.max(1));
        for index in 0..threads.max(1) {
            let job_rx = job_rx.clone();
            let outcome_tx = outcome_tx.clone();
            let preparer = Arc::clone(&preparer);
            let handle = std::thread::Builder::new()
                .name(format!("prep-{index}"))
                .spawn(move || {
                    while let Some(raw) = job_rx.pop_block() {
                        let result = preparer.prepare(raw.height, raw.hash, &raw.bytes);
                        let outcome = PrepOutcome {
                            height: raw.height,
                            result,
                        };
                        if outcome_tx.push_block(outcome).is_err() {
                            return;
                        }
                    }
                })?;
            handles.push(handle);
        }
        Ok(Self {
            jobs: Some(jobs),
            outcomes,
            order: InOrder::new(first.to_u32()),
            queued: 0,
            depth,
            threads: handles,
        })
    }

    #[must_use]
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// `true` while fewer than [`depth`](Self::depth) blocks are queued.
    #[must_use]
    pub fn has_room(&self) -> bool {
        self.queued < self.depth
    }

    /// Queue a block. Call only while [`has_room`](Self::has_room).
    ///
    /// # Panics
    /// Panics if the prep threads are gone, which only happens on a panic.
    pub fn submit(&mut self, raw: RawBlock) {
        self.queued += 1;
        let jobs = self.jobs.as_ref().expect("the job ring closes only on drop");
        if jobs.push_block(raw).is_err() {
            unreachable!("the pool owns the job producer, so the ring stays open");
        }
    }

    /// The next prepared block in height order, waiting for it if needed.
    /// `None` when nothing is queued.
    ///
    /// # Panics
    /// Panics if every prep thread has exited, which only happens on a panic.
    pub fn take_next(&mut self) -> Option<Result<Prepared, String>> {
        if !self.wait_for_next() {
            return None;
        }
        self.queued -= 1;
        self.order.pop()
    }

    /// The block that [`take_next`](Self::take_next) will return, if it is
    /// already prepared and ready to connect. Does not wait.
    pub fn peek_ready(&mut self) -> Option<&BlockJob> {
        self.collect_ready();
        match self.order.peek() {
            Some(Ok(Prepared::Ready(job))) => Some(job),
            _ => None,
        }
    }

    fn collect_ready(&mut self) {
        while let Some(outcome) = self.outcomes.pop() {
            self.order.push(outcome.height.to_u32(), outcome.result);
        }
    }

    /// Block until the next height is prepared. `false` when nothing is queued.
    fn wait_for_next(&mut self) -> bool {
        if self.queued == 0 {
            return false;
        }
        while self.order.peek().is_none() {
            let outcome = self
                .outcomes
                .pop_block()
                .expect("prep threads outlive the pool");
            self.order.push(outcome.height.to_u32(), outcome.result);
        }
        true
    }
}

impl Drop for PrepPool {
    fn drop(&mut self) {
        drop(self.jobs.take());
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}
