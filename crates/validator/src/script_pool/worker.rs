use std::sync::Arc;
use std::thread::JoinHandle;

use quetzalcoatl::{mpmc, mpsc};

use super::job::ScriptJob;
use super::roster::PoolRoster;
use super::verdict::JobOutcome;

/// One script-verification thread.
///
/// Takes jobs from the ring every worker shares, reports each outcome on the
/// coordinator's ring, and parks while the job ring is empty. It stops once
/// the roster is told to stop.
pub(super) struct ScriptWorker {
    pub(super) jobs: mpmc::Consumer<ScriptJob<'static>>,
    pub(super) outcomes: mpsc::Producer<JobOutcome>,
    pub(super) roster: Arc<PoolRoster>,
}

impl ScriptWorker {
    pub(super) fn spawn(self, index: usize) -> std::io::Result<JoinHandle<()>> {
        std::thread::Builder::new()
            .name(format!("script-{index}"))
            .spawn(move || self.run())
    }

    fn run(self) {
        while !self.roster.is_stopping() {
            match self.jobs.pop() {
                Some(job) => self.report(job.run()),
                None => PoolRoster::park(),
            }
        }
    }

    fn report(&self, mut outcome: JobOutcome) {
        loop {
            match self.outcomes.push(outcome) {
                Ok(()) => {
                    self.roster.wake_coordinator();
                    return;
                }
                Err(rejected) => {
                    outcome = rejected;
                    self.roster.wake_coordinator();
                    std::thread::yield_now();
                }
            }
        }
    }
}
