use std::thread::JoinHandle;

use quetzalcoatl::{mpmc, mpsc};

use super::job::ScriptJob;
use super::verdict::JobOutcome;

/// One script-verification thread.
///
/// Blocks on the shared job ring and reports each outcome on the
/// coordinator's ring. It exits when the pool drops its job producer, which
/// closes the ring.
pub(super) struct ScriptWorker {
    pub(super) jobs: mpmc::Consumer<ScriptJob<'static>>,
    pub(super) outcomes: mpsc::Producer<JobOutcome>,
}

impl ScriptWorker {
    pub(super) fn spawn(self, index: usize) -> std::io::Result<JoinHandle<()>> {
        std::thread::Builder::new()
            .name(format!("script-{index}"))
            .spawn(move || self.run())
    }

    fn run(self) {
        while let Some(job) = self.jobs.pop_block() {
            if self.outcomes.push_block(job.run()).is_err() {
                return;
            }
        }
    }
}
