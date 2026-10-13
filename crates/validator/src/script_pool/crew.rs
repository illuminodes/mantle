use std::thread::JoinHandle;

/// The pool's worker threads, joined on drop.
///
/// [`ScriptPool`](super::ScriptPool) declares this after its job producer,
/// so the producer is dropped first, the job ring closes, and every worker
/// leaves its blocking pop before the join.
#[derive(Default)]
pub(super) struct WorkerCrew {
    threads: Vec<JoinHandle<()>>,
}

impl WorkerCrew {
    pub(super) fn add(&mut self, thread: JoinHandle<()>) {
        self.threads.push(thread);
    }

    pub(super) fn len(&self) -> usize {
        self.threads.len()
    }
}

impl Drop for WorkerCrew {
    fn drop(&mut self) {
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}
