use std::collections::VecDeque;

use super::verdict::{BlockVerdict, JobOutcome};

#[derive(Default)]
struct BlockEntry {
    outstanding: usize,
    verdict: BlockVerdict,
    closed: bool,
}

/// Jobs still running and the verdict so far of every block that has
/// checks on the pool.
///
/// Blocks get consecutive ids. An entry stays until its block is closed and
/// every older block is closed too, so lookups are an index from the oldest
/// open id.
#[derive(Default)]
pub(super) struct BlockLedger {
    first: u64,
    entries: VecDeque<BlockEntry>,
    outstanding: usize,
}

impl BlockLedger {
    pub(super) fn open(&mut self) -> u64 {
        self.entries.push_back(BlockEntry::default());
        self.first + self.entries.len() as u64 - 1
    }

    pub(super) fn add_job(&mut self, block: u64) {
        self.entry(block).outstanding += 1;
        self.outstanding += 1;
    }

    pub(super) fn record(&mut self, outcome: JobOutcome) {
        let entry = self.entry(outcome.block);
        entry.verdict.record(outcome.result);
        entry.outstanding -= 1;
        self.outstanding -= 1;
    }

    pub(super) fn is_done(&self, block: u64) -> bool {
        self.entries[self.index(block)].outstanding == 0
    }

    pub(super) fn outstanding(&self) -> usize {
        self.outstanding
    }

    /// Hand back a finished block's verdict and forget the block.
    ///
    /// # Panics
    /// Panics if the block still has jobs running or was closed already.
    pub(super) fn close(&mut self, block: u64) -> BlockVerdict {
        let entry = self.entry(block);
        assert_eq!(entry.outstanding, 0, "closing block {block} with checks still running");
        assert!(!entry.closed, "block {block} closed twice");
        entry.closed = true;
        let verdict = std::mem::take(&mut entry.verdict);
        while self.entries.front().is_some_and(|e| e.closed) {
            self.entries.pop_front();
            self.first += 1;
        }
        verdict
    }

    fn index(&self, block: u64) -> usize {
        usize::try_from(block - self.first).expect("open blocks fit usize")
    }

    fn entry(&mut self, block: u64) -> &mut BlockEntry {
        let index = self.index(block);
        &mut self.entries[index]
    }
}

#[cfg(test)]
mod tests {
    use mantle_consensus::error::ValidationError;
    use mantle_consensus::script::ScriptError;

    use super::super::verdict::{InputPosition, JobResult, ScriptFailure};
    use super::*;

    fn failed(block: u64) -> JobOutcome {
        JobOutcome {
            block,
            result: JobResult::Failed(ScriptFailure::new(
                InputPosition {
                    tx_index: 1,
                    input_index: 0,
                },
                ScriptError::EvalFalse,
            )),
        }
    }

    fn passed(block: u64) -> JobOutcome {
        JobOutcome {
            block,
            result: JobResult::Passed,
        }
    }

    #[test]
    fn outcomes_are_counted_against_their_own_block() {
        let mut ledger = BlockLedger::default();
        let a = ledger.open();
        let b = ledger.open();
        ledger.add_job(a);
        ledger.add_job(b);
        ledger.add_job(b);
        ledger.record(failed(b));
        assert!(!ledger.is_done(a));
        assert!(!ledger.is_done(b));
        ledger.record(passed(b));
        assert!(ledger.is_done(b));
        assert_eq!(ledger.outstanding(), 1);
        assert!(ledger.close(b).take().is_err());
        ledger.record(passed(a));
        assert_eq!(ledger.close(a).take(), Ok::<(), ValidationError>(()));
        assert_eq!(ledger.outstanding(), 0);
        assert!(ledger.entries.is_empty());
        assert_eq!(ledger.open(), 2);
    }

    #[test]
    fn closing_out_of_order_keeps_younger_blocks_addressable() {
        let mut ledger = BlockLedger::default();
        let ids: Vec<u64> = (0..4).map(|_| ledger.open()).collect();
        ledger.close(ids[2]);
        ledger.close(ids[0]);
        assert_eq!(ledger.first, 1);
        ledger.add_job(ids[3]);
        ledger.record(passed(ids[3]));
        ledger.close(ids[1]);
        ledger.close(ids[3]);
        assert!(ledger.entries.is_empty());
        assert_eq!(ledger.first, 4);
    }

    #[test]
    #[should_panic(expected = "checks still running")]
    fn a_block_cannot_close_while_jobs_run() {
        let mut ledger = BlockLedger::default();
        let a = ledger.open();
        ledger.add_job(a);
        ledger.close(a);
    }
}
