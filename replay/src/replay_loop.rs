use mantle::collections::{BuildPrehashedHasher, PrehashedMap};
use mantle::primitives::{Block, BlockHeader, BlockHeight, Hash256};
use mantle_consensus::validation::{validate_block_context, validate_block_structure};
use mantle_storage::StorageHandle;
use mantle_storage::types::{Durability, ReqToken};
use mantle_validator::{
    BlockJob, ConnectPipeline, Connected, HeaderSnapshot, PrefetchedView, Retired, Verdict, Wait,
};

use crate::block_feed::{BlockFeed, FedBlock, FeedItem};
use crate::failures::{FailureLog, FailureStage};
use crate::report::Reporter;
use crate::stage_clock::{Stage, StageClock};
use mantle_replay::block_files::BlockFiles;
use mantle_replay::utxo_hash_check::{UtxoHashTracker, UtxoHashVerdict};

/// Drives blocks from the feed through the connect pipeline.
///
/// Each block is decoded and checked on its own, connected ahead of its
/// scripts, and committed once its scripts pass. Blocks reach storage, the
/// failure log and the UTXO hash tracker in height order.
pub struct ReplayLoop {
    pub storage: StorageHandle<'static>,
    pub pipeline: ConnectPipeline,
    pub allow_min_difficulty: bool,
    pub failures: Option<FailureLog>,
    pub failure_blocks: Option<BlockFiles>,
    pub utxo_hash: Option<UtxoHashTracker>,
    pub clock: StageClock,
    /// Durability of the commit at each `SYNC_EVERY` boundary. Ephemeral
    /// runs only need the write buffer drained there, not an `fsync`.
    pub boundary_durability: Durability,
    next_token: u64,
    last_committed: BlockHeight,
}

/// Blocks are written with `Durability::Synced` at difficulty-adjustment
/// boundaries; every other commit stays in memory until then.
const SYNC_EVERY: u32 = 2_016;

impl ReplayLoop {
    #[must_use]
    pub fn new(storage: StorageHandle<'static>, pipeline: ConnectPipeline) -> Self {
        let tip = storage.tip().height;
        Self {
            storage,
            pipeline,
            allow_min_difficulty: false,
            failures: None,
            failure_blocks: None,
            utxo_hash: None,
            clock: StageClock::default(),
            boundary_durability: Durability::Synced,
            next_token: u64::from(tip.to_u32()).saturating_add(1),
            last_committed: tip,
        }
    }

    /// Replay every block in `header_pairs`, window by window, and return
    /// the height storage ends at.
    ///
    /// # Errors
    /// A message on a feed or storage failure, or on the first consensus
    /// failure without `--keep-going`.
    pub fn run(
        &mut self,
        header_pairs: &[(BlockHeight, BlockHeader)],
        window: usize,
        feed: &mut BlockFeed,
        snapshot: &HeaderSnapshot,
        reporter: &mut Reporter,
    ) -> Result<BlockHeight, String> {
        for chunk in header_pairs.chunks(window) {
            for &(height, _) in chunk {
                let block = self.next_block(feed, height)?;
                self.replay_block(&block, snapshot)?;
                self.retire(Wait::IfOverLimit, reporter)?;
                if self.pipeline.is_stopped() {
                    return Ok(self.last_committed);
                }
            }
            if chunk.last() == header_pairs.last() {
                self.retire(Wait::Always, reporter)?;
            }
            eprintln!(
                "  window {}..={}: {}, {} blocks in flight",
                chunk[0].0.to_u32(),
                chunk[chunk.len() - 1].0.to_u32(),
                self.clock.take_line(),
                self.pipeline.in_flight()
            );
        }
        Ok(self.last_committed)
    }

    fn next_block(&mut self, feed: &mut BlockFeed, height: BlockHeight) -> Result<FedBlock, String> {
        let block = match self.clock.time(Stage::Wait, || feed.next()) {
            Some(FeedItem::Block(block)) => block,
            Some(FeedItem::Failed(e)) => return Err(e),
            Some(FeedItem::Headers(_)) | None => {
                return Err(format!("block feed ended before height {}", height.to_u32()));
            }
        };
        if block.height != height {
            return Err(format!(
                "block feed sent height {}, expected {}",
                block.height.to_u32(),
                height.to_u32()
            ));
        }
        Ok(block)
    }

    fn replay_block(&mut self, fed: &FedBlock, snapshot: &HeaderSnapshot) -> Result<(), String> {
        let (height, hash) = (fed.height, fed.hash);
        let block = self.clock.time(Stage::Decode, || fed.decode())?;
        let mut failed = false;
        if let Err(e) = validate_block_structure(&block) {
            failed = true;
            self.save_failed_block(height, hash, &fed.bytes);
            self.fail(height, hash, FailureStage::Structure, &e)?;
        }
        let empty = PrehashedMap::with_hasher(BuildPrehashedHasher);
        let view = PrefetchedView::new(&empty, snapshot, self.pipeline.tip().clone());
        if let Err(e) = validate_block_context(&block, &view, self.allow_min_difficulty) {
            if !failed {
                self.save_failed_block(height, hash, &fed.bytes);
            }
            failed = true;
            self.fail(height, hash, FailureStage::Context, &e)?;
        }
        let job = BlockJob::new(block, height, self.durability(height), self.next_token());
        if failed {
            return self.force(job);
        }
        let started = std::time::Instant::now();
        let connected = self
            .pipeline
            .connect(job, &mut self.storage, snapshot)
            .map_err(|e| format!("lookup at {}: {e}", height.to_u32()))?;
        self.clock.add(Stage::Validate, started);
        match connected {
            Connected::Queued => Ok(()),
            Connected::Rejected { error, job } => {
                self.save_failed_block(height, hash, &fed.bytes);
                self.fail(height, hash, FailureStage::Connect, &error)?;
                self.force(*job)
            }
        }
    }

    fn force(&mut self, job: BlockJob) -> Result<(), String> {
        let height = job.height;
        self.pipeline.stop_utxo_hash();
        if let Some(tracker) = &mut self.utxo_hash {
            tracker.stop(height);
        }
        self.pipeline
            .force(Box::new(job))
            .map_err(|e| format!("forced commit at {}: {e}", height.to_u32()))
    }

    fn retire(&mut self, wait: Wait, reporter: &mut Reporter) -> Result<(), String> {
        loop {
            let started = std::time::Instant::now();
            let retired = self
                .pipeline
                .retire_next(&mut self.storage, wait)
                .map_err(|e| format!("commit: {e}"))?;
            self.clock.add(Stage::Commit, started);
            let Some(retired) = retired else {
                return Ok(());
            };
            self.record(retired, reporter)?;
        }
    }

    fn record(&mut self, retired: Retired, reporter: &mut Reporter) -> Result<(), String> {
        let Retired {
            height,
            hash,
            verdict,
            committed,
            failed_block,
        } = retired;
        if let Verdict::ScriptFailed(error) = &verdict {
            if let Some(block) = &failed_block {
                self.save_block(height, hash, block);
            }
            if let Some(tracker) = &mut self.utxo_hash {
                tracker.stop(height);
            }
            self.pipeline.stop_utxo_hash();
            self.fail(height, hash, FailureStage::Connect, error)?;
        }
        if !committed {
            return Ok(());
        }
        self.last_committed = height;
        reporter.tick(height);
        self.check_utxo_hash(height, hash)
    }

    fn durability(&self, height: BlockHeight) -> Durability {
        if height.to_u32().is_multiple_of(SYNC_EVERY) {
            self.boundary_durability
        } else {
            Durability::Memory
        }
    }

    fn next_token(&mut self) -> ReqToken {
        let token = ReqToken(self.next_token);
        self.next_token = self.next_token.saturating_add(1);
        token
    }

    fn save_failed_block(&self, height: BlockHeight, hash: Hash256, bytes: &[u8]) {
        let Some(blocks) = &self.failure_blocks else {
            return;
        };
        match blocks.save(Some(height), hash, bytes) {
            Ok(path) => eprintln!("  saved failing block to {}", path.display()),
            Err(e) => eprintln!(
                "  warning: could not save failing block {}: {e}",
                height.to_u32()
            ),
        }
    }

    fn save_block(&self, height: BlockHeight, hash: Hash256, block: &Block) {
        use mantle::codec::Encode;
        let mut bytes = Vec::new();
        if block.encode(&mut bytes).is_ok() {
            self.save_failed_block(height, hash, &bytes);
        }
    }

    fn fail(
        &mut self,
        height: BlockHeight,
        hash: Hash256,
        stage: FailureStage,
        error: &dyn std::fmt::Display,
    ) -> Result<(), String> {
        match &mut self.failures {
            Some(log) => {
                log.record(height, hash, stage, error);
                Ok(())
            }
            None => Err(format!("{stage} check at {}: {error}", height.to_u32())),
        }
    }

    fn check_utxo_hash(&mut self, height: BlockHeight, hash: Hash256) -> Result<(), String> {
        let Some(tracker) = &mut self.utxo_hash else {
            return Ok(());
        };
        let current = if tracker.wants(height) {
            self.pipeline.utxo_hash().map(|h| h.finalize())
        } else {
            None
        };
        match tracker.after_block(height, current) {
            UtxoHashVerdict::NotChecked => Ok(()),
            UtxoHashVerdict::Match(muhash) => {
                eprintln!("  utxo hash matches at height {}: {muhash}", height.to_u32());
                Ok(())
            }
            UtxoHashVerdict::Mismatch { expected, actual } => self.fail(
                height,
                hash,
                FailureStage::UtxoHash,
                &format!("UTXO set MuHash {actual}, Bitcoin Core reports {expected}"),
            ),
        }
    }

    pub fn summarize_failures(&self) -> u64 {
        if let Some(tracker) = &self.utxo_hash {
            tracker.print_summary();
        }
        self.failures.as_ref().map_or(0, |log| {
            log.print_summary();
            log.total()
        })
    }
}
