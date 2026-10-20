use std::time::Instant;

use mantle::codec::Encode;
use mantle::primitives::{Block, BlockHeader, BlockHeight, Hash256};
use mantle_consensus::error::ValidationError;
use mantle_storage::StorageHandle;
use mantle_validator::{
    BlockJob, ConnectPipeline, Connected, HeaderSnapshot, PrepCheck, PrepPool, Prepared, RawBlock,
    Retired, Verdict, Wait,
};

use mantle_fetcher::{AdmitAll, BlockFeed, FeedItem};
use crate::failures::{FailureLog, FailureStage};
use crate::report::Reporter;
use crate::stage_clock::{Stage, StageClock};
use crate::window_meter::WindowMeter;
use mantle_replay::block_files::BlockFiles;
use mantle_replay::utxo_hash_check::{UtxoHashTracker, UtxoHashVerdict};

/// Drives blocks from the feed through preparation and the connect pipeline.
///
/// Prep threads decode and check blocks ahead of the one being connected;
/// this thread connects them in height order and commits each once its
/// scripts pass. Blocks reach storage, the failure log and the UTXO hash
/// tracker in height order.
pub struct ReplayLoop {
    pub storage: StorageHandle<'static>,
    pub pipeline: ConnectPipeline,
    pub prep: PrepPool,
    pub failures: Option<FailureLog>,
    pub failure_blocks: Option<BlockFiles>,
    pub utxo_hash: Option<UtxoHashTracker>,
    pub clock: StageClock,
    last_committed: BlockHeight,
}

impl ReplayLoop {
    #[must_use]
    pub fn new(storage: StorageHandle<'static>, pipeline: ConnectPipeline, prep: PrepPool) -> Self {
        let tip = storage.tip().height;
        Self {
            storage,
            pipeline,
            prep,
            failures: None,
            failure_blocks: None,
            utxo_hash: None,
            clock: StageClock::default(),
            last_committed: tip,
        }
    }

    /// Replay every block in `header_pairs`, logging stage times every
    /// `window` blocks, and return the height storage ends at.
    ///
    /// # Errors
    /// A message on a feed or storage failure, or on the first consensus
    /// failure without `--keep-going`.
    pub fn run(
        &mut self,
        header_pairs: &[(BlockHeight, BlockHeader)],
        window: usize,
        feed: &mut BlockFeed<AdmitAll>,
        snapshot: &HeaderSnapshot,
        reporter: &mut Reporter,
    ) -> Result<BlockHeight, String> {
        let mut to_submit = header_pairs.iter();
        let mut meter = WindowMeter::start(&self.pipeline);
        for chunk in header_pairs.chunks(window) {
            for _ in chunk {
                self.fill_prep(feed, &mut to_submit)?;
                let prepared = self
                    .clock
                    .time(Stage::Decode, || self.prep.take_next())
                    .ok_or("prep pool ran dry before the last header")??;
                self.connect(prepared, snapshot)?;
                self.retire(Wait::IfOverLimit, reporter)?;
                if self.pipeline.is_stopped() {
                    return Ok(self.last_committed);
                }
            }
            if chunk.last() == header_pairs.last() {
                self.retire(Wait::Always, reporter)?;
            }
            eprintln!(
                "  window {}..={}: {}, {} blocks in flight; {}",
                chunk[0].0.to_u32(),
                chunk[chunk.len() - 1].0.to_u32(),
                self.clock.take_line(),
                self.pipeline.in_flight(),
                meter.take_line(&self.pipeline),
            );
        }
        Ok(self.last_committed)
    }

    /// Keep the prep threads fed with downloaded blocks.
    fn fill_prep<'h>(
        &mut self,
        feed: &mut BlockFeed<AdmitAll>,
        headers: &mut impl Iterator<Item = &'h (BlockHeight, BlockHeader)>,
    ) -> Result<(), String> {
        while self.prep.has_room() {
            let Some(&(height, _)) = headers.next() else {
                return Ok(());
            };
            let block = loop {
                match self.clock.time(Stage::Wait, || feed.next_item()) {
                    Some(FeedItem::Block(block)) => break block,
                    Some(FeedItem::WindowDone { first, last, elapsed }) => eprintln!(
                        "  downloaded {}..={} in {:.1}s",
                        first.to_u32(),
                        last.to_u32(),
                        elapsed.as_secs_f64()
                    ),
                    Some(FeedItem::Failed(e)) => return Err(e),
                    Some(FeedItem::Headers(..) | FeedItem::Survey(_) | FeedItem::Done) | None => {
                        return Err(format!("block feed ended before height {}", height.to_u32()));
                    }
                }
            };
            if block.height != height {
                return Err(format!(
                    "block feed sent height {}, expected {}",
                    block.height.to_u32(),
                    height.to_u32()
                ));
            }
            self.prep.submit(RawBlock {
                height: block.height,
                hash: block.hash,
                bytes: block.bytes,
            });
        }
        Ok(())
    }

    fn connect(&mut self, prepared: Prepared, snapshot: &HeaderSnapshot) -> Result<(), String> {
        let job = match prepared {
            Prepared::Ready(job) => job,
            Prepared::Invalid { job, failures } => {
                self.save_block(job.height, job.hash, &job.block);
                for (check, error) in &failures {
                    let stage = match check {
                        PrepCheck::Structure => FailureStage::Structure,
                        PrepCheck::Context => FailureStage::Context,
                    };
                    self.fail(job.height, job.hash, stage, error)?;
                }
                return self.force(job);
            }
        };
        let (height, hash) = (job.height, job.hash);
        let started = Instant::now();
        let next = self.prep.peek_ready();
        let connected = self
            .pipeline
            .connect(job, next, &mut self.storage, snapshot)
            .map_err(|e| format!("lookup at {}: {e}", height.to_u32()))?;
        self.clock.add(Stage::Validate, started);
        match connected {
            Connected::Queued => Ok(()),
            Connected::Rejected { error, job } => {
                self.save_block(height, hash, &job.block);
                self.fail(height, hash, FailureStage::Connect, &error)?;
                self.force(*job)
            }
        }
    }

    fn force(&mut self, job: BlockJob) -> Result<(), String> {
        let height = job.height;
        self.stop_utxo_hash(height);
        self.pipeline
            .force(Box::new(job))
            .map_err(|e: ValidationError| format!("forced commit at {}: {e}", height.to_u32()))
    }

    fn retire(&mut self, wait: Wait, reporter: &mut Reporter) -> Result<(), String> {
        loop {
            let started = Instant::now();
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
            self.stop_utxo_hash(height);
            self.fail(height, hash, FailureStage::Connect, error)?;
        }
        if !committed {
            return Ok(());
        }
        self.last_committed = height;
        reporter.tick(height);
        self.check_utxo_hash(height, hash)
    }

    fn stop_utxo_hash(&mut self, height: BlockHeight) {
        self.pipeline.stop_utxo_hash();
        if let Some(tracker) = &mut self.utxo_hash {
            tracker.stop(height);
        }
    }

    fn save_block(&self, height: BlockHeight, hash: Hash256, block: &Block) {
        let Some(blocks) = &self.failure_blocks else {
            return;
        };
        let mut bytes = Vec::new();
        if let Err(e) = block.encode(&mut bytes) {
            eprintln!("  warning: could not encode failing block {}: {e}", height.to_u32());
            return;
        }
        match blocks.save(Some(height), hash, &bytes) {
            Ok(path) => eprintln!("  saved failing block to {}", path.display()),
            Err(e) => eprintln!(
                "  warning: could not save failing block {}: {e}",
                height.to_u32()
            ),
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
