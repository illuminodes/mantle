use std::io::Cursor;
use std::time::Instant;

use mantle::codec::Decode;
use mantle::collections::{BuildPrehashedHasher, PrehashedMap};
use mantle::primitives::{Block, BlockHeight};
use mantle_consensus::validation::{
    FixedClock, validate_block_context_with_clock, validate_block_structure,
};
use mantle_storage::types::{Durability, ReqToken};
use mantle_validator::{
    DeferredBlock, DeferredOpts, DeferredScripts, HeaderSnapshot, PrefetchedView, ReplayBufs,
    ScriptPool,
};

use crate::bench_args::BenchArgs;
use crate::chain_spec::ChainSpec;
use crate::cpu_meter::CpuMeter;
use crate::seeded_storage::SeededStorage;
use crate::synthetic_chain::SyntheticChain;

/// Replays a synthetic chain through the same calls `mantle-replay` makes
/// per block and reports throughput and CPU use per thread group.
pub struct ReplayDriver {
    snapshot: HeaderSnapshot,
    storage: SeededStorage,
    bufs: ReplayBufs,
    scripts: DeferredScripts,
    clock: FixedClock,
    sync_every: u32,
    synced_time: std::time::Duration,
    synced_blocks: u32,
    decode_time: std::time::Duration,
    checks_time: std::time::Duration,
    connect_time: std::time::Duration,
}

impl ReplayDriver {
    /// # Errors
    /// Returns a message on any I/O, setup or consensus failure.
    pub fn run(args: &BenchArgs) -> Result<(), String> {
        let chain = SyntheticChain::load_or_generate(&args.spec).map_err(|e| e.to_string())?;
        if args.generate_only {
            return Ok(());
        }
        let snapshot = SeededStorage::snapshot(&chain);
        let storage = SeededStorage::open(&args.spec, &chain.history, args.filler_coins)?;
        let pool = ScriptPool::new(args.script_threads).map_err(|e| e.to_string())?;
        let mut driver = Self {
            snapshot,
            storage,
            bufs: ReplayBufs::new(),
            scripts: DeferredScripts::new(pool),
            clock: FixedClock(u64::from(ChainSpec::time_at(args.spec.last_height()))),
            sync_every: args.sync_every,
            synced_time: std::time::Duration::ZERO,
            synced_blocks: 0,
            decode_time: std::time::Duration::ZERO,
            checks_time: std::time::Duration::ZERO,
            connect_time: std::time::Duration::ZERO,
        };
        let inputs = args.spec.inputs_per_block() * chain.blocks.len();
        println!(
            "replaying {} blocks, {} inputs, {} script workers",
            chain.blocks.len(),
            inputs,
            driver.scripts.workers()
        );
        let meter = CpuMeter::start();
        let started = Instant::now();
        let result = driver.replay(&chain);
        let wall = started.elapsed();
        let report = meter.finish();
        driver.storage.close();
        result?;
        let secs = wall.as_secs_f64();
        println!(
            "wall {secs:.2}s  {:.1} blocks/s  {:.0} inputs/s",
            chain.blocks.len() as f64 / secs,
            inputs as f64 / secs
        );
        println!(
            "main thread: decode {:.2}s, structure+context {:.2}s, connect+commit {:.2}s",
            driver.decode_time.as_secs_f64(),
            driver.checks_time.as_secs_f64(),
            driver.connect_time.as_secs_f64()
        );
        if driver.synced_blocks > 0 {
            println!(
                "{} synced blocks took {:.2}s of the wall time",
                driver.synced_blocks,
                driver.synced_time.as_secs_f64()
            );
        }
        report.print();
        Ok(())
    }

    fn replay(&mut self, chain: &SyntheticChain) -> Result<(), String> {
        for (offset, bytes) in chain.blocks.iter().enumerate() {
            let height = BlockHeight::new(
                ChainSpec::FIRST_HEIGHT + u32::try_from(offset).map_err(|e| e.to_string())?,
            );
            let started = Instant::now();
            let block = Block::decode(&mut Cursor::new(bytes)).map_err(|e| e.to_string())?;
            self.decode_time += started.elapsed();
            self.block(block, height)?;
        }
        Self::settled(self.scripts.settle())
    }

    fn block(&mut self, block: Block, height: BlockHeight) -> Result<(), String> {
        let at = height.to_u32();
        let checks_started = Instant::now();
        validate_block_structure(&block).map_err(|e| format!("structure at {at}: {e}"))?;
        let empty = PrehashedMap::with_hasher(BuildPrehashedHasher);
        let view = PrefetchedView::new(&empty, &self.snapshot, self.storage.handle.tip());
        validate_block_context_with_clock(&block, &view, &self.clock, false)
            .map_err(|e| format!("context at {at}: {e}"))?;
        self.checks_time += checks_started.elapsed();
        let durability = self.durability(at);
        let started = Instant::now();
        let step = self.bufs.validate_and_commit_deferred(
            block,
            height,
            &mut self.storage.handle,
            &self.snapshot,
            &mut self.scripts,
            DeferredOpts {
                durability,
                token: ReqToken(u64::from(at)),
                utxo_hash: None,
            },
        );
        self.connect_time += started.elapsed();
        if durability == Durability::Synced {
            self.synced_time += started.elapsed();
            self.synced_blocks += 1;
        }
        Self::settled(step.previous)?;
        match step.current {
            DeferredBlock::Committed(_) => Ok(()),
            DeferredBlock::Rejected { error, .. } => Err(format!("connect at {at}: {error}")),
        }
    }

    fn durability(&self, height: u32) -> Durability {
        if self.sync_every > 0 && height.is_multiple_of(self.sync_every) {
            Durability::Synced
        } else {
            Durability::Memory
        }
    }

    fn settled(settled: Option<mantle_validator::SettledScripts>) -> Result<(), String> {
        match settled {
            Some(s) if s.verdict.is_err() => Err(format!(
                "scripts at {}: {}",
                s.height.to_u32(),
                s.verdict.expect_err("checked is_err")
            )),
            _ => Ok(()),
        }
    }
}
