use std::io::Cursor;
use std::time::{Duration, Instant};

use mantle::codec::Decode;
use mantle::collections::{BuildPrehashedHasher, PrehashedMap};
use mantle::primitives::{Block, BlockHeight};
use mantle_consensus::validation::{
    FixedClock, validate_block_context_with_clock, validate_block_structure,
};
use mantle_storage::types::{Durability, ReqToken};
use mantle_validator::{
    BlockJob, ConnectPipeline, Connected, HeaderSnapshot, PrefetchedView, Retired, ScriptPool,
    Verdict, Wait,
};

use crate::bench_args::BenchArgs;
use crate::chain_spec::ChainSpec;
use crate::cpu_meter::CpuMeter;
use crate::seeded_storage::SeededStorage;
use crate::synthetic_chain::SyntheticChain;

#[derive(Default)]
struct StageTimes {
    decode: Duration,
    checks: Duration,
    connect: Duration,
    retire: Duration,
}

/// Replays a synthetic chain through the calls `mantle-replay` makes per
/// block and reports throughput and CPU use per thread group.
pub struct ReplayDriver {
    snapshot: HeaderSnapshot,
    storage: SeededStorage,
    pipeline: ConnectPipeline,
    clock: FixedClock,
    sync_every: u32,
    boundary: Durability,
    times: StageTimes,
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
        let storage =
            SeededStorage::open(&args.store_root, &args.spec, &chain.history, args.filler_coins)?;
        let pool = ScriptPool::new(args.script_threads).map_err(|e| e.to_string())?;
        let mut pipeline =
            ConnectPipeline::new(pool, storage.handle.tip(), args.limit);
        if args.skip_scripts {
            pipeline = pipeline.skip_scripts();
        }
        let mut driver = Self {
            snapshot,
            storage,
            pipeline,
            clock: FixedClock(u64::from(ChainSpec::time_at(args.spec.last_height()))),
            sync_every: args.sync_every,
            boundary: if args.sync_without_fsync {
                Durability::Flushed
            } else {
                Durability::Synced
            },
            times: StageTimes::default(),
        };
        let inputs = args.spec.inputs_per_block() * chain.blocks.len();
        println!(
            "replaying {} blocks, {} inputs, {} script workers, up to {} blocks in flight",
            chain.blocks.len(),
            inputs,
            driver.pipeline.workers(),
            args.limit.blocks
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
        let t = &driver.times;
        println!(
            "main thread: decode {:.2}s, structure+context {:.2}s, connect {:.2}s, retire+commit {:.2}s",
            t.decode.as_secs_f64(),
            t.checks.as_secs_f64(),
            t.connect.as_secs_f64(),
            t.retire.as_secs_f64()
        );
        let busy = driver.pipeline.script_busy();
        let workers = driver.pipeline.workers().max(1) as f64;
        println!(
            "script checks: workers ran {:.2}s ({:.1}% of their wall time), main thread ran {:.2}s",
            busy.workers.as_secs_f64(),
            100.0 * busy.workers.as_secs_f64() / secs / workers,
            busy.owner.as_secs_f64()
        );
        let own = report.main_thread().saturating_sub(busy.owner);
        println!(
            "main thread own work: {:.2}s cpu = {:.2} us/input (the ceiling once scripts keep up)",
            own.as_secs_f64(),
            own.as_secs_f64() * 1e6 / inputs as f64
        );
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
            self.times.decode += started.elapsed();
            self.block(block, height)?;
            self.retire(Wait::IfOverLimit)?;
        }
        self.retire(Wait::Always)
    }

    fn block(&mut self, block: Block, height: BlockHeight) -> Result<(), String> {
        let at = height.to_u32();
        let started = Instant::now();
        validate_block_structure(&block).map_err(|e| format!("structure at {at}: {e}"))?;
        let empty = PrehashedMap::with_hasher(BuildPrehashedHasher);
        let view = PrefetchedView::new(&empty, &self.snapshot, self.pipeline.tip().clone());
        validate_block_context_with_clock(&block, &view, &self.clock, false)
            .map_err(|e| format!("context at {at}: {e}"))?;
        let job = BlockJob::new(block, height, self.durability(at), ReqToken(u64::from(at)));
        self.times.checks += started.elapsed();
        let started = Instant::now();
        let connected = self
            .pipeline
            .connect(job, &mut self.storage.handle, &self.snapshot)
            .map_err(|e| format!("storage at {at}: {e}"))?;
        self.times.connect += started.elapsed();
        match connected {
            Connected::Queued => Ok(()),
            Connected::Rejected { error, .. } => Err(format!("connect at {at}: {error}")),
        }
    }

    fn retire(&mut self, wait: Wait) -> Result<(), String> {
        let started = Instant::now();
        while let Some(retired) = self
            .pipeline
            .retire_next(&mut self.storage.handle, wait)
            .map_err(|e| format!("commit: {e}"))?
        {
            Self::check(&retired)?;
        }
        self.times.retire += started.elapsed();
        Ok(())
    }

    fn check(retired: &Retired) -> Result<(), String> {
        match &retired.verdict {
            Verdict::Valid => Ok(()),
            other => Err(format!(
                "block {} retired as {other:?}",
                retired.height.to_u32()
            )),
        }
    }

    fn durability(&self, height: u32) -> Durability {
        if self.sync_every > 0 && height.is_multiple_of(self.sync_every) {
            self.boundary
        } else {
            Durability::Memory
        }
    }
}
