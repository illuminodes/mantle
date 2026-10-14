use std::sync::Arc;
use std::time::{Duration, Instant};

use mantle::primitives::{BlockHeader, BlockHeight};
use mantle_consensus::validation::FixedClock;
use mantle_storage::types::Durability;
use mantle_validator::{
    BlockPreparer, CommitPlan, ConnectPipeline, Connected, PrepPool, Prepared, RawBlock, Retired,
    ScriptPool, Verdict, Wait,
};

use crate::bench_args::BenchArgs;
use crate::chain_spec::ChainSpec;
use crate::cpu_meter::CpuMeter;
use crate::seeded_storage::SeededStorage;
use crate::synthetic_chain::SyntheticChain;

#[derive(Default)]
struct StageTimes {
    prepared: Duration,
    connect: Duration,
    retire: Duration,
}

/// Replays a synthetic chain through the same pipeline `mantle-replay`
/// uses and reports throughput and CPU use per thread group.
pub struct ReplayDriver {
    storage: SeededStorage,
    pipeline: ConnectPipeline,
    prep: PrepPool,
    snapshot: Arc<mantle_validator::HeaderSnapshot>,
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
        let snapshot = Arc::new(SeededStorage::snapshot(&chain));
        let storage =
            SeededStorage::open(&args.store_root, &args.spec, &chain.history, args.filler_coins)?;
        let pool = ScriptPool::new(args.script_threads).map_err(|e| e.to_string())?;
        let mut pipeline = ConnectPipeline::new(pool, storage.handle.tip(), args.limit);
        if args.skip_scripts {
            pipeline = pipeline.skip_scripts();
        }
        let commits = CommitPlan {
            every: args.sync_every,
            boundary: if args.sync_without_fsync {
                Durability::Flushed
            } else {
                Durability::Synced
            },
        };
        let preparer = BlockPreparer::new(
            Arc::clone(&snapshot),
            FixedClock(u64::from(ChainSpec::time_at(args.spec.last_height()))),
            false,
            commits,
        );
        let prep = PrepPool::new(
            preparer,
            args.prep_threads,
            args.prep_depth,
            BlockHeight::new(ChainSpec::FIRST_HEIGHT),
        )
        .map_err(|e| e.to_string())?;
        let mut driver = Self {
            storage,
            pipeline,
            prep,
            snapshot,
            times: StageTimes::default(),
        };
        let inputs = args.spec.inputs_per_block() * chain.blocks.len();
        println!(
            "replaying {} blocks, {} inputs, {} script workers, {} prep threads, up to {} blocks in flight",
            chain.blocks.len(),
            inputs,
            driver.pipeline.workers(),
            args.prep_threads,
            args.limit.blocks
        );
        let meter = CpuMeter::start();
        let started = Instant::now();
        let result = driver.replay(&chain);
        let wall = started.elapsed();
        let report = meter.finish();
        drop(driver.prep);
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
            "main thread: waiting for prepared blocks {:.2}s, connect {:.2}s, retire+commit {:.2}s",
            t.prepared.as_secs_f64(),
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
            "main thread own work: {:.2}s cpu = {:.2} us/input",
            own.as_secs_f64(),
            own.as_secs_f64() * 1e6 / inputs as f64
        );
        report.print();
        Ok(())
    }

    fn replay(&mut self, chain: &SyntheticChain) -> Result<(), String> {
        let mut feed = chain.blocks.iter().enumerate();
        loop {
            while self.prep.has_room() {
                let Some((offset, bytes)) = feed.next() else { break };
                let height = ChainSpec::FIRST_HEIGHT + u32::try_from(offset).map_err(|e| e.to_string())?;
                let header = BlockHeader::from_bytes(
                    bytes[..BlockHeader::ENCODED_LEN]
                        .try_into()
                        .map_err(|_| "short block".to_string())?,
                );
                self.prep.submit(RawBlock {
                    height: BlockHeight::new(height),
                    hash: header.hash(),
                    bytes: bytes.clone(),
                });
            }
            let started = Instant::now();
            let Some(prepared) = self.prep.take_next() else { break };
            self.times.prepared += started.elapsed();
            let job = match prepared? {
                Prepared::Ready(job) => job,
                Prepared::Invalid { job, failures } => {
                    return Err(format!(
                        "block {} failed {failures:?}",
                        job.height.to_u32()
                    ));
                }
            };
            let at = job.height.to_u32();
            let started = Instant::now();
            let connected = self
                .pipeline
                .connect(job, &mut self.storage.handle, &self.snapshot)
                .map_err(|e| format!("storage at {at}: {e}"))?;
            self.times.connect += started.elapsed();
            if let Connected::Rejected { error, .. } = connected {
                return Err(format!("connect at {at}: {error}"));
            }
            self.retire(Wait::IfOverLimit)?;
        }
        self.retire(Wait::Always)
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
}
