use std::path::PathBuf;

use mantle_validator::InFlightLimit;

use crate::chain_spec::ChainSpec;
use crate::seeded_storage::SeededStorage;

pub struct BenchArgs {
    pub spec: ChainSpec,
    pub script_threads: usize,
    pub filler_coins: usize,
    pub sync_every: u32,
    pub sync_without_fsync: bool,
    pub skip_scripts: bool,
    pub limit: InFlightLimit,
    pub store_root: PathBuf,
    pub generate_only: bool,
}

impl BenchArgs {
    const HELP: &'static str = "usage: pipeline-bench [--blocks N] [--txs N] [--inputs N] [--outputs N] \
         [--segwit-percent P] [--recent-percent P] [--script-threads N] [--filler-coins N] \
         [--sync-every N] [--no-fsync] [--skip-scripts] [--in-flight-blocks N] [--in-flight-inputs N] \
         [--store-dir DIR] [--generate-only]";

    /// # Errors
    /// Returns a message for an unknown flag, a missing or bad value, or a
    /// chain shape `ChainSpec::check` rejects.
    pub fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut spec = ChainSpec {
            blocks: 300,
            txs_per_block: 500,
            inputs_per_tx: 2,
            outputs_per_tx: 2,
            segwit_percent: 50,
            recent_spend_percent: 10,
        };
        let mut script_threads = std::thread::available_parallelism()
            .map_or(1, |n| n.get().saturating_sub(1));
        let mut filler_coins = 0;
        let mut sync_every = 0;
        let mut skip_scripts = false;
        let mut sync_without_fsync = false;
        let mut limit = InFlightLimit::default();
        let mut store_root = SeededStorage::default_root();
        let mut generate_only = false;
        while let Some(flag) = args.next() {
            if flag == "--generate-only" {
                generate_only = true;
                continue;
            }
            if flag == "--skip-scripts" {
                skip_scripts = true;
                continue;
            }
            if flag == "--no-fsync" {
                sync_without_fsync = true;
                continue;
            }
            if flag == "--help" || flag == "-h" {
                return Err(Self::HELP.to_string());
            }
            let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
            if flag == "--store-dir" {
                store_root = PathBuf::from(value);
                continue;
            }
            let number = |v: &str| v.parse::<usize>().map_err(|e| format!("{flag} {v}: {e}"));
            match flag.as_str() {
                "--blocks" => spec.blocks = u32::try_from(number(&value)?).map_err(|e| e.to_string())?,
                "--txs" => spec.txs_per_block = number(&value)?,
                "--inputs" => spec.inputs_per_tx = number(&value)?,
                "--outputs" => spec.outputs_per_tx = number(&value)?,
                "--segwit-percent" => {
                    spec.segwit_percent = u32::try_from(number(&value)?).map_err(|e| e.to_string())?;
                }
                "--recent-percent" => {
                    spec.recent_spend_percent =
                        u32::try_from(number(&value)?).map_err(|e| e.to_string())?;
                }
                "--script-threads" => script_threads = number(&value)?,
                "--filler-coins" => filler_coins = number(&value)?,
                "--in-flight-blocks" => limit.blocks = number(&value)?,
                "--in-flight-inputs" => limit.inputs = number(&value)?,
                "--sync-every" => {
                    sync_every = u32::try_from(number(&value)?).map_err(|e| e.to_string())?;
                }
                other => return Err(format!("unknown flag {other}\n{}", Self::HELP)),
            }
        }
        spec.check()?;
        Ok(Self {
            spec,
            script_threads,
            filler_coins,
            sync_every,
            sync_without_fsync,
            skip_scripts,
            limit,
            store_root,
            generate_only,
        })
    }
}
