use std::path::PathBuf;

use mantle::primitives::{CompactBits, Hash256, OutPoint, Satoshi};

use crate::keyring::Keyring;
use crate::spendable_coin::{CoinKind, SpendableCoin};

/// The shape of a synthetic chain.
///
/// Heights sit past every mainnet soft fork, so blocks are checked with the
/// full script flag set, and inside one difficulty period, so every header
/// carries the easy regtest target without a retarget.
#[derive(Clone, Copy, Debug)]
pub struct ChainSpec {
    pub blocks: u32,
    pub txs_per_block: usize,
    pub inputs_per_tx: usize,
    pub outputs_per_tx: usize,
    pub segwit_percent: u32,
    pub recent_spend_percent: u32,
}

impl ChainSpec {
    pub const FIRST_HEIGHT: u32 = 800_353;
    pub const BITS: CompactBits = CompactBits::new(0x207f_ffff);
    pub const FIRST_TIME: u32 = 1_700_000_000;
    pub const SPACING: u32 = 600;
    pub const HISTORY: u32 = 11;
    pub const SEED_VALUE: u64 = 100_000;
    pub const SEED_HEIGHT: u32 = Self::FIRST_HEIGHT - 1;
    const RETARGET_INTERVAL: u32 = 2016;

    pub fn last_height(&self) -> u32 {
        Self::FIRST_HEIGHT + self.blocks - 1
    }

    pub fn inputs_per_block(&self) -> usize {
        self.txs_per_block * self.inputs_per_tx
    }

    pub fn time_at(height: u32) -> u32 {
        Self::FIRST_TIME + (height + Self::HISTORY - Self::FIRST_HEIGHT) * Self::SPACING
    }

    /// Enough coins for every input to spend a seed coin.
    pub fn seed(&self) -> Vec<SpendableCoin> {
        let count = self.inputs_per_block() * self.blocks as usize;
        (0..count as u64)
            .map(|i| SpendableCoin {
                outpoint: OutPoint {
                    txid: Hash256::hash(&i.to_le_bytes()),
                    vout: 0,
                },
                value: Satoshi::new(Self::SEED_VALUE),
                key: usize::try_from(i).expect("seed index fits usize") % Keyring::SIZE,
                kind: CoinKind::pick(i, self.segwit_percent),
            })
            .collect()
    }

    /// # Errors
    /// Returns a message when the chain would cross a retarget height or
    /// a block would be empty.
    pub fn check(&self) -> Result<(), String> {
        let first_period = Self::FIRST_HEIGHT / Self::RETARGET_INTERVAL;
        if self.blocks == 0 || self.last_height() / Self::RETARGET_INTERVAL != first_period {
            return Err(format!(
                "--blocks must be 1..={} to stay inside one difficulty period",
                (first_period + 1) * Self::RETARGET_INTERVAL - Self::FIRST_HEIGHT
            ));
        }
        if self.outputs_per_tx == 0 || self.inputs_per_tx == 0 || self.txs_per_block == 0 {
            return Err("txs, inputs and outputs per block must be positive".to_string());
        }
        Ok(())
    }

    pub fn cache_path(&self) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../data/synthetic-chains")
            .join(format!(
                "b{}-t{}-i{}-o{}-sw{}-r{}.bin",
                self.blocks,
                self.txs_per_block,
                self.inputs_per_tx,
                self.outputs_per_tx,
                self.segwit_percent,
                self.recent_spend_percent
            ))
    }
}
