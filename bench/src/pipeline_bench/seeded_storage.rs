use std::path::PathBuf;

use mantle::primitives::{BlockHeader, BlockHeight, Hash256, OutPoint, Satoshi};
use mantle_consensus::chain_view::NewCoin;
use mantle_storage::StorageHandle;
use mantle_storage::types::{CommitBlockReq, Durability, ReqToken};
use mantle_validator::HeaderSnapshot;

use crate::chain_spec::ChainSpec;
use crate::keyring::Keyring;
use crate::synthetic_chain::SyntheticChain;

/// A fresh Robin Hood store holding the coins the synthetic chain spends,
/// plus filler coins nothing spends, so lookups search a table the size of
/// a real UTXO set. Everything is flushed to disk before the replay starts.
pub struct SeededStorage {
    pub handle: StorageHandle<'static>,
    dir: PathBuf,
}

impl SeededStorage {
    const FILLER_BATCH: usize = 1_000_000;
    const FILLER_SCRIPT: [u8; 22] = [0x00, 0x14, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab];

    pub fn default_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../data/pipeline-bench")
    }

    /// # Errors
    /// Returns a message when the store cannot be created or seeded.
    pub fn open(
        root: &std::path::Path,
        spec: &ChainSpec,
        history: &[BlockHeader],
        filler: usize,
    ) -> Result<Self, String> {
        let dir = root.join(format!("store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let mut handle = StorageHandle::open_robin_hood(&dir).map_err(|e| format!("open: {e}"))?;
        let started = std::time::Instant::now();
        let history_base = ChainSpec::FIRST_HEIGHT - ChainSpec::HISTORY;
        let batches = filler.div_ceil(Self::FILLER_BATCH);
        let mut placed = 0;
        for (batch, header) in history.iter().take(history.len() - 1).enumerate() {
            let count = if batch < batches {
                Self::FILLER_BATCH.min(filler - placed)
            } else {
                0
            };
            let filler_coins = Self::filler(placed, count);
            placed += count;
            let height = BlockHeight::new(history_base + u32::try_from(batch).expect("fits"));
            Self::commit(&mut handle, height, header, &filler_coins, Durability::Synced)?;
        }
        if placed < filler {
            return Err(format!(
                "at most {} filler coins fit in the history headers",
                (history.len() - 1) * Self::FILLER_BATCH
            ));
        }
        let keys = Keyring::new();
        let seed = spec.seed();
        let scripts: Vec<Vec<u8>> = seed.iter().map(|c| c.script_pubkey(&keys)).collect();
        let created: Vec<NewCoin<'_>> = seed
            .iter()
            .zip(&scripts)
            .map(|(coin, script)| NewCoin {
                outpoint: coin.outpoint,
                value: coin.value,
                script_pubkey: script,
                coinbase: false,
                height: BlockHeight::new(ChainSpec::SEED_HEIGHT),
            })
            .collect();
        let tip = history.last().expect("history is not empty");
        Self::commit(
            &mut handle,
            BlockHeight::new(ChainSpec::SEED_HEIGHT),
            tip,
            &created,
            Durability::Synced,
        )?;
        eprintln!(
            "seeded {} spendable and {filler} filler coins in {:.1}s at {}",
            seed.len(),
            started.elapsed().as_secs_f64(),
            dir.display()
        );
        Ok(Self { handle, dir })
    }

    fn filler(start: usize, count: usize) -> Vec<NewCoin<'static>> {
        (start..start + count)
            .map(|i| NewCoin {
                outpoint: OutPoint {
                    txid: Hash256::hash(&(i as u64 | 1 << 63).to_le_bytes()),
                    vout: u32::try_from(i % 3).expect("small"),
                },
                value: Satoshi::new(546),
                script_pubkey: &Self::FILLER_SCRIPT,
                coinbase: false,
                height: BlockHeight::new(1),
            })
            .collect()
    }

    fn commit(
        handle: &mut StorageHandle<'static>,
        height: BlockHeight,
        header: &BlockHeader,
        created: &[NewCoin<'_>],
        durability: Durability,
    ) -> Result<(), String> {
        handle
            .commit_block_borrowed(CommitBlockReq {
                token: ReqToken(u64::from(height.to_u32())),
                height,
                hash: header.hash(),
                prev_hash: header.prev_block(),
                header: *header,
                created,
                spent: &[],
                block_bytes: None,
                durability,
            })
            .map(|_| ())
            .map_err(|e| format!("seed commit at {}: {e}", height.to_u32()))
    }

    /// # Panics
    /// Panics if a block is shorter than a header, which generated blocks never are.
    pub fn snapshot(chain: &SyntheticChain) -> HeaderSnapshot {
        let mut entries: Vec<(Hash256, BlockHeader)> = chain
            .history
            .iter()
            .map(|h| (h.hash(), *h))
            .collect();
        for bytes in &chain.blocks {
            let raw: [u8; BlockHeader::ENCODED_LEN] = bytes[..BlockHeader::ENCODED_LEN]
                .try_into()
                .expect("block holds a header");
            let header = BlockHeader::from_bytes(raw);
            entries.push((header.hash(), header));
        }
        HeaderSnapshot::new(
            BlockHeight::new(ChainSpec::FIRST_HEIGHT - ChainSpec::HISTORY),
            entries,
        )
        .expect("snapshot fits")
    }

    pub fn close(self) {
        let _ = self.handle.shutdown();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
