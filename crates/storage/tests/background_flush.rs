use std::collections::HashMap;
use std::path::{Path, PathBuf};

use mantle::primitives::{
    BlockHeader, BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Nonce, OutPoint,
    Satoshi,
};
use mantle_consensus::chain_view::NewCoin;
use mantle_storage::engine::robin_hood::RobinHoodEngine;
use mantle_storage::engine::Engine;
use mantle_storage::{with_storage, CommitBlockReq, Durability, ReqToken};

struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(name: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let path = std::env::temp_dir().join(format!(
            "mantle-bg-flush-{name}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A chain whose blocks create coins and spend older ones, tracking which
/// coins must be live.
struct Chain {
    live: HashMap<OutPoint, u64>,
    order: Vec<OutPoint>,
    prev_hash: Hash256,
}

const SPK: [u8; 1] = [0x51];

impl Chain {
    fn new() -> Self {
        Self {
            live: HashMap::new(),
            order: Vec::new(),
            prev_hash: Hash256::ZERO,
        }
    }

    fn block_hash(height: u32) -> Hash256 {
        Hash256::hash(&(height + 7_000_000).to_le_bytes())
    }

    fn header(&self, height: u32) -> BlockHeader {
        let mut header = BlockHeader::new(
            BlockVersion::new(1),
            Hash256::ZERO,
            Hash256::ZERO,
            BlockTime::new(height),
            CompactBits::new(0x1d00_ffff),
            Nonce::new(0),
        );
        header.set_prev_block(self.prev_hash);
        header
    }

    fn created(height: u32, per_block: u32) -> Vec<(OutPoint, u64)> {
        (0..per_block)
            .map(|vout| {
                let op = OutPoint {
                    txid: Hash256::hash(&height.to_le_bytes()),
                    vout,
                };
                (op, u64::from(height) * 100 + u64::from(vout))
            })
            .collect()
    }

    fn spends(&self, height: u32) -> Vec<OutPoint> {
        if self.order.len() < 16 {
            return Vec::new();
        }
        let n = self.order.len();
        let mut picks: Vec<OutPoint> = [n / 7, n / 3, n / 2, n - 2]
            .iter()
            .map(|&i| self.order[(i + height as usize) % n])
            .filter(|op| self.live.contains_key(op))
            .collect();
        picks.sort_by_key(|op| (*op.txid.as_bytes(), op.vout));
        picks.dedup();
        picks
    }

    fn apply(&mut self, created: &[(OutPoint, u64)], spent: &[OutPoint]) {
        for op in spent {
            self.live.remove(op);
        }
        self.order.retain(|op| self.live.contains_key(op));
        for &(op, value) in created {
            self.live.insert(op, value);
            self.order.push(op);
        }
    }
}

#[test]
fn background_flushes_keep_every_coin_visible_and_checkpoint_after_sync() {
    let dir = ScratchDir::new("visible");
    let engine = RobinHoodEngine::open(dir.path()).unwrap();
    let mut chain = Chain::new();
    let last = 3_000u32;

    with_storage(engine, |handle| {
        for height in 1..=last {
            let created = Chain::created(height, 5);
            let spent = chain.spends(height);

            let mut lookup = Vec::new();
            handle.lookup_coins_borrowed(&spent, &mut lookup).unwrap();
            for result in &lookup {
                let want = chain.live.get(&result.outpoint).copied();
                assert_eq!(
                    result.coin.as_ref().map(|c| c.value.to_u64()),
                    want,
                    "height {height}: {:?}",
                    result.outpoint
                );
            }

            let new_coins: Vec<NewCoin<'_>> = created
                .iter()
                .map(|&(outpoint, value)| NewCoin {
                    outpoint,
                    value: Satoshi::new(value),
                    script_pubkey: &SPK,
                    coinbase: false,
                    height: BlockHeight::new(height),
                })
                .collect();
            let durability = match height % 250 {
                0 => Durability::Synced,
                125 => Durability::Flushed,
                _ => Durability::Memory,
            };
            let hash = Chain::block_hash(height);
            handle
                .commit_block_borrowed(CommitBlockReq {
                    token: ReqToken(u64::from(height)),
                    height: BlockHeight::new(height),
                    hash,
                    prev_hash: chain.prev_hash,
                    header: chain.header(height),
                    created: &new_coins,
                    spent: &spent,
                    block_bytes: None,
                    durability,
                })
                .unwrap();
            chain.apply(&created, &spent);
            chain.prev_hash = hash;
        }

        let all: Vec<OutPoint> = chain.live.keys().copied().collect();
        let mut out = Vec::new();
        handle.lookup_coins_borrowed(&all, &mut out).unwrap();
        let missing = out.iter().filter(|r| r.coin.is_none()).count();
        assert_eq!(missing, 0, "{missing} of {} live coins lost", all.len());
    })
    .unwrap();

    let mut reopened = RobinHoodEngine::open(dir.path()).unwrap();
    assert_eq!(reopened.tip().height, BlockHeight::new(last));
    for (op, value) in &chain.live {
        let coin = reopened.read_coin(op).unwrap();
        assert_eq!(coin.map(|c| c.value.to_u64()), Some(*value), "{op:?} after reopen");
    }
}
