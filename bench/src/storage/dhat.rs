//! Storage heap profiler — dhat allocation analysis.
//!
//! Run with:
//!   cargo build --release --bin storage-dhat
//!   ./target/release/storage-dhat

#[path = "fixtures.rs"]
#[allow(clippy::wildcard_imports)]
mod fixtures;

use fixtures::{
    make_block_hash, make_coin, make_header, make_outpoint, seed_flat,
    ITERS_LARGE, ITERS_SMALL, P2WPKH_SPK,
};
use mantle::primitives::{BlockHeight, Hash256, OutPoint, Satoshi};
use mantle_consensus::chain_view::NewCoin;
use mantle_storage::engine::robin_hood::RobinHoodTable;
use mantle_storage::engine::Engine;
use mantle_storage::types::{CommitBlockReq, Durability, LookupResult, ReqToken};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[allow(clippy::too_many_lines)]
fn main() {
    let _profiler = dhat::Profiler::new_heap();

    // ── FlatEngine: write_block (1000 blocks) ──────────────────────────────
    {
        let dir = tempfile::tempdir().unwrap();
        let mut eng = mantle_storage::engine::flat::FlatEngine::open(dir.path()).unwrap();
        let mut prev = Hash256::ZERO;
        for h in 1..=1000u32 {
            let op = make_outpoint(h);
            let block_hash = make_block_hash(h);
            let created = [NewCoin {
                outpoint: op,
                value: Satoshi::new(5_000_000_000),
                script_pubkey: &P2WPKH_SPK,
                coinbase: true,
                height: BlockHeight::new(h),
            }];
            let mut header = make_header(h);
            header.set_prev_block(prev);
            eng.write_block(&CommitBlockReq {
                token: ReqToken(u64::from(h)),
                height: BlockHeight::new(h),
                hash: block_hash,
                prev_hash: prev,
                header,
                created: &created,
                spent: &[],
                block_bytes: None,
                durability: Durability::Memory,
            })
            .unwrap();
            prev = block_hash;
        }
        eprintln!("flat_write_block: 1000 blocks done");
    }

    // ── FlatEngine: read_coin (500 iters) ──────────────────────────────────
    {
        let dir = tempfile::tempdir().unwrap();
        let mut eng = seed_flat(dir.path(), 1000);
        let target = make_outpoint(500);
        for _ in 0..ITERS_SMALL {
            let _ = eng.read_coin(&target);
        }
        eprintln!("flat_read_coin: {ITERS_SMALL} iters done");
    }

    // ── FlatEngine: read_coins batch (500 iters, 100 ops) ──────────────────
    {
        let dir = tempfile::tempdir().unwrap();
        let mut eng = seed_flat(dir.path(), 1000);
        let ops: Vec<OutPoint> = (1..=100).map(make_outpoint).collect();
        let mut out: Vec<LookupResult> = Vec::new();
        for _ in 0..ITERS_SMALL {
            out.clear();
            eng.read_coins(&ops, &mut out).unwrap();
        }
        eprintln!("flat_read_coins(100): {ITERS_SMALL} iters done");
    }

    // ── FlatEngine: recover (100 iters) ────────────────────────────────────
    {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut eng = seed_flat(dir.path(), 500);
            eng.flush(Durability::Synced).unwrap();
        }
        for _ in 0..100u32 {
            let _ = mantle_storage::engine::flat::FlatEngine::open(dir.path()).unwrap();
        }
        eprintln!("flat_recover(500 blocks): 100 iters done");
    }

    // ── RobinHoodTable: insert + get (10000 iters) ─────────────────────────
    {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("utxo_table.bin");
        let mut table = RobinHoodTable::open_with_capacity(&path, 65536).unwrap();
        let coin = make_coin(1000);
        for i in 0..ITERS_LARGE {
            let op = make_outpoint(i);
            table.insert(&op, &coin).unwrap();
        }
        for i in 0..ITERS_LARGE {
            let op = make_outpoint(i);
            let _ = table.get(&op);
        }
        eprintln!("robin_hood insert+get: {ITERS_LARGE} iters done");
    }

    // ── RobinHoodEngine: write_block (1000 blocks) ─────────────────────────
    {
        let dir = tempfile::tempdir().unwrap();
        let mut eng = mantle_storage::engine::robin_hood::RobinHoodEngine::open(dir.path()).unwrap();
        let mut prev = Hash256::ZERO;
        for h in 1..=1000u32 {
            let op = make_outpoint(h);
            let block_hash = make_block_hash(h);
            let created = [NewCoin {
                outpoint: op,
                value: Satoshi::new(5_000_000_000),
                script_pubkey: &P2WPKH_SPK,
                coinbase: true,
                height: BlockHeight::new(h),
            }];
            let mut header = make_header(h);
            header.set_prev_block(prev);
            eng.write_block(&CommitBlockReq {
                token: ReqToken(u64::from(h)),
                height: BlockHeight::new(h),
                hash: block_hash,
                prev_hash: prev,
                header,
                created: &created,
                spent: &[],
                block_bytes: None,
                durability: Durability::Memory,
            })
            .unwrap();
            prev = block_hash;
        }
        eprintln!("robin_hood_write_block: 1000 blocks done");
    }

    // ── with_storage handle: commit + lookup (500 iters) ───────────────────
    {
        let dir = tempfile::tempdir().unwrap();
        let eng = mantle_storage::engine::flat::FlatEngine::open(dir.path()).unwrap();
        mantle_storage::with_storage(eng, |handle| {
            let mut prev = Hash256::ZERO;
            for h in 1..=ITERS_SMALL {
                let op = make_outpoint(h);
                let block_hash = make_block_hash(h);
                let spk = P2WPKH_SPK;
                let created = [NewCoin {
                    outpoint: op,
                    value: Satoshi::new(5_000_000_000),
                    script_pubkey: &spk,
                    coinbase: true,
                    height: BlockHeight::new(h),
                }];
                let mut header = make_header(h);
                header.set_prev_block(prev);
                handle
                    .commit_block_borrowed(CommitBlockReq {
                        token: ReqToken(u64::from(h)),
                        height: BlockHeight::new(h),
                        hash: block_hash,
                        prev_hash: prev,
                        header,
                        created: &created,
                        spent: &[],
                        block_bytes: None,
                        durability: Durability::Memory,
                    })
                    .unwrap();
                prev = block_hash;
            }
            let target = [make_outpoint(250)];
            let mut out = Vec::new();
            for _ in 0..ITERS_SMALL {
                out.clear();
                handle.lookup_coins_borrowed(&target, &mut out).unwrap();
            }
            eprintln!("handle commit+lookup: {ITERS_SMALL} iters done");
        })
        .unwrap();
    }
}
