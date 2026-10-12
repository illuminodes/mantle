//! Storage CPU profiler — pprof-rs sampling analysis.
//!
//! Run with:
//!   cargo build --release --bin storage-pprof
//!   ./target/release/storage-pprof [SCENARIO]
//!
//! Without arguments, runs all scenarios. Pass a scenario name to run just one:
//!   ./target/release/storage-pprof `flat_write_block`
//!   ./target/release/storage-pprof `robin_hood_get`

#[path = "fixtures.rs"]
mod fixtures;

use fixtures::{
    make_block_hash, make_coin, make_header, make_outpoint, seed_flat, seed_robin_hood,
    P2WPKH_SPK,
};
use mantle::primitives::{BlockHeight, Hash256, OutPoint, Satoshi};
use mantle_consensus::chain_view::NewCoin;
use mantle_storage::engine::robin_hood::RobinHoodTable;
use mantle_storage::engine::Engine;
use mantle_storage::types::{CommitBlockReq, Durability, LookupResult, ReqToken};
use std::hint::black_box;

#[path = "../pprof_common.rs"]
mod pprof_common;
use pprof_common::profile;

fn run_flat_write_block() {
    let dir = tempfile::tempdir().unwrap();
    let mut eng = mantle_storage::engine::flat::FlatEngine::open(dir.path()).unwrap();
    let mut h = 1u32;
    let mut prev = Hash256::ZERO;
    profile("flat_write_block", 3, || {
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
        eng.write_block(black_box(&CommitBlockReq {
            token: ReqToken(u64::from(h)),
            height: BlockHeight::new(h),
            hash: block_hash,
            prev_hash: prev,
            header,
            created: &created,
            spent: &[],
            block_bytes: None,
            durability: Durability::Memory,
        }))
        .unwrap();
        prev = block_hash;
        h += 1;
    });
}

fn run_flat_read_coin() {
    let dir = tempfile::tempdir().unwrap();
    let mut eng = seed_flat(dir.path(), 2000);
    let target = make_outpoint(1000);
    profile("flat_read_coin", 3, || {
        black_box(eng.read_coin(black_box(&target)).unwrap());
    });
}

fn run_flat_read_coins_batch() {
    let dir = tempfile::tempdir().unwrap();
    let mut eng = seed_flat(dir.path(), 2000);
    let ops: Vec<OutPoint> = (1..=100).map(make_outpoint).collect();
    let mut out: Vec<LookupResult> = Vec::new();
    profile("flat_read_coins(100)", 3, || {
        out.clear();
        eng.read_coins(black_box(&ops), &mut out).unwrap();
    });
}

fn run_flat_recover() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut eng = seed_flat(dir.path(), 1000);
        eng.flush(Durability::Synced).unwrap();
    }
    profile("flat_recover(1000 blocks)", 3, || {
        black_box(mantle_storage::engine::flat::FlatEngine::open(dir.path()).unwrap());
    });
}

fn run_robin_hood_insert() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("utxo_table.bin");
    let mut table = RobinHoodTable::open_with_capacity(&path, 1 << 20).unwrap();
    let coin = make_coin(1000);
    let mut i = 0u32;
    profile("robin_hood_insert", 3, || {
        table.insert(black_box(&make_outpoint(i)), black_box(&coin)).unwrap();
        i += 1;
    });
}

fn run_robin_hood_get() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("utxo_table.bin");
    let mut table = RobinHoodTable::open_with_capacity(&path, 65536).unwrap();
    let coin = make_coin(1000);
    for i in 0..10_000u32 {
        table.insert(&make_outpoint(i), &coin).unwrap();
    }
    let target = make_outpoint(5000);
    profile("robin_hood_get", 3, || {
        black_box(table.get(black_box(&target)).unwrap());
    });
}

fn run_robin_hood_engine_write() {
    let dir = tempfile::tempdir().unwrap();
    let mut eng = mantle_storage::engine::robin_hood::RobinHoodEngine::open(dir.path()).unwrap();
    let mut h = 1u32;
    let mut prev = Hash256::ZERO;
    profile("robin_hood_engine_write", 3, || {
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
        eng.write_block(black_box(&CommitBlockReq {
            token: ReqToken(u64::from(h)),
            height: BlockHeight::new(h),
            hash: block_hash,
            prev_hash: prev,
            header,
            created: &created,
            spent: &[],
            block_bytes: None,
            durability: Durability::Memory,
        }))
        .unwrap();
        prev = block_hash;
        h += 1;
    });
}

fn run_rh_engine_read_coins() {
    let dir = tempfile::tempdir().unwrap();
    let mut eng = seed_robin_hood(dir.path(), 2000);
    eng.flush(Durability::Synced).unwrap();
    let ops: Vec<OutPoint> = (1..=100).map(make_outpoint).collect();
    let mut out: Vec<LookupResult> = Vec::new();
    profile("rh_engine_read_coins(100, all disk)", 5, || {
        out.clear();
        eng.read_coins(black_box(&ops), &mut out).unwrap();
    });
}

fn run_rh_engine_read_coins_mixed() {
    let dir = tempfile::tempdir().unwrap();
    let mut eng = seed_robin_hood(dir.path(), 2000);
    let ops: Vec<OutPoint> = (1900..=2000).map(make_outpoint).collect();
    let mut out: Vec<LookupResult> = Vec::new();
    profile("rh_engine_read_coins(101, buffered+disk)", 5, || {
        out.clear();
        eng.read_coins(black_box(&ops), &mut out).unwrap();
    });
}

fn run_rh_engine_flush() {
    let dir = tempfile::tempdir().unwrap();
    let mut eng = mantle_storage::engine::robin_hood::RobinHoodEngine::open(dir.path()).unwrap();
    let mut prev = Hash256::ZERO;
    for h in 1..=5000u32 {
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
    profile("rh_engine_flush(5000 coins)", 5, || {
        eng.flush(Durability::Synced).unwrap();
    });
}

fn run_handle_commit_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let eng = mantle_storage::engine::flat::FlatEngine::open(dir.path()).unwrap();
    mantle_storage::with_storage(eng, |handle| {
        let mut prev = Hash256::ZERO;
        for h in 1..=1000u32 {
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

        let target = [make_outpoint(500)];
        let mut out = Vec::new();
        profile("handle_lookup_coins", 3, || {
            out.clear();
            handle.lookup_coins_borrowed(black_box(&target), &mut out).unwrap();
        });
    })
    .unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let filter = args.get(1).map(String::as_str);

    let scenarios: &[(&str, fn())] = &[
        ("flat_write_block", run_flat_write_block),
        ("flat_read_coin", run_flat_read_coin),
        ("flat_read_coins_batch", run_flat_read_coins_batch),
        ("flat_recover", run_flat_recover),
        ("robin_hood_insert", run_robin_hood_insert),
        ("robin_hood_get", run_robin_hood_get),
        ("robin_hood_engine_write", run_robin_hood_engine_write),
        ("rh_engine_read_coins", run_rh_engine_read_coins),
        ("rh_engine_read_coins_mixed", run_rh_engine_read_coins_mixed),
        ("rh_engine_flush", run_rh_engine_flush),
        ("handle_commit_lookup", run_handle_commit_lookup),
    ];

    let mut ran = 0;
    for &(name, f) in scenarios {
        if filter.is_none() || filter == Some(name) {
            f();
            ran += 1;
        }
    }

    if ran == 0 {
        eprintln!("no matching scenario. available:");
        for &(name, _) in scenarios {
            eprintln!("  {name}");
        }
        std::process::exit(1);
    }
}
