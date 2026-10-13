//! Validator CPU profiler — pprof-rs sampling analysis.
//!
//! Run with:
//!   cargo build --release --bin validator-pprof
//!   ./target/release/validator-pprof [SCENARIO]
//!
//! Without arguments, runs all scenarios. Pass a scenario name to run just one:
//!   ./target/release/validator-pprof `validate_and_commit_coinbase`
//!   ./target/release/validator-pprof `validate_and_commit_50_spends`

#[path = "fixtures.rs"]
mod fixtures;

use fixtures::{
    build_spend_scenario, coinbase_tx, commit, make_block, make_snapshot, seed_storage,
    tmp_storage,
};
use mantle::primitives::{BlockHeight, Hash256};
use mantle_validator::ReplayBufs;
use std::hint::black_box;

#[path = "../pprof_common.rs"]
mod pprof_common;
use pprof_common::profile;

fn run_validate_and_commit_coinbase() {
    let block = make_block(Hash256::ZERO, 1, vec![coinbase_tx(1, 50_0000_0000)]);
    let hash = block.header.hash();
    let snap = make_snapshot(&[(hash, block.header)]);

    profile("validate_and_commit_coinbase", 5, || {
        let (mut storage, _dir) = tmp_storage();
        let mut bufs = ReplayBufs::new();
        commit(
            &mut bufs,
            &mut storage,
            black_box(&block),
            BlockHeight::new(1),
            &snap,
            1,
        );
        storage.shutdown().expect("shutdown");
    });
}

fn run_validate_and_commit_50_spends() {
    let state = build_spend_scenario(50);

    profile("validate_and_commit_50_spends", 5, || {
        let (mut storage, _dir) = tmp_storage();
        let mut bufs = ReplayBufs::new();
        seed_storage(&state, &mut storage, &mut bufs);
        commit(
            &mut bufs,
            &mut storage,
            black_box(&state.spend_block),
            BlockHeight::new(state.spend_height),
            &state.snap,
            u64::from(state.spend_height),
        );
        storage.shutdown().expect("shutdown");
    });
}

fn run_validate_and_commit_100_chain() {
    let mut prev = Hash256::ZERO;
    let mut chain = Vec::with_capacity(100);
    let mut blocks = Vec::with_capacity(100);
    for i in 0..100usize {
        let h = u32::try_from(i + 1).expect("fits");
        let block = make_block(prev, h, vec![coinbase_tx(h, 50_0000_0000)]);
        let hash = block.header.hash();
        chain.push((hash, block.header));
        prev = hash;
        blocks.push(block);
    }
    let snap = make_snapshot(&chain);

    profile("validate_and_commit_100_chain", 5, || {
        let (mut storage, _dir) = tmp_storage();
        let mut bufs = ReplayBufs::new();
        for (i, block) in blocks.iter().enumerate() {
            commit(
                &mut bufs,
                &mut storage,
                black_box(block),
                BlockHeight::new(u32::try_from(i + 1).expect("fits")),
                &snap,
                    i as u64,
            );
        }
        storage.shutdown().expect("shutdown");
    });
}

fn run_header_snapshot_construction() {
    let mut prev = Hash256::ZERO;
    let mut chain = Vec::with_capacity(10_000);
    for i in 0..10_000usize {
        let h = u32::try_from(i + 1).expect("fits");
        let block = make_block(prev, h, vec![coinbase_tx(h, 50_0000_0000)]);
        let hash = block.header.hash();
        chain.push((hash, block.header));
        prev = hash;
    }
    let mut entries = Vec::with_capacity(chain.len() + 1);
    entries.push((Hash256::ZERO, fixtures::pre_genesis_header()));
    entries.extend_from_slice(&chain);

    profile("header_snapshot_construction(10k)", 3, || {
        use mantle_validator::HeaderSnapshot;
        HeaderSnapshot::new(BlockHeight::new(0), black_box(entries.clone())).expect("fits");
    });
}

fn run_header_snapshot_mtp() {
    let mut prev = Hash256::ZERO;
    let mut chain = Vec::with_capacity(1000);
    for i in 0..1000usize {
        let h = u32::try_from(i + 1).expect("fits");
        let block = make_block(prev, h, vec![coinbase_tx(h, 50_0000_0000)]);
        let hash = block.header.hash();
        chain.push((hash, block.header));
        prev = hash;
    }
    let snap = make_snapshot(&chain);
    let hdr = chain[500].1;

    profile("header_snapshot_mtp(1k)", 3, || {
        black_box(snap.median_time_past(black_box(&hdr)));
    });
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let filter = args.get(1).map(String::as_str);

    let scenarios: &[(&str, fn())] = &[
        ("validate_and_commit_coinbase", run_validate_and_commit_coinbase),
        ("validate_and_commit_50_spends", run_validate_and_commit_50_spends),
        ("validate_and_commit_100_chain", run_validate_and_commit_100_chain),
        ("header_snapshot_construction", run_header_snapshot_construction),
        ("header_snapshot_mtp", run_header_snapshot_mtp),
    ];

    let mut ran = 0;
    for &(name, f) in scenarios {
        if filter.is_none() || filter == Some(name) {
            f();
            ran += 1;
        }
    }

    if ran == 0 {
        eprintln!("no matching scenario — available:");
        for &(name, _) in scenarios {
            eprintln!("  {name}");
        }
        std::process::exit(1);
    }
}
