//! Validator heap profiler — dhat allocation analysis.
//!
//! Run with:
//!   cargo build --release --bin validator-dhat
//!   ./target/release/validator-dhat
//!
//! dhat writes `dhat-heap.json` in the current directory on exit.
//! Open it at <https://nnethercote.github.io/dh_view/dh_view.html>.

#[path = "fixtures.rs"]
mod fixtures;

use fixtures::{
    build_spend_scenario, coinbase_tx, commit, make_block, make_snapshot, seed_storage,
    tmp_storage, ITERS_MEDIUM, ITERS_SMALL,
};
use mantle::primitives::{BlockHeight, Hash256};
use mantle_validator::{HeaderSnapshot, ReplayBufs};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() {
    let _profiler = dhat::Profiler::new_heap();

    scenario_coinbase_only();
    scenario_50_spends();
    scenario_100_chain();
    scenario_header_snapshot_construction();
    scenario_bufs_reuse();

    eprintln!("all scenarios complete — dhat summary follows");
}

fn scenario_coinbase_only() {
    let block = make_block(Hash256::ZERO, 1, vec![coinbase_tx(1, 50_0000_0000)]);
    let hash = block.header.hash();
    let snap = make_snapshot(&[(hash, block.header)]);

    for _ in 0..ITERS_SMALL {
        let (mut storage, _dir) = tmp_storage();
        let mut bufs = ReplayBufs::new();
        commit(
            &mut bufs,
            &mut storage,
            &block,
            BlockHeight::new(1),
            &snap,
            1,
        );
        storage.shutdown().expect("shutdown");
    }
    eprintln!("coinbase_only: {ITERS_SMALL} iters done");
}

fn scenario_50_spends() {
    let state = build_spend_scenario(50);

    for _ in 0..ITERS_SMALL {
        let (mut storage, _dir) = tmp_storage();
        let mut bufs = ReplayBufs::new();
        seed_storage(&state, &mut storage, &mut bufs);
        commit(
            &mut bufs,
            &mut storage,
            &state.spend_block,
            BlockHeight::new(state.spend_height),
            &state.snap,
            u64::from(state.spend_height),
        );
        storage.shutdown().expect("shutdown");
    }
    eprintln!("50_spends: {ITERS_SMALL} iters done");
}

fn scenario_100_chain() {
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

    for _ in 0..ITERS_SMALL {
        let (mut storage, _dir) = tmp_storage();
        let mut bufs = ReplayBufs::new();
        for (i, block) in blocks.iter().enumerate() {
            commit(
                &mut bufs,
                &mut storage,
                block,
                BlockHeight::new(u32::try_from(i + 1).expect("fits")),
                &snap,
                    i as u64,
            );
        }
        storage.shutdown().expect("shutdown");
    }
    eprintln!("100_chain: {ITERS_SMALL} iters done");
}

fn scenario_header_snapshot_construction() {
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

    for _ in 0..ITERS_MEDIUM {
        HeaderSnapshot::new(BlockHeight::new(0), entries.clone()).expect("fits");
    }
    eprintln!("header_snapshot_construction(10k): {ITERS_MEDIUM} iters done");
}

fn scenario_bufs_reuse() {
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

    let (mut storage, _dir) = tmp_storage();
    let mut bufs = ReplayBufs::new();
    for (i, block) in blocks.iter().enumerate() {
        commit(
            &mut bufs,
            &mut storage,
            block,
            BlockHeight::new(u32::try_from(i + 1).expect("fits")),
            &snap,
            i as u64,
        );
    }
    storage.shutdown().expect("shutdown");
    eprintln!("bufs_reuse(100 blocks, single ReplayBufs): done");
}
