//! Tx-grouped vs flat vs `robin_hood` — dhat allocation comparison.
//!
//! Run with:
//!   cargo build --release --bin utxo-set-dhat
//!   ./target/release/utxo-set-dhat [SCENARIO]

#[path = "fixtures.rs"]
#[allow(clippy::wildcard_imports)]
mod fixtures;

use fixtures::{
    make_block_hash, make_header, make_outpoint, seed_flat, seed_production, seed_robin_hood,
    seed_tx_grouped, ITERS_SMALL, P2WPKH_SPK,
};
use mantle::primitives::{BlockHeight, Hash256, OutPoint, Satoshi};
use mantle_consensus::chain_view::NewCoin;
use mantle_storage::engine::Engine;
use mantle_storage::types::{CommitBlockReq, Durability, LookupResult, ReqToken};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn write_blocks_1000(eng: &mut dyn Engine, label: &str) {
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
    eprintln!("{label}_write_block: 1000 blocks done");
}

fn write_and_spend_500(eng: &mut dyn Engine, label: &str) {
    let mut prev = Hash256::ZERO;
    for h in (1..=1000u32).step_by(2) {
        let op = make_outpoint(h);
        let block_hash = make_block_hash(h);
        let height = BlockHeight::new(h);
        let created = [NewCoin {
            outpoint: op,
            value: Satoshi::new(1000),
            script_pubkey: &P2WPKH_SPK,
            coinbase: false,
            height,
        }];
        let mut header = make_header(h);
        header.set_prev_block(prev);
        eng.write_block(&CommitBlockReq {
            token: ReqToken(u64::from(h)),
            height,
            hash: block_hash,
            prev_hash: prev,
            header,
            created: &created,
            spent: &[],
            block_bytes: None,
            durability: Durability::Memory,
        })
        .unwrap();

        let spend_hash = make_block_hash(h + 100_000);
        let spend_height = BlockHeight::new(h + 1);
        let mut spend_header = make_header(h + 1);
        spend_header.set_prev_block(block_hash);
        eng.write_block(&CommitBlockReq {
            token: ReqToken(u64::from(h) + 100_000),
            height: spend_height,
            hash: spend_hash,
            prev_hash: block_hash,
            header: spend_header,
            created: &[],
            spent: &[op],
            block_bytes: None,
            durability: Durability::Memory,
        })
        .unwrap();
        prev = spend_hash;
    }
    eprintln!("{label}_write_and_spend: 500 create+spend pairs done");
}

fn read_coins_batch(eng: &mut dyn Engine, label: &str) {
    let ops: Vec<OutPoint> = (1..=100).map(make_outpoint).collect();
    let mut out: Vec<LookupResult> = Vec::new();
    for _ in 0..ITERS_SMALL {
        out.clear();
        eng.read_coins(&ops, &mut out).unwrap();
    }
    eprintln!("{label}_read_coins(100): {ITERS_SMALL} iters done");
}

fn multi_output_lookup(eng: &mut dyn Engine, label: &str) {
    let ops: Vec<OutPoint> = (0..10)
        .map(|vout| {
            let mut txid_bytes = [0u8; 32];
            txid_bytes[..4].copy_from_slice(&500u32.to_le_bytes());
            OutPoint {
                txid: Hash256::from_bytes(txid_bytes),
                vout,
            }
        })
        .collect();
    let mut out: Vec<LookupResult> = Vec::new();
    for _ in 0..ITERS_SMALL {
        out.clear();
        eng.read_coins(&ops, &mut out).unwrap();
    }
    eprintln!("{label}_multi_output(10): {ITERS_SMALL} iters done");
}

fn seed_multi_output(eng: &mut dyn Engine, n_blocks: u32, outputs_per_tx: u32) {
    let mut prev = Hash256::ZERO;
    for h in 1..=n_blocks {
        let height = BlockHeight::new(h);
        let block_hash = make_block_hash(h);
        let mut txid_bytes = [0u8; 32];
        txid_bytes[..4].copy_from_slice(&h.to_le_bytes());
        let txid = Hash256::from_bytes(txid_bytes);
        let created: Vec<NewCoin<'_>> = (0..outputs_per_tx)
            .map(|vout| NewCoin {
                outpoint: OutPoint { txid, vout },
                value: Satoshi::new(1000),
                script_pubkey: &P2WPKH_SPK,
                coinbase: false,
                height,
            })
            .collect();
        let mut header = make_header(h);
        header.set_prev_block(prev);
        eng.write_block(&CommitBlockReq {
            token: ReqToken(u64::from(h)),
            height,
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
}

#[allow(clippy::too_many_lines)]
fn run_scenario(name: &str) {
    match name {
        "flat_write" => {
            let dir = tempfile::tempdir().unwrap();
            let mut eng =
                mantle_storage::engine::flat::FlatEngine::open(dir.path()).unwrap();
            write_blocks_1000(&mut eng, "flat");
        }
        "robin_hood_write" => {
            let dir = tempfile::tempdir().unwrap();
            let mut eng =
                mantle_storage::engine::robin_hood::RobinHoodEngine::open(dir.path()).unwrap();
            write_blocks_1000(&mut eng, "robin_hood");
        }
        "tx_grouped_write" => {
            let dir = tempfile::tempdir().unwrap();
            let mut eng =
                mantle_storage_engines::tx_grouped::TxGroupedEngine::open(dir.path()).unwrap();
            write_blocks_1000(&mut eng, "tx_grouped");
        }
        "flat_write_spend" => {
            let dir = tempfile::tempdir().unwrap();
            let mut eng =
                mantle_storage::engine::flat::FlatEngine::open(dir.path()).unwrap();
            write_and_spend_500(&mut eng, "flat");
        }
        "robin_hood_write_spend" => {
            let dir = tempfile::tempdir().unwrap();
            let mut eng =
                mantle_storage::engine::robin_hood::RobinHoodEngine::open(dir.path()).unwrap();
            write_and_spend_500(&mut eng, "robin_hood");
        }
        "tx_grouped_write_spend" => {
            let dir = tempfile::tempdir().unwrap();
            let mut eng =
                mantle_storage_engines::tx_grouped::TxGroupedEngine::open(dir.path()).unwrap();
            write_and_spend_500(&mut eng, "tx_grouped");
        }
        "flat_read_batch" => {
            let dir = tempfile::tempdir().unwrap();
            let mut eng = seed_flat(dir.path(), 1000);
            read_coins_batch(&mut eng, "flat");
        }
        "robin_hood_read_batch" => {
            let dir = tempfile::tempdir().unwrap();
            let mut eng = seed_robin_hood(dir.path(), 1000);
            read_coins_batch(&mut eng, "robin_hood");
        }
        "tx_grouped_read_batch" => {
            let dir = tempfile::tempdir().unwrap();
            let mut eng = seed_tx_grouped(dir.path(), 1000);
            read_coins_batch(&mut eng, "tx_grouped");
        }
        "flat_multi_output" => {
            let dir = tempfile::tempdir().unwrap();
            let mut eng =
                mantle_storage::engine::flat::FlatEngine::open(dir.path()).unwrap();
            seed_multi_output(&mut eng, 1000, 10);
            multi_output_lookup(&mut eng, "flat");
        }
        "robin_hood_multi_output" => {
            let dir = tempfile::tempdir().unwrap();
            let mut eng =
                mantle_storage::engine::robin_hood::RobinHoodEngine::open(dir.path()).unwrap();
            seed_multi_output(&mut eng, 1000, 10);
            multi_output_lookup(&mut eng, "robin_hood");
        }
        "tx_grouped_multi_output" => {
            let dir = tempfile::tempdir().unwrap();
            let mut eng =
                mantle_storage_engines::tx_grouped::TxGroupedEngine::open(dir.path()).unwrap();
            seed_multi_output(&mut eng, 1000, 10);
            multi_output_lookup(&mut eng, "tx_grouped");
        }
        "flat_recover" => {
            let dir = tempfile::tempdir().unwrap();
            {
                let mut eng = seed_flat(dir.path(), 500);
                eng.flush(Durability::Synced).unwrap();
            }
            for _ in 0..100u32 {
                let _ =
                    mantle_storage::engine::flat::FlatEngine::open(dir.path()).unwrap();
            }
            eprintln!("flat_recover(500 blocks): 100 iters done");
        }
        "robin_hood_recover" => {
            let dir = tempfile::tempdir().unwrap();
            {
                let mut eng = seed_robin_hood(dir.path(), 500);
                eng.flush(Durability::Synced).unwrap();
            }
            for _ in 0..100u32 {
                let _ =
                    mantle_storage::engine::robin_hood::RobinHoodEngine::open(dir.path())
                        .unwrap();
            }
            eprintln!("robin_hood_recover(500 blocks): 100 iters done");
        }
        "tx_grouped_recover" => {
            let dir = tempfile::tempdir().unwrap();
            {
                let mut eng = seed_tx_grouped(dir.path(), 500);
                eng.flush(Durability::Synced).unwrap();
            }
            for _ in 0..100u32 {
                let _ =
                    mantle_storage_engines::tx_grouped::TxGroupedEngine::open(dir.path())
                        .unwrap();
            }
            eprintln!("tx_grouped_recover(500 blocks): 100 iters done");
        }
        "production_write" => {
            let dir = tempfile::tempdir().unwrap();
            let mut eng =
                mantle_storage_engines::production::ProductionEngine::open(dir.path()).unwrap();
            write_blocks_1000(&mut eng, "production");
        }
        "production_write_spend" => {
            let dir = tempfile::tempdir().unwrap();
            let mut eng =
                mantle_storage_engines::production::ProductionEngine::open(dir.path()).unwrap();
            write_and_spend_500(&mut eng, "production");
        }
        "production_read_batch" => {
            let dir = tempfile::tempdir().unwrap();
            let mut eng = seed_production(dir.path(), 1000);
            read_coins_batch(&mut eng, "production");
        }
        "production_multi_output" => {
            let dir = tempfile::tempdir().unwrap();
            let mut eng =
                mantle_storage_engines::production::ProductionEngine::open(dir.path()).unwrap();
            seed_multi_output(&mut eng, 1000, 10);
            multi_output_lookup(&mut eng, "production");
        }
        "production_recover" => {
            let dir = tempfile::tempdir().unwrap();
            {
                let mut eng = seed_production(dir.path(), 500);
                eng.flush(Durability::Synced).unwrap();
            }
            for _ in 0..10u32 {
                let _ =
                    mantle_storage_engines::production::ProductionEngine::open(dir.path())
                        .unwrap();
            }
            eprintln!("production_recover(500 blocks): 10 iters done");
        }
        other => {
            eprintln!("unknown scenario: {other}");
            eprintln!("available:");
            for s in SCENARIOS {
                eprintln!("  {s}");
            }
            std::process::exit(1);
        }
    }
}

const SCENARIOS: &[&str] = &[
    "flat_write",
    "robin_hood_write",
    "tx_grouped_write",
    "production_write",
    "flat_write_spend",
    "robin_hood_write_spend",
    "tx_grouped_write_spend",
    "production_write_spend",
    "flat_read_batch",
    "robin_hood_read_batch",
    "tx_grouped_read_batch",
    "production_read_batch",
    "flat_multi_output",
    "robin_hood_multi_output",
    "tx_grouped_multi_output",
    "production_multi_output",
    "flat_recover",
    "robin_hood_recover",
    "tx_grouped_recover",
    "production_recover",
];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let filter = args.get(1).map(String::as_str);

    if let Some(name) = filter {
        let _profiler = dhat::Profiler::new_heap();
        run_scenario(name);
    } else {
        eprintln!("usage: storage-engines-dhat <SCENARIO>");
        eprintln!("available scenarios:");
        for s in SCENARIOS {
            eprintln!("  {s}");
        }
        std::process::exit(1);
    }
}
