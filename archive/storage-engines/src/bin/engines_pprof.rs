//! UTXO set CPU profiler — ordinals replay under pprof-rs.
//!
//! Run with:
//!   cargo build --release --bin utxo-set-pprof
//!   ./target/release/utxo-set-pprof <SCENARIO>

use std::io::Cursor;
use std::path::{Path, PathBuf};

use mantle::codec::Decode;
use mantle::collections::PrehashedSet;
use mantle::primitives::{
    Block, BlockHeader, BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Nonce,
    OutPoint, Satoshi, TxHash,
};
use mantle_consensus::chain_view::NewCoin;
use mantle_storage::engine::flat::FlatEngine;
use mantle_storage_engines::production::ProductionEngine;
use mantle_storage::engine::robin_hood::RobinHoodEngine;
use mantle_storage_engines::tx_grouped::TxGroupedEngine;
use mantle_storage::engine::Engine;
use mantle_storage::types::{CommitBlockReq, Durability, ReqToken};
use mantle_utxo_set::{ArenaUtxoSet, ConnectScratch};

#[path = "pprof_common.rs"]
mod pprof_common;
use pprof_common::print_top;

const START_HEIGHT: u32 = 767_430;
const END_HEIGHT: u32 = 768_430;

struct RealBlock {
    height: u32,
    header: BlockHeader,
    hash: Hash256,
    prev_hash: Hash256,
    created: Vec<(OutPoint, Satoshi, Vec<u8>, bool)>,
    spent: Vec<OutPoint>,
}

struct Corpus {
    blocks: Vec<RealBlock>,
    pre_window: Vec<(OutPoint, Satoshi, Vec<u8>)>,
}

fn ordinals_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../bench/fixtures")
        .join("ordinals")
}

fn build_corpus() -> Corpus {
    let dir = ordinals_dir();
    let mut blocks = Vec::with_capacity(1001);
    let mut created_set: PrehashedSet<OutPoint> = PrehashedSet::default();
    let mut pre_window: Vec<(OutPoint, Satoshi, Vec<u8>)> = Vec::new();
    let mut pre_window_set: PrehashedSet<OutPoint> = PrehashedSet::default();
    let mut txid_buf = Vec::new();

    for h in START_HEIGHT..=END_HEIGHT {
        let path = dir.join("blocks").join(format!("{h:07}.bin"));
        let Ok(bytes) = std::fs::read(&path) else { break };
        let block = Block::decode(&mut Cursor::new(&bytes))
            .unwrap_or_else(|e| panic!("decode block {h}: {e}"));

        let header = block.header;
        let hash = header.hash();
        let prev_hash = header.prev_block();

        let mut created = Vec::new();
        let mut spent = Vec::new();

        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            let txid = tx.txid_into(&mut txid_buf).expect("txid");
            let coinbase = tx_idx == 0;

            for (vout, out) in tx.outputs.iter().enumerate() {
                let op = OutPoint {
                    txid,
                    #[allow(clippy::cast_possible_truncation)]
                    vout: vout as u32,
                };
                created.push((op, out.value, out.script_pubkey.to_vec(), coinbase));
                created_set.insert(op);
            }

            if !coinbase {
                for inp in &tx.inputs {
                    let op = inp.previous_output;
                    spent.push(op);
                    if !created_set.contains(&op) && pre_window_set.insert(op) {
                        pre_window.push((
                            op,
                            Satoshi::new(1000),
                            vec![
                                0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                                0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
                            ],
                        ));
                    }
                }
            }
        }

        blocks.push(RealBlock {
            height: h,
            header,
            hash,
            prev_hash,
            created,
            spent,
        });
    }

    eprintln!(
        "ordinals corpus: {} blocks, {} pre-window UTXOs",
        blocks.len(),
        pre_window.len()
    );
    Corpus { blocks, pre_window }
}

fn seed_and_replay(eng: &mut dyn Engine, corpus: &Corpus) {
    let seed_hash = corpus.blocks[0].prev_hash;
    let seed_height = BlockHeight::new(START_HEIGHT - 1);
    let seed_created: Vec<NewCoin<'_>> = corpus
        .pre_window
        .iter()
        .map(|(op, value, spk)| NewCoin {
            outpoint: *op,
            value: *value,
            script_pubkey: spk,
            coinbase: false,
            height: BlockHeight::new(1),
        })
        .collect();
    let seed_header = BlockHeader::new(
        BlockVersion::new(1),
        Hash256::ZERO,
        Hash256::ZERO,
        BlockTime::new(1),
        CompactBits::new(0x1d00_ffff),
        Nonce::new(0),
    );
    eng.write_block(&CommitBlockReq {
        token: ReqToken(0),
        height: seed_height,
        hash: seed_hash,
        prev_hash: Hash256::ZERO,
        header: seed_header,
        created: &seed_created,
        spent: &[],
        block_bytes: None,
        durability: Durability::Memory,
    })
    .unwrap();

    for (i, rb) in corpus.blocks.iter().enumerate() {
        let created: Vec<NewCoin<'_>> = rb
            .created
            .iter()
            .map(|(op, value, spk, coinbase)| NewCoin {
                outpoint: *op,
                value: *value,
                script_pubkey: spk,
                coinbase: *coinbase,
                height: BlockHeight::new(rb.height),
            })
            .collect();
        eng.write_block(&CommitBlockReq {
            #[allow(clippy::cast_possible_truncation)]
            token: ReqToken(i as u64 + 1),
            height: BlockHeight::new(rb.height),
            hash: rb.hash,
            prev_hash: rb.prev_hash,
            header: rb.header,
            created: &created,
            spent: &rb.spent,
            block_bytes: None,
            durability: Durability::Memory,
        })
        .unwrap();
    }
}

fn run_ordinals(label: &str, mut make_engine: impl FnMut(&Path) -> Box<dyn Engine>) {
    let corpus = build_corpus();
    if corpus.blocks.is_empty() {
        eprintln!("ordinals fixtures missing, skipping");
        return;
    }

    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(997)
        .build()
        .expect("pprof profiler must initialize");

    let mut iters = 0u64;
    for _ in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let mut eng = make_engine(dir.path());
        seed_and_replay(eng.as_mut(), &corpus);
        iters += 1;
    }

    let report = guard.report().build().expect("pprof report must build");
    print_top(&report, label, iters, 0);
}

fn run_arena_ordinals() {
    let corpus = build_corpus();
    if corpus.blocks.is_empty() {
        eprintln!("ordinals fixtures missing, skipping");
        return;
    }

    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(997)
        .build()
        .expect("pprof profiler must initialize");

    for _ in 0..3 {
        let mut set = ArenaUtxoSet::new();
        let mut scratch = ConnectScratch::new();

        let seed_created: Vec<NewCoin<'_>> = corpus
            .pre_window
            .iter()
            .map(|(op, value, spk)| NewCoin {
                outpoint: *op,
                value: *value,
                script_pubkey: spk,
                coinbase: false,
                height: BlockHeight::new(1),
            })
            .collect();
        let undo = set
            .connect_block_with(&mut scratch, BlockHeight::new(1), &seed_created, &[])
            .unwrap();
        scratch.reclaim(undo);

        for rb in &corpus.blocks {
            let created: Vec<NewCoin<'_>> = rb
                .created
                .iter()
                .map(|(op, value, spk, coinbase)| NewCoin {
                    outpoint: *op,
                    value: *value,
                    script_pubkey: spk,
                    coinbase: *coinbase,
                    height: BlockHeight::new(rb.height),
                })
                .collect();
            let undo = set.connect_block_best_effort(
                &mut scratch,
                BlockHeight::new(rb.height),
                &created,
                &rb.spent,
            );
            scratch.reclaim(undo);
        }
        std::hint::black_box(&set);
    }

    let report = guard.report().build().expect("pprof report must build");
    print_top(&report, "arena_ordinals", 3, 0);
}

const SCENARIOS: &[&str] = &[
    "flat_ordinals",
    "robin_hood_ordinals",
    "tx_grouped_ordinals",
    "production_ordinals",
    "arena_ordinals",
];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let filter = args.get(1).map(String::as_str);

    match filter {
        Some("flat_ordinals") => {
            run_ordinals("flat_ordinals", |p| {
                Box::new(FlatEngine::open(p).unwrap())
            });
        }
        Some("robin_hood_ordinals") => {
            run_ordinals("robin_hood_ordinals", |p| {
                Box::new(RobinHoodEngine::open(p).unwrap())
            });
        }
        Some("tx_grouped_ordinals") => {
            run_ordinals("tx_grouped_ordinals", |p| {
                Box::new(TxGroupedEngine::open(p).unwrap())
            });
        }
        Some("production_ordinals") => {
            run_ordinals("production_ordinals", |p| {
                Box::new(ProductionEngine::open(p).unwrap())
            });
        }
        Some("arena_ordinals") => {
            run_arena_ordinals();
        }
        Some(other) => {
            eprintln!("unknown scenario: {other}");
            eprintln!("available:");
            for s in SCENARIOS {
                eprintln!("  {s}");
            }
            std::process::exit(1);
        }
        None => {
            for &name in SCENARIOS {
                // Re-invoke ourselves for each scenario so profiles don't overlap.
                let exe = std::env::current_exe().unwrap();
                let status = std::process::Command::new(&exe)
                    .arg(name)
                    .status()
                    .unwrap();
                if !status.success() {
                    std::process::exit(1);
                }
            }
        }
    }
}
