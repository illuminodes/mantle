//! Sustained N-block replay against a single growing storage instance.
//!
//! Unlike `replay-perf-ordinals` (which resets storage every block and only
//! visits hand-picked sample offsets), this driver replays a contiguous window
//! of blocks through one `StorageHandle` from start to finish. That's the
//! shape that matters for a full-node bottleneck analysis: storage reads
//! grow with the live UTXO set, the script cache warms, and per-block work
//! is attributed to a real chain segment rather than a fresh DB.
//!
//! Phase timings reported (wall-clock, summed across the window):
//!   - decode:    `BlockRef::decode_with_arena` + intra/spend-op gathering
//!   - lookup:    `send_lookup` + `recv_lookup` round-trip on storage
//!   - connect:   `connect_block` (validation + script verify)
//!   - commit:    `commit_block` (storage write of UTXO deltas + header)
//!
//! Usage:
//!   cargo run --release --bin replay-perf-window -- \
//!       --preset {early|ordinals} [--blocks N] [--skip-script]
//!
//! Examples:
//!   cargo run --release --bin replay-perf-window -- --preset ordinals --blocks 1000
//!   perf record -g target/release/replay-perf-window --preset early --blocks 1000

#![allow(clippy::cast_precision_loss)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use mantle::collections::{BuildPrehashedHasher, PrehashedMap, PrehashedSet};
use mantle::primitives::{BlockHeight, BlockRef, Hash256, OutPoint};
use mantle_consensus::chain_view::{Coin, ConnectScratch};
use mantle_consensus::script::ScriptExecutionCache;
use mantle_consensus::validation::connect_block;
use mantle_storage::StorageHandle;
use mantle_storage::types::{CommitBlockReq, Durability, ReqToken};
use mantle_validator::prefetched_view::HeaderSnapshot;

#[path = "fixtures_common.rs"]
mod fixtures_common;
use fixtures_common::{
    BenchView, fixtures_dir, headers_from_blocks, load_block_bytes, load_headers, make_snapshot,
    tmp_storage,
};

// ── CLI ──────────────────────────────────────────────────────────────────────

struct Args {
    preset: String,
    blocks: u32,
    skip_script: bool,
}

fn parse_args() -> Args {
    let mut preset = "ordinals".to_string();
    let mut blocks: u32 = 1000;
    let mut skip_script = false;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--preset" => preset = it.next().expect("--preset needs value"),
            "--blocks" => {
                blocks = it
                    .next()
                    .expect("--blocks needs value")
                    .parse()
                    .expect("u32");
            }
            "--skip-script" => skip_script = true,
            "--help" | "-h" => {
                eprintln!(
                    "usage: replay-perf-window --preset {{early|ordinals}} [--blocks N] [--skip-script]"
                );
                std::process::exit(0);
            }
            other => panic!("unknown arg: {other}"),
        }
    }
    Args {
        preset,
        blocks,
        skip_script,
    }
}

// ── per-phase timed replay ───────────────────────────────────────────────────

struct PhaseTimings {
    decode: Duration,
    lookup: Duration,
    connect: Duration,
    commit: Duration,
}

impl PhaseTimings {
    fn zero() -> Self {
        Self {
            decode: Duration::ZERO,
            lookup: Duration::ZERO,
            connect: Duration::ZERO,
            commit: Duration::ZERO,
        }
    }
    fn add(&mut self, o: &Self) {
        self.decode += o.decode;
        self.lookup += o.lookup;
        self.connect += o.connect;
        self.commit += o.commit;
    }
    fn total(&self) -> Duration {
        self.decode + self.lookup + self.connect + self.commit
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn replay_block_timed(
    wire: &[u8],
    height: BlockHeight,
    storage: &mut StorageHandle<'static>,
    snap: &HeaderSnapshot,
    cache: &mut ScriptExecutionCache,
    token: u64,
    dummy_on_miss: bool,
    skip_script: bool,
    arena: &mut Vec<u8>,
) -> PhaseTimings {
    use mantle::primitives::TxHash as _;

    // ── decode ───────────────────────────────────────────────────────────
    let t0 = Instant::now();
    let mut txs_buf = Vec::new();
    let block_ref = BlockRef::decode_with_arena(wire, arena, &mut txs_buf)
        .unwrap_or_else(|e| panic!("BlockRef decode at height {}: {e}", height.to_u32()));

    let tx_count = block_ref.tx_count();
    let total_inputs: usize = block_ref
        .transactions()
        .skip(1)
        .map(mantle::primitives::TransactionRef::input_count)
        .sum();

    let mut hash_scratch = Vec::new();
    let mut txids: Vec<Hash256> = Vec::with_capacity(tx_count);
    for tx in block_ref.transactions() {
        txids.push(
            tx.txid_into(&mut hash_scratch)
                .expect("txid hash never fails"),
        );
    }

    let mut spent_set: PrehashedSet<OutPoint> =
        PrehashedSet::with_capacity_and_hasher(total_inputs, BuildPrehashedHasher);
    for tx in block_ref.transactions().skip(1) {
        for i in tx.inputs().flatten() {
            spent_set.insert(i.previous_output);
        }
    }

    let mut intra: PrehashedMap<OutPoint, Option<Coin>> =
        PrehashedMap::with_capacity_and_hasher(spent_set.len(), BuildPrehashedHasher);
    for (tx_index, tx) in block_ref.transactions().enumerate() {
        let txid = txids[tx_index];
        for (vout, output) in tx.outputs().enumerate() {
            let Ok(out) = output else { continue };
            let Ok(vout_u32) = u32::try_from(vout) else {
                continue;
            };
            let op = OutPoint {
                txid,
                vout: vout_u32,
            };
            if spent_set.contains(&op) {
                intra.insert(
                    op,
                    Some(Coin {
                        value: out.value,
                        script_pubkey: out.script_pubkey.into(),
                        height: BlockHeight::ZERO,
                        coinbase: tx_index == 0,
                    }),
                );
            }
        }
    }

    let mut spend_ops: Vec<OutPoint> = Vec::with_capacity(total_inputs);
    for tx in block_ref.transactions().skip(1) {
        for inp in tx.inputs() {
            let Ok(i) = inp else { continue };
            if !intra.contains_key(&i.previous_output) {
                spend_ops.push(i.previous_output);
            }
        }
    }
    let mut spend_op_set: PrehashedSet<OutPoint> =
        PrehashedSet::with_capacity_and_hasher(spend_ops.len(), BuildPrehashedHasher);
    spend_op_set.extend(spend_ops.iter().copied());
    let mut bip30_ops: Vec<OutPoint> = Vec::with_capacity(tx_count);
    for op in mantle_consensus::validation::Bip30::new(height, &block_ref.header)
        .probes(&block_ref, &txids)
    {
        if !intra.contains_key(&op) && !spend_op_set.contains(&op) {
            bip30_ops.push(op);
        }
    }
    let mut all_ops = spend_ops;
    all_ops.extend_from_slice(&bip30_ops);
    let decode = t0.elapsed();

    // ── lookup ───────────────────────────────────────────────────────────
    let t0 = Instant::now();
    let mut lookup_results = Vec::new();
    storage
        .send_lookup_borrowed(&all_ops, &mut lookup_results)
        .expect("send_lookup");
    let hash = block_ref.header.hash();
    let prev_hash = block_ref.header.prev_block();
    let tip = storage.tip();
    storage.recv_lookup().expect("recv_lookup");
    let lookup = t0.elapsed();

    // ── connect ──────────────────────────────────────────────────────────
    let t0 = Instant::now();
    let mut coins: PrehashedMap<OutPoint, Option<Coin>> =
        PrehashedMap::with_capacity_and_hasher(all_ops.len() + intra.len(), BuildPrehashedHasher);
    for r in lookup_results.drain(..) {
        coins.insert(r.outpoint, r.coin);
    }
    coins.extend(intra);
    let view = BenchView::new(&coins, snap, tip, dummy_on_miss);
    let mut scratch = Vec::new();
    let connected = if skip_script {
        connect_block(
            &block_ref,
            height,
            &view,
            &mut scratch,
            &mut ConnectScratch::new(),
            &mut mantle_consensus::validation::SkippedScripts,
            Some(&txids),
        )
    } else {
        connect_block(
            &block_ref,
            height,
            &view,
            &mut scratch,
            &mut ConnectScratch::new(),
            &mut mantle_consensus::validation::InlineScripts::new(Some(&mut *cache)),
            Some(&txids),
        )
    };
    let result = connected
    .unwrap_or_else(|e| panic!("connect_block at height {}: {e}", height.to_u32()));
    let connect = t0.elapsed();

    // ── commit ───────────────────────────────────────────────────────────
    let t0 = Instant::now();
    storage
        .commit_block_borrowed(CommitBlockReq {
            token: ReqToken(token),
            height,
            hash,
            prev_hash,
            header: block_ref.header,
            created: &result.created,
            spent: &result.spent,
            block_bytes: None,
            durability: Durability::Memory,
        })
        .unwrap_or_else(|e| panic!("commit_block at height {}: {e}", height.to_u32()));
    let commit = t0.elapsed();

    PhaseTimings {
        decode,
        lookup,
        connect,
        commit,
    }
}

// ── main ─────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
fn main() {
    let args = parse_args();

    let dir: PathBuf = fixtures_dir(&args.preset);
    let (start, end, headers, dummy_on_miss) = match args.preset.as_str() {
        "early" => {
            let start = 1u32;
            let end = start + args.blocks - 1;
            let headers = headers_from_blocks(&dir, start, end);
            // Genesis-era: full UTXO history is available from height 1.
            (start, end, headers, false)
        }
        "ordinals" => {
            let start = 767_430u32;
            let end = start + args.blocks - 1;
            let headers = load_headers(&dir);
            assert!(
                headers.len() >= args.blocks as usize,
                "ordinals headers.bin has {} headers, need {}",
                headers.len(),
                args.blocks
            );
            // Mid-chain: inputs whose creating block is outside this window
            // get a dummy coin so connect_block's amount/script checks have
            // something to bind to.
            (start, end, headers[..args.blocks as usize].to_vec(), true)
        }
        other => panic!("unknown preset: {other} (expected 'early' or 'ordinals')"),
    };

    let snap = make_snapshot(&headers, start);

    eprint!(
        "[{}] loading {} blocks (heights {}..={})... ",
        args.preset, args.blocks, start, end
    );
    let load_start = Instant::now();
    let wires: Vec<Vec<u8>> = (start..=end).map(|h| load_block_bytes(&dir, h)).collect();
    eprintln!("done in {:.2?}", load_start.elapsed());

    let total_bytes: usize = wires.iter().map(Vec::len).sum();
    eprintln!(
        "[{}] block bytes: {} MB ({:.1} kB/block avg)",
        args.preset,
        total_bytes / (1024 * 1024),
        total_bytes as f64 / f64::from(args.blocks) / 1024.0,
    );

    let tag = format!("replay-perf-window-{}", args.preset);
    let (mut storage, _tmp) = tmp_storage(&tag);
    let mut cache = ScriptExecutionCache::new(64 * 1024);
    let mut arena = Vec::new();
    let mut totals = PhaseTimings::zero();

    eprintln!(
        "[{}] replay running (skip_script={})...",
        args.preset, args.skip_script
    );
    let t0 = Instant::now();
    for (i, wire) in wires.iter().enumerate() {
        let height = BlockHeight::new(start + u32::try_from(i).expect("fits"));
        let token = u64::try_from(i + 1).expect("fits");
        let phases = replay_block_timed(
            wire,
            height,
            &mut storage,
            &snap,
            &mut cache,
            token,
            dummy_on_miss,
            args.skip_script,
            &mut arena,
        );
        totals.add(&phases);
    }
    let wall = t0.elapsed();

    storage.shutdown().expect("shutdown");

    let n = f64::from(args.blocks);
    let pct = |d: Duration| 100.0 * d.as_secs_f64() / wall.as_secs_f64();
    println!();
    println!(
        "=== replay-perf-window: preset={} blocks={}  (skip_script={})",
        args.preset, args.blocks, args.skip_script
    );
    println!(
        "wall              : {:>10.3?}   ({:.1} blocks/s, {:.2} ms/block)",
        wall,
        n / wall.as_secs_f64(),
        wall.as_secs_f64() * 1000.0 / n
    );
    println!("phase totals (sum across blocks; phases run sequentially):");
    println!(
        "  decode          : {:>10.3?}   {:>5.1}%   ({:.3} ms/block)",
        totals.decode,
        pct(totals.decode),
        totals.decode.as_secs_f64() * 1000.0 / n
    );
    println!(
        "  lookup          : {:>10.3?}   {:>5.1}%   ({:.3} ms/block)",
        totals.lookup,
        pct(totals.lookup),
        totals.lookup.as_secs_f64() * 1000.0 / n
    );
    println!(
        "  connect (script): {:>10.3?}   {:>5.1}%   ({:.3} ms/block)",
        totals.connect,
        pct(totals.connect),
        totals.connect.as_secs_f64() * 1000.0 / n
    );
    println!(
        "  commit          : {:>10.3?}   {:>5.1}%   ({:.3} ms/block)",
        totals.commit,
        pct(totals.commit),
        totals.commit.as_secs_f64() * 1000.0 / n
    );
    let attributed = totals.total();
    println!("  ---------------");
    println!(
        "  sum             : {:>10.3?}   ({:.1}% of wall, rest is loop overhead)",
        attributed,
        pct(attributed)
    );
}
