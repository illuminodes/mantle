//! End-to-end script-verification parity bench: same corpus, mantle's
//! interpreter vs `libbitcoinconsensus`.
//!
//! Loads cached mainnet blocks from `/tmp/mantle-smoke/blocks/` (the data dir
//! the replay smoke test populates), walks blocks 1..=`STOP_HEIGHT` to build
//! a `txid → TxOut` map, then collects every non-coinbase input as a
//! self-contained verification job:
//!
//! ```text
//! Job {
//!   tx_owned: Transaction      // for mantle's verify_script
//!   tx_wire: Vec<u8>           // for bitcoinconsensus
//!   n_in: usize                // input under test
//!   script_sig: Vec<u8>        // input scriptSig (extracted from tx)
//!   spk: Vec<u8>               // scriptPubKey of the spent output
//!   amount: u64                // value of the spent output
//!   flags: u32                 // flags_for_height of the spending block
//! }
//! ```
//!
//! Two divan benches reuse the same prepared `JOBS` (built once via
//! `LazyLock` from disk), so the only difference between them is the
//! verifier choice. For pre-segwit blocks the `flags` bits and the lack of
//! `spent_outputs` (None) mean both verifiers see the exact same input
//! shape, only the implementation changes.
//!
//! Marked `#[ignore]` via the `MANTLE_BENCH_DATA_DIR` env-var gate: the bench
//! is skipped if the data dir is absent, so CI without the cached blocks
//! quietly does nothing instead of failing.
//!
//! Run:
//!     MANTLE_BENCH_DATA_DIR=/tmp/mantle-smoke \
//!         cargo bench -p mantle-bench --bench `replay_parity`

use std::collections::HashMap;
use std::fs;
use std::hint::black_box;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::LazyLock;

use mantle::codec::{Decode, Encode};
use mantle::primitives::{Block, Hash256, OutPoint, Transaction, TxHash, TxOut};
use mantle_consensus::script::{ScriptFlags, verify_script};

/// Final mainnet height to load (inclusive). 100k matches the replay smoke
/// run; pre-segwit so every input goes through the legacy ECDSA path.
const STOP_HEIGHT: u32 = 100_000;

fn main() {
    divan::main();
}

struct Job {
    tx: Transaction,
    tx_wire: Vec<u8>,
    n_in: usize,
    script_sig: Vec<u8>,
    spk: Vec<u8>,
    amount: u64,
    flags: u32,
}

/// Read the `MANTLE_BENCH_DATA_DIR` env-var (default `/tmp/mantle-smoke`)
/// and return the path that should contain `blocks/NNNNNN.bin` files. If
/// the directory is absent the benches return an empty `JOBS` slice and
/// divan's "no work" prints clearly without panicking.
fn data_dir() -> PathBuf {
    PathBuf::from(
        std::env::var("MANTLE_BENCH_DATA_DIR").unwrap_or_else(|_| "/tmp/mantle-smoke".to_string()),
    )
}

fn read_block(dir: &std::path::Path, height: u32) -> Option<Block> {
    let path = dir.join("blocks").join(format!("{height:07}.bin"));
    let bytes = fs::read(&path).ok()?;
    Block::decode(&mut Cursor::new(&bytes)).ok()
}

/// Walk blocks 1..=`STOP_HEIGHT`, build the UTXO map, collect every
/// non-coinbase input as a `Job`. Done once at first bench access via
/// `LazyLock`; both benches share the result.
fn build_jobs() -> Vec<Job> {
    let dir = data_dir();
    if !dir.join("blocks").is_dir() {
        eprintln!(
            "replay_parity: skipping — {} not present (run mantle-replay or fetch-fixtures first)",
            dir.display()
        );
        return Vec::new();
    }

    let mut utxos: HashMap<OutPoint, TxOut> = HashMap::new();
    let mut jobs: Vec<Job> = Vec::new();

    for h in 1u32..=STOP_HEIGHT {
        let Some(block) = read_block(&dir, h) else {
            eprintln!("replay_parity: missing block {h}, stopping at the prefix already loaded");
            break;
        };
        let flags = bitcoinconsensus::height_to_flags(h);

        for tx in &block.transactions {
            let txid = tx.txid().expect("txid");

            // Coinbase tx: no inputs to verify — only update UTXO set with
            // its outputs.
            let is_coinbase = tx.inputs.len() == 1
                && tx.inputs[0].previous_output.txid == Hash256::ZERO
                && tx.inputs[0].previous_output.vout == u32::MAX;

            if !is_coinbase {
                let mut tx_wire = Vec::new();
                tx.encode(&mut tx_wire).expect("encode tx");

                for (i, inp) in tx.inputs.iter().enumerate() {
                    let utxo = utxos.get(&inp.previous_output).unwrap_or_else(|| {
                        panic!(
                            "block {h}: prevout {}:{} not in UTXO map",
                            inp.previous_output.txid.to_display_hex(),
                            inp.previous_output.vout,
                        )
                    });
                    jobs.push(Job {
                        tx: tx.clone(),
                        tx_wire: tx_wire.clone(),
                        n_in: i,
                        script_sig: inp.script_sig.as_slice().to_vec(),
                        spk: utxo.script_pubkey.as_slice().to_vec(),
                        amount: utxo.value.to_u64(),
                        flags,
                    });
                }
            }

            // Apply this tx's spends and creates to the UTXO map (in that
            // order, since intra-block dependencies are valid in mainnet).
            if !is_coinbase {
                for inp in &tx.inputs {
                    utxos.remove(&inp.previous_output);
                }
            }
            for (vout, out) in tx.outputs.iter().enumerate() {
                let op = OutPoint {
                    txid,
                    vout: u32::try_from(vout).expect("vout"),
                };
                utxos.insert(op, out.clone());
            }
        }
    }

    eprintln!(
        "replay_parity: prepared {} verification jobs from blocks 1..={}",
        jobs.len(),
        STOP_HEIGHT
    );
    jobs
}

static JOBS: LazyLock<Vec<Job>> = LazyLock::new(build_jobs);

// ── benches ──────────────────────────────────────────────────────────────────

/// Mantle's `verify_script` over the full corpus. Reports the time it takes
/// to verify every non-coinbase input in blocks 1..=`STOP_HEIGHT`.
#[divan::bench(sample_count = 1, sample_size = 1)]
fn mantle(bencher: divan::Bencher) {
    let jobs = JOBS.as_slice();
    bencher.bench_local(|| {
        for job in jobs {
            let res = verify_script(
                black_box(&job.script_sig),
                black_box(&job.spk),
                black_box(&job.tx),
                black_box(job.n_in),
                black_box(mantle::primitives::Satoshi::new(job.amount)),
                black_box(ScriptFlags::from_bits(job.flags)),
            );
            // We expect every job to pass — assert to catch regressions.
            res.expect("mantle: verification must pass on real mainnet input");
        }
    });
}

/// `libbitcoinconsensus::verify` over the same corpus. Same loop, same
/// inputs, only the implementation differs.
#[divan::bench(sample_count = 1, sample_size = 1)]
fn bitcoinconsensus_oracle(bencher: divan::Bencher) {
    let jobs = JOBS.as_slice();
    bencher.bench_local(|| {
        for job in jobs {
            // Pre-segwit corpus → spent_outputs is irrelevant (TAPROOT bit
            // is never set). Pass `None` to match how the replay binary
            // would use it.
            let res = bitcoinconsensus::verify_with_flags(
                black_box(&job.spk),
                black_box(job.amount),
                black_box(&job.tx_wire),
                None,
                black_box(job.n_in),
                black_box(job.flags),
            );
            res.expect("bitcoinconsensus: verification must pass on real mainnet input");
        }
    });
}
