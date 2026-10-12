//! dhat heap profile of mantle's `verify_script` over the same 192k-input
//! mainnet corpus the `replay_parity` bench measures.
//!
//! `bitcoinconsensus` is C++ and its internal allocations don't go through
//! the Rust global allocator dhat hooks. So a "compare both arms in dhat"
//! framing would mislead — bitcoinconsensus would look near-zero while it
//! actually allocates plenty internally. This binary profiles only mantle's
//! arm, where dhat sees every allocation honestly.
//!
//! Workload setup mirrors `crates/bench/benches/replay_parity.rs`: load the
//! cached blocks 1..=`STOP_HEIGHT` from `MANTLE_BENCH_DATA_DIR` (defaults to
//! `/tmp/mantle-smoke`), walk them to build a `txid → TxOut` UTXO map, then
//! run mantle's `verify_script` on every non-coinbase input. The setup and
//! the verification loop both run under dhat.
//!
//! Run:
//!     cargo build --release --bin parity-dhat
//!     MANTLE_BENCH_DATA_DIR=/tmp/mantle-smoke ./target/release/parity-dhat
//!     # writes dhat-heap.json — open at
//!     # <https://nnethercote.github.io/dh_view/dh_view.html>

use std::collections::HashMap;
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;

use mantle::codec::Decode;
use mantle::primitives::{
    Block, BlockHeight, Hash256, OutPoint, Satoshi, Transaction, TxHash, TxOut,
};
use mantle_consensus::script::{ScriptFlags, verify_script};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const STOP_HEIGHT: u32 = 100_000;

struct Job {
    tx: Transaction,
    n_in: usize,
    script_sig: Vec<u8>,
    spk: Vec<u8>,
    amount: u64,
    flags: ScriptFlags,
}

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

fn build_jobs() -> Vec<Job> {
    let dir = data_dir();
    assert!(
        dir.join("blocks").is_dir(),
        "{} not present — run mantle-replay or fetch-fixtures first",
        dir.display()
    );

    let mut utxos: HashMap<OutPoint, TxOut> = HashMap::new();
    let mut jobs: Vec<Job> = Vec::new();

    for h in 1u32..=STOP_HEIGHT {
        let Some(block) = read_block(&dir, h) else {
            eprintln!("missing block {h}, stopping at prefix already loaded");
            break;
        };
        let flags = ScriptFlags::for_height(BlockHeight::new(h));

        for tx in &block.transactions {
            let txid = tx.txid().expect("txid");
            let is_coinbase = tx.inputs.len() == 1
                && tx.inputs[0].previous_output.txid == Hash256::ZERO
                && tx.inputs[0].previous_output.vout == u32::MAX;

            if !is_coinbase {
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
                        n_in: i,
                        script_sig: inp.script_sig.as_slice().to_vec(),
                        spk: utxo.script_pubkey.as_slice().to_vec(),
                        amount: utxo.value.to_u64(),
                        flags,
                    });
                }
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
        "parity-dhat: prepared {} verification jobs from blocks 1..={}",
        jobs.len(),
        STOP_HEIGHT
    );
    jobs
}

fn main() {
    let _profiler = dhat::Profiler::new_heap();

    let jobs = build_jobs();

    // Drop the encoded copies that build_jobs holds onto so they don't show
    // up as "still-live at exit" allocations. The verification loop is the
    // measurement target; setup is overhead.
    let mut total: u64 = 0;
    for job in &jobs {
        let res = verify_script(
            &job.script_sig,
            &job.spk,
            &job.tx,
            job.n_in,
            Satoshi::new(job.amount),
            job.flags,
        );
        // We expect every job to pass; assert to catch regressions but
        // don't `expect()` so a failure prints location not panic noise.
        if res.is_ok() {
            total += 1;
        } else {
            panic!("verify_script failed unexpectedly on a real-mainnet input: {res:?}");
        }
    }
    eprintln!("parity-dhat: verified {} / {} inputs", total, jobs.len());
}
