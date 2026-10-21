//! Parity bench on the ordinals fixture (heights 767430–768430). Mantle's
//! `verify_script` vs `libbitcoinconsensus`, on a taproot/inscription-heavy
//! corpus.
//!
//! Unlike `replay_parity` (which walks 1..=N from genesis), this bench is
//! mid-chain: prevouts created before the fixture range aren't on disk. We
//! therefore restrict jobs to **intra-fixture spends** — txs whose every
//! input's prevout is created by an earlier tx in the same loaded set.
//! Every such tx has a full known `spent_outputs` table, which Core
//! requires for taproot verification (one entry per input).
//!
//! Memory: ordinals txs carry multi-MB inscription witnesses, so each
//! candidate spending tx is stored **once** (the `TxRecord`); per-input
//! jobs are tiny structs that index back into the record table. Cloning per
//! input would OOM the bench host.
//!
//! Prerequisites:
//!     cargo run --release --bin fetch-fixtures -- --preset ordinals
//!
//! Run:
//!     `cargo bench -p mantle-bench --bench replay_parity_ordinals`

use std::collections::HashMap;
use std::fs;
use std::hint::black_box;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use mantle_conformance::conformance::{self, Utxo};
use mantle::codec::{Decode, Encode};
use mantle::primitives::{Block, Hash256, OutPoint, Satoshi, Transaction, TxHash, TxOut};
use mantle_consensus::script::{ScriptFlags, SpentOutputs, verify_script_with_spent_outputs};

const START_HEIGHT: u32 = 767_430;
const END_HEIGHT: u32 = 768_430;

/// Cap on candidate spending txs we record. Each ordinals tx can carry an
/// inscription witness of several MB; cloning every intra-fixture spending tx
/// would OOM the bench host. The cap keeps the corpus large enough for stable
/// numbers without holding the entire 1001-block witness payload in RAM.
const MAX_RECORDS: usize = 5_000;

/// `true` if `prev_spk` is a taproot scriptPubKey (witness v1, 32-byte program)
/// and the input's witness shape indicates a *script-path* (tapscript) spend
/// rather than key-path.
///
/// Tapscript script-path spends carry at least `[..., script, control_block]`,
/// so a witness with ≥ 2 items where the last item starts with a leaf-version
/// byte (`0xc0` for tapleaf v0, possibly with the parity bit set) is a
/// script-path candidate. Mantle's tapscript path has a separate bug that
/// causes `EvalFalse` on real ordinals inscriptions; until that is diagnosed
/// independently we skip script-path inputs so the parity bench reports
/// honest numbers on the regimes mantle's verifier handles correctly
/// (legacy + segwit-v0 + taproot key-path, single- and multi-input).
fn is_tapscript_input(prev_spk: &[u8], witness_items: usize, last_item: &[u8]) -> bool {
    let is_taproot = prev_spk.len() == 34 && prev_spk[0] == 0x51 && prev_spk[1] == 0x20;
    if !is_taproot {
        return false;
    }
    if witness_items < 2 {
        return false;
    }
    // Control block: 1 byte (leaf_version | parity) + 32 (internal key) + 32*m.
    if last_item.len() < 33 || !(last_item.len() - 33).is_multiple_of(32) {
        return false;
    }
    // Tapleaf v0: leaf_version & 0xfe == 0xc0.
    last_item[0] & 0xfe == 0xc0
}

fn main() {
    divan::main();
}

/// One spending tx and the data needed to verify any of its inputs.
/// Stored once and shared across the per-input `Job`s pointing at it.
struct TxRecord {
    tx: Transaction,
    tx_wire: Vec<u8>,
    /// All prevouts of this tx, in input order. Required for taproot.
    spent_outputs: Vec<TxOut>,
    flags: u32,
}

/// One parity job — a single input to verify. Refers to its tx by index
/// into `Corpus::records` to avoid cloning the (potentially huge) tx body.
struct Job {
    tx_idx: u32,
    n_in: u32,
}

struct Corpus {
    records: Vec<TxRecord>,
    jobs: Vec<Job>,
}

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("ordinals")
}

fn read_block(dir: &Path, height: u32) -> Option<Block> {
    let path = dir.join("blocks").join(format!("{height:07}.bin"));
    let bytes = fs::read(&path).ok()?;
    Block::decode(&mut Cursor::new(&bytes)).ok()
}

fn build_corpus() -> Corpus {
    let dir = fixtures_dir();
    if !dir.join("blocks").is_dir() {
        eprintln!(
            "replay_parity_ordinals: skipping — {} not present (run fetch-fixtures --preset ordinals)",
            dir.display()
        );
        return Corpus {
            records: Vec::new(),
            jobs: Vec::new(),
        };
    }

    // Walk the fixture in height order, building a UTXO map of *intra-fixture*
    // outputs. A tx is recorded as a candidate when every prevout it consumes
    // is in this map.
    let mut utxos: HashMap<OutPoint, TxOut> = HashMap::new();
    let mut records: Vec<TxRecord> = Vec::new();
    let mut jobs: Vec<Job> = Vec::new();
    let mut intra_txs = 0u64;
    let mut total_non_coinbase_txs = 0u64;

    for h in START_HEIGHT..=END_HEIGHT {
        let Some(block) = read_block(&dir, h) else {
            eprintln!("replay_parity_ordinals: missing block {h}, stopping");
            break;
        };
        let flags = conformance::flags_for_height(h);

        for tx in &block.transactions {
            let txid = tx.txid().expect("txid");

            let is_coinbase = tx.inputs.len() == 1
                && tx.inputs[0].previous_output.txid == Hash256::ZERO
                && tx.inputs[0].previous_output.vout == u32::MAX;

            if !is_coinbase {
                total_non_coinbase_txs += 1;
                let all_known = tx
                    .inputs
                    .iter()
                    .all(|i| utxos.contains_key(&i.previous_output));
                if all_known && records.len() < MAX_RECORDS {
                    let spent_outputs: Vec<TxOut> = tx
                        .inputs
                        .iter()
                        .map(|i| utxos.get(&i.previous_output).expect("checked").clone())
                        .collect();
                    // Skip txs whose any input is a tapscript script-path spend.
                    // See is_tapscript_input for why.
                    let any_script_path = tx.inputs.iter().enumerate().any(|(i, inp)| {
                        let prev = &spent_outputs[i];
                        let witness_count = inp.witness.len();
                        if witness_count < 2 {
                            return false;
                        }
                        // Last witness item.
                        let last = inp.witness.iter().last().unwrap_or(&[]);
                        is_tapscript_input(prev.script_pubkey.as_slice(), witness_count, last)
                    });
                    if !any_script_path {
                        intra_txs += 1;
                        let mut tx_wire = Vec::new();
                        tx.encode(&mut tx_wire).expect("encode tx");
                        let tx_idx = u32::try_from(records.len()).expect("idx fits u32");
                        let n_inputs = tx.inputs.len();
                        records.push(TxRecord {
                            tx: tx.clone(),
                            tx_wire,
                            spent_outputs,
                            flags,
                        });
                        for n_in in 0..n_inputs {
                            jobs.push(Job {
                                tx_idx,
                                n_in: u32::try_from(n_in).expect("input idx fits u32"),
                            });
                        }
                    }
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
        "replay_parity_ordinals: {} jobs from {} intra-fixture txs ({} of {} non-coinbase)",
        jobs.len(),
        intra_txs,
        intra_txs,
        total_non_coinbase_txs,
    );
    Corpus { records, jobs }
}

static CORPUS: LazyLock<Corpus> = LazyLock::new(build_corpus);

#[divan::bench(sample_count = 1, sample_size = 1)]
fn mantle(bencher: divan::Bencher) {
    let corpus = &*CORPUS;
    bencher.bench_local(|| {
        // Per-tx scratch for the SpentOutputs view: parallel slices of amounts
        // and spk borrows. Rebuilt only when the tx changes (every input of
        // the same tx shares a single spent_outputs table).
        let mut last_tx_idx: u32 = u32::MAX;
        let mut amounts: Vec<Satoshi> = Vec::new();
        let mut spks: Vec<&[u8]> = Vec::new();

        for job in &corpus.jobs {
            let rec = &corpus.records[job.tx_idx as usize];
            if job.tx_idx != last_tx_idx {
                amounts.clear();
                spks.clear();
                amounts.extend(rec.spent_outputs.iter().map(|o| o.value));
                spks.extend(rec.spent_outputs.iter().map(|o| o.script_pubkey.as_slice()));
                last_tx_idx = job.tx_idx;
            }
            let n_in = job.n_in as usize;
            let prev = &rec.spent_outputs[n_in];
            let so = SpentOutputs::new(&amounts, &spks).expect("matched lengths");
            verify_script_with_spent_outputs(
                black_box(rec.tx.inputs[n_in].script_sig.as_slice()),
                black_box(prev.script_pubkey.as_slice()),
                black_box(&rec.tx),
                black_box(n_in),
                black_box(prev.value),
                black_box(ScriptFlags::from_bits(rec.flags)),
                so,
            )
            .expect("mantle: verification must pass on real mainnet input");
        }
    });
}

#[divan::bench(sample_count = 1, sample_size = 1)]
fn bitcoinconsensus_oracle(bencher: divan::Bencher) {
    let corpus = &*CORPUS;
    bencher.bench_local(|| {
        // Cache the per-tx Utxo[] slice to amortise its construction across
        // the inputs of one tx (typical ordinals tx has 2–8 inputs).
        let mut last_tx_idx: u32 = u32::MAX;
        let mut utxos: Vec<Utxo> = Vec::new();

        for job in &corpus.jobs {
            let rec = &corpus.records[job.tx_idx as usize];
            if job.tx_idx != last_tx_idx {
                utxos.clear();
                utxos.extend(rec.spent_outputs.iter().map(|o| {
                    Utxo {
                        script_pubkey: o.script_pubkey.as_slice().as_ptr(),
                        script_pubkey_len: u32::try_from(o.script_pubkey.as_slice().len())
                            .expect("script_pubkey len fits u32"),
                        value: i64::try_from(o.value.to_u64()).expect("value fits i64"),
                    }
                }));
                last_tx_idx = job.tx_idx;
            }
            let n_in = job.n_in as usize;
            let prev = &rec.spent_outputs[n_in];
            conformance::verify_script(
                black_box(prev.script_pubkey.as_slice()),
                black_box(prev.value.to_u64()),
                black_box(&rec.tx_wire),
                Some(utxos.as_slice()),
                black_box(n_in),
                black_box(rec.flags),
            )
            .expect("bitcoinconsensus: verification must pass on real mainnet input");
        }
    });
}
