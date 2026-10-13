//! Consensus heap profiler — dhat allocation analysis.
//!
//! Run with:
//!   cargo build --release --bin consensus-dhat
//!   ./target/release/consensus-dhat
//!
//! Prints an allocation summary table to stderr on exit.

#[path = "fixtures.rs"]
#[allow(clippy::wildcard_imports)]
mod fixtures;

use fixtures::{
    ITERS_LARGE, ITERS_MEDIUM, ITERS_SMALL, encode, make_n_tx_block, make_p2wpkh, make_p2wsh,
    make_taproot_keypath, segwit_flags, taproot_flags,
};
use mantle::primitives::{BlockHeight, Hash256, OutPoint, Satoshi};
use mantle_consensus::chain_view::{ChainView, Coin, MemoryChainView};
use mantle_consensus::merkle::compute_merkle_root_reusing;
use mantle_consensus::script::checker::TxSigChecker;
use mantle_consensus::script::verify::{ScriptVerifier, verify_script};
use mantle_consensus::script::{
    InterpStackElement, Interpreter, NopSigChecker, ScriptFlags, SigVersion,
};
use mantle_consensus::validation::{validate_block_structure_reusing, validate_block_wire};
use std::collections::HashSet;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[allow(clippy::too_many_lines)]
fn main() {
    let _profiler = dhat::Profiler::new_heap();

    // ── Stage 1: validate_block_structure (100-tx, 500 iters) ───────────────
    {
        let block = make_n_tx_block(100);
        let mut serial = Vec::new();
        let mut txids = Vec::new();
        let mut merkle_buf = Vec::new();
        let mut seen_in = HashSet::new();
        let mut seen_tx = HashSet::new();
        for _ in 0..ITERS_SMALL {
            validate_block_structure_reusing(
                &block,
                &mut serial,
                &mut txids,
                &mut merkle_buf,
                &mut seen_in,
                &mut seen_tx,
            )
            .expect("valid block");
        }
        eprintln!("stage1_structure: {ITERS_SMALL} iters done");
    }

    // ── Stage 1: validate_block_wire (100-tx, 500 iters) ────────────────────
    {
        let wire = encode(&make_n_tx_block(100));
        let mut txids = Vec::new();
        let mut merkle_buf = Vec::new();
        let mut seen_in: HashSet<OutPoint> = HashSet::new();
        let mut seen_tx: HashSet<Hash256> = HashSet::new();
        for _ in 0..ITERS_SMALL {
            validate_block_wire(
                &wire,
                &mut txids,
                &mut merkle_buf,
                &mut seen_in,
                &mut seen_tx,
            )
            .expect("valid wire");
        }
        eprintln!("stage1_wire: {ITERS_SMALL} iters done");
    }

    // ── Merkle root (1000 txids, 500 iters) ─────────────────────────────────
    {
        let template: Vec<Hash256> = (0..1000u32)
            .map(|i| Hash256::from_bytes([(i & 0xff) as u8; 32]))
            .collect();
        let mut buf = Vec::with_capacity(template.len());
        for _ in 0..ITERS_SMALL {
            let _ = compute_merkle_root_reusing(&template, &mut buf);
        }
        eprintln!("merkle_root(1000): {ITERS_SMALL} iters done");
    }

    // ── ChainView coin ops (5000 iters) ─────────────────────────────────────
    {
        let mut view = MemoryChainView::new();
        for i in 0..5000u32 {
            let op = OutPoint {
                txid: Hash256::hash(&i.to_le_bytes()),
                vout: 0,
            };
            view.insert_coin(
                op,
                Coin {
                    value: Satoshi::new(1000),
                    script_pubkey: vec![0x51].into(),
                    height: BlockHeight::new(i),
                    coinbase: false,
                },
            );
            let _ = view.get_coin(&op);
            view.spend_coin(&op);
        }
        eprintln!("chain_view_coins: 5000 iters done");
    }

    // ── Script interpreter NOP dispatch (10000 iters) ───────────────────────
    {
        let checker = NopSigChecker;
        let script = vec![0x61u8; 200];
        for _ in 0..ITERS_LARGE {
            let mut interp = Interpreter::new(&checker, ScriptFlags::NONE, SigVersion::Base);
            interp.eval(&script).expect("NOP script must succeed");
        }
        eprintln!("script_eval(200 NOPs): {ITERS_LARGE} iters done");
    }

    // ── P2WPKH verify (2000 iters, fresh) ───────────────────────────────────
    {
        let fix = make_p2wpkh();
        let flags = segwit_flags();
        for _ in 0..ITERS_MEDIUM {
            verify_script(&[], &fix.spk, &fix.tx, 0, fix.amount, flags).expect("p2wpkh");
        }
        eprintln!("verify_p2wpkh: {ITERS_MEDIUM} iters done");
    }

    // ── P2WPKH verify with buffer reuse (2000 iters) ────────────────────────
    {
        let fix = make_p2wpkh();
        let flags = segwit_flags();
        let verifier = ScriptVerifier::new(&fix.tx, 0, fix.amount, flags);
        let mut bufs: (Vec<InterpStackElement>, Vec<InterpStackElement>) = (Vec::new(), Vec::new());
        for _ in 0..ITERS_MEDIUM {
            let (r, b) = verifier.verify_with_bufs(&[], &fix.spk, bufs);
            r.expect("p2wpkh");
            bufs = b;
        }
        eprintln!("verify_p2wpkh_reuse: {ITERS_MEDIUM} iters done");
    }

    // ── P2WSH verify (1000 iters) ───────────────────────────────────────────
    {
        let fix = make_p2wsh();
        let flags = segwit_flags();
        for _ in 0..1000 {
            verify_script(&[], &fix.spk, &fix.tx, 0, fix.amount, flags).expect("p2wsh");
        }
        eprintln!("verify_p2wsh: 1000 iters done");
    }

    // ── Taproot key-path verify (1000 iters) ────────────────────────────────
    {
        let fix = make_taproot_keypath();
        let flags = taproot_flags();
        for _ in 0..1000 {
            verify_script(&[], &fix.spk, &fix.tx, 0, fix.amount, flags).expect("taproot");
        }
        eprintln!("verify_taproot_keypath: 1000 iters done");
    }

    // ── CLTV + CSV opcode throughput (10000 iters each) ─────────────────────
    {
        let cltv_spk: &[u8] = &[0x01, 0x64, 0xb1, 0x75, 0x51];
        let cltv_flags = ScriptFlags::P2SH | ScriptFlags::CHECKLOCKTIMEVERIFY;
        let cltv_tx = mantle::primitives::Transaction {
            version: mantle::primitives::TxVersion::new(1),
            inputs: vec![mantle::primitives::TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([0x33; 32]),
                    vout: 0,
                },
                script_sig: vec![].into(),
                sequence: mantle::primitives::Sequence::new(0xffff_fffe),
                witness: mantle::primitives::Witness::empty(),
            }],
            outputs: vec![mantle::primitives::TxOut {
                value: Satoshi::new(1000),
                script_pubkey: vec![0x51].into(),
            }],
            locktime: mantle::primitives::Locktime::new(200),
        };
        for _ in 0..ITERS_LARGE {
            let checker = TxSigChecker::new(&cltv_tx, 0, Satoshi::new(1000), cltv_flags);
            let mut interp = Interpreter::new(&checker, cltv_flags, SigVersion::Base);
            interp.eval(cltv_spk).expect("CLTV must pass");
        }
        eprintln!("cltv_throughput: {ITERS_LARGE} iters done");

        let csv_spk: &[u8] = &[0x01, 0x05, 0xb2, 0x75, 0x51];
        let csv_flags = ScriptFlags::P2SH | ScriptFlags::CHECKSEQUENCEVERIFY;
        let csv_tx = mantle::primitives::Transaction {
            version: mantle::primitives::TxVersion::new(2),
            inputs: vec![mantle::primitives::TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([0x44; 32]),
                    vout: 0,
                },
                script_sig: vec![].into(),
                sequence: mantle::primitives::Sequence::new(10),
                witness: mantle::primitives::Witness::empty(),
            }],
            outputs: vec![mantle::primitives::TxOut {
                value: Satoshi::new(1000),
                script_pubkey: vec![0x51].into(),
            }],
            locktime: mantle::primitives::Locktime::new(0),
        };
        for _ in 0..ITERS_LARGE {
            let checker = TxSigChecker::new(&csv_tx, 0, Satoshi::new(1000), csv_flags);
            let mut interp = Interpreter::new(&checker, csv_flags, SigVersion::Base);
            interp.eval(csv_spk).expect("CSV must pass");
        }
        eprintln!("csv_throughput: {ITERS_LARGE} iters done");
    }

    eprintln!("all scenarios complete — dhat summary follows");
}
