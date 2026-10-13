//! Consensus CPU profiler — pprof-rs sampling analysis.
//!
//! Run with:
//!   cargo build --release --bin consensus-pprof
//!   ./target/release/consensus-pprof [SCENARIO]
//!
//! Without arguments, runs all scenarios. Pass a scenario name to run just one:
//!   ./target/release/consensus-pprof `stage1_structure`
//!   ./target/release/consensus-pprof `verify_p2wpkh`
//!
//! Prints a per-function CPU table to stdout after each scenario.

#[path = "fixtures.rs"]
mod fixtures;

use fixtures::{
    encode, make_n_tx_block, make_p2wpkh, make_p2wsh, make_taproot_keypath, segwit_flags,
    taproot_flags,
};
use mantle::primitives::{Hash256, OutPoint};
use mantle_consensus::merkle::compute_merkle_root_reusing;
use mantle_consensus::script::verify::{ScriptVerifier, verify_script};
use mantle_consensus::script::{
    InterpStackElement, Interpreter, NopSigChecker, ScriptFlags, SigVersion,
};
use mantle_consensus::validation::{validate_block_structure_reusing, validate_block_wire};
use std::collections::HashSet;
use std::hint::black_box;
use std::time::{Duration, Instant};

#[path = "../pprof_common.rs"]
mod pprof_common;
use pprof_common::{print_top, profile};

fn run_stage1_structure() {
    let block = make_n_tx_block(100);
    let mut serial = Vec::new();
    let mut txids = Vec::new();
    let mut merkle_buf = Vec::new();
    let mut seen_in = HashSet::new();
    let mut seen_tx = HashSet::new();
    profile("stage1_structure(100tx)", 3, || {
        validate_block_structure_reusing(
            black_box(&block),
            &mut serial,
            &mut txids,
            &mut merkle_buf,
            &mut seen_in,
            &mut seen_tx,
        )
        .expect("valid block");
    });
}

fn run_stage1_wire() {
    let wire = encode(&make_n_tx_block(100));
    let mut txids = Vec::new();
    let mut merkle_buf = Vec::new();
    let mut seen_in: HashSet<OutPoint> = HashSet::new();
    let mut seen_tx: HashSet<Hash256> = HashSet::new();
    profile("stage1_wire(100tx)", 3, || {
        validate_block_wire(
            black_box(&wire),
            &mut txids,
            &mut merkle_buf,
            &mut seen_in,
            &mut seen_tx,
        )
        .expect("valid wire");
    });
}

fn run_merkle_root() {
    let template: Vec<Hash256> = (0..1000u32)
        .map(|i| Hash256::from_bytes([(i & 0xff) as u8; 32]))
        .collect();
    let mut buf = Vec::with_capacity(template.len());
    profile("merkle_root(1000)", 3, || {
        let _ = compute_merkle_root_reusing(black_box(&template), &mut buf);
    });
}

fn run_script_nop() {
    let checker = NopSigChecker;
    let script = vec![0x61u8; 200];
    profile("script_eval(200 NOPs)", 3, || {
        let mut interp = Interpreter::new(&checker, ScriptFlags::NONE, SigVersion::Base);
        interp.eval(black_box(&script)).expect("NOP script");
    });
}

fn run_verify_p2wpkh() {
    let fix = make_p2wpkh();
    let flags = segwit_flags();
    profile("verify_p2wpkh", 5, || {
        verify_script(
            black_box(&[]),
            black_box(&fix.spk),
            &fix.tx,
            0,
            fix.amount,
            flags,
        )
        .expect("p2wpkh");
    });
}

fn run_verify_p2wpkh_reuse() {
    let fix = make_p2wpkh();
    let flags = segwit_flags();
    let verifier = ScriptVerifier::new(&fix.tx, 0, fix.amount, flags);
    let mut bufs: (Vec<InterpStackElement>, Vec<InterpStackElement>) = (Vec::new(), Vec::new());

    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(997)
        .build()
        .expect("pprof profiler must initialize");

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut iters = 0u64;
    while Instant::now() < deadline {
        let (r, b) = verifier.verify_with_bufs(black_box(&[]), black_box(&fix.spk), bufs);
        r.expect("p2wpkh");
        bufs = b;
        iters += 1;
    }

    let report = guard.report().build().expect("pprof report must build");
    print_top(&report, "verify_p2wpkh_reuse", iters, 5);
}

fn run_verify_p2wsh() {
    let fix = make_p2wsh();
    let flags = segwit_flags();
    profile("verify_p2wsh", 5, || {
        verify_script(
            black_box(&[]),
            black_box(&fix.spk),
            &fix.tx,
            0,
            fix.amount,
            flags,
        )
        .expect("p2wsh");
    });
}

fn run_verify_taproot() {
    let fix = make_taproot_keypath();
    let flags = taproot_flags();
    profile("verify_taproot_keypath", 5, || {
        verify_script(
            black_box(&[]),
            black_box(&fix.spk),
            &fix.tx,
            0,
            fix.amount,
            flags,
        )
        .expect("taproot");
    });
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let filter = args.get(1).map(String::as_str);

    let scenarios: &[(&str, fn())] = &[
        ("stage1_structure", run_stage1_structure),
        ("stage1_wire", run_stage1_wire),
        ("merkle_root", run_merkle_root),
        ("script_nop", run_script_nop),
        ("verify_p2wpkh", run_verify_p2wpkh),
        ("verify_p2wpkh_reuse", run_verify_p2wpkh_reuse),
        ("verify_p2wsh", run_verify_p2wsh),
        ("verify_taproot", run_verify_taproot),
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
