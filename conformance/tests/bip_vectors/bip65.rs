//! BIP65 — `OP_CHECKLOCKTIMEVERIFY` test vectors.
//!
//! Each vector drives `verify_script` directly, building a minimal transaction
//! whose `locktime` and input `sequence` fields produce the expected outcome.
//!
//! Script shape (lock-then-drop pattern):
//!   scriptPubKey:  `<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_1`
//!   scriptSig:     empty
//!
//! The `CHECKLOCKTIMEVERIFY` flag is required for `OP_NOP2` to be treated as
//! CLTV rather than a NOP. Without it the opcode is a no-op and the script
//! always succeeds; we cover that case explicitly.

use mantle::primitives::{
    Hash256, Locktime, OutPoint, Satoshi, Sequence, Transaction, TxIn, TxOut, TxVersion, Witness,
};

use mantle_consensus::script::{ScriptFlags, verify_script};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Encode `value` as a minimally-encoded `ScriptNum` push.
fn push_scriptnum(value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![0x00]; // OP_0
    }
    // Little-endian sign-magnitude.
    let abs = value.unsigned_abs();
    let negative = value < 0;
    let mut bytes = Vec::new();
    let mut remaining = abs;
    while remaining > 0 {
        bytes.push((remaining & 0xff) as u8);
        remaining >>= 8;
    }
    if bytes.last().is_some_and(|&b| b & 0x80 != 0) {
        // High bit of last byte is already set — add a sign byte.
        bytes.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        *bytes.last_mut().expect("non-empty") |= 0x80;
    }
    let len = u8::try_from(bytes.len()).expect("script number > 255 bytes");
    let mut out = vec![len];
    out.extend(bytes);
    out
}

/// `<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_1`
fn cltv_spk(locktime: i64) -> Vec<u8> {
    let mut s = push_scriptnum(locktime);
    s.push(0xb1); // OP_CHECKLOCKTIMEVERIFY
    s.push(0x75); // OP_DROP
    s.push(0x51); // OP_1
    s
}

fn make_tx(tx_locktime: u32, sequence: u32) -> Transaction {
    Transaction {
        version: TxVersion::new(1),
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_bytes([0x11; 32]),
                vout: 0,
            },
            script_sig: Vec::<u8>::new().into(),
            sequence: Sequence::new(sequence),
            witness: Witness::empty(),
        }],
        outputs: vec![TxOut {
            value: Satoshi::new(1000),
            script_pubkey: vec![0x51].into(),
        }],
        locktime: Locktime::new(tx_locktime),
    }
}

fn flags() -> ScriptFlags {
    ScriptFlags::P2SH | ScriptFlags::CHECKLOCKTIMEVERIFY
}

// ── BIP65 §Accept ─────────────────────────────────────────────────────────────

/// Lock at height 500; tx locktime 500 → satisfied.
#[test]
fn cltv_height_exact_match_accepts() {
    let spk = cltv_spk(500);
    let tx = make_tx(500, 0xffff_fffe); // sequence < 0xffffffff → nLockTime is active
    assert!(verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), flags()).is_ok());
}

/// Lock at height 100; tx locktime 200 → tx has a later locktime → satisfied.
#[test]
fn cltv_height_tx_locktime_greater_accepts() {
    let spk = cltv_spk(100);
    let tx = make_tx(200, 0xffff_fffe);
    assert!(verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), flags()).is_ok());
}

/// Lock at MTP-style locktime `500_000_001`; tx locktime `600_000_000` → satisfied.
#[test]
fn cltv_time_accepts() {
    let spk = cltv_spk(500_000_001);
    let tx = make_tx(600_000_000, 0xffff_fffe);
    assert!(verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), flags()).is_ok());
}

/// Lock value 0 → always satisfied when nLockTime is active.
#[test]
fn cltv_zero_locktime_accepts() {
    let spk = cltv_spk(0);
    let tx = make_tx(0, 0xffff_fffe);
    assert!(verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), flags()).is_ok());
}

// ── BIP65 §Reject ─────────────────────────────────────────────────────────────

/// nSequence == 0xffffffff disables nLockTime enforcement → CLTV must reject.
#[test]
fn cltv_sequence_max_rejects() {
    let spk = cltv_spk(100);
    let tx = make_tx(100, 0xffff_ffff); // locktime enforcement disabled
    let result = verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), flags());
    assert!(result.is_err());
}

/// Script locktime 200; tx locktime 100 → tx doesn't reach script's locktime.
#[test]
fn cltv_tx_locktime_too_low_rejects() {
    let spk = cltv_spk(200);
    let tx = make_tx(100, 0xffff_fffe);
    let result = verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), flags());
    assert!(result.is_err());
}

/// Mixing height-space (script = 100) with time-space (tx = `500_000_001`) → reject.
#[test]
fn cltv_type_mismatch_height_vs_time_rejects() {
    let spk = cltv_spk(100); // height-space
    let tx = make_tx(500_000_001, 0xffff_fffe); // time-space
    let result = verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), flags());
    assert!(result.is_err());
}

/// Mixing time-space (script = `500_000_001`) with height-space (tx = 100) → reject.
#[test]
fn cltv_type_mismatch_time_vs_height_rejects() {
    let spk = cltv_spk(500_000_001);
    let tx = make_tx(100, 0xffff_fffe);
    let result = verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), flags());
    assert!(result.is_err());
}

/// Negative locktime is always an error.
#[test]
fn cltv_negative_locktime_rejects() {
    let spk = cltv_spk(-1);
    let tx = make_tx(0, 0xffff_fffe);
    let result = verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), flags());
    assert!(result.is_err());
}

// ── Flag gating ───────────────────────────────────────────────────────────────

/// Without `CHECKLOCKTIMEVERIFY` flag, `OP_NOP2` is a no-op → script passes
/// regardless of the locktime mismatch.
#[test]
fn cltv_without_flag_is_nop_accepts() {
    let spk = cltv_spk(9999); // would fail if CLTV were enforced
    let tx = make_tx(0, 0xffff_fffe);
    // Only P2SH — no CLTV flag.
    let no_cltv = ScriptFlags::P2SH;
    assert!(verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), no_cltv).is_ok());
}

/// `DISCOURAGE_UPGRADABLE_NOPS` + no `CHECKLOCKTIMEVERIFY` → `OP_NOP2` fails.
#[test]
fn cltv_without_flag_but_discourage_rejects() {
    let spk = cltv_spk(0);
    let tx = make_tx(0, 0xffff_fffe);
    let f = ScriptFlags::P2SH | ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS;
    let result = verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), f);
    assert!(result.is_err());
}
