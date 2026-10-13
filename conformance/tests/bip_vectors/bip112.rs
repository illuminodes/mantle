//! BIP112 — `OP_CHECKSEQUENCEVERIFY` test vectors.
//!
//! Script shape (lock-then-drop pattern):
//!   scriptPubKey:  `<sequence> OP_CHECKSEQUENCEVERIFY OP_DROP OP_1`
//!   scriptSig:     empty
//!
//! BIP112 interacts with BIP68 (transaction version ≥ 2) and the two-layer
//! nSequence bitmask: bit 31 (disable flag), bit 22 (blocks vs. 512-sec units),
//! and bits 0–15 (the locktime value).

use mantle::primitives::{
    Hash256, Locktime, OutPoint, Satoshi, Sequence, Transaction, TxIn, TxOut, TxVersion, Witness,
};

use mantle_consensus::script::{ScriptFlags, verify_script};

// ── Constants (BIP68 / BIP112) ────────────────────────────────────────────────

const SEQ_DISABLE: u32 = 1 << 31;
const SEQ_TYPE: u32 = 1 << 22; // 0 = blocks, 1 = 512-sec units

// ── Helpers ───────────────────────────────────────────────────────────────────

fn push_scriptnum(value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![0x00];
    }
    let abs = value.unsigned_abs();
    let negative = value < 0;
    let mut bytes = Vec::new();
    let mut remaining = abs;
    while remaining > 0 {
        bytes.push((remaining & 0xff) as u8);
        remaining >>= 8;
    }
    if bytes.last().is_some_and(|&b| b & 0x80 != 0) {
        bytes.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        *bytes.last_mut().expect("non-empty") |= 0x80;
    }
    let len = u8::try_from(bytes.len()).expect("script number > 255 bytes");
    let mut out = vec![len];
    out.extend(bytes);
    out
}

/// `<sequence> OP_CHECKSEQUENCEVERIFY OP_DROP OP_1`
fn csv_spk(sequence: i64) -> Vec<u8> {
    let mut s = push_scriptnum(sequence);
    s.push(0xb2); // OP_CHECKSEQUENCEVERIFY
    s.push(0x75); // OP_DROP
    s.push(0x51); // OP_1
    s
}

fn make_tx(version: i32, n_sequence: u32) -> Transaction {
    Transaction {
        version: TxVersion::new(version),
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_bytes([0x22; 32]),
                vout: 0,
            },
            script_sig: Vec::<u8>::new().into(),
            sequence: Sequence::new(n_sequence),
            witness: Witness::empty(),
        }],
        outputs: vec![TxOut {
            value: Satoshi::new(1000),
            script_pubkey: vec![0x51].into(),
        }],
        locktime: Locktime::new(0),
    }
}

fn flags() -> ScriptFlags {
    ScriptFlags::P2SH | ScriptFlags::CHECKSEQUENCEVERIFY
}

// ── BIP112 §Accept ────────────────────────────────────────────────────────────

/// Require 5 blocks; nSequence encodes 5 blocks → satisfied.
#[test]
fn csv_blocks_exact_match_accepts() {
    let spk = csv_spk(5);
    let tx = make_tx(2, 5); // version 2, nSequence = 5 blocks
    assert!(verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), flags()).is_ok());
}

/// Require 5 blocks; nSequence encodes 10 blocks → tx provides more → satisfied.
#[test]
fn csv_blocks_tx_greater_accepts() {
    let spk = csv_spk(5);
    let tx = make_tx(2, 10);
    assert!(verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), flags()).is_ok());
}

/// Require 100 time-units; nSequence encodes 200 time-units → satisfied.
#[test]
fn csv_time_tx_greater_accepts() {
    let spk = csv_spk(i64::from(SEQ_TYPE | 0x0064));
    let tx = make_tx(2, SEQ_TYPE | 0x00c8);
    assert!(verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), flags()).is_ok());
}

/// Stack value has the disable flag set (bit 31) → CSV is a no-op → passes.
#[test]
fn csv_stack_disable_flag_is_nop_accepts() {
    // The *script* value has bit 31 set. CSV is inert in that case regardless
    // of the tx — BIP112 §"OP_CHECKSEQUENCEVERIFY".
    let spk = csv_spk(i64::from(SEQ_DISABLE | 0x03e7));
    let tx = make_tx(2, 0); // nSequence 0 would normally fail for a 999-unit req
    assert!(verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), flags()).is_ok());
}

// ── BIP112 §Reject ────────────────────────────────────────────────────────────

/// Require 10 blocks; nSequence encodes only 5 → not satisfied.
#[test]
fn csv_blocks_tx_too_low_rejects() {
    let spk = csv_spk(10);
    let tx = make_tx(2, 5);
    assert!(verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), flags()).is_err());
}

/// BIP68 only applies to tx version ≥ 2. Version 1 → CSV fails.
#[test]
fn csv_version_1_tx_rejects() {
    let spk = csv_spk(1);
    let tx = make_tx(1, 1); // version 1 disables BIP68
    assert!(verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), flags()).is_err());
}

/// nSequence has the disable flag (bit 31) set → the *input* opted out of
/// relative locktime. CSV must reject even if the numeric parts would match.
#[test]
fn csv_input_disable_flag_rejects() {
    let spk = csv_spk(5);
    let tx = make_tx(2, SEQ_DISABLE | 5); // bit 31 on nSequence
    assert!(verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), flags()).is_err());
}

/// Script requests blocks (bit 22 clear), nSequence encodes time (bit 22 set) →
/// type mismatch → reject.
#[test]
fn csv_type_mismatch_blocks_vs_time_rejects() {
    let spk = csv_spk(10); // blocks
    let tx = make_tx(2, SEQ_TYPE | 0x000a); // time
    assert!(verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), flags()).is_err());
}

/// Script requests time (bit 22 set), nSequence encodes blocks (bit 22 clear) →
/// type mismatch → reject.
#[test]
fn csv_type_mismatch_time_vs_blocks_rejects() {
    let spk = csv_spk(i64::from(SEQ_TYPE | 0x000a)); // time
    let tx = make_tx(2, 10); // blocks
    assert!(verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), flags()).is_err());
}

/// Negative value on the stack is always an error.
#[test]
fn csv_negative_rejects() {
    let spk = csv_spk(-1);
    let tx = make_tx(2, 0xffff_fffe);
    assert!(verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), flags()).is_err());
}

// ── Flag gating ───────────────────────────────────────────────────────────────

/// Without `CHECKSEQUENCEVERIFY` flag, `OP_NOP3` is a no-op → script passes.
#[test]
fn csv_without_flag_is_nop_accepts() {
    let spk = csv_spk(9999); // would fail if CSV were enforced
    let tx = make_tx(1, 0); // version 1 + nSequence 0 would also fail
    let no_csv = ScriptFlags::P2SH;
    assert!(verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), no_csv).is_ok());
}

/// `DISCOURAGE_UPGRADABLE_NOPS` + no `CHECKSEQUENCEVERIFY` → `OP_NOP3` fails.
#[test]
fn csv_without_flag_but_discourage_rejects() {
    let spk = csv_spk(0);
    let tx = make_tx(2, 0);
    let f = ScriptFlags::P2SH | ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS;
    assert!(verify_script(&[], &spk, &tx, 0, Satoshi::new(1000), f).is_err());
}

/// Both BIP65 and BIP112 flags together: a script that chains CLTV then CSV.
/// scriptPubKey: `<height> CLTV DROP <blocks> CSV DROP OP_1`
#[test]
fn cltv_and_csv_combined_accepts() {
    // scriptPubKey: OP_PUSHBYTES_1 0x64 CLTV DROP OP_PUSHBYTES_1 0x05 CSV DROP OP_1
    // height 100 = 0x64 (single byte, high bit clear — no sign extension needed)
    // blocks 5  = 0x05
    let spk: &[u8] = &[
        0x01, 0x64, // push 100
        0xb1, // OP_CHECKLOCKTIMEVERIFY
        0x75, // OP_DROP
        0x01, 0x05, // push 5
        0xb2, // OP_CHECKSEQUENCEVERIFY
        0x75, // OP_DROP
        0x51, // OP_1
    ];

    let tx = Transaction {
        version: TxVersion::new(2),
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_bytes([0x33; 32]),
                vout: 0,
            },
            script_sig: Vec::<u8>::new().into(),
            sequence: Sequence::new(5), // 5 blocks
            witness: Witness::empty(),
        }],
        outputs: vec![TxOut {
            value: Satoshi::new(1000),
            script_pubkey: vec![0x51].into(),
        }],
        locktime: Locktime::new(200), // ≥ 100
    };

    let f = ScriptFlags::P2SH | ScriptFlags::CHECKLOCKTIMEVERIFY | ScriptFlags::CHECKSEQUENCEVERIFY;
    assert!(verify_script(&[], spk, &tx, 0, Satoshi::new(1000), f).is_ok());
}
