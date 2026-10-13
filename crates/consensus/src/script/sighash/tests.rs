use super::*;
use mantle::primitives::{Locktime, OutPoint, Satoshi, Sequence, TxVersion, Witness};

fn make_tx() -> Transaction {
    Transaction {
        version: TxVersion::new(1),
        inputs: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([0x11; 32]),
                    vout: 0,
                },
                script_sig: vec![0xaa].into(),
                sequence: Sequence::new(0xffff_fffe),
                witness: Witness::empty(),
            },
            TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([0x22; 32]),
                    vout: 1,
                },
                script_sig: vec![0xbb].into(),
                sequence: Sequence::new(0xffff_fffd),
                witness: Witness::empty(),
            },
        ],
        outputs: vec![
            TxOut {
                value: Satoshi::new(1_000),
                script_pubkey: vec![0xcc].into(),
            },
            TxOut {
                value: Satoshi::new(2_000),
                script_pubkey: vec![0xdd].into(),
            },
        ],
        locktime: Locktime::new(0),
    }
}

#[test]
fn sighash_type_mode_decoding() {
    assert_eq!(SigHashType(0x01).mode(), SigHashMode::All);
    assert_eq!(SigHashType(0x02).mode(), SigHashMode::None);
    assert_eq!(SigHashType(0x03).mode(), SigHashMode::Single);
    // ANYONECANPAY bit doesn't change the mode.
    assert_eq!(SigHashType(0x81).mode(), SigHashMode::All);
    assert_eq!(SigHashType(0x82).mode(), SigHashMode::None);
    assert_eq!(SigHashType(0x83).mode(), SigHashMode::Single);
    // Unknown modes fall through to ALL.
    assert_eq!(SigHashType(0x05).mode(), SigHashMode::All);
}

#[test]
fn anyonecanpay_bit() {
    assert!(!SigHashType(0x01).is_anyonecanpay());
    assert!(SigHashType(0x81).is_anyonecanpay());
    assert!(SigHashType(0x83).is_anyonecanpay());
}

#[test]
fn sighash_single_one_bug() {
    // Two inputs, two outputs. n_in = 5 → past the last output → "1" digest.
    let tx = make_tx();
    let h = tx.legacy_sighash(5, &[0xab], SigHashType::SINGLE);
    let mut expected = [0u8; 32];
    expected[0] = 0x01;
    assert_eq!(*h.as_bytes(), expected);
}

#[test]
fn sighash_single_at_boundary_is_one_bug() {
    // n_in = 2 (== n_outputs) is also the "1" digest.
    let tx = make_tx();
    let h = tx.legacy_sighash(2, &[0xab], SigHashType::SINGLE);
    let mut expected = [0u8; 32];
    expected[0] = 0x01;
    assert_eq!(*h.as_bytes(), expected);
}

#[test]
fn sighash_all_differs_from_none_and_single() {
    let tx = make_tx();
    let all = tx.legacy_sighash(0, &[0xab], SigHashType::ALL);
    let none = tx.legacy_sighash(0, &[0xab], SigHashType::NONE);
    let single = tx.legacy_sighash(0, &[0xab], SigHashType::SINGLE);
    assert_ne!(all, none);
    assert_ne!(all, single);
    assert_ne!(none, single);
}

#[test]
fn sighash_anyonecanpay_changes_digest() {
    let tx = make_tx();
    let standard = tx.legacy_sighash(0, &[0xab], SigHashType::ALL);
    let anyone = tx.legacy_sighash(0, &[0xab], SigHashType(0x81));
    assert_ne!(standard, anyone);
}

#[test]
fn sighash_changes_with_input_index() {
    let tx = make_tx();
    let h0 = tx.legacy_sighash(0, &[0xab], SigHashType::ALL);
    let h1 = tx.legacy_sighash(1, &[0xab], SigHashType::ALL);
    assert_ne!(h0, h1);
}

#[test]
fn modified_tx_clears_other_input_scripts_under_sighash_all() {
    let tx = make_tx();
    let m = build_modified_tx(&tx, 0, &[0x99], SigHashType::ALL);
    assert_eq!(m.inputs[0].script_sig.as_slice(), &[0x99]);
    assert!(m.inputs[1].script_sig.is_empty());
    // SIGHASH_ALL preserves sequence on every input.
    assert_eq!(m.inputs[1].sequence, tx.inputs[1].sequence);
    // Outputs unchanged.
    assert_eq!(m.outputs.len(), 2);
}

#[test]
fn modified_tx_under_sighash_none_drops_outputs_and_seq() {
    let tx = make_tx();
    let m = build_modified_tx(&tx, 0, &[0x99], SigHashType::NONE);
    assert!(m.outputs.is_empty());
    assert_eq!(m.inputs[0].sequence, tx.inputs[0].sequence);
    assert_eq!(m.inputs[1].sequence, Sequence::new(0)); // zeroed
}

#[test]
fn modified_tx_under_anyonecanpay_keeps_only_self_input() {
    let tx = make_tx();
    let m = build_modified_tx(&tx, 1, &[0x99], SigHashType(0x81));
    assert_eq!(m.inputs.len(), 1);
    assert_eq!(m.inputs[0].previous_output, tx.inputs[1].previous_output);
    assert_eq!(m.inputs[0].script_sig.as_slice(), &[0x99]);
}

#[test]
fn modified_tx_under_sighash_single_truncates_outputs() {
    let tx = make_tx();
    let m = build_modified_tx(&tx, 1, &[0x99], SigHashType::SINGLE);
    // Outputs has length n_in + 1 = 2. Output[0] is the null sentinel,
    // output[1] is the real output at index n_in.
    assert_eq!(m.outputs.len(), 2);
    assert_eq!(m.outputs[0].value.to_u64(), u64::MAX);
    assert!(m.outputs[0].script_pubkey.is_empty());
    assert_eq!(m.outputs[1], tx.outputs[1]);
}

// ── FindAndDelete ───────────────────────────────────────────────────────

#[test]
fn find_and_delete_removes_exact_push() {
    // Script: <push 3 [0xaa,0xbb,0xcc]> OP_DUP <push 2 [0xaa,0xbb,0xcc]> OP_DROP
    let mut script = Vec::new();
    script.push(0x03);
    script.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
    script.push(0x76); // OP_DUP
    script.push(0x03);
    script.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
    script.push(0x75); // OP_DROP
    let out = find_and_delete_sig(&script, &[0xaa, 0xbb, 0xcc]);
    assert_eq!(out, vec![0x76, 0x75]);
}

#[test]
fn find_and_delete_doesnt_match_partial() {
    // Pushed payload contains the sig as a substring but is not equal to it.
    let mut script = vec![0x04];
    script.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
    let out = find_and_delete_sig(&script, &[0xaa, 0xbb, 0xcc]);
    assert_eq!(out, script);
}

#[test]
fn find_and_delete_empty_sig_doesnt_match_op0() {
    // OP_0 is byte 0x00 — not a push of empty under FindAndDelete (Core's
    // FindAndDelete only matches actual data pushes).
    let script = vec![0x00, 0x76];
    let out = find_and_delete_sig(&script, &[]);
    assert_eq!(out, script);
}

#[test]
fn find_and_delete_pushdata1_match() {
    // OP_PUSHDATA1 [0x03] [0xaa,0xbb,0xcc] then OP_DUP
    let script = vec![0x4c, 0x03, 0xaa, 0xbb, 0xcc, 0x76];
    let out = find_and_delete_sig(&script, &[0xaa, 0xbb, 0xcc]);
    assert_eq!(out, vec![0x76]);
}

// ── pushed_span coverage (via find_and_delete_sig) ──────────────────────

#[test]
fn find_and_delete_pushdata2_match() {
    // OP_PUSHDATA2 [0x03, 0x00] (little-endian len=3) [0xaa,0xbb,0xcc] OP_DUP
    let script = vec![0x4d, 0x03, 0x00, 0xaa, 0xbb, 0xcc, 0x76];
    let out = find_and_delete_sig(&script, &[0xaa, 0xbb, 0xcc]);
    assert_eq!(out, vec![0x76]);
}

#[test]
fn find_and_delete_pushdata4_match() {
    // OP_PUSHDATA4 [0x02, 0x00, 0x00, 0x00] (len=2) [0xdd, 0xee] OP_NOP
    let script = vec![0x4e, 0x02, 0x00, 0x00, 0x00, 0xdd, 0xee, 0x61];
    let out = find_and_delete_sig(&script, &[0xdd, 0xee]);
    assert_eq!(out, vec![0x61]);
}

#[test]
fn find_and_delete_pushdata2_truncated_header() {
    // OP_PUSHDATA2 but only one length byte available — truncated push.
    // Should be treated as a non-push opcode and passed through.
    let script = vec![0x4d, 0x03];
    let out = find_and_delete_sig(&script, &[0x03]);
    // The truncated push is passed through byte by byte.
    assert_eq!(out, script);
}

#[test]
fn find_and_delete_pushdata4_truncated_header() {
    // OP_PUSHDATA4 with only 3 length bytes — truncated.
    let script = vec![0x4e, 0x01, 0x00, 0x00];
    let out = find_and_delete_sig(&script, &[0x01]);
    assert_eq!(out, script);
}

#[test]
fn find_and_delete_pushdata2_truncated_data() {
    // OP_PUSHDATA2 declares 5 bytes but only 2 are present.
    let script = vec![0x4d, 0x05, 0x00, 0xaa, 0xbb];
    let out = find_and_delete_sig(&script, &[0xaa, 0xbb]);
    assert_eq!(out, script);
}

#[test]
fn find_and_delete_pushdata4_truncated_data() {
    // OP_PUSHDATA4 declares 10 bytes but only 1 is present.
    let script = vec![0x4e, 0x0a, 0x00, 0x00, 0x00, 0xcc];
    let out = find_and_delete_sig(&script, &[0xcc]);
    assert_eq!(out, script);
}

#[test]
fn find_and_delete_pushdata1_truncated_header() {
    // OP_PUSHDATA1 at end of script — no length byte.
    let script = vec![0x4c];
    let out = find_and_delete_sig(&script, &[]);
    assert_eq!(out, script);
}

#[test]
fn find_and_delete_direct_push_truncated() {
    // OP_PUSHBYTES_5 but only 2 data bytes — truncated.
    let script = vec![0x05, 0xaa, 0xbb];
    let out = find_and_delete_sig(&script, &[0xaa, 0xbb]);
    assert_eq!(out, script);
}

#[test]
fn find_and_delete_non_push_opcode_passthrough() {
    // All non-push opcodes (>= 0x4f) are passed through unchanged.
    let script = vec![0x76, 0xa9, 0x88]; // OP_DUP OP_HASH160 OP_EQUALVERIFY
    let out = find_and_delete_sig(&script, &[0x76]);
    assert_eq!(out, script); // none are pushes, so nothing matches
}

// ── script_code_after_codeseparator ─────────────────────────────────────

#[test]
fn codesep_slice_returns_suffix() {
    let script = [0x01, 0xaa, 0xab, 0x02, 0xbb, 0xcc];
    assert_eq!(script_code_after_codeseparator(&script, 0), &script);
    assert_eq!(script_code_after_codeseparator(&script, 3), &script[3..]);
    assert_eq!(script_code_after_codeseparator(&script, 6), &[] as &[u8]);
}

#[test]
fn codesep_slice_out_of_bounds_is_empty() {
    let script = [0x01, 0xaa];
    assert_eq!(script_code_after_codeseparator(&script, 99), &[] as &[u8]);
}

// ── BIP143 test vectors ─────────────────────────────────────────────────
//
// Source: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
// "Native P2WPKH" example transaction.

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn hash256_from_hex(s: &str) -> Hash256 {
    let b = hex(s);
    assert_eq!(b.len(), 32);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&b);
    Hash256::from_bytes(arr)
}

/// Build the BIP143 "Native P2WPKH" example transaction.
///
/// Source: <https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki>
/// Unsigned tx hex (no witnesses, no scriptSigs):
/// 0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f
/// 0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57
/// b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85
/// c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce
/// 2f0167faa815988ac11000000
fn bip143_p2wpkh_tx() -> Transaction {
    Transaction {
        version: TxVersion::new(1),
        inputs: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: hash256_from_hex(
                        "fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f",
                    ),
                    vout: 0,
                },
                script_sig: vec![].into(),
                sequence: Sequence::new(0xffff_ffee),
                witness: Witness::empty(),
            },
            TxIn {
                previous_output: OutPoint {
                    txid: hash256_from_hex(
                        "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a",
                    ),
                    vout: 1,
                },
                script_sig: vec![].into(),
                sequence: Sequence::new(0xffff_ffff),
                witness: Witness::empty(),
            },
        ],
        outputs: vec![
            TxOut {
                value: Satoshi::new(112_340_000),
                script_pubkey: hex("76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac").into(),
            },
            TxOut {
                value: Satoshi::new(223_450_000),
                script_pubkey: hex("76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac").into(),
            },
        ],
        locktime: Locktime::new(0x11),
    }
}

#[test]
fn bip143_hash_prevouts() {
    let tx = bip143_p2wpkh_tx();
    let cache = Bip143Cache::new(&tx);
    // hashPrevouts from BIP143 §"Native P2WPKH"
    assert_eq!(
        cache.prevouts,
        hash256_from_hex("96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37"),
    );
}

#[test]
fn bip143_hash_sequence() {
    let tx = bip143_p2wpkh_tx();
    let cache = Bip143Cache::new(&tx);
    // hashSequence from BIP143 §"Native P2WPKH"
    assert_eq!(
        cache.sequence,
        hash256_from_hex("52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b"),
    );
}

#[test]
fn bip143_hash_outputs() {
    let tx = bip143_p2wpkh_tx();
    let cache = Bip143Cache::new(&tx);
    // hashOutputs from BIP143 §"Native P2WPKH"
    assert_eq!(
        cache.outputs,
        hash256_from_hex("863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5"),
    );
}

#[test]
fn bip143_sighash_input1_p2wpkh() {
    let tx = bip143_p2wpkh_tx();
    let cache = Bip143Cache::new(&tx);

    // Input 1 signs a P2WPKH. scriptCode = synthetic P2PKH over the pubkeyhash
    // embedded in the witness program. The BIP gives:
    // scriptCode = 1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac
    // where 0x19 is the VarInt length prefix consumed by the sighash preimage.
    // We pass the raw script (without the VarInt prefix).
    let script_code = hex("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac");
    let amount = Satoshi::new(600_000_000); // 6 BTC

    let digest = tx.bip143_sighash(1, &script_code, amount, SigHashType::ALL, &cache);

    // sigHash from BIP143 §"Native P2WPKH"
    assert_eq!(
        digest,
        hash256_from_hex("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"),
    );
}
