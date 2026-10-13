//! BIP143 — segwit v0 sighash test vectors.
//!
//! All sighash digests, intermediate hashes, amounts, and scriptCodes are
//! taken verbatim from the BIP143 specification:
//!   <https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki>
//!
//! Coverage:
//!   §"Native P2WPKH"    — hashPrevouts / hashSequence / hashOutputs / sigHash
//!   §"P2SH-P2WPKH"      — hashPrevouts / hashSequence / hashOutputs / sigHash
//!   §"Native P2WSH"     — two signatures, `SIGHASH_SINGLE`, `FindAndDelete` scriptCode
//!   §"P2SH-P2WSH"       — all six sighash-type combinations on a 6-of-6 multisig
//!
//! Each test constructs the transaction from the BIP's unsigned hex, calls
//! `bip143_sighash`, and asserts the result matches the BIP's published digest.
//! No private keys or signature generation is needed — the published digests
//! are the ground truth.

use mantle::codec::Decode;
use mantle::primitives::{Hash256, Satoshi, Transaction};
use std::io::Cursor;

use mantle_consensus::script::sighash::{Bip143Cache, SigHashType, TxSighash};

// ── hex helpers ───────────────────────────────────────────────────────────────

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn h256(s: &str) -> Hash256 {
    let b = hex(s);
    assert_eq!(b.len(), 32, "expected 32-byte hash");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&b);
    Hash256::from_bytes(arr)
}

/// Decode a transaction from its legacy (non-witness) hex. Used for building
/// the sighash preimage — witness data is not needed for BIP143 digest tests.
fn decode_legacy_tx(hex_str: &str) -> Transaction {
    let raw = hex(hex_str);
    Transaction::decode(&mut Cursor::new(&raw)).expect("BIP143 tx hex must decode")
}

// ── §"Native P2WPKH" ─────────────────────────────────────────────────────────
//
// Source: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
//         §"Native P2WPKH"
//
// Unsigned tx (2 inputs; input 1 is the P2WPKH being signed):
//   0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f
//   0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57
//   b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85
//   c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce
//   2f0167faa815988ac11000000
//
// Intermediate hashes (verified in sighash/tests.rs which has crate-private access):
//   hashPrevouts: 96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37
//   hashSequence: 52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b
//   hashOutputs:  863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5

const P2WPKH_UNSIGNED_TX: &str = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f\
     0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57\
     b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85\
     c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce\
     2f0167faa815988ac11000000";

/// Input 1: P2WPKH, amount = `600_000_000` sat (6 BTC), `SIGHASH_ALL`.
/// scriptCode = synthetic P2PKH: 76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac
/// Expected sigHash: c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670
#[test]
fn p2wpkh_sighash_input1() {
    let tx = decode_legacy_tx(P2WPKH_UNSIGNED_TX);
    let cache = Bip143Cache::new(&tx);
    // scriptCode without its VarInt length prefix (bip143_sighash adds it)
    let script_code = hex("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac");
    let amount = Satoshi::new(600_000_000);
    let digest = tx.bip143_sighash(1, &script_code, amount, SigHashType::ALL, &cache);
    assert_eq!(
        digest,
        h256("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"),
        "P2WPKH input 1 sigHash mismatch"
    );
}

// ── §"P2SH-P2WPKH" ───────────────────────────────────────────────────────────
//
// Source: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
//         §"P2SH-P2WPKH"
//
// Single input (index 0), 10 BTC (1_000_000_000 sat), SIGHASH_ALL.
// scriptCode: 76a91479091972186c449eb1ded22b78e40d009bdf008988ac

// Intermediate hashes (verified in sighash/tests.rs which has crate-private access):
//   hashPrevouts: b0287b4a252ac05af83d2dcef00ba313af78a3e9c329afa216eb3aa2a7b4613a
//   hashSequence: 18606b350cd8bf565266bc352f0caddcf01e8fa789dd8a15386327cf8cabe198
//   hashOutputs:  de984f44532e2173ca0d64314fcefe6d30da6f8cf27bafa706da61df8a226c83

const P2SH_P2WPKH_UNSIGNED_TX: &str = "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477\
     0100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f3\
     5b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6\
     d77c88ac92040000";

/// Input 0: P2SH-P2WPKH, amount = `1_000_000_000` sat (10 BTC), `SIGHASH_ALL`.
/// Expected sigHash: 64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6
#[test]
fn p2sh_p2wpkh_sighash_input0() {
    let tx = decode_legacy_tx(P2SH_P2WPKH_UNSIGNED_TX);
    let cache = Bip143Cache::new(&tx);
    let script_code = hex("76a91479091972186c449eb1ded22b78e40d009bdf008988ac");
    let amount = Satoshi::new(1_000_000_000);
    let digest = tx.bip143_sighash(0, &script_code, amount, SigHashType::ALL, &cache);
    assert_eq!(
        digest,
        h256("64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"),
        "P2SH-P2WPKH input 0 sigHash mismatch"
    );
}

// ── §"Native P2WSH" ──────────────────────────────────────────────────────────
//
// Source: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
//         §"Native P2WSH"
//
// 2-input tx. Input 1 is a native P2WSH (2-of-2 multisig), signed with
// SIGHASH_SINGLE. The BIP applies FindAndDelete to the witnessScript when
// computing the scriptCode for each of the two signatures:
//   sig1 scriptCode includes both pubkeys (full witnessScript)
//   sig2 scriptCode has the first pubkey+sig stripped (FindAndDelete applied)
//
// hashSequence and hashOutputs are both zero (SIGHASH_SINGLE, n_in=1 > n_out=1,
// so the SIGHASH_SINGLE "1" bug applies for hashOutputs).

const P2WSH_UNSIGNED_TX: &str = "0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e\
     0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee\
     0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f7\
     51864167f32e0963f788ac00000000";

/// First signature on input 1 (full witnessScript as scriptCode), `SIGHASH_SINGLE`.
/// sigHash: 82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391
#[test]
fn p2wsh_sighash_input1_first_sig() {
    let tx = decode_legacy_tx(P2WSH_UNSIGNED_TX);
    let cache = Bip143Cache::new(&tx);
    // BIP shows scriptCode with leading VarInt (0x47=71); strip it — bip143_sighash adds it.
    let script_code = hex(
        "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880ae\
         adab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac",
    );
    let amount = Satoshi::new(4_900_000_000);
    let digest = tx.bip143_sighash(1, &script_code, amount, SigHashType::SINGLE, &cache);
    assert_eq!(
        digest,
        h256("82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391"),
        "P2WSH input 1 first-sig sigHash mismatch"
    );
}

/// Second signature on input 1 (`FindAndDelete` strips first key+sig from scriptCode).
/// sigHash: fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134fc47
#[test]
fn p2wsh_sighash_input1_second_sig() {
    let tx = decode_legacy_tx(P2WSH_UNSIGNED_TX);
    let cache = Bip143Cache::new(&tx);
    // BIP shows scriptCode with leading VarInt (0x23=35); strip it.
    let script_code = hex("210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac");
    let amount = Satoshi::new(4_900_000_000);
    let digest = tx.bip143_sighash(1, &script_code, amount, SigHashType::SINGLE, &cache);
    assert_eq!(
        digest,
        h256("fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134fc47"),
        "P2WSH input 1 second-sig sigHash mismatch"
    );
}

// ── §"P2SH-P2WSH" — all six sighash types ────────────────────────────────────
//
// Source: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
//         §"P2SH-P2WSH"
//
// Single input, 6-of-6 multisig witnessScript, amount = 987_654_321 sat.
// The BIP publishes the sigHash for all six SIGHASH_* combinations.

const P2SH_P2WSH_UNSIGNED_TX: &str = "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e\
     0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821f\
     fdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3e\
     e41588ac00000000";

/// 6-of-6 multisig witnessScript (same for all six sighash variants).
/// BIP preimage shows scriptCode with leading `VarInt` (0xcf=207); strip it.
fn p2sh_p2wsh_script_code() -> Vec<u8> {
    hex(
        "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3\
         2103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b2103\
         4b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400\
         f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b11\
         31e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b330\
         2ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae",
    )
}

const P2SH_P2WSH_AMOUNT: u64 = 987_654_321;

/// `SIGHASH_ALL` (0x01)
/// sigHash: 185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c
#[test]
fn p2sh_p2wsh_sighash_all() {
    let tx = decode_legacy_tx(P2SH_P2WSH_UNSIGNED_TX);
    let cache = Bip143Cache::new(&tx);
    let digest = tx.bip143_sighash(
        0,
        &p2sh_p2wsh_script_code(),
        Satoshi::new(P2SH_P2WSH_AMOUNT),
        SigHashType::ALL,
        &cache,
    );
    assert_eq!(
        digest,
        h256("185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c"),
    );
}

/// `SIGHASH_NONE` (0x02)
/// sigHash: e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36
#[test]
fn p2sh_p2wsh_sighash_none() {
    let tx = decode_legacy_tx(P2SH_P2WSH_UNSIGNED_TX);
    let cache = Bip143Cache::new(&tx);
    let digest = tx.bip143_sighash(
        0,
        &p2sh_p2wsh_script_code(),
        Satoshi::new(P2SH_P2WSH_AMOUNT),
        SigHashType::NONE,
        &cache,
    );
    assert_eq!(
        digest,
        h256("e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36"),
    );
}

/// `SIGHASH_SINGLE` (0x03)
/// sigHash: 1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea
#[test]
fn p2sh_p2wsh_sighash_single() {
    let tx = decode_legacy_tx(P2SH_P2WSH_UNSIGNED_TX);
    let cache = Bip143Cache::new(&tx);
    let digest = tx.bip143_sighash(
        0,
        &p2sh_p2wsh_script_code(),
        Satoshi::new(P2SH_P2WSH_AMOUNT),
        SigHashType::SINGLE,
        &cache,
    );
    assert_eq!(
        digest,
        h256("1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea"),
    );
}

/// `SIGHASH_ALL` | ANYONECANPAY (0x81)
/// sigHash: 2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e
#[test]
fn p2sh_p2wsh_sighash_all_anyonecanpay() {
    let tx = decode_legacy_tx(P2SH_P2WSH_UNSIGNED_TX);
    let cache = Bip143Cache::new(&tx);
    let digest = tx.bip143_sighash(
        0,
        &p2sh_p2wsh_script_code(),
        Satoshi::new(P2SH_P2WSH_AMOUNT),
        SigHashType(0x81),
        &cache,
    );
    assert_eq!(
        digest,
        h256("2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e"),
    );
}

/// `SIGHASH_NONE` | ANYONECANPAY (0x82)
/// sigHash: 781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a
#[test]
fn p2sh_p2wsh_sighash_none_anyonecanpay() {
    let tx = decode_legacy_tx(P2SH_P2WSH_UNSIGNED_TX);
    let cache = Bip143Cache::new(&tx);
    let digest = tx.bip143_sighash(
        0,
        &p2sh_p2wsh_script_code(),
        Satoshi::new(P2SH_P2WSH_AMOUNT),
        SigHashType(0x82),
        &cache,
    );
    assert_eq!(
        digest,
        h256("781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a"),
    );
}

/// `SIGHASH_SINGLE` | ANYONECANPAY (0x83)
/// sigHash: 511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b
#[test]
fn p2sh_p2wsh_sighash_single_anyonecanpay() {
    let tx = decode_legacy_tx(P2SH_P2WSH_UNSIGNED_TX);
    let cache = Bip143Cache::new(&tx);
    let digest = tx.bip143_sighash(
        0,
        &p2sh_p2wsh_script_code(),
        Satoshi::new(P2SH_P2WSH_AMOUNT),
        SigHashType(0x83),
        &cache,
    );
    assert_eq!(
        digest,
        h256("511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b"),
    );
}
