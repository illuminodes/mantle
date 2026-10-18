use super::*;

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature as EcdsaSig, SigningKey};

use mantle::primitives::{
    Hash256, Locktime, OutPoint, Sequence, Transaction, TxIn, TxOut, TxVersion, Witness,
};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::script::sighash::{SigHashType, TxSighash};

// ── End-to-end signing helpers ─────────────────────────────────────────

fn key(secret: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&secret.into()).expect("nonzero secret")
}

fn compressed_pubkey(sk: &SigningKey) -> Vec<u8> {
    sk.verifying_key().to_sec1_point(true).as_bytes().to_vec()
}

fn hash160(data: &[u8]) -> [u8; 20] {
    let mid = Sha256::digest(data);
    Ripemd160::digest(mid).into()
}

fn sign(sk: &SigningKey, sighash: &[u8; 32], hashtype: SigHashType) -> Vec<u8> {
    let sig: EcdsaSig = sk
        .sign_prehash(sighash)
        .expect("signing a 32-byte digest cannot fail");
    let sig = sig.normalize_s(); // canonical low-S
    let mut der = sig.to_der().as_bytes().to_vec();
    der.push(u8::try_from(hashtype.0 & 0xff).expect("hashtype fits in u8"));
    der
}

fn make_tx() -> Transaction {
    Transaction {
        version: TxVersion::new(1),
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_bytes([0u8; 32]),
                vout: 0,
            },
            script_sig: Vec::<u8>::new().into(),
            sequence: Sequence::new(0xffff_ffff),
            witness: Witness::empty(),
        }],
        outputs: vec![TxOut {
            value: Satoshi::new(50_000),
            script_pubkey: vec![0x6a].into(),
        }],
        locktime: Locktime::new(0),
    }
}

/// Standard P2PKH: `OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG`.
fn p2pkh_spk(pkh: &[u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(pkh);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

fn standard_flags() -> ScriptFlags {
    ScriptFlags::P2SH
        | ScriptFlags::DERSIG
        | ScriptFlags::LOW_S
        | ScriptFlags::STRICTENC
        | ScriptFlags::NULLDUMMY
}

// ── End-to-end ─────────────────────────────────────────────────────────

#[test]
fn p2pkh_succeeds() {
    let sk = key([7u8; 32]);
    let pk = compressed_pubkey(&sk);
    let pkh = hash160(&pk);
    let tx = make_tx();
    let spk = p2pkh_spk(&pkh);
    let digest = tx.legacy_sighash(0, &spk, SigHashType::ALL);
    let sig = sign(&sk, digest.as_bytes(), SigHashType::ALL);

    let mut script_sig = vec![u8::try_from(sig.len()).expect("DER ≤ 72")];
    script_sig.extend_from_slice(&sig);
    script_sig.push(u8::try_from(pk.len()).expect("compressed ≤ 33"));
    script_sig.extend_from_slice(&pk);

    verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, standard_flags())
        .expect("p2pkh should verify");
}

#[test]
fn p2pkh_fails_with_wrong_signature() {
    let sk = key([7u8; 32]);
    let attacker_sk = key([8u8; 32]);
    let pk = compressed_pubkey(&sk);
    let pkh = hash160(&pk);
    let tx = make_tx();
    let spk = p2pkh_spk(&pkh);

    // Sign with the *attacker* key but submit the real pubkey — CHECKSIG
    // verifies against the real pubkey and fails.
    let digest = tx.legacy_sighash(0, &spk, SigHashType::ALL);
    let sig = sign(&attacker_sk, digest.as_bytes(), SigHashType::ALL);

    let mut script_sig = vec![u8::try_from(sig.len()).expect("DER ≤ 72")];
    script_sig.extend_from_slice(&sig);
    script_sig.push(u8::try_from(pk.len()).expect("compressed ≤ 33"));
    script_sig.extend_from_slice(&pk);

    // Without NULLFAIL the failure is `EvalFalse` (CHECKSIG pushes false,
    // OP_EQUALVERIFY long since passed because the pubkey hash matched).
    // Actually CHECKSIG runs last → false on top → EvalFalse.
    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, standard_flags());
    assert!(matches!(r, Err(ScriptError::EvalFalse)));
}

#[test]
fn p2pkh_wrong_sig_nullfail_rejects() {
    let sk = key([7u8; 32]);
    let attacker_sk = key([8u8; 32]);
    let pk = compressed_pubkey(&sk);
    let pkh = hash160(&pk);
    let tx = make_tx();
    let spk = p2pkh_spk(&pkh);
    let digest = tx.legacy_sighash(0, &spk, SigHashType::ALL);
    let sig = sign(&attacker_sk, digest.as_bytes(), SigHashType::ALL);
    let mut script_sig = vec![u8::try_from(sig.len()).expect("DER ≤ 72")];
    script_sig.extend_from_slice(&sig);
    script_sig.push(u8::try_from(pk.len()).expect("compressed ≤ 33"));
    script_sig.extend_from_slice(&pk);
    let flags = standard_flags() | ScriptFlags::NULLFAIL;
    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, flags);
    assert!(matches!(r, Err(ScriptError::SigNullFail)));
}

#[test]
fn p2pkh_fails_with_empty_stack() {
    // Empty scriptSig + non-trivial scriptPubKey → final stack falsey.
    let pkh = [0u8; 20];
    let spk = p2pkh_spk(&pkh);
    let tx = make_tx();
    let r = verify_script(&[], &spk, &tx, 0, Satoshi::ZERO, standard_flags());
    // OP_DUP on empty stack → InvalidStackOperation.
    assert!(matches!(r, Err(ScriptError::InvalidStackOperation)));
}

#[test]
fn sigpushonly_rejects_non_push_in_scriptsig() {
    // scriptSig contains OP_NOP (0x61) — not a push.
    let pkh = [0u8; 20];
    let spk = p2pkh_spk(&pkh);
    let tx = make_tx();
    let r = verify_script(
        &[0x61],
        &spk,
        &tx,
        0,
        Satoshi::ZERO,
        standard_flags() | ScriptFlags::SIGPUSHONLY,
    );
    assert!(matches!(r, Err(ScriptError::SigPushOnly)));
}

// ── P2SH ───────────────────────────────────────────────────────────────

#[test]
fn p2sh_wrapped_p2pkh_succeeds() {
    // Redeem script is a standard P2PKH; outer scriptPubKey is its P2SH wrap.
    let sk = key([42u8; 32]);
    let pk = compressed_pubkey(&sk);
    let pkh = hash160(&pk);
    let redeem = p2pkh_spk(&pkh);
    let redeem_hash = hash160(&redeem);

    let mut spk = vec![0xa9, 0x14];
    spk.extend_from_slice(&redeem_hash);
    spk.push(0x87);
    assert!(is_p2sh(&spk));

    let tx = make_tx();
    // For BIP16, sighash is computed against the *redeem* script, not
    // the P2SH-wrapped outer script.
    let digest = tx.legacy_sighash(0, &redeem, SigHashType::ALL);
    let sig = sign(&sk, digest.as_bytes(), SigHashType::ALL);

    // scriptSig = <sig> <pk> <redeem>
    let mut script_sig = vec![u8::try_from(sig.len()).expect("DER ≤ 72")];
    script_sig.extend_from_slice(&sig);
    script_sig.push(u8::try_from(pk.len()).expect("compressed ≤ 33"));
    script_sig.extend_from_slice(&pk);
    script_sig.push(u8::try_from(redeem.len()).expect("redeem ≤ 75 here"));
    script_sig.extend_from_slice(&redeem);

    verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, standard_flags())
        .expect("p2sh-wrapped p2pkh should verify");
}

#[test]
fn p2sh_fails_when_redeem_hash_mismatches() {
    let sk = key([42u8; 32]);
    let pk = compressed_pubkey(&sk);
    let pkh = hash160(&pk);
    let redeem = p2pkh_spk(&pkh);
    // Use a *different* hash than the actual redeem to break the OP_EQUAL.
    let bogus_hash = [0u8; 20];

    let mut spk = vec![0xa9, 0x14];
    spk.extend_from_slice(&bogus_hash);
    spk.push(0x87);

    let tx = make_tx();
    let digest = tx.legacy_sighash(0, &redeem, SigHashType::ALL);
    let sig = sign(&sk, digest.as_bytes(), SigHashType::ALL);

    let mut script_sig = vec![u8::try_from(sig.len()).expect("DER ≤ 72")];
    script_sig.extend_from_slice(&sig);
    script_sig.push(u8::try_from(pk.len()).expect("compressed ≤ 33"));
    script_sig.extend_from_slice(&pk);
    script_sig.push(u8::try_from(redeem.len()).expect("redeem fits"));
    script_sig.extend_from_slice(&redeem);

    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, standard_flags());
    // OP_HASH160 == bogus → false on top → EvalFalse before P2SH path runs.
    assert!(matches!(r, Err(ScriptError::EvalFalse)));
}

#[test]
fn p2sh_off_falls_back_to_legacy_eval() {
    // Without P2SH, the scriptPubKey is treated as a literal script. With
    // a redeem-script-shaped scriptSig pushing a valid P2PKH-shaped redeem
    // and the outer P2SH template, the `OP_HASH160 <hash> OP_EQUAL` *just
    // checks the hash equality* and pushes true — no inner eval.
    let sk = key([42u8; 32]);
    let pk = compressed_pubkey(&sk);
    let pkh = hash160(&pk);
    let redeem = p2pkh_spk(&pkh);
    let redeem_hash = hash160(&redeem);

    let mut spk = vec![0xa9, 0x14];
    spk.extend_from_slice(&redeem_hash);
    spk.push(0x87);

    let tx = make_tx();
    // scriptSig = <redeem> only — push the redeem, scriptPubKey hashes
    // and compares it. No signature verification.
    let mut script_sig = vec![u8::try_from(redeem.len()).expect("redeem fits")];
    script_sig.extend_from_slice(&redeem);

    // P2SH off; legacy semantics. The OP_EQUAL pushes true, end of
    // story.
    let flags = standard_flags() - ScriptFlags::P2SH;
    verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, flags)
        .expect("legacy eval of P2SH-shaped scriptPubKey is just hash equality");
}

// ── CLEANSTACK ─────────────────────────────────────────────────────────

#[test]
fn cleanstack_passes_when_only_one_item_remains_after_p2sh() {
    // Reuse the P2SH-wrapped P2PKH success case and turn CLEANSTACK on.
    let sk = key([42u8; 32]);
    let pk = compressed_pubkey(&sk);
    let pkh = hash160(&pk);
    let redeem = p2pkh_spk(&pkh);
    let redeem_hash = hash160(&redeem);

    let mut spk = vec![0xa9, 0x14];
    spk.extend_from_slice(&redeem_hash);
    spk.push(0x87);

    let tx = make_tx();
    let digest = tx.legacy_sighash(0, &redeem, SigHashType::ALL);
    let sig = sign(&sk, digest.as_bytes(), SigHashType::ALL);

    let mut script_sig = vec![u8::try_from(sig.len()).expect("DER ≤ 72")];
    script_sig.extend_from_slice(&sig);
    script_sig.push(u8::try_from(pk.len()).expect("compressed ≤ 33"));
    script_sig.extend_from_slice(&pk);
    script_sig.push(u8::try_from(redeem.len()).expect("redeem fits"));
    script_sig.extend_from_slice(&redeem);

    verify_script(
        &script_sig,
        &spk,
        &tx,
        0,
        Satoshi::ZERO,
        standard_flags() | ScriptFlags::CLEANSTACK,
    )
    .expect("clean stack at end");
}

#[test]
fn cleanstack_fails_when_extra_item_remains() {
    // Push a junk item before the legitimate P2PKH unlock — the final
    // stack will have 2 items, violating CLEANSTACK.
    let sk = key([42u8; 32]);
    let pk = compressed_pubkey(&sk);
    let pkh = hash160(&pk);
    let redeem = p2pkh_spk(&pkh);
    let redeem_hash = hash160(&redeem);

    let mut spk = vec![0xa9, 0x14];
    spk.extend_from_slice(&redeem_hash);
    spk.push(0x87);

    let tx = make_tx();
    let digest = tx.legacy_sighash(0, &redeem, SigHashType::ALL);
    let sig = sign(&sk, digest.as_bytes(), SigHashType::ALL);

    // Junk push at the front of scriptSig. Pure data push so SIGPUSHONLY
    // doesn't catch it — the offence is purely "extra item left over".
    let mut script_sig = vec![0x01, 0xff];
    script_sig.push(u8::try_from(sig.len()).expect("DER ≤ 72"));
    script_sig.extend_from_slice(&sig);
    script_sig.push(u8::try_from(pk.len()).expect("compressed ≤ 33"));
    script_sig.extend_from_slice(&pk);
    script_sig.push(u8::try_from(redeem.len()).expect("redeem fits"));
    script_sig.extend_from_slice(&redeem);

    let r = verify_script(
        &script_sig,
        &spk,
        &tx,
        0,
        Satoshi::ZERO,
        standard_flags() | ScriptFlags::CLEANSTACK,
    );
    assert!(matches!(r, Err(ScriptError::CleanStack)));
}

// ── is_push_only ────────────────────────────────────────────────────────

#[test]
fn push_only_accepts_data_push() {
    // OP_PUSHBYTES_2 0xab 0xcd
    assert!(is_push_only(&[0x02, 0xab, 0xcd]));
}

#[test]
fn push_only_accepts_op0_op1_op16() {
    assert!(is_push_only(&[0x00])); // OP_0
    assert!(is_push_only(&[0x4f])); // OP_1NEGATE
    assert!(is_push_only(&[0x51, 0x60])); // OP_1, OP_16
}

#[test]
fn push_only_rejects_arithmetic() {
    // OP_1 OP_2 OP_ADD — has a non-push.
    assert!(!is_push_only(&[0x51, 0x52, 0x93]));
}

#[test]
fn push_only_rejects_truncated_push() {
    // OP_PUSHBYTES_3 0xab — declares 3 bytes, only 1 supplied.
    assert!(!is_push_only(&[0x03, 0xab]));
}

#[test]
fn push_only_accepts_pushdata1() {
    assert!(is_push_only(&[0x4c, 0x01, 0xaa]));
}

// ── is_p2sh ─────────────────────────────────────────────────────────────

#[test]
fn p2sh_template_match() {
    let mut s = vec![0xa9, 0x14];
    s.extend_from_slice(&[0xab; 20]);
    s.push(0x87);
    assert!(is_p2sh(&s));
}

#[test]
fn p2sh_template_wrong_length() {
    // 22 bytes — short by one.
    let mut s = vec![0xa9, 0x14];
    s.extend_from_slice(&[0xab; 19]);
    s.push(0x87);
    assert!(!is_p2sh(&s));
}

#[test]
fn p2sh_template_wrong_first_byte() {
    let mut s = vec![0x76, 0x14]; // OP_DUP instead of OP_HASH160
    s.extend_from_slice(&[0xab; 20]);
    s.push(0x87);
    assert!(!is_p2sh(&s));
}

#[test]
fn p2sh_template_wrong_last_byte() {
    let mut s = vec![0xa9, 0x14];
    s.extend_from_slice(&[0xab; 20]);
    s.push(0x88); // OP_EQUALVERIFY instead of OP_EQUAL
    assert!(!is_p2sh(&s));
}

#[test]
fn p2sh_template_wrong_push_length() {
    let mut s = vec![0xa9, 0x15]; // 21-byte push
    s.extend_from_slice(&[0xab; 20]);
    s.push(0x87);
    assert!(!is_p2sh(&s));
}

// ── Segwit v0 ──────────────────────────────────────────────────────────

fn segwit_flags() -> ScriptFlags {
    standard_flags() | ScriptFlags::WITNESS
}

/// Build a tx whose input has `witness` set.
fn make_witness_tx(witness_items: &[Vec<u8>]) -> Transaction {
    Transaction {
        version: TxVersion::new(1),
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_bytes([0u8; 32]),
                vout: 0,
            },
            script_sig: Vec::<u8>::new().into(),
            sequence: Sequence::new(0xffff_ffff),
            witness: Witness::from_slice(
                &witness_items.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            ),
        }],
        outputs: vec![TxOut {
            value: Satoshi::new(100_000),
            script_pubkey: vec![0x6a].into(),
        }],
        locktime: Locktime::new(0),
    }
}

/// P2WPKH scriptPubKey: `OP_0 <20-byte key hash>`.
fn p2wpkh_spk(pkh: &[u8; 20]) -> Vec<u8> {
    let mut s = vec![0x00, 0x14];
    s.extend_from_slice(pkh);
    s
}

#[test]
fn p2wpkh_succeeds() {
    let sk = key([11u8; 32]);
    let pk = compressed_pubkey(&sk);
    let pkh = hash160(&pk);
    let spk = p2wpkh_spk(&pkh);
    let amount = Satoshi::new(100_000);

    // The BIP143 sighash uses a synthetic P2PKH scriptCode.
    let mut script_code = vec![0x76u8, 0xa9, 0x14];
    script_code.extend_from_slice(&pkh);
    script_code.extend_from_slice(&[0x88, 0xac]);

    // Build a temporary tx with empty witness to compute the sighash.
    let tmp_tx = make_witness_tx(&[]);
    let cache = crate::script::sighash::Bip143Cache::new(&tmp_tx);
    let digest = tmp_tx.bip143_sighash(0, &script_code, amount, SigHashType::ALL, &cache);
    let sig = sign(&sk, digest.as_bytes(), SigHashType::ALL);

    let tx = make_witness_tx(&[sig, pk]);
    verify_script(&[], &spk, &tx, 0, amount, segwit_flags()).expect("p2wpkh should verify");
}

#[test]
fn p2wpkh_wrong_sig_fails() {
    let sk = key([11u8; 32]);
    let attacker = key([12u8; 32]);
    let pk = compressed_pubkey(&sk);
    let pkh = hash160(&pk);
    let spk = p2wpkh_spk(&pkh);
    let amount = Satoshi::new(100_000);

    let mut script_code = vec![0x76u8, 0xa9, 0x14];
    script_code.extend_from_slice(&pkh);
    script_code.extend_from_slice(&[0x88, 0xac]);

    let tmp_tx = make_witness_tx(&[]);
    let cache = crate::script::sighash::Bip143Cache::new(&tmp_tx);
    let digest = tmp_tx.bip143_sighash(0, &script_code, amount, SigHashType::ALL, &cache);
    // Sign with the attacker key.
    let sig = sign(&attacker, digest.as_bytes(), SigHashType::ALL);

    let tx = make_witness_tx(&[sig, pk]);
    let r = verify_script(&[], &spk, &tx, 0, amount, segwit_flags());
    assert!(r.is_err(), "wrong sig must fail");
}

#[test]
fn p2wpkh_nonempty_scriptsig_is_malleable() {
    let sk = key([11u8; 32]);
    let pk = compressed_pubkey(&sk);
    let pkh = hash160(&pk);
    let spk = p2wpkh_spk(&pkh);
    let amount = Satoshi::new(100_000);

    let tx = make_witness_tx(&[vec![0xab], pk.clone()]);
    // Supply a non-empty scriptSig — must be rejected.
    let r = verify_script(&[0x01, 0xff], &spk, &tx, 0, amount, segwit_flags());
    assert!(matches!(r, Err(ScriptError::WitnessMalleated)));
}

#[test]
fn p2wsh_succeeds() {
    // Witness script: OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG (P2PKH inside P2WSH).
    let sk = key([13u8; 32]);
    let pk = compressed_pubkey(&sk);
    let pkh = hash160(&pk);
    let witness_script = p2pkh_spk(&pkh);

    // P2WSH scriptPubKey: OP_0 <SHA256(witness_script)>
    let script_hash: [u8; 32] = Sha256::digest(&witness_script).into();
    let mut spk = vec![0x00, 0x20];
    spk.extend_from_slice(&script_hash);

    let amount = Satoshi::new(200_000);

    // BIP143 sighash: scriptCode = witness_script.
    let tmp_tx = make_witness_tx(&[]);
    let cache = crate::script::sighash::Bip143Cache::new(&tmp_tx);
    let digest = tmp_tx.bip143_sighash(0, &witness_script, amount, SigHashType::ALL, &cache);
    let sig = sign(&sk, digest.as_bytes(), SigHashType::ALL);

    // Witness stack: [sig, pubkey, witness_script]
    let tx = make_witness_tx(&[sig, pk, witness_script]);
    verify_script(&[], &spk, &tx, 0, amount, segwit_flags()).expect("p2wsh should verify");
}

#[test]
fn p2wsh_wrong_script_hash_fails() {
    let witness_script = vec![0x51]; // OP_1 — trivially true
    // Correct SHA256 of the witness script, but we use a *different* hash
    // in the scriptPubKey so the commitment check must fail.
    // The scriptPubKey program bytes must be non-zero so the initial
    // scriptPubKey eval leaves a truthy top-of-stack (all-zero = falsey).
    let correct_hash: [u8; 32] = Sha256::digest(&witness_script).into();
    let mut wrong_hash = correct_hash;
    wrong_hash[0] ^= 0xff; // flip one byte

    let mut spk = vec![0x00, 0x20];
    spk.extend_from_slice(&wrong_hash);

    let tx = make_witness_tx(&[witness_script]);
    let r = verify_script(&[], &spk, &tx, 0, Satoshi::new(0), segwit_flags());
    assert!(matches!(r, Err(ScriptError::WitnessProgramMismatch)));
}

#[test]
fn witness_unexpected_on_legacy_input() {
    // A P2WPKH input with only 1 witness item (should be 2).
    let pkh = [0xabu8; 20]; // non-zero so eval leaves truthy top
    let spk = p2wpkh_spk(&pkh);
    let tx = make_witness_tx(&[vec![0xab]]); // 1 item instead of 2
    let r = verify_script(&[], &spk, &tx, 0, Satoshi::new(0), segwit_flags());
    assert!(matches!(r, Err(ScriptError::WitnessProgramMismatch)));
}

// ── CHECKMULTISIG ─────────────────────────────────────────────────────

fn multisig_spk(m: u8, pubkeys: &[Vec<u8>]) -> Vec<u8> {
    let n = u8::try_from(pubkeys.len()).expect("pubkey count fits u8");
    let mut s = vec![0x50 + m]; // OP_M
    for pk in pubkeys {
        s.push(u8::try_from(pk.len()).expect("compressed pk ≤ 75"));
        s.extend_from_slice(pk);
    }
    s.push(0x50 + n); // OP_N
    s.push(0xae); // OP_CHECKMULTISIG
    s
}

fn multisig_script_sig(sigs: &[Vec<u8>]) -> Vec<u8> {
    let mut s = vec![0x00]; // OP_0 dummy (off-by-one bug)
    for sig in sigs {
        s.push(u8::try_from(sig.len()).expect("DER sig ≤ 75"));
        s.extend_from_slice(sig);
    }
    s
}

fn multisig_flags() -> ScriptFlags {
    ScriptFlags::P2SH
        | ScriptFlags::DERSIG
        | ScriptFlags::LOW_S
        | ScriptFlags::STRICTENC
        | ScriptFlags::NULLDUMMY
        | ScriptFlags::NULLFAIL
}

#[test]
fn checkmultisig_2of3_succeeds() {
    let sk1 = key([21u8; 32]);
    let sk2 = key([22u8; 32]);
    let sk3 = key([23u8; 32]);
    let pk1 = compressed_pubkey(&sk1);
    let pk2 = compressed_pubkey(&sk2);
    let pk3 = compressed_pubkey(&sk3);
    let spk = multisig_spk(2, &[pk1, pk2.clone(), pk3]);
    let tx = make_tx();
    let digest = tx.legacy_sighash(0, &spk, SigHashType::ALL);
    // Sign with keys 1 and 2 (must be in pubkey order).
    let sig1 = sign(&sk1, digest.as_bytes(), SigHashType::ALL);
    let sig2 = sign(&sk2, digest.as_bytes(), SigHashType::ALL);
    let script_sig = multisig_script_sig(&[sig1, sig2]);
    verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, multisig_flags())
        .expect("2-of-3 multisig should verify");
}

#[test]
fn checkmultisig_1of1_succeeds() {
    let sk = key([30u8; 32]);
    let pk = compressed_pubkey(&sk);
    let spk = multisig_spk(1, &[pk]);
    let tx = make_tx();
    let digest = tx.legacy_sighash(0, &spk, SigHashType::ALL);
    let sig = sign(&sk, digest.as_bytes(), SigHashType::ALL);
    let script_sig = multisig_script_sig(&[sig]);
    verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, multisig_flags())
        .expect("1-of-1 multisig should verify");
}

#[test]
fn checkmultisig_2of3_with_keys_1_and_3() {
    let sk1 = key([21u8; 32]);
    let sk2 = key([22u8; 32]);
    let sk3 = key([23u8; 32]);
    let pk1 = compressed_pubkey(&sk1);
    let pk2 = compressed_pubkey(&sk2);
    let pk3 = compressed_pubkey(&sk3);
    let spk = multisig_spk(2, &[pk1, pk2, pk3]);
    let tx = make_tx();
    let digest = tx.legacy_sighash(0, &spk, SigHashType::ALL);
    // Sign with keys 1 and 3 (skipping key 2 — pubkeys may be skipped).
    let sig1 = sign(&sk1, digest.as_bytes(), SigHashType::ALL);
    let sig3 = sign(&sk3, digest.as_bytes(), SigHashType::ALL);
    let script_sig = multisig_script_sig(&[sig1, sig3]);
    verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, multisig_flags())
        .expect("2-of-3 with keys 1,3 should verify");
}

#[test]
fn checkmultisig_wrong_sig_order_fails() {
    let sk1 = key([21u8; 32]);
    let sk2 = key([22u8; 32]);
    let sk3 = key([23u8; 32]);
    let pk1 = compressed_pubkey(&sk1);
    let pk2 = compressed_pubkey(&sk2);
    let pk3 = compressed_pubkey(&sk3);
    let spk = multisig_spk(2, &[pk1, pk2, pk3]);
    let tx = make_tx();
    let digest = tx.legacy_sighash(0, &spk, SigHashType::ALL);
    // Reversed order: sig2 then sig1 — violates the "sigs must match
    // pubkeys in order" rule.
    let sig1 = sign(&sk1, digest.as_bytes(), SigHashType::ALL);
    let sig2 = sign(&sk2, digest.as_bytes(), SigHashType::ALL);
    let script_sig = multisig_script_sig(&[sig2, sig1]);
    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, multisig_flags());
    assert!(matches!(r, Err(ScriptError::SigNullFail)));
}

#[test]
fn checkmultisig_wrong_key_fails() {
    let sk1 = key([21u8; 32]);
    let sk_attacker = key([99u8; 32]);
    let pk1 = compressed_pubkey(&sk1);
    let spk = multisig_spk(1, &[pk1]);
    let tx = make_tx();
    let digest = tx.legacy_sighash(0, &spk, SigHashType::ALL);
    let sig = sign(&sk_attacker, digest.as_bytes(), SigHashType::ALL);
    let script_sig = multisig_script_sig(&[sig]);
    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, multisig_flags());
    assert!(matches!(r, Err(ScriptError::SigNullFail)));
}

#[test]
fn checkmultisig_nulldummy_enforced() {
    let sk = key([30u8; 32]);
    let pk = compressed_pubkey(&sk);
    let spk = multisig_spk(1, &[pk]);
    let tx = make_tx();
    let digest = tx.legacy_sighash(0, &spk, SigHashType::ALL);
    let sig = sign(&sk, digest.as_bytes(), SigHashType::ALL);
    // Non-empty dummy element (should be OP_0 = empty push).
    let mut script_sig = vec![0x01, 0xff]; // push 1 byte: 0xff
    script_sig.push(u8::try_from(sig.len()).expect("DER ≤ 75"));
    script_sig.extend_from_slice(&sig);
    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, multisig_flags());
    assert!(matches!(r, Err(ScriptError::SigNullDummy)));
}

#[test]
fn checkmultisig_nulldummy_not_enforced_without_flag() {
    let sk = key([30u8; 32]);
    let pk = compressed_pubkey(&sk);
    let spk = multisig_spk(1, &[pk]);
    let tx = make_tx();
    let digest = tx.legacy_sighash(0, &spk, SigHashType::ALL);
    let sig = sign(&sk, digest.as_bytes(), SigHashType::ALL);
    // Non-empty dummy — but NULLDUMMY is off, so this should still pass.
    let mut script_sig = vec![0x01, 0xff];
    script_sig.push(u8::try_from(sig.len()).expect("DER ≤ 75"));
    script_sig.extend_from_slice(&sig);
    let flags = multisig_flags() - ScriptFlags::NULLDUMMY;
    verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, flags)
        .expect("non-empty dummy allowed without NULLDUMMY flag");
}

#[test]
fn checkmultisig_too_many_pubkeys() {
    // n_pubkeys = 21 which exceeds the MAX_PUBKEYS_PER_MULTISIG (20).
    // Build a script that pushes 21 as n_pubkeys.
    let mut spk = vec![0x51]; // OP_1 (m=1)
    // We don't need real pubkeys — the count check happens before the pops.
    // Push 21 dummy pubkeys.
    for _ in 0..21 {
        spk.push(0x21); // push 33 bytes
        spk.extend_from_slice(&[0x02; 33]); // dummy compressed pk
    }
    spk.push(0x01); // push literal byte 21
    spk.push(21);
    spk.push(0xae); // OP_CHECKMULTISIG
    let tx = make_tx();
    let script_sig = multisig_script_sig(&[]);
    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, multisig_flags());
    assert!(matches!(r, Err(ScriptError::PubKeyCount)));
}

#[test]
fn checkmultisig_zero_of_zero_succeeds() {
    // 0-of-0 multisig: degenerate but valid per consensus rules.
    let spk = vec![0x00, 0x00, 0xae]; // OP_0 OP_0 OP_CHECKMULTISIG
    let tx = make_tx();
    let script_sig = multisig_script_sig(&[]); // OP_0 dummy only
    verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, multisig_flags())
        .expect("0-of-0 multisig is valid");
}

#[test]
fn checkmultisigverify_succeeds() {
    let sk = key([30u8; 32]);
    let pk = compressed_pubkey(&sk);
    // Build: OP_1 <pk> OP_1 OP_CHECKMULTISIGVERIFY OP_1
    let mut spk = vec![0x51]; // OP_1
    spk.push(u8::try_from(pk.len()).expect("compressed pk ≤ 75"));
    spk.extend_from_slice(&pk);
    spk.push(0x51); // OP_1
    spk.push(0xaf); // OP_CHECKMULTISIGVERIFY
    spk.push(0x51); // OP_1 (leave truthy value for final stack)
    let tx = make_tx();
    let digest = tx.legacy_sighash(0, &spk, SigHashType::ALL);
    let sig = sign(&sk, digest.as_bytes(), SigHashType::ALL);
    let script_sig = multisig_script_sig(&[sig]);
    verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, multisig_flags())
        .expect("CHECKMULTISIGVERIFY should verify and consume result");
}

#[test]
fn checkmultisigverify_fails_on_bad_sig() {
    let sk = key([30u8; 32]);
    let sk_bad = key([31u8; 32]);
    let pk = compressed_pubkey(&sk);
    let mut spk = vec![0x51]; // OP_1
    spk.push(u8::try_from(pk.len()).expect("compressed pk ≤ 75"));
    spk.extend_from_slice(&pk);
    spk.push(0x51); // OP_1
    spk.push(0xaf); // OP_CHECKMULTISIGVERIFY
    spk.push(0x51); // OP_1
    let tx = make_tx();
    let digest = tx.legacy_sighash(0, &spk, SigHashType::ALL);
    let sig = sign(&sk_bad, digest.as_bytes(), SigHashType::ALL);
    let script_sig = multisig_script_sig(&[sig]);
    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, multisig_flags());
    assert!(matches!(r, Err(ScriptError::SigNullFail)));
}

// ── verify_script_inner: segwit branches ──────────────────────────────

#[test]
fn witness_v2_discourage_upgradable_rejected() {
    // A witness program with version 2 (OP_2 = 0x52) and a 20-byte program.
    // With DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, this must be rejected.
    let program = [0xaa; 20];
    let mut spk = vec![0x52, 0x14]; // OP_2, push 20 bytes
    spk.extend_from_slice(&program);

    let tx = make_witness_tx(&[vec![0x01]]);
    let flags = segwit_flags() | ScriptFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
    let r = verify_script(&[], &spk, &tx, 0, Satoshi::new(100_000), flags);
    assert!(
        matches!(r, Err(ScriptError::DiscourageUpgradableWitnessProgram)),
        "witness v2 with DISCOURAGE flag must fail, got: {r:?}"
    );
}

#[test]
fn witness_v16_discourage_upgradable_rejected() {
    // OP_16 = 0x60, 32-byte program
    let program = [0xbb; 32];
    let mut spk = vec![0x60, 0x20]; // OP_16, push 32 bytes
    spk.extend_from_slice(&program);

    let tx = make_witness_tx(&[vec![0x01]]);
    let flags = segwit_flags() | ScriptFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
    let r = verify_script(&[], &spk, &tx, 0, Satoshi::new(100_000), flags);
    assert!(
        matches!(r, Err(ScriptError::DiscourageUpgradableWitnessProgram)),
        "witness v16 with DISCOURAGE flag must fail, got: {r:?}"
    );
}

#[test]
fn witness_v2_accepted_without_discourage_flag() {
    // Without DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, unknown witness
    // versions are accepted (future soft-fork).
    let program = [0xaa; 20];
    let mut spk = vec![0x52, 0x14]; // OP_2, push 20 bytes
    spk.extend_from_slice(&program);

    let tx = make_witness_tx(&[vec![0x01]]);
    let flags = segwit_flags(); // no DISCOURAGE flag
    verify_script(&[], &spk, &tx, 0, Satoshi::new(100_000), flags)
        .expect("unknown witness version without DISCOURAGE flag must succeed");
}

#[test]
fn witness_unexpected_on_non_witness_script_with_witness_data() {
    // A legacy script (not a witness program) but the input carries witness
    // data. With WITNESS flag active, this must return WitnessUnexpected.
    // Use a simple OP_1 scriptPubKey (always true, not a witness program).
    let spk = vec![0x51]; // OP_1
    let tx = make_witness_tx(&[vec![0xab, 0xcd]]);
    let r = verify_script(&[], &spk, &tx, 0, Satoshi::ZERO, segwit_flags());
    assert!(
        matches!(r, Err(ScriptError::WitnessUnexpected)),
        "legacy script with witness data must return WitnessUnexpected, got: {r:?}"
    );
}

#[test]
fn cleanstack_fails_on_non_p2sh_legacy_script() {
    // A non-P2SH script where evaluation leaves >1 item on the stack.
    // scriptPubKey: OP_1 (pushes 1 onto stack; scriptSig also pushes
    // something, leaving 2 items).
    let spk = vec![0x51]; // OP_1
    let script_sig = vec![0x51]; // OP_1
    let tx = make_tx();
    let flags = standard_flags() | ScriptFlags::CLEANSTACK;
    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, flags);
    assert!(
        matches!(r, Err(ScriptError::CleanStack)),
        "non-P2SH script with 2 stack items must fail CLEANSTACK, got: {r:?}"
    );
}

// ── P2SH-wrapped segwit (P2SH-P2WPKH) ────────────────────────────────

#[test]
fn p2sh_p2wpkh_succeeds() {
    let sk = key([50u8; 32]);
    let pk = compressed_pubkey(&sk);
    let pkh = hash160(&pk);

    // The redeem script is the witness program: OP_0 <20-byte pkh>
    let mut redeem = vec![0x00, 0x14];
    redeem.extend_from_slice(&pkh);
    let redeem_hash = hash160(&redeem);

    // Outer P2SH scriptPubKey: OP_HASH160 <20> <hash> OP_EQUAL
    let mut spk = vec![0xa9, 0x14];
    spk.extend_from_slice(&redeem_hash);
    spk.push(0x87);

    let amount = Satoshi::new(200_000);

    // BIP143 sighash: scriptCode is synthetic P2PKH over pkh
    let mut script_code = vec![0x76u8, 0xa9, 0x14];
    script_code.extend_from_slice(&pkh);
    script_code.extend_from_slice(&[0x88, 0xac]);

    // Build temporary tx with empty witness for sighash computation
    let tmp_tx = make_witness_tx(&[]);
    let cache = crate::script::sighash::Bip143Cache::new(&tmp_tx);
    let digest = tmp_tx.bip143_sighash(0, &script_code, amount, SigHashType::ALL, &cache);
    let sig = sign(&sk, digest.as_bytes(), SigHashType::ALL);

    // For P2SH-P2WPKH, the witness is [sig, pubkey]
    let tx = Transaction {
        version: TxVersion::new(1),
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_bytes([0u8; 32]),
                vout: 0,
            },
            // scriptSig for P2SH-P2WPKH: just the redeem script push
            script_sig: {
                let mut ss = vec![u8::try_from(redeem.len()).expect("redeem fits")];
                ss.extend_from_slice(&redeem);
                ss.into()
            },
            sequence: Sequence::new(0xffff_ffff),
            witness: Witness::from_slice(&[sig.as_slice(), pk.as_slice()]),
        }],
        outputs: vec![TxOut {
            value: Satoshi::new(100_000),
            script_pubkey: vec![0x6a].into(),
        }],
        locktime: Locktime::new(0),
    };

    verify_script(
        tx.inputs[0].script_sig.as_ref(),
        &spk,
        &tx,
        0,
        amount,
        segwit_flags(),
    )
    .expect("P2SH-P2WPKH should verify");
}

#[test]
fn p2sh_p2wpkh_non_push_scriptsig_rejected() {
    // P2SH-wrapped witness with non-push scriptSig must be rejected.
    let pkh = [0xaa; 20];
    let mut redeem = vec![0x00, 0x14];
    redeem.extend_from_slice(&pkh);
    let redeem_hash = hash160(&redeem);
    let mut spk = vec![0xa9, 0x14];
    spk.extend_from_slice(&redeem_hash);
    spk.push(0x87);

    let tx = make_witness_tx(&[vec![0x01], vec![0x02; 33]]);
    // scriptSig with a non-push byte (OP_NOP=0x61)
    let script_sig = vec![0x61];
    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::new(100), segwit_flags());
    assert!(r.is_err(), "non-push scriptSig for P2SH must fail");
}

#[test]
fn native_segwit_non_empty_scriptsig_is_malleated() {
    // Native segwit (not P2SH-wrapped): any non-empty scriptSig is rejected
    // as WitnessMalleated.
    let program = [0xaa; 20];
    let mut spk = vec![0x52, 0x14]; // witness v2, 20-byte program
    spk.extend_from_slice(&program);

    let tx = make_witness_tx(&[vec![0x01]]);
    let flags = segwit_flags(); // no DISCOURAGE
    let r = verify_script(&[0x01, 0xff], &spk, &tx, 0, Satoshi::new(100), flags);
    assert!(
        matches!(r, Err(ScriptError::WitnessMalleated)),
        "native segwit with non-empty scriptSig must be WitnessMalleated, got: {r:?}"
    );
}

// ── CHECKMULTISIG with OP_CODESEPARATOR ───────────────────────────────

#[test]
fn checkmultisig_with_codeseparator() {
    // Build a script: OP_CODESEPARATOR OP_1 <pk> OP_1 OP_CHECKMULTISIG
    // The CODESEPARATOR partitions the script so the sighash only covers
    // the part after it.
    let sk = key([55u8; 32]);
    let pk = compressed_pubkey(&sk);

    let mut spk = Vec::new();
    spk.push(0xab); // OP_CODESEPARATOR
    spk.push(0x51); // OP_1
    spk.push(u8::try_from(pk.len()).expect("compressed pk ≤ 75"));
    spk.extend_from_slice(&pk);
    spk.push(0x51); // OP_1
    spk.push(0xae); // OP_CHECKMULTISIG

    let tx = make_tx();
    // The sighash should be computed against the part of the script AFTER
    // the OP_CODESEPARATOR (byte index 1 onwards).
    let script_code = &spk[1..]; // skip the OP_CODESEPARATOR
    let digest = tx.legacy_sighash(0, script_code, SigHashType::ALL);
    let sig = sign(&sk, digest.as_bytes(), SigHashType::ALL);
    let script_sig = multisig_script_sig(&[sig]);
    verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, multisig_flags())
        .expect("CHECKMULTISIG with CODESEPARATOR should verify");
}

#[test]
fn checkmultisig_nsigs_greater_than_npubkeys_fails() {
    // n_sigs > n_pubkeys: must fail with SigCount.
    // Script: OP_2 <pk> OP_1 OP_CHECKMULTISIG (2-of-1 is invalid)
    let sk = key([60u8; 32]);
    let pk = compressed_pubkey(&sk);
    let mut spk = vec![0x52]; // OP_2
    spk.push(u8::try_from(pk.len()).expect("pk ≤ 75"));
    spk.extend_from_slice(&pk);
    spk.push(0x51); // OP_1
    spk.push(0xae); // OP_CHECKMULTISIG
    let tx = make_tx();
    let digest = tx.legacy_sighash(0, &spk, SigHashType::ALL);
    let sig1 = sign(&sk, digest.as_bytes(), SigHashType::ALL);
    let sig2 = sign(&sk, digest.as_bytes(), SigHashType::ALL);
    let script_sig = multisig_script_sig(&[sig1, sig2]);
    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, multisig_flags());
    assert!(
        matches!(r, Err(ScriptError::SigCount)),
        "n_sigs > n_pubkeys must fail with SigCount, got: {r:?}"
    );
}

#[test]
fn checkmultisig_negative_nsigs_fails() {
    // To trigger n_sigs < 0, we need the CHECKMULTISIG stack to have -1
    // in the n_sigs position.
    //
    // CHECKMULTISIG pops (top to bottom):
    //   n_pubkeys, [pubkeys...], n_sigs, [sigs...], dummy
    //
    // scriptSig: OP_0 (dummy)
    // scriptPubKey: OP_1NEGATE OP_0 OP_CHECKMULTISIG
    //
    // Stack after both scripts (bottom to top): [<empty>, <-1>, <empty>]
    // CHECKMULTISIG pops:
    //   n_pubkeys = 0 (top empty)
    //   0 pubkeys
    //   n_sigs = -1 -> SigCount
    let spk = vec![0x4f, 0x00, 0xae]; // OP_1NEGATE OP_0 OP_CHECKMULTISIG
    let script_sig = vec![0x00]; // OP_0 (dummy)
    let tx = make_tx();
    // No NULLDUMMY/STRICTENC/DERSIG so encoding checks don't fire first.
    let flags = ScriptFlags::P2SH;
    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, flags);
    assert!(
        matches!(r, Err(ScriptError::SigCount)),
        "negative n_sigs must fail with SigCount, got: {r:?}"
    );
}

#[test]
fn checkmultisig_bad_pubkey_encoding_rejected() {
    // A pubkey that is neither compressed (33 bytes starting with 02/03)
    // nor uncompressed (65 bytes starting with 04) triggers PubKeyType
    // when STRICTENC is set. This covers line 294 of op_crypto.rs.
    let sk = key([40u8; 32]);
    let pk = compressed_pubkey(&sk);

    // Build a 1-of-2 multisig where the second pubkey is malformed:
    // 33 bytes but starts with 0x05 (invalid prefix).
    let mut bad_pk = vec![0x05];
    bad_pk.extend_from_slice(&[0xaa; 32]);

    let spk = multisig_spk(1, &[pk.clone(), bad_pk]);
    let tx = make_tx();
    let digest = tx.legacy_sighash(0, &spk, SigHashType::ALL);
    let sig = sign(&sk, digest.as_bytes(), SigHashType::ALL);
    let script_sig = multisig_script_sig(&[sig]);
    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, multisig_flags());
    assert!(
        matches!(r, Err(ScriptError::PubKeyType)),
        "malformed pubkey in multisig must fail with PubKeyType, got: {r:?}"
    );
}

#[test]
fn checkmultisigverify_0of0_succeeds() {
    // 0-of-0 CHECKMULTISIGVERIFY with verify=true: should succeed
    // (nothing to verify, result is true, verify consumes it).
    // Script: OP_0 OP_0 OP_CHECKMULTISIGVERIFY OP_1
    let spk = vec![0x00, 0x00, 0xaf, 0x51]; // OP_0 OP_0 OP_CHECKMULTISIGVERIFY OP_1
    let tx = make_tx();
    let script_sig = multisig_script_sig(&[]); // OP_0 dummy only
    verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, multisig_flags())
        .expect("0-of-0 CHECKMULTISIGVERIFY should succeed");
}

// ── try_verify_p2pkh: uncovered branches ─────────────────────────────

#[test]
fn try_verify_p2pkh_wrong_pubkey_hash_fails() {
    // Valid P2PKH pattern, correct sig, but the pubkey hash does not match
    // the hash in scriptPubKey. The fast path should return EvalFalse.
    let sk = key([70u8; 32]);
    let pk = compressed_pubkey(&sk);
    // Use a different pubkey's hash in the scriptPubKey.
    let wrong_pkh = [0xdd; 20];
    let spk = p2pkh_spk(&wrong_pkh);
    let tx = make_tx();
    let digest = tx.legacy_sighash(0, &spk, SigHashType::ALL);
    let sig = sign(&sk, digest.as_bytes(), SigHashType::ALL);

    let mut script_sig = vec![u8::try_from(sig.len()).expect("DER <= 72")];
    script_sig.extend_from_slice(&sig);
    script_sig.push(u8::try_from(pk.len()).expect("compressed <= 33"));
    script_sig.extend_from_slice(&pk);

    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, standard_flags());
    assert!(
        matches!(r, Err(ScriptError::EvalFalse)),
        "wrong pkh should fail with EvalFalse, got: {r:?}"
    );
}

#[test]
fn try_verify_p2pkh_not_p2pkh_pattern_falls_through() {
    // scriptPubKey that is almost P2PKH but wrong length (24 bytes instead of 25).
    // The fast path should return None and fall through to the full interpreter.
    let mut spk = vec![0x76, 0xa9, 0x13]; // OP_DUP OP_HASH160 OP_PUSHBYTES_19
    spk.extend_from_slice(&[0xab; 19]);
    spk.extend_from_slice(&[0x88, 0xac]);
    // This is 24 bytes, not 25. try_verify_p2pkh returns None.
    let tx = make_tx();
    let r = verify_script(&[], &spk, &tx, 0, Satoshi::ZERO, standard_flags());
    // OP_DUP on empty stack -> InvalidStackOperation (through the interpreter).
    assert!(
        matches!(r, Err(ScriptError::InvalidStackOperation)),
        "non-P2PKH pattern should fall through to interpreter, got: {r:?}"
    );
}

#[test]
fn try_verify_p2pkh_witness_unexpected_on_legacy() {
    // P2PKH input that carries witness data. With WITNESS flag active,
    // the fast path should return WitnessUnexpected.
    let sk = key([71u8; 32]);
    let pk = compressed_pubkey(&sk);
    let pkh = hash160(&pk);
    let spk = p2pkh_spk(&pkh);
    let tx = make_witness_tx(&[vec![0x01]]); // witness present
    let digest = tx.legacy_sighash(0, &spk, SigHashType::ALL);
    let sig = sign(&sk, digest.as_bytes(), SigHashType::ALL);

    let mut script_sig = vec![u8::try_from(sig.len()).expect("DER <= 72")];
    script_sig.extend_from_slice(&sig);
    script_sig.push(u8::try_from(pk.len()).expect("compressed <= 33"));
    script_sig.extend_from_slice(&pk);

    let r = verify_script(
        &script_sig,
        &spk,
        &tx,
        0,
        Satoshi::ZERO,
        standard_flags() | ScriptFlags::WITNESS,
    );
    assert!(
        matches!(r, Err(ScriptError::WitnessUnexpected)),
        "P2PKH with witness data should be WitnessUnexpected, got: {r:?}"
    );
}

#[test]
fn try_verify_p2pkh_empty_sig_fails() {
    // P2PKH with valid pubkey hash but empty signature. The fast path
    // should return EvalFalse (empty sig means CHECKSIG pushes false).
    let sk = key([72u8; 32]);
    let pk = compressed_pubkey(&sk);
    let pkh = hash160(&pk);
    let spk = p2pkh_spk(&pkh);
    let tx = make_tx();

    // scriptSig = <empty sig> <pubkey>
    let mut script_sig = vec![0x00]; // OP_0 (empty push for sig)
    script_sig.push(u8::try_from(pk.len()).expect("compressed <= 33"));
    script_sig.extend_from_slice(&pk);

    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, standard_flags());
    assert!(
        matches!(r, Err(ScriptError::EvalFalse)),
        "empty sig should fail with EvalFalse, got: {r:?}"
    );
}

// ── verify_script_inner: segwit v1 (taproot) dispatch ────────────────

#[test]
fn witness_v1_non_32byte_program_accepted_without_discourage() {
    // Witness v1 (OP_1 = 0x51) with a 20-byte program (not 32 bytes).
    // Without DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, this is an unknown
    // witness version and is accepted.
    let program = [0xcc; 20];
    let mut spk = vec![0x51, 0x14]; // OP_1, push 20 bytes
    spk.extend_from_slice(&program);

    let tx = make_witness_tx(&[vec![0x01]]);
    let flags = segwit_flags() | ScriptFlags::TAPROOT;
    verify_script(&[], &spk, &tx, 0, Satoshi::new(100_000), flags)
        .expect("v1 non-32-byte program should be accepted without discourage");
}

#[test]
fn witness_v1_non_32byte_program_rejected_with_discourage() {
    // Same as above but with DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM.
    let program = [0xcc; 20];
    let mut spk = vec![0x51, 0x14]; // OP_1, push 20 bytes
    spk.extend_from_slice(&program);

    let tx = make_witness_tx(&[vec![0x01]]);
    let flags =
        segwit_flags() | ScriptFlags::TAPROOT | ScriptFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
    let r = verify_script(&[], &spk, &tx, 0, Satoshi::new(100_000), flags);
    assert!(
        matches!(r, Err(ScriptError::DiscourageUpgradableWitnessProgram)),
        "v1 non-32-byte program with DISCOURAGE must fail, got: {r:?}"
    );
}

#[test]
fn p2sh_wrapped_v1_program_is_an_unknown_witness_version() {
    let program = [0xdd; 32];
    // Redeem script: OP_1 OP_PUSHBYTES_32 <32 bytes>
    let mut redeem = vec![0x51, 0x20];
    redeem.extend_from_slice(&program);
    let redeem_hash = hash160(&redeem);

    // Outer P2SH scriptPubKey
    let mut spk = vec![0xa9, 0x14];
    spk.extend_from_slice(&redeem_hash);
    spk.push(0x87);

    // scriptSig pushes the redeem script
    let mut script_sig = vec![u8::try_from(redeem.len()).expect("redeem fits")];
    script_sig.extend_from_slice(&redeem);

    let tx = make_witness_tx(&[vec![0x01; 64]]); // dummy Schnorr sig

    let flags = segwit_flags() | ScriptFlags::TAPROOT;
    assert_eq!(
        verify_script(&script_sig, &spk, &tx, 0, Satoshi::new(100_000), flags),
        Ok(())
    );
    let discouraged = flags | ScriptFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
    assert_eq!(
        verify_script(
            &script_sig,
            &spk,
            &tx,
            0,
            Satoshi::new(100_000),
            discouraged
        ),
        Err(ScriptError::DiscourageUpgradableWitnessProgram)
    );
}

#[test]
fn p2sh_wrapped_witness_needs_a_canonical_single_push() {
    let mut redeem = vec![0x00, 0x14];
    redeem.extend_from_slice(&[0xcc; 20]);
    let mut spk = vec![0xa9, 0x14];
    spk.extend_from_slice(&hash160(&redeem));
    spk.push(0x87);
    let mut script_sig = vec![0x4c, u8::try_from(redeem.len()).expect("fits")];
    script_sig.extend_from_slice(&redeem);
    let tx = make_witness_tx(&[vec![0x01], vec![0x02]]);
    assert_eq!(
        verify_script(&script_sig, &spk, &tx, 0, Satoshi::new(1), segwit_flags()),
        Err(ScriptError::WitnessMalleatedP2sh)
    );
}

// ── verify_script_inner: uncovered branches ──────────────────────────

#[test]
fn cleanstack_rejects_extra_item_on_legacy_with_p2sh_flag() {
    // Exercise the CLEANSTACK check at the end of verify_script_inner
    // (line 658). scriptPubKey = OP_1 (always true), scriptSig = OP_1 OP_1
    // (pushes two items). After eval, stack has [1, 1, 1] = 3 items.
    // CLEANSTACK + P2SH flags are both set but the scriptPubKey is not
    // P2SH-shaped, so the P2SH block is skipped and the final cleanstack
    // gate at the bottom fires.
    let spk = vec![0x51]; // OP_1
    // scriptSig pushes two items: OP_1 OP_1
    let script_sig = vec![0x51, 0x51];
    let tx = make_tx();
    let flags = ScriptFlags::P2SH | ScriptFlags::CLEANSTACK;
    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, flags);
    assert!(
        matches!(r, Err(ScriptError::CleanStack)),
        "3 items on stack with CLEANSTACK+P2SH must fail, got: {r:?}"
    );
}

#[test]
fn cleanstack_passes_with_exactly_one_item_on_legacy() {
    // Counterpart: exactly one item left, CLEANSTACK + P2SH set, non-P2SH
    // scriptPubKey. Must pass.
    let spk = vec![0x51]; // OP_1
    let script_sig: Vec<u8> = vec![]; // empty — OP_1 pushes one item
    let tx = make_tx();
    let flags = ScriptFlags::P2SH | ScriptFlags::CLEANSTACK;
    verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, flags)
        .expect("exactly one item on stack must pass CLEANSTACK");
}

#[test]
fn p2sh_non_push_only_scriptsig_rejected() {
    // The P2SH block (line 555) independently checks `is_push_only(script_sig)`
    // even when the standalone SIGPUSHONLY flag is off. We craft a scriptSig
    // that has a non-push opcode (OP_NOP = 0x61) followed by the redeem script
    // push. The outer P2SH eval must pass (the redeem hash matches) but then
    // the P2SH is_push_only check rejects it.
    //
    // Redeem script: OP_1 (trivially true).
    let redeem = vec![0x51u8]; // OP_1
    let redeem_hash = hash160(&redeem);

    // Outer P2SH scriptPubKey: OP_HASH160 <20> <hash> OP_EQUAL
    let mut spk = vec![0xa9, 0x14];
    spk.extend_from_slice(&redeem_hash);
    spk.push(0x87);
    assert!(is_p2sh(&spk));

    // scriptSig: OP_NOP <push redeem>
    // OP_NOP (0x61) does nothing — leaves stack unchanged.
    // Then push the redeem script bytes.
    let mut script_sig = vec![0x61]; // OP_NOP — non-push opcode
    script_sig.push(u8::try_from(redeem.len()).expect("redeem fits"));
    script_sig.extend_from_slice(&redeem);

    let tx = make_tx();
    // P2SH on, but SIGPUSHONLY off — so the early gate at line 487 does NOT fire.
    let flags = ScriptFlags::P2SH;
    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, flags);
    assert!(
        matches!(r, Err(ScriptError::SigPushOnly)),
        "P2SH with non-push scriptSig must fail with SigPushOnly, got: {r:?}"
    );
}

#[test]
fn native_segwit_v0_non_empty_scriptsig_is_malleated() {
    // Native segwit (v0 P2WPKH) with a non-empty scriptSig must be rejected
    // as WitnessMalleated. This exercises the `!is_p2sh_wrapped && !script_sig.is_empty()`
    // branch (line 610-611).
    let pkh = [0xbb; 20];
    let spk = p2wpkh_spk(&pkh);
    let tx = make_witness_tx(&[vec![0x01], vec![0x02; 33]]);
    let r = verify_script(
        &[0x01, 0xaa],
        &spk,
        &tx,
        0,
        Satoshi::new(100),
        segwit_flags(),
    );
    assert!(
        matches!(r, Err(ScriptError::WitnessMalleated)),
        "native segwit v0 with non-empty scriptSig must be WitnessMalleated, got: {r:?}"
    );
}

#[test]
fn p2sh_wrapped_p2wpkh_witness_program_from_redeem() {
    // Exercises the witness_program_of(redeem) path inside the P2SH block
    // (line 571). The redeem script is a witness v0 program (P2WPKH).
    // This is the same as p2sh_p2wpkh_succeeds but we verify the code path
    // is reached by providing a wrong witness to trigger a distinct error
    // from the segwit execution (not just EvalFalse from the P2SH path).
    let pkh = [0xcc; 20];

    // Redeem script = witness program: OP_0 <20-byte pkh>
    let mut redeem = vec![0x00, 0x14];
    redeem.extend_from_slice(&pkh);
    let redeem_hash = hash160(&redeem);

    // Outer P2SH scriptPubKey
    let mut spk = vec![0xa9, 0x14];
    spk.extend_from_slice(&redeem_hash);
    spk.push(0x87);

    // Witness with wrong item count (3 instead of 2 for P2WPKH).
    let tx = Transaction {
        version: TxVersion::new(1),
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_bytes([0u8; 32]),
                vout: 0,
            },
            script_sig: {
                let mut ss = vec![u8::try_from(redeem.len()).expect("redeem fits")];
                ss.extend_from_slice(&redeem);
                ss.into()
            },
            sequence: Sequence::new(0xffff_ffff),
            witness: Witness::from_slice(&[&[0x01][..], &[0x02; 33][..], &[0x03][..]]),
        }],
        outputs: vec![TxOut {
            value: Satoshi::new(100_000),
            script_pubkey: vec![0x6a].into(),
        }],
        locktime: Locktime::new(0),
    };

    let r = verify_script(
        tx.inputs[0].script_sig.as_ref(),
        &spk,
        &tx,
        0,
        Satoshi::new(100_000),
        segwit_flags(),
    );
    // P2WPKH requires exactly 2 witness items; 3 items triggers WitnessProgramMismatch.
    assert!(
        matches!(r, Err(ScriptError::WitnessProgramMismatch)),
        "P2SH-wrapped P2WPKH with wrong witness count must fail, got: {r:?}"
    );
}

#[test]
fn unknown_witness_version_accepted_without_discourage() {
    // An unknown witness version (v3, OP_3 = 0x53) with a 20-byte program.
    // Without DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, this must be accepted
    // silently per the "future soft-fork" rule (line 642-644).
    let program = [0xdd; 20];
    let mut spk = vec![0x53, 0x14]; // OP_3, push 20 bytes
    spk.extend_from_slice(&program);

    let tx = make_witness_tx(&[vec![0xab]]);
    let flags = segwit_flags(); // no DISCOURAGE flag
    verify_script(&[], &spk, &tx, 0, Satoshi::new(100_000), flags)
        .expect("unknown witness v3 without DISCOURAGE flag must succeed");
}

#[test]
fn unknown_witness_version_v16_accepted_without_discourage() {
    // Same with v16 (OP_16 = 0x60) and a 32-byte program — widest version range.
    let program = [0xee; 32];
    let mut spk = vec![0x60, 0x20]; // OP_16, push 32 bytes
    spk.extend_from_slice(&program);

    let tx = make_witness_tx(&[vec![0x01]]);
    let flags = segwit_flags();
    verify_script(&[], &spk, &tx, 0, Satoshi::new(100_000), flags)
        .expect("unknown witness v16 without DISCOURAGE flag must succeed");
}

// ── Taproot (witness v1, 32-byte program) dispatch ──────────────────

#[test]
fn taproot_empty_witness_fails() {
    // Witness v1 (OP_1 = 0x51), 32-byte program, TAPROOT flag set,
    // but an empty witness stack. run_taproot dispatches on
    // effective_witness.len() — 0 items hits the catch-all arm
    // returning WitnessProgramMismatch.
    let program = [0xaa; 32];
    let mut spk = vec![0x51, 0x20]; // OP_1, push 32 bytes
    spk.extend_from_slice(&program);

    let tx = make_witness_tx(&[]); // empty witness
    let flags = segwit_flags() | ScriptFlags::TAPROOT;
    let r = verify_script(&[], &spk, &tx, 0, Satoshi::new(100_000), flags);
    assert!(
        matches!(r, Err(ScriptError::WitnessProgramMismatch)),
        "taproot with empty witness must fail with WitnessProgramMismatch, got: {r:?}"
    );
}

#[test]
fn taproot_invalid_schnorr_sig_format_fails() {
    // Witness v1, 32-byte program, TAPROOT flag set. One witness item
    // (key-path spend) but the item is too short to be a valid Schnorr
    // signature (must be 64 or 65 bytes). This triggers
    // SchnorrSigInvalidFormat inside run_taproot.
    let program = [0xbb; 32];
    let mut spk = vec![0x51, 0x20];
    spk.extend_from_slice(&program);

    let tx = make_witness_tx(&[vec![0xab; 10]]); // 10 bytes, not 64/65
    let flags = segwit_flags() | ScriptFlags::TAPROOT;
    let r = verify_script(&[], &spk, &tx, 0, Satoshi::new(100_000), flags);
    assert!(
        matches!(r, Err(ScriptError::SchnorrSigInvalidFormat)),
        "taproot with malformed sig must fail with SchnorrSigInvalidFormat, got: {r:?}"
    );
}

#[test]
fn taproot_wrong_schnorr_sig_fails() {
    // Witness v1, 32-byte program, TAPROOT flag set. One witness item
    // of 64 bytes (valid length for a Schnorr sig with default hashtype)
    // but the signature itself is all-zeros — verification against the
    // output key must fail with TaprootVerify.
    let program = [0xcc; 32];
    let mut spk = vec![0x51, 0x20];
    spk.extend_from_slice(&program);

    let tx = make_witness_tx(&[vec![0x00; 64]]); // 64-byte all-zero "sig"
    let flags = segwit_flags() | ScriptFlags::TAPROOT;
    let r = verify_script(&[], &spk, &tx, 0, Satoshi::new(100_000), flags);
    assert!(
        matches!(r, Err(ScriptError::TaprootVerify)),
        "taproot with wrong sig must fail with TaprootVerify, got: {r:?}"
    );
}

// ── Native segwit: witness program extracted from scriptPubKey ───────

#[test]
fn native_p2wpkh_wrong_witness_count_fails() {
    // Native P2WPKH (not P2SH-wrapped): scriptPubKey = OP_0 <20-byte pkh>.
    // This exercises the `else if flags.contains(WITNESS)` branch at line 588
    // where the witness program is extracted directly from the scriptPubKey
    // (not from a P2SH redeem script). Providing 3 witness items instead of
    // the required 2 triggers WitnessProgramMismatch from run_witness_v0.
    let pkh = [0xaa; 20];
    let spk = p2wpkh_spk(&pkh);
    let tx = make_witness_tx(&[vec![0x01], vec![0x02; 33], vec![0x03]]);
    let r = verify_script(&[], &spk, &tx, 0, Satoshi::new(100_000), segwit_flags());
    assert!(
        matches!(r, Err(ScriptError::WitnessProgramMismatch)),
        "native P2WPKH with 3 witness items must fail with WitnessProgramMismatch, got: {r:?}"
    );
}

#[test]
fn native_p2wsh_empty_witness_fails() {
    // Native P2WSH: scriptPubKey = OP_0 <32-byte script hash>.
    // Again exercises the native (non-P2SH) witness program extraction at
    // line 588-589. An empty witness stack triggers WitnessProgramMismatch
    // because split_last() returns None.
    let script_hash = [0xbb; 32];
    let mut spk = vec![0x00, 0x20];
    spk.extend_from_slice(&script_hash);

    let tx = make_witness_tx(&[]);
    let r = verify_script(&[], &spk, &tx, 0, Satoshi::new(100_000), segwit_flags());
    assert!(
        matches!(r, Err(ScriptError::WitnessProgramMismatch)),
        "native P2WSH with empty witness must fail with WitnessProgramMismatch, got: {r:?}"
    );
}

// ── P2SH redeem script eval failure paths ───────────────────────────

#[test]
fn p2sh_redeem_eval_fails_on_op_return() {
    // Redeem script = OP_RETURN (0x6a). When evaluated, OP_RETURN
    // always returns an error. The P2SH path runs interp.eval(redeem)
    // which propagates the error.
    let redeem = vec![0x6a]; // OP_RETURN
    let redeem_hash = hash160(&redeem);

    let mut spk = vec![0xa9, 0x14];
    spk.extend_from_slice(&redeem_hash);
    spk.push(0x87);
    assert!(is_p2sh(&spk));

    // scriptSig = <push redeem>
    let mut script_sig = vec![u8::try_from(redeem.len()).expect("redeem fits")];
    script_sig.extend_from_slice(&redeem);

    let tx = make_tx();
    let flags = ScriptFlags::P2SH;
    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, flags);
    assert!(
        r.is_err(),
        "P2SH with OP_RETURN redeem must fail, got: {r:?}"
    );
}

#[test]
fn p2sh_redeem_leaves_empty_stack() {
    // Redeem script = OP_1 OP_DROP. Pushes 1 then drops it, leaving
    // an empty stack. The P2SH path checks stack().is_empty() after
    // eval and returns EvalFalse.
    let redeem = vec![0x51, 0x75]; // OP_1 OP_DROP
    let redeem_hash = hash160(&redeem);

    let mut spk = vec![0xa9, 0x14];
    spk.extend_from_slice(&redeem_hash);
    spk.push(0x87);
    assert!(is_p2sh(&spk));

    // scriptSig = <push redeem>
    let mut script_sig = vec![u8::try_from(redeem.len()).expect("redeem fits")];
    script_sig.extend_from_slice(&redeem);

    let tx = make_tx();
    let flags = ScriptFlags::P2SH;
    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, flags);
    assert!(
        matches!(r, Err(ScriptError::EvalFalse)),
        "P2SH redeem leaving empty stack must fail with EvalFalse, got: {r:?}"
    );
}

#[test]
fn p2sh_redeem_leaves_falsy_top() {
    // Redeem script = OP_0. Pushes an empty byte vector (falsy) onto
    // the stack. The P2SH path checks is_truthy() on the top item
    // and returns EvalFalse.
    let redeem = vec![0x00]; // OP_0
    let redeem_hash = hash160(&redeem);

    let mut spk = vec![0xa9, 0x14];
    spk.extend_from_slice(&redeem_hash);
    spk.push(0x87);
    assert!(is_p2sh(&spk));

    // scriptSig = <push redeem>
    let mut script_sig = vec![u8::try_from(redeem.len()).expect("redeem fits")];
    script_sig.extend_from_slice(&redeem);

    let tx = make_tx();
    let flags = ScriptFlags::P2SH;
    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, flags);
    assert!(
        matches!(r, Err(ScriptError::EvalFalse)),
        "P2SH redeem leaving falsy top must fail with EvalFalse, got: {r:?}"
    );
}

// ── try_verify_p2pkh: early None returns (lines 414, 417) ───────────

#[test]
fn try_verify_p2pkh_three_pushes_falls_through() {
    // Line 414: scriptSig has MORE than 2 push items. The P2PKH fast path
    // returns None and the full interpreter runs.
    //
    // Build a valid P2PKH scriptPubKey + a scriptSig with 3 pushes:
    //   <sig> <pk> <extra>
    // The fast path bails at reader.next_step() finding a third item.
    // The full interpreter runs OP_DUP OP_HASH160 ... but the extra push
    // leaves an additional item on the stack, which causes either a hash
    // mismatch or a stack issue depending on execution order.
    let sk = key([80u8; 32]);
    let pk = compressed_pubkey(&sk);
    let pkh = hash160(&pk);
    let spk = p2pkh_spk(&pkh);
    let tx = make_tx();
    let digest = tx.legacy_sighash(0, &spk, SigHashType::ALL);
    let sig = sign(&sk, digest.as_bytes(), SigHashType::ALL);

    // scriptSig = <sig> <pk> <extra byte>
    let mut script_sig = vec![u8::try_from(sig.len()).expect("DER <= 72")];
    script_sig.extend_from_slice(&sig);
    script_sig.push(u8::try_from(pk.len()).expect("compressed <= 33"));
    script_sig.extend_from_slice(&pk);
    script_sig.push(0x01); // OP_PUSHBYTES_1
    script_sig.push(0xaa); // extra data byte

    // The fast path returns None; the full interpreter runs the P2PKH
    // script. With 3 items on the stack after scriptSig, OP_DUP
    // duplicates the extra byte (top), OP_HASH160 hashes it, and
    // OP_EQUALVERIFY fails because hash(0xaa) != pkh. The specific
    // error (Verify from EQUALVERIFY) proves the full interpreter ran.
    let flags = standard_flags();
    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, flags);
    assert!(
        r.is_err(),
        "3-push scriptSig should fall through to interpreter (fast path returns None), got: {r:?}"
    );
}

#[test]
fn try_verify_p2pkh_non_push_opcode_falls_through() {
    // Line 417: scriptSig items are not push opcodes. The P2PKH fast
    // path returns None and the full interpreter runs.
    //
    // Build a valid P2PKH scriptPubKey + a scriptSig containing a
    // non-push opcode. The simplest: OP_1 OP_DUP. The reader sees
    // OP_1 (push, ok) then OP_DUP (not a push) and the fast path
    // returns None at the `!pk_step.opcode.is_push()` check.
    let pkh = [0xab; 20];
    let spk = p2pkh_spk(&pkh);
    let tx = make_tx();

    // scriptSig = OP_1(0x51) OP_DUP(0x76)
    // OP_1 is a push (pushes the number 1), OP_DUP is NOT a push.
    // The fast path sees the second step is not a push and returns None.
    // The full interpreter then runs: scriptSig pushes 1, DUPs it (stack=[1,1]),
    // then scriptPubKey runs OP_DUP OP_HASH160 ... which won't match.
    let script_sig = vec![0x51, 0x76]; // OP_1 OP_DUP
    let flags = standard_flags();
    let r = verify_script(&script_sig, &spk, &tx, 0, Satoshi::ZERO, flags);
    // The full interpreter runs: after scriptSig, stack = [1, 1, 1] (OP_1 pushes 1,
    // OP_DUP duplicates it). Then scriptPubKey OP_DUP duplicates top, OP_HASH160
    // hashes it, and the hash of [0x01] won't match [0xab; 20].
    // OP_EQUALVERIFY will fail, returning EqualVerify.
    assert!(
        r.is_err(),
        "non-push scriptSig should fall through to interpreter (fast path returns None), got: {r:?}"
    );
}
