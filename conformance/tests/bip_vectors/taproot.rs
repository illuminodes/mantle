//! BIP340/341/342 end-to-end test vectors.
//!
//! Every case encodes a complete input from first principles so that the
//! test acts as a specification: read this file and you can reconstruct any
//! vector by hand.  No external JSON fixtures; all values are computed inline
//! from the same primitives the implementation uses.
//!
//! Coverage:
//!  - BIP340 key-path: valid / corrupted Schnorr sig, explicit `SIGHASH_ALL`
//!  - BIP341 script-path: `OP_1` leaf, wrong output key, bad control block,
//!    wrong committed script
//!  - BIP342 tapscript CHECKSIG: valid sign + corrupted sig
//!  - Structural: empty witness, non-empty scriptSig, P2SH-wrapped v1
//!    program (unknown witness version), TAPROOT flag disabled
//!  - Annex: key-path spend with a valid annex item

use mantle::primitives::{
    Hash256, Locktime, OutPoint, Satoshi, Sequence, Transaction, TxIn, TxOut, TxVersion, Witness,
};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use mantle_consensus::script::sighash::{Bip341Cache, TapHasher, TaprootSigHashType, TxSighash};
use mantle_consensus::script::{ScriptFlags, verify_script};

// ── helpers ───────────────────────────────────────────────────────────────────

fn taproot_flags() -> ScriptFlags {
    ScriptFlags::P2SH | ScriptFlags::WITNESS | ScriptFlags::TAPROOT
}

fn make_taproot_tx(spk: Vec<u8>, _amount: Satoshi, witness_items: &[Vec<u8>]) -> Transaction {
    Transaction {
        version: TxVersion::new(2),
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_bytes([0x11; 32]),
                vout: 0,
            },
            script_sig: Vec::<u8>::new().into(),
            sequence: Sequence::new(0xffff_fffd),
            witness: Witness::from_slice(
                &witness_items.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            ),
        }],
        outputs: vec![TxOut {
            value: Satoshi::new(900),
            script_pubkey: spk.into(),
        }],
        locktime: Locktime::new(0),
    }
}

/// Build a taproot key-path scriptPubKey: `OP_1 <32-byte x-only pubkey>`.
fn taproot_spk(output_key: &[u8; 32]) -> Vec<u8> {
    let mut s = vec![0x51, 0x20]; // OP_1, push 32
    s.extend_from_slice(output_key);
    s
}

fn key_path_output_key(internal_key: &[u8; 32]) -> [u8; 32] {
    TapHasher::tweak_output_key(internal_key, &[]).expect("valid internal key")
}

fn schnorr_sign(secret: &[u8; 32], msg: &[u8; 32]) -> [u8; 64] {
    use k256::schnorr::SigningKey;
    use k256::schnorr::signature::hazmat::PrehashSigner;
    let sk = SigningKey::from_bytes(secret.into()).expect("nonzero secret");
    let sig: k256::schnorr::Signature = sk.sign_prehash(msg).expect("sign cannot fail");
    sig.to_bytes()
}

fn schnorr_pubkey(secret: &[u8; 32]) -> [u8; 32] {
    use k256::schnorr::SigningKey;
    SigningKey::from_bytes(secret.into())
        .expect("nonzero secret")
        .verifying_key()
        .to_bytes()
        .into()
}

/// Compute the BIP341 tweaked signing key for a key-path spend.
///
/// BIP341 §"Spending using the key path":
///   d = `internal_secret` (negated if `internal_pubkey` has odd Y — k256 does this on construction)
///   t = int(TapTweak(`internal_pubkey` || `merkle_root`))  mod n
///   `tweaked_secret` = (d + t) mod n
fn tweaked_signing_key(internal_secret: &[u8; 32], merkle_root: &[u8]) -> [u8; 32] {
    use k256::elliptic_curve::bigint::Encoding;
    use k256::elliptic_curve::ops::Reduce;
    use k256::schnorr::SigningKey;
    use k256::{NonZeroScalar, Scalar, U256};

    // k256 normalises to even-Y on construction (negates d if pubkey.y is odd).
    let sk = SigningKey::from_bytes(internal_secret.into()).expect("nonzero secret");
    let internal_pubkey: [u8; 32] = sk.verifying_key().to_bytes().into();

    let mut tweak_input = Vec::with_capacity(32 + merkle_root.len());
    tweak_input.extend_from_slice(&internal_pubkey);
    tweak_input.extend_from_slice(merkle_root);
    let tweak_bytes =
        mantle_consensus::script::consensus_crypto::Schnorr::tagged_hash(b"TapTweak", &tweak_input);
    let t = <Scalar as Reduce<U256>>::reduce(&U256::from_be_bytes(tweak_bytes.into()));

    let d: Scalar = *sk.as_nonzero_scalar().as_ref();
    let tweaked = d + t;
    let tweaked_nz = NonZeroScalar::new(tweaked).expect("tweaked scalar is non-zero");

    tweaked_nz.to_bytes().into()
}

// ── BIP340 key-path ───────────────────────────────────────────────────────────

#[test]
fn bip340_key_path_spend_succeeds() {
    let internal_secret = [0x42u8; 32];
    let internal_key = schnorr_pubkey(&internal_secret);
    let output_key = key_path_output_key(&internal_key);
    let spk = taproot_spk(&output_key);
    let amount = Satoshi::new(100_000);
    let tweaked_secret = tweaked_signing_key(&internal_secret, &[]);

    // Compute sighash on a placeholder tx, sign, then rebuild with the real sig.
    // Two-pass: first pass uses a zeroed sig placeholder to get the tx shape
    // (sighash doesn't commit to witness, so this equals the final tx's sighash).
    let placeholder_tx = make_taproot_tx(spk.clone(), amount, &[[0u8; 64].to_vec()]);
    let cache = Bip341Cache::new(&placeholder_tx, &[amount], &[spk.as_slice()]);
    let msg = placeholder_tx.bip341_sighash(
        0,
        amount,
        &spk,
        TaprootSigHashType::DEFAULT,
        &cache,
        None,
        None,
    );
    let sig64 = schnorr_sign(&tweaked_secret, &msg);

    let tx = make_taproot_tx(spk.clone(), amount, &[sig64.to_vec()]);
    verify_script(&[], &spk, &tx, 0, amount, taproot_flags())
        .expect("BIP340 key-path spend must verify");
}

#[test]
fn bip340_key_path_wrong_sig_fails() {
    let internal_secret = [0x42u8; 32];
    let internal_key = schnorr_pubkey(&internal_secret);
    let output_key = key_path_output_key(&internal_key);
    let spk = taproot_spk(&output_key);
    let amount = Satoshi::new(100_000);

    let tmp_tx = make_taproot_tx(spk.clone(), amount, &[]);
    let cache = Bip341Cache::new(&tmp_tx, &[amount], &[spk.as_slice()]);
    let msg = tmp_tx.bip341_sighash(
        0,
        amount,
        &spk,
        TaprootSigHashType::DEFAULT,
        &cache,
        None,
        None,
    );
    let tweaked_secret = tweaked_signing_key(&internal_secret, &[]);
    let mut sig64 = schnorr_sign(&tweaked_secret, &msg);
    sig64[0] ^= 0xff;

    let tx = make_taproot_tx(spk.clone(), amount, &[sig64.to_vec()]);
    assert!(
        verify_script(&[], &spk, &tx, 0, amount, taproot_flags()).is_err(),
        "corrupted sig must fail"
    );
}

#[test]
fn bip340_key_path_sighash_all_explicit_succeeds() {
    // 65-byte form: append 0x01 (explicit SIGHASH_ALL).
    let internal_secret = [0x43u8; 32];
    let internal_key = schnorr_pubkey(&internal_secret);
    let output_key = key_path_output_key(&internal_key);
    let spk = taproot_spk(&output_key);
    let amount = Satoshi::new(50_000);

    let tmp_tx = make_taproot_tx(spk.clone(), amount, &[]);
    let cache = Bip341Cache::new(&tmp_tx, &[amount], &[spk.as_slice()]);
    let msg = tmp_tx.bip341_sighash(0, amount, &spk, TaprootSigHashType::ALL, &cache, None, None);
    let tweaked_secret = tweaked_signing_key(&internal_secret, &[]);
    let sig64 = schnorr_sign(&tweaked_secret, &msg);
    let mut sig65 = sig64.to_vec();
    sig65.push(0x01);

    let tx = make_taproot_tx(spk.clone(), amount, &[sig65]);
    verify_script(&[], &spk, &tx, 0, amount, taproot_flags())
        .expect("65-byte explicit SIGHASH_ALL must verify");
}

#[test]
fn bip340_key_path_empty_witness_fails() {
    let internal_secret = [0x42u8; 32];
    let internal_key = schnorr_pubkey(&internal_secret);
    let output_key = key_path_output_key(&internal_key);
    let spk = taproot_spk(&output_key);
    let amount = Satoshi::new(100_000);

    let tx = make_taproot_tx(spk.clone(), amount, &[]);
    assert!(
        verify_script(&[], &spk, &tx, 0, amount, taproot_flags()).is_err(),
        "empty witness must fail for taproot"
    );
}

// ── BIP341 script-path ────────────────────────────────────────────────────────

/// Build a script-path spend for a single-leaf tree.
///
/// Returns `(spk, witness_items)` ready for `make_taproot_tx`.
fn script_path_single_leaf(internal_key: &[u8; 32], script: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let leaf_version: u8 = 0xc0;
    let leaf_hash = TapHasher::leaf(leaf_version, script);
    let tweaked = TapHasher::tweak(internal_key, &leaf_hash).expect("valid internal key");
    let spk = taproot_spk(&tweaked.x);

    let mut control_block = vec![leaf_version | u8::from(tweaked.odd_y)];
    control_block.extend_from_slice(internal_key);

    // Witness: [script, control_block]  — no stack inputs for OP_1
    let witness_items = vec![script.to_vec(), control_block];
    (spk, witness_items)
}

#[test]
fn bip341_script_path_op1_leaf_succeeds() {
    let internal_key = schnorr_pubkey(&[0x55u8; 32]);
    let script = vec![0x51]; // OP_1
    let (spk, witness_items) = script_path_single_leaf(&internal_key, &script);
    let amount = Satoshi::new(200_000);

    let tx = make_taproot_tx(spk.clone(), amount, &witness_items);
    verify_script(&[], &spk, &tx, 0, amount, taproot_flags())
        .expect("OP_1 tapscript leaf must verify");
}

#[test]
fn bip341_script_path_wrong_output_key_fails() {
    let internal_key = schnorr_pubkey(&[0x55u8; 32]);
    let script = vec![0x51]; // OP_1
    let (correct_spk, witness_items) = script_path_single_leaf(&internal_key, &script);

    let mut wrong_spk = correct_spk.clone();
    wrong_spk[2] ^= 0xff;

    let amount = Satoshi::new(200_000);
    let tx = make_taproot_tx(wrong_spk.clone(), amount, &witness_items);
    assert!(
        verify_script(&[], &wrong_spk, &tx, 0, amount, taproot_flags()).is_err(),
        "wrong output key must fail"
    );
}

#[test]
fn bip341_script_path_bad_control_block_fails() {
    let internal_key = schnorr_pubkey(&[0x55u8; 32]);
    let script = vec![0x51]; // OP_1
    let (spk, _) = script_path_single_leaf(&internal_key, &script);

    let bad_control = vec![0xc0]; // only leaf_version byte, no internal key
    let witness_items = vec![script.clone(), bad_control];
    let amount = Satoshi::new(200_000);
    let tx = make_taproot_tx(spk.clone(), amount, &witness_items);
    assert!(
        verify_script(&[], &spk, &tx, 0, amount, taproot_flags()).is_err(),
        "truncated control block must fail"
    );
}

#[test]
fn bip341_script_path_wrong_leaf_script_fails() {
    let internal_key = schnorr_pubkey(&[0x55u8; 32]);
    let committed_script = vec![0x51]; // OP_1
    let (spk, mut witness_items) = script_path_single_leaf(&internal_key, &committed_script);

    witness_items[0] = vec![0x00]; // swap to OP_0 — leaf hash won't match

    let amount = Satoshi::new(200_000);
    let tx = make_taproot_tx(spk.clone(), amount, &witness_items);
    assert!(
        verify_script(&[], &spk, &tx, 0, amount, taproot_flags()).is_err(),
        "mismatched committed script must fail"
    );
}

// ── BIP342 tapscript CHECKSIG ─────────────────────────────────────────────────

fn checksig_tapscript(pubkey32: &[u8; 32]) -> Vec<u8> {
    let mut s = vec![0x20]; // push 32 bytes
    s.extend_from_slice(pubkey32);
    s.push(0xac); // OP_CHECKSIG
    s
}

#[test]
fn bip342_tapscript_checksig_succeeds() {
    let secret = [0x77u8; 32];
    let pubkey32 = schnorr_pubkey(&secret);
    let internal_key = schnorr_pubkey(&[0x56u8; 32]);

    let script = checksig_tapscript(&pubkey32);
    let leaf_version: u8 = 0xc0;
    let leaf_hash = TapHasher::leaf(leaf_version, &script);
    let tweaked = TapHasher::tweak(&internal_key, &leaf_hash).expect("valid internal key");
    let spk = taproot_spk(&tweaked.x);

    let mut control_block = vec![leaf_version | u8::from(tweaked.odd_y)];
    control_block.extend_from_slice(&internal_key);

    let amount = Satoshi::new(300_000);
    let tmp_tx = make_taproot_tx(spk.clone(), amount, &[]);
    let cache = Bip341Cache::new(&tmp_tx, &[amount], &[spk.as_slice()]);
    let msg = tmp_tx.bip341_sighash(
        0,
        amount,
        &spk,
        TaprootSigHashType::DEFAULT,
        &cache,
        None,
        Some((leaf_hash, 0xffff_ffff)),
    );
    let sig64 = schnorr_sign(&secret, &msg);

    let witness_items = vec![sig64.to_vec(), script.clone(), control_block];
    let tx = make_taproot_tx(spk.clone(), amount, &witness_items);
    verify_script(&[], &spk, &tx, 0, amount, taproot_flags())
        .expect("BIP342 CHECKSIG tapscript must verify");
}

#[test]
fn bip342_tapscript_checksig_wrong_sig_fails() {
    let secret = [0x77u8; 32];
    let pubkey32 = schnorr_pubkey(&secret);
    let internal_key = schnorr_pubkey(&[0x56u8; 32]);

    let script = checksig_tapscript(&pubkey32);
    let leaf_version: u8 = 0xc0;
    let leaf_hash = TapHasher::leaf(leaf_version, &script);
    let tweaked = TapHasher::tweak(&internal_key, &leaf_hash).expect("valid internal key");
    let spk = taproot_spk(&tweaked.x);

    let mut control_block = vec![leaf_version | u8::from(tweaked.odd_y)];
    control_block.extend_from_slice(&internal_key);

    let amount = Satoshi::new(300_000);
    let tmp_tx = make_taproot_tx(spk.clone(), amount, &[]);
    let cache = Bip341Cache::new(&tmp_tx, &[amount], &[spk.as_slice()]);
    let msg = tmp_tx.bip341_sighash(
        0,
        amount,
        &spk,
        TaprootSigHashType::DEFAULT,
        &cache,
        None,
        Some((leaf_hash, 0xffff_ffff)),
    );
    let mut sig64 = schnorr_sign(&secret, &msg);
    sig64[0] ^= 0xff;

    let witness_items = vec![sig64.to_vec(), script.clone(), control_block];
    let tx = make_taproot_tx(spk.clone(), amount, &witness_items);
    assert!(
        verify_script(&[], &spk, &tx, 0, amount, taproot_flags()).is_err(),
        "wrong sig in tapscript CHECKSIG must fail"
    );
}

// ── Structural rejections ─────────────────────────────────────────────────────

#[test]
fn taproot_nonempty_scriptsig_is_malleated() {
    let secret = [0x42u8; 32];
    let internal_key = schnorr_pubkey(&secret);
    let output_key = key_path_output_key(&internal_key);
    let spk = taproot_spk(&output_key);
    let amount = Satoshi::new(100_000);

    let tmp_tx = make_taproot_tx(spk.clone(), amount, &[]);
    let cache = Bip341Cache::new(&tmp_tx, &[amount], &[spk.as_slice()]);
    let msg = tmp_tx.bip341_sighash(
        0,
        amount,
        &spk,
        TaprootSigHashType::DEFAULT,
        &cache,
        None,
        None,
    );
    let sig64 = schnorr_sign(&secret, &msg);

    let mut tx = make_taproot_tx(spk.clone(), amount, &[sig64.to_vec()]);
    tx.inputs[0].script_sig = vec![0x51].into();

    // Non-empty scriptSig on a native segwit input → WitnessMalleated.
    assert!(
        verify_script(&[0x51], &spk, &tx, 0, amount, taproot_flags()).is_err(),
        "non-empty scriptSig on taproot must be rejected"
    );
}

#[test]
fn p2sh_wrapped_v1_program_is_an_unknown_witness_version() {
    let internal_key = schnorr_pubkey(&[0x42u8; 32]);
    let output_key = key_path_output_key(&internal_key);
    let taproot_spk_bytes = taproot_spk(&output_key);

    let h160: [u8; 20] = Ripemd160::digest(Sha256::digest(&taproot_spk_bytes)).into();
    let mut p2sh_spk = vec![0xa9, 0x14];
    p2sh_spk.extend_from_slice(&h160);
    p2sh_spk.push(0x87);

    let mut script_sig = vec![u8::try_from(taproot_spk_bytes.len()).expect("≤ 75")];
    script_sig.extend_from_slice(&taproot_spk_bytes);

    let tx = Transaction {
        version: TxVersion::new(2),
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_bytes([0x11; 32]),
                vout: 0,
            },
            script_sig: script_sig.clone().into(),
            sequence: Sequence::new(0xffff_ffff),
            witness: Witness::from_slice(&[&[][..]]),
        }],
        outputs: vec![TxOut {
            value: Satoshi::new(900),
            script_pubkey: vec![0x6a].into(),
        }],
        locktime: Locktime::new(0),
    };

    assert!(
        verify_script(
            &script_sig,
            &p2sh_spk,
            &tx,
            0,
            Satoshi::new(100_000),
            taproot_flags()
        )
        .is_ok(),
        "BIP341 applies only to native v1 outputs; wrapped ones are an unknown version"
    );
}

#[test]
fn taproot_disabled_treats_as_unknown_witness_version() {
    // Without TAPROOT flag a v1 witness program is an unknown version.
    // Unknown versions succeed unless DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM is set.
    let internal_key = schnorr_pubkey(&[0x42u8; 32]);
    let output_key = key_path_output_key(&internal_key);
    let spk = taproot_spk(&output_key);
    let amount = Satoshi::new(100_000);

    let tx = make_taproot_tx(spk.clone(), amount, &[vec![0xde, 0xad]]);

    let flags_no_taproot = ScriptFlags::P2SH | ScriptFlags::WITNESS;
    verify_script(&[], &spk, &tx, 0, amount, flags_no_taproot)
        .expect("unknown witness version without DISCOURAGE flag must succeed");
}

// ── Annex handling ────────────────────────────────────────────────────────────

#[test]
fn bip341_key_path_with_annex_succeeds() {
    // The annex (last witness item starting with 0x50) is committed to in the
    // sighash but otherwise ignored during key-path execution.
    let internal_secret = [0x42u8; 32];
    let internal_key = schnorr_pubkey(&internal_secret);
    let output_key = key_path_output_key(&internal_key);
    let spk = taproot_spk(&output_key);
    let amount = Satoshi::new(100_000);

    let annex = vec![0x50, 0xde, 0xad];

    // Use the final tx layout (sig placeholder + annex) so the sighash sees
    // the right annex commitment.
    let tmp_tx = make_taproot_tx(spk.clone(), amount, &[vec![0u8; 64], annex.clone()]);
    let cache = Bip341Cache::new(&tmp_tx, &[amount], &[spk.as_slice()]);
    let annex_body = &annex[1..]; // strip 0x50 prefix byte
    let msg = tmp_tx.bip341_sighash(
        0,
        amount,
        &spk,
        TaprootSigHashType::DEFAULT,
        &cache,
        Some(annex_body),
        None,
    );
    // Key-path sigs are produced with the *tweaked* secret so the resulting
    // signature verifies against the output (tweaked) key in the scriptPubKey.
    let tweaked_secret = tweaked_signing_key(&internal_secret, &[]);
    let sig64 = schnorr_sign(&tweaked_secret, &msg);

    let tx = make_taproot_tx(spk.clone(), amount, &[sig64.to_vec(), annex]);
    verify_script(&[], &spk, &tx, 0, amount, taproot_flags())
        .expect("key-path spend with annex must verify");
}

#[test]
fn diag_schnorr_sign_verify_roundtrip() {
    use k256::schnorr::SigningKey;
    use k256::schnorr::signature::hazmat::{PrehashSigner, PrehashVerifier};

    let secret = [0x42u8; 32];
    let sk = SigningKey::from_bytes((&secret).into()).expect("valid");
    let msg = [0xabu8; 32];
    let sig: k256::schnorr::Signature = sk.sign_prehash(&msg).expect("sign");
    let vk = sk.verifying_key();
    // PrehashVerifier uses the raw bytes (no re-hash) — must match sign_prehash.
    vk.verify_prehash(&msg, &sig)
        .expect("k256 prehash verify must pass");

    let sig_bytes: [u8; 64] = sig.to_bytes();
    let pk_bytes: [u8; 32] = vk.to_bytes().into();
    let ok =
        mantle_consensus::script::consensus_crypto::Schnorr::verify(&sig_bytes, &pk_bytes, &msg);
    assert!(ok, "Schnorr::verify must pass for k256-signed msg");
}

#[test]
fn diag_sighash_determinism() {
    let secret = [0x42u8; 32];
    let internal_key = schnorr_pubkey(&secret);
    let output_key = key_path_output_key(&internal_key);
    let spk = taproot_spk(&output_key);
    let amount = Satoshi::new(100_000);

    let tmp_tx = make_taproot_tx(spk.clone(), amount, &[]);
    let cache1 = Bip341Cache::new(&tmp_tx, &[amount], &[spk.as_slice()]);
    let msg1 = tmp_tx.bip341_sighash(
        0,
        amount,
        &spk,
        TaprootSigHashType::DEFAULT,
        &cache1,
        None,
        None,
    );

    // The real tx has a witness — sighash must be the same.
    let sig64 = [0u8; 64];
    let real_tx = make_taproot_tx(spk.clone(), amount, &[sig64.to_vec()]);
    let cache2 = Bip341Cache::new(&real_tx, &[amount], &[spk.as_slice()]);
    let msg2 = real_tx.bip341_sighash(
        0,
        amount,
        &spk,
        TaprootSigHashType::DEFAULT,
        &cache2,
        None,
        None,
    );

    // Also compute what run_taproot computes: it builds cache from the REAL tx.
    assert_eq!(msg1, msg2, "sighash must not depend on witness content");

    let tweaked_secret = tweaked_signing_key(&secret, &[]);
    let sig = schnorr_sign(&tweaked_secret, &msg1);

    // Mimic exactly what run_taproot does: build cache from the REAL tx (with sig in witness).
    let real_tx = make_taproot_tx(spk.clone(), amount, &[sig.to_vec()]);
    let rt_cache = Bip341Cache::new(&real_tx, &[amount], &[spk.as_slice()]);
    let rt_msg = real_tx.bip341_sighash(
        0,
        amount,
        &spk,
        TaprootSigHashType::DEFAULT,
        &rt_cache,
        None,
        None,
    );

    eprintln!("msg1 (from placeholder_tx): {msg1:02x?}");
    eprintln!("rt_msg (from real_tx):      {rt_msg:02x?}");
    eprintln!("msgs_match: {}", msg1 == rt_msg);

    // run_taproot verifies: Schnorr::verify(sig64, program32=output_key, &rt_msg)
    let ok =
        mantle_consensus::script::consensus_crypto::Schnorr::verify(&sig, &output_key, &rt_msg);
    eprintln!("verify_schnorr(tweaked_sig, output_key, rt_msg): {ok}");
}

// ── multi-input taproot ───────────────────────────────────────────────────────

/// Build a 2-input single-output taproot tx. Distinct `previous_outputs` so
/// the two inputs don't collide in `hashPrevouts`. The per-input spent spks
/// (`spk0`, `spk1`) and amounts are passed separately to `Bip341Cache::new`
/// at the call site — they aren't needed inside the tx body itself.
fn make_two_input_taproot_tx(
    out_value: Satoshi,
    out_spk: Vec<u8>,
    witness0: &[Vec<u8>],
    witness1: &[Vec<u8>],
) -> Transaction {
    Transaction {
        version: TxVersion::new(2),
        inputs: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([0x11; 32]),
                    vout: 0,
                },
                script_sig: Vec::<u8>::new().into(),
                sequence: Sequence::new(0xffff_fffd),
                witness: Witness::from_slice(
                    &witness0.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                ),
            },
            TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([0x22; 32]),
                    vout: 1,
                },
                script_sig: Vec::<u8>::new().into(),
                sequence: Sequence::new(0xffff_fffd),
                witness: Witness::from_slice(
                    &witness1.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                ),
            },
        ],
        outputs: vec![TxOut {
            value: out_value,
            script_pubkey: out_spk.into(),
        }],
        locktime: Locktime::new(0),
    }
}

/// Two-input taproot key-path spend. Both inputs sign over the full
/// `spent_outputs` table; verification must succeed for both inputs.
///
/// Regression test: prior to threading `SpentOutputs` through the verify
/// pipeline, `run_taproot` built `Bip341Cache` with single-element slices
/// regardless of `tx.input_count()`, panicking the moment the cache's
/// `assert_eq!(spent_amounts.len(), tx.input_count())` ran.
#[test]
fn bip341_key_path_two_input_succeeds() {
    use mantle_consensus::script::SpentOutputs;
    use mantle_consensus::script::verify_script_with_spent_outputs;

    let secret0 = [0x33u8; 32];
    let secret1 = [0x44u8; 32];
    let out_key0 = key_path_output_key(&schnorr_pubkey(&secret0));
    let out_key1 = key_path_output_key(&schnorr_pubkey(&secret1));
    let spk0 = taproot_spk(&out_key0);
    let spk1 = taproot_spk(&out_key1);
    let amt0 = Satoshi::new(60_000);
    let amt1 = Satoshi::new(40_000);

    let tweaked0 = tweaked_signing_key(&secret0, &[]);
    let tweaked1 = tweaked_signing_key(&secret1, &[]);

    // Placeholder pass: zeroed sigs to lock in the tx shape (sighash doesn't
    // commit to witness data so the digest equals the final-tx digest).
    let placeholder = make_two_input_taproot_tx(
        Satoshi::new(95_000),
        vec![0x51], // OP_TRUE output
        &[[0u8; 64].to_vec()],
        &[[0u8; 64].to_vec()],
    );
    let amounts = [amt0, amt1];
    let all_spks: [&[u8]; 2] = [spk0.as_slice(), spk1.as_slice()];
    let cache = Bip341Cache::new(&placeholder, &amounts, &all_spks);

    let msg0 = placeholder.bip341_sighash(
        0,
        amt0,
        &spk0,
        TaprootSigHashType::DEFAULT,
        &cache,
        None,
        None,
    );
    let msg1 = placeholder.bip341_sighash(
        1,
        amt1,
        &spk1,
        TaprootSigHashType::DEFAULT,
        &cache,
        None,
        None,
    );
    let sig0 = schnorr_sign(&tweaked0, &msg0);
    let sig1 = schnorr_sign(&tweaked1, &msg1);

    let tx = make_two_input_taproot_tx(
        Satoshi::new(95_000),
        vec![0x51],
        &[sig0.to_vec()],
        &[sig1.to_vec()],
    );

    let so = SpentOutputs::new(&amounts, &all_spks).expect("matched lengths");

    verify_script_with_spent_outputs(&[], &spk0, &tx, 0, amt0, taproot_flags(), so)
        .expect("two-input taproot key-path: input 0 must verify");
    verify_script_with_spent_outputs(&[], &spk1, &tx, 1, amt1, taproot_flags(), so)
        .expect("two-input taproot key-path: input 1 must verify");
}

/// Two-input taproot key-path spend, signed with
/// `SIGHASH_SINGLE | ANYONECANPAY` (0x83) — the variant the ordinals
/// parity bench discovered failing in mantle.
#[test]
#[allow(clippy::too_many_lines)]
fn bip341_key_path_two_input_single_anyonecanpay() {
    use mantle_consensus::script::SpentOutputs;
    use mantle_consensus::script::sighash::TaprootSigHashType;
    use mantle_consensus::script::verify_script_with_spent_outputs;

    // Two-output tx so SIGHASH_SINGLE has both n_in=0 and n_in=1 outputs to commit to.
    fn make_two_in_two_out_taproot_tx(
        out0_value: Satoshi,
        out0_spk: Vec<u8>,
        out1_value: Satoshi,
        out1_spk: Vec<u8>,
        witness0: &[Vec<u8>],
        witness1: &[Vec<u8>],
    ) -> Transaction {
        Transaction {
            version: TxVersion::new(2),
            inputs: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: Hash256::from_bytes([0xaa; 32]),
                        vout: 0,
                    },
                    script_sig: Vec::<u8>::new().into(),
                    sequence: Sequence::new(0xffff_fffd),
                    witness: Witness::from_slice(
                        &witness0.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                    ),
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: Hash256::from_bytes([0xbb; 32]),
                        vout: 1,
                    },
                    script_sig: Vec::<u8>::new().into(),
                    sequence: Sequence::new(0xffff_fffd),
                    witness: Witness::from_slice(
                        &witness1.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                    ),
                },
            ],
            outputs: vec![
                TxOut {
                    value: out0_value,
                    script_pubkey: out0_spk.into(),
                },
                TxOut {
                    value: out1_value,
                    script_pubkey: out1_spk.into(),
                },
            ],
            locktime: Locktime::new(0),
        }
    }

    let secret0 = [0x77u8; 32];
    let secret1 = [0x88u8; 32];
    let out_key0 = key_path_output_key(&schnorr_pubkey(&secret0));
    let out_key1 = key_path_output_key(&schnorr_pubkey(&secret1));
    let spk0 = taproot_spk(&out_key0);
    let spk1 = taproot_spk(&out_key1);
    let amt0 = Satoshi::new(70_000);
    let amt1 = Satoshi::new(50_000);

    let tweaked0 = tweaked_signing_key(&secret0, &[]);

    // Placeholder pass: 65-byte zero sig + sighash type byte to lock in tx shape.
    let mut placeholder_sig0 = vec![0u8; 64];
    placeholder_sig0.push(0x83);
    let placeholder = make_two_in_two_out_taproot_tx(
        Satoshi::new(40_000),
        vec![0x51],
        Satoshi::new(20_000),
        vec![0x51],
        &[placeholder_sig0],
        &[vec![0u8; 64]],
    );
    let amounts = [amt0, amt1];
    let all_spks: [&[u8]; 2] = [spk0.as_slice(), spk1.as_slice()];
    let cache = Bip341Cache::new(&placeholder, &amounts, &all_spks);

    let msg0 = placeholder.bip341_sighash(
        0,
        amt0,
        &spk0,
        TaprootSigHashType::SINGLE_ANYONECANPAY,
        &cache,
        None,
        None,
    );
    let sig64 = schnorr_sign(&tweaked0, &msg0);
    let mut sig65 = sig64.to_vec();
    sig65.push(0x83);

    // Final tx: input 0 has the real 65-byte sig; input 1 is signed default.
    let tweaked1 = tweaked_signing_key(&secret1, &[]);
    let msg1_default = placeholder.bip341_sighash(
        1,
        amt1,
        &spk1,
        TaprootSigHashType::DEFAULT,
        &cache,
        None,
        None,
    );
    let sig1_default = schnorr_sign(&tweaked1, &msg1_default);

    let tx = make_two_in_two_out_taproot_tx(
        Satoshi::new(40_000),
        vec![0x51],
        Satoshi::new(20_000),
        vec![0x51],
        &[sig65],
        &[sig1_default.to_vec()],
    );

    let so = SpentOutputs::new(&amounts, &all_spks).expect("matched lengths");

    verify_script_with_spent_outputs(&[], &spk0, &tx, 0, amt0, taproot_flags(), so)
        .expect("two-input taproot SINGLE_ANYONECANPAY: input 0 must verify");
}

/// Real-mainnet regression: tx `d7748e08…8bdfab` from block 767,434 is a
/// 4-input/7-output transaction whose input 2 is a taproot key-path spend
/// signed with `SIGHASH_SINGLE | ANYONECANPAY` (0x83). Mantle previously
/// returned `TaprootVerify` because `compute_bip341_sighash` emitted
/// `sha_single_output` *before* the spend-type byte instead of *after* the
/// annex hash, putting it in the wrong position in the BIP341 message.
///
/// Wire bytes captured from the ordinals fixture corpus via
/// `bench/src/find_tx.rs`. Embedded here as a hex string so the test
/// is self-contained and runs without the fixture present.
#[test]
fn bip341_real_mainnet_block_767434_single_anyonecanpay() {
    use mantle::codec::Decode;
    use std::io::Cursor;

    use mantle_consensus::script::SpentOutputs;
    use mantle_consensus::script::verify_script_with_spent_outputs;

    // Tx d7748e08b2ce8c492c3593df39fba058ed1c2c9ab2bac1de6a5f853ef826b5f8.
    const TX_WIRE_HEX: &str = "02000000000104362cfe19efc4ddc48d3e1aae1fbd5fe16a993ab0ca1c1f2fd99c1548b4bccde200000000171600144c6b82aa8e759d8e8d41792210bd777baaa22145ffffffff362cfe19efc4ddc48d3e1aae1fbd5fe16a993ab0ca1c1f2fd99c1548b4bccde201000000171600144c6b82aa8e759d8e8d41792210bd777baaa22145ffffffff5f2360c1ea9b62f61746dd65a270f6432818931afb56d2ca0a240cd7ba9b4c610000000000ffffffff362cfe19efc4ddc48d3e1aae1fbd5fe16a993ab0ca1c1f2fd99c1548b4bccde20a000000171600144c6b82aa8e759d8e8d41792210bd777baaa22145ffffffff07b00400000000000017a91466d3f0c3febcf2dc0e49bbd71ee8a026792dc5ac871027000000000000225120d553550d056e80ffe07c0630698546ff756c38dc9f8075f7d10c2a8bedc41d07d972000000000000225120c20deca5159cb269fab27e1237e2f2cc39f8c5bcaa668968597ef52c290b33e6d502000000000000160014c015c65276d5f38d599d445c4cb03aa7aa0dc365580200000000000017a91466d3f0c3febcf2dc0e49bbd71ee8a026792dc5ac87580200000000000017a91466d3f0c3febcf2dc0e49bbd71ee8a026792dc5ac876aa901000000000017a91466d3f0c3febcf2dc0e49bbd71ee8a026792dc5ac8702473044022024c9ae64da2d9ad245e620eab60e2c9ccae26268a0c6f67cbf4e44fdd5d8db8902202c91f9db5bb06427203f5a210a43380a1bbc8149c4d0db57dad1f7328aad3126012102d33fb5661ea2afb54bf9fa147c6a2ae2492e81877c3370d07256054b0e5fe3cc02473044022009b9798b20fa54a8d6636a5c352837f22cd476b24d8b7e69da9533894c8486ee02203e996fce541781f425b8b6b80fb10e54a08d08a5d70c1771db8a75a1175886d8012102d33fb5661ea2afb54bf9fa147c6a2ae2492e81877c3370d07256054b0e5fe3cc014113f35fbb2d2e217ad013d10941547125eb118977f21262cb51709fa3fbe73a8df2c03d8057f437e71ef29741c6ac7430153e47fa8fc2184a1a469ff55f4c85a28302483045022100c9ed6d4950e60869f443c637f38467bff14b5426ccbd57a7bfbd0f4a1c85fad202206068d32c4e5dede68292134fbbfd0496a7b9b53b213e115f1217008b0bed8fdc012102d33fb5661ea2afb54bf9fa147c6a2ae2492e81877c3370d07256054b0e5fe3cc00000000";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex byte"))
            .collect()
    }

    let tx_wire = unhex(TX_WIRE_HEX);
    let tx = Transaction::decode(&mut Cursor::new(&tx_wire)).expect("decode tx");
    assert_eq!(tx.inputs.len(), 4, "regression: tx must have 4 inputs");
    assert_eq!(tx.outputs.len(), 7, "regression: tx must have 7 outputs");

    // Spent outputs in input order. Captured from the ordinals fixture
    // corpus via crates/bench/src/find_tx.rs.
    let p2sh_p2wpkh_spk = unhex("a91466d3f0c3febcf2dc0e49bbd71ee8a026792dc5ac87");
    let p2tr_spk = unhex("5120c20deca5159cb269fab27e1237e2f2cc39f8c5bcaa668968597ef52c290b33e6");
    let amounts = [
        Satoshi::new(600),
        Satoshi::new(600),
        Satoshi::new(546),
        Satoshi::new(154_969),
    ];
    let spks: [&[u8]; 4] = [
        &p2sh_p2wpkh_spk,
        &p2sh_p2wpkh_spk,
        &p2tr_spk,
        &p2sh_p2wpkh_spk,
    ];
    let spent_outputs = SpentOutputs::new(&amounts, &spks).expect("matched");

    // Verify input 2 (the taproot key-path spend that previously failed).
    // Mainnet flags at this height include P2SH | WITNESS | TAPROOT.
    let flags = ScriptFlags::P2SH | ScriptFlags::WITNESS | ScriptFlags::TAPROOT;
    verify_script_with_spent_outputs(
        &[],
        &p2tr_spk,
        &tx,
        2,
        Satoshi::new(546),
        flags,
        spent_outputs,
    )
    .expect("real-mainnet taproot SIGHASH_SINGLE|ANYONECANPAY (0x83) input must verify");
}

/// Without `SpentOutputs`, a multi-input taproot input returns
/// `TaprootMissingSpentOutputs` instead of panicking.
#[test]
fn bip341_key_path_two_input_without_spent_outputs_errors() {
    use mantle_consensus::script::ScriptError;

    let secret0 = [0x55u8; 32];
    let secret1 = [0x66u8; 32];
    let out_key0 = key_path_output_key(&schnorr_pubkey(&secret0));
    let out_key1 = key_path_output_key(&schnorr_pubkey(&secret1));
    let spk0 = taproot_spk(&out_key0);
    let spk1 = taproot_spk(&out_key1);
    let amt0 = Satoshi::new(11_000);
    let amt1 = Satoshi::new(22_000);

    // Witnesses don't matter — the missing-spent-outputs error fires before
    // the signature is consulted. Use zeroed placeholders so the witness
    // shape (1 item) is recognised as a key-path spend.
    let tx = make_two_input_taproot_tx(
        Satoshi::new(30_000),
        vec![0x51],
        &[[0u8; 64].to_vec()],
        &[[0u8; 64].to_vec()],
    );

    let result = verify_script(&[], &spk0, &tx, 0, amt0, taproot_flags());
    assert!(
        matches!(result, Err(ScriptError::TaprootMissingSpentOutputs)),
        "expected TaprootMissingSpentOutputs, got {result:?}"
    );
    let _ = (spk1, amt1); // suppress unused warnings if the assertion macro reorders
}
