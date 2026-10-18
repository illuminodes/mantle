//! `SignatureChecker` — the abstraction the interpreter uses to ask the
//! transaction context "does this signature verify?".
//!
//! Mirrors Bitcoin Core's `BaseSignatureChecker` virtual class, but as a Rust
//! trait — the interpreter is generic over `C: SignatureChecker` so dispatch
//! is monomorphised, no vtable.
//!
//! Production wires a `TxSigChecker { tx, n_in, amount }` (M1.2). Tests wire
//! `NopSigChecker` to exercise non-crypto opcodes without a transaction.

use std::sync::OnceLock;

use mantle::primitives::{Satoshi, Sequence};

use super::consensus_crypto::{Ecdsa, Schnorr};
use super::flags::ScriptFlags;
use super::sig_version::SigVersion;
use super::sighash::{
    Bip143Cache, Bip341Cache, FindAndDelete, SigHashType, TaprootSigHashType, TxSighash,
};
use crate::tx_view::{InputView, TxView};

/// Asks "does this signature, pubkey, and scriptCode verify?" for the script
/// being evaluated. The interpreter calls one of these methods for every
/// signature-checking opcode (`OP_CHECKSIG`, `OP_CHECKMULTISIG`,
/// `OP_CHECKLOCKTIMEVERIFY`, `OP_CHECKSEQUENCEVERIFY`).
pub trait SignatureChecker {
    /// Verify an ECDSA signature against a pubkey and the sighash computed
    /// from `script_code` (the scriptCode of the current `OP_CHECKSIG` call,
    /// already with `OP_CODESEPARATOR` handling applied) under `sig_version`.
    ///
    /// Returns `true` on success, `false` on any failure mode that consensus
    /// treats as "signature did not verify" — including malformed encodings,
    /// curve failures, and `NULLFAIL` violations. The interpreter does not
    /// distinguish *why* a signature failed; it only acts on the boolean.
    fn check_ecdsa_sig(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        script_code: &[u8],
        sig_version: SigVersion,
    ) -> bool;

    /// Verify a BIP340 Schnorr signature in tapscript.
    ///
    /// `sig` is the raw witness item (64 or 65 bytes, already encoding-checked).
    /// `pubkey32` is the x-only pubkey (32 bytes).
    /// `leaf_hash` is the `TapLeaf` hash for this script-path execution.
    /// `code_sep_pos` is `0xFFFF_FFFF` if no `OP_CODESEPARATOR` has run,
    /// otherwise the opcode index of the last one.
    /// `spent_amount` and `spent_spk` are the UTXO being spent.
    /// `bip341_cache` carries the per-transaction precomputed hash fields.
    /// `annex` is the annex body without its `0x50` prefix.
    ///
    /// Returns `true` iff the signature verifies.
    #[allow(clippy::too_many_arguments)]
    fn check_schnorr_sig(
        &self,
        sig: &[u8],
        pubkey32: &[u8],
        leaf_hash: &[u8; 32],
        code_sep_pos: u32,
        spent_amount: mantle::primitives::Satoshi,
        spent_spk: &[u8],
        bip341_cache: &Bip341Cache,
        annex: Option<&[u8]>,
    ) -> bool;

    /// `OP_CHECKLOCKTIMEVERIFY` — does this transaction's `nLockTime` permit
    /// spending under `locktime`?
    fn check_lock_time(&self, locktime: i64) -> bool;

    /// `OP_CHECKSEQUENCEVERIFY` — does this input's `nSequence` permit
    /// spending under `sequence`?
    fn check_sequence(&self, sequence: i64) -> bool;
}

/// Production `SignatureChecker`. Borrows the transaction being validated, the
/// input index whose script is currently executing, and the amount of the
/// spent output. The BIP143 cache is built lazily on first segwit-v0 use —
/// legacy-only inputs never pay for it.
///
/// `script_flags` is the full `ScriptFlags` for this verification call —
/// `consensus_crypto::verify_ecdsa` reads `DERSIG` / `STRICTENC` / `LOW_S`
/// from it.
#[derive(Debug)]
pub struct TxSigChecker<'a, T: TxView> {
    tx: &'a T,
    n_in: usize,
    amount: Satoshi,
    #[allow(dead_code)]
    script_flags: ScriptFlags,
    /// Lazy BIP143 shared hash fields. Empty until the first witness-v0
    /// signature check on this checker; populated in place on first use.
    /// Pre-segwit txs (the bulk of early mainnet) never allocate this.
    bip143_cache: OnceLock<Bip143Cache>,
}

impl<'a, T: TxView> TxSigChecker<'a, T> {
    /// Construct a checker for input `n_in` of `tx` with the given output
    /// amount and verification flags. The BIP143 cache is allocated lazily
    /// on first segwit-v0 signature check.
    #[must_use]
    pub fn new(tx: &'a T, n_in: usize, amount: Satoshi, script_flags: ScriptFlags) -> Self {
        Self {
            tx,
            n_in,
            amount,
            script_flags,
            bip143_cache: OnceLock::new(),
        }
    }

    /// Construct a checker, seeding the BIP143 cache from a pre-built one.
    ///
    /// Used by callers (e.g. `connect_block`) that have already paid the
    /// per-tx cost of computing `Bip143Cache::new(tx)` and want every input's
    /// checker to share that work. Equivalent to [`Self::new`] for transactions
    /// that never reach a witness-v0 input.
    #[must_use]
    pub fn with_cache(
        tx: &'a T,
        n_in: usize,
        amount: Satoshi,
        script_flags: ScriptFlags,
        bip143_cache: Bip143Cache,
    ) -> Self {
        let cell = OnceLock::new();
        // Cell is freshly created; set cannot fail.
        let _ = cell.set(bip143_cache);
        Self {
            tx,
            n_in,
            amount,
            script_flags,
            bip143_cache: cell,
        }
    }
}

impl<T: TxView> SignatureChecker for TxSigChecker<'_, T> {
    fn check_ecdsa_sig(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        script_code: &[u8],
        sig_version: SigVersion,
    ) -> bool {
        // Tapscript uses Schnorr, not ECDSA — should never reach here.
        if sig_version == SigVersion::Tapscript {
            return false;
        }

        // The signature on the wire is `<DER>||<hashtype>`. An empty signature
        // is a fail — there's no hashtype byte to read.
        let Some((&hashtype_byte, sig_der)) = sig.split_last() else {
            return false;
        };
        let hash_type = SigHashType(u32::from(hashtype_byte));

        let digest = match sig_version {
            SigVersion::Base => {
                // FindAndDelete: legacy regime removes any push of the exact
                // `sig` bytes from `script_code` before hashing.
                let cleaned_code = FindAndDelete::for_push(sig).apply(script_code);
                self.tx.legacy_sighash(self.n_in, &cleaned_code, hash_type)
            }
            SigVersion::WitnessV0 => {
                // BIP143: no FindAndDelete; script_code is already the
                // scriptCode for this input (P2WPKH synthetic or P2WSH witness
                // script), passed through unchanged. The shared cache is built
                // lazily on first witness-v0 signature check — pre-segwit txs
                // (the bulk of early mainnet) never pay for it.
                let cache = self.bip143_cache.get_or_init(|| Bip143Cache::new(self.tx));
                self.tx
                    .bip143_sighash(self.n_in, script_code, self.amount, hash_type, cache)
            }
            SigVersion::Tapscript => unreachable!(),
        };

        Ecdsa::verify(sig_der, pubkey, digest.as_bytes())
    }

    fn check_schnorr_sig(
        &self,
        sig: &[u8],
        pubkey32: &[u8],
        leaf_hash: &[u8; 32],
        code_sep_pos: u32,
        spent_amount: mantle::primitives::Satoshi,
        spent_spk: &[u8],
        bip341_cache: &Bip341Cache,
        annex: Option<&[u8]>,
    ) -> bool {
        let Ok((sig64, hash_type_byte)) = Schnorr::check_sig_encoding(sig) else {
            return false;
        };
        // Pubkey must be exactly 32 bytes.
        let Ok(pubkey_arr) = <&[u8; 32]>::try_from(pubkey32) else {
            return false;
        };

        let hash_type = TaprootSigHashType(hash_type_byte);
        if !hash_type.is_valid() || !hash_type.is_signable(self.n_in, self.tx.output_count()) {
            return false;
        }

        let digest = self.tx.bip341_sighash(
            self.n_in,
            spent_amount,
            spent_spk,
            hash_type,
            bip341_cache,
            annex,
            Some((*leaf_hash, code_sep_pos)),
        );

        Schnorr::verify(sig64, pubkey_arr, &digest)
    }

    fn check_lock_time(&self, locktime: i64) -> bool {
        if !self.tx.locktime().satisfies_cltv(locktime) {
            return false;
        }
        self.tx.input(self.n_in).sequence() != Sequence::MAX
    }

    fn check_sequence(&self, sequence: i64) -> bool {
        // BIP112: if the *stack* value has the disable flag set, CSV is a
        // NOP-pass regardless of tx version.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let script_disable = (sequence as u32) & (1 << 31) != 0;
        if script_disable {
            return true;
        }

        // BIP68 only applies to txs whose version (treated as unsigned,
        // per Core) is >= 2.
        if self.tx.version().to_u32() < 2 {
            return false;
        }

        self.tx.input(self.n_in).sequence().satisfies_csv(sequence)
    }
}

/// A `SignatureChecker` that fails every check. Useful in tests that exercise
/// the non-crypto opcode set: any path that reaches a signature operation
/// will short-circuit to `false`, which the interpreter treats as a failed
/// `CHECKSIG`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NopSigChecker;

impl SignatureChecker for NopSigChecker {
    fn check_ecdsa_sig(
        &self,
        _sig: &[u8],
        _pubkey: &[u8],
        _script_code: &[u8],
        _sig_version: SigVersion,
    ) -> bool {
        false
    }

    fn check_schnorr_sig(
        &self,
        _sig: &[u8],
        _pubkey32: &[u8],
        _leaf_hash: &[u8; 32],
        _code_sep_pos: u32,
        _spent_amount: mantle::primitives::Satoshi,
        _spent_spk: &[u8],
        _bip341_cache: &Bip341Cache,
        _annex: Option<&[u8]>,
    ) -> bool {
        false
    }

    fn check_lock_time(&self, _locktime: i64) -> bool {
        false
    }

    fn check_sequence(&self, _sequence: i64) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::{Signature as EcdsaSig, SigningKey};

    use mantle::primitives::{
        Hash256, Locktime, OutPoint, Sequence, Transaction, TxIn, TxOut, TxVersion, Witness,
    };
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};

    use crate::script::interpreter::Interpreter;
    use crate::script::sighash::{SigHashType, TxSighash};
    use crate::script::stack::Stack;

    #[test]
    fn nop_checker_rejects_everything() {
        let c = NopSigChecker;
        assert!(!c.check_ecdsa_sig(&[], &[], &[], SigVersion::Base));
        assert!(!c.check_lock_time(0));
        assert!(!c.check_sequence(0));
    }

    /// Build a deterministic signing key from a 32-byte secret. Tests stay
    /// reproducible without pulling `rand_core` into the test runtime.
    fn key(secret: [u8; 32]) -> SigningKey {
        SigningKey::from_bytes(&secret.into()).expect("nonzero secret")
    }

    /// Compressed SEC1 pubkey bytes (33 bytes).
    fn compressed_pubkey(sk: &SigningKey) -> Vec<u8> {
        sk.verifying_key().to_sec1_point(true).as_bytes().to_vec()
    }

    fn hash160(data: &[u8]) -> [u8; 20] {
        let mid = Sha256::digest(data);
        Ripemd160::digest(mid).into()
    }

    /// Build a single-input/single-output tx that spends a P2PKH output.
    /// `_pubkey_hash` is unused inside the tx body — the hash lives in the
    /// scriptPubKey, which the caller builds separately via `p2pkh_script`.
    /// The argument is kept so call sites read at the level of intent.
    fn make_tx_p2pkh(_pubkey_hash: &[u8; 20]) -> Transaction {
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
                // Arbitrary scriptPubKey for the output; not exercised by sighash here.
                script_pubkey: vec![0x6a].into(),
            }],
            locktime: Locktime::new(0),
        }
    }

    /// Standard P2PKH scriptPubKey: `OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG`.
    fn p2pkh_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(pubkey_hash);
        s.extend_from_slice(&[0x88, 0xac]);
        s
    }

    /// Sign a sighash with `sk`, returning `<DER>||<hashtype>`.
    fn sign(sk: &SigningKey, sighash: &[u8; 32], hashtype: SigHashType) -> Vec<u8> {
        let sig: EcdsaSig = sk
            .sign_prehash(sighash)
            .expect("signing a 32-byte digest cannot fail");
        let sig = sig.normalize_s(); // canonical low-S
        let mut der = sig.to_der().as_bytes().to_vec();
        der.push(u8::try_from(hashtype.0 & 0xff).expect("hashtype fits in u8"));
        der
    }

    #[test]
    fn p2pkh_end_to_end_succeeds() {
        let sk = key([7u8; 32]);
        let pk = compressed_pubkey(&sk);
        let pkh: [u8; 20] = hash160(&pk);

        let tx = make_tx_p2pkh(&pkh);
        let script_pubkey = p2pkh_script(&pkh);

        // Compute legacy sighash over the full scriptPubKey.
        let digest = tx.legacy_sighash(0, &script_pubkey, SigHashType::ALL);
        let sig = sign(&sk, digest.as_bytes(), SigHashType::ALL);

        // Build scriptSig: <sig> <pubkey>.
        let mut script_sig = vec![u8::try_from(sig.len()).expect("DER ≤ 72")];
        script_sig.extend_from_slice(&sig);
        script_sig.push(u8::try_from(pk.len()).expect("compressed ≤ 33"));
        script_sig.extend_from_slice(&pk);

        let flags = ScriptFlags::DERSIG | ScriptFlags::LOW_S | ScriptFlags::STRICTENC;
        let checker = TxSigChecker::new(&tx, 0, Satoshi::ZERO, flags);

        // Evaluate scriptSig then scriptPubKey on the same stack — what
        // verify_script will do once it lands. For now we drive the
        // Interpreter directly.
        let mut interp = Interpreter::new(&checker, flags, SigVersion::Base);
        interp.eval(&script_sig).expect("scriptSig pushes ok");
        interp.eval(&script_pubkey).expect("scriptPubKey runs ok");
        let s: &Stack = interp.stack();
        assert_eq!(s.len(), 1);
        assert!(s.peek(0).expect("non-empty").is_truthy());
    }

    #[test]
    fn p2pkh_with_wrong_pubkey_pushes_false_or_fails() {
        let sk = key([7u8; 32]);
        let attacker_sk = key([8u8; 32]);
        let pk = compressed_pubkey(&sk);
        let attacker_pubkey = compressed_pubkey(&attacker_sk);
        let pkh: [u8; 20] = hash160(&pk);

        let tx = make_tx_p2pkh(&pkh);
        let script_pubkey = p2pkh_script(&pkh);
        let digest = tx.legacy_sighash(0, &script_pubkey, SigHashType::ALL);
        let sig = sign(&sk, digest.as_bytes(), SigHashType::ALL);

        // Wrong pubkey supplied — fails at OP_EQUALVERIFY (hash mismatch).
        let mut script_sig = vec![u8::try_from(sig.len()).expect("DER ≤ 72")];
        script_sig.extend_from_slice(&sig);
        script_sig.push(u8::try_from(attacker_pubkey.len()).expect("compressed ≤ 33"));
        script_sig.extend_from_slice(&attacker_pubkey);

        let flags = ScriptFlags::DERSIG | ScriptFlags::LOW_S | ScriptFlags::STRICTENC;
        let checker = TxSigChecker::new(&tx, 0, Satoshi::ZERO, flags);
        let mut interp = Interpreter::new(&checker, flags, SigVersion::Base);
        interp.eval(&script_sig).expect("scriptSig pushes ok");
        let r = interp.eval(&script_pubkey);
        assert!(matches!(r, Err(crate::script::error::ScriptError::Verify)));
    }

    #[test]
    fn empty_signature_pushes_false() {
        let sk = key([7u8; 32]);
        let pk = compressed_pubkey(&sk);
        let pkh = hash160(&pk);

        let tx = make_tx_p2pkh(&pkh);
        let flags = ScriptFlags::DERSIG | ScriptFlags::LOW_S | ScriptFlags::STRICTENC;
        let checker = TxSigChecker::new(&tx, 0, Satoshi::ZERO, flags);

        // Direct CHECKSIG with empty sig + valid pubkey.
        let mut interp = Interpreter::new(&checker, flags, SigVersion::Base);
        // Push empty sig (OP_0) and pubkey, then CHECKSIG.
        let mut script = vec![0x00];
        script.push(u8::try_from(pk.len()).expect("len fits"));
        script.extend_from_slice(&pk);
        script.push(0xac); // OP_CHECKSIG
        interp.eval(&script).expect("ok");
        let s = interp.stack();
        assert_eq!(s.len(), 1);
        assert!(!s.peek(0).expect("non-empty").is_truthy());
    }

    #[test]
    fn nullfail_rejects_failed_nonempty_signature() {
        let sk = key([7u8; 32]);
        let other_sk = key([9u8; 32]);
        let pk = compressed_pubkey(&sk);
        let pkh = hash160(&pk);
        let tx = make_tx_p2pkh(&pkh);
        let script_pubkey = p2pkh_script(&pkh);

        // Sign with the wrong key — yields a strict-DER signature that won't verify.
        let digest = tx.legacy_sighash(0, &script_pubkey, SigHashType::ALL);
        let sig = sign(&other_sk, digest.as_bytes(), SigHashType::ALL);

        // Build scriptSig with the *correct* pubkey but wrong sig — CHECKSIG
        // returns false; without NULLFAIL the result is just a `false` push.
        let mut script_sig = vec![u8::try_from(sig.len()).expect("DER ≤ 72")];
        script_sig.extend_from_slice(&sig);
        script_sig.push(u8::try_from(pk.len()).expect("compressed ≤ 33"));
        script_sig.extend_from_slice(&pk);

        let flags = ScriptFlags::DERSIG
            | ScriptFlags::LOW_S
            | ScriptFlags::STRICTENC
            | ScriptFlags::NULLFAIL;
        let checker = TxSigChecker::new(&tx, 0, Satoshi::ZERO, flags);
        let mut interp = Interpreter::new(&checker, flags, SigVersion::Base);
        interp.eval(&script_sig).expect("scriptSig ok");
        let r = interp.eval(&script_pubkey);
        assert!(matches!(
            r,
            Err(crate::script::error::ScriptError::SigNullFail)
        ));
    }
}
