//! Hashing and signature opcodes.
//!
//! Hash opcodes — `OP_RIPEMD160`, `OP_SHA1`, `OP_SHA256`, `OP_HASH160`,
//! `OP_HASH256` — pop one byte string and push its digest.
//!
//! Signature opcodes — `OP_CHECKSIG`, `OP_CHECKSIGVERIFY`,
//! `OP_CHECKMULTISIG`, `OP_CHECKMULTISIGVERIFY`, `OP_CODESEPARATOR` — call
//! the `SignatureChecker` trait with the scriptCode sliced from
//! `last_codeseparator` and the legacy sighash regime.

use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::script::checker::SignatureChecker;
use crate::script::consensus_crypto::Ecdsa;
use crate::script::error::ScriptError;
use crate::script::flags::ScriptFlags;
use crate::script::sig_version::SigVersion;
use crate::script::sighash::{FindAndDelete, script_code_after_codeseparator};

use super::Interpreter;

/// `OP_CHECKMULTISIG`'s pubkey count limit (consensus): 20.
const MAX_PUBKEYS_PER_MULTISIG: i64 = 20;

impl<C: SignatureChecker> Interpreter<'_, C> {
    /// Pop the top, hash it with `H`, push the digest.
    ///
    /// The digest goes through `push_checked(&[u8], …)` which copies into an
    /// inline `StackElement` slot — no `Vec` allocation. SHA-256 / SHA-1 /
    /// RIPEMD-160 outputs (32, 20, 20 bytes) all fit in the default 32-byte
    /// inline cap.
    fn hash_top<H: Digest>(&mut self) -> Result<(), ScriptError> {
        let top = self.stack.pop()?;
        let digest = H::digest(top.as_slice());
        self.stack
            .push_checked(digest.as_slice(), self.altstack.len())
    }

    pub(super) fn op_ripemd160(&mut self) -> Result<(), ScriptError> {
        self.hash_top::<Ripemd160>()
    }

    pub(super) fn op_sha1(&mut self) -> Result<(), ScriptError> {
        self.hash_top::<Sha1>()
    }

    pub(super) fn op_sha256(&mut self) -> Result<(), ScriptError> {
        self.hash_top::<Sha256>()
    }

    /// `OP_HASH160` = `RIPEMD160(SHA256(top))`.
    pub(super) fn op_hash160(&mut self) -> Result<(), ScriptError> {
        let top = self.stack.pop()?;
        let inner = Sha256::digest(top.as_slice());
        let outer = Ripemd160::digest(inner);
        self.stack
            .push_checked(outer.as_slice(), self.altstack.len())
    }

    /// `OP_HASH256` = `SHA256(SHA256(top))`. Reuses `mantle::hash::sha256d`.
    pub(super) fn op_hash256(&mut self) -> Result<(), ScriptError> {
        let top = self.stack.pop()?;
        let digest = mantle::hash::Hash256::hash(top.as_slice());
        self.stack
            .push_checked(digest.as_ref(), self.altstack.len())
    }

    /// `OP_CODESEPARATOR`. Records the byte offset of the *next* opcode as
    /// the new `last_codeseparator`. All subsequent `OP_CHECKSIG` calls
    /// within this script slice scriptCode to start from there.
    ///
    /// `pos_after` is the cursor position immediately after this opcode —
    /// i.e. the byte index of the first byte of scriptCode for the next
    /// CHECKSIG.
    #[allow(clippy::unnecessary_wraps)] // dispatch shape
    pub(super) fn op_code_separator(&mut self, pos_after: usize) -> Result<(), ScriptError> {
        self.last_codeseparator = pos_after;
        Ok(())
    }

    /// `OP_CHECKSIG` (and `OP_CHECKSIGVERIFY` when `verify` is `true`).
    ///
    /// In legacy and segwit-v0 regimes: pops `pubkey`, then `sig`, computes
    /// the scriptCode from `last_codeseparator`, and calls
    /// `SignatureChecker::check_ecdsa_sig`.
    ///
    /// In tapscript (BIP342): uses Schnorr verification via
    /// `SignatureChecker::check_schnorr_sig`. An empty sig is a clean failure
    /// (pushes false); unknown pubkey type (not 32 bytes) is a NOP (push false,
    /// no error). Under `NULLFAIL`, a non-empty sig that fails is an error.
    pub(super) fn op_check_sig(&mut self, script: &[u8], verify: bool) -> Result<(), ScriptError> {
        use crate::script::sig_version::SigVersion;

        let pubkey = self.stack.pop()?;
        let sig = self.stack.pop()?;

        let ok = if self.sig_version == SigVersion::Tapscript {
            // BIP342: OP_CHECKSIG uses Schnorr over x-only pubkeys.
            // Unknown pubkey type (not 32 bytes) → NOP (push false, no error).
            if pubkey.as_slice().len() != 32 {
                self.stack.push_bool(false, self.altstack.len())?;
                return Ok(());
            }
            // Empty sig → clean failure (not a NULLFAIL error).
            if sig.is_empty() {
                self.stack.push_bool(false, self.altstack.len())?;
                return Ok(());
            }
            let Some(ctx) = &self.tapscript else {
                return Err(ScriptError::BadOpcode);
            };
            let leaf_hash = ctx.leaf_hash;
            let code_sep_pos = u32::try_from(self.last_codeseparator).unwrap_or(0xffff_ffff);
            let spent_amount = ctx.spent_amount;
            let spent_spk = ctx.spent_spk.clone();
            let bip341_cache = ctx.bip341_cache.clone();
            let ok = self.checker.check_schnorr_sig(
                sig.as_slice(),
                pubkey.as_slice(),
                &leaf_hash,
                code_sep_pos,
                spent_amount,
                &spent_spk,
                &bip341_cache,
            );
            if !ok && self.flags.contains(ScriptFlags::NULLFAIL) {
                return Err(ScriptError::SigNullFail);
            }
            ok
        } else {
            // Legacy / segwit-v0: ECDSA path.
            Ecdsa::check_sig_encoding(sig.as_slice(), self.flags)?;
            Ecdsa::check_pubkey_encoding(pubkey.as_slice(), self.flags)?;

            // usize::MAX is the sentinel for "no OP_CODESEPARATOR seen" → use the whole script (pos=0).
            let codesep = if self.last_codeseparator == usize::MAX {
                0
            } else {
                self.last_codeseparator
            };
            let script_code = script_code_after_codeseparator(script, codesep);
            let ok = self.checker.check_ecdsa_sig(
                sig.as_slice(),
                pubkey.as_slice(),
                script_code,
                self.sig_version,
            );
            if !ok && self.flags.contains(ScriptFlags::NULLFAIL) && !sig.is_empty() {
                return Err(ScriptError::SigNullFail);
            }
            ok
        };

        if verify {
            if ok { Ok(()) } else { Err(ScriptError::Verify) }
        } else {
            self.stack.push_bool(ok, self.altstack.len())
        }
    }

    /// `OP_CHECKSIGADD` — BIP342 tapscript only.
    ///
    /// Stack on entry (top to bottom): `pubkey`, `n`, `sig`.
    /// - If `pubkey` is empty, push `n` unchanged (unknown pubkey type = NOP).
    /// - If `sig` is empty, push `n` unchanged (no signature = count stays).
    /// - Otherwise verify the Schnorr signature and push `n + 1` on success,
    ///   `n` on failure. Under `NULLFAIL`, a non-empty sig that fails is an error.
    pub(super) fn op_check_sig_add(&mut self, _script: &[u8]) -> Result<(), ScriptError> {
        use crate::script::num::ScriptNum;

        let pubkey = self.stack.pop()?;
        let n_elem = self.stack.pop()?;
        let sig = self.stack.pop()?;

        let n = ScriptNum::from_bytes(
            n_elem.as_slice(),
            crate::script::num::MAX_NUM_SIZE_ARITHMETIC,
            self.flags.contains(ScriptFlags::MINIMALDATA),
        )?
        .to_i64();

        // Unknown pubkey type (empty) — push n unchanged. BIP342 §"Rules".
        if pubkey.is_empty() {
            return self.stack.push_num(n, self.altstack.len());
        }

        // Pubkey must be 32 bytes (x-only).
        if pubkey.as_slice().len() != 32 {
            return Err(ScriptError::XOnlyPubkeySize);
        }

        // Empty sig → no contribution, push n unchanged.
        if sig.is_empty() {
            return self.stack.push_num(n, self.altstack.len());
        }

        // Verify the Schnorr signature using the tapscript context.
        let Some(ctx) = &self.tapscript else {
            // Should not be reachable — tapscript context must be set.
            return Err(ScriptError::BadOpcode);
        };
        let leaf_hash = ctx.leaf_hash;
        let code_sep_pos = u32::try_from(self.last_codeseparator).unwrap_or(0xffff_ffff);
        let spent_amount = ctx.spent_amount;
        let spent_spk = ctx.spent_spk.clone();
        let bip341_cache = ctx.bip341_cache.clone();

        let ok = self.checker.check_schnorr_sig(
            sig.as_slice(),
            pubkey.as_slice(),
            &leaf_hash,
            code_sep_pos,
            spent_amount,
            &spent_spk,
            &bip341_cache,
        );

        if !ok && self.flags.contains(ScriptFlags::NULLFAIL) {
            return Err(ScriptError::TaprootChecksigAdd);
        }

        let new_n = if ok { n.saturating_add(1) } else { n };
        self.stack.push_num(new_n, self.altstack.len())
    }

    /// `OP_CHECKMULTISIG` (and `OP_CHECKMULTISIGVERIFY` when `verify`).
    ///
    /// Stack on entry (top to bottom):
    /// `n_pubkeys, pk_n, pk_{n-1}, …, pk_1, n_sigs, sig_m, sig_{m-1}, …, sig_1, dummy`
    ///
    /// Reproduces the **off-by-one dummy bug**: the `dummy` element exists
    /// because Core's original implementation popped one more item than it
    /// should. `NULLDUMMY` makes that dummy required to be the empty push.
    ///
    /// Signatures must match in order against pubkeys; pubkeys may be
    /// skipped, signatures may not.
    pub(super) fn op_check_multi_sig(
        &mut self,
        script: &[u8],
        verify: bool,
    ) -> Result<(), ScriptError> {
        let n_pubkeys_i = self
            .stack
            .pop_num(4, self.flags.contains(ScriptFlags::MINIMALDATA))?;
        if !(0..=MAX_PUBKEYS_PER_MULTISIG).contains(&n_pubkeys_i) {
            return Err(ScriptError::PubKeyCount);
        }
        let n_pubkeys = usize::try_from(n_pubkeys_i).map_err(|_| ScriptError::PubKeyCount)?;

        // Pubkey ops *do* count against the 201 op limit. Bump it by n_pubkeys
        // (the CHECKMULTISIG opcode itself was already counted by the dispatch).
        self.op_count = self
            .op_count
            .checked_add(u32::try_from(n_pubkeys).unwrap_or(u32::MAX))
            .ok_or(ScriptError::OpCount)?;
        if self.op_count > super::MAX_OPS_PER_SCRIPT {
            return Err(ScriptError::OpCount);
        }

        // Pop pubkeys.
        let mut pubkeys = Vec::with_capacity(n_pubkeys);
        for _ in 0..n_pubkeys {
            pubkeys.push(self.stack.pop()?);
        }

        let n_sigs_i = self
            .stack
            .pop_num(4, self.flags.contains(ScriptFlags::MINIMALDATA))?;
        if n_sigs_i < 0 || n_sigs_i > n_pubkeys_i {
            return Err(ScriptError::SigCount);
        }
        let n_sigs = usize::try_from(n_sigs_i).map_err(|_| ScriptError::SigCount)?;

        // Pop signatures.
        let mut sigs = Vec::with_capacity(n_sigs);
        for _ in 0..n_sigs {
            sigs.push(self.stack.pop()?);
        }

        // Pop the dummy element. Under NULLDUMMY it must be the empty push.
        let dummy = self.stack.pop()?;
        if self.flags.contains(ScriptFlags::NULLDUMMY) && !dummy.is_empty() {
            return Err(ScriptError::SigNullDummy);
        }

        // Encoding checks for every sig and pubkey, applied up-front.
        // Empty sigs short-circuit `Ok(())` so this doesn't reject the
        // common "skipped slot" case in n-of-m multisigs.
        for s in &sigs {
            Ecdsa::check_sig_encoding(s.as_slice(), self.flags)?;
        }
        for p in &pubkeys {
            Ecdsa::check_pubkey_encoding(p.as_slice(), self.flags)?;
        }

        // Walk sigs and pubkeys in parallel. Signatures must match in order
        // against pubkeys; pubkeys may be skipped. The pops above placed the
        // topmost item at index 0 — i.e. *last* in script order — so we
        // iterate from the back to recover original push order.
        let codesep = if self.last_codeseparator == usize::MAX {
            0
        } else {
            self.last_codeseparator
        };
        let mut script_code =
            std::borrow::Cow::Borrowed(script_code_after_codeseparator(script, codesep));
        if self.sig_version == SigVersion::Base {
            for s in &sigs {
                if let std::borrow::Cow::Owned(cleaned) =
                    FindAndDelete::for_push(s.as_slice()).apply(&script_code)
                {
                    script_code = std::borrow::Cow::Owned(cleaned);
                }
            }
        }
        let mut sig_idx = 0;
        let mut pk_idx = 0;
        let mut ok = true;
        while sig_idx < n_sigs {
            // If we have more sigs to verify than pubkeys remaining, fail.
            if n_sigs - sig_idx > n_pubkeys - pk_idx {
                ok = false;
                break;
            }
            let sig = sigs[n_sigs - 1 - sig_idx].as_slice();
            let pubkey = pubkeys[n_pubkeys - 1 - pk_idx].as_slice();
            if self
                .checker
                .check_ecdsa_sig(sig, pubkey, &script_code, self.sig_version)
            {
                sig_idx += 1;
            }
            pk_idx += 1;
        }

        // NULLFAIL: every signature must be empty if the multisig overall
        // failed. This is stricter than NULLFAIL on single CHECKSIG: any
        // non-empty sig at all requires success.
        if !ok && self.flags.contains(ScriptFlags::NULLFAIL) {
            for s in &sigs {
                if !s.is_empty() {
                    return Err(ScriptError::SigNullFail);
                }
            }
        }

        if verify {
            if ok { Ok(()) } else { Err(ScriptError::Verify) }
        } else {
            self.stack.push_bool(ok, self.altstack.len())
        }
    }

    /// `OP_CHECKLOCKTIMEVERIFY` (BIP65).
    ///
    /// Peek (don't pop) the top of stack as a 5-byte `ScriptNum`. Reject
    /// negative values. Then call `SignatureChecker::check_lock_time`,
    /// which compares against the tx's `nLockTime` per BIP65 rules.
    ///
    /// The script value remains on the stack — CLTV is a peek-and-verify
    /// operation, not a pop.
    pub(super) fn op_check_lock_time_verify(&mut self) -> Result<(), ScriptError> {
        // Peek the top — CLTV doesn't consume the operand.
        let top = self.stack.peek(0)?;
        let locktime = crate::script::num::ScriptNum::from_bytes(
            top.as_slice(),
            crate::script::num::MAX_NUM_SIZE_CLTV,
            self.flags
                .contains(crate::script::flags::ScriptFlags::MINIMALDATA),
        )?
        .to_i64();
        if locktime < 0 {
            return Err(ScriptError::NegativeLocktime);
        }
        if !self.checker.check_lock_time(locktime) {
            return Err(ScriptError::UnsatisfiedLocktime);
        }
        Ok(())
    }

    /// `OP_CHECKSEQUENCEVERIFY` (BIP112).
    ///
    /// Same shape as CLTV — peek, range-check, delegate to the checker.
    pub(super) fn op_check_sequence_verify(&mut self) -> Result<(), ScriptError> {
        let top = self.stack.peek(0)?;
        let sequence = crate::script::num::ScriptNum::from_bytes(
            top.as_slice(),
            crate::script::num::MAX_NUM_SIZE_CLTV,
            self.flags
                .contains(crate::script::flags::ScriptFlags::MINIMALDATA),
        )?
        .to_i64();
        if sequence < 0 {
            return Err(ScriptError::NegativeLocktime);
        }
        // BIP112: high-bit-set means the opcode is inert (forward-compat).
        // The trait-level checker handles that, so we don't filter here.
        if !self.checker.check_sequence(sequence) {
            return Err(ScriptError::UnsatisfiedLocktime);
        }
        Ok(())
    }
}
