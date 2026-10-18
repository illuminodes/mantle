//! The thin wrapper around `k256` that the rest of the script interpreter
//! calls. Per `principles.md` §3 and `validation.md` §"Cryptographic concerns",
//! this module is the *only* place in Mantle that directly imports `k256`.
//!
//! Operations are grouped into two zero-sized namespaces:
//! - [`Ecdsa`] — legacy/segwit-v0 ECDSA: BIP66 strict-DER, BIP146 low-S,
//!   STRICTENC pubkey, curve-check verification.
//! - [`Schnorr`] — BIP340 Schnorr: tagged hash, x-only verify, BIP340/342
//!   wire-encoding check.
//!
//! These structs hold no state; they exist to give the call sites a single
//! `Ecdsa::verify(...)` / `Schnorr::verify(...)` shape rather than scattered
//! free functions, matching the project-wide "methods over free functions"
//! rule (`docs/architecture/script.md` §9). Both delegate to `k256` for the
//! curve work and add the consensus-encoding rules `k256` does not enforce
//! on its own.

mod ecdsa_verify;

use k256::ProjectivePoint;
use k256::ecdsa::{Signature as EcdsaSig, VerifyingKey};
use k256::schnorr::signature::hazmat::PrehashVerifier as SchnorrPrehashVerifier;
use k256::schnorr::{Signature as SchnorrSig, VerifyingKey as SchnorrVerifyingKey};
use sha2::{Digest, Sha256};

use super::error::ScriptError;
use super::flags::ScriptFlags;
use super::lax_der::LaxDer;
use ecdsa_verify::EcdsaVerifier;

/// Half the curve order, in big-endian. `s` values strictly above this are
/// rejected under `SCRIPT_VERIFY_LOW_S`. Source: BIP146 (the constant is the
/// secp256k1 group order divided by two, rounded down).
const HALF_CURVE_ORDER_BE: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// ECDSA operations for legacy and segwit-v0 sighash regimes.
///
/// Zero-sized — these are namespaced associated functions, not methods on
/// instance state. The call sites read `Ecdsa::verify(sig, pk, msg)` rather
/// than a bare `verify_ecdsa(...)` free fn so the cryptographic regime is
/// visible at every call site.
pub struct Ecdsa;

impl Ecdsa {
    /// Validate the wire encoding of a signature *under the active flags*.
    /// What BIP66 / BIP146 / STRICTENC police: shape, not curve correctness.
    ///
    /// `sig` is the full `<DER>||<sighash_byte>` blob as it appeared on the
    /// stack. An empty `sig` short-circuits `Ok(())` — the caller (CHECKSIG)
    /// treats empty signatures as a curve-check failure with no encoding
    /// check (this is what enables NULLFAIL's "must be empty if you wanted
    /// to fail").
    ///
    /// # Errors
    /// - `SigDer` if DERSIG/STRICTENC is set and the DER part fails strict-DER.
    /// - `SigHashtype` if STRICTENC is set and the hashtype byte is unknown.
    /// - `SigHighS` if `LOW_S` is set and `s > N/2`.
    pub fn check_sig_encoding(sig: &[u8], flags: ScriptFlags) -> Result<(), ScriptError> {
        if sig.is_empty() {
            return Ok(());
        }

        // Split the trailing sighash byte. With non-empty sig, we always have one.
        let (Some(&hashtype), Some(sig_der)) = (sig.last(), sig.split_last().map(|(_, body)| body))
        else {
            return Ok(());
        };

        let strict = flags.contains(ScriptFlags::DERSIG) || flags.contains(ScriptFlags::STRICTENC);
        if strict && !Self::is_valid_der_encoding(sig_der) {
            return Err(ScriptError::SigDer);
        }
        if flags.contains(ScriptFlags::LOW_S) && !Self::is_low_s(sig_der) {
            return Err(ScriptError::SigHighS);
        }
        if flags.contains(ScriptFlags::STRICTENC) && !Self::is_defined_hashtype(hashtype) {
            return Err(ScriptError::SigHashtype);
        }

        Ok(())
    }

    /// Validate the wire encoding of a pubkey under STRICTENC.
    ///
    /// Without STRICTENC, every byte string parses (`k256` is permissive
    /// within reason). With it, only 33-byte compressed (`0x02`/`0x03`) and
    /// 65-byte uncompressed (`0x04`) leads are accepted.
    ///
    /// # Errors
    /// `PubKeyType` if STRICTENC is set and the pubkey doesn't match either
    /// form.
    pub fn check_pubkey_encoding(pubkey: &[u8], flags: ScriptFlags) -> Result<(), ScriptError> {
        if flags.contains(ScriptFlags::STRICTENC) && !Self::is_compressed_or_uncompressed(pubkey) {
            return Err(ScriptError::PubKeyType);
        }
        Ok(())
    }

    /// Verify an ECDSA signature against a 32-byte sighash digest.
    ///
    /// *Curve-check only* — encoding rules are checked separately by
    /// [`Ecdsa::check_sig_encoding`] and [`Ecdsa::check_pubkey_encoding`],
    /// which the opcode handler must call before this one. An empty
    /// signature here always returns `false` (no DER body to parse).
    ///
    /// Bitcoin's *consensus* curve-check accepts both low-S and high-S
    /// signatures; the `LOW_S` rule (BIP146, activated 2016) is enforced
    /// separately by [`Ecdsa::is_low_s`] in [`Ecdsa::check_sig_encoding`].
    /// k256's `verify_prehash` rejects high-S unconditionally for secp256k1
    /// (`NORMALIZE_S = true` on the curve), so we must `normalize_s` before
    /// the curve math — otherwise legitimate pre-LOW_S signatures (every
    /// signature signed by Satoshi-era code that happened to land high)
    /// fail to verify. Mainnet block 183 contains the canonical regression.
    ///
    /// The signature is decoded with [`LaxDer`], as Core does: before BIP66
    /// non-DER encodings were valid, and mainnet block 124,276 spends one.
    #[must_use]
    pub fn verify(sig_der: &[u8], pubkey_bytes: &[u8], sighash: &[u8; 32]) -> bool {
        let Some(compact) = LaxDer::parse(sig_der) else {
            return false;
        };
        let Ok(sig) = EcdsaSig::from_slice(&compact) else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_sec1_bytes(pubkey_bytes) else {
            return false;
        };
        let (r, s) = sig.split_scalars();
        let q = ProjectivePoint::from(*vk.as_affine());
        EcdsaVerifier::verify(&q, sighash, &r, &s)
    }

    /// Hand-rolled BIP66 strict-DER validator.
    ///
    /// Behavioural mirror of Core's `IsValidSignatureEncoding` — the
    /// consensus rule is "what Core accepts", not "what is valid DER".
    /// Re-derived from BIP66 prose. Layout:
    ///
    /// ```text
    /// 0x30  total_len
    /// 0x02  r_len  r_bytes...
    /// 0x02  s_len  s_bytes...
    /// ```
    ///
    /// Length range is `8..=72` total bytes (excluding sighash byte). `r`
    /// and `s` are positive integers: leading zero only when next byte's
    /// high bit is set; no extra leading zeros otherwise; non-zero
    /// magnitude.
    #[must_use]
    pub fn is_valid_der_encoding(sig: &[u8]) -> bool {
        // Minimum: 0x30 len(1) 0x02 r_len(1) r(1) 0x02 s_len(1) s(1) = 8 bytes.
        // Maximum: 72 (signature alone, no sighash byte).
        if sig.len() < 8 || sig.len() > 72 {
            return false;
        }
        // Outer SEQUENCE tag.
        if sig[0] != 0x30 {
            return false;
        }
        // Total length excludes the leading two header bytes (tag + length).
        if usize::from(sig[1]) != sig.len() - 2 {
            return false;
        }

        // r: tag 0x02, then length, then magnitude.
        if sig[2] != 0x02 {
            return false;
        }
        let r_len = usize::from(sig[3]);
        // r occupies sig[4..4+r_len]. Need at least r_len + 2 (for s tag + s_len)
        // + 1 (for at least one s byte) bytes after sig[3].
        if r_len == 0 || 4 + r_len + 3 > sig.len() {
            return false;
        }
        let r = &sig[4..4 + r_len];

        // s: tag 0x02, then length, then magnitude.
        if sig[4 + r_len] != 0x02 {
            return false;
        }
        let s_len = usize::from(sig[5 + r_len]);
        if s_len == 0 || 6 + r_len + s_len != sig.len() {
            return false;
        }
        let s = &sig[6 + r_len..6 + r_len + s_len];

        // r and s rules: positive, minimal-encoded.
        Self::is_valid_der_integer(r) && Self::is_valid_der_integer(s)
    }

    /// Validate a single DER `INTEGER` body under BIP66.
    ///
    /// - Top bit of first byte must be 0 (i.e. positive).
    /// - No unnecessary leading 0x00 byte: only allowed when the next byte's
    ///   high bit is set (otherwise the leading zero is redundant).
    fn is_valid_der_integer(bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }
        if bytes[0] & 0x80 != 0 {
            return false;
        }
        if bytes.len() > 1 && bytes[0] == 0x00 && (bytes[1] & 0x80) == 0 {
            return false;
        }
        true
    }

    /// `s` value of the signature is below or equal to half the curve order.
    ///
    /// Returns `false` if the signature is not parseable as a strict-DER
    /// signature (already strict-checked at this point in normal flow).
    /// This helper does the BIP66-style walk again to extract `s` without
    /// going through `k256`'s parser — that lets us reject high-S without
    /// first successfully constructing an `EcdsaSig` (which would normalise
    /// it).
    #[must_use]
    fn is_low_s(sig_der: &[u8]) -> bool {
        // Extract s. Mirrors the validator above but only as far as needed.
        if sig_der.len() < 8 || sig_der[0] != 0x30 {
            return false;
        }
        if sig_der[2] != 0x02 {
            return false;
        }
        let r_len = usize::from(sig_der[3]);
        if 4 + r_len + 2 > sig_der.len() {
            return false;
        }
        if sig_der[4 + r_len] != 0x02 {
            return false;
        }
        let s_len = usize::from(sig_der[5 + r_len]);
        let s_start = 6 + r_len;
        if s_start + s_len > sig_der.len() {
            return false;
        }
        let s = &sig_der[s_start..s_start + s_len];

        // Strip the leading 0x00 sign-padding, if any. The BIP66 validator
        // forbids a redundant 0x00, but a 0x00 *is* required when the
        // magnitude's high bit is set, and we want to compare magnitude to
        // N/2.
        let s_mag: &[u8] = if !s.is_empty() && s[0] == 0x00 {
            &s[1..]
        } else {
            s
        };

        // Right-align into a 32-byte buffer for big-endian comparison.
        // Anything longer than 32 bytes can't be ≤ N/2 (which is 256 bits).
        if s_mag.len() > 32 {
            return false;
        }
        let mut s_be = [0u8; 32];
        s_be[32 - s_mag.len()..].copy_from_slice(s_mag);
        s_be <= HALF_CURVE_ORDER_BE
    }

    /// `true` iff `byte` is a recognised hashtype value under STRICTENC.
    /// The set is `SIGHASH_ALL | NONE | SINGLE` optionally OR'd with
    /// `ANYONECANPAY`.
    #[must_use]
    fn is_defined_hashtype(byte: u8) -> bool {
        let masked = byte & !0x80; // strip ANYONECANPAY bit
        matches!(masked, 1..=3)
    }

    /// Pubkey is one of the two strict encodings: 33-byte compressed (`0x02`
    /// or `0x03` lead) or 65-byte uncompressed (`0x04` lead). Hybrid 65-byte
    /// encodings (`0x06`/`0x07` lead) are excluded under `STRICTENC`.
    #[must_use]
    fn is_compressed_or_uncompressed(pubkey: &[u8]) -> bool {
        match pubkey.first().copied() {
            Some(0x02 | 0x03) => pubkey.len() == 33,
            Some(0x04) => pubkey.len() == 65,
            _ => false,
        }
    }
}

/// BIP340 Schnorr operations: x-only pubkeys, 64/65-byte sigs, tagged hashes.
///
/// Zero-sized — see [`Ecdsa`] for the rationale. `tagged_hash` lives here
/// because BIP340 is where it is specified, even though both BIP340 (sigs)
/// and BIP341 (sighash, taproot tweak) consume it.
pub struct Schnorr;

impl Schnorr {
    /// Validate the wire encoding of a Schnorr signature *and* return the
    /// optional hash-type byte for the 65-byte form.
    ///
    /// BIP340/342 wire format:
    /// - 64 bytes → `SIGHASH_DEFAULT` (all), no hash-type byte.
    /// - 65 bytes → explicit hash-type byte at the end; must not be 0x00
    ///   (0x00 is reserved for `SIGHASH_DEFAULT` in the 64-byte form and is
    ///   disallowed in the 65-byte form per BIP342).
    ///
    /// Any other length is `SchnorrSigSize`. An explicit hash-type byte of
    /// 0x00 is `SchnorrSigHashType`.
    ///
    /// Returns `(sig_bytes_64, hash_type_u8)` where `hash_type_u8` is `0x00`
    /// (the default-sighash sentinel) when the 64-byte form is used.
    ///
    /// # Errors
    /// `SchnorrSigSize` or `SchnorrSigHashType`.
    pub fn check_sig_encoding(sig: &[u8]) -> Result<(&[u8], u8), ScriptError> {
        match sig.len() {
            64 => Ok((sig, 0x00)), // 64-byte sig → SIGHASH_DEFAULT (BIP341)
            65 => {
                let hash_type = sig[64];
                if hash_type == 0x00 {
                    return Err(ScriptError::SchnorrSigHashType);
                }
                Ok((&sig[..64], hash_type))
            }
            _ => Err(ScriptError::SchnorrSigSize),
        }
    }

    /// BIP340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
    ///
    /// The tag is hashed twice and prepended so that hash outputs in
    /// different protocol contexts are domain-separated even if they share
    /// the same message bytes.
    #[must_use]
    pub fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
        let tag_hash = Sha256::digest(tag);
        let mut h = Sha256::new();
        h.update(tag_hash);
        h.update(tag_hash);
        h.update(msg);
        h.finalize().into()
    }

    /// Verify a BIP340 Schnorr signature.
    ///
    /// `sig64` must be exactly 64 bytes (the caller has already validated
    /// length via [`Schnorr::check_sig_encoding`]). `pubkey32` is the x-only
    /// pubkey (32 bytes). `msg` is the 32-byte sighash digest.
    ///
    /// Returns `true` iff the signature verifies.
    #[must_use]
    pub fn verify(sig64: &[u8], pubkey32: &[u8], msg: &[u8; 32]) -> bool {
        let Ok(sig) = SchnorrSig::try_from(sig64) else {
            return false;
        };
        let Ok(pubkey32) = pubkey32.try_into() else {
            return false;
        };
        let Ok(vk) = SchnorrVerifyingKey::from_bytes(pubkey32) else {
            return false;
        };
        SchnorrPrehashVerifier::verify_prehash(&vk, msg, &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Strict-DER ──────────────────────────────────────────────────────────

    #[test]
    fn der_minimum_valid() {
        // SEQUENCE { INTEGER 1, INTEGER 1 }
        let sig = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        assert!(Ecdsa::is_valid_der_encoding(&sig));
    }

    #[test]
    fn der_too_short() {
        assert!(!Ecdsa::is_valid_der_encoding(&[0x30, 0x05]));
    }

    #[test]
    fn der_too_long() {
        let sig = [0u8; 73];
        assert!(!Ecdsa::is_valid_der_encoding(&sig));
    }

    #[test]
    fn der_wrong_outer_tag() {
        let sig = [0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        assert!(!Ecdsa::is_valid_der_encoding(&sig));
    }

    #[test]
    fn der_wrong_total_length() {
        // total length byte claims 5 but actual body is 6
        let sig = [0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        assert!(!Ecdsa::is_valid_der_encoding(&sig));
    }

    #[test]
    fn der_r_with_leading_zero_not_needed() {
        // r = 00 01 — leading zero is redundant since 0x01's high bit is clear.
        let sig = [0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01];
        assert!(!Ecdsa::is_valid_der_encoding(&sig));
    }

    #[test]
    fn der_r_with_required_leading_zero() {
        // r = 00 80 — high bit set, leading zero required to keep r positive.
        let sig = [0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01];
        assert!(Ecdsa::is_valid_der_encoding(&sig));
    }

    #[test]
    fn der_negative_r() {
        // r high bit set without leading zero — would parse as negative.
        let sig = [0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01];
        assert!(!Ecdsa::is_valid_der_encoding(&sig));
    }

    #[test]
    fn der_zero_r_length() {
        let sig = [0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01];
        assert!(!Ecdsa::is_valid_der_encoding(&sig));
    }

    // ── Low-S ───────────────────────────────────────────────────────────────

    #[test]
    fn low_s_accepts_small_s() {
        // r = 1, s = 1 — well under N/2.
        let sig = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        assert!(Ecdsa::is_low_s(&sig));
    }

    #[test]
    fn low_s_rejects_above_half_order() {
        // s = N/2 + 1 (high bit set, requires leading zero pad).
        let mut s_be = HALF_CURVE_ORDER_BE;
        s_be[31] += 1;
        let mut sig = vec![0x30, 0x00, 0x02, 0x01, 0x01, 0x02, 33, 0x00];
        sig.extend_from_slice(&s_be);
        sig[1] = u8::try_from(sig.len() - 2).expect("len fits");
        assert!(!Ecdsa::is_low_s(&sig));
    }

    #[test]
    fn low_s_accepts_exactly_half_order() {
        // Exactly N/2 — high bit set, requires leading zero pad.
        let mut sig = vec![0x30, 0x00, 0x02, 0x01, 0x01, 0x02, 33, 0x00];
        sig.extend_from_slice(&HALF_CURVE_ORDER_BE);
        sig[1] = u8::try_from(sig.len() - 2).expect("len fits");
        assert!(Ecdsa::is_low_s(&sig));
    }

    // ── Pubkey encoding ─────────────────────────────────────────────────────

    #[test]
    fn pubkey_compressed_accepted() {
        let mut pk = [0u8; 33];
        pk[0] = 0x02;
        assert!(Ecdsa::is_compressed_or_uncompressed(&pk));
        pk[0] = 0x03;
        assert!(Ecdsa::is_compressed_or_uncompressed(&pk));
    }

    #[test]
    fn pubkey_uncompressed_accepted() {
        let mut pk = [0u8; 65];
        pk[0] = 0x04;
        assert!(Ecdsa::is_compressed_or_uncompressed(&pk));
    }

    #[test]
    fn pubkey_hybrid_rejected_under_strictenc() {
        let mut pk = [0u8; 65];
        pk[0] = 0x06;
        assert!(!Ecdsa::is_compressed_or_uncompressed(&pk));
        pk[0] = 0x07;
        assert!(!Ecdsa::is_compressed_or_uncompressed(&pk));
    }

    #[test]
    fn pubkey_wrong_length_rejected() {
        let pk = [0x02u8; 32]; // compressed lead, wrong length
        assert!(!Ecdsa::is_compressed_or_uncompressed(&pk));
        let pk = [0x04u8; 64]; // uncompressed lead, wrong length
        assert!(!Ecdsa::is_compressed_or_uncompressed(&pk));
    }

    // ── DER edge cases for is_valid_der_encoding ──────────────────────────

    #[test]
    fn der_s_with_zero_length() {
        // s_len = 0 → should be rejected (we need at least one s byte).
        let sig = [0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x00];
        assert!(!Ecdsa::is_valid_der_encoding(&sig));
    }

    #[test]
    fn der_s_with_leading_zero_not_needed() {
        // s = 00 01 — leading zero is redundant since 0x01's high bit is clear.
        let sig = [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x01];
        assert!(!Ecdsa::is_valid_der_encoding(&sig));
    }

    #[test]
    fn der_s_negative() {
        // s = 0x80 — high bit set without leading zero → negative → invalid.
        let sig = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x80];
        assert!(!Ecdsa::is_valid_der_encoding(&sig));
    }

    #[test]
    fn der_s_with_required_leading_zero() {
        // s = 00 80 — high bit set, leading zero required to keep s positive.
        let sig = [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80];
        assert!(Ecdsa::is_valid_der_encoding(&sig));
    }

    #[test]
    fn der_wrong_r_tag() {
        // R tag is 0x03 instead of 0x02.
        let sig = [0x30, 0x06, 0x03, 0x01, 0x01, 0x02, 0x01, 0x01];
        assert!(!Ecdsa::is_valid_der_encoding(&sig));
    }

    #[test]
    fn der_wrong_s_tag() {
        // S tag is 0x03 instead of 0x02.
        let sig = [0x30, 0x06, 0x02, 0x01, 0x01, 0x03, 0x01, 0x01];
        assert!(!Ecdsa::is_valid_der_encoding(&sig));
    }

    #[test]
    fn der_r_len_too_large() {
        // r_len claims bytes that overflow into where s should be.
        // sig = [0x30, 0x06, 0x02, 0x04, 0x01, 0x01, 0x01, 0x01]
        // r_len=4, so r occupies sig[4..8], leaving no room for s header + s.
        let sig = [0x30, 0x06, 0x02, 0x04, 0x01, 0x01, 0x01, 0x01];
        assert!(!Ecdsa::is_valid_der_encoding(&sig));
    }

    #[test]
    fn der_s_len_wrong_total() {
        // s_len doesn't make total match: 6 + r_len + s_len != sig.len()
        // r_len=1, s_len=2, but only 1 byte of s data → total mismatch.
        let sig = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x02, 0x01];
        assert!(!Ecdsa::is_valid_der_encoding(&sig));
    }
}
