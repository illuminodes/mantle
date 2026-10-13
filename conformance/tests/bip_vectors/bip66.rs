// ── BIP66: strict-DER signature encoding ─────────────────────────────────────
//
// BIP66 narrowed the legacy ECDSA signature encoding to canonical DER. The
// vectors below cover both sides of that line:
//
// - **Accept** vectors are canonical DER: outer `SEQUENCE`, two unsigned
//   `INTEGER` bodies, no superfluous leading zeros, no negative values.
// - **Reject** vectors are the forms that *did* parse on pre-BIP66 nodes
//   (libsecp256k1's lenient parser) but are now consensus-invalid.
//
// We exercise `Ecdsa::is_valid_der_encoding` — the behavioural mirror of
// Core's `IsValidSignatureEncoding`. Both arms include a brief description
// so failures point at the rule under test.
//
// Note: these are signature *bodies*, not `<DER>||<sighash>` blobs — the
// trailing sighash byte is split off by `TxSigChecker` before this validator
// runs. Vector lengths are 8..=72 (the post-split body range).

use mantle_consensus::script::consensus_crypto::Ecdsa;

/// Smallest possible canonical DER signature: `r=1, s=1`.
/// `30 06 02 01 01 02 01 01`.
fn minimal_canonical() -> Vec<u8> {
    vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]
}

/// `r` with high bit set, requiring a leading 0x00 sign byte.
/// `30 07 02 02 00 80 02 01 01`.
fn r_with_required_zero_pad() -> Vec<u8> {
    vec![0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01]
}

/// 32-byte `r` and `s` — typical real signature shape.
/// `30 44 02 20 <32 bytes> 02 20 <32 bytes>`.
fn full_size_canonical() -> Vec<u8> {
    let mut v = vec![0x30, 0x44, 0x02, 0x20];
    v.extend_from_slice(&[0x7f; 32]); // top bit clear → no padding needed
    v.push(0x02);
    v.push(0x20);
    v.extend_from_slice(&[0x7f; 32]);
    v
}

#[test]
fn accept_minimal() {
    assert!(Ecdsa::is_valid_der_encoding(&minimal_canonical()));
}

#[test]
fn accept_r_with_required_leading_zero() {
    assert!(Ecdsa::is_valid_der_encoding(&r_with_required_zero_pad()));
}

#[test]
fn accept_full_size() {
    assert!(Ecdsa::is_valid_der_encoding(&full_size_canonical()));
}

#[test]
fn accept_72_byte_max() {
    // 72-byte total: SEQUENCE (2) + r INTEGER (35: tag+len+33 bytes with
    // leading 0x00) + s INTEGER (35: same shape).
    let mut v = vec![0x30, 0x46, 0x02, 0x21, 0x00];
    v.extend_from_slice(&[0xff; 32]); // 33-byte r magnitude with leading 0
    v.push(0x02);
    v.push(0x21);
    v.push(0x00);
    v.extend_from_slice(&[0xff; 32]);
    assert_eq!(v.len(), 72);
    assert!(Ecdsa::is_valid_der_encoding(&v));
}

// ── Reject vectors ───────────────────────────────────────────────────────

#[test]
fn reject_too_short() {
    // 7 bytes — under the 8-byte minimum.
    assert!(!Ecdsa::is_valid_der_encoding(&[
        0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x00
    ]));
}

#[test]
fn reject_too_long() {
    // 73 bytes — over the 72-byte maximum.
    let v = vec![0u8; 73];
    assert!(!Ecdsa::is_valid_der_encoding(&v));
}

#[test]
fn reject_wrong_outer_tag() {
    // Outer tag must be 0x30 (SEQUENCE).
    let mut v = minimal_canonical();
    v[0] = 0x31;
    assert!(!Ecdsa::is_valid_der_encoding(&v));
}

#[test]
fn reject_total_length_mismatch() {
    // Total-length byte claims 5 but body is 6.
    assert!(!Ecdsa::is_valid_der_encoding(&[
        0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
    ]));
}

#[test]
fn reject_r_not_integer_tag() {
    let mut v = minimal_canonical();
    v[2] = 0x03; // BIT STRING instead of INTEGER
    assert!(!Ecdsa::is_valid_der_encoding(&v));
}

#[test]
fn reject_r_zero_length() {
    // r length 0 — empty INTEGER bodies aren't valid magnitude encodings.
    assert!(!Ecdsa::is_valid_der_encoding(&[
        0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01,
    ]));
}

#[test]
fn reject_r_negative() {
    // r high bit set without a leading 0x00 → reads as negative.
    assert!(!Ecdsa::is_valid_der_encoding(&[
        0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01,
    ]));
}

#[test]
fn reject_r_redundant_leading_zero() {
    // r = 00 01 — leading zero is redundant since 0x01's high bit is clear.
    assert!(!Ecdsa::is_valid_der_encoding(&[
        0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01,
    ]));
}

#[test]
fn reject_s_not_integer_tag() {
    // r is fine; s tag is 0x03 instead of 0x02.
    assert!(!Ecdsa::is_valid_der_encoding(&[
        0x30, 0x06, 0x02, 0x01, 0x01, 0x03, 0x01, 0x01,
    ]));
}

#[test]
fn reject_s_zero_length() {
    assert!(!Ecdsa::is_valid_der_encoding(&[
        0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x00,
    ]));
}

#[test]
fn reject_s_negative() {
    assert!(!Ecdsa::is_valid_der_encoding(&[
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x80,
    ]));
}

#[test]
fn reject_s_redundant_leading_zero() {
    assert!(!Ecdsa::is_valid_der_encoding(&[
        0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x01,
    ]));
}

#[test]
fn reject_truncated_after_r_length_byte() {
    // r tag + r len byte but no body and no s.
    assert!(!Ecdsa::is_valid_der_encoding(&[0x30, 0x02, 0x02, 0x01,]));
}

#[test]
fn reject_trailing_garbage() {
    // Canonical signature with one extra byte appended — total length
    // byte no longer matches actual body length.
    let mut v = minimal_canonical();
    v.push(0xff);
    assert!(!Ecdsa::is_valid_der_encoding(&v));
}
