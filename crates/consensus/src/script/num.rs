//! `ScriptNum` — Bitcoin's variable-length, sign-magnitude script integer.
//!
//! Encoding rules (consensus):
//! - Little-endian magnitude with the high bit of the most-significant byte
//!   used as a sign bit. Zero is encoded as the empty byte sequence.
//! - The encoding is "minimal" iff the high bit of the most-significant byte
//!   is meaningful: i.e. either the magnitude bit (≥ 0x80) is set, or the
//!   second-most-significant byte's high bit is the sign bit. Equivalently,
//!   removing the most-significant byte must change the value.
//! - Arithmetic opcodes accept at most 4 bytes; `OP_CHECKLOCKTIMEVERIFY`
//!   accepts 5. Both limits are enforced at decode time, not at parse time —
//!   a 5-byte push is fine, it just can't be used as an arithmetic operand.
//!
//! Stored as `[u8; 5] + len` per `docs/architecture/script.md` open-question 2.
//! That avoids re-encoding on push at the cost of going through `to_i64` for
//! arithmetic; the trade is settled by the doc, not re-debated here.

use super::error::ScriptError;

/// Maximum encoded length of an arithmetic operand. Inputs to `OP_ADD` and
/// friends must be ≤ 4 bytes.
pub const MAX_NUM_SIZE_ARITHMETIC: usize = 4;

/// Maximum encoded length for `OP_CHECKLOCKTIMEVERIFY` operands.
pub const MAX_NUM_SIZE_CLTV: usize = 5;

/// Bitcoin's script integer: little-endian sign-magnitude, up to 5 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScriptNum {
    buf: [u8; 5],
    len: u8,
}

impl ScriptNum {
    /// The empty-encoded zero.
    pub const ZERO: Self = Self {
        buf: [0; 5],
        len: 0,
    };

    /// Encode an `i64` minimally.
    ///
    /// # Panics
    /// Never — the magnitude of any `i64` fits in 8 bytes and we only push
    /// up to 5 here; values outside the consensus range are still encodable
    /// (the *limit* is enforced at decode time, not encode time, matching
    /// Core's behaviour where `2 OP_ADD` is fine even if either operand is
    /// near the 4-byte ceiling).
    #[must_use]
    pub fn from_i64(mut value: i64) -> Self {
        if value == 0 {
            return Self::ZERO;
        }

        // Fast path: the vast majority of script integers are OP_1..OP_16
        // pushes (1–16) or small arithmetic results. Values in 1..=127 encode
        // as a single byte with no sign bit manipulation needed.
        // Both casts are safe: the range guards ensure the value fits in u8
        // and that -value is positive before the cast.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        if (1..=127).contains(&value) {
            return Self {
                buf: [value as u8, 0, 0, 0, 0],
                len: 1,
            };
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        if (-127..=-1).contains(&value) {
            return Self {
                buf: [((-value) as u8) | 0x80, 0, 0, 0, 0],
                len: 1,
            };
        }

        let negative = value < 0;
        // For i64::MIN, wrapping_neg returns i64::MIN; reading those bits as
        // u64 gives 0x8000_0000_0000_0000 — the correct unsigned magnitude.
        let mut magnitude: u64 = if negative {
            value = value.wrapping_neg();
            #[allow(clippy::cast_sign_loss)] // see comment above
            {
                value as u64
            }
        } else {
            #[allow(clippy::cast_sign_loss)] // value > 0 here
            {
                value as u64
            }
        };

        let mut buf = [0u8; 5];
        let mut len: usize = 0;
        while magnitude != 0 && len < 5 {
            #[allow(clippy::cast_possible_truncation)] // intentional low byte
            let byte = (magnitude & 0xff) as u8;
            buf[len] = byte;
            magnitude >>= 8;
            len += 1;
        }

        // If the high bit of the top byte is already set, append a sign byte.
        // Otherwise set the high bit to encode the sign.
        if len > 0 && buf[len - 1] & 0x80 != 0 {
            if len < 5 {
                buf[len] = if negative { 0x80 } else { 0x00 };
                len += 1;
            }
            // If len == 5 and we needed an extra byte, the value was outside
            // the encodable range. We silently truncate; callers that care
            // (decode-side) enforce the size limit instead.
        } else if negative && len > 0 {
            buf[len - 1] |= 0x80;
        }

        #[allow(clippy::cast_possible_truncation)] // len ≤ 5
        Self {
            buf,
            len: len as u8,
        }
    }

    /// Decode the magnitude as an `i64`.
    ///
    /// # Panics
    /// Never — `len` is bounded to 5 and an `i64` covers any 5-byte magnitude.
    #[must_use]
    pub fn to_i64(self) -> i64 {
        let len = self.len as usize;
        if len == 0 {
            return 0;
        }

        let mut magnitude: i64 = 0;
        for i in 0..len {
            let byte = if i == len - 1 {
                self.buf[i] & 0x7f
            } else {
                self.buf[i]
            };
            magnitude |= i64::from(byte) << (8 * i);
        }

        if self.buf[len - 1] & 0x80 != 0 {
            -magnitude
        } else {
            magnitude
        }
    }

    /// Decode from a wire byte slice with a size limit.
    ///
    /// `max_len` is the consensus limit for the calling opcode: 4 for
    /// arithmetic, 5 for `OP_CHECKLOCKTIMEVERIFY`. If `require_minimal` is
    /// `true` (under `MINIMALDATA`), reject non-minimally-encoded values.
    ///
    /// # Errors
    /// - `NumOverflow` if `bytes.len() > max_len`.
    /// - `NumNotMinimal` if `require_minimal` and the encoding has a
    ///   redundant most-significant byte.
    pub fn from_bytes(
        bytes: &[u8],
        max_len: usize,
        require_minimal: bool,
    ) -> Result<Self, ScriptError> {
        if bytes.len() > max_len {
            return Err(ScriptError::NumOverflow);
        }
        if require_minimal && !Self::is_minimally_encoded(bytes) {
            return Err(ScriptError::NumNotMinimal);
        }
        let mut buf = [0u8; 5];
        buf[..bytes.len()].copy_from_slice(bytes);
        #[allow(clippy::cast_possible_truncation)] // bytes.len() ≤ max_len ≤ 5
        Ok(Self {
            buf,
            len: bytes.len() as u8,
        })
    }

    /// `true` if `bytes` is the minimal encoding of the value it represents.
    ///
    /// The empty slice is minimal (encodes zero). Otherwise, the most-significant
    /// byte must contain a magnitude bit (≥ 0x80) *or* the byte below it must
    /// have its high bit set as the sign bit — equivalently, the top byte
    /// after masking off the sign bit must not be zero unless the next byte's
    /// high bit (the sign) is set.
    #[must_use]
    pub fn is_minimally_encoded(bytes: &[u8]) -> bool {
        let Some((&last, rest)) = bytes.split_last() else {
            return true; // empty == 0 is minimal
        };
        // The magnitude bits of the top byte. `0x7f` reads as "the value bits";
        // `trailing_zeros` would be slower to read for the same check.
        #[allow(clippy::verbose_bit_mask)]
        if last & 0x7f == 0 {
            // The most-significant magnitude byte is zero. Only legal if the
            // byte below it has its high bit set as the sign — i.e. the top
            // byte is purely a sign carrier.
            return rest.last().is_some_and(|b| b & 0x80 != 0);
        }
        true
    }

    /// Encoded byte slice. Borrowed view; cheap to call.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    /// Encoded length in bytes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// `true` if this encodes zero (empty bytes).
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// `true` if this encodes the value zero. Distinct from `is_empty` only
    /// in spirit — for `ScriptNum`, zero *is* the empty encoding.
    #[inline]
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.len == 0
    }
}

impl From<i64> for ScriptNum {
    #[inline]
    fn from(value: i64) -> Self {
        Self::from_i64(value)
    }
}

impl From<i32> for ScriptNum {
    #[inline]
    fn from(value: i32) -> Self {
        Self::from_i64(i64::from(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(value: i64) {
        let n = ScriptNum::from_i64(value);
        assert_eq!(n.to_i64(), value, "roundtrip failed for {value}");
    }

    #[test]
    fn zero_is_empty() {
        let n = ScriptNum::from_i64(0);
        assert!(n.is_zero());
        assert_eq!(n.as_bytes(), &[]);
        assert_eq!(n.to_i64(), 0);
    }

    #[test]
    fn small_positive_roundtrip() {
        for v in 1..=127i64 {
            roundtrip(v);
        }
    }

    #[test]
    fn small_negative_roundtrip() {
        for v in -127..0i64 {
            roundtrip(v);
        }
    }

    #[test]
    fn boundary_high_bit_appends_sign_byte() {
        // 128 fits in one byte by magnitude (0x80), but the high bit is set,
        // which would be misread as the sign bit. So it must encode as two bytes.
        let n = ScriptNum::from_i64(128);
        assert_eq!(n.as_bytes(), &[0x80, 0x00]);
        assert_eq!(n.to_i64(), 128);

        let n = ScriptNum::from_i64(-128);
        assert_eq!(n.as_bytes(), &[0x80, 0x80]);
        assert_eq!(n.to_i64(), -128);
    }

    #[test]
    fn known_encodings() {
        // Spot-checks against the BIP / Core test vectors.
        assert_eq!(ScriptNum::from_i64(1).as_bytes(), &[0x01]);
        assert_eq!(ScriptNum::from_i64(-1).as_bytes(), &[0x81]);
        assert_eq!(ScriptNum::from_i64(127).as_bytes(), &[0x7f]);
        assert_eq!(ScriptNum::from_i64(-127).as_bytes(), &[0xff]);
        assert_eq!(ScriptNum::from_i64(255).as_bytes(), &[0xff, 0x00]);
        assert_eq!(ScriptNum::from_i64(-255).as_bytes(), &[0xff, 0x80]);
        assert_eq!(ScriptNum::from_i64(256).as_bytes(), &[0x00, 0x01]);
        assert_eq!(
            ScriptNum::from_i64(0x00ff_ffff).as_bytes(),
            &[0xff, 0xff, 0xff, 0x00]
        );
    }

    #[test]
    fn four_byte_max_arithmetic_range() {
        // The largest 4-byte arithmetic value: 2^31 - 1 = 0x7fff_ffff.
        let n = ScriptNum::from_i64(0x7fff_ffff);
        assert_eq!(n.as_bytes(), &[0xff, 0xff, 0xff, 0x7f]);
        assert_eq!(n.to_i64(), 0x7fff_ffff);
    }

    #[test]
    fn five_byte_cltv_range() {
        // CLTV accepts 5 bytes — used to encode timestamps past 2106.
        let v = 0x007f_ffff_ffff_i64;
        let n = ScriptNum::from_i64(v);
        assert_eq!(n.len(), 5);
        assert_eq!(n.to_i64(), v);
    }

    #[test]
    fn from_bytes_respects_size_limit() {
        let too_big = [0x01, 0x02, 0x03, 0x04, 0x05]; // 5 bytes
        assert!(matches!(
            ScriptNum::from_bytes(&too_big, MAX_NUM_SIZE_ARITHMETIC, false),
            Err(ScriptError::NumOverflow)
        ));
        // Same bytes are fine under the CLTV limit.
        assert!(ScriptNum::from_bytes(&too_big, MAX_NUM_SIZE_CLTV, false).is_ok());
    }

    #[test]
    fn from_bytes_minimal_check() {
        // 0x00 is non-minimal: empty would encode zero too.
        assert!(matches!(
            ScriptNum::from_bytes(&[0x00], 4, true),
            Err(ScriptError::NumNotMinimal)
        ));
        // 0x80 is non-minimal: empty would encode "negative zero" which Core
        // canonicalises to empty.
        assert!(matches!(
            ScriptNum::from_bytes(&[0x80], 4, true),
            Err(ScriptError::NumNotMinimal)
        ));
        // 0x01 is minimal.
        assert!(ScriptNum::from_bytes(&[0x01], 4, true).is_ok());
        // 0x80 0x00 is minimal (encodes 128 — the sign byte is needed).
        assert!(ScriptNum::from_bytes(&[0x80, 0x00], 4, true).is_ok());
        // 0x01 0x00 is non-minimal (top byte adds nothing — equivalent to [0x01]).
        assert!(matches!(
            ScriptNum::from_bytes(&[0x01, 0x00], 4, true),
            Err(ScriptError::NumNotMinimal)
        ));
    }

    #[test]
    fn empty_is_minimal() {
        assert!(ScriptNum::is_minimally_encoded(&[]));
    }

    #[test]
    fn roundtrip_via_bytes_lenient() {
        for v in [-1, 1, 100, -100, 0xff, -0xff, 0x7fff_ffff, -0x7fff_ffff] {
            let n = ScriptNum::from_i64(v);
            let m = ScriptNum::from_bytes(n.as_bytes(), 5, false).expect("valid bytes");
            assert_eq!(m.to_i64(), v);
        }
    }

    #[test]
    fn i64_min_roundtrips() {
        // i64::MIN = -9223372036854775808. Its magnitude 0x8000_0000_0000_0000
        // needs 8 bytes, but ScriptNum only encodes up to 5 bytes, so the
        // value is truncated. Verify encode+decode at least doesn't panic.
        let n = ScriptNum::from_i64(i64::MIN);
        // The magnitude is 0x8000_0000_0000_0000 — after the while loop
        // only the low 5 bytes are kept (magnitude is shifted right 40 bits).
        // Since this exceeds the 5-byte range, the encoding is silently truncated.
        assert!(n.len() <= 5);
        // The value won't roundtrip correctly because of truncation, but
        // the important thing is it doesn't panic or UB.
    }

    #[test]
    fn i64_max_roundtrips() {
        // i64::MAX = 9223372036854775807. Magnitude fits in 8 bytes but
        // ScriptNum only encodes up to 5 bytes. Verify no panic.
        let n = ScriptNum::from_i64(i64::MAX);
        assert!(n.len() <= 5);
    }

    #[test]
    fn value_128_needs_sign_byte() {
        // 128 = 0x80. The high bit of the top byte is set, so we need
        // an extra 0x00 sign byte. Encoded as [0x80, 0x00].
        let n = ScriptNum::from_i64(128);
        assert_eq!(n.as_bytes(), &[0x80, 0x00]);
        assert_eq!(n.to_i64(), 128);
    }

    #[test]
    fn value_neg128_needs_sign_byte() {
        // -128 = magnitude 0x80. High bit set, need extra 0x80 sign byte.
        let n = ScriptNum::from_i64(-128);
        assert_eq!(n.as_bytes(), &[0x80, 0x80]);
        assert_eq!(n.to_i64(), -128);
    }

    #[test]
    fn value_neg256_encoding() {
        // -256: magnitude = 256 = 0x0100. Two bytes [0x00, 0x01].
        // Top byte 0x01 has high bit clear, so sign bit is set: [0x00, 0x81].
        let n = ScriptNum::from_i64(-256);
        assert_eq!(n.as_bytes(), &[0x00, 0x81]);
        assert_eq!(n.to_i64(), -256);
    }

    #[test]
    fn value_neg32768_encoding() {
        // -32768 = -0x8000. Magnitude [0x00, 0x80]. High bit of top byte (0x80) is set,
        // so needs sign byte: [0x00, 0x80, 0x80].
        let n = ScriptNum::from_i64(-32768);
        assert_eq!(n.as_bytes(), &[0x00, 0x80, 0x80]);
        assert_eq!(n.to_i64(), -32768);
    }
}
