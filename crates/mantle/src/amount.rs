use std::fmt;
use std::io::{Read, Write};

use crate::codec::{Decode, DecodeRef, Encode, Error};

/// A monetary value in satoshis (1 BTC = 100,000,000 satoshis).
///
/// Distinct from a plain `u64` so that values, fees, and counts cannot be
/// accidentally interchanged. Construct with [`Satoshi::new`]; extract with
/// [`Satoshi::to_u64`] or `u64::from`. The inner representation is hidden so
/// the type stays a single source of truth for "this u64 is money."
///
/// Note: any `u64` is a representable `Satoshi` — the consensus rule that
/// values must be at or below [`MAX_MONEY`](Self::MAX_MONEY) is enforced by
/// the validator, not the type. This matches Bitcoin Core's `CAmount`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Satoshi(u64);

impl Satoshi {
    pub const ZERO: Self = Self(0);

    /// Maximum money supply: 21,000,000 BTC expressed in satoshis.
    pub const MAX_MONEY: Self = Self(21_000_000 * 100_000_000);

    /// Construct from a raw `u64` count of satoshis.
    #[inline]
    #[must_use]
    pub const fn new(sats: u64) -> Self {
        Self(sats)
    }

    /// Extract the underlying `u64` count of satoshis.
    ///
    /// Prefer Satoshi's own arithmetic ops where possible. Use this only
    /// at FFI boundaries (e.g. `bitcoinconsensus`) or for cache keys.
    #[inline]
    #[must_use]
    pub const fn to_u64(self) -> u64 {
        self.0
    }

    /// Little-endian byte representation for wire serialisation.
    #[inline]
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// `self + rhs`, returning `None` on overflow.
    #[must_use]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self)
    }

    /// `self - rhs`, returning `None` on underflow.
    #[must_use]
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.0.checked_sub(rhs.0).map(Self)
    }
}

impl std::ops::Add for Satoshi {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self(self.0.checked_add(rhs.0).expect("Satoshi overflow"))
    }
}

impl std::ops::Sub for Satoshi {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self(self.0.checked_sub(rhs.0).expect("Satoshi underflow"))
    }
}

impl std::iter::Sum for Satoshi {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, std::ops::Add::add)
    }
}

impl fmt::Display for Satoshi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Encode for Satoshi {
    #[inline]
    fn encode(&self, w: &mut impl Write) -> Result<(), Error> {
        self.0.encode(w)
    }
}

impl Decode for Satoshi {
    #[inline]
    fn decode(r: &mut impl Read) -> Result<Self, Error> {
        u64::decode(r).map(Self)
    }
}

impl<'a> DecodeRef<'a> for Satoshi {
    #[inline]
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        u64::decode_ref(buf).map(|(v, rest)| (Self(v), rest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Decode, DecodeRef, Encode};
    use std::io::Cursor;

    fn encode_val<T: Encode>(val: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        val.encode(&mut buf).expect("Vec<u8> write cannot fail");
        buf
    }
    fn decode_val<T: Decode>(bytes: &[u8]) -> T {
        T::decode(&mut Cursor::new(bytes)).expect("test data must decode")
    }

    #[test]
    fn roundtrip_encode_decode() {
        let original = Satoshi::new(123_456_789);
        let bytes = encode_val(&original);
        let decoded: Satoshi = decode_val(&bytes);
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_ref_zero_copy() {
        let original = Satoshi::new(42);
        let bytes = encode_val(&original);
        let (decoded, rest) = Satoshi::decode_ref(&bytes).expect("decode_ref must succeed");
        assert_eq!(decoded, original);
        assert!(rest.is_empty());
    }

    #[test]
    fn max_money_constant() {
        assert_eq!(Satoshi::MAX_MONEY.to_u64(), 21_000_000 * 100_000_000);
    }

    #[test]
    fn checked_add_normal() {
        let a = Satoshi::new(100);
        let b = Satoshi::new(200);
        assert_eq!(a.checked_add(b), Some(Satoshi::new(300)));
    }

    #[test]
    fn checked_add_overflow_returns_none() {
        let a = Satoshi::new(u64::MAX);
        let b = Satoshi::new(1);
        assert_eq!(a.checked_add(b), None);
    }

    #[test]
    fn checked_sub_normal() {
        let a = Satoshi::new(500);
        let b = Satoshi::new(200);
        assert_eq!(a.checked_sub(b), Some(Satoshi::new(300)));
    }

    #[test]
    fn checked_sub_underflow_returns_none() {
        let a = Satoshi::new(100);
        let b = Satoshi::new(200);
        assert_eq!(a.checked_sub(b), None);
    }

    #[test]
    fn add_normal() {
        let result = Satoshi::new(10) + Satoshi::new(20);
        assert_eq!(result, Satoshi::new(30));
    }

    #[test]
    #[should_panic(expected = "overflow")]
    fn add_overflow_panics() {
        let _ = Satoshi::new(u64::MAX) + Satoshi::new(1);
    }

    #[test]
    fn sub_normal() {
        let result = Satoshi::new(50) - Satoshi::new(30);
        assert_eq!(result, Satoshi::new(20));
    }

    #[test]
    #[should_panic(expected = "underflow")]
    fn sub_underflow_panics() {
        let _ = Satoshi::new(10) - Satoshi::new(20);
    }

    #[test]
    fn sum_empty_iterator() {
        let vals: Vec<Satoshi> = vec![];
        let total: Satoshi = vals.into_iter().sum();
        assert_eq!(total, Satoshi::ZERO);
    }

    #[test]
    fn sum_several_values() {
        let vals = vec![Satoshi::new(10), Satoshi::new(20), Satoshi::new(30)];
        let total: Satoshi = vals.into_iter().sum();
        assert_eq!(total, Satoshi::new(60));
    }

    #[test]
    fn to_le_bytes_matches_u64_encoding() {
        let val = Satoshi::new(0x0102_0304_0506_0708);
        assert_eq!(val.to_le_bytes(), 0x0102_0304_0506_0708_u64.to_le_bytes());
    }

    #[test]
    fn decode_truncated_fails() {
        let bytes = [0u8; 7]; // only 7 bytes, need 8
        let result = Satoshi::decode(&mut Cursor::new(&bytes[..]));
        assert!(result.is_err());
    }
}
