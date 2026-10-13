use std::fmt;
use std::io::{Read, Write};

use crate::codec::{Decode, DecodeRef, Encode, Error};

// ── BlockVersion ─────────────────────────────────────────────────────────────

/// Block header version field (i32, supports BIP9 version bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct BlockVersion(i32);

impl BlockVersion {
    #[inline]
    #[must_use]
    pub const fn new(v: i32) -> Self {
        Self(v)
    }

    #[inline]
    #[must_use]
    pub const fn to_i32(self) -> i32 {
        self.0
    }

    #[inline]
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
}

impl Encode for BlockVersion {
    #[inline]
    fn encode(&self, w: &mut impl Write) -> Result<(), Error> {
        self.0.encode(w)
    }
}

impl Decode for BlockVersion {
    #[inline]
    fn decode(r: &mut impl Read) -> Result<Self, Error> {
        i32::decode(r).map(Self)
    }
}

impl<'a> DecodeRef<'a> for BlockVersion {
    #[inline]
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        i32::decode_ref(buf).map(|(v, rest)| (Self(v), rest))
    }
}

// ── Nonce ────────────────────────────────────────────────────────────────────

/// Block header nonce field (u32, iterated during proof-of-work mining).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Nonce(u32);

impl Nonce {
    #[inline]
    #[must_use]
    pub const fn new(n: u32) -> Self {
        Self(n)
    }

    #[inline]
    #[must_use]
    pub const fn to_u32(self) -> u32 {
        self.0
    }

    #[inline]
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
}

impl Encode for Nonce {
    #[inline]
    fn encode(&self, w: &mut impl Write) -> Result<(), Error> {
        self.0.encode(w)
    }
}

impl Decode for Nonce {
    #[inline]
    fn decode(r: &mut impl Read) -> Result<Self, Error> {
        u32::decode(r).map(Self)
    }
}

impl<'a> DecodeRef<'a> for Nonce {
    #[inline]
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        u32::decode_ref(buf).map(|(v, rest)| (Self(v), rest))
    }
}

// ── BlockTime ────────────────────────────────────────────────────────────────

/// Block header timestamp (u32 Unix seconds). Also the type returned by
/// `median_time_past()` — both represent consensus-layer timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct BlockTime(u32);

impl BlockTime {
    #[inline]
    #[must_use]
    pub const fn new(t: u32) -> Self {
        Self(t)
    }

    #[inline]
    #[must_use]
    pub const fn to_u32(self) -> u32 {
        self.0
    }

    #[inline]
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
}

impl Encode for BlockTime {
    #[inline]
    fn encode(&self, w: &mut impl Write) -> Result<(), Error> {
        self.0.encode(w)
    }
}

impl Decode for BlockTime {
    #[inline]
    fn decode(r: &mut impl Read) -> Result<Self, Error> {
        u32::decode(r).map(Self)
    }
}

impl<'a> DecodeRef<'a> for BlockTime {
    #[inline]
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        u32::decode_ref(buf).map(|(v, rest)| (Self(v), rest))
    }
}

impl fmt::Display for BlockTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<BlockTime> for u64 {
    #[inline]
    fn from(t: BlockTime) -> u64 {
        u64::from(t.0)
    }
}

impl std::ops::Add<u32> for BlockTime {
    type Output = Self;
    fn add(self, rhs: u32) -> Self {
        Self(self.0.checked_add(rhs).expect("BlockTime overflow"))
    }
}

// ── CompactBits ──────────────────────────────────────────────────────────────

/// The `nBits` compact-format difficulty target stored in a block header.
///
/// Wraps a `u32` to make difficulty fields type-distinct from plain integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CompactBits(u32);

impl CompactBits {
    #[inline]
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    #[inline]
    #[must_use]
    pub const fn to_u32(self) -> u32 {
        self.0
    }

    #[inline]
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
}

impl Encode for CompactBits {
    #[inline]
    fn encode(&self, w: &mut impl Write) -> Result<(), Error> {
        self.0.encode(w)
    }
}

impl Decode for CompactBits {
    #[inline]
    fn decode(r: &mut impl Read) -> Result<Self, Error> {
        u32::decode(r).map(Self)
    }
}

impl<'a> DecodeRef<'a> for CompactBits {
    #[inline]
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        u32::decode_ref(buf).map(|(v, rest)| (Self(v), rest))
    }
}

impl CompactBits {
    /// Decode to a 256-bit target as a 32-byte big-endian array.
    ///
    /// Returns `None` if the value is zero, negative, or encodes an overflowed target.
    #[must_use]
    pub fn to_target(self) -> Option<[u8; 32]> {
        let raw = self.0;
        let exponent = (raw >> 24) as usize;
        let mantissa = raw & 0x007f_ffff;

        if raw & 0x0080_0000 != 0 {
            return None;
        } // negative mantissa
        if mantissa == 0 {
            return None;
        }
        if exponent > 34 || (exponent == 34 && mantissa > 0xff) {
            return None;
        }

        let mut target = [0u8; 32];
        if exponent >= 3 {
            let start = 32 - exponent;
            target[start] = ((mantissa >> 16) & 0xff) as u8;
            target[start + 1] = ((mantissa >> 8) & 0xff) as u8;
            target[start + 2] = (mantissa & 0xff) as u8;
        } else {
            let shift = (3 - exponent) * 8;
            let m = mantissa >> shift;
            if exponent > 0 {
                target[32 - exponent] = (m & 0xff) as u8;
            }
        }
        Some(target)
    }

    /// Encode a 256-bit big-endian target back into compact nBits format.
    ///
    /// Returns `None` if the target is all-zero.
    #[must_use]
    pub fn from_target(target: [u8; 32]) -> Option<Self> {
        let first_nonzero = target.iter().position(|&b| b != 0)?;
        let exponent = u32::try_from(32 - first_nonzero).ok()?;

        let mut mantissa = u32::from(target[first_nonzero]) << 16;
        if first_nonzero + 1 < 32 {
            mantissa |= u32::from(target[first_nonzero + 1]) << 8;
        }
        if first_nonzero + 2 < 32 {
            mantissa |= u32::from(target[first_nonzero + 2]);
        }

        if mantissa & 0x0080_0000 != 0 {
            mantissa >>= 8;
            Some(Self((exponent + 1) << 24 | mantissa))
        } else {
            Some(Self(exponent << 24 | mantissa))
        }
    }
}

/// A block height on the canonical chain.
///
/// Wraps a `u32` to make height values type-distinct from plain integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct BlockHeight(u32);

impl BlockHeight {
    pub const ZERO: Self = Self(0);

    #[inline]
    #[must_use]
    pub const fn new(h: u32) -> Self {
        Self(h)
    }

    #[inline]
    #[must_use]
    pub const fn to_u32(self) -> u32 {
        self.0
    }

    #[must_use]
    pub fn checked_add(self, rhs: u32) -> Option<Self> {
        self.0.checked_add(rhs).map(Self)
    }

    #[must_use]
    pub fn saturating_sub(self, rhs: u32) -> Self {
        Self(self.0.saturating_sub(rhs))
    }
}

impl fmt::Display for BlockHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::ops::Add<u32> for BlockHeight {
    type Output = Self;
    fn add(self, rhs: u32) -> Self {
        Self(self.0.checked_add(rhs).expect("BlockHeight overflow"))
    }
}

impl std::ops::Sub<u32> for BlockHeight {
    type Output = Self;
    fn sub(self, rhs: u32) -> Self {
        Self(self.0.checked_sub(rhs).expect("BlockHeight underflow"))
    }
}

impl std::ops::Rem<u32> for BlockHeight {
    type Output = u32;
    fn rem(self, rhs: u32) -> u32 {
        self.0 % rhs
    }
}

// ── TxVersion ───────────────────────────────────────────────────────────────

/// Transaction version field (i32, supports BIP68/BIP112/BIP113 version semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TxVersion(i32);

impl TxVersion {
    #[inline]
    #[must_use]
    pub const fn new(v: i32) -> Self {
        Self(v)
    }

    #[inline]
    #[must_use]
    pub const fn to_i32(self) -> i32 {
        self.0
    }

    #[inline]
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }

    /// Interpret the version as unsigned (matching Bitcoin Core's `static_cast<uint32_t>`
    /// in BIP68/112 enforcement).
    #[inline]
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub const fn to_u32(self) -> u32 {
        self.0 as u32
    }
}

impl PartialOrd for TxVersion {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TxVersion {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl Encode for TxVersion {
    #[inline]
    fn encode(&self, w: &mut impl Write) -> Result<(), Error> {
        self.0.encode(w)
    }
}

impl Decode for TxVersion {
    #[inline]
    fn decode(r: &mut impl Read) -> Result<Self, Error> {
        i32::decode(r).map(Self)
    }
}

impl<'a> DecodeRef<'a> for TxVersion {
    #[inline]
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        i32::decode_ref(buf).map(|(v, rest)| (Self(v), rest))
    }
}

// ── Locktime ────────────────────────────────────────────────────────────────

/// Transaction locktime field (u32). Values below `500_000_000` are block heights;
/// values at or above are Unix timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Locktime(u32);

impl Locktime {
    /// Threshold separating block-height locktimes from Unix-timestamp locktimes.
    pub const THRESHOLD: u32 = 500_000_000;

    #[inline]
    #[must_use]
    pub const fn new(n: u32) -> Self {
        Self(n)
    }

    #[inline]
    #[must_use]
    pub const fn to_u32(self) -> u32 {
        self.0
    }

    #[inline]
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }

    /// `true` if this locktime represents a block height (below the threshold).
    #[inline]
    #[must_use]
    pub const fn is_block_height(self) -> bool {
        self.0 < Self::THRESHOLD
    }

    /// `true` if this locktime represents a Unix timestamp (at or above the threshold).
    #[inline]
    #[must_use]
    pub const fn is_time_based(self) -> bool {
        self.0 >= Self::THRESHOLD
    }

    /// Check whether a script-level CLTV value (already validated as non-negative
    /// by the interpreter) is satisfied by this transaction locktime.
    ///
    /// Returns `false` if the two values are in different domains (height vs. time)
    /// or if the script value exceeds this locktime.
    #[inline]
    #[must_use]
    pub const fn satisfies_cltv(self, script_locktime: i64) -> bool {
        let threshold = Self::THRESHOLD as i64;
        let tx_lock = self.0 as i64;
        // Both must be in the same domain.
        if (script_locktime < threshold) != (tx_lock < threshold) {
            return false;
        }
        script_locktime <= tx_lock
    }
}

impl PartialOrd for Locktime {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Locktime {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl Encode for Locktime {
    #[inline]
    fn encode(&self, w: &mut impl Write) -> Result<(), Error> {
        self.0.encode(w)
    }
}

impl Decode for Locktime {
    #[inline]
    fn decode(r: &mut impl Read) -> Result<Self, Error> {
        u32::decode(r).map(Self)
    }
}

impl<'a> DecodeRef<'a> for Locktime {
    #[inline]
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        u32::decode_ref(buf).map(|(v, rest)| (Self(v), rest))
    }
}

// ── Sequence ────────────────────────────────────────────────────────────────

/// Transaction input sequence number (u32). Encodes relative timelocks (BIP68)
/// and opt-in replace-by-fee signalling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Sequence(u32);

impl Sequence {
    pub const MAX: Self = Self(0xFFFF_FFFF);

    /// BIP68: when set, `nSequence` is not interpreted as a relative lock-time.
    const LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
    /// BIP68: when set (and disable flag clear), the lock-time is in 512-second
    /// units rather than blocks.
    const LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
    /// BIP68: mask for the lock-time value (lower 16 bits).
    const LOCKTIME_MASK: u32 = 0x0000_ffff;

    #[inline]
    #[must_use]
    pub const fn new(n: u32) -> Self {
        Self(n)
    }

    #[inline]
    #[must_use]
    pub const fn to_u32(self) -> u32 {
        self.0
    }

    #[inline]
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }

    /// `true` if the disable flag (bit 31) is set — relative lock-time is ignored.
    #[inline]
    #[must_use]
    pub const fn is_locktime_disabled(self) -> bool {
        self.0 & Self::LOCKTIME_DISABLE_FLAG != 0
    }

    /// `true` if the type flag (bit 22) is set — lock-time is in 512-second units.
    /// Only meaningful when `!is_locktime_disabled()`.
    #[inline]
    #[must_use]
    pub const fn is_time_based(self) -> bool {
        self.0 & Self::LOCKTIME_TYPE_FLAG != 0
    }

    /// The masked lock-time value (lower 16 bits) with the type flag preserved.
    /// Used for same-domain comparison in BIP112 CSV enforcement.
    #[inline]
    #[must_use]
    pub const fn locktime_value(self) -> u32 {
        self.0 & (Self::LOCKTIME_TYPE_FLAG | Self::LOCKTIME_MASK)
    }

    /// Check whether a script-level CSV value (already validated as non-negative
    /// by the interpreter, disable-flag already checked by caller) is satisfied
    /// by this input's sequence number.
    ///
    /// Returns `false` if the input's disable flag is set, or the two values
    /// are in different domains (blocks vs. time), or the script value exceeds
    /// the input's masked value.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub const fn satisfies_csv(self, script_sequence: i64) -> bool {
        if self.is_locktime_disabled() {
            return false;
        }
        let script_masked =
            script_sequence as u32 & (Self::LOCKTIME_TYPE_FLAG | Self::LOCKTIME_MASK);
        let tx_masked = self.locktime_value();
        // Both must be in the same domain (blocks vs. 512-second units).
        let script_is_time = script_masked & Self::LOCKTIME_TYPE_FLAG != 0;
        let tx_is_time = tx_masked & Self::LOCKTIME_TYPE_FLAG != 0;
        if script_is_time != tx_is_time {
            return false;
        }
        script_masked <= tx_masked
    }
}

impl PartialOrd for Sequence {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Sequence {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl Encode for Sequence {
    #[inline]
    fn encode(&self, w: &mut impl Write) -> Result<(), Error> {
        self.0.encode(w)
    }
}

impl Decode for Sequence {
    #[inline]
    fn decode(r: &mut impl Read) -> Result<Self, Error> {
        u32::decode(r).map(Self)
    }
}

impl<'a> DecodeRef<'a> for Sequence {
    #[inline]
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        u32::decode_ref(buf).map(|(v, rest)| (Self(v), rest))
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

    // ── CompactBits ──────────────────────────────────────────────────────

    #[test]
    fn compact_bits_genesis_target() {
        let bits = CompactBits::new(0x1d00_ffff);
        let target = bits
            .to_target()
            .expect("genesis bits must produce a target");
        // The genesis target: 0x00000000FFFF0000...0000 (difficulty-1 target)
        // exponent = 0x1d = 29, mantissa = 0x00ffff
        // target = 0x00ffff * 2^(8*(29-3)) = 0x00ffff * 2^208
        // byte 3 (from the high end) should start with 00 ff ff
        assert_eq!(target[3], 0x00);
        assert_eq!(target[4], 0xff);
        assert_eq!(target[5], 0xff);
        // leading 3 bytes must be zero
        assert_eq!(target[0], 0);
        assert_eq!(target[1], 0);
        assert_eq!(target[2], 0);
        // remaining bytes from index 6..32 must be zero
        for &b in &target[6..] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn compact_bits_zero_mantissa_returns_none() {
        // exponent = 0x1d, mantissa = 0 -> target would be zero, should return None
        let bits = CompactBits::new(0x1d00_0000);
        assert!(bits.to_target().is_none());
    }

    #[test]
    fn compact_bits_negative_mantissa_returns_none() {
        // bit 23 set -> negative flag in Bitcoin compact format
        let bits = CompactBits::new(0x0180_0001);
        assert!(bits.to_target().is_none());
    }

    #[test]
    fn compact_bits_exponent_zero() {
        // exponent = 0, mantissa = 1 -> value would be shifted by 8*(0-3) = negative shift
        let bits = CompactBits::new(0x0000_0001);
        // With exponent 0, the mantissa is right-shifted so far it becomes zero
        // Result should be None (zero target) or a valid all-zero-ish target
        // Either way it should not panic
        let _result = bits.to_target();
    }

    #[test]
    fn compact_bits_exponent_too_large_returns_none() {
        // exponent > 34 should not fit in 32 bytes
        let bits = CompactBits::new(0x2300_0001); // exponent = 0x23 = 35
        assert!(bits.to_target().is_none());
    }

    #[test]
    fn from_target_all_zero_returns_none() {
        let zero = [0u8; 32];
        assert!(CompactBits::from_target(zero).is_none());
    }

    #[test]
    fn from_target_to_target_roundtrip_genesis() {
        let bits = CompactBits::new(0x1d00_ffff);
        let target = bits.to_target().expect("genesis bits must have a target");
        let recovered = CompactBits::from_target(target).expect("non-zero target must roundtrip");
        let target2 = recovered
            .to_target()
            .expect("recovered bits must have a target");
        assert_eq!(target, target2);
    }

    #[test]
    fn from_target_to_target_roundtrip_difficulty_1() {
        // Difficulty-1 target in big-endian 32 bytes
        let mut target = [0u8; 32];
        target[3] = 0x00;
        target[4] = 0xff;
        target[5] = 0xff;
        let bits = CompactBits::from_target(target).expect("difficulty-1 target must convert");
        let rt = bits.to_target().expect("bits must convert back");
        assert_eq!(target, rt);
    }

    #[test]
    fn compact_bits_encode_decode_roundtrip() {
        let original = CompactBits::new(0x1d00_ffff);
        let bytes = encode_val(&original);
        let decoded: CompactBits = decode_val(&bytes);
        assert_eq!(original, decoded);
    }

    #[test]
    fn compact_bits_decode_ref_trailing() {
        let original = CompactBits::new(0x1d00_ffff);
        let mut bytes = encode_val(&original);
        bytes.extend_from_slice(&[0xDE, 0xAD]);
        let (decoded, rest) = CompactBits::decode_ref(&bytes).expect("decode_ref must succeed");
        assert_eq!(decoded, original);
        assert_eq!(rest, &[0xDE, 0xAD]);
    }

    // ── BlockHeight ──────────────────────────────────────────────────────

    #[test]
    fn block_height_zero() {
        assert_eq!(BlockHeight::ZERO.to_u32(), 0);
    }

    #[test]
    fn block_height_checked_add_normal() {
        let h = BlockHeight::new(100);
        assert_eq!(h.checked_add(50), Some(BlockHeight::new(150)));
    }

    #[test]
    fn block_height_checked_add_overflow_returns_none() {
        let h = BlockHeight::new(u32::MAX);
        assert_eq!(h.checked_add(1), None);
    }

    #[test]
    fn block_height_saturating_sub_normal() {
        let h = BlockHeight::new(100);
        assert_eq!(h.saturating_sub(30), BlockHeight::new(70));
    }

    #[test]
    fn block_height_saturating_sub_floors_at_zero() {
        let h = BlockHeight::new(10);
        assert_eq!(h.saturating_sub(100), BlockHeight::ZERO);
    }

    #[test]
    #[should_panic(expected = "BlockHeight overflow")]
    fn block_height_add_overflow_panics() {
        let _ = BlockHeight::new(u32::MAX) + 1u32;
    }

    #[test]
    #[should_panic(expected = "BlockHeight underflow")]
    fn block_height_sub_underflow_panics() {
        let _ = BlockHeight::new(0) - 1u32;
    }

    #[test]
    fn block_height_rem() {
        let h = BlockHeight::new(2016);
        let rem = h % 2016u32;
        assert_eq!(rem, 0u32);
        let h2 = BlockHeight::new(2017);
        let rem2 = h2 % 2016u32;
        assert_eq!(rem2, 1u32);
    }

    #[test]
    fn block_height_display() {
        let h = BlockHeight::new(840_000);
        assert_eq!(format!("{h}"), "840000");
    }

    // ── BlockTime ────────────────────────────────────────────────────────

    #[test]
    #[should_panic(expected = "BlockTime overflow")]
    fn block_time_add_overflow_panics() {
        let _ = BlockTime::new(u32::MAX) + 1u32;
    }

    #[test]
    fn block_time_into_u64() {
        let t = BlockTime::new(1_700_000_000);
        let val: u64 = t.into();
        assert_eq!(val, 1_700_000_000u64);
    }

    #[test]
    fn block_time_encode_decode_roundtrip() {
        let original = BlockTime::new(1_231_006_505);
        let bytes = encode_val(&original);
        let decoded: BlockTime = decode_val(&bytes);
        assert_eq!(original, decoded);
    }

    #[test]
    fn block_time_decode_ref_trailing() {
        let original = BlockTime::new(1_231_006_505);
        let mut bytes = encode_val(&original);
        bytes.push(0xFF);
        let (decoded, rest) = BlockTime::decode_ref(&bytes).expect("decode_ref must succeed");
        assert_eq!(decoded, original);
        assert_eq!(rest, &[0xFF]);
    }

    // ── BlockVersion ─────────────────────────────────────────────────────

    #[test]
    fn block_version_encode_decode_roundtrip() {
        let original = BlockVersion::new(0x2000_0000);
        let bytes = encode_val(&original);
        let decoded: BlockVersion = decode_val(&bytes);
        assert_eq!(original, decoded);
    }

    #[test]
    fn block_version_decode_ref_trailing() {
        let original = BlockVersion::new(1);
        let mut bytes = encode_val(&original);
        bytes.extend_from_slice(&[0xAB, 0xCD]);
        let (decoded, rest) = BlockVersion::decode_ref(&bytes).expect("decode_ref must succeed");
        assert_eq!(decoded, original);
        assert_eq!(rest, &[0xAB, 0xCD]);
    }

    #[test]
    fn block_version_to_le_bytes() {
        let v = BlockVersion::new(0x2000_0000);
        assert_eq!(v.to_le_bytes(), 0x2000_0000_i32.to_le_bytes());
    }

    // ── Nonce ────────────────────────────────────────────────────────────

    #[test]
    fn nonce_encode_decode_roundtrip() {
        let original = Nonce::new(0xDEAD_BEEF);
        let bytes = encode_val(&original);
        let decoded: Nonce = decode_val(&bytes);
        assert_eq!(original, decoded);
    }

    #[test]
    fn nonce_decode_ref_trailing() {
        let original = Nonce::new(42);
        let mut bytes = encode_val(&original);
        bytes.push(0x01);
        let (decoded, rest) = Nonce::decode_ref(&bytes).expect("decode_ref must succeed");
        assert_eq!(decoded, original);
        assert_eq!(rest, &[0x01]);
    }

    #[test]
    fn nonce_to_le_bytes() {
        let n = Nonce::new(0xDEAD_BEEF);
        assert_eq!(n.to_le_bytes(), 0xDEAD_BEEF_u32.to_le_bytes());
    }

    // ── TxVersion ────────────────────────────────────────────────────────

    #[test]
    fn tx_version_encode_decode_roundtrip() {
        let original = TxVersion::new(2);
        let bytes = encode_val(&original);
        let decoded: TxVersion = decode_val(&bytes);
        assert_eq!(original, decoded);
    }

    #[test]
    fn tx_version_decode_ref_trailing() {
        let original = TxVersion::new(1);
        let mut bytes = encode_val(&original);
        bytes.extend_from_slice(&[0x00, 0x00]);
        let (decoded, rest) = TxVersion::decode_ref(&bytes).expect("decode_ref must succeed");
        assert_eq!(decoded, original);
        assert_eq!(rest, &[0x00, 0x00]);
    }

    #[test]
    fn tx_version_to_le_bytes() {
        let v = TxVersion::new(2);
        assert_eq!(v.to_le_bytes(), 2i32.to_le_bytes());
    }

    // ── Locktime ─────────────────────────────────────────────────────────

    #[test]
    fn locktime_encode_decode_roundtrip() {
        let original = Locktime::new(500_000);
        let bytes = encode_val(&original);
        let decoded: Locktime = decode_val(&bytes);
        assert_eq!(original, decoded);
    }

    #[test]
    fn locktime_decode_ref_trailing() {
        let original = Locktime::new(0);
        let mut bytes = encode_val(&original);
        bytes.push(0xFF);
        let (decoded, rest) = Locktime::decode_ref(&bytes).expect("decode_ref must succeed");
        assert_eq!(decoded, original);
        assert_eq!(rest, &[0xFF]);
    }

    #[test]
    fn locktime_to_le_bytes() {
        let l = Locktime::new(500_000);
        assert_eq!(l.to_le_bytes(), 500_000u32.to_le_bytes());
    }

    // ── Sequence ─────────────────────────────────────────────────────────

    #[test]
    fn sequence_max_constant() {
        assert_eq!(Sequence::MAX.to_u32(), 0xFFFF_FFFF);
    }

    #[test]
    fn sequence_encode_decode_roundtrip() {
        let original = Sequence::new(0xFFFF_FFFE);
        let bytes = encode_val(&original);
        let decoded: Sequence = decode_val(&bytes);
        assert_eq!(original, decoded);
    }

    #[test]
    fn sequence_decode_ref_trailing() {
        let original = Sequence::MAX;
        let mut bytes = encode_val(&original);
        bytes.extend_from_slice(&[0x01, 0x02, 0x03]);
        let (decoded, rest) = Sequence::decode_ref(&bytes).expect("decode_ref must succeed");
        assert_eq!(decoded, original);
        assert_eq!(rest, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn sequence_to_le_bytes() {
        let s = Sequence::new(0xFFFF_FFFE);
        assert_eq!(s.to_le_bytes(), 0xFFFF_FFFE_u32.to_le_bytes());
    }
}
