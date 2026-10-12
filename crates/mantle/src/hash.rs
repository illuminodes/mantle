use std::fmt;
use std::io::{Read, Write};

use sha2::{Digest, Sha256};

use crate::codec::{Decode, DecodeRef, Encode, Error};

// ── Hash256 ───────────────────────────────────────────────────────────────────

/// A 32-byte hash (txid, block hash, merkle root, etc.). Stored as raw bytes,
/// displayed in reversed byte order per Bitcoin convention.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Hash256([u8; 32]);

impl Hash256 {
    pub const ZERO: Self = Self([0u8; 32]);

    /// Double-SHA256 of `data`, producing a [`Hash256`].
    ///
    /// This is the canonical Bitcoin hash used for txids, block hashes,
    /// merkle nodes, and message checksums.
    #[inline]
    #[must_use]
    pub fn hash(data: &[u8]) -> Self {
        let first = Sha256::digest(data);
        Self(Sha256::digest(first).into())
    }

    /// First 4 bytes of the double-SHA256 — used as the P2P message checksum.
    #[inline]
    #[must_use]
    pub fn checksum(data: &[u8]) -> [u8; 4] {
        let h = Self::hash(data);
        [h.0[0], h.0[1], h.0[2], h.0[3]]
    }

    /// Parse a 64-character hex string in display order (reversed from internal
    /// storage, per Bitcoin convention).
    ///
    /// # Errors
    /// Returns `Err` if the input is not exactly 64 hex characters.
    pub fn from_display_hex(s: &str) -> Result<Self, HexError> {
        if s.len() != 64 {
            return Err(HexError::Length(s.len()));
        }
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let pair = &s[i * 2..i * 2 + 2];
            *byte = u8::from_str_radix(pair, 16)
                .map_err(|_| HexError::InvalidChar { offset: i * 2 })?;
        }
        bytes.reverse();
        Ok(Self(bytes))
    }

    /// Const-context twin of [`Self::from_display_hex`] for hash constants.
    ///
    /// # Panics
    /// Panics (at compile time when used in a `const`) if `s` is not exactly
    /// 64 hex characters.
    #[must_use]
    pub const fn from_display_hex_const(s: &str) -> Self {
        let s = s.as_bytes();
        assert!(s.len() == 64, "expected 64 hex characters");
        let mut bytes = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            bytes[31 - i] = Self::hex_nibble(s[i * 2]) << 4 | Self::hex_nibble(s[i * 2 + 1]);
            i += 1;
        }
        Self(bytes)
    }

    const fn hex_nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("invalid hex character"),
        }
    }

    /// Format as a 64-character hex string in display order (reversed from
    /// internal storage, per Bitcoin convention).
    #[must_use]
    pub fn to_display_hex(self) -> String {
        self.to_string()
    }

    /// Raw 32-byte array (internal byte order).
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Construct from a raw 32-byte array.
    #[inline]
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Hash256 {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Errors returned by [`Hash256::from_display_hex`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexError {
    /// The input string was not 64 characters long.
    Length(usize),
    /// A character at the given byte offset was not a valid hex digit.
    InvalidChar { offset: usize },
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length(n) => write!(f, "expected 64 hex characters, got {n}"),
            Self::InvalidChar { offset } => write!(f, "invalid hex character at offset {offset}"),
        }
    }
}

impl std::error::Error for HexError {}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut rev = self.0;
        rev.reverse();
        for b in &rev {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl Encode for Hash256 {
    #[inline]
    fn encode(&self, w: &mut impl Write) -> Result<(), Error> {
        w.write_all(&self.0)?;
        Ok(())
    }
}

impl Decode for Hash256 {
    #[inline]
    fn decode(r: &mut impl Read) -> Result<Self, Error> {
        let mut buf = [0u8; 32];
        r.read_exact(&mut buf)?;
        Ok(Self(buf))
    }
}

impl<'a> DecodeRef<'a> for Hash256 {
    #[inline]
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        if buf.len() < 32 {
            return Err(Error::UnexpectedEof);
        }
        let (head, tail) = buf.split_at(32);
        Ok((
            Self(head.try_into().map_err(|_| Error::UnexpectedEof)?),
            tail,
        ))
    }
}

// ── ByteSliceExt ─────────────────────────────────────────────────────────────

/// Extension methods on byte slices for hashing and fixed-width field parsing.
pub trait ByteSliceExt {
    /// Double-SHA256 of this slice, returned as a [`Hash256`].
    #[must_use]
    fn sha256d(&self) -> Hash256;

    /// Read a `u32` in little-endian byte order from `offset`.
    ///
    /// # Panics
    /// Panics if `offset + 4 > self.len()`.
    #[must_use]
    fn read_u32_le(&self, offset: usize) -> u32;

    /// Copy 32 bytes starting at `offset` into a new `[u8; 32]`.
    ///
    /// # Panics
    /// Panics if `offset + 32 > self.len()`.
    #[must_use]
    fn read_hash(&self, offset: usize) -> [u8; 32];

    /// Copy 32 bytes starting at `offset` into a caller-supplied buffer `out`,
    /// returning it by mutable reference for chaining.
    ///
    /// # Panics
    /// Panics if `offset + 32 > self.len()`.
    fn read_hash_into<'a>(&self, offset: usize, out: &'a mut [u8; 32]) -> &'a mut [u8; 32];
}

impl ByteSliceExt for [u8] {
    #[inline]
    fn sha256d(&self) -> Hash256 {
        Hash256::hash(self)
    }

    #[inline]
    fn read_u32_le(&self, offset: usize) -> u32 {
        u32::from_le_bytes([
            self[offset],
            self[offset + 1],
            self[offset + 2],
            self[offset + 3],
        ])
    }

    #[inline]
    fn read_hash(&self, offset: usize) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self[offset..offset + 32]);
        out
    }

    #[inline]
    fn read_hash_into<'a>(&self, offset: usize, out: &'a mut [u8; 32]) -> &'a mut [u8; 32] {
        out.copy_from_slice(&self[offset..offset + 32]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256d_empty() {
        let hash = Hash256::hash(b"");
        assert_eq!(
            *hash.as_bytes(),
            [
                0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3, 0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29,
                0x9f, 0xcc, 0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4, 0x3e, 0x41, 0x98, 0x3f,
                0x5d, 0x4c, 0x94, 0x56,
            ]
        );
    }

    #[test]
    fn checksum_is_first_4_bytes() {
        let data = b"hello";
        let full = Hash256::hash(data);
        let bytes = full.as_bytes();
        assert_eq!(
            Hash256::checksum(data),
            [bytes[0], bytes[1], bytes[2], bytes[3]]
        );
    }

    // ── Hash256 tests ─────────────────────────────────────────────────────────

    fn encode<T: Encode>(val: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        val.encode(&mut buf).expect("Vec<u8> write cannot fail");
        buf
    }

    fn decode<T: Decode>(bytes: &[u8]) -> T {
        T::decode(&mut std::io::Cursor::new(bytes)).expect("test data must decode")
    }

    fn decode_err<T: Decode + std::fmt::Debug>(bytes: &[u8]) -> Error {
        T::decode(&mut std::io::Cursor::new(bytes)).unwrap_err()
    }

    fn decode_ref_err<'a, T: DecodeRef<'a> + std::fmt::Debug>(buf: &'a [u8]) -> Error {
        T::decode_ref(buf).unwrap_err()
    }

    #[test]
    fn hash256_display() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xab;
        bytes[31] = 0xcd;
        let h = Hash256(bytes);
        let s = h.to_string();
        assert!(s.starts_with("cd"));
        assert!(s.ends_with("ab"));
    }

    #[test]
    fn hash256_truncated() {
        let e = decode_err::<Hash256>(&[0u8; 31]);
        assert!(matches!(e, Error::UnexpectedEof | Error::Io(_)));
    }

    #[test]
    fn hash256_decode_ref_truncated() {
        let e = decode_ref_err::<Hash256>(&[0u8; 16]);
        assert!(matches!(e, Error::UnexpectedEof | Error::Io(_)));
    }

    #[test]
    fn hash256_all_ones_roundtrip() {
        let h = Hash256([0xff; 32]);
        let bytes = encode(&h);
        assert_eq!(decode::<Hash256>(&bytes), h);
    }

    #[test]
    fn hash256_zero_display() {
        assert_eq!(Hash256::ZERO.to_string(), "0".repeat(64));
    }

    #[test]
    fn from_display_hex_roundtrip() {
        let h = Hash256::hash(b"test");
        let hex = h.to_display_hex();
        assert_eq!(Hash256::from_display_hex(&hex).unwrap(), h);
    }

    #[test]
    fn from_display_hex_wrong_length() {
        assert!(matches!(
            Hash256::from_display_hex("abcd"),
            Err(HexError::Length(4))
        ));
        assert!(matches!(
            Hash256::from_display_hex(""),
            Err(HexError::Length(0))
        ));
    }

    #[test]
    fn from_display_hex_invalid_char() {
        let bad = format!("{}zz", "00".repeat(31));
        assert!(matches!(
            Hash256::from_display_hex(&bad),
            Err(HexError::InvalidChar { .. })
        ));
    }

    #[test]
    fn from_display_hex_genesis_block() {
        let hex = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let h = Hash256::from_display_hex(hex).unwrap();
        assert_eq!(h.to_display_hex(), hex);
    }

    #[test]
    fn from_display_hex_const_matches_runtime_parser() {
        const GENESIS: Hash256 = Hash256::from_display_hex_const(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        );
        let runtime = Hash256::from_display_hex(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )
        .unwrap();
        assert_eq!(GENESIS, runtime);
        assert_eq!(
            Hash256::from_display_hex_const(&"AB".repeat(32)),
            Hash256::from_bytes([0xab; 32])
        );
    }

    #[test]
    fn hash256_as_ref_slice() {
        let h = Hash256::from_bytes([0xab; 32]);
        let slice: &[u8] = h.as_ref();
        assert_eq!(slice.len(), 32);
        assert_eq!(slice[0], 0xab);
    }

    #[test]
    fn read_u32_le_and_read_hash() {
        let mut data = [0xaa; 36];
        data[0] = 0x01;
        data[1] = 0x02;
        data[2] = 0x03;
        data[3] = 0x04;
        assert_eq!(data.read_u32_le(0), 0x0403_0201);
        let h = data.read_hash(4);
        assert_eq!(h, [0xaa; 32]);
    }

    #[test]
    fn read_hash_into() {
        let data = [0xbb; 40];
        let mut out = [0u8; 32];
        data.read_hash_into(8, &mut out);
        assert_eq!(out, [0xbb; 32]);
    }

    #[test]
    fn hash256_display_is_64_hex_chars() {
        let h = Hash256::from_bytes([0xab; 32]);
        let s = format!("{h}");
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hex_error_display() {
        let e = HexError::Length(10);
        assert!(format!("{e}").contains("64"));
        let e = HexError::InvalidChar { offset: 5 };
        assert!(format!("{e}").contains("offset 5"));
    }
}
