use std::fmt;
use std::io::{Read, Write};

use crate::codec::{Decode, Encode, Error, VarInt};

// ── ScriptBuf ─────────────────────────────────────────────────────────────────

/// Inline-optimised byte buffer for Bitcoin scripts.
///
/// Stores scripts up to `N` bytes on the stack; falls back to heap for longer
/// ones. `N` is chosen per field: 128 for `ScriptSig` (covers all coinbase and
/// standard legacy inputs), 36 for `ScriptPubKey` (covers every standard output
/// type including P2WSH at 34 bytes).
#[derive(Clone)]
pub enum ScriptBuf<const N: usize> {
    Inline { len: u8, data: [u8; N] },
    Heap(Vec<u8>),
}

impl<const N: usize> ScriptBuf<N> {
    /// Construct from a byte slice, choosing inline or heap automatically.
    ///
    /// # Panics
    /// Never in practice — `N` is always ≤ 255 (128 or 36), so `s.len() <= N`
    /// implies `s.len()` fits in `u8`.
    #[must_use]
    pub fn from_slice(s: &[u8]) -> Self {
        if s.len() <= N {
            let mut data = [0u8; N];
            data[..s.len()].copy_from_slice(s);
            #[allow(clippy::cast_possible_truncation)] // N <= 255, so len <= N fits u8
            Self::Inline {
                len: s.len() as u8,
                data,
            }
        } else {
            Self::Heap(s.to_vec())
        }
    }

    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Inline { len, data } => &data[..*len as usize],
            Self::Heap(v) => v.as_slice(),
        }
    }

    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Inline { len, .. } => *len as usize,
            Self::Heap(v) => v.len(),
        }
    }

    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }
}

impl<const N: usize> std::ops::Deref for ScriptBuf<N> {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> From<Vec<u8>> for ScriptBuf<N> {
    fn from(v: Vec<u8>) -> Self {
        if v.len() <= N {
            Self::from_slice(&v)
        } else {
            Self::Heap(v)
        }
    }
}

impl<const N: usize> From<&[u8]> for ScriptBuf<N> {
    fn from(s: &[u8]) -> Self {
        Self::from_slice(s)
    }
}

impl<const N: usize> PartialEq for ScriptBuf<N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<const N: usize> Eq for ScriptBuf<N> {}

impl<const N: usize> PartialEq<[u8]> for ScriptBuf<N> {
    fn eq(&self, other: &[u8]) -> bool {
        self.as_slice() == other
    }
}

impl<const N: usize> PartialEq<Vec<u8>> for ScriptBuf<N> {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<const N: usize> fmt::Debug for ScriptBuf<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ScriptBuf({:?})", self.as_slice())
    }
}

impl<const N: usize> Encode for ScriptBuf<N> {
    fn encode(&self, w: &mut impl Write) -> Result<(), Error> {
        let s = self.as_slice();
        VarInt::from(s.len()).encode(w)?;
        w.write_all(s)?;
        Ok(())
    }
}

impl<const N: usize> Decode for ScriptBuf<N> {
    /// Bounded by the block weight: the 10 000-byte script limit applies at
    /// execution, and output scripts above it are valid on chain.
    fn decode(r: &mut impl Read) -> Result<Self, Error> {
        VarInt::decode_bytes_limited::<{ 4 * 1024 * 1024 }>(r).map(Self::from)
    }
}

// ── ScriptSig / ScriptPubKey ──────────────────────────────────────────────────

/// Input script (scriptSig). Inline up to 128 bytes; heap beyond that.
///
/// 128 bytes covers all standard legacy inputs (P2PKH scriptSig is 107 bytes)
/// and the consensus coinbase maximum (100 bytes).
pub type ScriptSig = ScriptBuf<128>;

/// Output script (scriptPubKey). Inline up to 36 bytes; heap beyond that.
///
/// 36 bytes covers every standard output type: P2PKH (25), P2SH (23),
/// P2WPKH (22), P2WSH (34), `OP_RETURN` bare (1+).
pub type ScriptPubKey = ScriptBuf<36>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Decode, Encode};
    use std::io::Cursor;

    fn encode_val<T: Encode>(val: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        val.encode(&mut buf).expect("Vec<u8> write cannot fail");
        buf
    }
    fn decode_val<T: Decode>(bytes: &[u8]) -> T {
        T::decode(&mut Cursor::new(bytes)).expect("test data must decode")
    }

    // ── Empty script ─────────────────────────────────────────────────────

    #[test]
    fn empty_script_from_slice() {
        let s = ScriptSig::from_slice(&[]);
        assert_eq!(s.len(), 0);
        assert!(s.is_empty());
        assert!(matches!(s, ScriptBuf::Inline { .. }));
    }

    // ── ScriptSig inline/heap boundary (128) ─────────────────────────────

    #[test]
    fn scriptsig_at_boundary_stays_inline() {
        let data = vec![0xABu8; 128];
        let s = ScriptSig::from_slice(&data);
        assert_eq!(s.len(), 128);
        assert!(matches!(s, ScriptBuf::Inline { .. }));
        assert_eq!(s.as_slice(), &data[..]);
    }

    #[test]
    fn scriptsig_above_boundary_goes_to_heap() {
        let data = vec![0xCDu8; 129];
        let s = ScriptSig::from_slice(&data);
        assert_eq!(s.len(), 129);
        assert!(matches!(s, ScriptBuf::Heap(_)));
        assert_eq!(s.as_slice(), &data[..]);
    }

    // ── ScriptPubKey inline/heap boundary (36) ───────────────────────────

    #[test]
    fn scriptpubkey_at_boundary_stays_inline() {
        let data = vec![0x01u8; 36];
        let s = ScriptPubKey::from_slice(&data);
        assert_eq!(s.len(), 36);
        assert!(matches!(s, ScriptBuf::Inline { .. }));
    }

    #[test]
    fn scriptpubkey_above_boundary_goes_to_heap() {
        let data = vec![0x02u8; 37];
        let s = ScriptPubKey::from_slice(&data);
        assert_eq!(s.len(), 37);
        assert!(matches!(s, ScriptBuf::Heap(_)));
    }

    // ── as_slice / to_vec ────────────────────────────────────────────────

    #[test]
    fn as_slice_inline() {
        let data = [1, 2, 3, 4, 5];
        let s = ScriptSig::from_slice(&data);
        assert!(matches!(s, ScriptBuf::Inline { .. }));
        assert_eq!(s.as_slice(), &data);
    }

    #[test]
    fn as_slice_heap() {
        let data = vec![0xFFu8; 200];
        let s = ScriptSig::from_slice(&data);
        assert!(matches!(s, ScriptBuf::Heap(_)));
        assert_eq!(s.as_slice(), &data[..]);
    }

    #[test]
    fn to_vec_matches_as_slice() {
        let data = vec![10u8; 50];
        let s = ScriptSig::from_slice(&data);
        assert_eq!(s.to_vec(), s.as_slice().to_vec());
    }

    // ── From<Vec<u8>> ────────────────────────────────────────────────────

    #[test]
    fn from_vec_small_becomes_inline() {
        let v = vec![0xAAu8; 10];
        let s: ScriptSig = v.clone().into();
        assert!(matches!(s, ScriptBuf::Inline { .. }));
        assert_eq!(s.as_slice(), &v[..]);
    }

    #[test]
    fn from_vec_large_stays_heap() {
        let v = vec![0xBBu8; 200];
        let s: ScriptSig = v.clone().into();
        assert!(matches!(s, ScriptBuf::Heap(_)));
        assert_eq!(s.as_slice(), &v[..]);
    }

    // ── PartialEq ────────────────────────────────────────────────────────

    #[test]
    fn eq_inline_vs_heap_same_content() {
        // Force one Inline (via ScriptSig with 100 bytes) and one Heap (via ScriptPubKey with same 100 bytes)
        let data = vec![0x42u8; 100];
        let inline = ScriptSig::from_slice(&data); // 100 <= 128, Inline
        let heap = ScriptPubKey::from_slice(&data); // 100 > 36, Heap
        assert!(matches!(inline, ScriptBuf::Inline { .. }));
        assert!(matches!(heap, ScriptBuf::Heap(_)));
        // They are different generic types, so compare slices
        assert_eq!(inline.as_slice(), heap.as_slice());
    }

    #[test]
    fn eq_with_raw_slice() {
        let data = [1u8, 2, 3];
        let s = ScriptSig::from_slice(&data);
        assert!(s == data[..]);
    }

    #[test]
    fn eq_with_vec() {
        let data = vec![4u8, 5, 6];
        let s = ScriptSig::from_slice(&data);
        assert!(s == data);
    }

    // ── Deref ────────────────────────────────────────────────────────────

    #[test]
    fn deref_to_slice() {
        let data = [7u8, 8, 9];
        let s = ScriptSig::from_slice(&data);
        let slice: &[u8] = &s;
        assert_eq!(slice, &data);
    }

    // ── Encode / Decode roundtrip ────────────────────────────────────────

    #[test]
    fn encode_decode_empty() {
        let s = ScriptSig::from_slice(&[]);
        let bytes = encode_val(&s);
        let decoded: ScriptSig = decode_val(&bytes);
        assert_eq!(s, decoded);
    }

    #[test]
    fn encode_decode_small() {
        let data = vec![0x76u8, 0xa9, 0x14]; // OP_DUP OP_HASH160 PUSH20
        let s = ScriptSig::from_slice(&data);
        let bytes = encode_val(&s);
        let decoded: ScriptSig = decode_val(&bytes);
        assert_eq!(s, decoded);
    }

    #[test]
    fn encode_decode_at_inline_boundary() {
        let data = vec![0xEEu8; 128];
        let s = ScriptSig::from_slice(&data);
        let bytes = encode_val(&s);
        let decoded: ScriptSig = decode_val(&bytes);
        assert_eq!(s, decoded);
    }

    #[test]
    fn encode_decode_heap() {
        let data = vec![0xDDu8; 500];
        let s = ScriptSig::from_slice(&data);
        let bytes = encode_val(&s);
        let decoded: ScriptSig = decode_val(&bytes);
        assert_eq!(s, decoded);
    }

    #[test]
    fn an_output_script_above_the_execution_limit_still_decodes() {
        let data = vec![0x6au8; 80_000];
        let s = ScriptPubKey::from_slice(&data);
        let decoded: ScriptPubKey = decode_val(&encode_val(&s));
        assert_eq!(decoded.len(), 80_000);
    }

    #[test]
    fn a_script_longer_than_a_block_is_refused() {
        let mut bytes = Vec::new();
        VarInt::from(4_usize * 1024 * 1024 + 1)
            .encode(&mut bytes)
            .expect("Vec<u8> write cannot fail");
        assert!(ScriptPubKey::decode(&mut Cursor::new(&bytes)).is_err());
    }

    #[test]
    fn decode_truncated_fails() {
        // VarInt says 100 bytes but we only provide 5
        let mut bytes = Vec::new();
        // VarInt encoding of 100: single byte 0x64
        bytes.push(0x64);
        bytes.extend_from_slice(&[0x00; 5]);
        let result = ScriptSig::decode(&mut Cursor::new(&bytes));
        assert!(result.is_err());
    }
}
