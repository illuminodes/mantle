use std::io::{self, Read, Write};

use crate::codec::{Decode, DecodeRef, Encode, Error as CodecError, VarInt};
use crate::primitives::Hash256;

/// Inventory vector types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvType {
    Tx,
    Block,
    FilteredBlock,
    CmpctBlock,
    WitnessTx,
    WitnessBlock,
    Unknown(u32),
}

impl InvType {
    fn to_u32(self) -> u32 {
        match self {
            Self::Tx => 1,
            Self::Block => 2,
            Self::FilteredBlock => 3,
            Self::CmpctBlock => 4,
            Self::WitnessTx => 0x4000_0001,
            Self::WitnessBlock => 0x4000_0002,
            Self::Unknown(n) => n,
        }
    }

    fn from_u32(n: u32) -> Self {
        match n {
            1 => Self::Tx,
            2 => Self::Block,
            3 => Self::FilteredBlock,
            4 => Self::CmpctBlock,
            0x4000_0001 => Self::WitnessTx,
            0x4000_0002 => Self::WitnessBlock,
            n => Self::Unknown(n),
        }
    }
}

/// A single inventory entry: `type(4 LE) || hash(32)`.
///
/// `#[repr(C)]` guarantees the field layout matches the wire format exactly —
/// no padding, no reordering. `size_of::<InvEntry>() == 36`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InvEntry {
    kind_raw: u32,
    hash: Hash256,
}

impl InvEntry {
    pub const ENCODED_LEN: usize = 36; // 4 (type) + 32 (hash)

    #[inline]
    #[must_use]
    pub fn new(kind: InvType, hash: Hash256) -> Self {
        Self {
            kind_raw: kind.to_u32(),
            hash,
        }
    }

    #[inline]
    #[must_use]
    pub fn kind(&self) -> InvType {
        InvType::from_u32(self.kind_raw)
    }

    #[inline]
    #[must_use]
    pub fn hash(&self) -> Hash256 {
        self.hash
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let mut buf = [0u8; Self::ENCODED_LEN];
        buf[0..4].copy_from_slice(&self.kind_raw.to_le_bytes());
        buf[4..36].copy_from_slice(self.hash.as_bytes());
        buf
    }

    #[must_use]
    pub fn from_bytes(b: &[u8; Self::ENCODED_LEN]) -> Self {
        let kind_raw = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&b[4..36]);
        Self {
            kind_raw,
            hash: Hash256::from_bytes(hash),
        }
    }
}

#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for InvEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvEntry")
            .field("kind", &self.kind())
            .field("hash", &self.hash)
            .finish()
    }
}

impl Encode for InvEntry {
    #[inline]
    fn encode(&self, w: &mut impl Write) -> Result<(), CodecError> {
        w.write_all(&self.to_bytes()).map_err(CodecError::Io)
    }
}

impl Decode for InvEntry {
    #[inline]
    fn decode(r: &mut impl Read) -> Result<Self, CodecError> {
        let mut buf = [0u8; Self::ENCODED_LEN];
        r.read_exact(&mut buf).map_err(CodecError::Io)?;
        Ok(Self::from_bytes(&buf))
    }
}

impl<'a> DecodeRef<'a> for InvEntry {
    #[inline]
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), CodecError> {
        if buf.len() < Self::ENCODED_LEN {
            return Err(CodecError::UnexpectedEof);
        }
        let (head, tail) = buf.split_at(Self::ENCODED_LEN);
        let arr: &[u8; Self::ENCODED_LEN] =
            head.try_into().map_err(|_| CodecError::UnexpectedEof)?;
        Ok((Self::from_bytes(arr), tail))
    }
}

/// `inv` / `getdata` — list of inventory entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvMsg(pub Vec<InvEntry>);

impl Encode for InvMsg {
    fn encode(&self, w: &mut impl Write) -> Result<(), CodecError> {
        VarInt::from(self.0.len()).encode(w)?;
        for entry in &self.0 {
            entry.encode(w)?;
        }
        Ok(())
    }
}

/// Zero-alloc lazy iterator over `InvEntry` values parsed from a raw byte slice.
///
/// Created by [`InvMsg::iter_entries`]. Yields `Result<InvEntry, CodecError>` so
/// the caller can handle truncation errors entry-by-entry.
#[derive(Debug)]
pub struct InvEntryIter<'a> {
    remaining: &'a [u8],
    /// How many entries are left to yield (from the decoded `VarInt` count).
    left: usize,
}

impl Iterator for InvEntryIter<'_> {
    type Item = Result<InvEntry, CodecError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        if self.remaining.len() < InvEntry::ENCODED_LEN {
            self.left = 0; // prevent further iteration after error
            return Some(Err(CodecError::UnexpectedEof));
        }
        let (head, tail) = self.remaining.split_at(InvEntry::ENCODED_LEN);
        self.remaining = tail;
        self.left -= 1;
        Some(
            head.try_into()
                .map(InvEntry::from_bytes)
                .map_err(|_| CodecError::UnexpectedEof),
        )
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl ExactSizeIterator for InvEntryIter<'_> {}

impl InvMsg {
    /// Return a zero-allocation iterator over entries in a raw `inv`/`getdata` payload.
    ///
    /// `buf` must start immediately after the message framing (i.e. be the raw payload).
    /// The `VarInt` count is read from the front of `buf`; no heap allocation occurs.
    ///
    /// # Errors
    /// Returns `InvalidData` if the entry count exceeds `MAX_ENTRIES` or if the `VarInt`
    /// cannot be decoded. Individual entries surface truncation errors as `Err` items.
    pub fn iter_entries<const MAX_ENTRIES: usize>(
        buf: &[u8],
    ) -> Result<InvEntryIter<'_>, CodecError> {
        let (varint, rest) = VarInt::decode_ref(buf)?;
        let count = varint.to_usize()?;
        if count > MAX_ENTRIES {
            return Err(CodecError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "inv entry count exceeds limit",
            )));
        }
        Ok(InvEntryIter {
            remaining: rest,
            left: count,
        })
    }

    /// # Errors
    /// Returns `InvalidData` if the entry count exceeds `MAX_ENTRIES`, or on any I/O error.
    #[allow(clippy::missing_panics_doc)] // chunks_exact guarantees chunk size — unwrap cannot panic
    pub fn decode_limited<const MAX_ENTRIES: usize>(r: &mut impl Read) -> Result<Self, CodecError> {
        let count = VarInt::decode(r)?.to_usize()?;
        if count > MAX_ENTRIES {
            return Err(CodecError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "inv entry count exceeds limit",
            )));
        }
        // Read all entry bytes in one shot, then decode via the zero-copy path.
        let byte_len = count * InvEntry::ENCODED_LEN;
        let mut buf = vec![0u8; byte_len];
        r.read_exact(&mut buf).map_err(CodecError::Io)?;
        let entries = buf
            .chunks_exact(InvEntry::ENCODED_LEN)
            .map(|chunk| {
                chunk
                    .try_into()
                    .map(InvEntry::from_bytes)
                    .map_err(|_| CodecError::UnexpectedEof)
            })
            .collect::<Result<Vec<_>, CodecError>>()?;
        Ok(Self(entries))
    }

    /// Decode into a caller-supplied buffer, clearing it first.
    ///
    /// On the second and subsequent calls the `Vec` already has capacity, so no
    /// heap allocation occurs. Equivalent to `decode_limited` but reuses storage.
    ///
    /// # Errors
    /// Returns `InvalidData` if the entry count exceeds `MAX_ENTRIES`, or on any I/O error.
    #[allow(clippy::missing_panics_doc)] // chunks_exact guarantees chunk size — unwrap cannot panic
    pub fn decode_into_limited<const MAX_ENTRIES: usize>(
        r: &mut impl Read,
        out: &mut Vec<InvEntry>,
    ) -> Result<(), CodecError> {
        let count = VarInt::decode(r)?.to_usize()?;
        if count > MAX_ENTRIES {
            return Err(CodecError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "inv entry count exceeds limit",
            )));
        }
        let byte_len = count * InvEntry::ENCODED_LEN;
        let mut buf = vec![0u8; byte_len];
        r.read_exact(&mut buf).map_err(CodecError::Io)?;
        out.clear();
        out.extend(buf.chunks_exact(InvEntry::ENCODED_LEN).map(|chunk| {
            let arr: &[u8; InvEntry::ENCODED_LEN] = chunk.try_into().unwrap();
            InvEntry::from_bytes(arr)
        }));
        Ok(())
    }
}

impl Decode for InvMsg {
    fn decode(r: &mut impl Read) -> Result<Self, CodecError> {
        Self::decode_limited::<50_000>(r)
    }
}

// getdata has identical wire format
pub type GetDataMsg = InvMsg;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn encode<T: Encode>(val: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        val.encode(&mut buf).expect("Vec<u8> write cannot fail");
        buf
    }

    fn decode<T: Decode>(bytes: &[u8]) -> T {
        T::decode(&mut Cursor::new(bytes)).expect("test data must decode")
    }

    fn decode_err<T: Decode + std::fmt::Debug>(bytes: &[u8]) -> CodecError {
        T::decode(&mut std::io::Cursor::new(bytes)).unwrap_err()
    }

    #[test]
    fn inv_msg_roundtrip() {
        let inv = InvMsg(vec![
            InvEntry::new(InvType::Block, Hash256::ZERO),
            InvEntry::new(InvType::Tx, Hash256::ZERO),
        ]);
        let bytes = encode(&inv);
        assert_eq!(decode::<InvMsg>(&bytes), inv);
    }

    #[test]
    fn inv_msg_empty() {
        let msg = InvMsg(vec![]);
        let bytes = encode(&msg);
        assert_eq!(bytes, [0x00]); // VarInt(0)
        assert_eq!(decode::<InvMsg>(&bytes), msg);
    }

    #[test]
    fn inv_msg_unknown_inv_type() {
        let entry = InvEntry::new(InvType::Unknown(0xdead_beef), Hash256::ZERO);
        let msg = InvMsg(vec![entry]);
        let bytes = encode(&msg);
        let decoded = decode::<InvMsg>(&bytes);
        assert_eq!(decoded.0[0].kind(), InvType::Unknown(0xdead_beef));
    }

    #[test]
    fn inv_msg_truncated_entries() {
        let mut bytes = encode(&InvMsg(vec![
            InvEntry::new(InvType::Block, Hash256::ZERO),
            InvEntry::new(InvType::Tx, Hash256::ZERO),
        ]));
        // Truncate to cut off the second entry.
        bytes.truncate(1 + 36); // VarInt(2) + one full entry
        let e = decode_err::<InvMsg>(&bytes);
        assert!(matches!(e, CodecError::UnexpectedEof | CodecError::Io(_)));
    }

    #[test]
    fn inv_iter_matches_owned() {
        let inv = InvMsg(vec![
            InvEntry::new(InvType::Block, Hash256::ZERO),
            InvEntry::new(InvType::Tx, Hash256::ZERO),
        ]);
        let bytes = encode(&inv);
        let iter_entries: Vec<InvEntry> = InvMsg::iter_entries::<50_000>(&bytes)
            .expect("iter_entries must succeed on valid bytes")
            .map(|r| r.expect("each entry must decode"))
            .collect();
        assert_eq!(iter_entries, inv.0);
    }

    #[test]
    fn inv_iter_empty() {
        let bytes = encode(&InvMsg(vec![]));
        let mut iter = InvMsg::iter_entries::<50_000>(&bytes)
            .expect("iter_entries must succeed on valid bytes");
        assert_eq!(iter.len(), 0);
        assert!(iter.next().is_none());
    }

    #[test]
    fn inv_iter_exact_size() {
        let inv = InvMsg(vec![
            InvEntry::new(InvType::Tx, Hash256::ZERO),
            InvEntry::new(InvType::Tx, Hash256::ZERO),
            InvEntry::new(InvType::Tx, Hash256::ZERO),
        ]);
        let bytes = encode(&inv);
        let iter = InvMsg::iter_entries::<50_000>(&bytes)
            .expect("iter_entries must succeed on valid bytes");
        assert_eq!(iter.len(), 3);
    }

    #[test]
    fn inv_iter_limit_exceeded() {
        let inv = InvMsg(vec![
            InvEntry::new(InvType::Block, Hash256::ZERO),
            InvEntry::new(InvType::Block, Hash256::ZERO),
        ]);
        let bytes = encode(&inv);
        let err = InvMsg::iter_entries::<1>(&bytes).unwrap_err();
        assert!(matches!(
            err,
            CodecError::Io(_) | CodecError::LengthOverflow(_)
        ));
    }

    #[test]
    fn inv_iter_truncated_entry() {
        let inv = InvMsg(vec![
            InvEntry::new(InvType::Block, Hash256::ZERO),
            InvEntry::new(InvType::Tx, Hash256::ZERO),
        ]);
        let mut bytes = encode(&inv);
        bytes.truncate(1 + 36 + 10); // VarInt + full entry + partial second entry
        let mut iter = InvMsg::iter_entries::<50_000>(&bytes)
            .expect("iter_entries must succeed on valid bytes");
        assert!(iter.next().expect("first entry must be present").is_ok());
        assert!(matches!(
            iter.next()
                .expect("second entry must be present")
                .unwrap_err(),
            CodecError::UnexpectedEof | CodecError::Io(_)
        ));
        assert!(iter.next().is_none()); // stops after error
    }

    #[test]
    fn inv_decode_into_reuses_capacity() {
        let inv = InvMsg(vec![
            InvEntry::new(InvType::Block, Hash256::ZERO),
            InvEntry::new(InvType::Tx, Hash256::ZERO),
        ]);
        let bytes = encode(&inv);
        let mut buf: Vec<InvEntry> = Vec::new();
        InvMsg::decode_into_limited::<50_000>(&mut std::io::Cursor::new(&bytes), &mut buf)
            .expect("decode_into_limited must succeed on valid bytes");
        assert_eq!(buf, inv.0);
        let cap_after_first = buf.capacity();

        // Second call: no new allocation if same or smaller count.
        InvMsg::decode_into_limited::<50_000>(&mut std::io::Cursor::new(&bytes), &mut buf)
            .expect("decode_into_limited must succeed on valid bytes");
        assert_eq!(buf, inv.0);
        assert!(buf.capacity() >= cap_after_first);
    }

    #[test]
    fn inv_decode_into_limit_exceeded() {
        let inv = InvMsg(vec![
            InvEntry::new(InvType::Block, Hash256::ZERO),
            InvEntry::new(InvType::Block, Hash256::ZERO),
        ]);
        let bytes = encode(&inv);
        let mut buf = Vec::new();
        let err = InvMsg::decode_into_limited::<1>(&mut std::io::Cursor::new(&bytes), &mut buf)
            .unwrap_err();
        assert!(matches!(
            err,
            CodecError::Io(_) | CodecError::LengthOverflow(_)
        ));
    }

    #[test]
    fn inv_entry_size_eq_encoded_len() {
        assert_eq!(std::mem::size_of::<InvEntry>(), InvEntry::ENCODED_LEN,);
    }

    #[test]
    fn inv_entry_decode_ref_roundtrip() {
        let entry = InvEntry::new(InvType::WitnessTx, Hash256::from_bytes([0xab; 32]));
        let bytes = encode(&InvMsg(vec![entry]));
        let entry_bytes = &bytes[1..];
        let (decoded, rest) = InvEntry::decode_ref(entry_bytes).unwrap();
        assert_eq!(decoded.kind(), InvType::WitnessTx);
        assert!(rest.is_empty());
    }

    #[test]
    fn inv_entry_decode_ref_truncated() {
        let short = [0u8; InvEntry::ENCODED_LEN - 1];
        assert!(InvEntry::decode_ref(&short).is_err());
    }

    #[test]
    fn inv_entry_decode_ref_with_trailing_data() {
        let entry = InvEntry::new(InvType::Block, Hash256::ZERO);
        let bytes = encode(&InvMsg(vec![entry]));
        let mut entry_bytes = bytes[1..].to_vec();
        entry_bytes.push(0xff); // trailing byte
        let (decoded, rest) = InvEntry::decode_ref(&entry_bytes).unwrap();
        assert_eq!(decoded.kind(), InvType::Block);
        assert_eq!(rest, &[0xff]);
    }

    #[test]
    fn inv_type_all_known_variants_roundtrip() {
        for &(variant, _expected_u32) in &[
            (InvType::Tx, 1u32),
            (InvType::Block, 2),
            (InvType::FilteredBlock, 3),
            (InvType::CmpctBlock, 4),
            (InvType::WitnessTx, 0x4000_0001),
            (InvType::WitnessBlock, 0x4000_0002),
        ] {
            let entry = InvEntry::new(variant, Hash256::ZERO);
            let bytes = encode(&InvMsg(vec![entry]));
            let decoded = decode::<InvMsg>(&bytes);
            assert_eq!(decoded.0[0].kind(), variant);
        }
    }
}
