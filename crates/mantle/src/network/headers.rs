use std::io::{self, Read, Write};

use crate::codec::{Decode, DecodeRef, Encode, Error as CodecError, VarInt};
use crate::primitives::{BlockHeader, Hash256};

use super::envelope::ProtocolVersion;

/// `getheaders` — request headers from a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetHeadersMsg {
    pub version: ProtocolVersion,
    pub locator_hashes: Vec<Hash256>,
    pub stop_hash: Hash256,
}

impl Encode for GetHeadersMsg {
    fn encode(&self, w: &mut impl Write) -> Result<(), CodecError> {
        self.version.encode(w)?;
        VarInt::from(self.locator_hashes.len()).encode(w)?;
        for h in &self.locator_hashes {
            h.encode(w)?;
        }
        self.stop_hash.encode(w)
    }
}

impl GetHeadersMsg {
    /// Build a `getheaders` request that asks for headers built on top of
    /// `locator`, with no stop. The protocol version is 70015 (the same value
    /// every other place in this codebase that constructs `getheaders`
    /// messages picks). The locator vector contains a single hash, which is
    /// what every caller in this codebase needs — IBD bootstrap from genesis
    /// and "give me 2000 more after this hash" both fit.
    #[must_use]
    pub fn single_locator(locator: Hash256) -> Self {
        Self {
            version: ProtocolVersion::CURRENT,
            locator_hashes: vec![locator],
            stop_hash: Hash256::ZERO,
        }
    }

    /// Encode this message into a fresh `Vec<u8>`. Convenience wrapper around
    /// `Encode::encode` for the common "build a P2P payload" path.
    ///
    /// # Panics
    /// Never in practice — `Vec<u8>` cannot return an I/O error from `Write`.
    #[must_use]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf).expect("Vec<u8> writes never fail");
        buf
    }

    /// # Errors
    /// Returns `InvalidData` if the locator count exceeds `MAX_LOCATORS`, or on any I/O error.
    pub fn decode_limited<const MAX_LOCATORS: usize>(
        r: &mut impl Read,
    ) -> Result<Self, CodecError> {
        let version = ProtocolVersion::decode(r)?;
        let count = VarInt::decode(r)?.to_usize()?;
        if count > MAX_LOCATORS {
            return Err(CodecError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "locator count exceeds limit",
            )));
        }
        let mut locator_hashes = Vec::with_capacity(count);
        for _ in 0..count {
            locator_hashes.push(Hash256::decode(r)?);
        }
        let stop_hash = Hash256::decode(r)?;
        Ok(Self {
            version,
            locator_hashes,
            stop_hash,
        })
    }
}

impl Decode for GetHeadersMsg {
    fn decode(r: &mut impl Read) -> Result<Self, CodecError> {
        Self::decode_limited::<2_000>(r)
    }
}

/// `headers` — response with up to 2000 block headers.
/// Each header is followed by a `tx_count` `VarInt` (always 0x00 in this message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadersMsg(pub Vec<BlockHeader>);

impl Encode for HeadersMsg {
    fn encode(&self, w: &mut impl Write) -> Result<(), CodecError> {
        VarInt::from(self.0.len()).encode(w)?;
        for header in &self.0 {
            header.encode(w)?;
            w.write_all(&[0x00]).map_err(CodecError::Io)?; // tx_count placeholder (always zero)
        }
        Ok(())
    }
}

/// Zero-alloc lazy iterator over [`BlockHeader`] values parsed from a raw `headers` payload.
///
/// Created by [`HeadersMsg::iter_entries`]. Each entry in the wire format is an
/// 80-byte header followed by a `VarInt` `tx_count` stub (always `0x00`), which the
/// iterator consumes and discards.
#[derive(Debug)]
pub struct BlockHeaderIter<'a> {
    remaining: &'a [u8],
    left: usize,
}

impl Iterator for BlockHeaderIter<'_> {
    type Item = Result<BlockHeader, CodecError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        if self.remaining.len() < BlockHeader::ENCODED_LEN {
            self.left = 0;
            return Some(Err(CodecError::UnexpectedEof));
        }
        let (head, tail) = self.remaining.split_at(BlockHeader::ENCODED_LEN);
        let arr = match head
            .try_into()
            .map_err(|_| CodecError::Io(io::Error::from(io::ErrorKind::InvalidData)))
        {
            Ok(a) => a,
            Err(e) => {
                self.left = 0;
                return Some(Err(e));
            }
        };
        let header = BlockHeader::from_bytes(arr);
        // Consume the tx_count VarInt stub that follows every header.
        match VarInt::decode_ref(tail) {
            Ok((_tx_count, rest)) => {
                self.remaining = rest;
                self.left -= 1;
                Some(Ok(header))
            }
            Err(e) => {
                self.left = 0;
                Some(Err(e))
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl ExactSizeIterator for BlockHeaderIter<'_> {}

impl HeadersMsg {
    /// Return a zero-allocation iterator over headers in a raw `headers` payload.
    ///
    /// `buf` must start immediately after the message framing (i.e. be the raw payload).
    /// The `VarInt` count is read from the front of `buf`; no heap allocation occurs.
    ///
    /// # Errors
    /// Returns `InvalidData` if the header count exceeds `MAX_HEADERS` or if the `VarInt`
    /// cannot be decoded. Individual entries surface truncation errors as `Err` items.
    pub fn iter_entries<const MAX_HEADERS: usize>(
        buf: &[u8],
    ) -> Result<BlockHeaderIter<'_>, CodecError> {
        let (varint, rest) = VarInt::decode_ref(buf)?;
        let count = varint.to_usize()?;
        if count > MAX_HEADERS {
            return Err(CodecError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "header count exceeds limit",
            )));
        }
        Ok(BlockHeaderIter {
            remaining: rest,
            left: count,
        })
    }

    /// # Errors
    /// Returns `InvalidData` if the header count exceeds `MAX_HEADERS`, or on any I/O error.
    pub fn decode_limited<const MAX_HEADERS: usize>(r: &mut impl Read) -> Result<Self, CodecError> {
        let count = VarInt::decode(r)?.to_usize()?;
        if count > MAX_HEADERS {
            return Err(CodecError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "header count exceeds limit",
            )));
        }
        let mut headers = Vec::with_capacity(count);
        for _ in 0..count {
            headers.push(BlockHeader::decode(r)?);
            let _tx_count = VarInt::decode(r)?;
        }
        Ok(Self(headers))
    }

    /// Decode into a caller-supplied buffer, clearing it first.
    ///
    /// On the second and subsequent calls the `Vec` already has capacity, so no
    /// heap allocation occurs. Equivalent to `decode_limited` but reuses storage.
    ///
    /// # Errors
    /// Returns `InvalidData` if the header count exceeds `MAX_HEADERS`, or on any I/O error.
    pub fn decode_into_limited<const MAX_HEADERS: usize>(
        r: &mut impl Read,
        out: &mut Vec<BlockHeader>,
    ) -> Result<(), CodecError> {
        let count = VarInt::decode(r)?.to_usize()?;
        if count > MAX_HEADERS {
            return Err(CodecError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "header count exceeds limit",
            )));
        }
        out.clear();
        for _ in 0..count {
            out.push(BlockHeader::decode(r)?);
            let _tx_count = VarInt::decode(r)?;
        }
        Ok(())
    }
}

impl Decode for HeadersMsg {
    fn decode(r: &mut impl Read) -> Result<Self, CodecError> {
        Self::decode_limited::<2_000>(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{BlockTime, BlockVersion, CompactBits, Nonce};
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
    fn getheaders_roundtrip() {
        let msg = GetHeadersMsg {
            version: ProtocolVersion::CURRENT,
            locator_hashes: vec![Hash256::ZERO, Hash256::ZERO],
            stop_hash: Hash256::ZERO,
        };
        let bytes = encode(&msg);
        assert_eq!(decode::<GetHeadersMsg>(&bytes), msg);
    }

    #[test]
    fn getheaders_empty_locator() {
        let msg = GetHeadersMsg {
            version: ProtocolVersion::CURRENT,
            locator_hashes: vec![],
            stop_hash: Hash256::ZERO,
        };
        let bytes = encode(&msg);
        assert_eq!(decode::<GetHeadersMsg>(&bytes), msg);
    }

    #[test]
    fn getheaders_truncated_stop_hash() {
        let msg = GetHeadersMsg {
            version: ProtocolVersion::CURRENT,
            locator_hashes: vec![],
            stop_hash: Hash256::ZERO,
        };
        let mut bytes = encode(&msg);
        bytes.truncate(bytes.len() - 1); // shave one byte off stop_hash
        let e = decode_err::<GetHeadersMsg>(&bytes);
        assert!(matches!(e, CodecError::UnexpectedEof | CodecError::Io(_)));
    }

    #[test]
    fn headers_msg_roundtrip() {
        let header = BlockHeader::new(
            BlockVersion::new(1),
            Hash256::ZERO,
            Hash256::ZERO,
            BlockTime::new(1_231_006_505),
            CompactBits::new(0x1d00_ffff),
            Nonce::new(2_083_236_893),
        );
        let msg = HeadersMsg(vec![header]);
        let bytes = encode(&msg);
        let decoded = decode::<HeadersMsg>(&bytes);
        assert_eq!(decoded, msg);
    }

    #[test]
    fn headers_msg_empty() {
        let msg = HeadersMsg(vec![]);
        let bytes = encode(&msg);
        assert_eq!(decode::<HeadersMsg>(&bytes), msg);
    }

    #[test]
    fn headers_msg_nonzero_tx_count_placeholder() {
        let header = BlockHeader::new(
            BlockVersion::new(1),
            Hash256::ZERO,
            Hash256::ZERO,
            BlockTime::new(0),
            CompactBits::new(0x1d00_ffff),
            Nonce::new(0),
        );
        // Manually encode with tx_count = 5 instead of 0.
        let mut buf = Vec::new();
        crate::codec::VarInt::from(1u64)
            .encode(&mut buf)
            .expect("Vec<u8> write cannot fail"); // 1 header
        header.encode(&mut buf).expect("Vec<u8> write cannot fail");
        crate::codec::VarInt::from(5u64)
            .encode(&mut buf)
            .expect("Vec<u8> write cannot fail"); // non-zero tx_count
        // Decoder reads and discards tx_count regardless of value.
        let decoded = decode::<HeadersMsg>(&buf);
        assert_eq!(decoded.0.len(), 1);
    }

    #[test]
    fn headers_msg_truncated_header() {
        let header = BlockHeader::new(
            BlockVersion::new(1),
            Hash256::ZERO,
            Hash256::ZERO,
            BlockTime::new(0),
            CompactBits::new(0),
            Nonce::new(0),
        );
        let mut bytes = encode(&HeadersMsg(vec![header]));
        bytes.truncate(bytes.len() - 5); // truncate inside the header
        let e = decode_err::<HeadersMsg>(&bytes);
        assert!(matches!(e, CodecError::UnexpectedEof | CodecError::Io(_)));
    }

    // ── HeadersMsg iterator and reuse paths ───────────────────────────────────

    fn sample_header(nonce: u32) -> BlockHeader {
        BlockHeader::new(
            BlockVersion::new(1),
            Hash256::ZERO,
            Hash256::ZERO,
            BlockTime::new(0),
            CompactBits::new(0x1d00_ffff),
            Nonce::new(nonce),
        )
    }

    #[test]
    fn headers_iter_matches_owned() {
        let msg = HeadersMsg(vec![sample_header(1), sample_header(2)]);
        let bytes = encode(&msg);
        let iter_headers: Vec<BlockHeader> = HeadersMsg::iter_entries::<2_000>(&bytes)
            .expect("iter_entries must succeed on valid bytes")
            .map(|r| r.expect("each header must decode"))
            .collect();
        assert_eq!(iter_headers, msg.0);
    }

    #[test]
    fn headers_iter_empty() {
        let bytes = encode(&HeadersMsg(vec![]));
        let mut iter = HeadersMsg::iter_entries::<2_000>(&bytes)
            .expect("iter_entries must succeed on valid bytes");
        assert_eq!(iter.len(), 0);
        assert!(iter.next().is_none());
    }

    #[test]
    fn headers_iter_exact_size() {
        let msg = HeadersMsg(vec![sample_header(0), sample_header(1), sample_header(2)]);
        let bytes = encode(&msg);
        let iter = HeadersMsg::iter_entries::<2_000>(&bytes)
            .expect("iter_entries must succeed on valid bytes");
        assert_eq!(iter.len(), 3);
    }

    #[test]
    fn headers_iter_limit_exceeded() {
        let msg = HeadersMsg(vec![sample_header(0), sample_header(1)]);
        let bytes = encode(&msg);
        let err = HeadersMsg::iter_entries::<1>(&bytes).unwrap_err();
        assert!(matches!(
            err,
            CodecError::Io(_) | CodecError::LengthOverflow(_)
        ));
    }

    #[test]
    fn headers_iter_truncated_entry() {
        let msg = HeadersMsg(vec![sample_header(0), sample_header(1)]);
        let mut bytes = encode(&msg);
        // Each encoded entry is 81 bytes (80 header + 1 byte tx_count VarInt).
        bytes.truncate(1 + 81 + 40); // VarInt + full entry + partial second
        let mut iter = HeadersMsg::iter_entries::<2_000>(&bytes)
            .expect("iter_entries must succeed on valid bytes");
        assert!(iter.next().expect("first entry must be present").is_ok());
        assert!(matches!(
            iter.next()
                .expect("second entry must be present")
                .unwrap_err(),
            CodecError::UnexpectedEof | CodecError::Io(_)
        ));
        assert!(iter.next().is_none());
    }

    #[test]
    fn headers_decode_into_reuses_capacity() {
        let msg = HeadersMsg(vec![sample_header(1), sample_header(2)]);
        let bytes = encode(&msg);
        let mut buf: Vec<BlockHeader> = Vec::new();
        HeadersMsg::decode_into_limited::<2_000>(&mut std::io::Cursor::new(&bytes), &mut buf)
            .expect("decode_into_limited must succeed on valid bytes");
        assert_eq!(buf, msg.0);
        let cap_after_first = buf.capacity();

        HeadersMsg::decode_into_limited::<2_000>(&mut std::io::Cursor::new(&bytes), &mut buf)
            .expect("decode_into_limited must succeed on valid bytes");
        assert_eq!(buf, msg.0);
        assert!(buf.capacity() >= cap_after_first);
    }

    #[test]
    fn headers_decode_into_limit_exceeded() {
        let msg = HeadersMsg(vec![sample_header(0), sample_header(1)]);
        let bytes = encode(&msg);
        let mut buf = Vec::new();
        let err = HeadersMsg::decode_into_limited::<1>(&mut std::io::Cursor::new(&bytes), &mut buf)
            .unwrap_err();
        assert!(matches!(
            err,
            CodecError::Io(_) | CodecError::LengthOverflow(_)
        ));
    }
}
