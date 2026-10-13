use crate::codec::{Decode, DecodeRef, Encode, Error};
use crate::hash::Hash256;

// ── OutPoint ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutPoint {
    pub txid: Hash256,
    pub vout: u32,
}

impl std::hash::Hash for OutPoint {
    /// Writes one 8-byte word: the txid's first 8 bytes with the vout spread
    /// across all 64 bits. A prehashing hasher keeps only the first 8 bytes it
    /// is given, so without the vout every output of one transaction would
    /// share a bucket.
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
        h.write(&self.spread_key().to_le_bytes());
    }
}

impl OutPoint {
    pub const ENCODED_LEN: usize = 36;

    const VOUT_SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;

    /// The txid's first 8 bytes, xored with the vout times a 64-bit odd
    /// constant, so outputs of one transaction get unrelated keys.
    #[inline]
    #[must_use]
    pub fn spread_key(&self) -> u64 {
        let bytes = self.txid.as_bytes();
        let txid = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        txid ^ u64::from(self.vout).wrapping_mul(Self::VOUT_SPREAD)
    }
}

impl Encode for OutPoint {
    fn encode(&self, w: &mut impl std::io::Write) -> Result<(), Error> {
        self.txid.encode(w)?;
        self.vout.encode(w)
    }
}

impl Decode for OutPoint {
    fn decode(r: &mut impl std::io::Read) -> Result<Self, Error> {
        Ok(Self {
            txid: Hash256::decode(r)?,
            vout: u32::decode(r)?,
        })
    }
}

impl<'a> DecodeRef<'a> for OutPoint {
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        let (txid, buf) = Hash256::decode_ref(buf)?;
        let (vout, buf) = u32::decode_ref(buf)?;
        Ok((Self { txid, vout }, buf))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::codec::{Decode, Encode, Error};
    use crate::hash::Hash256;

    use super::OutPoint;

    fn encode<T: Encode>(val: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        val.encode(&mut buf).expect("Vec<u8> write cannot fail");
        buf
    }

    fn decode<T: Decode>(bytes: &[u8]) -> T {
        T::decode(&mut Cursor::new(bytes)).expect("test data must decode")
    }

    fn decode_err<T: Decode + std::fmt::Debug>(bytes: &[u8]) -> Error {
        T::decode(&mut std::io::Cursor::new(bytes)).unwrap_err()
    }

    #[test]
    fn outpoint_roundtrip() {
        let op = OutPoint {
            txid: Hash256::ZERO,
            vout: 3,
        };
        let bytes = encode(&op);
        assert_eq!(bytes.len(), OutPoint::ENCODED_LEN);
        assert_eq!(decode::<OutPoint>(&bytes), op);
    }

    #[test]
    fn outpoint_coinbase_vout() {
        let op = OutPoint {
            txid: Hash256::ZERO,
            vout: u32::MAX,
        };
        let bytes = encode(&op);
        assert_eq!(bytes.len(), OutPoint::ENCODED_LEN);
        assert_eq!(decode::<OutPoint>(&bytes), op);
    }

    #[test]
    fn outpoint_truncated_txid() {
        let e = decode_err::<OutPoint>(&[0u8; 16]);
        assert!(matches!(e, Error::UnexpectedEof | Error::Io(_)));
    }

    #[test]
    fn outputs_of_one_transaction_hash_to_different_prehashed_keys() {
        use std::hash::BuildHasher;
        let txid = Hash256::hash(b"fan-out");
        let keys: std::collections::HashSet<u64> = (0..1_000)
            .map(|vout| crate::collections::BuildPrehashedHasher.hash_one(OutPoint { txid, vout }))
            .collect();
        assert_eq!(keys.len(), 1_000);
    }

    #[test]
    fn outpoint_size_eq_encoded_len() {
        assert_eq!(std::mem::size_of::<OutPoint>(), OutPoint::ENCODED_LEN,);
    }
}
