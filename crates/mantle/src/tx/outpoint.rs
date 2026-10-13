use crate::codec::{Decode, DecodeRef, Encode, Error};
use crate::hash::Hash256;

// ── OutPoint ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutPoint {
    pub txid: Hash256,
    pub vout: u32,
}

impl std::hash::Hash for OutPoint {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
        // Write txid + vout as one contiguous slice. PrehashedHasher takes the
        // first 8 bytes in a single write call; two separate writes (derive)
        // would let the vout write overwrite the txid bytes entirely.
        let mut buf = [0u8; 36];
        buf[..32].copy_from_slice(self.txid.as_bytes());
        buf[32..].copy_from_slice(&self.vout.to_le_bytes());
        h.write(&buf);
    }
}

impl OutPoint {
    pub const ENCODED_LEN: usize = 36;
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
    fn outpoint_size_eq_encoded_len() {
        assert_eq!(std::mem::size_of::<OutPoint>(), OutPoint::ENCODED_LEN,);
    }
}
