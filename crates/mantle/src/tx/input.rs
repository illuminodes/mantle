use crate::codec::{Decode, DecodeRef, Encode, Error};
use crate::difficulty::Sequence;
use crate::script::{ScriptSig, Witness};

use super::outpoint::OutPoint;

// ── TxIn ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    pub previous_output: OutPoint,
    pub script_sig: ScriptSig,
    pub sequence: Sequence,
    /// Witness stack for this input (BIP141). Empty for legacy inputs.
    /// Not included in the non-witness serialisation used for txid.
    pub witness: Witness,
}

impl Encode for TxIn {
    /// Non-witness serialisation: outpoint + scriptSig + sequence.
    /// Witness data is serialised separately by `Transaction::encode`.
    fn encode(&self, w: &mut impl std::io::Write) -> Result<(), Error> {
        self.previous_output.encode(w)?;
        self.script_sig.encode(w)?;
        self.sequence.encode(w)
    }
}

impl Decode for TxIn {
    /// Decodes the non-witness fields only. Use `Transaction::decode` to
    /// parse a full BIP144 witness transaction including witness stacks.
    fn decode(r: &mut impl std::io::Read) -> Result<Self, Error> {
        Ok(Self {
            previous_output: OutPoint::decode(r)?,
            script_sig: ScriptSig::decode(r)?,
            sequence: Sequence::decode(r)?,
            witness: Witness::empty(),
        })
    }
}

/// Borrowed view of a `TxIn` — `script_sig` is a slice into the source buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxInRef<'a> {
    pub previous_output: OutPoint,
    pub script_sig: &'a [u8],
    pub sequence: Sequence,
}

impl<'a> DecodeRef<'a> for TxInRef<'a> {
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        let (previous_output, buf) = OutPoint::decode_ref(buf)?;
        let (script_sig, buf) = <&'a [u8]>::decode_ref(buf)?;
        let (sequence, buf) = Sequence::decode_ref(buf)?;
        Ok((
            Self {
                previous_output,
                script_sig,
                sequence,
            },
            buf,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::codec::{Decode, DecodeRef, Encode, Error};
    use crate::difficulty::Sequence;
    use crate::hash::Hash256;
    use crate::script::Witness;
    use crate::tx::{OutPoint, TxIn, TxInRef};

    fn encode<T: Encode>(val: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        val.encode(&mut buf).expect("Vec<u8> write cannot fail");
        buf
    }

    fn decode<T: Decode>(bytes: &[u8]) -> T {
        T::decode(&mut Cursor::new(bytes)).expect("test data must decode")
    }

    fn decode_ref<'a, T: DecodeRef<'a>>(buf: &'a [u8]) -> (T, &'a [u8]) {
        T::decode_ref(buf).expect("test data must decode")
    }

    fn decode_err<T: Decode + std::fmt::Debug>(bytes: &[u8]) -> Error {
        T::decode(&mut std::io::Cursor::new(bytes)).unwrap_err()
    }

    #[test]
    fn txin_ref_zero_copy() {
        let txin = TxIn {
            previous_output: OutPoint {
                txid: Hash256::ZERO,
                vout: 0,
            },
            script_sig: vec![0x01, 0x02, 0x03].into(),
            sequence: Sequence::MAX,
            witness: Witness::empty(),
        };
        let bytes = encode(&txin);
        let (txin_ref, tail) = decode_ref::<TxInRef>(&bytes);
        assert_eq!(txin_ref.script_sig, &[0x01, 0x02, 0x03]);
        assert_eq!(txin_ref.sequence, Sequence::MAX);
        assert!(tail.is_empty());
        // script_sig borrows directly from bytes
        assert!(std::ptr::eq(
            txin_ref.script_sig.as_ptr(),
            &raw const bytes[OutPoint::ENCODED_LEN + 1]
        ));
    }

    #[test]
    fn txin_empty_script_sig() {
        let txin = TxIn {
            previous_output: OutPoint {
                txid: Hash256::ZERO,
                vout: 0,
            },
            script_sig: vec![].into(),
            sequence: Sequence::new(0),
            witness: Witness::empty(),
        };
        let bytes = encode(&txin);
        assert_eq!(decode::<TxIn>(&bytes), txin);

        // Zero-copy path.
        let (r, tail) = decode_ref::<TxInRef>(&bytes);
        assert!(r.script_sig.is_empty());
        assert!(tail.is_empty());
    }

    #[test]
    fn txin_truncated_script_sig() {
        let txin = TxIn {
            previous_output: OutPoint {
                txid: Hash256::ZERO,
                vout: 0,
            },
            script_sig: vec![0x01, 0x02, 0x03, 0x04].into(),
            sequence: Sequence::MAX,
            witness: Witness::empty(),
        };
        let mut bytes = encode(&txin);
        bytes.truncate(bytes.len() - 6); // cut into script_sig + sequence
        let e = decode_err::<TxIn>(&bytes);
        assert!(matches!(e, Error::UnexpectedEof | Error::Io(_)));
    }
}
