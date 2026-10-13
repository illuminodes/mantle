use crate::amount::Satoshi;
use crate::codec::{Decode, DecodeRef, Encode, Error};
use crate::script::ScriptPubKey;

// ── TxOut ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    pub value: Satoshi,
    pub script_pubkey: ScriptPubKey,
}

impl Encode for TxOut {
    fn encode(&self, w: &mut impl std::io::Write) -> Result<(), Error> {
        self.value.encode(w)?;
        self.script_pubkey.encode(w)
    }
}

impl Decode for TxOut {
    fn decode(r: &mut impl std::io::Read) -> Result<Self, Error> {
        Ok(Self {
            value: Satoshi::decode(r)?,
            script_pubkey: ScriptPubKey::decode(r)?,
        })
    }
}

/// Borrowed view of a `TxOut` — `script_pubkey` is a slice into the source buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxOutRef<'a> {
    pub value: Satoshi,
    pub script_pubkey: &'a [u8],
}

impl<'a> DecodeRef<'a> for TxOutRef<'a> {
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        let (value, buf) = Satoshi::decode_ref(buf)?;
        let (script_pubkey, buf) = <&'a [u8]>::decode_ref(buf)?;
        Ok((
            Self {
                value,
                script_pubkey,
            },
            buf,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::amount::Satoshi;
    use crate::codec::{Decode, DecodeRef, Encode, Error};
    use crate::tx::{TxOut, TxOutRef};

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
    fn txout_ref_zero_copy() {
        let txout = TxOut {
            value: Satoshi::new(5_000_000_000),
            script_pubkey: vec![0xac, 0xbd].into(),
        };
        let bytes = encode(&txout);
        let (txout_ref, tail) = decode_ref::<TxOutRef>(&bytes);
        assert_eq!(txout_ref.value, Satoshi::new(5_000_000_000));
        assert_eq!(txout_ref.script_pubkey, &[0xac, 0xbd]);
        assert!(tail.is_empty());
    }

    #[test]
    fn txout_zero_value() {
        let txout = TxOut {
            value: Satoshi::ZERO,
            script_pubkey: vec![0x6a].into(),
        }; // OP_RETURN
        let bytes = encode(&txout);
        assert_eq!(decode::<TxOut>(&bytes), txout);
    }

    #[test]
    fn txout_max_value() {
        let txout = TxOut {
            value: Satoshi::new(u64::MAX),
            script_pubkey: vec![].into(),
        };
        let bytes = encode(&txout);
        assert_eq!(decode::<TxOut>(&bytes), txout);
    }

    #[test]
    fn txout_truncated_script_pubkey() {
        let txout = TxOut {
            value: Satoshi::new(1000),
            script_pubkey: vec![0x76, 0xa9, 0x14].into(),
        };
        let mut bytes = encode(&txout);
        bytes.truncate(bytes.len() - 2);
        let e = decode_err::<TxOut>(&bytes);
        assert!(matches!(e, Error::UnexpectedEof | Error::Io(_)));
    }
}
