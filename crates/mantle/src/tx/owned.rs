use std::io::{Read, Write};

use crate::codec::{Decode, Encode, Error, VarInt};
use crate::difficulty::{BlockHeight, Locktime, TxVersion};
use crate::hash::{ByteSliceExt, Hash256};
use crate::script::Witness;

use super::hash::TxHash;
use super::input::TxIn;
use super::outpoint::OutPoint;
use super::output::TxOut;

// ── Transaction ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub version: TxVersion,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: Locktime,
}

impl TxHash for Transaction {
    fn txid_into(&self, buf: &mut Vec<u8>) -> Result<Hash256, Error> {
        buf.clear();
        buf.reserve(self.base_encoded_len());
        self.encode_base(buf)?;
        Ok(buf.sha256d())
    }
}

impl Transaction {
    /// BIP34: check that the coinbase scriptSig begins with a minimally-encoded
    /// push of `height`.
    ///
    /// Returns `false` if the prefix is absent or malformed.
    #[must_use]
    pub fn validate_bip34(&self, height: BlockHeight) -> bool {
        let script = &self.inputs[0].script_sig;
        let encoded = Self::bip34_height_script(height);
        script.len() >= encoded.len() && script[..encoded.len()] == encoded
    }

    /// Minimal Script push encoding of a block height as used by BIP34.
    ///
    /// # Panics
    /// Never in practice — a `u32` height encodes to at most 5 bytes, which fits in `u8`.
    #[must_use]
    pub fn bip34_height_script(height: BlockHeight) -> Vec<u8> {
        if height == BlockHeight::ZERO {
            return vec![0x00];
        }
        let mut le = height.to_u32().to_le_bytes().to_vec();
        while le.last() == Some(&0) {
            le.pop();
        }
        if le.last().is_some_and(|&b| b & 0x80 != 0) {
            le.push(0x00);
        }
        let len = u8::try_from(le.len()).expect("BIP34 height encoding ≤ 5 bytes");
        let mut out = vec![len];
        out.extend_from_slice(&le);
        out
    }

    /// `true` if any input carries a non-empty witness stack.
    #[must_use]
    pub fn is_segwit(&self) -> bool {
        self.inputs.iter().any(|i| !i.witness.is_empty())
    }

    /// Non-witness serialised byte length (used for txid and base weight).
    #[must_use]
    pub fn base_encoded_len(&self) -> usize {
        let inputs_len: usize = self
            .inputs
            .iter()
            .map(|i| {
                OutPoint::ENCODED_LEN
                    + VarInt::from(i.script_sig.len()).encoded_len()
                    + i.script_sig.len()
                    + 4
            })
            .sum();
        let outputs_len: usize = self
            .outputs
            .iter()
            .map(|o| 8 + VarInt::from(o.script_pubkey.len()).encoded_len() + o.script_pubkey.len())
            .sum();
        4 // version
            + VarInt::from(self.inputs.len()).encoded_len()
            + inputs_len
            + VarInt::from(self.outputs.len()).encoded_len()
            + outputs_len
            + 4 // locktime
    }

    /// Total serialised byte length including witness data (BIP144).
    /// Equal to `base_encoded_len` for non-segwit transactions.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        if !self.is_segwit() {
            return self.base_encoded_len();
        }
        let witness_len: usize = self.inputs.iter().map(|i| i.witness.encoded_len()).sum();
        self.base_encoded_len()
            + 2 // marker (0x00) + flag (0x01)
            + witness_len
    }

    /// Write the non-witness serialisation (version, inputs, outputs, locktime).
    /// Used for txid computation and as the base of BIP144 encoding.
    fn encode_base(&self, w: &mut impl Write) -> Result<(), Error> {
        self.version.encode(w)?;
        VarInt::from(self.inputs.len()).encode(w)?;
        for input in &self.inputs {
            input.encode(w)?;
        }
        VarInt::from(self.outputs.len()).encode(w)?;
        for output in &self.outputs {
            output.encode(w)?;
        }
        self.locktime.encode(w)
    }
}

impl Encode for Transaction {
    /// BIP144 serialisation: non-witness form for legacy transactions; marker +
    /// flag + per-input witness stacks appended after outputs for segwit ones.
    fn encode(&self, w: &mut impl Write) -> Result<(), Error> {
        if !self.is_segwit() {
            return self.encode_base(w);
        }
        self.version.encode(w)?;
        w.write_all(&[0x00, 0x01])?; // marker, flag
        VarInt::from(self.inputs.len()).encode(w)?;
        for input in &self.inputs {
            input.encode(w)?;
        }
        VarInt::from(self.outputs.len()).encode(w)?;
        for output in &self.outputs {
            output.encode(w)?;
        }
        for input in &self.inputs {
            input.witness.encode(w)?;
        }
        self.locktime.encode(w)
    }
}

impl Transaction {
    /// Largest serialization any transaction can have: a whole block.
    pub const MAX_SERIALIZED_SIZE: usize = 4_000_000;
    /// Outpoint (36) + empty script length (1) + sequence (4).
    pub const MIN_INPUT_SIZE: usize = 41;
    /// Value (8) + empty script length (1).
    pub const MIN_OUTPUT_SIZE: usize = 9;
    /// Version (4) + input count (1) + output count (1) + locktime (4).
    pub const MIN_SERIALIZED_SIZE: usize = 10;
    pub const MAX_INPUTS: usize = Self::MAX_SERIALIZED_SIZE / Self::MIN_INPUT_SIZE;
    pub const MAX_OUTPUTS: usize = Self::MAX_SERIALIZED_SIZE / Self::MIN_OUTPUT_SIZE;
    const PREALLOCATE_CAP: usize = 1024;

    /// Decode with caller-specified per-list caps.
    ///
    /// # Errors
    /// Returns `InvalidData` if either list count exceeds its cap, or on any I/O error.
    pub fn decode_limited<const MAX_INPUTS: usize, const MAX_OUTPUTS: usize>(
        r: &mut impl Read,
    ) -> Result<Self, Error> {
        let version = TxVersion::decode(r)?;

        // BIP144: read the input-count VarInt byte. If it is 0x00 we may be
        // looking at a segwit transaction (marker=0x00, flag=0x01). Read one
        // more byte to check: if it is 0x01 this is segwit and the real
        // input-count VarInt follows; if it is anything else we have a legacy
        // 0-input transaction and that byte is the output-count VarInt start.
        let first = u8::decode(r)?;
        let (segwit, input_count, legacy_output_count_first) = if first == 0x00 {
            let flag = u8::decode(r)?;
            if flag == 0x01 {
                // Segwit: read the real input count.
                let n = VarInt::decode(r)?.to_usize()?;
                (true, n, None)
            } else {
                // Legacy 0-input tx: `first`=0x00 was the input count (0
                // inputs), `flag` is the first byte of the output-count VarInt.
                (false, 0usize, Some(flag))
            }
        } else {
            let n = VarInt::decode_from_first_byte(first, r)?.to_usize()?;
            (false, n, None)
        };

        if input_count > MAX_INPUTS {
            return Err(Error::LengthOverflow(input_count as u64));
        }
        let mut inputs = Vec::with_capacity(input_count.min(Self::PREALLOCATE_CAP));
        for _ in 0..input_count {
            inputs.push(TxIn::decode(r)?);
        }

        let output_count = if let Some(b) = legacy_output_count_first {
            VarInt::decode_from_first_byte(b, r)?.to_usize()?
        } else {
            VarInt::decode(r)?.to_usize()?
        };
        if output_count > MAX_OUTPUTS {
            return Err(Error::LengthOverflow(output_count as u64));
        }
        let mut outputs = Vec::with_capacity(output_count.min(Self::PREALLOCATE_CAP));
        for _ in 0..output_count {
            outputs.push(TxOut::decode(r)?);
        }

        if segwit {
            for input in &mut inputs {
                input.witness = Witness::decode(r)?;
            }
        }

        let locktime = Locktime::decode(r)?;
        Ok(Self {
            version,
            inputs,
            outputs,
            locktime,
        })
    }
}

impl Decode for Transaction {
    fn decode(r: &mut impl Read) -> Result<Self, Error> {
        Self::decode_limited::<{ Self::MAX_INPUTS }, { Self::MAX_OUTPUTS }>(r)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::amount::Satoshi;
    use crate::codec::{Decode, Encode, Error};
    use crate::difficulty::{BlockHeight, Locktime, Sequence, TxVersion};
    use crate::hash::Hash256;
    use crate::script::Witness;
    use crate::tx::{OutPoint, Transaction, TxIn, TxOut};

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
    fn transaction_roundtrip() {
        let tx = Transaction {
            version: TxVersion::new(1),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: 0xffff_ffff,
                },
                script_sig: vec![0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04].into(),
                sequence: Sequence::MAX,
                witness: Witness::empty(),
            }],
            outputs: vec![TxOut {
                value: Satoshi::new(5_000_000_000),
                script_pubkey: vec![0x41, 0xac].into(),
            }],
            locktime: Locktime::new(0),
        };
        let bytes = encode(&tx);
        assert_eq!(decode::<Transaction>(&bytes), tx);
    }

    #[test]
    fn transaction_empty_inputs_outputs() {
        let tx = Transaction {
            version: TxVersion::new(1),
            inputs: vec![],
            outputs: vec![],
            locktime: Locktime::new(0),
        };
        let bytes = encode(&tx);
        assert_eq!(decode::<Transaction>(&bytes), tx);
    }

    #[test]
    fn transaction_negative_version() {
        let tx = Transaction {
            version: TxVersion::new(-1),
            inputs: vec![],
            outputs: vec![],
            locktime: Locktime::new(u32::MAX),
        };
        let bytes = encode(&tx);
        assert_eq!(decode::<Transaction>(&bytes), tx);
    }

    #[test]
    fn transaction_truncated_after_input_count() {
        // version(4) + VarInt(1) then nothing.
        let buf = [0x01, 0x00, 0x00, 0x00, 0x01];
        let e = decode_err::<Transaction>(&buf);
        assert!(matches!(e, Error::UnexpectedEof | Error::Io(_)));
    }

    #[test]
    fn transaction_input_count_exceeds_data() {
        let mut buf = vec![0x01, 0x00, 0x00, 0x00];
        buf.push(0x64);
        let e = decode_err::<Transaction>(&buf);
        assert!(matches!(e, Error::UnexpectedEof | Error::Io(_)));
    }

    #[test]
    fn segwit_tx_roundtrip() {
        let tx = Transaction {
            version: TxVersion::new(2),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([0x11; 32]),
                    vout: 0,
                },
                script_sig: Vec::<u8>::new().into(),
                sequence: Sequence::new(0xffff_fffe),
                witness: Witness::from_slice(&[&[0xde, 0xad, 0xbe, 0xef][..], &[0x01; 33][..]]),
            }],
            outputs: vec![TxOut {
                value: Satoshi::new(99_000),
                script_pubkey: vec![0x00, 0x14, 0xaa, 0xbb, 0xcc].into(),
            }],
            locktime: Locktime::new(0),
        };
        let bytes = encode(&tx);
        let decoded = decode::<Transaction>(&bytes);
        assert_eq!(decoded, tx);
        assert!(decoded.is_segwit());
    }

    #[test]
    fn segwit_tx_encoded_len_includes_witness() {
        let tx = Transaction {
            version: TxVersion::new(2),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: 0,
                },
                script_sig: Vec::<u8>::new().into(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[&[0xab; 72][..], &[0xcd; 33][..]]),
            }],
            outputs: vec![TxOut {
                value: Satoshi::new(1000),
                script_pubkey: vec![0x00, 0x14].into(),
            }],
            locktime: Locktime::new(0),
        };
        let bytes = encode(&tx);
        assert_eq!(tx.encoded_len(), bytes.len());
        assert!(tx.encoded_len() > tx.base_encoded_len());
    }

    #[test]
    fn segwit_txid_differs_from_wire_hash() {
        use crate::tx::TxHash;
        let tx = Transaction {
            version: TxVersion::new(2),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: 0,
                },
                script_sig: Vec::<u8>::new().into(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[&[0xab; 72][..], &[0xcd; 33][..]]),
            }],
            outputs: vec![TxOut {
                value: Satoshi::new(1000),
                script_pubkey: vec![0x00, 0x14].into(),
            }],
            locktime: Locktime::new(0),
        };
        let txid = tx.txid().unwrap();
        let wire_hash = Hash256::hash(&encode(&tx));
        assert_ne!(txid, wire_hash);
    }

    #[test]
    fn legacy_tx_encoded_len_eq_base() {
        let tx = Transaction {
            version: TxVersion::new(1),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: 0,
                },
                script_sig: vec![0x51].into(),
                sequence: Sequence::MAX,
                witness: Witness::empty(),
            }],
            outputs: vec![],
            locktime: Locktime::new(0),
        };
        assert!(!tx.is_segwit());
        assert_eq!(tx.encoded_len(), tx.base_encoded_len());
    }

    #[test]
    fn bip34_height_script_zero() {
        assert_eq!(
            Transaction::bip34_height_script(BlockHeight::ZERO),
            vec![0x00]
        );
    }

    #[test]
    fn bip34_height_script_small() {
        let script = Transaction::bip34_height_script(BlockHeight::new(1));
        assert_eq!(script, vec![0x01, 0x01]);
    }

    #[test]
    fn bip34_height_script_128_needs_padding() {
        let script = Transaction::bip34_height_script(BlockHeight::new(128));
        assert_eq!(script, vec![0x02, 0x80, 0x00]);
    }

    #[test]
    fn bip34_validate_correct() {
        use crate::difficulty::BlockHeight;
        let height = BlockHeight::new(500_000);
        let script_prefix = Transaction::bip34_height_script(height);
        let mut script_sig: Vec<u8> = script_prefix;
        script_sig.extend_from_slice(b"extra coinbase data");
        let tx = Transaction {
            version: TxVersion::new(1),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: u32::MAX,
                },
                script_sig: script_sig.into(),
                sequence: Sequence::MAX,
                witness: Witness::empty(),
            }],
            outputs: vec![TxOut {
                value: Satoshi::new(50 * 100_000_000),
                script_pubkey: vec![0x76, 0xa9].into(),
            }],
            locktime: Locktime::new(0),
        };
        assert!(tx.validate_bip34(height));
        assert!(!tx.validate_bip34(BlockHeight::new(500_001)));
    }

    #[test]
    fn decode_limited_rejects_too_many_inputs() {
        let tx = Transaction {
            version: TxVersion::new(1),
            inputs: (0..5)
                .map(|i| TxIn {
                    previous_output: OutPoint {
                        txid: Hash256::ZERO,
                        vout: i,
                    },
                    script_sig: vec![].into(),
                    sequence: Sequence::MAX,
                    witness: Witness::empty(),
                })
                .collect(),
            outputs: vec![],
            locktime: Locktime::new(0),
        };
        let bytes = encode(&tx);
        let err = Transaction::decode_limited::<3, 10_000>(&mut std::io::Cursor::new(&bytes));
        assert!(err.is_err());
    }

    #[test]
    fn decode_limited_rejects_too_many_outputs() {
        let tx = Transaction {
            version: TxVersion::new(1),
            inputs: vec![],
            outputs: (0..5)
                .map(|_| TxOut {
                    value: Satoshi::new(1000),
                    script_pubkey: vec![0x51].into(),
                })
                .collect(),
            locktime: Locktime::new(0),
        };
        let bytes = encode(&tx);
        let err = Transaction::decode_limited::<10_000, 3>(&mut std::io::Cursor::new(&bytes));
        assert!(err.is_err());
    }

    #[test]
    fn a_transaction_with_twenty_thousand_outputs_decodes() {
        let tx = Transaction {
            version: TxVersion::new(1),
            inputs: vec![],
            outputs: (0..20_000)
                .map(|_| TxOut {
                    value: Satoshi::new(546),
                    script_pubkey: vec![0x51].into(),
                })
                .collect(),
            locktime: Locktime::new(0),
        };
        let decoded = decode::<Transaction>(&encode(&tx));
        assert_eq!(decoded.outputs.len(), 20_000);
    }

    #[test]
    fn a_count_no_transaction_can_hold_is_rejected_without_allocating() {
        let mut buf = Vec::new();
        TxVersion::new(1).encode(&mut buf).unwrap();
        buf.push(0xfe);
        buf.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(Transaction::decode(&mut std::io::Cursor::new(&buf)).is_err());
    }

    #[test]
    fn decode_limited_segwit_marker_zero_inputs_nonzero_flag() {
        // Craft a legacy tx where the first byte after version is 0x00
        // (zero inputs) and the next byte is NOT 0x01 (not a segwit flag).
        // This exercises the legacy_output_count_first path.
        //
        // version(4) + 0x00(input_count=0) + 0x02(output_count=2 via flag byte)
        // + 2 outputs + locktime
        let mut buf = Vec::new();
        TxVersion::new(1).encode(&mut buf).unwrap();
        buf.push(0x00); // input count = 0 (also looks like segwit marker)
        buf.push(0x02); // NOT 0x01 so not segwit; treated as output_count first byte = 2
        // Two minimal outputs.
        for _ in 0..2 {
            Satoshi::new(500).encode(&mut buf).unwrap();
            // script_pubkey: VarInt len + bytes
            buf.push(0x01); // 1-byte script
            buf.push(0x51); // OP_1
        }
        Locktime::new(0).encode(&mut buf).unwrap();

        let tx = Transaction::decode_limited::<10_000, 10_000>(
            &mut std::io::Cursor::new(&buf),
        )
        .expect("should decode as legacy 0-input tx");
        assert_eq!(tx.inputs.len(), 0);
        assert_eq!(tx.outputs.len(), 2);
    }
}
