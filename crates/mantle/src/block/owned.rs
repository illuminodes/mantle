use std::io::{self, Read, Write};

use crate::codec::{Decode, Encode, Error, VarInt};
use crate::tx::Transaction;

use super::header::BlockHeader;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Encode for Block {
    fn encode(&self, w: &mut impl Write) -> Result<(), Error> {
        self.header.encode(w)?;
        VarInt::from(self.transactions.len()).encode(w)?;
        for tx in &self.transactions {
            tx.encode(w)?;
        }
        Ok(())
    }
}

impl Block {
    pub const MAX_TXS: usize = Transaction::MAX_SERIALIZED_SIZE / Transaction::MIN_SERIALIZED_SIZE;
    const PREALLOCATE_CAP: usize = 4096;

    /// Block weight per BIP141: base size × 4 + witness-only size × 1.
    ///
    /// Base size is the non-witness serialisation (no marker/flag/witness
    /// fields). Total size is the full BIP144 serialisation. The formula
    /// `base × 3 + total` is equivalent to `base × 4 + witness_extra`.
    #[must_use]
    pub fn weight(&self) -> u64 {
        let tx_count = self.transactions.len();
        let header_and_count = BlockHeader::ENCODED_LEN + VarInt::from(tx_count).encoded_len();
        let base: usize = header_and_count
            + self
                .transactions
                .iter()
                .map(Transaction::base_encoded_len)
                .sum::<usize>();
        let total: usize = header_and_count
            + self
                .transactions
                .iter()
                .map(Transaction::encoded_len)
                .sum::<usize>();
        (base as u64) * 3 + total as u64
    }

    /// Decode with caller-specified caps forwarded to each `Transaction`.
    ///
    /// # Errors
    /// Returns `InvalidData` if the tx count exceeds `MAX_TXS`, or on any I/O error.
    pub fn decode_limited<
        const MAX_TXS: usize,
        const MAX_INPUTS: usize,
        const MAX_OUTPUTS: usize,
    >(
        r: &mut impl Read,
    ) -> Result<Self, Error> {
        let header = BlockHeader::decode(r)?;
        let tx_count = VarInt::decode(r)?
            .to_usize()
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::InvalidData, e.to_string())))?;
        if tx_count > MAX_TXS {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "tx count exceeds limit",
            )));
        }
        let mut transactions = Vec::with_capacity(tx_count.min(Self::PREALLOCATE_CAP));
        for _ in 0..tx_count {
            transactions.push(Transaction::decode_limited::<MAX_INPUTS, MAX_OUTPUTS>(r)?);
        }
        Ok(Self {
            header,
            transactions,
        })
    }
}

impl Decode for Block {
    fn decode(r: &mut impl Read) -> Result<Self, Error> {
        Self::decode_limited::<
            { Self::MAX_TXS },
            { Transaction::MAX_INPUTS },
            { Transaction::MAX_OUTPUTS },
        >(r)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::amount::Satoshi;
    use crate::block::{Block, BlockHeader};
    use crate::codec::{Decode, Encode, Error};
    use crate::difficulty::{
        BlockTime, BlockVersion, CompactBits, Locktime, Nonce, Sequence, TxVersion,
    };
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
    fn block_roundtrip() {
        let block = Block {
            header: BlockHeader::new(
                BlockVersion::new(1),
                Hash256::ZERO,
                Hash256::ZERO,
                BlockTime::new(1_231_006_505),
                CompactBits::new(0x1d00_ffff),
                Nonce::new(2_083_236_893),
            ),
            transactions: vec![Transaction {
                version: TxVersion::new(1),
                inputs: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Hash256::ZERO,
                        vout: 0xffff_ffff,
                    },
                    script_sig: vec![0x04].into(),
                    sequence: Sequence::MAX,
                    witness: Witness::empty(),
                }],
                outputs: vec![TxOut {
                    value: Satoshi::new(5_000_000_000),
                    script_pubkey: vec![0xac].into(),
                }],
                locktime: Locktime::new(0),
            }],
        };
        let bytes = encode(&block);
        assert_eq!(decode::<Block>(&bytes), block);
    }

    #[test]
    fn block_zero_transactions() {
        let block = Block {
            header: BlockHeader::new(
                BlockVersion::new(1),
                Hash256::ZERO,
                Hash256::ZERO,
                BlockTime::new(0),
                CompactBits::new(0),
                Nonce::new(0),
            ),
            transactions: vec![],
        };
        let bytes = encode(&block);
        assert_eq!(decode::<Block>(&bytes), block);
    }

    #[test]
    fn block_truncated_after_tx_count() {
        let block = Block {
            header: BlockHeader::new(
                BlockVersion::new(1),
                Hash256::ZERO,
                Hash256::ZERO,
                BlockTime::new(0),
                CompactBits::new(0),
                Nonce::new(0),
            ),
            transactions: vec![],
        };
        let mut bytes = encode(&block);
        // Overwrite tx_count to claim 5 transactions, then provide none.
        let tx_count_offset = BlockHeader::ENCODED_LEN;
        bytes[tx_count_offset] = 0x05;
        let e = decode_err::<Block>(&bytes);
        assert!(matches!(e, Error::UnexpectedEof | Error::Io(_)));
    }

    #[test]
    fn block_tx_count_varint_3byte_encoding() {
        let dummy_tx = Transaction {
            version: TxVersion::new(1),
            inputs: vec![],
            outputs: vec![],
            locktime: Locktime::new(0),
        };
        let block = Block {
            header: BlockHeader::new(
                BlockVersion::new(1),
                Hash256::ZERO,
                Hash256::ZERO,
                BlockTime::new(0),
                CompactBits::new(0),
                Nonce::new(0),
            ),
            transactions: vec![dummy_tx; 253],
        };
        let bytes = encode(&block);
        assert_eq!(bytes[BlockHeader::ENCODED_LEN], 0xfd);
        assert_eq!(decode::<Block>(&bytes), block);
    }

    #[test]
    fn block_with_segwit_tx_roundtrips() {
        let block = Block {
            header: BlockHeader::new(
                BlockVersion::new(1),
                Hash256::ZERO,
                Hash256::ZERO,
                BlockTime::new(0),
                CompactBits::new(0),
                Nonce::new(0),
            ),
            transactions: vec![Transaction {
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
            }],
        };
        let bytes = encode(&block);
        assert_eq!(decode::<Block>(&bytes), block);
    }

    #[test]
    fn block_weight_legacy_only() {
        let block = Block {
            header: BlockHeader::new(
                BlockVersion::new(1),
                Hash256::ZERO,
                Hash256::ZERO,
                BlockTime::new(0),
                CompactBits::new(0),
                Nonce::new(0),
            ),
            transactions: vec![Transaction {
                version: TxVersion::new(1),
                inputs: vec![],
                outputs: vec![],
                locktime: Locktime::new(0),
            }],
        };
        let bytes = encode(&block);
        assert_eq!(block.weight(), (bytes.len() as u64) * 4);
    }

    #[test]
    fn block_weight_segwit_less_than_4x_total() {
        let block = Block {
            header: BlockHeader::new(
                BlockVersion::new(1),
                Hash256::ZERO,
                Hash256::ZERO,
                BlockTime::new(0),
                CompactBits::new(0),
                Nonce::new(0),
            ),
            transactions: vec![Transaction {
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
            }],
        };
        let total_bytes = encode(&block).len() as u64;
        assert!(block.weight() < total_bytes * 4);
        assert!(block.weight() > total_bytes);
    }

    #[test]
    fn decode_limited_rejects_too_many_txs() {
        let block = Block {
            header: BlockHeader::new(
                BlockVersion::new(1),
                Hash256::ZERO,
                Hash256::ZERO,
                BlockTime::new(0),
                CompactBits::new(0),
                Nonce::new(0),
            ),
            transactions: vec![
                Transaction {
                    version: TxVersion::new(1),
                    inputs: vec![],
                    outputs: vec![],
                    locktime: Locktime::new(0),
                };
                5
            ],
        };
        let bytes = encode(&block);
        let err = Block::decode_limited::<3, 10_000, 10_000>(&mut std::io::Cursor::new(&bytes));
        assert!(err.is_err());
    }

    #[test]
    fn a_block_with_more_than_ten_thousand_transactions_decodes() {
        let tx = Transaction {
            version: TxVersion::new(1),
            inputs: vec![],
            outputs: vec![],
            locktime: Locktime::new(0),
        };
        let block = Block {
            header: BlockHeader::new(
                BlockVersion::new(1),
                Hash256::ZERO,
                Hash256::ZERO,
                BlockTime::new(0),
                CompactBits::new(0),
                Nonce::new(0),
            ),
            transactions: vec![tx; 12_000],
        };
        let decoded = decode::<Block>(&encode(&block));
        assert_eq!(decoded.transactions.len(), 12_000);
    }

    #[test]
    fn block_truncated_inside_header() {
        let e = decode_err::<Block>(&[0u8; 40]);
        assert!(matches!(e, Error::UnexpectedEof | Error::Io(_)));
    }
}
