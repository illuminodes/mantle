use std::fmt;
use std::io::Cursor;

use mantle::codec::Decode;
use mantle::primitives::{Block, Hash256, TxHash};
use mantle_consensus::merkle::compute_merkle_root;

/// Self-consistency checks on raw block bytes that need no chain context:
/// the bytes decode as exactly one block, the header hashes to the requested
/// hash, and the header's merkle root commits to the transactions.
pub struct BlockIntegrity;

#[derive(Debug, PartialEq, Eq)]
pub enum IntegrityError {
    Decode(String),
    TrailingBytes(u64),
    HashMismatch { expected: Hash256, got: Hash256 },
    NoTransactions,
    MerkleMismatch { header: Hash256, computed: Hash256 },
}

impl fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "does not decode as a block: {e}"),
            Self::TrailingBytes(n) => write!(f, "{n} bytes after the last transaction"),
            Self::HashMismatch { expected, got } => {
                write!(f, "header hashes to {got}, expected {expected}")
            }
            Self::NoTransactions => f.write_str("block has no transactions"),
            Self::MerkleMismatch { header, computed } => {
                write!(f, "merkle root {computed} does not match header {header}")
            }
        }
    }
}

impl std::error::Error for IntegrityError {}

impl BlockIntegrity {
    /// # Errors
    /// Returns the first integrity check that `bytes` fails.
    pub fn check(bytes: &[u8], expected: Hash256) -> Result<Block, IntegrityError> {
        let mut cursor = Cursor::new(bytes);
        let block = Block::decode(&mut cursor).map_err(|e| IntegrityError::Decode(e.to_string()))?;
        let trailing = bytes.len() as u64 - cursor.position();
        if trailing != 0 {
            return Err(IntegrityError::TrailingBytes(trailing));
        }
        let got = block.header.hash();
        if got != expected {
            return Err(IntegrityError::HashMismatch { expected, got });
        }
        let txids = block
            .transactions
            .iter()
            .map(TxHash::txid)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| IntegrityError::Decode(e.to_string()))?;
        let computed = compute_merkle_root(&txids).ok_or(IntegrityError::NoTransactions)?;
        let header = block.header.merkle_root();
        if computed != header {
            return Err(IntegrityError::MerkleMismatch { header, computed });
        }
        Ok(block)
    }
}

#[cfg(test)]
mod tests {
    use mantle::codec::Encode;
    use mantle::primitives::{
        BlockHeader, BlockTime, BlockVersion, CompactBits, Locktime, Nonce, OutPoint, Satoshi,
        Sequence, Transaction, TxIn, TxOut, TxVersion, Witness,
    };

    use super::*;

    fn block() -> Block {
        let coinbase = Transaction {
            version: TxVersion::new(1),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: u32::MAX,
                },
                script_sig: vec![0x01, 0x07].into(),
                sequence: Sequence::MAX,
                witness: Witness::empty(),
            }],
            outputs: vec![TxOut {
                value: Satoshi::new(50),
                script_pubkey: vec![0x51].into(),
            }],
            locktime: Locktime::new(0),
        };
        let root = coinbase.txid().expect("txid");
        Block {
            header: BlockHeader::new(
                BlockVersion::new(1),
                Hash256::ZERO,
                root,
                BlockTime::new(1_231_006_505),
                CompactBits::new(0x1d00_ffff),
                Nonce::new(0),
            ),
            transactions: vec![coinbase],
        }
    }

    fn bytes(block: &Block) -> Vec<u8> {
        let mut out = Vec::new();
        block.encode(&mut out).expect("encode");
        out
    }

    #[test]
    fn accepts_consistent_block() {
        let b = block();
        assert_eq!(BlockIntegrity::check(&bytes(&b), b.header.hash()), Ok(b));
    }

    #[test]
    fn rejects_wrong_hash() {
        let b = block();
        let err = BlockIntegrity::check(&bytes(&b), Hash256::ZERO).unwrap_err();
        assert!(matches!(err, IntegrityError::HashMismatch { .. }));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let b = block();
        let mut raw = bytes(&b);
        raw.push(0);
        assert_eq!(
            BlockIntegrity::check(&raw, b.header.hash()),
            Err(IntegrityError::TrailingBytes(1))
        );
    }

    #[test]
    fn rejects_merkle_mismatch() {
        let mut b = block();
        b.transactions[0].outputs[0].value = Satoshi::new(51);
        let err = BlockIntegrity::check(&bytes(&b), b.header.hash()).unwrap_err();
        assert!(matches!(err, IntegrityError::MerkleMismatch { .. }));
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(
            BlockIntegrity::check(&[1, 2, 3], Hash256::ZERO),
            Err(IntegrityError::Decode(_))
        ));
    }
}
