use std::io;

use crate::codec::{DecodeRef, Error, VarInt};
use crate::tx::TransactionRef;

use super::header::BlockHeader;

/// Zero-copy borrowed view of a `Block`.
///
/// Decodes the header and a `Vec<TransactionRef<'a>>` from a wire buffer,
/// using a caller-supplied arena to materialise the non-witness preimage of
/// any segwit transactions. After construction every transaction's
/// [`TransactionRef::txid_into`] is correct (legacy txs alias the wire
/// directly; segwit txs alias the arena).
///
/// Both the wire bytes and the arena are caller-owned. The lifetime `'a`
/// is the shorter of the two, so a `BlockRef` can outlive its decoder but
/// not its data.
/// Two lifetimes:
/// - `'wire` — the block wire bytes (slab slot / network buffer).
/// - `'arena` — the decode arena (segwit non-witness preimages).
///
/// `'wire: 'arena` — wire data outlives the arena, so legacy txs
/// can alias wire bytes through `non_witness_raw`.
#[derive(Debug)]
pub struct BlockRef<'wire, 'arena>
where
    'wire: 'arena,
{
    pub header: BlockHeader,
    pub raw: &'wire [u8],
    pub txs: &'arena [TransactionRef<'wire, 'arena>],
}

/// Reusable decode buffers for zero-allocation block decoding.
///
/// Two lifetimes mirror [`BlockRef`]:
/// - `'wire`  — wire data (slab slot / network buffer).
/// - `'arena` — the arena's own heap storage.
///
/// Create with [`DecodeArena::new`], call [`decode`](Self::decode) in
/// a loop.  Capacity is preserved across calls; the `&'arena mut self`
/// borrow is released when the returned `BlockRef` drops.
pub struct DecodeArena<'wire, 'arena>
where
    'wire: 'arena,
{
    arena: Vec<u8>,
    txs: Vec<TransactionRef<'wire, 'arena>>,
    segwit_spans: Vec<(usize, usize, usize)>,
}

impl DecodeArena<'_, '_> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            arena: Vec::new(),
            txs: Vec::new(),
            segwit_spans: Vec::new(),
        }
    }
}

impl Default for DecodeArena<'_, '_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'wire, 'arena> DecodeArena<'wire, 'arena>
where
    'wire: 'arena,
{
    /// Decode a block from `wire`, reusing internal buffers.
    ///
    /// # Errors
    /// Propagates I/O errors from the decoder.
    pub fn decode(
        &'arena mut self,
        wire: &'wire [u8],
    ) -> Result<BlockRef<'wire, 'arena>, Error> {
        self.arena.clear();
        self.txs.clear();
        self.segwit_spans.clear();

        let (header, rest) = BlockHeader::decode_ref(wire)?;
        let (vi, mut rest) = VarInt::decode_ref(rest)?;
        let tx_count = vi
            .to_usize()
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::InvalidData, e.to_string())))?;

        self.arena.reserve(rest.len());
        self.txs.reserve(tx_count.saturating_sub(self.txs.capacity()));

        for i in 0..tx_count {
            let (tx, after) = TransactionRef::decode_ref(rest)?;

            if tx.is_segwit {
                let arena_start = self.arena.len();
                let raw = tx.raw;
                let inputs_region_start = 4 + 2;
                let witnesses_start_offset = if tx.witnesses_buf.is_empty() {
                    raw.len() - 4
                } else {
                    (tx.witnesses_buf.as_ptr() as usize) - (raw.as_ptr() as usize)
                };
                self.arena.extend_from_slice(&raw[..4]);
                self.arena.extend_from_slice(&raw[inputs_region_start..witnesses_start_offset]);
                self.arena.extend_from_slice(&raw[raw.len() - 4..]);
                self.segwit_spans.push((i, arena_start, self.arena.len()));
            }

            self.txs.push(tx);
            rest = after;
        }

        for &(idx, start, end) in &self.segwit_spans {
            self.txs[idx].non_witness_raw = &self.arena[start..end];
        }

        let raw_consumed = wire.len() - rest.len();
        let raw = &wire[..raw_consumed];

        Ok(BlockRef {
            header,
            raw,
            txs: &self.txs,
        })
    }
}

impl<'wire, 'arena> BlockRef<'wire, 'arena>
where
    'wire: 'arena,
{
    /// Convenience wrapper — allocates fresh buffers per call.
    ///
    /// For hot loops, prefer [`DecodeArena::decode`].
    ///
    /// # Errors
    /// Propagates I/O errors from the decoder.
    pub fn decode_with_arena(
        wire: &'wire [u8],
        arena_buf: &'arena mut Vec<u8>,
        txs_buf: &'arena mut Vec<TransactionRef<'wire, 'arena>>,
    ) -> Result<Self, Error> {
        arena_buf.clear();
        txs_buf.clear();

        let mut segwit_spans: Vec<(usize, usize, usize)> = Vec::new();

        let (header, rest) = BlockHeader::decode_ref(wire)?;
        let (vi, mut rest) = VarInt::decode_ref(rest)?;
        let tx_count = vi
            .to_usize()
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::InvalidData, e.to_string())))?;

        arena_buf.reserve(rest.len());

        let txs = txs_buf;
        txs.reserve(tx_count.saturating_sub(txs.capacity()));

        for i in 0..tx_count {
            let (tx, after) = TransactionRef::decode_ref(rest)?;

            if tx.is_segwit {
                let arena_start = arena_buf.len();
                let raw = tx.raw;
                let inputs_region_start = 4 + 2;
                let witnesses_start_offset = if tx.witnesses_buf.is_empty() {
                    raw.len() - 4
                } else {
                    (tx.witnesses_buf.as_ptr() as usize) - (raw.as_ptr() as usize)
                };
                arena_buf.extend_from_slice(&raw[..4]);
                arena_buf.extend_from_slice(&raw[inputs_region_start..witnesses_start_offset]);
                arena_buf.extend_from_slice(&raw[raw.len() - 4..]);
                segwit_spans.push((i, arena_start, arena_buf.len()));
            }

            txs.push(tx);
            rest = after;
        }

        for &(idx, start, end) in &segwit_spans {
            txs[idx].non_witness_raw = &arena_buf[start..end];
        }

        let raw_consumed = wire.len() - rest.len();
        let raw = &wire[..raw_consumed];

        Ok(Self {
            header,
            raw,
            txs: txs.as_slice(),
        })
    }

    /// Number of transactions in this block.
    #[must_use]
    pub fn tx_count(&self) -> usize {
        self.txs.len()
    }

    /// Iterate transactions.
    pub fn transactions(&self) -> std::slice::Iter<'_, TransactionRef<'wire, 'arena>> {
        self.txs.iter()
    }
}

#[cfg(test)]
mod tests {
    use crate::amount::Satoshi;
    use crate::block::{Block, BlockHeader, BlockRef};
    use crate::codec::Encode;
    use crate::difficulty::{
        BlockTime, BlockVersion, CompactBits, Locktime, Nonce, Sequence, TxVersion,
    };
    use crate::hash::Hash256;
    use crate::script::Witness;
    use crate::tx::{OutPoint, Transaction, TxHash, TxIn, TxOut};

    fn encode<T: Encode>(val: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        val.encode(&mut buf).expect("Vec<u8> write cannot fail");
        buf
    }

    fn make_tx() -> Transaction {
        Transaction {
            version: TxVersion::new(2),
            inputs: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: Hash256::from_bytes([0xab; 32]),
                        vout: 1,
                    },
                    script_sig: vec![0x01, 0x02, 0x03].into(),
                    sequence: Sequence::new(0xffff_fffe),
                    witness: Witness::empty(),
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: Hash256::from_bytes([0xcd; 32]),
                        vout: 0,
                    },
                    script_sig: vec![].into(),
                    sequence: Sequence::new(0),
                    witness: Witness::empty(),
                },
            ],
            outputs: vec![
                TxOut {
                    value: Satoshi::new(50_000),
                    script_pubkey: vec![0x76, 0xa9].into(),
                },
                TxOut {
                    value: Satoshi::ZERO,
                    script_pubkey: vec![].into(),
                },
            ],
            locktime: Locktime::new(800_000),
        }
    }

    fn make_segwit_tx() -> Transaction {
        Transaction {
            version: TxVersion::new(2),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([0x11u8; 32]),
                    vout: 0,
                },
                script_sig: Vec::<u8>::new().into(),
                sequence: Sequence::new(0xffff_fffe),
                witness: Witness::from_slice(&[
                    &[0xde, 0xad, 0xbe, 0xef][..],
                    &[0x01, 0x02, 0x03, 0x04, 0x05][..],
                ]),
            }],
            outputs: vec![TxOut {
                value: Satoshi::new(99_000),
                script_pubkey: vec![0x00, 0x14, 0xaa, 0xbb, 0xcc].into(),
            }],
            locktime: Locktime::new(0),
        }
    }

    #[test]
    fn block_ref_mixed_txids_match_owned() {
        let legacy = make_tx();
        let segwit = make_segwit_tx();
        let block = Block {
            header: BlockHeader::new(
                BlockVersion::new(1),
                Hash256::ZERO,
                Hash256::ZERO,
                BlockTime::new(1_700_000_000),
                CompactBits::new(0x1d00_ffff),
                Nonce::new(0),
            ),
            transactions: vec![legacy.clone(), segwit.clone()],
        };
        let bytes = encode(&block);
        let mut arena = Vec::new();

        let expected_legacy = legacy.txid().expect("legacy txid");
        let expected_segwit = segwit.txid().expect("segwit txid");

        let mut txs_buf = Vec::new();
        let block_ref = BlockRef::decode_with_arena(&bytes, &mut arena, &mut txs_buf)
            .expect("BlockRef decode must succeed");
        assert_eq!(block_ref.tx_count(), 2);

        let tx0 = &block_ref.txs[0];
        let tx1 = &block_ref.txs[1];
        assert!(!tx0.is_segwit);
        assert!(tx1.is_segwit);

        assert_eq!(
            tx0.txid_into(&mut Vec::new()).expect("hash"),
            expected_legacy
        );
        assert_eq!(
            tx1.txid_into(&mut Vec::new()).expect("hash"),
            expected_segwit
        );
    }

    #[test]
    fn block_ref_arena_reuse_clears_between_calls() {
        let segwit = make_segwit_tx();
        let block = Block {
            header: BlockHeader::new(
                BlockVersion::new(1),
                Hash256::ZERO,
                Hash256::ZERO,
                BlockTime::new(0),
                CompactBits::new(0x1d00_ffff),
                Nonce::new(0),
            ),
            transactions: vec![segwit.clone()],
        };
        let bytes = encode(&block);
        let mut arena = Vec::with_capacity(1024);
        // First decode populates the arena; second decode must clear it
        // (otherwise the arena would grow unboundedly across IBD blocks).
        {
            let mut txs_buf = Vec::new();
            let _br =
                BlockRef::decode_with_arena(&bytes, &mut arena, &mut txs_buf).expect("decode 1");
        }
        let cap_before = arena.capacity();
        {
            let mut txs_buf = Vec::new();
            let br2 =
                BlockRef::decode_with_arena(&bytes, &mut arena, &mut txs_buf).expect("decode 2");
            assert_eq!(
                br2.txs[0].txid_into(&mut Vec::new()).expect("hash"),
                segwit.txid().expect("owned txid")
            );
        }
        // Capacity should not have grown (the second pass fits within the
        // first pass's high-water mark).
        assert!(arena.capacity() >= cap_before);
    }

    #[test]
    fn block_ref_zero_transactions() {
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
        let mut arena = Vec::new();
        let mut txs_buf = Vec::new();
        let br = BlockRef::decode_with_arena(&bytes, &mut arena, &mut txs_buf)
            .expect("empty block must decode");
        assert_eq!(br.tx_count(), 0);
        assert_eq!(br.transactions().count(), 0);
        assert!(arena.is_empty());
    }

    #[test]
    fn block_ref_truncated_wire_fails() {
        let block = Block {
            header: BlockHeader::new(
                BlockVersion::new(1),
                Hash256::ZERO,
                Hash256::ZERO,
                BlockTime::new(0),
                CompactBits::new(0),
                Nonce::new(0),
            ),
            transactions: vec![make_tx()],
        };
        let bytes = encode(&block);
        let truncated = &bytes[..bytes.len() / 2];
        let mut arena = Vec::new();
        let mut txs_buf = Vec::new();
        assert!(BlockRef::decode_with_arena(truncated, &mut arena, &mut txs_buf).is_err());
    }

    #[test]
    fn block_ref_truncated_at_header() {
        let mut arena = Vec::new();
        let mut txs_buf = Vec::new();
        assert!(BlockRef::decode_with_arena(&[0u8; 40], &mut arena, &mut txs_buf).is_err());
    }

    #[test]
    fn block_ref_all_txids_correct_multi_segwit() {
        let segwit1 = make_segwit_tx();
        let segwit2 = Transaction {
            version: TxVersion::new(2),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([0x22u8; 32]),
                    vout: 1,
                },
                script_sig: Vec::<u8>::new().into(),
                sequence: Sequence::new(0xffff_fffe),
                witness: Witness::from_slice(&[&[0xaa; 71][..], &[0xbb; 33][..]]),
            }],
            outputs: vec![TxOut {
                value: Satoshi::new(50_000),
                script_pubkey: vec![0x00, 0x14, 0xcc, 0xdd].into(),
            }],
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
            transactions: vec![make_tx(), segwit1.clone(), segwit2.clone(), make_tx()],
        };
        let bytes = encode(&block);
        let mut arena = Vec::new();
        let mut txs_buf = Vec::new();
        let br = BlockRef::decode_with_arena(&bytes, &mut arena, &mut txs_buf)
            .expect("block with mixed txs must decode");
        assert_eq!(br.tx_count(), 4);

        let expected_txids: Vec<_> = block
            .transactions
            .iter()
            .map(|tx| tx.txid().unwrap())
            .collect();
        for (i, tx_ref) in br.transactions().enumerate() {
            let ref_txid = tx_ref.txid_into(&mut Vec::new()).unwrap();
            assert_eq!(ref_txid, expected_txids[i], "txid mismatch at index {i}");
        }
    }

    #[test]
    fn decode_arena_decode_matches_owned_block() {
        let block = Block {
            header: BlockHeader::new(
                BlockVersion::new(1),
                Hash256::ZERO,
                Hash256::ZERO,
                BlockTime::new(1_700_000_000),
                CompactBits::new(0x1d00_ffff),
                Nonce::new(42),
            ),
            transactions: vec![make_tx(), make_segwit_tx()],
        };
        let bytes = encode(&block);

        let mut arena = super::DecodeArena::new();
        let block_ref = arena.decode(&bytes).expect("DecodeArena::decode");

        assert_eq!(block_ref.header, block.header);
        assert_eq!(block_ref.tx_count(), block.transactions.len());
        for (i, (tx_ref, tx_owned)) in block_ref
            .transactions()
            .zip(block.transactions.iter())
            .enumerate()
        {
            let ref_txid = tx_ref.txid_into(&mut Vec::new()).unwrap();
            let owned_txid = tx_owned.txid().unwrap();
            assert_eq!(ref_txid, owned_txid, "txid mismatch at index {i}");
        }
    }

    #[test]
    fn block_ref_raw_spans_full_wire() {
        let block = Block {
            header: BlockHeader::new(
                BlockVersion::new(1),
                Hash256::ZERO,
                Hash256::ZERO,
                BlockTime::new(0),
                CompactBits::new(0),
                Nonce::new(0),
            ),
            transactions: vec![make_tx(), make_segwit_tx()],
        };
        let bytes = encode(&block);
        let mut arena = Vec::new();
        let mut txs_buf = Vec::new();
        let br = BlockRef::decode_with_arena(&bytes, &mut arena, &mut txs_buf).unwrap();
        assert_eq!(br.raw.len(), bytes.len());
    }
}
