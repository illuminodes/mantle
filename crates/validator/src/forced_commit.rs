use mantle::primitives::{Block, BlockHeight, OutPoint, TxHash};
use mantle_consensus::chain_view::NewCoin;
use mantle_consensus::error::ValidationError;
use mantle_storage::ops::StorageOps;
use mantle_storage::types::{CommitBlockReq, CommittedResp, Durability, ReqToken};

use crate::pipeline::PipelineError;

/// Applies a block's UTXO delta without validating it.
///
/// Used by keep-going replays: after a block fails a consensus check, the
/// delta is still committed so later blocks see the UTXO set the real chain
/// produced, and further failures can be found in the same run.
#[derive(Default)]
pub struct ForcedCommit {
    hash_scratch: Vec<u8>,
    spent: Vec<OutPoint>,
}

impl ForcedCommit {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Commit every output of `block` as created and every non-coinbase input
    /// as spent.
    ///
    /// # Errors
    /// Returns `PipelineError` if a txid cannot be computed or storage fails.
    pub fn commit<S>(
        &mut self,
        block: &Block,
        height: BlockHeight,
        storage: &mut S,
        durability: Durability,
        token: ReqToken,
    ) -> Result<CommittedResp, PipelineError>
    where
        S: for<'x> StorageOps<'x>,
    {
        let mut created: Vec<NewCoin<'_>> = Vec::new();
        self.spent.clear();
        for (tx_index, tx) in block.transactions.iter().enumerate() {
            let txid = tx
                .txid_into(&mut self.hash_scratch)
                .map_err(ValidationError::from)?;
            if tx_index > 0 {
                self.spent
                    .extend(tx.inputs.iter().map(|input| input.previous_output));
            }
            for (vout, output) in tx.outputs.iter().enumerate() {
                let vout = u32::try_from(vout).map_err(|_| {
                    ValidationError::MalformedTransaction { tx_index }
                })?;
                created.push(NewCoin {
                    outpoint: OutPoint { txid, vout },
                    value: output.value,
                    script_pubkey: output.script_pubkey.as_slice(),
                    coinbase: tx_index == 0,
                    height,
                });
            }
        }

        let resp = storage.commit_block_borrowed(CommitBlockReq {
            token,
            height,
            hash: block.header.hash(),
            prev_hash: block.header.prev_block(),
            header: block.header,
            created: &created,
            spent: &self.spent,
            block_bytes: None,
            durability,
        })?;
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantle::primitives::{
        BlockHeader, BlockTime, BlockVersion, CompactBits, Hash256, Locktime, Nonce, Satoshi,
        Sequence, Transaction, TxIn, TxOut, TxVersion, Witness,
    };
    use mantle_consensus::chain_view::TipInfo;
    use mantle_storage::types::{LookupResult, StorageError};

    #[derive(Default)]
    struct RecordingStorage {
        created: Vec<(OutPoint, bool, BlockHeight)>,
        spent: Vec<OutPoint>,
        height: Option<BlockHeight>,
    }

    impl<'req> StorageOps<'req> for RecordingStorage {
        fn send_lookup(
            &mut self,
            _ops: &'req [OutPoint],
            _out: &'req mut Vec<LookupResult>,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        fn recv_lookup(&mut self) -> Result<(), StorageError> {
            Ok(())
        }

        fn commit_block_borrowed(
            &mut self,
            req: CommitBlockReq<'req>,
        ) -> Result<CommittedResp, StorageError> {
            self.created = req
                .created
                .iter()
                .map(|c| (c.outpoint, c.coinbase, c.height))
                .collect();
            self.spent = req.spent.to_vec();
            self.height = Some(req.height);
            Ok(CommittedResp {
                token: req.token,
                tip: TipInfo {
                    hash: req.hash,
                    height: req.height,
                },
            })
        }

        fn tip(&self) -> TipInfo {
            TipInfo {
                hash: Hash256::ZERO,
                height: BlockHeight::ZERO,
            }
        }

        fn read_header(&mut self, _hash: Hash256) -> Result<Option<BlockHeader>, StorageError> {
            Ok(None)
        }

        fn read_header_at(
            &mut self,
            _h: BlockHeight,
        ) -> Result<Option<BlockHeader>, StorageError> {
            Ok(None)
        }
    }

    fn tx(prev: OutPoint, outputs: usize) -> Transaction {
        Transaction {
            version: TxVersion::new(1),
            inputs: vec![TxIn {
                previous_output: prev,
                script_sig: vec![0x01, 0x01].into(),
                sequence: Sequence::MAX,
                witness: Witness::empty(),
            }],
            outputs: (0..outputs)
                .map(|_| TxOut {
                    value: Satoshi::new(1_000),
                    script_pubkey: vec![0x51].into(),
                })
                .collect(),
            locktime: Locktime::new(0),
        }
    }

    #[test]
    fn commits_all_outputs_and_non_coinbase_inputs() {
        let coinbase = tx(
            OutPoint {
                txid: Hash256::ZERO,
                vout: 0xffff_ffff,
            },
            1,
        );
        let external = OutPoint {
            txid: Hash256::from_bytes([0x42; 32]),
            vout: 3,
        };
        let spender = tx(external, 2);
        let block = Block {
            header: BlockHeader::new(
                BlockVersion::new(1),
                Hash256::ZERO,
                Hash256::ZERO,
                BlockTime::new(0),
                CompactBits::new(0x1d00_ffff),
                Nonce::new(0),
            ),
            transactions: vec![coinbase, spender],
        };

        let mut storage = RecordingStorage::default();
        let resp = ForcedCommit::new()
            .commit(
                &block,
                BlockHeight::new(9),
                &mut storage,
                Durability::Memory,
                ReqToken(5),
            )
            .expect("forced commit");

        assert_eq!(resp.token, ReqToken(5));
        assert_eq!(storage.height, Some(BlockHeight::new(9)));
        assert_eq!(storage.spent, vec![external]);
        assert_eq!(storage.created.len(), 3);
        assert!(storage.created[0].1, "coinbase output flagged coinbase");
        assert!(!storage.created[1].1 && !storage.created[2].1);
        assert_eq!(storage.created[2].0.vout, 1);
        assert!(
            storage
                .created
                .iter()
                .all(|(_, _, h)| *h == BlockHeight::new(9))
        );
    }
}
