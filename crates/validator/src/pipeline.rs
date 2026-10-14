use mantle::collections::{BuildPrehashedHasher, PrehashedMap, PrehashedSet};
use mantle::primitives::{Block, BlockHeight, Hash256, OutPoint, TxHash};
use mantle_consensus::chain_view::{Coin, ConnectScratch};
use mantle_consensus::error::ValidationError;
use mantle_consensus::tx_view::BlockView;
use mantle_consensus::validation::Bip30;
use mantle_storage::ops::StorageOps;
use mantle_storage::types::{CommitBlockReq, CommittedResp, Durability, ReqToken, StorageError};
use mantle_utxo_hash::UtxoSetHash;

use crate::prefetched_view::{HeaderSnapshot, PrefetchedView};
use crate::script_policy::{ConnectCall, ScriptPolicy};
use crate::utxo_hash_update::UtxoHashUpdate;

/// Per-block pipeline options: script policy, storage commit parameters and
/// UTXO hashing.
pub struct PipelineOpts<'a> {
    pub scripts: ScriptPolicy<'a>,
    pub durability: Durability,
    pub token: ReqToken,
    /// Updated with the block's UTXO delta once the block is committed.
    pub utxo_hash: Option<&'a mut UtxoSetHash>,
}

/// Reusable per-block working buffers for the validation pipeline.
///
/// Created once before the replay loop. All inner collections are `clear()`'d
/// at the start of each method call but retain their backing capacity,
/// eliminating the ~5 MB/block allocation churn that dominates the mid-chain
/// profile.
pub struct ReplayBufs {
    spent_set: PrehashedSet<OutPoint>,
    txids: Vec<Hash256>,
    hash_scratch: Vec<u8>,
    intra: PrehashedMap<OutPoint, Option<Coin>>,
    spend_ops: Vec<OutPoint>,
    bip30_ops: Vec<OutPoint>,
    lookup: Vec<mantle_storage::types::LookupResult>,
    coins: PrehashedMap<OutPoint, Option<Coin>>,
    txid_scratch: Vec<u8>,
    connect_scratch: ConnectScratch,
    utxo_hash_update: UtxoHashUpdate,
}

impl ReplayBufs {
    #[must_use]
    pub fn new() -> Self {
        Self {
            spent_set: PrehashedSet::with_hasher(BuildPrehashedHasher),
            txids: Vec::new(),
            hash_scratch: Vec::new(),
            intra: PrehashedMap::with_hasher(BuildPrehashedHasher),
            spend_ops: Vec::new(),
            bip30_ops: Vec::new(),
            lookup: Vec::new(),
            coins: PrehashedMap::with_hasher(BuildPrehashedHasher),
            txid_scratch: Vec::new(),
            connect_scratch: ConnectScratch::new(),
            utxo_hash_update: UtxoHashUpdate::new(),
        }
    }

    fn clear(&mut self) {
        self.spent_set.clear();
        self.txids.clear();
        self.intra.clear();
        self.spend_ops.clear();
        self.bip30_ops.clear();
        self.coins.clear();
    }

    /// Collect intra-block outputs and external outpoints from an owned `Block`.
    ///
    /// After this call `self.intra` holds intra-block coins, `self.spend_ops`
    /// holds all outpoints to look up from storage (spend + BIP30).
    fn collect_outpoints_block(&mut self, block: &Block, height: BlockHeight) {
        for tx in block.transactions.iter().skip(1) {
            for inp in &tx.inputs {
                self.spent_set.insert(inp.previous_output);
            }
        }

        for (tx_index, tx) in block.transactions.iter().enumerate() {
            let Ok(txid) = tx.txid_into(&mut self.hash_scratch) else {
                continue;
            };
            self.txids.push(txid);
            for (vout, output) in tx.outputs.iter().enumerate() {
                let Ok(vout_u32) = u32::try_from(vout) else {
                    continue;
                };
                let op = OutPoint {
                    txid,
                    vout: vout_u32,
                };
                if self.spent_set.contains(&op) {
                    self.intra.insert(
                        op,
                        Some(Coin {
                            value: output.value,
                            script_pubkey: output.script_pubkey.clone(),
                            height: BlockHeight::ZERO,
                            coinbase: tx_index == 0,
                        }),
                    );
                }
            }
        }

        for tx in block.transactions.iter().skip(1) {
            for inp in &tx.inputs {
                if !self.intra.contains_key(&inp.previous_output) {
                    self.spend_ops.push(inp.previous_output);
                }
            }
        }

        self.collect_bip30_probes(block, height);
    }

    fn collect_bip30_probes<B: BlockView>(&mut self, block: &B, height: BlockHeight) {
        self.spent_set.clear();
        self.spent_set.extend(self.spend_ops.iter().copied());
        let bip30 = Bip30::new(height, block.header());
        for op in bip30.probes(block, &self.txids) {
            if !self.intra.contains_key(&op) && !self.spent_set.contains(&op) {
                self.bip30_ops.push(op);
            }
        }
        self.spend_ops.extend_from_slice(&self.bip30_ops);
    }

    /// Fetch coins from storage into `self.coins`. Outpoints created inside
    /// the block are registered as absent: `connect_block` resolves them
    /// itself, in block order. After this call the coin map is ready for
    /// building a `PrefetchedView`.
    fn fetch_coins<S>(&mut self, storage: &mut S) -> Result<(), StorageError>
    where
        S: for<'x> StorageOps<'x>,
    {
        let all_ops_len = self.spend_ops.len();
        storage.send_lookup(&self.spend_ops, &mut self.lookup)?;
        storage.recv_lookup()?;

        self.coins.reserve(all_ops_len + self.intra.len());
        for r in self.lookup.drain(..) {
            self.coins.insert(r.outpoint, r.coin);
        }
        for (k, _) in self.intra.drain() {
            self.coins.insert(k, None);
        }

        Ok(())
    }

    /// Validate an owned `Block` and commit it to storage.
    ///
    /// Full pipeline: collect outpoints, batch-fetch from storage, run
    /// `connect_block` with `scripts` verifying inputs, commit the UTXO
    /// delta. Reuses buffer capacity across calls.
    ///
    /// # Errors
    ///
    /// Returns `PipelineError` on any validation or storage failure.
    pub fn validate_and_commit<S>(
        &mut self,
        block: &Block,
        height: BlockHeight,
        storage: &mut S,
        headers: &HeaderSnapshot,
        mut opts: PipelineOpts<'_>,
    ) -> Result<CommittedResp, PipelineError>
    where
        S: for<'x> StorageOps<'x>,
    {
        self.clear();
        self.collect_outpoints_block(block, height);

        let hash = block.header.hash();
        self.fetch_coins(storage)?;
        let tip = storage.tip();
        let view = PrefetchedView::new(&self.coins, headers, tip);

        let result = opts.scripts.connect(ConnectCall {
            block,
            height,
            view: &view,
            scratch: &mut self.txid_scratch,
            connect_scratch: &mut self.connect_scratch,
            txids: (self.txids.len() == block.transactions.len()).then_some(self.txids.as_slice()),
        })?;

        let resp = storage.commit_block_borrowed(CommitBlockReq {
            token: opts.token,
            height,
            hash,
            prev_hash: block.header.prev_block(),
            header: block.header,
            created: &result.created,
            spent: &result.spent,
            block_bytes: None,
            durability: opts.durability,
        })?;

        if let Some(utxo_hash) = opts.utxo_hash {
            self.utxo_hash_update.apply(
                utxo_hash,
                (height, hash),
                &result.created,
                &result.spent,
                &self.coins,
            );
        }

        Ok(resp)
    }
}

impl Default for ReplayBufs {
    fn default() -> Self {
        Self::new()
    }
}

/// Error from the validation pipeline: either a consensus validation failure
/// or a storage I/O error.
#[derive(Debug)]
pub enum PipelineError {
    Validation(ValidationError),
    Storage(StorageError),
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(e) => write!(f, "validation: {e}"),
            Self::Storage(e) => write!(f, "storage: {e}"),
        }
    }
}

impl std::error::Error for PipelineError {}

impl From<ValidationError> for PipelineError {
    fn from(e: ValidationError) -> Self {
        Self::Validation(e)
    }
}

impl From<StorageError> for PipelineError {
    fn from(e: StorageError) -> Self {
        Self::Storage(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantle::primitives::{
        Block, BlockHeader, BlockTime, BlockVersion, CompactBits, Hash256, Locktime, Nonce,
        OutPoint, Satoshi, Sequence, Transaction, TxIn, TxVersion,
    };
    use mantle::primitives::{TxOut, Witness};

    const TEST_HEIGHT: BlockHeight = BlockHeight::new(100);

    /// Build a minimal block with one coinbase tx and one spending tx.
    ///
    /// The spending tx's input references `(prev_txid, 0)`, so we can
    /// predict what outpoints the collector should record.
    fn make_block_with_spend(prev_txid: Hash256) -> Block {
        let header = BlockHeader::new(
            BlockVersion::new(1),
            Hash256::ZERO,
            Hash256::ZERO,
            BlockTime::new(1_231_006_505),
            CompactBits::new(0x1d00_ffff),
            Nonce::new(0),
        );

        let coinbase = Transaction {
            version: TxVersion::new(1),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: 0xffff_ffff,
                },
                script_sig: vec![0x04, 0x01].into(),
                sequence: Sequence::MAX,
                witness: Witness::empty(),
            }],
            outputs: vec![TxOut {
                value: Satoshi::new(5_000_000_000),
                script_pubkey: vec![0xac].into(),
            }],
            locktime: Locktime::new(0),
        };

        let spending = Transaction {
            version: TxVersion::new(1),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_txid,
                    vout: 0,
                },
                script_sig: vec![0x00].into(),
                sequence: Sequence::MAX,
                witness: Witness::empty(),
            }],
            outputs: vec![TxOut {
                value: Satoshi::new(4_999_000_000),
                script_pubkey: vec![0x76, 0xa9].into(),
            }],
            locktime: Locktime::new(0),
        };

        Block {
            header,
            transactions: vec![coinbase, spending],
        }
    }

    #[test]
    fn collect_outpoints_block_finds_external_spend() {
        let prev_txid = Hash256::from_bytes([0xab; 32]);
        let block = make_block_with_spend(prev_txid);

        let mut bufs = ReplayBufs::new();
        bufs.collect_outpoints_block(&block, TEST_HEIGHT);

        // The spending tx references (prev_txid, 0). Since prev_txid is not
        // produced by any tx in this block, it must appear in spend_ops as an
        // external outpoint to look up from storage.
        let expected_external = OutPoint {
            txid: prev_txid,
            vout: 0,
        };
        assert!(
            bufs.spend_ops.contains(&expected_external),
            "spend_ops should contain the external outpoint {:?}, got {:?}",
            expected_external,
            bufs.spend_ops,
        );

        // No intra-block outputs should exist because the spending tx
        // references a txid that doesn't match any tx in this block.
        assert!(
            bufs.intra.is_empty(),
            "intra should be empty when spending from outside the block"
        );
    }

    #[test]
    fn collect_outpoints_block_detects_intra_block_spend() {
        // Build a block where tx1 spends from the coinbase (tx0).
        let header = BlockHeader::new(
            BlockVersion::new(1),
            Hash256::ZERO,
            Hash256::ZERO,
            BlockTime::new(1_231_006_505),
            CompactBits::new(0x1d00_ffff),
            Nonce::new(0),
        );

        let coinbase = Transaction {
            version: TxVersion::new(1),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: 0xffff_ffff,
                },
                script_sig: vec![0x04, 0x01].into(),
                sequence: Sequence::MAX,
                witness: Witness::empty(),
            }],
            outputs: vec![TxOut {
                value: Satoshi::new(5_000_000_000),
                script_pubkey: vec![0xac].into(),
            }],
            locktime: Locktime::new(0),
        };

        // Compute the coinbase txid so we can reference it.
        let mut scratch = Vec::new();
        use mantle::primitives::TxHash;
        let coinbase_txid = coinbase.txid_into(&mut scratch).expect("txid");

        let spending = Transaction {
            version: TxVersion::new(1),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: coinbase_txid,
                    vout: 0,
                },
                script_sig: vec![0x00].into(),
                sequence: Sequence::MAX,
                witness: Witness::empty(),
            }],
            outputs: vec![TxOut {
                value: Satoshi::new(4_999_000_000),
                script_pubkey: vec![0x76, 0xa9].into(),
            }],
            locktime: Locktime::new(0),
        };

        let block = Block {
            header,
            transactions: vec![coinbase, spending],
        };

        let mut bufs = ReplayBufs::new();
        bufs.collect_outpoints_block(&block, TEST_HEIGHT);

        // The spend of (coinbase_txid, 0) is intra-block, so it should
        // appear in `intra` with the coinbase output's coin data.
        let intra_op = OutPoint {
            txid: coinbase_txid,
            vout: 0,
        };
        assert!(
            bufs.intra.contains_key(&intra_op),
            "intra should contain the coinbase outpoint spent within the block"
        );

        let coin = bufs.intra[&intra_op].as_ref().expect("coin should be Some");
        assert_eq!(coin.value, Satoshi::new(5_000_000_000));
        assert!(coin.coinbase, "coin should be marked as coinbase");

        // Since the spend is intra-block, it should NOT appear in spend_ops
        // (no external lookup needed).
        assert!(
            !bufs.spend_ops.iter().any(|op| *op == intra_op),
            "spend_ops should not contain the intra-block outpoint (except bip30)"
        );
    }

    #[test]
    fn collect_outpoints_block_coinbase_only() {
        let header = BlockHeader::new(
            BlockVersion::new(1),
            Hash256::ZERO,
            Hash256::ZERO,
            BlockTime::new(0),
            CompactBits::new(0),
            Nonce::new(0),
        );

        let coinbase = Transaction {
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
        };

        let block = Block {
            header,
            transactions: vec![coinbase],
        };

        let mut bufs = ReplayBufs::new();
        bufs.collect_outpoints_block(&block, TEST_HEIGHT);

        // With only a coinbase, there are no non-coinbase inputs, so no
        // external spends. The only spend_ops entry (if any) is the BIP30
        // check for the coinbase txid:0.
        assert!(bufs.intra.is_empty());
        // txids should have one entry (the coinbase txid).
        assert_eq!(bufs.txids.len(), 1);
    }

    #[test]
    fn bip30_probes_cover_every_output_only_while_enforced() {
        let mut block = make_block_with_spend(Hash256::from_bytes([0xab; 32]));
        block.transactions[1].outputs.push(TxOut {
            value: Satoshi::new(1),
            script_pubkey: vec![0x51].into(),
        });

        let mut bufs = ReplayBufs::new();
        bufs.collect_outpoints_block(&block, TEST_HEIGHT);
        let mut scratch = Vec::new();
        let spender = block.transactions[1].txid_into(&mut scratch).expect("txid");
        assert!(bufs.bip30_ops.contains(&OutPoint { txid: spender, vout: 1 }));
        assert_eq!(bufs.bip30_ops.len(), 3);

        bufs.clear();
        bufs.collect_outpoints_block(&block, BlockHeight::new(500_000));
        assert!(bufs.bip30_ops.is_empty());
    }

    #[test]
    fn collect_outpoints_block_records_txids() {
        let prev_txid = Hash256::from_bytes([0xcd; 32]);
        let block = make_block_with_spend(prev_txid);

        let mut bufs = ReplayBufs::new();
        bufs.collect_outpoints_block(&block, TEST_HEIGHT);

        // Should have recorded 2 txids (coinbase + spending tx).
        assert_eq!(bufs.txids.len(), 2, "expected 2 txids");
    }

    #[test]
    fn pipeline_error_display_validation() {
        let err = PipelineError::Validation(ValidationError::EmptyBlock);
        let msg = format!("{err}");
        assert!(msg.starts_with("validation:"), "got: {msg}");
    }

    #[test]
    fn pipeline_error_display_storage() {
        let err = PipelineError::Storage(StorageError::ThreadGone);
        let msg = format!("{err}");
        assert!(msg.starts_with("storage:"), "got: {msg}");
    }

    /// Minimal mock that returns `None` for every outpoint lookup.
    struct MockStorage;

    impl<'req> mantle_storage::ops::StorageOps<'req> for MockStorage {
        fn send_lookup(
            &mut self,
            ops: &'req [OutPoint],
            out: &'req mut Vec<mantle_storage::types::LookupResult>,
        ) -> Result<(), StorageError> {
            out.clear();
            for op in ops {
                out.push(mantle_storage::types::LookupResult {
                    outpoint: *op,
                    coin: None,
                });
            }
            Ok(())
        }

        fn recv_lookup(&mut self) -> Result<(), StorageError> {
            Ok(())
        }

        fn commit_block_borrowed(
            &mut self,
            _req: mantle_storage::types::CommitBlockReq<'req>,
        ) -> Result<mantle_storage::types::CommittedResp, StorageError> {
            unimplemented!()
        }

        fn tip(&self) -> mantle_consensus::chain_view::TipInfo {
            mantle_consensus::chain_view::TipInfo {
                hash: Hash256::ZERO,
                height: mantle::primitives::BlockHeight::ZERO,
            }
        }

        fn read_header(
            &mut self,
            _hash: Hash256,
        ) -> Result<Option<mantle::primitives::BlockHeader>, StorageError> {
            Ok(None)
        }

        fn read_header_at(
            &mut self,
            _h: mantle::primitives::BlockHeight,
        ) -> Result<Option<mantle::primitives::BlockHeader>, StorageError> {
            Ok(None)
        }
    }

    #[test]
    fn fetch_coins_merges_intra_and_storage() {
        let prev_txid = Hash256::from_bytes([0xab; 32]);
        let block = make_block_with_spend(prev_txid);

        let mut bufs = ReplayBufs::new();
        bufs.collect_outpoints_block(&block, TEST_HEIGHT);

        // Record how many external ops need lookup.
        let external_count = bufs.spend_ops.len();
        assert!(external_count > 0);

        let mut storage = MockStorage;
        bufs.fetch_coins(&mut storage).unwrap();

        // After fetch_coins, `coins` should contain at least the external
        // lookups (all None from mock) plus any intra-block entries.
        // The external outpoint (prev_txid, 0) should map to None.
        let ext_op = OutPoint { txid: prev_txid, vout: 0 };
        assert!(
            bufs.coins.contains_key(&ext_op),
            "coins should contain the external outpoint"
        );
        assert!(
            bufs.coins[&ext_op].is_none(),
            "mock storage returns None for all lookups"
        );
    }

    #[test]
    fn replay_bufs_clear_resets_state() {
        let prev_txid = Hash256::from_bytes([0xab; 32]);
        let block = make_block_with_spend(prev_txid);

        let mut bufs = ReplayBufs::new();
        bufs.collect_outpoints_block(&block, TEST_HEIGHT);

        // Verify some state was accumulated.
        assert!(!bufs.txids.is_empty());

        bufs.clear();

        assert!(bufs.spent_set.is_empty());
        assert!(bufs.txids.is_empty());
        assert!(bufs.intra.is_empty());
        assert!(bufs.spend_ops.is_empty());
        assert!(bufs.bip30_ops.is_empty());
        assert!(bufs.coins.is_empty());
    }
}
