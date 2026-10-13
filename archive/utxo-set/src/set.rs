use mantle::collections::PrehashedMap;
use mantle::primitives::{BlockHeight, Hash256, OutPoint, Satoshi};
use mantle_consensus::chain_view::{Coin, NewCoin};

use crate::coin_entry::CoinEntry;
use crate::error::UtxoError;
use crate::tx_entry::TxEntry;

const COINBASE_MATURITY: u32 = 100;

/// Scan a contiguous `NewCoin` slice, detect tx boundaries by txid, and
/// insert a `TxEntry` per transaction directly — no intermediate scratch vec.
fn insert_created(
    txs: &mut PrehashedMap<Hash256, TxEntry>,
    created_txids: &mut Vec<Hash256>,
    height: BlockHeight,
    created: &[NewCoin<'_>],
) {
    let mut i = 0;
    while i < created.len() {
        let txid = created[i].outpoint.txid;
        let coinbase = created[i].coinbase;
        created_txids.push(txid);

        let run_start = i;
        let mut max_vout = 0u32;
        while i < created.len() && created[i].outpoint.txid == txid {
            max_vout = max_vout.max(created[i].outpoint.vout);
            i += 1;
        }

        let entry = TxEntry::from_new_coins(
            height,
            coinbase,
            &created[run_start..i],
            max_vout,
        );
        txs.insert(txid, entry);
    }
}

/// Undo record for a single spend within a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendUndo {
    pub outpoint: OutPoint,
    pub coin: CoinEntry,
    pub height: BlockHeight,
    pub coinbase: bool,
}

/// Undo record for an entire block: the spent coins and the txids created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockUndo {
    pub spent: Vec<SpendUndo>,
    pub created_txids: Vec<Hash256>,
}

/// Reusable scratch buffers for `connect_block` / `disconnect_block`.
/// Eliminates per-block allocations on the hot path.
pub struct ConnectScratch {
    pub(crate) undo_spent: Vec<SpendUndo>,
    pub(crate) created_txids: Vec<Hash256>,
}

impl ConnectScratch {
    #[must_use]
    pub fn new() -> Self {
        Self {
            undo_spent: Vec::new(),
            created_txids: Vec::new(),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.undo_spent.clear();
        self.created_txids.clear();
    }

    /// Return consumed `BlockUndo` vecs so their capacity is reused on the
    /// next `connect_block_with` call.
    pub fn reclaim(&mut self, undo: BlockUndo) {
        let mut spent = undo.spent;
        let mut txids = undo.created_txids;
        spent.clear();
        txids.clear();
        self.undo_spent = spent;
        self.created_txids = txids;
    }
}

impl Default for ConnectScratch {
    fn default() -> Self {
        Self::new()
    }
}

pub struct UtxoSet {
    txs: PrehashedMap<Hash256, TxEntry>,
}

impl UtxoSet {
    #[must_use]
    pub fn new() -> Self {
        Self {
            txs: PrehashedMap::default(),
        }
    }

    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        use mantle::collections::BuildPrehashedHasher;
        Self {
            txs: PrehashedMap::with_capacity_and_hasher(cap, BuildPrehashedHasher),
        }
    }

    #[inline]
    #[must_use]
    pub fn tx_count(&self) -> usize {
        self.txs.len()
    }

    #[must_use]
    pub fn coin_count(&self) -> usize {
        self.txs.values().map(|e| e.unspent_count() as usize).sum()
    }

    #[must_use]
    pub fn get(&self, outpoint: &OutPoint) -> Option<Coin> {
        let entry = self.txs.get(&outpoint.txid)?;
        let coin = entry.get(outpoint.vout)?;
        Some(Coin {
            value: coin.value,
            script_pubkey: coin.script_pubkey.clone(),
            height: entry.height,
            coinbase: entry.coinbase,
        })
    }

    #[must_use]
    pub fn get_entry(&self, outpoint: &OutPoint) -> Option<(&TxEntry, &CoinEntry)> {
        let entry = self.txs.get(&outpoint.txid)?;
        let coin = entry.get(outpoint.vout)?;
        Some((entry, coin))
    }

    /// # Errors
    /// Returns `UtxoError::OutputAlreadyExists` if a transaction with this
    /// txid is already in the set.
    pub fn insert_tx<'a>(
        &mut self,
        txid: Hash256,
        height: BlockHeight,
        coinbase: bool,
        outputs: impl Iterator<Item = (Satoshi, &'a [u8])>,
    ) -> Result<(), UtxoError> {
        let coins: Vec<Option<CoinEntry>> = outputs
            .map(|(value, script_pubkey)| {
                Some(CoinEntry {
                    value,
                    script_pubkey: script_pubkey.into(),
                })
            })
            .collect();
        let entry = TxEntry::new(height, coinbase, coins);
        if self.txs.insert(txid, entry).is_some() {
            return Err(UtxoError::OutputAlreadyExists(OutPoint { txid, vout: 0 }));
        }
        Ok(())
    }

    /// # Errors
    /// Returns `UtxoError::OutputNotFound` if the coin doesn't exist, or
    /// `UtxoError::CoinbaseMaturity` if spending a coinbase output too early.
    pub fn spend(
        &mut self,
        outpoint: &OutPoint,
        spend_height: BlockHeight,
    ) -> Result<SpendUndo, UtxoError> {
        let entry = self
            .txs
            .get_mut(&outpoint.txid)
            .ok_or(UtxoError::OutputNotFound(*outpoint))?;

        if entry.coinbase {
            let age = spend_height.to_u32().saturating_sub(entry.height.to_u32());
            if age < COINBASE_MATURITY {
                return Err(UtxoError::CoinbaseMaturity {
                    outpoint: *outpoint,
                    created: entry.height,
                    spend: spend_height,
                });
            }
        }

        let height = entry.height;
        let coinbase = entry.coinbase;
        let coin = entry
            .spend(outpoint.vout)
            .ok_or(UtxoError::OutputNotFound(*outpoint))?;

        let undo = SpendUndo {
            outpoint: *outpoint,
            coin,
            height,
            coinbase,
        };

        if entry.is_fully_spent() {
            self.txs.remove(&outpoint.txid);
        }

        Ok(undo)
    }

    /// Connect a block: insert created outputs and remove spent inputs.
    /// Returns a `BlockUndo` that can reverse this operation.
    ///
    /// `created` must be ordered by transaction — all outputs for a given
    /// txid must be contiguous. This is the natural order from `connect_block`
    /// in the consensus crate.
    ///
    /// # Errors
    /// Returns `UtxoError` if any spent outpoint is missing or immature.
    pub fn connect_block(
        &mut self,
        height: BlockHeight,
        created: &[NewCoin<'_>],
        spent: &[OutPoint],
    ) -> Result<BlockUndo, UtxoError> {
        let mut scratch = ConnectScratch::new();
        self.connect_block_with(&mut scratch, height, created, spent)
    }

    /// Like `connect_block` but reuses caller-owned scratch buffers.
    ///
    /// # Errors
    /// Returns `UtxoError` if any spent outpoint is missing or immature.
    pub fn connect_block_with(
        &mut self,
        scratch: &mut ConnectScratch,
        height: BlockHeight,
        created: &[NewCoin<'_>],
        spent: &[OutPoint],
    ) -> Result<BlockUndo, UtxoError> {
        scratch.clear();

        insert_created(&mut self.txs, &mut scratch.created_txids, height, created);

        scratch.undo_spent.reserve(spent.len());
        for op in spent {
            scratch.undo_spent.push(self.spend(op, height)?);
        }

        Ok(BlockUndo {
            spent: std::mem::take(&mut scratch.undo_spent),
            created_txids: std::mem::take(&mut scratch.created_txids),
        })
    }

    /// Like `connect_block_with` but silently skips missing or immature
    /// spends instead of returning an error. Matches the storage-engine
    /// contract where `remove` on a missing key is a no-op.
    pub fn connect_block_best_effort(
        &mut self,
        scratch: &mut ConnectScratch,
        height: BlockHeight,
        created: &[NewCoin<'_>],
        spent: &[OutPoint],
    ) -> BlockUndo {
        scratch.clear();

        insert_created(&mut self.txs, &mut scratch.created_txids, height, created);

        scratch.undo_spent.reserve(spent.len());
        for op in spent {
            if let Ok(undo) = self.spend(op, height) {
                scratch.undo_spent.push(undo);
            }
        }

        BlockUndo {
            spent: std::mem::take(&mut scratch.undo_spent),
            created_txids: std::mem::take(&mut scratch.created_txids),
        }
    }

    /// Disconnect a block using its undo record. Reverses `connect_block`.
    pub fn disconnect_block(&mut self, undo: &BlockUndo) {
        for txid in &undo.created_txids {
            self.txs.remove(txid);
        }

        for su in undo.spent.iter().rev() {
            let entry = self
                .txs
                .entry(su.outpoint.txid)
                .or_insert_with(|| TxEntry::new(su.height, su.coinbase, Vec::new()));
            entry.unspend(su.outpoint.vout, su.coin.clone());
        }
    }
}

impl Default for UtxoSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use mantle::primitives::{BlockHeight, Hash256, OutPoint, Satoshi};
    use mantle_consensus::chain_view::NewCoin;

    use super::*;

    fn txid(n: u8) -> Hash256 {
        Hash256::from_bytes([n; 32])
    }

    fn new_coin<'a>(
        tx: Hash256,
        vout: u32,
        value: u64,
        coinbase: bool,
        height: BlockHeight,
        script: &'a [u8],
    ) -> NewCoin<'a> {
        NewCoin {
            outpoint: OutPoint { txid: tx, vout },
            value: Satoshi::new(value),
            script_pubkey: script,
            coinbase,
            height,
        }
    }

    #[test]
    fn empty_set() {
        let set = UtxoSet::new();
        assert_eq!(set.tx_count(), 0);
        assert_eq!(set.coin_count(), 0);
        let op = OutPoint {
            txid: txid(1),
            vout: 0,
        };
        assert!(set.get(&op).is_none());
    }

    #[test]
    fn connect_and_lookup() {
        let mut set = UtxoSet::new();
        let h = BlockHeight::new(100);
        let script = [0x76u8, 0xa9];

        let created = vec![
            new_coin(txid(1), 0, 5000, false, h, &script),
            new_coin(txid(1), 1, 3000, false, h, &script),
            new_coin(txid(2), 0, 1000, true, h, &script),
        ];

        let undo = set.connect_block(h, &created, &[]).unwrap();
        assert_eq!(set.tx_count(), 2);
        assert_eq!(set.coin_count(), 3);

        let coin = set
            .get(&OutPoint {
                txid: txid(1),
                vout: 0,
            })
            .unwrap();
        assert_eq!(coin.value, Satoshi::new(5000));
        assert!(!coin.coinbase);

        let coin2 = set
            .get(&OutPoint {
                txid: txid(2),
                vout: 0,
            })
            .unwrap();
        assert!(coin2.coinbase);

        assert_eq!(undo.created_txids.len(), 2);
        assert!(undo.spent.is_empty());
    }

    #[test]
    fn spend_removes_coin() {
        let mut set = UtxoSet::new();
        let h = BlockHeight::new(100);
        let script = [0x76u8];

        let created = vec![
            new_coin(txid(1), 0, 5000, false, h, &script),
            new_coin(txid(1), 1, 3000, false, h, &script),
        ];
        set.connect_block(h, &created, &[]).unwrap();

        let spend_h = BlockHeight::new(101);
        let op = OutPoint {
            txid: txid(1),
            vout: 0,
        };
        let undo = set.spend(&op, spend_h).unwrap();
        assert_eq!(undo.coin.value, Satoshi::new(5000));
        assert!(set.get(&op).is_none());
        assert!(
            set.get(&OutPoint {
                txid: txid(1),
                vout: 1,
            })
            .is_some()
        );
    }

    #[test]
    fn fully_spent_tx_removed_from_map() {
        let mut set = UtxoSet::new();
        let h = BlockHeight::new(100);
        let script = [0x76u8];

        let created = vec![new_coin(txid(1), 0, 5000, false, h, &script)];
        set.connect_block(h, &created, &[]).unwrap();
        assert_eq!(set.tx_count(), 1);

        set.spend(
            &OutPoint {
                txid: txid(1),
                vout: 0,
            },
            BlockHeight::new(101),
        )
        .unwrap();
        assert_eq!(set.tx_count(), 0);
    }

    #[test]
    fn coinbase_maturity_enforced() {
        let mut set = UtxoSet::new();
        let h = BlockHeight::new(50);
        let script = [0x76u8];

        let created = vec![new_coin(txid(1), 0, 5_000_000_000, true, h, &script)];
        set.connect_block(h, &created, &[]).unwrap();

        let op = OutPoint {
            txid: txid(1),
            vout: 0,
        };
        let err = set.spend(&op, BlockHeight::new(100)).unwrap_err();
        assert!(matches!(err, UtxoError::CoinbaseMaturity { .. }));

        let undo = set.spend(&op, BlockHeight::new(150)).unwrap();
        assert_eq!(undo.coin.value, Satoshi::new(5_000_000_000));
    }

    #[test]
    fn connect_then_disconnect_restores_state() {
        let mut set = UtxoSet::new();
        let h1 = BlockHeight::new(100);
        let h2 = BlockHeight::new(101);
        let script = [0x76u8];

        let created1 = vec![
            new_coin(txid(1), 0, 5000, false, h1, &script),
            new_coin(txid(1), 1, 3000, false, h1, &script),
        ];
        set.connect_block(h1, &created1, &[]).unwrap();

        let spent2 = vec![OutPoint {
            txid: txid(1),
            vout: 0,
        }];
        let created2 = vec![new_coin(txid(2), 0, 4000, false, h2, &script)];
        let undo2 = set.connect_block(h2, &created2, &spent2).unwrap();

        assert!(
            set.get(&OutPoint {
                txid: txid(1),
                vout: 0,
            })
            .is_none()
        );
        assert!(
            set.get(&OutPoint {
                txid: txid(2),
                vout: 0,
            })
            .is_some()
        );

        set.disconnect_block(&undo2);

        let restored = set
            .get(&OutPoint {
                txid: txid(1),
                vout: 0,
            })
            .unwrap();
        assert_eq!(restored.value, Satoshi::new(5000));

        assert!(
            set.get(&OutPoint {
                txid: txid(2),
                vout: 0,
            })
            .is_none()
        );
    }

    #[test]
    fn connect_block_spends_within_same_block() {
        let mut set = UtxoSet::new();
        let h1 = BlockHeight::new(100);
        let h2 = BlockHeight::new(101);
        let script = [0x76u8];

        let created1 = vec![new_coin(txid(1), 0, 5000, false, h1, &script)];
        set.connect_block(h1, &created1, &[]).unwrap();

        let created2 = vec![new_coin(txid(2), 0, 4000, false, h2, &script)];
        let spent2 = vec![OutPoint {
            txid: txid(1),
            vout: 0,
        }];
        let undo = set.connect_block(h2, &created2, &spent2).unwrap();

        assert_eq!(undo.spent.len(), 1);
        assert_eq!(undo.spent[0].coin.value, Satoshi::new(5000));
        assert_eq!(set.tx_count(), 1);
    }

    #[test]
    fn multiple_disconnect_blocks() {
        let mut set = UtxoSet::new();
        let script = [0x76u8];

        let h1 = BlockHeight::new(100);
        let c1 = vec![new_coin(txid(1), 0, 1000, false, h1, &script)];
        let u1 = set.connect_block(h1, &c1, &[]).unwrap();

        let h2 = BlockHeight::new(101);
        let c2 = vec![new_coin(txid(2), 0, 2000, false, h2, &script)];
        let s2 = vec![OutPoint {
            txid: txid(1),
            vout: 0,
        }];
        let u2 = set.connect_block(h2, &c2, &s2).unwrap();

        let h3 = BlockHeight::new(102);
        let c3 = vec![new_coin(txid(3), 0, 3000, false, h3, &script)];
        let s3 = vec![OutPoint {
            txid: txid(2),
            vout: 0,
        }];
        let u3 = set.connect_block(h3, &c3, &s3).unwrap();

        set.disconnect_block(&u3);
        set.disconnect_block(&u2);
        set.disconnect_block(&u1);

        assert_eq!(set.tx_count(), 0);
        assert_eq!(set.coin_count(), 0);
    }

    #[test]
    fn connect_block_with_scratch_reuse() {
        let mut set = UtxoSet::new();
        let mut scratch = ConnectScratch::new();
        let script = [0x76u8];

        for h in 1..=10u32 {
            let height = BlockHeight::new(h);
            let created = vec![new_coin(txid(h as u8), 0, 1000, false, height, &script)];
            set.connect_block_with(&mut scratch, height, &created, &[])
                .unwrap();
        }
        assert_eq!(set.tx_count(), 10);
        assert_eq!(set.coin_count(), 10);
    }
}
