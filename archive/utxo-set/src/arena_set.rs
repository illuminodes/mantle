use mantle::collections::PrehashedMap;
use mantle::primitives::{BlockHeight, Hash256, OutPoint};
use mantle_consensus::chain_view::{Coin, NewCoin};

use crate::arena::{CoinArena, TxHandle};
use crate::error::UtxoError;
use crate::set::{BlockUndo, ConnectScratch, SpendUndo};

const COINBASE_MATURITY: u32 = 100;

pub struct ArenaUtxoSet {
    txs: PrehashedMap<Hash256, TxHandle>,
    arena: CoinArena,
}

impl ArenaUtxoSet {
    #[must_use]
    pub fn new() -> Self {
        Self {
            txs: PrehashedMap::default(),
            arena: CoinArena::new(),
        }
    }

    #[must_use]
    pub fn with_capacity(tx_cap: usize, coin_cap: usize) -> Self {
        use mantle::collections::BuildPrehashedHasher;
        Self {
            txs: PrehashedMap::with_capacity_and_hasher(tx_cap, BuildPrehashedHasher),
            arena: CoinArena::with_capacity(coin_cap),
        }
    }

    #[inline]
    #[must_use]
    pub fn tx_count(&self) -> usize {
        self.txs.len()
    }

    #[must_use]
    pub fn coin_count(&self) -> usize {
        self.txs.values().map(|h| h.unspent_count() as usize).sum()
    }

    #[must_use]
    pub fn get(&self, outpoint: &OutPoint) -> Option<Coin> {
        let handle = self.txs.get(&outpoint.txid)?;
        if !handle.is_unspent(outpoint.vout) {
            return None;
        }
        let coin = self.arena.get(handle.span, outpoint.vout)?;
        Some(Coin {
            value: coin.value,
            script_pubkey: coin.script_pubkey.clone(),
            height: handle.height,
            coinbase: handle.coinbase,
        })
    }

    /// # Errors
    /// Returns `UtxoError::OutputNotFound` or `UtxoError::CoinbaseMaturity`.
    pub fn spend(
        &mut self,
        outpoint: &OutPoint,
        spend_height: BlockHeight,
    ) -> Result<SpendUndo, UtxoError> {
        let handle = self
            .txs
            .get_mut(&outpoint.txid)
            .ok_or(UtxoError::OutputNotFound(*outpoint))?;

        if !handle.is_unspent(outpoint.vout) {
            return Err(UtxoError::OutputNotFound(*outpoint));
        }

        if handle.coinbase {
            let age = spend_height.to_u32().saturating_sub(handle.height.to_u32());
            if age < COINBASE_MATURITY {
                return Err(UtxoError::CoinbaseMaturity {
                    outpoint: *outpoint,
                    created: handle.height,
                    spend: spend_height,
                });
            }
        }

        let height = handle.height;
        let coinbase = handle.coinbase;
        handle.mark_spent(outpoint.vout);

        let coin = self
            .arena
            .take(handle.span, outpoint.vout)
            .ok_or(UtxoError::OutputNotFound(*outpoint))?;

        if handle.is_fully_spent() {
            self.txs.remove(&outpoint.txid);
        }

        Ok(SpendUndo {
            outpoint: *outpoint,
            coin,
            height,
            coinbase,
        })
    }

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
        self.insert_created(&mut scratch.created_txids, height, created);

        scratch.undo_spent.reserve(spent.len());
        for op in spent {
            scratch.undo_spent.push(self.spend(op, height)?);
        }

        Ok(BlockUndo {
            spent: std::mem::take(&mut scratch.undo_spent),
            created_txids: std::mem::take(&mut scratch.created_txids),
        })
    }

    pub fn connect_block_best_effort(
        &mut self,
        scratch: &mut ConnectScratch,
        height: BlockHeight,
        created: &[NewCoin<'_>],
        spent: &[OutPoint],
    ) -> BlockUndo {
        scratch.clear();
        self.insert_created(&mut scratch.created_txids, height, created);

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

    pub fn disconnect_block(&mut self, undo: &BlockUndo) {
        for txid in &undo.created_txids {
            self.txs.remove(txid);
        }

        for su in undo.spent.iter().rev() {
            if let Some(handle) = self.txs.get_mut(&su.outpoint.txid) {
                handle.mark_unspent(su.outpoint.vout);
                self.arena.put(handle.span, su.outpoint.vout, su.coin.clone());
            } else {
                #[allow(clippy::cast_possible_truncation)]
                let span = self.arena.alloc(su.outpoint.vout as u16 + 1);
                self.arena.put(span, su.outpoint.vout, su.coin.clone());
                let mut live = 0u64;
                if su.outpoint.vout < 64 {
                    live = 1 << su.outpoint.vout;
                }
                self.txs.insert(su.outpoint.txid, TxHandle {
                    span,
                    height: su.height,
                    live,
                    coinbase: su.coinbase,
                });
            }
        }
    }

    fn insert_created(
        &mut self,
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

            let span = self
                .arena
                .alloc_from_coins(&created[run_start..i], max_vout);

            let mut live = 0u64;
            for c in &created[run_start..i] {
                if c.outpoint.vout < 64 {
                    live |= 1 << c.outpoint.vout;
                }
            }

            self.txs.insert(txid, TxHandle {
                span,
                height,
                live,
                coinbase,
            });
        }
    }
}

impl Default for ArenaUtxoSet {
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
        let set = ArenaUtxoSet::new();
        assert_eq!(set.tx_count(), 0);
        assert_eq!(set.coin_count(), 0);
        assert!(set.get(&OutPoint { txid: txid(1), vout: 0 }).is_none());
    }

    #[test]
    fn connect_and_lookup() {
        let mut set = ArenaUtxoSet::new();
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

        let coin = set.get(&OutPoint { txid: txid(1), vout: 0 }).unwrap();
        assert_eq!(coin.value, Satoshi::new(5000));
        assert!(!coin.coinbase);

        let coin2 = set.get(&OutPoint { txid: txid(2), vout: 0 }).unwrap();
        assert!(coin2.coinbase);

        assert_eq!(undo.created_txids.len(), 2);
        assert!(undo.spent.is_empty());
    }

    #[test]
    fn spend_removes_coin() {
        let mut set = ArenaUtxoSet::new();
        let h = BlockHeight::new(100);
        let script = [0x76u8];

        let created = vec![
            new_coin(txid(1), 0, 5000, false, h, &script),
            new_coin(txid(1), 1, 3000, false, h, &script),
        ];
        set.connect_block(h, &created, &[]).unwrap();

        let op = OutPoint { txid: txid(1), vout: 0 };
        let undo = set.spend(&op, BlockHeight::new(101)).unwrap();
        assert_eq!(undo.coin.value, Satoshi::new(5000));
        assert!(set.get(&op).is_none());
        assert!(set.get(&OutPoint { txid: txid(1), vout: 1 }).is_some());
    }

    #[test]
    fn fully_spent_tx_removed_from_map() {
        let mut set = ArenaUtxoSet::new();
        let h = BlockHeight::new(100);
        let script = [0x76u8];

        let created = vec![new_coin(txid(1), 0, 5000, false, h, &script)];
        set.connect_block(h, &created, &[]).unwrap();
        assert_eq!(set.tx_count(), 1);

        set.spend(&OutPoint { txid: txid(1), vout: 0 }, BlockHeight::new(101))
            .unwrap();
        assert_eq!(set.tx_count(), 0);
    }

    #[test]
    fn coinbase_maturity_enforced() {
        let mut set = ArenaUtxoSet::new();
        let h = BlockHeight::new(50);
        let script = [0x76u8];

        let created = vec![new_coin(txid(1), 0, 5_000_000_000, true, h, &script)];
        set.connect_block(h, &created, &[]).unwrap();

        let op = OutPoint { txid: txid(1), vout: 0 };
        let err = set.spend(&op, BlockHeight::new(100)).unwrap_err();
        assert!(matches!(err, UtxoError::CoinbaseMaturity { .. }));

        let undo = set.spend(&op, BlockHeight::new(150)).unwrap();
        assert_eq!(undo.coin.value, Satoshi::new(5_000_000_000));
    }

    #[test]
    fn connect_then_disconnect_restores_state() {
        let mut set = ArenaUtxoSet::new();
        let h1 = BlockHeight::new(100);
        let h2 = BlockHeight::new(101);
        let script = [0x76u8];

        let created1 = vec![
            new_coin(txid(1), 0, 5000, false, h1, &script),
            new_coin(txid(1), 1, 3000, false, h1, &script),
        ];
        set.connect_block(h1, &created1, &[]).unwrap();

        let spent2 = vec![OutPoint { txid: txid(1), vout: 0 }];
        let created2 = vec![new_coin(txid(2), 0, 4000, false, h2, &script)];
        let undo2 = set.connect_block(h2, &created2, &spent2).unwrap();

        assert!(set.get(&OutPoint { txid: txid(1), vout: 0 }).is_none());
        assert!(set.get(&OutPoint { txid: txid(2), vout: 0 }).is_some());

        set.disconnect_block(&undo2);

        let restored = set.get(&OutPoint { txid: txid(1), vout: 0 }).unwrap();
        assert_eq!(restored.value, Satoshi::new(5000));
        assert!(set.get(&OutPoint { txid: txid(2), vout: 0 }).is_none());
    }

    #[test]
    fn multiple_disconnect_blocks() {
        let mut set = ArenaUtxoSet::new();
        let script = [0x76u8];

        let h1 = BlockHeight::new(100);
        let c1 = vec![new_coin(txid(1), 0, 1000, false, h1, &script)];
        let u1 = set.connect_block(h1, &c1, &[]).unwrap();

        let h2 = BlockHeight::new(101);
        let c2 = vec![new_coin(txid(2), 0, 2000, false, h2, &script)];
        let s2 = vec![OutPoint { txid: txid(1), vout: 0 }];
        let u2 = set.connect_block(h2, &c2, &s2).unwrap();

        let h3 = BlockHeight::new(102);
        let c3 = vec![new_coin(txid(3), 0, 3000, false, h3, &script)];
        let s3 = vec![OutPoint { txid: txid(2), vout: 0 }];
        let u3 = set.connect_block(h3, &c3, &s3).unwrap();

        set.disconnect_block(&u3);
        set.disconnect_block(&u2);
        set.disconnect_block(&u1);

        assert_eq!(set.tx_count(), 0);
        assert_eq!(set.coin_count(), 0);
    }
}
