use std::collections::VecDeque;

use mantle::collections::{BuildPrehashedHasher, PrehashedMap};
use mantle::primitives::{BlockHeight, OutPoint, ScriptPubKey};
use mantle_consensus::chain_view::{Coin, NewCoin};

struct OverlayEntry {
    height: BlockHeight,
    coin: Option<Coin>,
}

/// UTXO changes of connected blocks that are not in storage yet.
///
/// A block is connected against storage seen through this overlay, applies
/// its delta here, and is written to storage only once its scripts pass.
/// Each entry is tagged with the block that last touched it, so retiring a
/// committed block removes only the entries no later block has changed.
pub struct UtxoOverlay {
    entries: PrehashedMap<OutPoint, OverlayEntry>,
    touched: VecDeque<(BlockHeight, Vec<OutPoint>)>,
}

impl UtxoOverlay {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: PrehashedMap::with_hasher(BuildPrehashedHasher),
            touched: VecDeque::new(),
        }
    }

    /// `Some(Some(coin))` when a pending block created the coin,
    /// `Some(None)` when a pending block spent it, `None` when storage
    /// holds the answer.
    #[must_use]
    pub fn get(&self, outpoint: &OutPoint) -> Option<Option<&Coin>> {
        self.entries.get(outpoint).map(|e| e.coin.as_ref())
    }

    /// Record a connected block's delta. Coins created and spent inside the
    /// block end up marked spent.
    pub fn apply(&mut self, height: BlockHeight, created: &[NewCoin<'_>], spent: &[OutPoint]) {
        let mut keys = Vec::with_capacity(created.len() + spent.len());
        for coin in created {
            self.entries.insert(
                coin.outpoint,
                OverlayEntry {
                    height,
                    coin: Some(Coin {
                        value: coin.value,
                        script_pubkey: ScriptPubKey::from_slice(coin.script_pubkey),
                        height: coin.height,
                        coinbase: coin.coinbase,
                    }),
                },
            );
            keys.push(coin.outpoint);
        }
        for outpoint in spent {
            self.entries
                .insert(*outpoint, OverlayEntry { height, coin: None });
            keys.push(*outpoint);
        }
        self.touched.push_back((height, keys));
    }

    /// Forget the oldest applied block once storage holds its delta.
    ///
    /// # Panics
    /// Panics if `height` is not the oldest block still in the overlay.
    pub fn retire(&mut self, height: BlockHeight) {
        let (oldest, keys) = self
            .touched
            .pop_front()
            .expect("retiring a block the overlay never applied");
        assert_eq!(oldest, height, "blocks must be retired in the order they were applied");
        for key in keys {
            if self.entries.get(&key).is_some_and(|e| e.height == height) {
                self.entries.remove(&key);
            }
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.touched.is_empty()
    }

    #[must_use]
    pub fn blocks(&self) -> usize {
        self.touched.len()
    }
}

impl Default for UtxoOverlay {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use mantle::primitives::{Hash256, Satoshi};

    use super::*;

    const SCRIPT: &[u8] = &[0x51];

    fn outpoint(tag: u8) -> OutPoint {
        OutPoint {
            txid: Hash256::from_bytes([tag; 32]),
            vout: 0,
        }
    }

    fn created(tag: u8, height: u32) -> NewCoin<'static> {
        NewCoin {
            outpoint: outpoint(tag),
            value: Satoshi::new(1_000),
            script_pubkey: SCRIPT,
            coinbase: false,
            height: BlockHeight::new(height),
        }
    }

    #[test]
    fn unknown_outpoints_fall_through_to_storage() {
        let overlay = UtxoOverlay::new();
        assert!(overlay.get(&outpoint(1)).is_none());
    }

    #[test]
    fn a_coin_created_then_spent_by_a_later_pending_block_reads_as_spent() {
        let mut overlay = UtxoOverlay::new();
        overlay.apply(BlockHeight::new(10), &[created(1, 10)], &[]);
        assert!(overlay.get(&outpoint(1)).expect("pending").is_some());
        overlay.apply(BlockHeight::new(11), &[], &[outpoint(1)]);
        assert!(overlay.get(&outpoint(1)).expect("pending").is_none());

        overlay.retire(BlockHeight::new(10));
        assert!(
            overlay.get(&outpoint(1)).expect("still pending spend").is_none(),
            "block 11's spend must survive block 10 reaching storage"
        );
        overlay.retire(BlockHeight::new(11));
        assert!(overlay.get(&outpoint(1)).is_none());
        assert!(overlay.is_empty());
    }

    #[test]
    fn a_coin_created_and_spent_in_one_block_reads_as_spent() {
        let mut overlay = UtxoOverlay::new();
        overlay.apply(BlockHeight::new(10), &[created(2, 10)], &[outpoint(2)]);
        assert!(overlay.get(&outpoint(2)).expect("pending").is_none());
    }

    #[test]
    #[should_panic(expected = "in the order they were applied")]
    fn blocks_retire_oldest_first() {
        let mut overlay = UtxoOverlay::new();
        overlay.apply(BlockHeight::new(10), &[], &[]);
        overlay.apply(BlockHeight::new(11), &[], &[]);
        overlay.retire(BlockHeight::new(11));
    }
}
