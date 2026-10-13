use mantle::collections::{BuildPrehashedHasher, PrehashedMap, PrehashedSet};
use mantle::primitives::{BlockHeight, Hash256, OutPoint};
use mantle_consensus::chain_view::{Coin, NewCoin};
use mantle_utxo_hash::{UtxoCoin, UtxoSetHash};

/// Applies one connected block's UTXO delta to a [`UtxoSetHash`].
///
/// Coins created and spent inside the same block never reach the UTXO set,
/// so they are left out of the hash on both sides.
pub struct UtxoHashUpdate {
    in_block_spends: PrehashedSet<OutPoint>,
}

impl UtxoHashUpdate {
    #[must_use]
    pub fn new() -> Self {
        Self {
            in_block_spends: PrehashedSet::with_hasher(BuildPrehashedHasher),
        }
    }

    /// `prior` maps each spent outpoint to the coin it had before this block;
    /// outpoints missing from it (or mapped to `None`) were created in the block.
    pub fn apply(
        &mut self,
        hash: &mut UtxoSetHash,
        block: (BlockHeight, Hash256),
        created: &[NewCoin<'_>],
        spent: &[OutPoint],
        prior: &PrehashedMap<OutPoint, Option<Coin>>,
    ) {
        self.in_block_spends.clear();
        for outpoint in spent {
            match prior.get(outpoint) {
                Some(Some(coin)) => hash.remove(&Self::prior_coin(*outpoint, coin)),
                _ => {
                    self.in_block_spends.insert(*outpoint);
                }
            }
        }
        let skip_coinbase = UtxoSetHash::skips_coinbase_of(block.0, block.1);
        for coin in created {
            if self.in_block_spends.contains(&coin.outpoint) || (skip_coinbase && coin.coinbase) {
                continue;
            }
            hash.insert(&UtxoCoin {
                outpoint: coin.outpoint,
                value: coin.value,
                script_pubkey: coin.script_pubkey,
                height: coin.height,
                coinbase: coin.coinbase,
            });
        }
    }

    fn prior_coin(outpoint: OutPoint, coin: &Coin) -> UtxoCoin<'_> {
        UtxoCoin {
            outpoint,
            value: coin.value,
            script_pubkey: coin.script_pubkey.as_slice(),
            height: coin.height,
            coinbase: coin.coinbase,
        }
    }
}

impl Default for UtxoHashUpdate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::UtxoHashUpdate;
    use mantle::collections::{BuildPrehashedHasher, PrehashedMap};
    use mantle::primitives::{BlockHeight, Hash256, OutPoint, Satoshi};
    use mantle_consensus::chain_view::{Coin, NewCoin};
    use mantle_utxo_hash::{UtxoCoin, UtxoSetHash};

    const SCRIPT: &[u8] = &[0x51];

    fn outpoint(byte: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: Hash256::from_bytes([byte; 32]),
            vout,
        }
    }

    fn new_coin(outpoint: OutPoint, height: u32, coinbase: bool) -> NewCoin<'static> {
        NewCoin {
            outpoint,
            value: Satoshi::new(1_000),
            script_pubkey: SCRIPT,
            coinbase,
            height: BlockHeight::new(height),
        }
    }

    fn utxo(c: &NewCoin<'static>) -> UtxoCoin<'static> {
        UtxoCoin {
            outpoint: c.outpoint,
            value: c.value,
            script_pubkey: c.script_pubkey,
            height: c.height,
            coinbase: c.coinbase,
        }
    }

    fn block(height: u32) -> (BlockHeight, Hash256) {
        (BlockHeight::new(height), Hash256::from_bytes([0xee; 32]))
    }

    #[test]
    fn matches_inserting_and_removing_the_coins_directly() {
        let old = new_coin(outpoint(1, 0), 5, false);
        let mut prior = PrehashedMap::with_hasher(BuildPrehashedHasher);
        prior.insert(
            old.outpoint,
            Some(Coin {
                value: old.value,
                script_pubkey: SCRIPT.to_vec().into(),
                height: old.height,
                coinbase: false,
            }),
        );
        let fresh = new_coin(outpoint(2, 0), 9, false);

        let mut tracked = UtxoSetHash::new();
        tracked.insert(&utxo(&old));
        UtxoHashUpdate::new().apply(
            &mut tracked,
            block(9),
            std::slice::from_ref(&fresh),
            &[old.outpoint],
            &prior,
        );

        let mut direct = UtxoSetHash::new();
        direct.insert(&utxo(&fresh));
        assert_eq!(tracked.finalize(), direct.finalize());
    }

    #[test]
    fn coins_created_and_spent_in_the_block_are_left_out() {
        let made = new_coin(outpoint(3, 0), 9, false);
        let kept = new_coin(outpoint(3, 1), 9, false);
        let mut prior = PrehashedMap::with_hasher(BuildPrehashedHasher);
        prior.insert(made.outpoint, None);

        let mut tracked = UtxoSetHash::new();
        UtxoHashUpdate::new().apply(
            &mut tracked,
            block(9),
            &[made.clone(), kept.clone()],
            &[made.outpoint],
            &prior,
        );

        let mut direct = UtxoSetHash::new();
        direct.insert(&utxo(&kept));
        assert_eq!(tracked.finalize(), direct.finalize());
    }

    #[test]
    fn the_overwritten_coinbase_blocks_add_no_coinbase_outputs() {
        let hash_91812 = Hash256::from_display_hex_const(
            "00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f",
        );
        let coinbase = new_coin(outpoint(4, 0), 91_812, true);
        let other = new_coin(outpoint(5, 0), 91_812, false);

        let mut tracked = UtxoSetHash::new();
        UtxoHashUpdate::new().apply(
            &mut tracked,
            (BlockHeight::new(91_812), hash_91812),
            &[coinbase, other.clone()],
            &[],
            &PrehashedMap::with_hasher(BuildPrehashedHasher),
        );

        let mut direct = UtxoSetHash::new();
        direct.insert(&utxo(&other));
        assert_eq!(tracked.finalize(), direct.finalize());
    }
}
