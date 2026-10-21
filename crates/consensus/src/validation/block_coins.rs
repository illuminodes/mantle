use mantle::collections::{PrehashedMap, PrehashedSet};
use mantle::primitives::{BlockHeight, OutPoint, Satoshi};

use super::tx_script_context::Prevout;
use crate::chain_view::{Coin, NewCoin};

/// The output an input spends, whether it came from the UTXO set or from an
/// earlier transaction in the same block.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SpentCoin<'a> {
    pub value: Satoshi,
    pub script_pubkey: &'a [u8],
    pub height: BlockHeight,
    pub coinbase: bool,
}

impl<'a> SpentCoin<'a> {
    pub(crate) fn from_utxo(coin: &'a Coin) -> Self {
        Self {
            value: coin.value,
            script_pubkey: coin.script_pubkey.as_slice(),
            height: coin.height,
            coinbase: coin.coinbase,
        }
    }

    pub(crate) fn from_block(coin: &NewCoin<'a>) -> Self {
        Self {
            value: coin.value,
            script_pubkey: coin.script_pubkey,
            height: coin.height,
            coinbase: coin.coinbase,
        }
    }

    pub(crate) fn prevout(&self) -> Prevout<'a> {
        Prevout {
            value: self.value,
            script_pubkey: self.script_pubkey,
        }
    }
}

/// Outputs created and outpoints spent so far while connecting one block.
///
/// Lets `connect_block` resolve spends of earlier same-block outputs in block
/// order, and reject a second spend of any outpoint within the block.
#[derive(Default)]
pub(crate) struct InBlockCoins {
    created: PrehashedMap<OutPoint, usize>,
    spent: PrehashedSet<OutPoint>,
}

impl InBlockCoins {
    pub(crate) fn clear(&mut self) {
        self.created.clear();
        self.spent.clear();
    }

    pub(crate) fn record_created(&mut self, outpoint: OutPoint, index: usize) {
        self.created.insert(outpoint, index);
    }

    /// Mark `outpoint` spent. Returns `false` if it was already spent earlier
    /// in this block.
    pub(crate) fn spend(&mut self, outpoint: OutPoint) -> bool {
        self.spent.insert(outpoint)
    }

    /// Index into the block's created-coin list, if `outpoint` was created by
    /// an earlier transaction in this block.
    pub(crate) fn created_index(&self, outpoint: &OutPoint) -> Option<usize> {
        self.created.get(outpoint).copied()
    }
}
