use mantle::primitives::{OutPoint, Satoshi};

use crate::keyring::Keyring;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoinKind {
    P2pkh,
    P2wpkh,
}

impl CoinKind {
    /// Spreads `percent` segwit outputs evenly over consecutive `counter` values.
    pub fn pick(counter: u64, segwit_percent: u32) -> Self {
        if (counter * 37) % 100 < u64::from(segwit_percent) {
            Self::P2wpkh
        } else {
            Self::P2pkh
        }
    }
}

/// An unspent output of the synthetic chain, with what it takes to spend it.
#[derive(Clone, Copy, Debug)]
pub struct SpendableCoin {
    pub outpoint: OutPoint,
    pub value: Satoshi,
    pub key: usize,
    pub kind: CoinKind,
}

impl SpendableCoin {
    pub fn script_pubkey(&self, keys: &Keyring) -> Vec<u8> {
        match self.kind {
            CoinKind::P2pkh => keys.p2pkh_script(self.key),
            CoinKind::P2wpkh => keys.p2wpkh_script(self.key),
        }
    }
}
