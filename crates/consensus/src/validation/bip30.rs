use mantle::primitives::{BlockHeader, BlockHeight, Hash256, OutPoint};

use super::structure::BIP34_HEIGHT;
use crate::chain_view::ChainView;
use crate::error::ValidationError;
use crate::tx_view::{BlockView, TxView};

/// BIP30: a transaction may not create an output that already exists unspent.
///
/// Enforced like Bitcoin Core's `ConnectBlock`: on every block except the two
/// historical duplicate-coinbase blocks, up to and including the BIP34
/// activation height, and again from height 1,983,702, where coinbases from
/// before BIP34 could first be repeated. Activation is decided by mainnet
/// height, as for the other buried deployments.
#[derive(Debug, Clone, Copy)]
pub struct Bip30 {
    enforced: bool,
}

impl Bip30 {
    const EXCEPTIONS: [(BlockHeight, Hash256); 2] = [
        (
            BlockHeight::new(91_842),
            Hash256::from_display_hex_const(
                "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec",
            ),
        ),
        (
            BlockHeight::new(91_880),
            Hash256::from_display_hex_const(
                "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721",
            ),
        ),
    ];

    /// First height at which a coinbase from before BIP34 could repeat a txid.
    pub const BIP34_IMPLIES_BIP30_LIMIT: BlockHeight = BlockHeight::new(1_983_702);

    #[must_use]
    pub fn new(height: BlockHeight, header: &BlockHeader) -> Self {
        let covered_by_bip34 = height > BIP34_HEIGHT && height < Self::BIP34_IMPLIES_BIP30_LIMIT;
        Self {
            enforced: !covered_by_bip34 && !Self::is_exception(height, header),
        }
    }

    fn is_exception(height: BlockHeight, header: &BlockHeader) -> bool {
        Self::EXCEPTIONS
            .iter()
            .any(|(h, hash)| *h == height && header.hash() == *hash)
    }

    #[must_use]
    pub fn is_enforced(self) -> bool {
        self.enforced
    }

    /// Every outpoint the check will look up, in block order. Empty when the
    /// rule is not enforced. `txids` must be the block's txids in order.
    #[allow(clippy::cast_possible_truncation)]
    pub fn probes<'a, B: BlockView>(
        self,
        block: &'a B,
        txids: &'a [Hash256],
    ) -> impl Iterator<Item = OutPoint> + 'a {
        let enforced = self.enforced;
        block
            .txs()
            .zip(txids)
            .filter(move |_| enforced)
            .flat_map(|(tx, &txid)| {
                (0..tx.output_count()).map(move |vout| OutPoint {
                    txid,
                    vout: vout as u32,
                })
            })
    }

    /// # Errors
    /// `Bip30Violation` when any output of `tx` already exists in `view`;
    /// `ChainView` when a lookup fails.
    #[allow(clippy::cast_possible_truncation)]
    pub(super) fn check<V: ChainView, T: TxView>(
        self,
        view: &V,
        tx: &T,
        txid: Hash256,
        tx_index: usize,
    ) -> Result<(), ValidationError> {
        if !self.enforced {
            return Ok(());
        }
        for vout in 0..tx.output_count() {
            let outpoint = OutPoint {
                txid,
                vout: vout as u32,
            };
            if view.get_coin(&outpoint)?.is_some() {
                return Err(ValidationError::Bip30Violation { tx_index });
            }
        }
        Ok(())
    }
}
