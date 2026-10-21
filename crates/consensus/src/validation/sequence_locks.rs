use mantle::primitives::{
    BlockHeader, BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Nonce,
};

use super::block_coins::SpentCoin;
use crate::chain_view::ChainView;
use crate::error::{ChainViewError, ValidationError};
use crate::tx_view::{InputView, TxView};

/// BIP68 relative lock-times, enforced per transaction while connecting a block.
///
/// For a version-2+ transaction, each input whose `nSequence` does not set the
/// disable flag requires its spent coin to be buried by a number of blocks, or
/// by a number of 512-second units of median time past, before the block that
/// spends it.
pub(super) struct SequenceLocks<'v, V: ChainView> {
    view: &'v V,
    block_header: &'v BlockHeader,
    height: BlockHeight,
}

impl<'v, V: ChainView> SequenceLocks<'v, V> {
    /// Mainnet height at which BIP68 (with BIP112 and BIP113) became active.
    pub(super) const BIP68_HEIGHT: BlockHeight = BlockHeight::new(419_328);

    const DISABLE_FLAG: u32 = 1 << 31;
    const TYPE_FLAG: u32 = 1 << 22;
    const VALUE_MASK: u32 = 0x0000_ffff;
    const GRANULARITY_SHIFT: u32 = 9;

    pub(super) fn new(view: &'v V, block_header: &'v BlockHeader, height: BlockHeight) -> Self {
        Self {
            view,
            block_header,
            height,
        }
    }

    /// # Errors
    /// `SequenceLockNotSatisfied` when an input's relative lock has not
    /// elapsed; `ChainView` when a needed header is unavailable.
    pub(super) fn check<T: TxView>(
        &self,
        tx: &T,
        coins: &[SpentCoin<'_>],
        tx_index: usize,
    ) -> Result<(), ValidationError> {
        if self.height < Self::BIP68_HEIGHT || tx.version().to_u32() < 2 {
            return Ok(());
        }
        let mut min_height: i64 = -1;
        let mut min_time: i64 = -1;
        for (input, coin) in tx.inputs().zip(coins) {
            let sequence = input.sequence().to_u32();
            if sequence & Self::DISABLE_FLAG != 0 {
                continue;
            }
            let value = i64::from(sequence & Self::VALUE_MASK);
            let coin_height = i64::from(coin.height.to_u32());
            if sequence & Self::TYPE_FLAG != 0 {
                let anchor = coin.height.to_u32().saturating_sub(1);
                let coin_time = self.median_time_past_at(anchor)?;
                min_time = min_time.max(coin_time + (value << Self::GRANULARITY_SHIFT) - 1);
            } else {
                min_height = min_height.max(coin_height + value - 1);
            }
        }
        let height_unmet = min_height >= i64::from(self.height.to_u32());
        let time_unmet = min_time >= 0 && min_time >= self.previous_median_time_past()?;
        if height_unmet || time_unmet {
            return Err(ValidationError::SequenceLockNotSatisfied { tx_index });
        }
        Ok(())
    }

    fn previous_median_time_past(&self) -> Result<i64, ValidationError> {
        Ok(i64::from(
            self.view.median_time_past(self.block_header)?.to_u32(),
        ))
    }

    fn median_time_past_at(&self, height: u32) -> Result<i64, ValidationError> {
        let header = self
            .view
            .get_header_at(BlockHeight::new(height))?
            .ok_or(ValidationError::ChainView(ChainViewError::NotFound))?;
        let child = BlockHeader::new(
            BlockVersion::new(0),
            header.hash(),
            Hash256::ZERO,
            BlockTime::new(0),
            CompactBits::new(0),
            Nonce::new(0),
        );
        Ok(i64::from(self.view.median_time_past(&child)?.to_u32()))
    }
}
