use mantle::primitives::{Block, BlockHeight, BlockTime, Sequence, Transaction};

use crate::error::ValidationError;

/// Lock-time finality of a block's transactions (`IsFinalTx`).
///
/// A transaction is final when its `nLockTime` is zero, lies below the
/// block's height (height locks) or cutoff time (time locks), or every input
/// opts out with `nSequence = 0xffffffff`. From BIP113 activation the cutoff
/// time is the median time past of the previous 11 blocks instead of the
/// block's own timestamp.
pub(super) struct TxFinality {
    height: BlockHeight,
    cutoff_time: BlockTime,
}

impl TxFinality {
    /// Mainnet height at which BIP113 (with BIP68 and BIP112) became active.
    pub(super) const BIP113_HEIGHT: BlockHeight = BlockHeight::new(419_328);

    pub(super) fn new(height: BlockHeight, block_time: BlockTime, median_time_past: BlockTime) -> Self {
        let cutoff_time = if height >= Self::BIP113_HEIGHT {
            median_time_past
        } else {
            block_time
        };
        Self {
            height,
            cutoff_time,
        }
    }

    pub(super) fn is_final(&self, tx: &Transaction) -> bool {
        let lock = tx.locktime;
        if lock.to_u32() == 0 {
            return true;
        }
        let limit = if lock.is_block_height() {
            self.height.to_u32()
        } else {
            self.cutoff_time.to_u32()
        };
        if lock.to_u32() < limit {
            return true;
        }
        tx.inputs.iter().all(|input| input.sequence == Sequence::MAX)
    }

    /// # Errors
    /// `NonFinalTransaction` for the first transaction that is not final.
    pub(super) fn check(&self, block: &Block) -> Result<(), ValidationError> {
        match block.transactions.iter().position(|tx| !self.is_final(tx)) {
            Some(tx_index) => Err(ValidationError::NonFinalTransaction { tx_index }),
            None => Ok(()),
        }
    }
}
