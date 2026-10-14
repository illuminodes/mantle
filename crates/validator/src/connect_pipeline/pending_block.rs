use mantle::primitives::{Block, OutPoint};
use mantle_consensus::chain_view::NewCoin;

use super::block_job::BlockJob;
use crate::prefetched_view::CoinMap;

/// Where a pending block's script checks stand.
#[derive(Clone, Copy, Debug)]
pub(super) enum ScriptState {
    /// Queued on the pool under this block id.
    Running(u64),
    /// The pipeline does not verify scripts.
    Skipped,
    /// Queued unvalidated after another check failed.
    Forced,
}

/// A block's UTXO delta whose created coins borrow script bytes from the
/// block's transactions, with that borrow's lifetime erased.
///
/// The transactions are heap allocations inside a boxed [`BlockJob`], so
/// moving the box, or the struct that owns it, does not move them.
/// [`PendingBlock`] keeps this delta next to the job and drops it first.
pub(super) struct DetachedDelta {
    created: Vec<NewCoin<'static>>,
    spent: Vec<OutPoint>,
}

impl DetachedDelta {
    /// # Safety
    /// Every coin in `created` must borrow only from the block of the
    /// `BlockJob` this delta is later queued with.
    pub(super) unsafe fn new(created: Vec<NewCoin<'_>>, spent: Vec<OutPoint>) -> Self {
        // SAFETY: only the lifetime parameter changes; the caller ties the
        // borrowed bytes to the job the delta is stored next to.
        let created =
            unsafe { std::mem::transmute::<Vec<NewCoin<'_>>, Vec<NewCoin<'static>>>(created) };
        Self { created, spent }
    }

    pub(super) fn created(&self) -> &[NewCoin<'_>] {
        &self.created
    }

    pub(super) fn spent(&self) -> &[OutPoint] {
        &self.spent
    }
}

/// A connected block waiting for its scripts, holding everything its
/// checks read and everything its commit writes.
///
/// Field order matters: `delta` drops before `job`, whose block its coins
/// borrow from.
pub(super) struct PendingBlock {
    pub(super) delta: DetachedDelta,
    pub(super) coins: CoinMap,
    pub(super) scripts: ScriptState,
    pub(super) inputs: usize,
    pub(super) job: Box<BlockJob>,
}

impl PendingBlock {
    pub(super) fn new(
        job: Box<BlockJob>,
        delta: DetachedDelta,
        coins: CoinMap,
        scripts: ScriptState,
    ) -> Self {
        let inputs = job.inputs.input_count();
        Self {
            delta,
            coins,
            scripts,
            inputs,
            job,
        }
    }

    /// Hand back the coin map for reuse and the block, which is only kept
    /// when `keep_block` is set.
    pub(super) fn into_parts(self, keep_block: bool) -> (CoinMap, Option<Block>) {
        let Self {
            delta, coins, job, ..
        } = self;
        drop(delta);
        let block = keep_block.then_some(job.block);
        (coins, block)
    }
}
