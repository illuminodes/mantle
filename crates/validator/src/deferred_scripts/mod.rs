use mantle::collections::{BuildPrehashedHasher, PrehashedMap};
use mantle::primitives::{Block, BlockHeight, Hash256, OutPoint};
use mantle_consensus::chain_view::Coin;
use mantle_consensus::error::ValidationError;

use crate::script_pool::{ScriptBatch, ScriptPool};

#[cfg(test)]
mod tests;

pub(crate) type CoinMap = PrehashedMap<OutPoint, Option<Coin>>;

/// A committed block whose script checks may still be running, together
/// with the data those checks read.
struct PendingBlock {
    height: BlockHeight,
    hash: Hash256,
    block: Block,
    coins: CoinMap,
}

/// The script verdict of a block that was committed before its scripts
/// finished.
#[derive(Debug)]
pub struct SettledScripts {
    pub height: BlockHeight,
    pub hash: Hash256,
    pub verdict: Result<(), ValidationError>,
}

/// A [`ScriptPool`] whose checks for one block keep running while the
/// next block is prepared.
///
/// Holds the last committed block and the coin map its checks read until
/// [`settle`](Self::settle) collects their verdict. Moving a `Block` or a
/// map does not move the heap data the checks borrow, so both can be held
/// here by value.
///
/// Field order matters: `pool` drops first and waits for every check before
/// `pending` frees what they read.
pub struct DeferredScripts {
    pool: ScriptPool,
    pending: Option<PendingBlock>,
    spare: CoinMap,
}

impl DeferredScripts {
    #[must_use]
    pub fn new(pool: ScriptPool) -> Self {
        Self {
            pool,
            pending: None,
            spare: PrehashedMap::with_hasher(BuildPrehashedHasher),
        }
    }

    #[must_use]
    pub fn workers(&self) -> usize {
        self.pool.workers()
    }

    /// Wait for the held block's checks and return their verdict, freeing
    /// the block. Returns `None` when no block is held.
    pub fn settle(&mut self) -> Option<SettledScripts> {
        let verdict = self.pool.settle_verdict();
        let PendingBlock {
            height,
            hash,
            block,
            mut coins,
        } = self.pending.take()?;
        drop(block);
        coins.clear();
        self.spare = coins;
        Some(SettledScripts {
            height,
            hash,
            verdict,
        })
    }

    /// A batch for the next block's checks.
    ///
    /// # Safety
    /// Before the block and coin map the checks borrow are dropped or
    /// mutated, the caller must either pass both to [`hold`](Self::hold)
    /// untouched or call [`discard`](Self::discard).
    pub(crate) unsafe fn batch<'env>(&mut self) -> ScriptBatch<'_, 'env> {
        // SAFETY: forwarded to the caller.
        unsafe { self.pool.deferred_batch() }
    }

    /// Wait for the checks of a block that was rejected for another reason
    /// and drop their verdict.
    pub(crate) fn discard(&mut self) {
        self.pool.discard();
    }

    /// Keep `block` and `coins` alive until the next [`settle`](Self::settle).
    /// `coins` is swapped for an empty map with reusable capacity.
    ///
    /// The caller settles the previous block first. If it did not, this
    /// waits for every running check before freeing that block, so the
    /// mistake costs a verdict, never a dangling read.
    pub(crate) fn hold(
        &mut self,
        height: BlockHeight,
        hash: Hash256,
        block: Block,
        coins: &mut CoinMap,
    ) {
        if self.pending.is_some() {
            self.pool.wait_all();
        }
        let coins = std::mem::replace(coins, std::mem::take(&mut self.spare));
        self.pending = Some(PendingBlock {
            height,
            hash,
            block,
            coins,
        });
    }
}
