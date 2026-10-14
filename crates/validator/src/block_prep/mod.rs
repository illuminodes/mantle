mod commit_plan;
mod in_order;
mod prep_pool;

#[cfg(test)]
mod tests;

use std::io::Cursor;
use std::sync::Arc;

use mantle::codec::Decode;
use mantle::collections::{BuildPrehashedHasher, PrehashedMap};
use mantle::primitives::{Block, BlockHeight, Hash256};
use mantle_consensus::chain_view::TipInfo;
use mantle_consensus::error::ValidationError;
use mantle_consensus::validation::{
    Clock, validate_block_context_with_clock, validate_block_structure,
};

pub use commit_plan::CommitPlan;
pub use in_order::InOrder;
pub use prep_pool::{PrepPool, RawBlock};

use crate::connect_pipeline::BlockJob;
use crate::prefetched_view::{HeaderSnapshot, PrefetchedView};

/// A check that needs only the block and the header chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrepCheck {
    Structure,
    Context,
}

/// A block ready for [`ConnectPipeline::connect`](crate::ConnectPipeline::connect),
/// or one that already failed a check that does not need the UTXO set.
pub enum Prepared {
    Ready(BlockJob),
    Invalid {
        job: BlockJob,
        failures: Vec<(PrepCheck, ValidationError)>,
    },
}

/// Turns downloaded block bytes into a [`BlockJob`]: decodes them, checks
/// the hash, runs the structure and context checks, and works out what the
/// block reads from the UTXO set. None of this depends on earlier blocks
/// being connected, so many threads can prepare blocks ahead of the one
/// being connected.
pub struct BlockPreparer<C> {
    headers: Arc<HeaderSnapshot>,
    clock: C,
    allow_min_difficulty: bool,
    commits: CommitPlan,
}

impl<C: Clock> BlockPreparer<C> {
    #[must_use]
    pub fn new(
        headers: Arc<HeaderSnapshot>,
        clock: C,
        allow_min_difficulty: bool,
        commits: CommitPlan,
    ) -> Self {
        Self {
            headers,
            clock,
            allow_min_difficulty,
            commits,
        }
    }

    /// # Errors
    /// A message when the bytes do not decode or hash to `hash`.
    pub fn prepare(
        &self,
        height: BlockHeight,
        hash: Hash256,
        bytes: &[u8],
    ) -> Result<Prepared, String> {
        let block = Block::decode(&mut Cursor::new(bytes))
            .map_err(|e| format!("decode block {}: {e}", height.to_u32()))?;
        if block.header.hash() != hash {
            return Err(format!(
                "block {} hashes to {}, expected {hash}",
                height.to_u32(),
                block.header.hash()
            ));
        }
        let mut failures = Vec::new();
        if let Err(e) = validate_block_structure(&block) {
            failures.push((PrepCheck::Structure, e));
        }
        if let Err(e) = self.check_context(&block, height) {
            failures.push((PrepCheck::Context, e));
        }
        let job = BlockJob::new(
            block,
            height,
            self.commits.durability(height),
            CommitPlan::token(height),
        );
        Ok(if failures.is_empty() {
            Prepared::Ready(job)
        } else {
            Prepared::Invalid { job, failures }
        })
    }

    fn check_context(&self, block: &Block, height: BlockHeight) -> Result<(), ValidationError> {
        let empty = PrehashedMap::with_hasher(BuildPrehashedHasher);
        let parent = TipInfo {
            hash: block.header.prev_block(),
            height: BlockHeight::new(height.to_u32().saturating_sub(1)),
        };
        let view = PrefetchedView::new(&empty, &self.headers, parent);
        validate_block_context_with_clock(block, &view, &self.clock, self.allow_min_difficulty)
    }
}
