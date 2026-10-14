use mantle::primitives::{Block, BlockHeight, Hash256};
use mantle_consensus::error::ValidationError;

use super::block_job::BlockJob;

/// What [`ConnectPipeline::connect`](super::ConnectPipeline::connect) did
/// with a block.
pub enum Connected {
    /// Every rule but the scripts passed; the block is queued and its
    /// scripts are running.
    Queued,
    /// A rule other than a script check failed. Nothing was queued; the job
    /// is handed back so the caller can save it or queue it unvalidated.
    Rejected {
        error: ValidationError,
        job: Box<BlockJob>,
    },
}

/// The script outcome of a queued block.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Valid,
    ScriptFailed(ValidationError),
    /// Queued with [`ConnectPipeline::force`](super::ConnectPipeline::force)
    /// after failing another check; its scripts were not run.
    Forced,
}

/// A block that left the pipeline, oldest first.
#[derive(Debug)]
pub struct Retired {
    pub height: BlockHeight,
    pub hash: Hash256,
    pub verdict: Verdict,
    /// `false` from the first script failure on in a pipeline that does not
    /// commit invalid blocks; storage then ends at the block before it.
    pub committed: bool,
    /// The block itself when its scripts failed, so it can be saved.
    pub failed_block: Option<Block>,
}

/// How long [`ConnectPipeline::retire_next`](super::ConnectPipeline::retire_next)
/// may wait for the oldest block's scripts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// Only when the pipeline holds more than its in-flight limit.
    IfOverLimit,
    /// Always; used to drain the pipeline.
    Always,
}
