use mantle::primitives::{BlockHeader, BlockHeight, Hash256};

/// What a [`crate::BlockFeed`] caller wants headers for.
pub struct HeaderRequest<A> {
    pub start: BlockHeight,
    pub stop: BlockHeight,
    pub locator: Hash256,
    pub admission: A,
}

/// The blocks a [`crate::BlockFeed`] should download and hand over.
///
/// Blocks are fetched `window` at a time and handed over in height order;
/// the next window downloads while the caller works on the one before it.
/// With `discard_each_window` the cached block files are dropped once a
/// window has been handed over. Without `deliver` the blocks are only
/// cached and nothing but the end of the request comes back. `staging`
/// says where a window waits before it is handed over.
pub struct BlocksRequest {
    pub wanted: Vec<(BlockHeight, BlockHeader)>,
    pub window: usize,
    pub discard_each_window: bool,
    pub deliver: bool,
    pub staging: BlockStaging,
}

/// Where a downloading window waits: in the block cache on disk, which a
/// later run can read again, or in memory, which never touches the disk
/// and holds at most one window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockStaging {
    Disk,
    Memory,
}

/// Ask the peers which headers follow `held`, the chain from `start` whose
/// parent is `base`, without admitting any of them.
pub struct SurveyRequest {
    pub start: BlockHeight,
    pub base: Hash256,
    pub held: Vec<(BlockHeight, BlockHeader)>,
}

pub(crate) enum FeedRequest<A> {
    Headers(HeaderRequest<A>),
    Survey(SurveyRequest),
    Blocks(BlocksRequest),
    Discard,
}
