use std::time::Duration;

use mantle::primitives::{BlockHeader, BlockHeight, Hash256};

/// A downloaded block, not yet decoded.
pub struct FedBlock {
    pub height: BlockHeight,
    pub hash: Hash256,
    pub bytes: Vec<u8>,
}

/// What a [`crate::BlockFeed`] sends back.
///
/// A header request ends in `Headers` or `Failed`; a blocks request in
/// `Done` or `Failed`, after its `Block`s and `WindowDone`s; a discard in
/// `Done` or `Failed`.
pub enum FeedItem<A> {
    Headers(Vec<(BlockHeight, BlockHeader)>, A),
    Block(FedBlock),
    WindowDone {
        first: BlockHeight,
        last: BlockHeight,
        elapsed: Duration,
    },
    Done,
    Failed(String),
}
