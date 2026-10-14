use mantle::primitives::{Block, BlockHeight, Hash256};
use mantle_storage::types::{Durability, ReqToken};

use crate::block_inputs::BlockInputs;

/// A decoded block handed to the pipeline, with what it reads from the
/// UTXO set and how its commit should be written.
pub struct BlockJob {
    pub height: BlockHeight,
    pub hash: Hash256,
    pub block: Block,
    pub inputs: BlockInputs,
    pub durability: Durability,
    pub token: ReqToken,
}

impl BlockJob {
    #[must_use]
    pub fn new(block: Block, height: BlockHeight, durability: Durability, token: ReqToken) -> Self {
        let inputs = BlockInputs::of(&block, height);
        Self {
            height,
            hash: block.header.hash(),
            block,
            inputs,
            durability,
            token,
        }
    }
}
