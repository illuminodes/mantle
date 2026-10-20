use std::collections::HashMap;

use mantle::primitives::BlockHeight;

/// Raw blocks held in memory by height while one window downloads, for a
/// caller that does not keep blocks on disk.
#[derive(Debug, Default)]
pub struct MemoryBlocks {
    blocks: HashMap<BlockHeight, Vec<u8>>,
}

impl MemoryBlocks {
    #[must_use]
    pub fn has(&self, height: BlockHeight) -> bool {
        self.blocks.contains_key(&height)
    }

    pub fn put(&mut self, height: BlockHeight, bytes: Vec<u8>) {
        self.blocks.insert(height, bytes);
    }

    pub fn take(&mut self, height: BlockHeight) -> Option<Vec<u8>> {
        self.blocks.remove(&height)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use mantle::primitives::BlockHeight;

    use super::MemoryBlocks;

    #[test]
    fn a_block_is_held_until_taken() {
        let mut held = MemoryBlocks::default();
        held.put(BlockHeight::new(5), vec![1, 2]);

        assert!(held.has(BlockHeight::new(5)));
        assert_eq!(held.take(BlockHeight::new(5)), Some(vec![1, 2]));
        assert!(held.is_empty());
        assert_eq!(held.take(BlockHeight::new(5)), None);
    }
}
