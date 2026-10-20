mod support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mantle::network::Network;
use mantle::primitives::{BlockHeader, BlockHeight};
use mantle_fetcher::MemoryBlocks;

use support::{ChainFixture, FakeNode};

#[test]
fn blocks_fetched_in_memory_arrive_whole_and_leave_no_block_file() {
    let fixture = ChainFixture::new("memory-blocks");
    let headers = ChainFixture::branch(Network::Regtest.genesis_hash(), 3, 0);
    let blocks: HashMap<_, _> = headers.iter().map(|header| (header.hash(), ChainFixture::block(header))).collect();
    let (address, node) = FakeNode::spawn_with(Arc::new(Mutex::new(headers.clone())), blocks.clone(), Duration::ZERO);
    let window: Vec<(BlockHeight, BlockHeader)> = (1..).map(BlockHeight::new).zip(headers.iter().copied()).collect();

    let mut fetcher = fixture.fetcher(&[address]);
    let mut held = MemoryBlocks::default();
    fetcher.fetch_blocks_in_memory(&window, &mut held).expect("fetch");
    drop(fetcher);
    node.join().expect("node");

    assert_eq!(held.len(), 3);
    for (height, header) in &window {
        assert_eq!(held.take(*height), blocks.get(&header.hash()).cloned());
    }
    let block_file = std::fs::metadata(fixture.dir.join("blocks.bin")).map_or(0, |metadata| metadata.len());
    assert_eq!(block_file, 0);
}
