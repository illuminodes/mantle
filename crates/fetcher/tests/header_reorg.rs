mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use mantle::network::Network;
use mantle::primitives::{BlockHeader, BlockHeight};

use support::{ChainFixture, FakeNode};

#[test]
fn a_sync_whose_cached_tip_was_orphaned_follows_the_longer_branch() {
    let fixture = ChainFixture::new("reorg");
    let first = ChainFixture::branch(Network::Regtest.genesis_hash(), 3, 0);
    let mut longer = first[..2].to_vec();
    longer.extend(ChainFixture::branch(first[1].hash(), 2, 1));
    let chain = Arc::new(Mutex::new(first.clone()));
    let (address, node) = FakeNode::spawn(Arc::clone(&chain));

    let mut fetcher = fixture.fetcher(&[address]);
    let start = BlockHeight::new(1);
    let stop = BlockHeight::new(u32::MAX);
    let genesis = Network::Regtest.genesis_hash();
    let synced = fetcher.sync_headers(start, stop, genesis).expect("first sync");
    assert_eq!(ChainFixture::hashes(&synced), first.iter().map(BlockHeader::hash).collect::<Vec<_>>());

    *chain.lock().expect("chain") = longer.clone();
    let resynced = fetcher.sync_headers(start, stop, genesis).expect("sync after the reorg");
    drop(fetcher);
    node.join().expect("node");

    assert_eq!(ChainFixture::hashes(&resynced), longer.iter().map(BlockHeader::hash).collect::<Vec<_>>());
    assert_eq!(resynced.last().map(|(height, _)| *height), Some(BlockHeight::new(4)));
}

#[test]
fn a_survey_reports_each_peers_page_from_the_locator_without_admitting_any() {
    let fixture = ChainFixture::new("survey");
    let genesis = Network::Regtest.genesis_hash();
    let shared = ChainFixture::branch(genesis, 2, 0);
    let mut agreeing = shared.clone();
    agreeing.extend(ChainFixture::branch(shared[1].hash(), 2, 0));
    let mut forked = shared.clone();
    forked.extend(ChainFixture::branch(shared[1].hash(), 3, 9));
    let (first, first_node) = FakeNode::spawn(Arc::new(Mutex::new(agreeing.clone())));
    let (second, second_node) = FakeNode::spawn(Arc::new(Mutex::new(forked.clone())));
    let held: Vec<(BlockHeight, BlockHeader)> = (1..).map(BlockHeight::new).zip(shared).collect();

    let mut fetcher = fixture.fetcher(&[first, second]);
    let pages = fetcher.survey_headers(BlockHeight::new(1), genesis, &held).expect("survey");
    drop(fetcher);
    first_node.join().expect("first node");
    second_node.join().expect("second node");

    assert_eq!(pages.len(), 2);
    assert_eq!(pages[0].first, BlockHeight::new(3));
    assert_eq!(pages[0].headers, forked[2..].to_vec());
    assert_eq!(pages[0].senders, vec![second]);
    assert_eq!(pages[1].headers, agreeing[2..].to_vec());
    assert_eq!(pages[1].senders, vec![first]);
}

#[test]
fn the_branch_with_the_most_work_wins_even_when_it_answers_last() {
    let fixture = ChainFixture::new("most-work");
    let genesis = Network::Regtest.genesis_hash();
    let light = ChainFixture::branch(genesis, 3, 0);
    let heavy = ChainFixture::branch(genesis, 5, 1);
    let (quick, quick_node) = FakeNode::spawn(Arc::new(Mutex::new(light)));
    let (slow, slow_node) = FakeNode::spawn_slow(Arc::new(Mutex::new(heavy.clone())), Duration::from_millis(500));

    let mut fetcher = fixture.fetcher(&[quick, slow]);
    let synced = fetcher
        .sync_headers(BlockHeight::new(1), BlockHeight::new(u32::MAX), genesis)
        .expect("sync");
    drop(fetcher);
    quick_node.join().expect("quick node");
    slow_node.join().expect("slow node");

    assert_eq!(ChainFixture::hashes(&synced), heavy.iter().map(BlockHeader::hash).collect::<Vec<_>>());
}
