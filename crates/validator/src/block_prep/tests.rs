use std::sync::Arc;

use mantle::codec::Encode;
use mantle::primitives::{
    Block, BlockHeader, BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Locktime,
    Nonce, OutPoint, Satoshi, Sequence, Transaction, TxHash, TxIn, TxOut, TxVersion, Witness,
};
use mantle_consensus::merkle::compute_merkle_root;
use mantle_consensus::validation::FixedClock;
use mantle_storage::types::Durability;

use super::{BlockPreparer, CommitPlan, PrepCheck, PrepPool, Prepared, RawBlock};
use crate::prefetched_view::HeaderSnapshot;

const BITS: CompactBits = CompactBits::new(0x207f_ffff);
const START_TIME: u32 = 1_231_006_505;
const FIRST: u32 = 20;

struct TestChain {
    headers: Vec<BlockHeader>,
    blocks: Vec<Block>,
}

impl TestChain {
    fn new(count: u32) -> Self {
        let mut headers = Vec::new();
        let mut prev = Hash256::ZERO;
        for height in 0..FIRST {
            let header = Self::header(prev, Hash256::ZERO, height);
            prev = header.hash();
            headers.push(header);
        }
        let mut blocks = Vec::new();
        for height in FIRST..FIRST + count {
            let coinbase = Self::coinbase(height);
            let root = compute_merkle_root(&[coinbase.txid().expect("txid")]).expect("one tx");
            let header = Self::mine(Self::header(prev, root, height));
            prev = header.hash();
            headers.push(header);
            blocks.push(Block {
                header,
                transactions: vec![coinbase],
            });
        }
        Self { headers, blocks }
    }

    fn header(prev: Hash256, root: Hash256, height: u32) -> BlockHeader {
        BlockHeader::new(
            BlockVersion::new(1),
            prev,
            root,
            BlockTime::new(START_TIME + height * 600),
            BITS,
            Nonce::new(0),
        )
    }

    fn mine(mut header: BlockHeader) -> BlockHeader {
        let target = BITS.to_target().expect("easy target");
        for nonce in 0.. {
            header.set_nonce(Nonce::new(nonce));
            let mut hash = *header.hash().as_bytes();
            hash.reverse();
            if hash <= target {
                return header;
            }
        }
        unreachable!()
    }

    fn coinbase(height: u32) -> Transaction {
        let mut script_sig = vec![0x02];
        script_sig.extend_from_slice(&u16::try_from(height).expect("small").to_le_bytes());
        Transaction {
            version: TxVersion::new(1),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: u32::MAX,
                },
                script_sig: script_sig.into(),
                sequence: Sequence::MAX,
                witness: Witness::empty(),
            }],
            outputs: vec![TxOut {
                value: Satoshi::new(50 * 100_000_000),
                script_pubkey: vec![0x51].into(),
            }],
            locktime: Locktime::new(0),
        }
    }

    fn snapshot(&self) -> Arc<HeaderSnapshot> {
        let entries = self.headers.iter().map(|h| (h.hash(), *h)).collect();
        Arc::new(HeaderSnapshot::new(BlockHeight::ZERO, entries).expect("small"))
    }

    fn preparer(&self) -> BlockPreparer<FixedClock> {
        BlockPreparer::new(
            self.snapshot(),
            FixedClock(u64::from(START_TIME) + 100_000_000),
            false,
            CommitPlan {
                every: 4,
                boundary: Durability::Flushed,
            },
        )
    }

    fn raw(block: &Block, height: u32) -> RawBlock {
        let mut bytes = Vec::new();
        block.encode(&mut bytes).expect("encode");
        RawBlock {
            height: BlockHeight::new(height),
            hash: block.header.hash(),
            bytes,
        }
    }
}

#[test]
fn a_valid_block_is_ready_with_its_commit_plan_applied() {
    let chain = TestChain::new(4);
    let preparer = chain.preparer();
    let raw = TestChain::raw(&chain.blocks[0], FIRST);
    match preparer.prepare(raw.height, raw.hash, &raw.bytes).expect("decodes") {
        Prepared::Ready(job) => {
            assert_eq!(job.height.to_u32(), FIRST);
            assert_eq!(job.durability, Durability::Flushed);
            assert_eq!(job.inputs.txids.len(), 1);
        }
        Prepared::Invalid { failures, .. } => panic!("unexpected failures {failures:?}"),
    }
    let raw = TestChain::raw(&chain.blocks[1], FIRST + 1);
    match preparer.prepare(raw.height, raw.hash, &raw.bytes).expect("decodes") {
        Prepared::Ready(job) => assert_eq!(job.durability, Durability::Memory),
        Prepared::Invalid { failures, .. } => panic!("unexpected failures {failures:?}"),
    }
}

#[test]
fn bytes_that_hash_to_another_block_are_an_error() {
    let chain = TestChain::new(2);
    let preparer = chain.preparer();
    let raw = TestChain::raw(&chain.blocks[0], FIRST);
    let wrong = chain.blocks[1].header.hash();
    assert!(preparer.prepare(raw.height, wrong, &raw.bytes).is_err());
}

#[test]
fn a_broken_block_is_handed_back_with_every_failed_check() {
    let chain = TestChain::new(1);
    let preparer = chain.preparer();
    let mut block = chain.blocks[0].clone();
    block.transactions[0].outputs[0].value = Satoshi::new(7);
    let raw = TestChain::raw(&block, FIRST);
    match preparer.prepare(raw.height, raw.hash, &raw.bytes).expect("decodes") {
        Prepared::Invalid { failures, job } => {
            assert!(failures.iter().any(|(check, _)| *check == PrepCheck::Structure));
            assert_eq!(job.height.to_u32(), FIRST);
        }
        Prepared::Ready(_) => panic!("a merkle mismatch must fail the structure check"),
    }
}

#[test]
fn the_pool_hands_blocks_back_in_height_order() {
    let chain = TestChain::new(40);
    let mut pool =
        PrepPool::new(chain.preparer(), 4, 8, BlockHeight::new(FIRST)).expect("spawn");
    let mut submitted = 0;
    let mut heights = Vec::new();
    while heights.len() < chain.blocks.len() {
        while pool.has_room() && submitted < chain.blocks.len() {
            let height = FIRST + u32::try_from(submitted).expect("small");
            pool.submit(TestChain::raw(&chain.blocks[submitted], height));
            submitted += 1;
        }
        match pool.take_next().expect("something is queued").expect("decodes") {
            Prepared::Ready(job) => heights.push(job.height.to_u32()),
            Prepared::Invalid { failures, .. } => panic!("unexpected failures {failures:?}"),
        }
    }
    let expected: Vec<u32> = (FIRST..FIRST + 40).collect();
    assert_eq!(heights, expected);
    assert!(pool.take_next().is_none());
}

#[test]
fn dropping_a_pool_with_blocks_queued_joins_its_threads() {
    let chain = TestChain::new(8);
    let mut pool =
        PrepPool::new(chain.preparer(), 3, 8, BlockHeight::new(FIRST)).expect("spawn");
    for (offset, block) in chain.blocks.iter().enumerate() {
        pool.submit(TestChain::raw(block, FIRST + u32::try_from(offset).expect("small")));
    }
    drop(pool);
}
