use mantle::primitives::{
    Block, BlockHeader, BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Locktime,
    Nonce, OutPoint, Satoshi, Sequence, Transaction, TxIn, TxOut, TxVersion, Witness,
};
use mantle_consensus::chain_view::{Coin, ConnectScratch, MemoryChainView};
use mantle_consensus::error::ValidationError;
use mantle_consensus::script::ScriptError;
use mantle_consensus::validation::{InlineScripts, connect_block};

use super::ScriptPool;

const OP_TRUE: u8 = 0x51;
const OP_FALSE: u8 = 0x00;
const HEIGHT: u32 = 200;

struct Chain {
    view: MemoryChainView,
}

impl Chain {
    fn new() -> Self {
        let mut view = MemoryChainView::new();
        let mut prev = Hash256::ZERO;
        for i in 0..HEIGHT {
            let header = BlockHeader::new(
                BlockVersion::new(1),
                prev,
                Hash256::ZERO,
                BlockTime::new(1_231_006_505 + i * 600),
                CompactBits::new(0x207f_ffff),
                Nonce::new(0),
            );
            prev = header.hash();
            view.push_header(header);
        }
        Self { view }
    }

    fn fund(&mut self, tag: u32, script_pubkey: u8) -> OutPoint {
        let mut txid = [0u8; 32];
        txid[..4].copy_from_slice(&tag.to_le_bytes());
        let outpoint = OutPoint {
            txid: Hash256::from_bytes(txid),
            vout: 0,
        };
        self.view.insert_coin(
            outpoint,
            Coin {
                value: Satoshi::new(10_000),
                script_pubkey: vec![script_pubkey].into(),
                height: BlockHeight::new(1),
                coinbase: false,
            },
        );
        outpoint
    }

    fn block(&mut self, spenders: &[&[u8]]) -> Block {
        let mut tag = 0;
        let mut txs = vec![Self::tx(
            vec![OutPoint {
                txid: Hash256::ZERO,
                vout: u32::MAX,
            }],
            &[0x02, 0xc8, 0x00],
        )];
        for scripts in spenders {
            let inputs = scripts
                .iter()
                .map(|&spk| {
                    tag += 1;
                    self.fund(tag, spk)
                })
                .collect();
            txs.push(Self::tx(inputs, &[]));
        }
        Block {
            header: BlockHeader::new(
                BlockVersion::new(1),
                Hash256::ZERO,
                Hash256::ZERO,
                BlockTime::new(1_231_200_000),
                CompactBits::new(0x207f_ffff),
                Nonce::new(0),
            ),
            transactions: txs,
        }
    }

    fn tx(inputs: Vec<OutPoint>, script_sig: &[u8]) -> Transaction {
        Transaction {
            version: TxVersion::new(1),
            inputs: inputs
                .into_iter()
                .map(|previous_output| TxIn {
                    previous_output,
                    script_sig: script_sig.to_vec().into(),
                    sequence: Sequence::MAX,
                    witness: Witness::empty(),
                })
                .collect(),
            outputs: vec![TxOut {
                value: Satoshi::new(1_000),
                script_pubkey: vec![OP_TRUE].into(),
            }],
            locktime: Locktime::new(0),
        }
    }

    fn inline(&self, block: &Block) -> Result<Satoshi, ValidationError> {
        connect_block(
            block,
            BlockHeight::new(HEIGHT),
            &self.view,
            &mut Vec::new(),
            &mut ConnectScratch::new(),
            &mut InlineScripts::new(None),
            None,
        )
        .map(|r| r.fees)
    }

    fn pooled(&self, pool: &mut ScriptPool, block: &Block) -> Result<Satoshi, ValidationError> {
        pool.scope(|batch| {
            connect_block(
                block,
                BlockHeight::new(HEIGHT),
                &self.view,
                &mut Vec::new(),
                &mut ConnectScratch::new(),
                batch,
                None,
            )
            .map(|r| r.fees)
        })
    }
}

fn wide_block(chain: &mut Chain, txs: usize, inputs: usize) -> Block {
    let scripts = vec![OP_TRUE; inputs];
    let spenders: Vec<&[u8]> = (0..txs).map(|_| scripts.as_slice()).collect();
    chain.block(&spenders)
}

#[test]
fn a_valid_block_passes_on_the_pool_as_it_does_inline() {
    let mut chain = Chain::new();
    let block = wide_block(&mut chain, 40, 25);
    let mut pool = ScriptPool::new(4).expect("spawn");
    let inline = chain.inline(&block);
    assert!(inline.is_ok(), "{inline:?}");
    assert_eq!(chain.pooled(&mut pool, &block), inline);
}

#[test]
fn the_pool_reports_the_first_failing_input_in_block_order() {
    let mut chain = Chain::new();
    let late = [OP_TRUE, OP_TRUE, OP_FALSE];
    let early = [OP_TRUE, OP_FALSE, OP_FALSE];
    let fine = [OP_TRUE; 3];
    let mut spenders: Vec<&[u8]> = vec![&fine; 30];
    spenders[21] = &late;
    spenders[9] = &early;
    let block = chain.block(&spenders);
    let mut pool = ScriptPool::new(4).expect("spawn");

    let expected = Err(ValidationError::ScriptVerifyFailed {
        tx_index: 10,
        input_index: 1,
        kind: ScriptError::EvalFalse,
    });
    assert_eq!(chain.inline(&block), expected);
    for _ in 0..50 {
        assert_eq!(chain.pooled(&mut pool, &block), expected);
    }
}

#[test]
fn a_pool_without_workers_verifies_on_the_calling_thread() {
    let mut chain = Chain::new();
    let block = wide_block(&mut chain, 10, 10);
    let mut pool = ScriptPool::new(0).expect("no threads to spawn");
    assert_eq!(pool.workers(), 0);
    assert_eq!(chain.pooled(&mut pool, &block), chain.inline(&block));
}

#[test]
fn more_checks_than_the_job_ring_holds_all_complete() {
    let mut chain = Chain::new();
    let block = wide_block(&mut chain, 30, 200);
    let mut pool = ScriptPool::new(2).expect("spawn");
    assert_eq!(chain.pooled(&mut pool, &block), chain.inline(&block));
}

#[test]
fn one_pool_serves_many_blocks() {
    let mut chain = Chain::new();
    let mut pool = ScriptPool::new(3).expect("spawn");
    for _ in 0..20 {
        let block = wide_block(&mut chain, 8, 8);
        assert_eq!(chain.pooled(&mut pool, &block), chain.inline(&block));
    }
}

#[test]
fn idle_workers_wake_for_each_of_many_tiny_blocks_and_release_on_drop() {
    let mut chain = Chain::new();
    let mut pool = ScriptPool::new(8).expect("spawn");
    for _ in 0..500 {
        let block = wide_block(&mut chain, 1, 2);
        assert_eq!(chain.pooled(&mut pool, &block), chain.inline(&block));
    }
    drop(pool);
}

#[test]
fn a_block_rejected_before_its_scripts_finish_leaves_the_pool_usable() {
    let mut chain = Chain::new();
    let mut block = wide_block(&mut chain, 20, 20);
    block.transactions[0].outputs[0].value = Satoshi::new(100 * 100_000_000);
    let mut pool = ScriptPool::new(4).expect("spawn");
    assert_eq!(
        chain.pooled(&mut pool, &block),
        Err(ValidationError::CoinbaseRewardExceedsSubsidy)
    );
    let good = wide_block(&mut chain, 5, 5);
    assert_eq!(chain.pooled(&mut pool, &good), chain.inline(&good));
}
