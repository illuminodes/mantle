use mantle::collections::{BuildPrehashedHasher, PrehashedMap};
use mantle::primitives::{
    Block, BlockHeader, BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Locktime,
    Nonce, OutPoint, Satoshi, Sequence, Transaction, TxIn, TxOut, TxVersion, Witness,
};
use mantle::tx::TxHash;
use mantle_consensus::chain_view::{Coin, TipInfo};
use mantle_consensus::error::ValidationError;
use mantle_consensus::script::ScriptError;
use mantle_storage::ops::StorageOps;
use mantle_storage::types::{
    CommitBlockReq, CommittedResp, Durability, LookupResult, ReqToken, StorageError,
};

use super::DeferredScripts;
use crate::pipeline::{DeferredBlock, DeferredOpts, DeferredStep, PipelineError, ReplayBufs};
use crate::prefetched_view::HeaderSnapshot;
use crate::script_pool::ScriptPool;

const OP_TRUE: u8 = 0x51;
const OP_FALSE: u8 = 0x00;
const FIRST_HEIGHT: u32 = 200;

struct MemoryUtxos {
    coins: PrehashedMap<OutPoint, Coin>,
    tip: TipInfo,
    commits: Vec<BlockHeight>,
}

impl MemoryUtxos {
    fn new() -> Self {
        Self {
            coins: PrehashedMap::with_hasher(BuildPrehashedHasher),
            tip: TipInfo {
                hash: Hash256::ZERO,
                height: BlockHeight::new(FIRST_HEIGHT - 1),
            },
            commits: Vec::new(),
        }
    }

    fn fund(&mut self, tag: u32, script_pubkey: u8) -> OutPoint {
        let mut txid = [0xee; 32];
        txid[..4].copy_from_slice(&tag.to_le_bytes());
        let outpoint = OutPoint {
            txid: Hash256::from_bytes(txid),
            vout: 0,
        };
        self.coins.insert(
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
}

impl<'req> StorageOps<'req> for MemoryUtxos {
    fn send_lookup(
        &mut self,
        ops: &'req [OutPoint],
        out: &'req mut Vec<LookupResult>,
    ) -> Result<(), StorageError> {
        out.clear();
        out.extend(ops.iter().map(|op| LookupResult {
            outpoint: *op,
            coin: self.coins.get(op).cloned(),
        }));
        Ok(())
    }

    fn recv_lookup(&mut self) -> Result<(), StorageError> {
        Ok(())
    }

    fn commit_block_borrowed(
        &mut self,
        req: CommitBlockReq<'req>,
    ) -> Result<CommittedResp, StorageError> {
        for op in req.spent {
            self.coins.remove(op);
        }
        for coin in req.created {
            self.coins.insert(
                coin.outpoint,
                Coin {
                    value: coin.value,
                    script_pubkey: coin.script_pubkey.to_vec().into(),
                    height: coin.height,
                    coinbase: coin.coinbase,
                },
            );
        }
        self.tip = TipInfo {
            hash: req.hash,
            height: req.height,
        };
        self.commits.push(req.height);
        Ok(CommittedResp {
            token: req.token,
            tip: self.tip.clone(),
        })
    }

    fn tip(&self) -> TipInfo {
        self.tip.clone()
    }

    fn read_header(&mut self, _hash: Hash256) -> Result<Option<BlockHeader>, StorageError> {
        Ok(None)
    }

    fn read_header_at(&mut self, _h: BlockHeight) -> Result<Option<BlockHeader>, StorageError> {
        Ok(None)
    }
}

struct Replay {
    utxos: MemoryUtxos,
    headers: HeaderSnapshot,
    bufs: ReplayBufs,
    scripts: DeferredScripts,
    next_tag: u32,
    next_height: u32,
}

impl Replay {
    fn new(workers: usize) -> Self {
        let mut entries = Vec::new();
        let mut prev = Hash256::ZERO;
        for i in 0..FIRST_HEIGHT + 64 {
            let header = BlockHeader::new(
                BlockVersion::new(1),
                prev,
                Hash256::ZERO,
                BlockTime::new(1_231_006_505 + i * 600),
                CompactBits::new(0x207f_ffff),
                Nonce::new(0),
            );
            prev = header.hash();
            entries.push((prev, header));
        }
        Self {
            utxos: MemoryUtxos::new(),
            headers: HeaderSnapshot::new(BlockHeight::ZERO, entries).expect("small snapshot"),
            bufs: ReplayBufs::new(),
            scripts: DeferredScripts::new(ScriptPool::new(workers).expect("spawn")),
            next_tag: 0,
            next_height: FIRST_HEIGHT,
        }
    }

    fn block(&mut self, spenders: &[&[u8]], extra_coinbase_value: u64) -> Block {
        let height = self.next_height;
        let mut coinbase_sig = vec![0x02];
        coinbase_sig.extend_from_slice(&u16::try_from(height).expect("small").to_le_bytes());
        let mut txs = vec![Self::tx(
            vec![OutPoint {
                txid: Hash256::ZERO,
                vout: u32::MAX,
            }],
            &coinbase_sig,
            50 * 100_000_000 + extra_coinbase_value,
        )];
        for scripts in spenders {
            let inputs = scripts
                .iter()
                .map(|&spk| {
                    self.next_tag += 1;
                    self.utxos.fund(self.next_tag, spk)
                })
                .collect();
            txs.push(Self::tx(inputs, &[], 1_000));
        }
        Block {
            header: BlockHeader::new(
                BlockVersion::new(1),
                Hash256::from_bytes([u8::try_from(height % 251).expect("< 251"); 32]),
                Hash256::ZERO,
                BlockTime::new(1_231_200_000),
                CompactBits::new(0x207f_ffff),
                Nonce::new(height),
            ),
            transactions: txs,
        }
    }

    fn tx(inputs: Vec<OutPoint>, script_sig: &[u8], value: u64) -> Transaction {
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
                value: Satoshi::new(value),
                script_pubkey: vec![OP_TRUE].into(),
            }],
            locktime: Locktime::new(0),
        }
    }

    fn step(&mut self, block: Block) -> DeferredStep {
        let height = BlockHeight::new(self.next_height);
        self.next_height += 1;
        let token = ReqToken(u64::from(height.to_u32()));
        self.bufs.validate_and_commit_deferred(
            block,
            height,
            &mut self.utxos,
            &self.headers,
            &mut self.scripts,
            DeferredOpts {
                durability: Durability::Memory,
                token,
                utxo_hash: None,
            },
        )
    }
}

fn wide(txs: usize, inputs: usize) -> Vec<Vec<u8>> {
    vec![vec![OP_TRUE; inputs]; txs]
}

fn borrowed(spenders: &[Vec<u8>]) -> Vec<&[u8]> {
    spenders.iter().map(Vec::as_slice).collect()
}

#[test]
fn each_block_s_script_verdict_arrives_with_the_next_call() {
    let mut replay = Replay::new(4);
    let mut previous_heights = Vec::new();
    for _ in 0..30 {
        let spenders = wide(10, 10);
        let block = replay.block(&borrowed(&spenders), 0);
        let step = replay.step(block);
        assert!(matches!(step.current, DeferredBlock::Committed(_)));
        if let Some(settled) = step.previous {
            assert_eq!(settled.verdict, Ok(()));
            previous_heights.push(settled.height.to_u32());
        }
    }
    let last = replay.scripts.settle().expect("the last block is still held");
    assert_eq!(last.verdict, Ok(()));
    previous_heights.push(last.height.to_u32());
    let expected: Vec<u32> = (FIRST_HEIGHT..FIRST_HEIGHT + 30).collect();
    assert_eq!(previous_heights, expected);
    assert!(replay.scripts.settle().is_none());
}

#[test]
fn a_script_failure_is_reported_for_its_own_block_at_the_lowest_input() {
    let mut replay = Replay::new(4);
    let fine = wide(5, 5);
    let first = replay.block(&borrowed(&fine), 0);
    assert!(matches!(replay.step(first).current, DeferredBlock::Committed(_)));

    let late = [OP_TRUE, OP_TRUE, OP_FALSE];
    let early = [OP_TRUE, OP_FALSE, OP_FALSE];
    let ok = [OP_TRUE; 3];
    let mut spenders: Vec<&[u8]> = vec![&ok; 30];
    spenders[21] = &late;
    spenders[9] = &early;
    let bad = replay.block(&spenders, 0);
    let bad_hash = bad.header.hash();
    let step = replay.step(bad);
    assert_eq!(step.previous.expect("first block").verdict, Ok(()));
    assert!(matches!(step.current, DeferredBlock::Committed(_)));

    let after = replay.block(&borrowed(&fine), 0);
    let step = replay.step(after);
    let settled = step.previous.expect("the bad block settles here");
    assert_eq!(settled.height, BlockHeight::new(FIRST_HEIGHT + 1));
    assert_eq!(settled.hash, bad_hash);
    assert_eq!(
        settled.verdict,
        Err(ValidationError::ScriptVerifyFailed {
            tx_index: 10,
            input_index: 1,
            kind: ScriptError::EvalFalse,
        })
    );
}

#[test]
fn a_block_rejected_before_its_scripts_finish_is_not_committed_or_held() {
    let mut replay = Replay::new(4);
    let fine = wide(5, 5);
    let first = replay.block(&borrowed(&fine), 0);
    assert!(matches!(replay.step(first).current, DeferredBlock::Committed(_)));

    let greedy_spenders = wide(20, 20);
    let greedy = replay.block(&borrowed(&greedy_spenders), 100 * 100_000_000);
    let step = replay.step(greedy);
    assert_eq!(step.previous.expect("first block").verdict, Ok(()));
    match step.current {
        DeferredBlock::Rejected { error, block } => {
            assert!(
                matches!(
                    error,
                    PipelineError::Validation(ValidationError::CoinbaseRewardExceedsSubsidy)
                ),
                "{error}"
            );
            assert_eq!(block.transactions.len(), 21);
        }
        DeferredBlock::Committed(_) => panic!("an overpaying coinbase must be rejected"),
    }
    assert_eq!(replay.utxos.commits, vec![BlockHeight::new(FIRST_HEIGHT)]);
    assert!(replay.scripts.settle().is_none());

    let next = replay.block(&borrowed(&fine), 0);
    let step = replay.step(next);
    assert!(step.previous.is_none());
    assert!(matches!(step.current, DeferredBlock::Committed(_)));
}

#[test]
fn a_block_spending_the_previous_block_s_output_sees_it_committed() {
    let mut replay = Replay::new(4);
    let fine = wide(3, 3);
    let first = replay.block(&borrowed(&fine), 0);
    let created = OutPoint {
        txid: first.transactions[1].txid().expect("txid"),
        vout: 0,
    };
    assert!(matches!(replay.step(first).current, DeferredBlock::Committed(_)));

    let mut second = replay.block(&[], 0);
    second
        .transactions
        .push(Replay::tx(vec![created], &[], 500));
    let step = replay.step(second);
    assert_eq!(step.previous.expect("first block").verdict, Ok(()));
    assert!(matches!(step.current, DeferredBlock::Committed(_)));
    assert_eq!(replay.scripts.settle().expect("second").verdict, Ok(()));
}

#[test]
fn deferred_and_scoped_runs_agree_without_workers() {
    let mut replay = Replay::new(0);
    let spenders = wide(8, 8);
    let block = replay.block(&borrowed(&spenders), 0);
    assert!(matches!(replay.step(block).current, DeferredBlock::Committed(_)));
    assert_eq!(replay.scripts.settle().expect("held").verdict, Ok(()));
}

#[test]
fn dropping_with_a_block_in_flight_waits_for_its_checks() {
    let mut replay = Replay::new(8);
    let spenders = wide(40, 40);
    let block = replay.block(&borrowed(&spenders), 0);
    assert!(matches!(replay.step(block).current, DeferredBlock::Committed(_)));
    drop(replay);
}
