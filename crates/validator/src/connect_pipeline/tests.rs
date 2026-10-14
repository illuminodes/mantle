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

use super::{BlockJob, ConnectPipeline, Connected, InFlightLimit, OnScriptFailure, Verdict, Wait};
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
    pipeline: ConnectPipeline,
    next_tag: u32,
    next_height: u32,
}

impl Replay {
    fn new(workers: usize, limit: InFlightLimit, on_failure: OnScriptFailure) -> Self {
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
        let utxos = MemoryUtxos::new();
        let pipeline = ConnectPipeline::new(
            ScriptPool::new(workers).expect("spawn"),
            utxos.tip(),
            limit,
        )
        .on_script_failure(on_failure);
        Self {
            utxos,
            headers: HeaderSnapshot::new(BlockHeight::ZERO, entries).expect("small snapshot"),
            pipeline,
            next_tag: 0,
            next_height: FIRST_HEIGHT,
        }
    }

    fn deep() -> Self {
        Self::new(4, InFlightLimit::default(), OnScriptFailure::Stop)
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

    fn connect(&mut self, block: Block) -> Connected {
        let height = BlockHeight::new(self.next_height);
        self.next_height += 1;
        let job = BlockJob::new(
            block,
            height,
            Durability::Memory,
            ReqToken(u64::from(height.to_u32())),
        );
        self.pipeline
            .connect(job, &mut self.utxos, &self.headers)
            .expect("memory storage")
    }

    fn drain(&mut self) -> Vec<super::Retired> {
        self.pipeline.drain(&mut self.utxos).expect("memory storage")
    }
}

fn wide(txs: usize, inputs: usize) -> Vec<Vec<u8>> {
    vec![vec![OP_TRUE; inputs]; txs]
}

fn borrowed(spenders: &[Vec<u8>]) -> Vec<&[u8]> {
    spenders.iter().map(Vec::as_slice).collect()
}

#[test]
fn blocks_reach_storage_in_height_order_after_their_scripts_pass() {
    let mut replay = Replay::deep();
    for _ in 0..30 {
        let spenders = wide(10, 10);
        let block = replay.block(&borrowed(&spenders), 0);
        assert!(matches!(replay.connect(block), Connected::Queued));
    }
    let retired = replay.drain();
    let heights: Vec<u32> = retired.iter().map(|r| r.height.to_u32()).collect();
    let expected: Vec<u32> = (FIRST_HEIGHT..FIRST_HEIGHT + 30).collect();
    assert_eq!(heights, expected);
    assert!(retired.iter().all(|r| r.verdict == Verdict::Valid && r.committed));
    let committed: Vec<u32> = replay.utxos.commits.iter().map(|h| h.to_u32()).collect();
    assert_eq!(committed, expected);
}

#[test]
fn nothing_reaches_storage_until_it_is_retired() {
    let mut replay = Replay::deep();
    for _ in 0..5 {
        let spenders = wide(4, 4);
        let block = replay.block(&borrowed(&spenders), 0);
        assert!(matches!(replay.connect(block), Connected::Queued));
    }
    assert!(replay.utxos.commits.is_empty());
    assert_eq!(replay.pipeline.in_flight(), 5);
    assert_eq!(replay.pipeline.tip().height.to_u32(), FIRST_HEIGHT + 4);
}

#[test]
fn a_script_failure_stops_storage_at_the_block_before_it() {
    let mut replay = Replay::deep();
    let fine = wide(5, 5);
    let first = replay.block(&borrowed(&fine), 0);
    assert!(matches!(replay.connect(first), Connected::Queued));

    let late = [OP_TRUE, OP_TRUE, OP_FALSE];
    let early = [OP_TRUE, OP_FALSE, OP_FALSE];
    let ok = [OP_TRUE; 3];
    let mut spenders: Vec<&[u8]> = vec![&ok; 30];
    spenders[21] = &late;
    spenders[9] = &early;
    let bad = replay.block(&spenders, 0);
    let bad_hash = bad.header.hash();
    assert!(matches!(replay.connect(bad), Connected::Queued));

    let after = replay.block(&borrowed(&fine), 0);
    assert!(matches!(replay.connect(after), Connected::Queued));

    let retired = replay.drain();
    assert_eq!(retired.len(), 3);
    assert_eq!(retired[0].verdict, Verdict::Valid);
    assert!(retired[0].committed);
    assert_eq!(retired[1].hash, bad_hash);
    assert_eq!(
        retired[1].verdict,
        Verdict::ScriptFailed(ValidationError::ScriptVerifyFailed {
            tx_index: 10,
            input_index: 1,
            kind: ScriptError::EvalFalse,
        })
    );
    assert!(!retired[1].committed);
    assert!(!retired[2].committed, "a block on top of an invalid one is never stored");
    assert!(replay.pipeline.is_stopped());
    assert_eq!(replay.utxos.commits, vec![BlockHeight::new(FIRST_HEIGHT)]);
}

#[test]
fn a_keep_going_pipeline_commits_the_failed_block_and_continues() {
    let mut replay = Replay::new(4, InFlightLimit::default(), OnScriptFailure::CommitAnyway);
    let bad_scripts = [OP_FALSE];
    let bad = replay.block(&[&bad_scripts], 0);
    assert!(matches!(replay.connect(bad), Connected::Queued));
    let fine = wide(2, 2);
    let next = replay.block(&borrowed(&fine), 0);
    assert!(matches!(replay.connect(next), Connected::Queued));
    let retired = replay.drain();
    assert!(matches!(retired[0].verdict, Verdict::ScriptFailed(_)));
    assert!(retired[0].committed);
    assert_eq!(retired[1].verdict, Verdict::Valid);
    assert_eq!(replay.utxos.commits.len(), 2);
}

#[test]
fn a_block_rejected_by_another_rule_is_not_queued() {
    let mut replay = Replay::deep();
    let fine = wide(5, 5);
    let first = replay.block(&borrowed(&fine), 0);
    assert!(matches!(replay.connect(first), Connected::Queued));

    let greedy_spenders = wide(20, 20);
    let greedy = replay.block(&borrowed(&greedy_spenders), 100 * 100_000_000);
    match replay.connect(greedy) {
        Connected::Rejected { error, job } => {
            assert_eq!(error, ValidationError::CoinbaseRewardExceedsSubsidy);
            assert_eq!(job.block.transactions.len(), 21);
        }
        Connected::Queued => panic!("an overpaying coinbase must be rejected"),
    }
    assert_eq!(replay.pipeline.in_flight(), 1);
    assert_eq!(replay.pipeline.tip().height.to_u32(), FIRST_HEIGHT);

    let next = replay.block(&borrowed(&fine), 0);
    assert!(matches!(replay.connect(next), Connected::Queued));
    assert_eq!(replay.drain().len(), 2);
}

#[test]
fn a_forced_block_is_stored_unvalidated_and_later_blocks_build_on_it() {
    let mut replay = Replay::deep();
    let fine = wide(2, 2);
    let greedy = replay.block(&borrowed(&fine), 100 * 100_000_000);
    let created = OutPoint {
        txid: greedy.transactions[1].txid().expect("txid"),
        vout: 0,
    };
    let Connected::Rejected { job, .. } = replay.connect(greedy) else {
        panic!("an overpaying coinbase must be rejected");
    };
    replay.pipeline.force(job).expect("delta");

    let mut spender = replay.block(&[], 0);
    spender.transactions.push(Replay::tx(vec![created], &[], 500));
    assert!(matches!(replay.connect(spender), Connected::Queued));
    let retired = replay.drain();
    assert_eq!(retired[0].verdict, Verdict::Forced);
    assert!(retired[0].committed);
    assert_eq!(retired[1].verdict, Verdict::Valid);
}

#[test]
fn a_block_spending_a_pending_block_s_output_sees_it_before_storage_does() {
    let mut replay = Replay::deep();
    let fine = wide(3, 3);
    let first = replay.block(&borrowed(&fine), 0);
    let created = OutPoint {
        txid: first.transactions[1].txid().expect("txid"),
        vout: 0,
    };
    assert!(matches!(replay.connect(first), Connected::Queued));

    let mut second = replay.block(&[], 0);
    second.transactions.push(Replay::tx(vec![created], &[], 500));
    assert!(matches!(replay.connect(second), Connected::Queued));
    assert!(replay.utxos.commits.is_empty());

    let mut double = replay.block(&[], 0);
    double.transactions.push(Replay::tx(vec![created], &[], 400));
    match replay.connect(double) {
        Connected::Rejected { error, .. } => {
            assert_eq!(
                error,
                ValidationError::MissingInput {
                    tx_index: 1,
                    input_index: 0
                }
            );
        }
        Connected::Queued => panic!("a coin spent by a pending block cannot be spent again"),
    }
    let retired = replay.drain();
    assert!(retired.iter().all(|r| r.verdict == Verdict::Valid));
    assert!(!replay.utxos.coins.contains_key(&created));
}

#[test]
fn a_tight_limit_retires_blocks_as_it_goes() {
    let limit = InFlightLimit {
        blocks: 2,
        inputs: usize::MAX,
    };
    let mut replay = Replay::new(2, limit, OnScriptFailure::Stop);
    for _ in 0..10 {
        let spenders = wide(3, 3);
        let block = replay.block(&borrowed(&spenders), 0);
        assert!(matches!(replay.connect(block), Connected::Queued));
        while replay
            .pipeline
            .retire_next(&mut replay.utxos, Wait::IfOverLimit)
            .expect("memory storage")
            .is_some()
        {}
        assert!(replay.pipeline.in_flight() <= 2);
    }
    assert!(replay.utxos.commits.len() >= 8);
    replay.drain();
    assert_eq!(replay.utxos.commits.len(), 10);
}

#[test]
fn a_pool_without_workers_gives_the_same_verdicts() {
    let mut replay = Replay::new(0, InFlightLimit::default(), OnScriptFailure::Stop);
    let spenders = wide(8, 8);
    let block = replay.block(&borrowed(&spenders), 0);
    assert!(matches!(replay.connect(block), Connected::Queued));
    let retired = replay.drain();
    assert_eq!(retired[0].verdict, Verdict::Valid);
}

#[test]
fn dropping_with_blocks_in_flight_waits_for_their_checks() {
    let mut replay = Replay::new(8, InFlightLimit::default(), OnScriptFailure::Stop);
    for _ in 0..6 {
        let spenders = wide(40, 40);
        let block = replay.block(&borrowed(&spenders), 0);
        assert!(matches!(replay.connect(block), Connected::Queued));
    }
    drop(replay);
}
