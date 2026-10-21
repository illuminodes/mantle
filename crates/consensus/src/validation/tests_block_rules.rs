use std::io::Cursor;

use mantle::codec::Decode;
use mantle::primitives::{
    Block, BlockHeader, BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Locktime,
    Nonce, OutPoint, Satoshi, Sequence, Transaction, TxHash, TxIn, TxOut, TxVersion, Witness,
};

use super::connect::{block_subsidy, connect_block};
use super::sigop_cost::SigopCost;
use super::tx_finality::TxFinality;
use super::witness_commitment::WitnessCommitment;
use super::{FixedClock, validate_block_context_with_clock};
use crate::chain_view::{ChainView, Coin, ConnectScratch, MemoryChainView};
use crate::error::ValidationError;
use crate::merkle::compute_merkle_root;
use crate::test_helpers::decode_hex;

const MAINNET_481828_HEADER: &str = "02000020b4747817e93fab4d169f61911d81ece2db528ad563985000000000000000000077a8959a0fc500b3bed63e381ad001543468df754ba85ddf7b57e293fccd784302409e59e93c0118311e5f46";
const MAINNET_481828_COINBASE: &str = "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff3203245a07254d696e656420627920416e74506f6f6c6d2f4542312f4144362f4e59412f5720599e400201ae3700003b7c0000ffffffff02807c814a000000001976a9140801bee4ed1e0ad6c0c4a5a7205142a8e0b2ce5388ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000";

struct Fixture;

impl Fixture {
    fn mainnet_481828() -> Block {
        let mut bytes = decode_hex(MAINNET_481828_HEADER);
        bytes.push(0x01);
        bytes.extend(decode_hex(MAINNET_481828_COINBASE));
        Block::decode(&mut Cursor::new(bytes)).expect("mainnet block 481828 decodes")
    }

    fn coinbase(height: BlockHeight) -> Transaction {
        Transaction {
            version: TxVersion::new(1),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: u32::MAX,
                },
                script_sig: Transaction::bip34_height_script(height).into(),
                sequence: Sequence::MAX,
                witness: Witness::empty(),
            }],
            outputs: vec![TxOut {
                value: Satoshi::new(1),
                script_pubkey: vec![0x51].into(),
            }],
            locktime: Locktime::new(0),
        }
    }

    fn spend(locktime: u32, sequence: Sequence) -> Transaction {
        Transaction {
            version: TxVersion::new(1),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([0x77; 32]),
                    vout: 0,
                },
                script_sig: vec![0x51].into(),
                sequence,
                witness: Witness::empty(),
            }],
            outputs: vec![TxOut {
                value: Satoshi::new(1),
                script_pubkey: vec![0x51].into(),
            }],
            locktime: Locktime::new(locktime),
        }
    }

    fn block(header_prev: Hash256, time: u32, txs: Vec<Transaction>) -> Block {
        let txids: Vec<Hash256> = txs.iter().map(|t| t.txid().expect("txid")).collect();
        Block {
            header: BlockHeader::new(
                BlockVersion::new(4),
                header_prev,
                compute_merkle_root(&txids).expect("non-empty"),
                BlockTime::new(time),
                CompactBits::new(0x207f_ffff),
                Nonce::new(0),
            ),
            transactions: txs,
        }
    }

    fn chain(tip: u32, first_time: u32) -> MemoryChainView {
        let start = tip - 11;
        let mut view = MemoryChainView::with_height_base(BlockHeight::new(start));
        let mut prev = Hash256::ZERO;
        for i in 0..12 {
            let header = BlockHeader::new(
                BlockVersion::new(4),
                prev,
                Hash256::ZERO,
                BlockTime::new(first_time + i * 600),
                CompactBits::new(0x207f_ffff),
                Nonce::new(0),
            );
            prev = header.hash();
            view.push_header(header);
        }
        view
    }
}

struct RelativeLock {
    view: MemoryChainView,
    funded: OutPoint,
}

impl RelativeLock {
    const TIP: u32 = 500_000;
    const COIN_HEIGHT: u32 = 499_990;
    const FIRST_TIME: u32 = 1_500_000_000;

    fn new() -> Self {
        let mut view = Fixture::chain(Self::TIP, Self::FIRST_TIME);
        let funded = OutPoint {
            txid: Hash256::from_bytes([0x88; 32]),
            vout: 0,
        };
        view.insert_coin(
            funded,
            Coin {
                value: Satoshi::new(10_000),
                script_pubkey: vec![0x51].into(),
                height: BlockHeight::new(Self::COIN_HEIGHT),
                coinbase: false,
            },
        );
        Self { view, funded }
    }

    fn connect(&self, version: i32, sequence: u32) -> Result<(), ValidationError> {
        let height = BlockHeight::new(Self::TIP + 1);
        let mut spend = Fixture::spend(0, Sequence::new(sequence));
        spend.version = TxVersion::new(version);
        spend.inputs[0].previous_output = self.funded;
        let mut coinbase = Fixture::coinbase(height);
        coinbase.outputs[0].value = block_subsidy(height);
        let block = Fixture::block(self.view.tip().hash, 0, vec![coinbase, spend]);
        connect_block(
            &block,
            height,
            &self.view,
            &mut Vec::new(),
            &mut ConnectScratch::new(),
            &mut super::SkippedScripts,
            None,
        )
        .map(|_| ())
    }
}

#[test]
fn a_height_lock_is_satisfied_only_once_enough_blocks_have_passed() {
    let chain = RelativeLock::new();
    let depth = RelativeLock::TIP + 1 - RelativeLock::COIN_HEIGHT;
    assert_eq!(chain.connect(2, depth), Ok(()));
    assert_eq!(
        chain.connect(2, depth + 1),
        Err(ValidationError::SequenceLockNotSatisfied { tx_index: 1 })
    );
}

#[test]
fn relative_locks_are_ignored_for_version_1_and_disabled_sequences() {
    let chain = RelativeLock::new();
    assert_eq!(chain.connect(1, 0xffff), Ok(()));
    assert_eq!(chain.connect(2, (1 << 31) | 0xffff), Ok(()));
}

#[test]
fn a_time_lock_compares_median_times_past() {
    let chain = RelativeLock::new();
    let type_flag = 1u32 << 22;
    assert_eq!(chain.connect(2, type_flag | 1), Ok(()));
    assert_eq!(
        chain.connect(2, type_flag | 20),
        Err(ValidationError::SequenceLockNotSatisfied { tx_index: 1 })
    );
}

#[test]
fn accurate_multisig_counting_uses_the_key_count() {
    let two_of_three = [0x52, 0x21, 0x02, 0x53, 0xae];
    assert_eq!(SigopCost::count(&[0x52, 0x53, 0xae], true), 3);
    assert_eq!(SigopCost::count(&[0x52, 0x53, 0xae], false), 20);
    assert_eq!(SigopCost::count(&[0xac, 0xad], true), 2);
    assert_eq!(SigopCost::count(&two_of_three, true), 0);
}

#[test]
fn sigop_counting_skips_push_data() {
    assert_eq!(SigopCost::count(&[0x02, 0xac, 0xac, 0xac], false), 1);
    assert_eq!(SigopCost::count(&[0x4c, 0x05, 0xac], false), 0);
}

#[test]
fn p2sh_sigops_come_from_the_redeem_script() {
    let p2sh_spk = {
        let mut s = vec![0xa9, 0x14];
        s.extend_from_slice(&[0u8; 20]);
        s.push(0x87);
        s
    };
    let script_sig = [0x00, 0x03, 0x52, 0x53, 0xae];
    assert_eq!(SigopCost::p2sh(&script_sig, &p2sh_spk), 3);
    assert_eq!(SigopCost::p2sh(&script_sig, &[0x51]), 0);
    assert_eq!(
        SigopCost::p2sh(&[0xac, 0x03, 0x52, 0x53, 0xae], &p2sh_spk),
        0
    );
}

#[test]
fn locktime_at_the_block_height_is_not_final() {
    let finality = TxFinality::new(BlockHeight::new(500), BlockTime::new(0), BlockTime::new(0));
    assert!(!finality.is_final(&Fixture::spend(500, Sequence::new(0))));
    assert!(finality.is_final(&Fixture::spend(499, Sequence::new(0))));
}

#[test]
fn final_sequences_override_an_unmet_locktime() {
    let finality = TxFinality::new(BlockHeight::new(500), BlockTime::new(0), BlockTime::new(0));
    assert!(finality.is_final(&Fixture::spend(10_000, Sequence::MAX)));
}

#[test]
fn time_locks_use_median_time_past_from_bip113() {
    let mtp = 1_500_000_000;
    let block_time = mtp + 3_600;
    let tx = Fixture::spend(mtp + 1, Sequence::new(0));

    let before = TxFinality::new(
        BlockHeight::new(TxFinality::BIP113_HEIGHT.to_u32() - 1),
        BlockTime::new(block_time),
        BlockTime::new(mtp),
    );
    assert!(
        before.is_final(&tx),
        "pre-BIP113 time locks compare against the block time"
    );

    let after = TxFinality::new(
        TxFinality::BIP113_HEIGHT,
        BlockTime::new(block_time),
        BlockTime::new(mtp),
    );
    assert!(
        !after.is_final(&tx),
        "post-BIP113 time locks compare against median time past"
    );
}

#[test]
fn context_validation_rejects_a_non_final_transaction() {
    let view = Fixture::chain(200, 1_300_000_000);
    let tip = view.tip();
    let height = BlockHeight::new(201);
    let block = Fixture::block(
        tip.hash,
        1_300_000_000 + 12 * 600,
        vec![
            Fixture::coinbase(height),
            Fixture::spend(201, Sequence::new(0)),
        ],
    );
    assert_eq!(
        validate_block_context_with_clock(&block, &view, &FixedClock(u64::MAX / 2), false),
        Err(ValidationError::NonFinalTransaction { tx_index: 1 })
    );
}

#[test]
fn mainnet_block_481828_witness_commitment_verifies() {
    let block = Fixture::mainnet_481828();
    assert_eq!(
        WitnessCommitment::check(&block, BlockHeight::new(481_828)),
        Ok(())
    );
}

#[test]
fn a_tampered_witness_commitment_is_rejected() {
    let mut block = Fixture::mainnet_481828();
    let mut spk = block.transactions[0].outputs[1].script_pubkey.to_vec();
    spk[10] ^= 0x01;
    block.transactions[0].outputs[1].script_pubkey = spk.into();
    assert_eq!(
        WitnessCommitment::check(&block, BlockHeight::new(481_828)),
        Err(ValidationError::BadWitnessMerkleMatch)
    );
}

#[test]
fn a_wrong_size_witness_reserved_value_is_rejected() {
    let mut block = Fixture::mainnet_481828();
    block.transactions[0].inputs[0].witness = Witness::from_slice(&[&[0u8; 31][..]]);
    assert_eq!(
        WitnessCommitment::check(&block, BlockHeight::new(481_828)),
        Err(ValidationError::BadWitnessNonceSize)
    );
}

#[test]
fn witness_data_without_a_commitment_is_rejected() {
    let height = BlockHeight::new(500_000);
    let mut spend = Fixture::spend(0, Sequence::MAX);
    spend.inputs[0].witness = Witness::from_slice(&[&[0x01][..]]);
    let block = Fixture::block(Hash256::ZERO, 0, vec![Fixture::coinbase(height), spend]);
    assert_eq!(
        WitnessCommitment::check(&block, height),
        Err(ValidationError::UnexpectedWitness { tx_index: 1 })
    );

    let plain = Fixture::block(
        Hash256::ZERO,
        0,
        vec![Fixture::coinbase(height), Fixture::spend(0, Sequence::MAX)],
    );
    assert_eq!(WitnessCommitment::check(&plain, height), Ok(()));
}

#[test]
fn a_commitment_before_segwit_activation_does_not_permit_witness_data() {
    let mut block = Fixture::mainnet_481828();
    let height = BlockHeight::new(WitnessCommitment::SEGWIT_HEIGHT.to_u32() - 1);
    assert_eq!(
        WitnessCommitment::check(&block, height),
        Err(ValidationError::UnexpectedWitness { tx_index: 0 })
    );
    block.transactions[0].inputs[0].witness = Witness::empty();
    assert_eq!(WitnessCommitment::check(&block, height), Ok(()));
}
