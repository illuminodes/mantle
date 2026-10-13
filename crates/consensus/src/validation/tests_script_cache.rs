use k256::ecdsa::signature::hazmat::PrehashSigner;
use mantle::primitives::{
    Block, BlockHeader, BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Locktime,
    Nonce, OutPoint, Satoshi, Sequence, Transaction, TxHash, TxIn, TxOut, TxVersion, Witness,
};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use super::connect::{block_subsidy, connect_block};
use crate::chain_view::{Coin, ConnectScratch, MemoryChainView};
use crate::error::ValidationError;
use crate::merkle::compute_merkle_root;
use crate::script::sighash::{Bip341Cache, SigHashType, TapHasher, TaprootSigHashType, TxSighash};
use crate::script::{ScriptError, ScriptExecutionCache};

const HEIGHT: u32 = 800_000;

struct EcdsaKey(k256::ecdsa::SigningKey);

impl EcdsaKey {
    fn new(secret: u8) -> Self {
        Self(k256::ecdsa::SigningKey::from_bytes(&[secret; 32].into()).expect("nonzero secret"))
    }

    fn pubkey(&self) -> Vec<u8> {
        self.0.verifying_key().to_sec1_point(true).as_bytes().to_vec()
    }

    fn p2pkh_spk(&self) -> Vec<u8> {
        let pkh: [u8; 20] = Ripemd160::digest(Sha256::digest(self.pubkey())).into();
        let mut spk = vec![0x76, 0xa9, 0x14];
        spk.extend_from_slice(&pkh);
        spk.extend_from_slice(&[0x88, 0xac]);
        spk
    }

    fn p2pkh_script_sig(&self, tx: &Transaction, n_in: usize) -> Vec<u8> {
        let digest = tx.legacy_sighash(n_in, &self.p2pkh_spk(), SigHashType::ALL);
        let sig: k256::ecdsa::Signature = self.0.sign_prehash(digest.as_bytes()).expect("sign");
        let mut der = sig.normalize_s().to_der().as_bytes().to_vec();
        der.push(0x01);
        let pk = self.pubkey();
        let mut script_sig = vec![u8::try_from(der.len()).expect("der fits")];
        script_sig.extend_from_slice(&der);
        script_sig.push(u8::try_from(pk.len()).expect("pk fits"));
        script_sig.extend_from_slice(&pk);
        script_sig
    }
}

struct TaprootKey {
    tweaked_secret: [u8; 32],
    output_key: [u8; 32],
}

impl TaprootKey {
    fn new(secret: u8) -> Self {
        use k256::elliptic_curve::bigint::Encoding;
        use k256::elliptic_curve::ops::Reduce;
        use k256::{NonZeroScalar, Scalar, U256};

        let sk = k256::schnorr::SigningKey::from_bytes(&[secret; 32].into()).expect("nonzero");
        let internal: [u8; 32] = sk.verifying_key().to_bytes().into();
        let tweak = crate::script::consensus_crypto::Schnorr::tagged_hash(b"TapTweak", &internal);
        let t = <Scalar as Reduce<U256>>::reduce(&U256::from_be_bytes(tweak.into()));
        let d: Scalar = *sk.as_nonzero_scalar().as_ref();
        let tweaked = NonZeroScalar::new(d + t).expect("nonzero tweak");
        Self {
            tweaked_secret: tweaked.to_bytes().into(),
            output_key: TapHasher::tweak_output_key(&internal, &[]).expect("valid key"),
        }
    }

    fn spk(&self) -> Vec<u8> {
        let mut spk = vec![0x51, 0x20];
        spk.extend_from_slice(&self.output_key);
        spk
    }

    fn sign(&self, msg: &[u8; 32]) -> Vec<u8> {
        use k256::schnorr::signature::hazmat::PrehashSigner as _;
        let sk = k256::schnorr::SigningKey::from_bytes(&self.tweaked_secret.into()).expect("key");
        let sig: k256::schnorr::Signature = sk.sign_prehash(msg).expect("sign");
        sig.to_bytes().to_vec()
    }
}

struct Chain {
    view: MemoryChainView,
}

impl Chain {
    fn new() -> Self {
        let mut view = MemoryChainView::with_height_base(BlockHeight::new(HEIGHT - 1));
        view.push_header(BlockHeader::new(
            BlockVersion::new(4),
            Hash256::ZERO,
            Hash256::ZERO,
            BlockTime::new(1_700_000_000),
            CompactBits::new(0x207f_ffff),
            Nonce::new(0),
        ));
        Self { view }
    }

    fn fund(&mut self, tag: u8, value: u64, spk: &[u8]) -> OutPoint {
        let outpoint = OutPoint {
            txid: Hash256::from_bytes([tag; 32]),
            vout: 0,
        };
        self.view.insert_coin(
            outpoint,
            Coin {
                value: Satoshi::new(value),
                script_pubkey: spk.to_vec().into(),
                height: BlockHeight::new(1),
                coinbase: false,
            },
        );
        outpoint
    }

    fn block(spends: Vec<Transaction>) -> Block {
        let height = BlockHeight::new(HEIGHT);
        let coinbase = Transaction {
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
                value: block_subsidy(height),
                script_pubkey: vec![0x51].into(),
            }],
            locktime: Locktime::new(0),
        };
        let mut txs = vec![coinbase];
        txs.extend(spends);
        let txids: Vec<Hash256> = txs.iter().map(|t| t.txid().expect("txid")).collect();
        Block {
            header: BlockHeader::new(
                BlockVersion::new(4),
                Hash256::ZERO,
                compute_merkle_root(&txids).expect("non-empty"),
                BlockTime::new(1_700_000_600),
                CompactBits::new(0x207f_ffff),
                Nonce::new(0),
            ),
            transactions: txs,
        }
    }

    fn connect(
        &self,
        block: &Block,
        cache: Option<&mut ScriptExecutionCache>,
    ) -> Result<Satoshi, ValidationError> {
        connect_block(
            block,
            BlockHeight::new(HEIGHT),
            &self.view,
            &mut Vec::new(),
            &mut ConnectScratch::new(),
            &mut super::InlineScripts::new(cache),
            None,
        )
        .map(|r| r.fees)
    }
}

struct Spend;

impl Spend {
    fn tx(inputs: &[OutPoint], out_value: u64) -> Transaction {
        Transaction {
            version: TxVersion::new(2),
            inputs: inputs
                .iter()
                .map(|&previous_output| TxIn {
                    previous_output,
                    script_sig: Vec::<u8>::new().into(),
                    sequence: Sequence::MAX,
                    witness: Witness::empty(),
                })
                .collect(),
            outputs: vec![TxOut {
                value: Satoshi::new(out_value),
                script_pubkey: vec![0x51].into(),
            }],
            locktime: Locktime::new(0),
        }
    }
}

struct SigopHeavy;

impl SigopHeavy {
    const P2SH_REDEEM_LEN: usize = 520;
    const WITNESS_SCRIPT_LEN: usize = 5_000;

    fn p2sh(chain: &mut Chain, tag: u8) -> (OutPoint, Vec<u8>) {
        let redeem = vec![0xae; Self::P2SH_REDEEM_LEN];
        let hash: [u8; 20] = Ripemd160::digest(Sha256::digest(&redeem)).into();
        let mut spk = vec![0xa9, 0x14];
        spk.extend_from_slice(&hash);
        spk.push(0x87);
        let len = u16::try_from(redeem.len()).expect("fits").to_le_bytes();
        let mut script_sig = vec![0x4d, len[0], len[1]];
        script_sig.extend_from_slice(&redeem);
        (chain.fund(tag, 10_000, &spk), script_sig)
    }

    fn p2wsh(chain: &mut Chain, tag: u8) -> (OutPoint, Vec<u8>) {
        let script = vec![0xae; Self::WITNESS_SCRIPT_LEN];
        let mut spk = vec![0x00, 0x20];
        spk.extend_from_slice(&Sha256::digest(&script));
        (chain.fund(tag, 10_000, &spk), script)
    }

    fn connect(chain: &Chain, tx: Transaction) -> Result<Satoshi, ValidationError> {
        connect_block(
            &Chain::block(vec![tx]),
            BlockHeight::new(HEIGHT),
            &chain.view,
            &mut Vec::new(),
            &mut ConnectScratch::new(),
            &mut super::SkippedScripts,
            None,
        )
        .map(|r| r.fees)
    }
}

#[test]
fn connect_block_counts_p2sh_redeem_script_sigops() {
    let mut chain = Chain::new();
    let (a, sig_a) = SigopHeavy::p2sh(&mut chain, 0x61);
    let (b, sig_b) = SigopHeavy::p2sh(&mut chain, 0x62);
    let mut tx = Spend::tx(&[a, b], 1_000);
    tx.inputs[0].script_sig = sig_a.into();
    tx.inputs[1].script_sig = sig_b.into();
    let r = SigopHeavy::connect(&chain, tx);
    assert!(
        matches!(r, Err(ValidationError::SigopsLimitExceeded { cost: 83_200 })),
        "two 520-byte CHECKMULTISIG redeem scripts must exceed the budget, got {r:?}"
    );
}

#[test]
fn connect_block_counts_witness_script_sigops() {
    let mut chain = Chain::new();
    let (outpoint, script) = SigopHeavy::p2wsh(&mut chain, 0x71);
    let mut tx = Spend::tx(&[outpoint], 1_000);
    tx.inputs[0].witness = Witness::from_slice(&[&script]);
    let r = SigopHeavy::connect(&chain, tx);
    assert!(
        matches!(r, Err(ValidationError::SigopsLimitExceeded { cost: 100_000 })),
        "a 5,000-byte CHECKMULTISIG witness script must exceed the budget, got {r:?}"
    );
}

#[test]
fn connect_block_rejects_two_transactions_spending_one_output() {
    let mut chain = Chain::new();
    let funded = chain.fund(0x31, 50_000, &[0x51]);
    let first = Spend::tx(&[funded], 40_000);
    let mut second = Spend::tx(&[funded], 30_000);
    second.version = TxVersion::new(1);
    let r = chain.connect(&Chain::block(vec![first, second]), None);
    assert!(
        matches!(r, Err(ValidationError::MissingInput { tx_index: 2, input_index: 0 })),
        "a second spend of the same output must be rejected, got {r:?}"
    );
}

#[test]
fn connect_block_resolves_a_spend_of_an_earlier_output_in_the_block() {
    let mut chain = Chain::new();
    let funded = chain.fund(0x41, 50_000, &[0x51]);
    let parent = Spend::tx(&[funded], 45_000);
    let parent_txid = parent.txid().expect("txid");
    let child = Spend::tx(&[OutPoint { txid: parent_txid, vout: 0 }], 40_000);
    assert_eq!(
        chain.connect(&Chain::block(vec![parent, child]), None),
        Ok(Satoshi::new(10_000))
    );
}

#[test]
fn connect_block_rejects_a_spend_of_a_later_output_in_the_block() {
    let mut chain = Chain::new();
    let funded = chain.fund(0x51, 50_000, &[0x51]);
    let parent = Spend::tx(&[funded], 45_000);
    let parent_txid = parent.txid().expect("txid");
    let child = Spend::tx(&[OutPoint { txid: parent_txid, vout: 0 }], 40_000);
    let r = chain.connect(&Chain::block(vec![child, parent]), None);
    assert!(
        matches!(r, Err(ValidationError::MissingInput { tx_index: 1, input_index: 0 })),
        "spending an output created later in the block must fail, got {r:?}"
    );
}

#[test]
fn exec_cache_does_not_reuse_a_verdict_across_transactions() {
    let key = EcdsaKey::new(7);
    let spk = key.p2pkh_spk();
    let mut chain = Chain::new();
    let funded_a = chain.fund(0xa1, 50_000, &spk);
    let funded_b = chain.fund(0xb2, 50_000, &spk);

    let mut honest = Spend::tx(&[funded_a], 40_000);
    honest.inputs[0].script_sig = key.p2pkh_script_sig(&honest, 0).into();

    let mut forged = Spend::tx(&[funded_b], 49_000);
    forged.inputs[0].script_sig = honest.inputs[0].script_sig.clone();

    let mut cache = ScriptExecutionCache::new(64);
    chain
        .connect(&Chain::block(vec![honest]), Some(&mut cache))
        .expect("honest spend verifies");

    let uncached = chain.connect(&Chain::block(vec![forged.clone()]), None);
    assert!(
        matches!(uncached, Err(ValidationError::ScriptVerifyFailed { .. })),
        "replayed signature must fail without a cache, got {uncached:?}"
    );

    let cached = chain.connect(&Chain::block(vec![forged]), Some(&mut cache));
    assert!(
        matches!(cached, Err(ValidationError::ScriptVerifyFailed { .. })),
        "replayed signature must fail with a warm cache, got {cached:?}"
    );
}

#[test]
fn exec_cache_hits_for_the_same_transaction() {
    let key = EcdsaKey::new(9);
    let spk = key.p2pkh_spk();
    let mut chain = Chain::new();
    let funded = chain.fund(0xc3, 50_000, &spk);

    let mut tx = Spend::tx(&[funded], 40_000);
    tx.inputs[0].script_sig = key.p2pkh_script_sig(&tx, 0).into();
    let block = Chain::block(vec![tx]);

    let mut cache = ScriptExecutionCache::new(64);
    chain.connect(&block, Some(&mut cache)).expect("cold");
    chain.connect(&block, Some(&mut cache)).expect("hot");
    assert_eq!(cache.hits(), 1);
}

#[test]
fn connect_block_verifies_multi_input_taproot_key_path() {
    let k0 = TaprootKey::new(0x33);
    let k1 = TaprootKey::new(0x44);
    let (spk0, spk1) = (k0.spk(), k1.spk());
    let mut chain = Chain::new();
    let in0 = chain.fund(0xd4, 60_000, &spk0);
    let in1 = chain.fund(0xe5, 40_000, &spk1);

    let mut tx = Spend::tx(&[in0, in1], 95_000);
    let amounts = [Satoshi::new(60_000), Satoshi::new(40_000)];
    let spent_table: [&[u8]; 2] = [&spk0, &spk1];
    let cache = Bip341Cache::new(&tx, &amounts, &spent_table);
    let sig0 = k0.sign(&tx.bip341_sighash(
        0,
        amounts[0],
        &spk0,
        TaprootSigHashType::DEFAULT,
        &cache,
        None,
        None,
    ));
    let sig1 = k1.sign(&tx.bip341_sighash(
        1,
        amounts[1],
        &spk1,
        TaprootSigHashType::DEFAULT,
        &cache,
        None,
        None,
    ));
    tx.inputs[0].witness = Witness::from_slice(&[&sig0]);
    tx.inputs[1].witness = Witness::from_slice(&[&sig1]);
    let block = Chain::block(vec![tx]);

    assert_eq!(chain.connect(&block, None), Ok(Satoshi::new(5_000)));
    let mut exec = ScriptExecutionCache::new(64);
    assert_eq!(chain.connect(&block, Some(&mut exec)), Ok(Satoshi::new(5_000)));
}

#[test]
fn connect_block_rejects_multi_input_taproot_with_a_bad_signature() {
    let k0 = TaprootKey::new(0x55);
    let k1 = TaprootKey::new(0x66);
    let (spk0, spk1) = (k0.spk(), k1.spk());
    let mut chain = Chain::new();
    let in0 = chain.fund(0xf6, 60_000, &spk0);
    let in1 = chain.fund(0x17, 40_000, &spk1);

    let mut tx = Spend::tx(&[in0, in1], 95_000);
    let amounts = [Satoshi::new(60_000), Satoshi::new(40_000)];
    let spent_table: [&[u8]; 2] = [&spk0, &spk1];
    let cache = Bip341Cache::new(&tx, &amounts, &spent_table);
    let sig0 = k0.sign(&tx.bip341_sighash(
        0,
        amounts[0],
        &spk0,
        TaprootSigHashType::DEFAULT,
        &cache,
        None,
        None,
    ));
    let wrong = k0.sign(&[0x99; 32]);
    tx.inputs[0].witness = Witness::from_slice(&[&sig0]);
    tx.inputs[1].witness = Witness::from_slice(&[&wrong]);

    let r = chain.connect(&Chain::block(vec![tx]), None);
    match r {
        Err(ValidationError::ScriptVerifyFailed {
            input_index: 1,
            kind,
            ..
        }) => assert_ne!(kind, ScriptError::TaprootMissingSpentOutputs),
        other => panic!("expected input 1 to fail its signature, got {other:?}"),
    }
}
