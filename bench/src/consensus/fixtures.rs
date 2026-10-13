use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature as EcdsaSig, SigningKey};
use mantle::codec::Encode;
use mantle::primitives::{
    Block, BlockHeader, BlockTime, BlockVersion, CompactBits, Hash256, Locktime, Nonce, OutPoint,
    Satoshi, Sequence, Transaction, TxHash, TxIn, TxOut, TxVersion, Witness,
};
use mantle_consensus::merkle::merkle_root_owned;
use mantle_consensus::script::ScriptFlags;
use mantle_consensus::script::consensus_crypto::Schnorr;
use mantle_consensus::script::sighash::{
    Bip143Cache, Bip341Cache, SigHashType, TapHasher, TaprootSigHashType, TxSighash,
};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

pub const EASY_BITS: CompactBits = CompactBits::new(0x207f_ffff);
#[allow(dead_code)]
pub const ITERS_SMALL: u32 = 500;
#[allow(dead_code)]
pub const ITERS_MEDIUM: u32 = 2_000;
#[allow(dead_code)]
pub const ITERS_LARGE: u32 = 10_000;

pub fn encode<T: Encode>(val: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    val.encode(&mut buf).expect("Vec<u8> write cannot fail");
    buf
}

pub fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(data)).into()
}

pub fn coinbase_tx(height_script: Vec<u8>, value: u64) -> Transaction {
    Transaction {
        version: TxVersion::new(1),
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::ZERO,
                vout: u32::MAX,
            },
            script_sig: height_script.into(),
            sequence: Sequence::MAX,
            witness: Witness::empty(),
        }],
        outputs: vec![TxOut {
            value: Satoshi::new(value),
            script_pubkey: vec![0x51].into(),
        }],
        locktime: Locktime::new(0),
    }
}

pub fn regular_tx(prev: Hash256, vout: u32, value: u64) -> Transaction {
    Transaction {
        version: TxVersion::new(1),
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: prev, vout },
            script_sig: vec![0x51; 20].into(),
            sequence: Sequence::MAX,
            witness: Witness::empty(),
        }],
        outputs: vec![TxOut {
            value: Satoshi::new(value),
            script_pubkey: vec![0x51].into(),
        }],
        locktime: Locktime::new(0),
    }
}

pub fn mine_block(mut block: Block) -> Block {
    let target = block
        .header
        .bits()
        .to_target()
        .expect("mine_block called with invalid nBits");
    for nonce in 0..=u32::MAX {
        block.header.set_nonce(Nonce::new(nonce));
        let raw = *Hash256::hash(&block.header.to_bytes()).as_bytes();
        let mut be = raw;
        be.reverse();
        if be <= target {
            return block;
        }
    }
    panic!("no nonce found");
}

pub fn make_valid_block(txs: Vec<Transaction>) -> Block {
    let txids: Vec<Hash256> = txs
        .iter()
        .map(Transaction::txid)
        .collect::<Result<Vec<_>, _>>()
        .expect("txid encoding cannot fail");
    let merkle_root = merkle_root_owned(txids).expect("non-empty tx list always has a merkle root");
    let block = Block {
        header: BlockHeader::new(
            BlockVersion::new(1),
            Hash256::ZERO,
            merkle_root,
            BlockTime::new(1_231_006_505),
            EASY_BITS,
            Nonce::new(0),
        ),
        transactions: txs,
    };
    mine_block(block)
}

pub fn make_n_tx_block(n: usize) -> Block {
    let cb = coinbase_tx(vec![0x03, 0x64, 0x00, 0x00], 5_000_000_000);
    let mut txs = vec![cb];
    for i in 1..n {
        txs.push(regular_tx(
            Hash256::from_bytes([u8::try_from(i & 0xff).unwrap(); 32]),
            0,
            1000,
        ));
    }
    make_valid_block(txs)
}

pub fn make_witness_tx(witness_items: &[&[u8]]) -> Transaction {
    Transaction {
        version: TxVersion::new(1),
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::ZERO,
                vout: 0,
            },
            script_sig: vec![].into(),
            sequence: Sequence::new(0xffff_ffff),
            witness: Witness::from_slice(witness_items),
        }],
        outputs: vec![TxOut {
            value: Satoshi::new(100_000),
            script_pubkey: vec![0x6a].into(),
        }],
        locktime: Locktime::new(0),
    }
}

pub fn segwit_flags() -> ScriptFlags {
    ScriptFlags::P2SH
        | ScriptFlags::DERSIG
        | ScriptFlags::LOW_S
        | ScriptFlags::STRICTENC
        | ScriptFlags::NULLDUMMY
        | ScriptFlags::WITNESS
}

pub fn taproot_flags() -> ScriptFlags {
    ScriptFlags::P2SH | ScriptFlags::WITNESS | ScriptFlags::TAPROOT
}

pub fn ecdsa_sign(sk: &SigningKey, digest: &[u8; 32], hash_type: SigHashType) -> Vec<u8> {
    let sig: EcdsaSig = sk.sign_prehash(digest).expect("signing cannot fail");
    let sig = sig.normalize_s();
    let mut bytes = sig.to_der().as_bytes().to_vec();
    bytes.push(u8::try_from(hash_type.0 & 0xff).expect("hashtype fits u8"));
    bytes
}

pub struct P2wpkhFixture {
    pub tx: Transaction,
    pub spk: Vec<u8>,
    pub amount: Satoshi,
}

pub fn make_p2wpkh() -> P2wpkhFixture {
    let sk = SigningKey::from_bytes(&[11u8; 32].into()).expect("nonzero secret");
    let pk: Vec<u8> = sk.verifying_key().to_sec1_point(true).as_bytes().to_vec();
    let pkh = hash160(&pk);

    let mut spk = vec![0x00u8, 0x14];
    spk.extend_from_slice(&pkh);

    let mut script_code = vec![0x76u8, 0xa9, 0x14];
    script_code.extend_from_slice(&pkh);
    script_code.extend_from_slice(&[0x88, 0xac]);

    let amount = Satoshi::new(100_000);
    let tmp_tx = make_witness_tx(&[]);
    let cache = Bip143Cache::new(&tmp_tx);
    let digest = tmp_tx.bip143_sighash(0, &script_code, amount, SigHashType::ALL, &cache);
    let sig = ecdsa_sign(&sk, digest.as_bytes(), SigHashType::ALL);

    let tx = make_witness_tx(&[sig.as_slice(), pk.as_slice()]);
    P2wpkhFixture { tx, spk, amount }
}

pub struct P2wshFixture {
    pub tx: Transaction,
    pub spk: Vec<u8>,
    pub amount: Satoshi,
}

pub fn make_p2wsh() -> P2wshFixture {
    let sk = SigningKey::from_bytes(&[13u8; 32].into()).expect("nonzero secret");
    let pk: Vec<u8> = sk.verifying_key().to_sec1_point(true).as_bytes().to_vec();
    let pkh = hash160(&pk);

    let mut witness_script = vec![0x76u8, 0xa9, 0x14];
    witness_script.extend_from_slice(&pkh);
    witness_script.extend_from_slice(&[0x88, 0xac]);

    let script_hash: [u8; 32] = Sha256::digest(&witness_script).into();
    let mut spk = vec![0x00u8, 0x20];
    spk.extend_from_slice(&script_hash);

    let amount = Satoshi::new(200_000);
    let tmp_tx = make_witness_tx(&[]);
    let cache = Bip143Cache::new(&tmp_tx);
    let digest = tmp_tx.bip143_sighash(0, &witness_script, amount, SigHashType::ALL, &cache);
    let sig = ecdsa_sign(&sk, digest.as_bytes(), SigHashType::ALL);

    let tx = make_witness_tx(&[sig.as_slice(), pk.as_slice(), witness_script.as_slice()]);
    P2wshFixture { tx, spk, amount }
}

pub struct TaprootKeypathFixture {
    pub tx: Transaction,
    pub spk: Vec<u8>,
    pub amount: Satoshi,
}

pub fn make_taproot_keypath() -> TaprootKeypathFixture {
    use k256::schnorr::SigningKey as SchnorrSK;
    use k256::schnorr::signature::hazmat::PrehashSigner as _;

    let internal_secret = [0x55u8; 32];
    let internal_key: [u8; 32] = SchnorrSK::from_bytes((&internal_secret).into())
        .expect("nonzero")
        .verifying_key()
        .to_bytes()
        .into();
    let output_key = TapHasher::tweak_output_key(&internal_key, &[]).expect("valid key");

    let tweaked_secret: [u8; 32] = {
        use k256::elliptic_curve::bigint::Encoding;
        use k256::elliptic_curve::ops::Reduce;
        use k256::{NonZeroScalar, Scalar, U256};
        let sk = SchnorrSK::from_bytes((&internal_secret).into()).expect("nonzero");
        let mut tweak_input = [0u8; 32];
        tweak_input.copy_from_slice(&internal_key);
        let tweak_bytes = Schnorr::tagged_hash(b"TapTweak", &tweak_input);
        let t = <Scalar as Reduce<U256>>::reduce(&U256::from_be_bytes(tweak_bytes.into()));
        let d: Scalar = *sk.as_nonzero_scalar().as_ref();
        NonZeroScalar::new(d + t)
            .expect("nonzero")
            .to_bytes()
            .into()
    };

    let amount = Satoshi::new(100_000);
    let mut spk = vec![0x51u8, 0x20];
    spk.extend_from_slice(&output_key);

    let placeholder = Transaction {
        version: TxVersion::new(2),
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_bytes([0x55; 32]),
                vout: 0,
            },
            script_sig: vec![].into(),
            sequence: Sequence::new(0xffff_fffd),
            witness: Witness::empty(),
        }],
        outputs: vec![TxOut {
            value: amount,
            script_pubkey: spk.clone().into(),
        }],
        locktime: Locktime::new(0),
    };
    let cache = Bip341Cache::new(&placeholder, &[amount], &[spk.as_slice()]);
    let msg = placeholder.bip341_sighash(
        0,
        amount,
        &spk,
        TaprootSigHashType::DEFAULT,
        &cache,
        None,
        None,
    );
    let sig64: [u8; 64] = {
        let sk = SchnorrSK::from_bytes((&tweaked_secret).into()).expect("nonzero");
        let sig: k256::schnorr::Signature = sk.sign_prehash(&msg).expect("sign");
        sig.to_bytes()
    };

    let tx = Transaction {
        version: TxVersion::new(2),
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_bytes([0x55; 32]),
                vout: 0,
            },
            script_sig: vec![].into(),
            sequence: Sequence::new(0xffff_fffd),
            witness: Witness::from_slice(&[sig64.as_slice()]),
        }],
        outputs: vec![TxOut {
            value: amount,
            script_pubkey: spk.clone().into(),
        }],
        locktime: Locktime::new(0),
    };

    TaprootKeypathFixture { tx, spk, amount }
}
