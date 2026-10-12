#![allow(dead_code)]

use mantle::primitives::{
    Block, BlockHeader, BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Locktime,
    Nonce, OutPoint, Satoshi, Sequence, Transaction, TxHash, TxIn, TxOut, TxVersion, Witness,
};
use mantle_consensus::merkle::compute_merkle_root;
use mantle_consensus::script::ScriptExecutionCache;
use mantle_storage::StorageHandle;
use mantle_storage::types::{Durability, ReqToken};
use mantle_validator::{HeaderSnapshot, PipelineOpts, ReplayBufs};

pub const EASY_BITS: CompactBits = CompactBits::new(0x207f_ffff);
pub const BASE_TIME: u32 = 1_231_006_505;
pub const ITERS_SMALL: u32 = 500;
pub const ITERS_MEDIUM: u32 = 2_000;
pub const ITERS_LARGE: u32 = 5_000;

pub fn coinbase_tx(height: u32, value: u64) -> Transaction {
    let h = height.to_le_bytes();
    Transaction {
        version: TxVersion::new(1),
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::ZERO,
                vout: u32::MAX,
            },
            script_sig: vec![0x03, h[0], h[1], h[2]].into(),
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

pub fn spend_tx(prev_txid: Hash256, vout: u32, value: u64) -> Transaction {
    Transaction {
        version: TxVersion::new(1),
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: prev_txid,
                vout,
            },
            script_sig: vec![0x51].into(),
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

pub fn multi_output_coinbase(height: u32, n_outputs: usize) -> Transaction {
    let h = height.to_le_bytes();
    Transaction {
        version: TxVersion::new(1),
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::ZERO,
                vout: u32::MAX,
            },
            script_sig: vec![0x03, h[0], h[1], h[2]].into(),
            sequence: Sequence::MAX,
            witness: Witness::empty(),
        }],
        outputs: (0..n_outputs)
            .map(|_| TxOut {
                value: Satoshi::new(1000),
                script_pubkey: vec![0x51].into(),
            })
            .collect(),
        locktime: Locktime::new(0),
    }
}

pub fn mine(mut block: Block) -> Block {
    let target = block
        .header
        .bits()
        .to_target()
        .expect("EASY_BITS always valid");
    for nonce in 0..=u32::MAX {
        block.header.set_nonce(Nonce::new(nonce));
        let mut hash = *Hash256::hash(&block.header.to_bytes()).as_bytes();
        hash.reverse();
        if hash <= target {
            return block;
        }
    }
    panic!("no valid nonce");
}

pub fn make_block(prev_hash: Hash256, height: u32, txs: Vec<Transaction>) -> Block {
    let txids: Vec<Hash256> = txs.iter().map(|tx| tx.txid().expect("txid")).collect();
    let merkle_root = compute_merkle_root(&txids).expect("non-empty list has merkle root");
    mine(Block {
        header: BlockHeader::new(
            BlockVersion::new(4),
            prev_hash,
            merkle_root,
            BlockTime::new(BASE_TIME + height * 600),
            EASY_BITS,
            Nonce::new(0),
        ),
        transactions: txs,
    })
}

pub fn pre_genesis_header() -> BlockHeader {
    BlockHeader::new(
        BlockVersion::new(1),
        Hash256::ZERO,
        Hash256::ZERO,
        BlockTime::new(BASE_TIME),
        EASY_BITS,
        Nonce::new(0),
    )
}

pub fn make_snapshot(chain: &[(Hash256, BlockHeader)]) -> HeaderSnapshot {
    let mut entries = Vec::with_capacity(chain.len() + 1);
    entries.push((Hash256::ZERO, pre_genesis_header()));
    entries.extend_from_slice(chain);
    HeaderSnapshot::new(BlockHeight::new(0), entries).expect("snapshot fits u32")
}

pub struct TmpDir(pub std::path::PathBuf);
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn tmp_storage() -> (StorageHandle<'static>, TmpDir) {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let path = std::env::temp_dir().join(format!(
        "mantle-validator-bench-{}-{}",
        std::process::id(),
        ns
    ));
    std::fs::create_dir_all(&path).expect("create tmp dir");
    let handle = StorageHandle::open(&path).expect("StorageHandle::open");
    (handle, TmpDir(path))
}

pub fn commit(
    bufs: &mut ReplayBufs,
    storage: &mut StorageHandle<'static>,
    block: &Block,
    height: BlockHeight,
    snap: &HeaderSnapshot,
    cache: &mut ScriptExecutionCache,
    token: u64,
) {
    bufs.validate_and_commit(
        block,
        height,
        storage,
        snap,
        PipelineOpts {
            skip_script: true,
            exec_cache: Some(cache),
            durability: Durability::Memory,
            token: ReqToken(token),
            utxo_hash: None,
        },
    )
    .unwrap_or_else(|e| panic!("commit at height {}: {e}", height.to_u32()));
}

pub struct SeedState {
    pub chain: Vec<(Hash256, BlockHeader)>,
    pub snap: HeaderSnapshot,
    pub fund_block: Block,
    pub filler: Vec<Block>,
    pub spend_block: Block,
    pub fund_height: u32,
    pub spend_height: u32,
}

pub fn build_spend_scenario(n_spends: usize) -> SeedState {
    let maturity: u32 = 100;
    let fund_height: u32 = 1;
    let spend_height: u32 = fund_height + maturity + 1;

    let fund_block = make_block(
        Hash256::ZERO,
        fund_height,
        vec![multi_output_coinbase(fund_height, n_spends)],
    );
    let fund_txid = fund_block.transactions[0].txid().expect("txid");
    let fund_hash = fund_block.header.hash();

    let mut prev_hash = fund_hash;
    let mut filler: Vec<Block> = Vec::new();
    for h in 2..spend_height {
        let b = make_block(prev_hash, h, vec![coinbase_tx(h, 50_0000_0000)]);
        prev_hash = b.header.hash();
        filler.push(b);
    }

    let spend_txs: Vec<Transaction> = std::iter::once(coinbase_tx(spend_height, 50_0000_0000))
        .chain(
            (0..n_spends).map(|i| spend_tx(fund_txid, u32::try_from(i).expect("fits"), 999)),
        )
        .collect();
    let spend_block = make_block(prev_hash, spend_height, spend_txs);
    let spend_hash = spend_block.header.hash();

    let mut chain = vec![(fund_hash, fund_block.header)];
    for b in &filler {
        chain.push((b.header.hash(), b.header));
    }
    chain.push((spend_hash, spend_block.header));
    let snap = make_snapshot(&chain);

    SeedState {
        chain,
        snap,
        fund_block,
        filler,
        spend_block,
        fund_height,
        spend_height,
    }
}

pub fn seed_storage(
    state: &SeedState,
    storage: &mut StorageHandle<'static>,
    bufs: &mut ReplayBufs,
    cache: &mut ScriptExecutionCache,
) {
    commit(
        bufs,
        storage,
        &state.fund_block,
        BlockHeight::new(state.fund_height),
        &state.snap,
        cache,
        1,
    );
    for (i, b) in state.filler.iter().enumerate() {
        commit(
            bufs,
            storage,
            b,
            BlockHeight::new(2 + u32::try_from(i).expect("fits")),
            &state.snap,
            cache,
            2 + u64::try_from(i).expect("fits"),
        );
    }
}
