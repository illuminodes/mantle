#![allow(dead_code)]

use mantle::primitives::{
    BlockHeader, BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Nonce, OutPoint,
    Satoshi, ScriptPubKey,
};
use mantle_consensus::chain_view::{Coin, NewCoin};
use mantle_storage::engine::flat::FlatEngine;
use mantle_storage::engine::robin_hood::RobinHoodEngine;
use mantle_storage::engine::Engine;
use mantle_storage::types::{CommitBlockReq, Durability, ReqToken};

pub const ITERS_SMALL: u32 = 500;
pub const ITERS_MEDIUM: u32 = 2_000;
pub const ITERS_LARGE: u32 = 10_000;

pub const P2WPKH_SPK: [u8; 22] = [
    0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
];

pub fn make_header(time: u32) -> BlockHeader {
    BlockHeader::new(
        BlockVersion::new(1),
        Hash256::ZERO,
        Hash256::ZERO,
        BlockTime::new(time),
        CompactBits::new(0x1d00_ffff),
        Nonce::new(0),
    )
}

pub fn make_outpoint(i: u32) -> OutPoint {
    let mut txid_bytes = [0u8; 32];
    txid_bytes[..4].copy_from_slice(&i.to_le_bytes());
    OutPoint {
        txid: Hash256::from_bytes(txid_bytes),
        vout: 0,
    }
}

pub fn make_block_hash(i: u32) -> Hash256 {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&(i + 10_000).to_le_bytes());
    Hash256::from_bytes(bytes)
}

pub fn make_coin(value: u64) -> Coin {
    Coin {
        value: Satoshi::new(value),
        script_pubkey: ScriptPubKey::from_slice(&P2WPKH_SPK),
        height: BlockHeight::new(100),
        coinbase: false,
    }
}

pub fn seed_flat(dir: &std::path::Path, n_blocks: u32) -> FlatEngine {
    let mut eng = FlatEngine::open(dir).unwrap();
    commit_blocks(&mut eng, n_blocks);
    eng
}

pub fn seed_robin_hood(dir: &std::path::Path, n_blocks: u32) -> RobinHoodEngine {
    let mut eng = RobinHoodEngine::open(dir).unwrap();
    commit_blocks(&mut eng, n_blocks);
    eng
}

fn commit_blocks(eng: &mut dyn Engine, n_blocks: u32) {
    let mut prev = Hash256::ZERO;
    for h in 1..=n_blocks {
        let op = make_outpoint(h);
        let block_hash = make_block_hash(h);
        let created = [NewCoin {
            outpoint: op,
            value: Satoshi::new(5_000_000_000),
            script_pubkey: &P2WPKH_SPK,
            coinbase: true,
            height: BlockHeight::new(h),
        }];
        let mut header = make_header(h);
        header.set_prev_block(prev);
        eng.write_block(&CommitBlockReq {
            token: ReqToken(u64::from(h)),
            height: BlockHeight::new(h),
            hash: block_hash,
            prev_hash: prev,
            header,
            created: &created,
            spent: &[],
            block_bytes: None,
            durability: Durability::Memory,
        })
        .unwrap();
        prev = block_hash;
    }
}
