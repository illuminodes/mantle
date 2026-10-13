use std::hint::black_box;

use mantle::primitives::{
    BlockHeader, BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Nonce, OutPoint,
    Satoshi, ScriptPubKey,
};
use mantle_consensus::chain_view::{Coin, NewCoin};
use mantle_storage::engine::flat::FlatEngine;
use mantle_storage::engine::Engine;
use mantle_storage::types::{CommitBlockReq, Durability, LookupResult, ReqToken};
use mantle_storage::with_storage;

fn main() {
    divan::main();
}

// ── Helpers ────────────────────────────────────────────────────────────────

struct TmpDir(std::path::PathBuf);
impl TmpDir {
    fn new(name: &str) -> Self {
        let ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let path = std::env::temp_dir().join(format!(
            "mantle-bench-{}-{}-{}",
            name,
            std::process::id(),
            ns
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn make_header(time: u32) -> BlockHeader {
    BlockHeader::new(
        BlockVersion::new(1),
        Hash256::ZERO,
        Hash256::ZERO,
        BlockTime::new(time),
        CompactBits::new(0x1d00_ffff),
        Nonce::new(0),
    )
}

fn make_outpoint(i: u32) -> OutPoint {
    let mut txid_bytes = [0u8; 32];
    txid_bytes[..4].copy_from_slice(&i.to_le_bytes());
    OutPoint {
        txid: Hash256::from_bytes(txid_bytes),
        vout: 0,
    }
}

fn make_block_hash(i: u32) -> Hash256 {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&(i + 10_000).to_le_bytes());
    Hash256::from_bytes(bytes)
}

const P2WPKH_SPK: [u8; 22] = [
    0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
];

// ── FlatEngine ─────────────────────────────────────────────────────────────

mod flat {
    use super::{
        black_box, make_block_hash, make_header, make_outpoint, BlockHeight, CommitBlockReq,
        Durability, Engine, FlatEngine, Hash256, LookupResult, NewCoin, OutPoint, P2WPKH_SPK,
        ReqToken, Satoshi, TmpDir,
    };

    fn seeded_engine(n_blocks: u32) -> (TmpDir, FlatEngine) {
        let dir = TmpDir::new("flat");
        let mut eng = FlatEngine::open(dir.path()).unwrap();
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
        (dir, eng)
    }

    #[divan::bench]
    fn write_block(bencher: divan::Bencher) {
        let dir = TmpDir::new("flat-wb");
        let mut eng = FlatEngine::open(dir.path()).unwrap();
        let mut h = 1u32;
        let mut prev = Hash256::ZERO;
        bencher.bench_local(|| {
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
            h += 1;
        });
    }

    #[divan::bench]
    fn read_coin_hit(bencher: divan::Bencher) {
        let (_dir, mut eng) = seeded_engine(1000);
        let target = make_outpoint(500);
        bencher.bench_local(|| {
            black_box(eng.read_coin(black_box(&target)).unwrap());
        });
    }

    #[divan::bench]
    fn read_coin_miss(bencher: divan::Bencher) {
        let (_dir, mut eng) = seeded_engine(1000);
        let missing = make_outpoint(99_999);
        bencher.bench_local(|| {
            black_box(eng.read_coin(black_box(&missing)).unwrap());
        });
    }

    #[divan::bench(args = [1usize, 10, 100])]
    fn read_coins_batch(bencher: divan::Bencher, n: usize) {
        let (_dir, mut eng) = seeded_engine(1000);
        let ops: Vec<OutPoint> =
            (1..=n).map(|i| make_outpoint(u32::try_from(i).expect("bench index fits u32"))).collect();
        let mut out: Vec<LookupResult> = Vec::new();
        bencher.bench_local(|| {
            out.clear();
            eng.read_coins(black_box(&ops), &mut out).unwrap();
        });
    }

    #[divan::bench]
    fn read_header_at(bencher: divan::Bencher) {
        let (_dir, eng) = seeded_engine(1000);
        bencher.bench(|| {
            black_box(
                eng.read_header_at(black_box(BlockHeight::new(500)))
                    .unwrap(),
            );
        });
    }

    #[divan::bench]
    fn flush_synced(bencher: divan::Bencher) {
        let (_dir, mut eng) = seeded_engine(100);
        bencher.bench_local(|| {
            eng.flush(Durability::Synced).unwrap();
        });
    }

    #[divan::bench]
    fn recover(bencher: divan::Bencher) {
        let dir = TmpDir::new("flat-recover");
        {
            let mut eng = FlatEngine::open(dir.path()).unwrap();
            let mut prev = Hash256::ZERO;
            for h in 1..=500u32 {
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
                eng.flush(Durability::Synced).unwrap();
                prev = block_hash;
            }
        }
        bencher.bench(|| {
            black_box(FlatEngine::open(dir.path()).unwrap());
        });
    }
}

// ── RobinHoodTable (synchronous) ───────────────────────────────────────────

mod robin_hood {
    use super::{black_box, make_outpoint, BlockHeight, Coin, P2WPKH_SPK, Satoshi, ScriptPubKey, TmpDir};
    use mantle_storage::engine::robin_hood::RobinHoodTable;

    fn make_coin(value: u64) -> Coin {
        Coin {
            value: Satoshi::new(value),
            script_pubkey: ScriptPubKey::from_slice(&P2WPKH_SPK),
            height: BlockHeight::new(100),
            coinbase: false,
        }
    }

    #[divan::bench]
    fn insert(bencher: divan::Bencher) {
        let dir = TmpDir::new("rh-insert");
        let path = dir.path().join("utxo_table.bin");
        let mut table = RobinHoodTable::open_with_capacity(&path, 65536).unwrap();
        let coin = make_coin(1000);
        let mut i = 0u32;
        bencher.bench_local(|| {
            let op = make_outpoint(i);
            table.insert(&op, &coin).unwrap();
            i += 1;
        });
    }

    #[divan::bench]
    fn get_hit(bencher: divan::Bencher) {
        let dir = TmpDir::new("rh-get");
        let path = dir.path().join("utxo_table.bin");
        let mut table = RobinHoodTable::open_with_capacity(&path, 65536).unwrap();
        let coin = make_coin(1000);
        for i in 0..10_000u32 {
            table.insert(&make_outpoint(i), &coin).unwrap();
        }
        let target = make_outpoint(5000);
        bencher.bench(|| {
            black_box(table.get(black_box(&target)).unwrap());
        });
    }

    #[divan::bench]
    fn get_miss(bencher: divan::Bencher) {
        let dir = TmpDir::new("rh-miss");
        let path = dir.path().join("utxo_table.bin");
        let mut table = RobinHoodTable::open_with_capacity(&path, 65536).unwrap();
        let coin = make_coin(1000);
        for i in 0..10_000u32 {
            table.insert(&make_outpoint(i), &coin).unwrap();
        }
        let missing = make_outpoint(99_999);
        bencher.bench(|| {
            black_box(table.get(black_box(&missing)).unwrap());
        });
    }

    #[divan::bench]
    fn remove(bencher: divan::Bencher) {
        let dir = TmpDir::new("rh-remove");
        let path = dir.path().join("utxo_table.bin");
        let mut table = RobinHoodTable::open_with_capacity(&path, 65536).unwrap();
        let coin = make_coin(1000);
        for i in 0..10_000u32 {
            table.insert(&make_outpoint(i), &coin).unwrap();
        }
        let mut i = 0u32;
        bencher.bench_local(|| {
            table.remove(&make_outpoint(i)).unwrap();
            i += 1;
        });
    }
}

// ── StorageHandle (threaded, via with_storage) ─────────────────────────────

mod handle {
    use super::{
        black_box, make_block_hash, make_header, make_outpoint, with_storage, BlockHeight,
        CommitBlockReq, Durability, FlatEngine, Hash256, NewCoin, P2WPKH_SPK, ReqToken, Satoshi,
        TmpDir,
    };

    #[divan::bench]
    fn commit_block_flat(bencher: divan::Bencher) {
        let dir = TmpDir::new("handle-flat");
        let eng = FlatEngine::open(dir.path()).unwrap();
        with_storage(eng, |handle| {
            let mut h = 1u32;
            let mut prev = Hash256::ZERO;
            bencher.bench_local(|| {
                let op = make_outpoint(h);
                let block_hash = make_block_hash(h);
                let spk = P2WPKH_SPK;
                let created = [NewCoin {
                    outpoint: op,
                    value: Satoshi::new(5_000_000_000),
                    script_pubkey: &spk,
                    coinbase: true,
                    height: BlockHeight::new(h),
                }];
                let mut header = make_header(h);
                header.set_prev_block(prev);
                handle
                    .commit_block_borrowed(CommitBlockReq {
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
                h += 1;
            });
        })
        .unwrap();
    }

    #[divan::bench]
    fn lookup_coins_flat(bencher: divan::Bencher) {
        let dir = TmpDir::new("handle-lookup");
        let eng = FlatEngine::open(dir.path()).unwrap();
        with_storage(eng, |handle| {
            let mut prev = Hash256::ZERO;
            for h in 1..=1000u32 {
                let op = make_outpoint(h);
                let block_hash = make_block_hash(h);
                let spk = P2WPKH_SPK;
                let created = [NewCoin {
                    outpoint: op,
                    value: Satoshi::new(5_000_000_000),
                    script_pubkey: &spk,
                    coinbase: true,
                    height: BlockHeight::new(h),
                }];
                let mut header = make_header(h);
                header.set_prev_block(prev);
                handle
                    .commit_block_borrowed(CommitBlockReq {
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
            let target = [make_outpoint(500)];
            let mut out = Vec::new();
            bencher.bench_local(|| {
                out.clear();
                handle
                    .lookup_coins_borrowed(black_box(&target), &mut out)
                    .unwrap();
            });
        })
        .unwrap();
    }
}
