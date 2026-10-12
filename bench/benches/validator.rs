use mantle::primitives::{BlockHeader, BlockHeight, Hash256};
use mantle_consensus::script::ScriptExecutionCache;
use mantle_validator::{HeaderSnapshot, PipelineOpts, ReplayBufs};
use mantle_storage::types::{Durability, ReqToken};
use std::hint::black_box;
use std::sync::OnceLock;

fn main() {
    divan::main();
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const EASY_BITS: mantle::primitives::CompactBits =
    mantle::primitives::CompactBits::new(0x207f_ffff);
const BASE_TIME: u32 = 1_231_006_505;

fn coinbase_tx(height: u32, value: u64) -> mantle::primitives::Transaction {
    use mantle::primitives::*;
    let h = height.to_le_bytes();
    Transaction {
        version: TxVersion::new(1),
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: Hash256::ZERO, vout: u32::MAX },
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

fn mine(mut block: mantle::primitives::Block) -> mantle::primitives::Block {
    use mantle::primitives::*;
    let target = block.header.bits().to_target().expect("valid bits");
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

fn make_block(
    prev_hash: Hash256,
    height: u32,
    txs: Vec<mantle::primitives::Transaction>,
) -> mantle::primitives::Block {
    use mantle::primitives::*;
    use mantle_consensus::merkle::compute_merkle_root;
    let txids: Vec<Hash256> = txs.iter().map(|tx| tx.txid().expect("txid")).collect();
    let merkle_root = compute_merkle_root(&txids).expect("merkle root");
    mine(Block {
        header: BlockHeader::new(
            BlockVersion::new(4), prev_hash, merkle_root,
            BlockTime::new(BASE_TIME + height * 600), EASY_BITS, Nonce::new(0),
        ),
        transactions: txs,
    })
}

fn pre_genesis_header() -> BlockHeader {
    BlockHeader::new(
        mantle::primitives::BlockVersion::new(1), Hash256::ZERO, Hash256::ZERO,
        mantle::primitives::BlockTime::new(BASE_TIME), EASY_BITS,
        mantle::primitives::Nonce::new(0),
    )
}

fn make_snapshot(chain: &[(Hash256, BlockHeader)]) -> HeaderSnapshot {
    let mut entries = Vec::with_capacity(chain.len() + 1);
    entries.push((Hash256::ZERO, pre_genesis_header()));
    entries.extend_from_slice(chain);
    HeaderSnapshot::new(BlockHeight::new(0), entries).expect("snapshot fits u32")
}

struct TmpDir(std::path::PathBuf);
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tmp_storage() -> (mantle_storage::StorageHandle<'static>, TmpDir) {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let path = std::env::temp_dir().join(format!(
        "mantle-validator-bench-{}-{}", std::process::id(), ns
    ));
    std::fs::create_dir_all(&path).expect("create tmp dir");
    let handle = mantle_storage::StorageHandle::open(&path).expect("open");
    (handle, TmpDir(path))
}

fn commit(
    bufs: &mut ReplayBufs,
    storage: &mut mantle_storage::StorageHandle<'static>,
    block: &mantle::primitives::Block,
    height: BlockHeight,
    snap: &HeaderSnapshot,
    cache: &mut ScriptExecutionCache,
    token: u64,
) {
    bufs.validate_and_commit(block, height, storage, snap, PipelineOpts {
        skip_script: true,
        exec_cache: Some(cache),
        durability: Durability::Memory,
        token: ReqToken(token),
        utxo_hash: None,
    }).unwrap_or_else(|e| panic!("commit at height {}: {e}", height.to_u32()));
}

// ── HeaderSnapshot ───────────────────────────────────────────────────────────

mod header_snapshot {
    use super::*;

    fn make_chain(n: usize) -> (Vec<(Hash256, BlockHeader)>, HeaderSnapshot) {
        let mut prev = Hash256::ZERO;
        let mut chain = Vec::with_capacity(n);
        for i in 0..n {
            let h = u32::try_from(i + 1).expect("fits");
            let block = make_block(prev, h, vec![coinbase_tx(h, 50_0000_0000)]);
            let hash = block.header.hash();
            chain.push((hash, block.header));
            prev = hash;
        }
        let snap = make_snapshot(&chain);
        (chain, snap)
    }

    #[divan::bench(args = [100usize, 1000, 10_000])]
    fn construction(bencher: divan::Bencher, n: usize) {
        let mut prev = Hash256::ZERO;
        let mut chain = Vec::with_capacity(n);
        for i in 0..n {
            let h = u32::try_from(i + 1).expect("fits");
            let block = make_block(prev, h, vec![coinbase_tx(h, 50_0000_0000)]);
            let hash = block.header.hash();
            chain.push((hash, block.header));
            prev = hash;
        }
        let mut entries = Vec::with_capacity(chain.len() + 1);
        entries.push((Hash256::ZERO, pre_genesis_header()));
        entries.extend_from_slice(&chain);
        bencher.bench(|| {
            HeaderSnapshot::new(BlockHeight::new(0), black_box(entries.clone()))
                .expect("fits");
        });
    }

    #[divan::bench(args = [100usize, 1000, 10_000])]
    fn get_header_by_hash(bencher: divan::Bencher, n: usize) {
        let (chain, snap) = make_chain(n);
        let target = chain[n / 2].0;
        bencher.bench(|| {
            black_box(snap.get_header(black_box(&target)));
        });
    }

    #[divan::bench(args = [100usize, 1000, 10_000])]
    fn get_header_at(bencher: divan::Bencher, n: usize) {
        let (_chain, snap) = make_chain(n);
        let target = BlockHeight::new(u32::try_from(n / 2).expect("fits"));
        bencher.bench(|| {
            black_box(snap.get_header_at(black_box(target)));
        });
    }

    #[divan::bench(args = [100usize, 1000, 10_000])]
    fn median_time_past(bencher: divan::Bencher, n: usize) {
        let (chain, snap) = make_chain(n);
        let hdr = chain[n / 2].1;
        bencher.bench(|| {
            black_box(snap.median_time_past(black_box(&hdr)));
        });
    }
}

// ── Pipeline: validate_and_commit ────────────────────────────────────────────

mod pipeline {
    use super::*;

    #[divan::bench]
    fn coinbase_only(bencher: divan::Bencher) {
        let block = make_block(Hash256::ZERO, 1, vec![coinbase_tx(1, 50_0000_0000)]);
        let hash = block.header.hash();
        let snap = make_snapshot(&[(hash, block.header)]);
        bencher.bench_local(|| {
            let (mut storage, _dir) = tmp_storage();
            let mut cache = ScriptExecutionCache::new(1024);
            let mut bufs = ReplayBufs::new();
            commit(&mut bufs, &mut storage, black_box(&block),
                   BlockHeight::new(1), &snap, &mut cache, 1);
            storage.shutdown().expect("shutdown");
        });
    }

    #[divan::bench(args = [10usize, 50, 100])]
    fn n_spends(bencher: divan::Bencher, n: usize) {
        use mantle::primitives::*;

        let fund_cb = Transaction {
            version: TxVersion::new(1),
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256::ZERO, vout: u32::MAX },
                script_sig: vec![0x03, 0x01, 0x00, 0x00].into(),
                sequence: Sequence::MAX,
                witness: Witness::empty(),
            }],
            outputs: (0..n).map(|_| TxOut {
                value: Satoshi::new(1000),
                script_pubkey: vec![0x51].into(),
            }).collect(),
            locktime: Locktime::new(0),
        };
        let fund_block = make_block(Hash256::ZERO, 1, vec![fund_cb]);
        let fund_txid = fund_block.transactions[0].txid().expect("txid");
        let fund_hash = fund_block.header.hash();

        let mut prev = fund_hash;
        let mut filler = Vec::new();
        for h in 2..=101u32 {
            let b = make_block(prev, h, vec![coinbase_tx(h, 50_0000_0000)]);
            prev = b.header.hash();
            filler.push(b);
        }

        let spend_txs: Vec<Transaction> =
            std::iter::once(coinbase_tx(102, 50_0000_0000))
                .chain((0..n).map(|i| {
                    Transaction {
                        version: TxVersion::new(1),
                        inputs: vec![TxIn {
                            previous_output: OutPoint {
                                txid: fund_txid, vout: u32::try_from(i).unwrap(),
                            },
                            script_sig: vec![0x51].into(),
                            sequence: Sequence::MAX,
                            witness: Witness::empty(),
                        }],
                        outputs: vec![TxOut {
                            value: Satoshi::new(999),
                            script_pubkey: vec![0x51].into(),
                        }],
                        locktime: Locktime::new(0),
                    }
                }))
                .collect();
        let spend_block = make_block(prev, 102, spend_txs);
        let spend_hash = spend_block.header.hash();

        let mut chain = vec![(fund_hash, fund_block.header)];
        for b in &filler {
            chain.push((b.header.hash(), b.header));
        }
        chain.push((spend_hash, spend_block.header));
        let snap = make_snapshot(&chain);

        bencher.bench_local(|| {
            let (mut storage, _dir) = tmp_storage();
            let mut cache = ScriptExecutionCache::new(1024);
            let mut bufs = ReplayBufs::new();
            commit(&mut bufs, &mut storage, &fund_block,
                   BlockHeight::new(1), &snap, &mut cache, 1);
            for (i, b) in filler.iter().enumerate() {
                commit(&mut bufs, &mut storage, b,
                       BlockHeight::new(2 + u32::try_from(i).unwrap()),
                       &snap, &mut cache, 2 + i as u64);
            }
            commit(&mut bufs, &mut storage, black_box(&spend_block),
                   BlockHeight::new(102), &snap, &mut cache, 102);
            storage.shutdown().expect("shutdown");
        });
    }

    #[divan::bench(args = [10usize, 50, 100])]
    fn chain_k(bencher: divan::Bencher, k: usize) {
        let mut prev = Hash256::ZERO;
        let mut chain = Vec::with_capacity(k);
        let mut blocks = Vec::with_capacity(k);
        for i in 0..k {
            let h = u32::try_from(i + 1).expect("fits");
            let block = make_block(prev, h, vec![coinbase_tx(h, 50_0000_0000)]);
            let hash = block.header.hash();
            chain.push((hash, block.header));
            prev = hash;
            blocks.push(block);
        }
        let snap = make_snapshot(&chain);

        bencher.bench_local(|| {
            let (mut storage, _dir) = tmp_storage();
            let mut cache = ScriptExecutionCache::new(1024);
            let mut bufs = ReplayBufs::new();
            for (i, block) in blocks.iter().enumerate() {
                commit(&mut bufs, &mut storage, black_box(block),
                       BlockHeight::new(u32::try_from(i + 1).expect("fits")),
                       &snap, &mut cache, i as u64);
            }
            storage.shutdown().expect("shutdown");
        });
    }

    #[divan::bench]
    fn bufs_reuse_across_100_blocks(bencher: divan::Bencher) {
        let mut prev = Hash256::ZERO;
        let mut chain = Vec::with_capacity(100);
        let mut blocks = Vec::with_capacity(100);
        for i in 0..100usize {
            let h = u32::try_from(i + 1).expect("fits");
            let block = make_block(prev, h, vec![coinbase_tx(h, 50_0000_0000)]);
            let hash = block.header.hash();
            chain.push((hash, block.header));
            prev = hash;
            blocks.push(block);
        }
        let snap = make_snapshot(&chain);

        bencher.bench_local(|| {
            let (mut storage, _dir) = tmp_storage();
            let mut cache = ScriptExecutionCache::new(1024);
            let mut bufs = ReplayBufs::new();
            for (i, block) in blocks.iter().enumerate() {
                bufs.validate_and_commit(block, BlockHeight::new(u32::try_from(i + 1).unwrap()),
                    &mut storage, &snap, PipelineOpts {
                        skip_script: true,
                        exec_cache: Some(&mut cache),
                        durability: Durability::Memory,
                        token: ReqToken(i as u64),
                        utxo_hash: None,
                    },
                ).expect("validate_and_commit");
            }
            storage.shutdown().expect("shutdown");
        });
    }
}

// ── Ordinals-era real mainnet blocks ─────────────────────────────────────────

mod ordinals {
    use super::*;
    use mantle::codec::Decode;
    use mantle::collections::{BuildPrehashedHasher, PrehashedMap, PrehashedSet};
    use mantle::primitives::{Block, OutPoint, Satoshi, TxHash};
    use mantle_consensus::chain_view::{ChainView, Coin, ConnectScratch, TipInfo};
    use mantle_consensus::error::ChainViewError;
    use mantle_consensus::validation::connect_block;
    use mantle_storage::types::CommitBlockReq;

    struct Fixtures {
        start: u32,
        blocks: Vec<Block>,
        snap: HeaderSnapshot,
    }

    fn load() -> Option<&'static Fixtures> {
        static CELL: OnceLock<Option<Fixtures>> = OnceLock::new();
        CELL.get_or_init(|| {
            let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures")
                .join("ordinals");

            let meta = std::fs::read(dir.join("metadata.bin")).ok()?;
            if meta.len() < 4 {
                return None;
            }
            let start = u32::from_le_bytes([meta[0], meta[1], meta[2], meta[3]]);

            let hdr_bytes = std::fs::read(dir.join("headers.bin")).ok()?;
            if hdr_bytes.len() % 80 != 0 {
                return None;
            }
            let headers: Vec<BlockHeader> = hdr_bytes
                .chunks_exact(80)
                .map(|c| BlockHeader::from_bytes(c.try_into().unwrap()))
                .collect();

            let n = u32::try_from(headers.len()).expect("fits");
            let blocks_dir = dir.join("blocks");
            let mut blocks = Vec::with_capacity(headers.len());
            for h in start..start + n {
                let bytes = std::fs::read(blocks_dir.join(format!("{h:07}.bin"))).ok()?;
                blocks.push(Block::decode(&mut std::io::Cursor::new(&bytes)).ok()?);
            }

            let entries: Vec<(Hash256, BlockHeader)> =
                headers.iter().map(|hdr| (hdr.hash(), *hdr)).collect();
            let snap = HeaderSnapshot::new(BlockHeight::new(start), entries).ok()?;

            Some(Fixtures { start, blocks, snap })
        })
        .as_ref()
    }

    struct DummyView<'a> {
        coins: PrehashedMap<OutPoint, Option<Coin>>,
        snap: &'a HeaderSnapshot,
        tip: TipInfo,
        dummy: Coin,
    }

    impl ChainView for DummyView<'_> {
        fn get_coin(&self, op: &OutPoint) -> Result<Option<&Coin>, ChainViewError> {
            Ok(match self.coins.get(op) {
                Some(Some(c)) => Some(c),
                Some(None) | None => Some(&self.dummy),
            })
        }
        fn get_header(&self, hash: &Hash256) -> Result<Option<BlockHeader>, ChainViewError> {
            Ok(self.snap.get_header(hash))
        }
        fn get_header_at(&self, h: BlockHeight) -> Result<Option<BlockHeader>, ChainViewError> {
            Ok(self.snap.get_header_at(h))
        }
        fn height_of(&self, hash: &Hash256) -> Result<Option<BlockHeight>, ChainViewError> {
            Ok(self.snap.height_of(hash))
        }
        fn median_time_past(
            &self,
            hdr: &BlockHeader,
        ) -> Result<mantle::primitives::BlockTime, ChainViewError> {
            self.snap
                .median_time_past(hdr)
                .ok_or(ChainViewError::NotFound)
        }
        fn tip(&self) -> TipInfo {
            self.tip.clone()
        }
    }

    fn replay_block(
        block: &Block,
        height: BlockHeight,
        storage: &mut mantle_storage::StorageHandle<'static>,
        snap: &HeaderSnapshot,
        cache: &mut ScriptExecutionCache,
        token: u64,
    ) {
        let mut spent_set: PrehashedSet<OutPoint> = PrehashedSet::default();
        for tx in block.transactions.iter().skip(1) {
            for inp in &tx.inputs {
                spent_set.insert(inp.previous_output);
            }
        }
        let mut intra: PrehashedMap<OutPoint, Option<Coin>> =
            PrehashedMap::with_capacity_and_hasher(spent_set.len(), BuildPrehashedHasher);
        let mut scratch = Vec::new();
        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            let Ok(txid) = tx.txid_into(&mut scratch) else {
                continue;
            };
            for (vout, out) in tx.outputs.iter().enumerate() {
                let Ok(v) = u32::try_from(vout) else { continue };
                let op = OutPoint { txid, vout: v };
                if spent_set.contains(&op) {
                    intra.insert(
                        op,
                        Some(Coin {
                            value: out.value,
                            script_pubkey: out.script_pubkey.clone(),
                            height: BlockHeight::ZERO,
                            coinbase: tx_idx == 0,
                        }),
                    );
                }
            }
        }
        let spend_ops: Vec<OutPoint> = block
            .transactions
            .iter()
            .skip(1)
            .flat_map(|tx| tx.inputs.iter())
            .map(|inp| inp.previous_output)
            .filter(|op| !intra.contains_key(op))
            .collect();
        let spend_set: PrehashedSet<OutPoint> = spend_ops.iter().copied().collect();
        let txids: Vec<Hash256> = block
            .transactions
            .iter()
            .map(|tx| tx.txid_into(&mut scratch).expect("txid hash never fails"))
            .collect();
        let bip30_ops: Vec<OutPoint> =
            mantle_consensus::validation::Bip30::new(height, &block.header)
                .probes(block, &txids)
                .filter(|op| !intra.contains_key(op) && !spend_set.contains(op))
                .collect();
        let mut all_ops = spend_ops;
        all_ops.extend_from_slice(&bip30_ops);

        let mut lookup = Vec::new();
        storage
            .send_lookup_borrowed(&all_ops, &mut lookup)
            .expect("send_lookup");
        let hash = block.header.hash();
        let tip = storage.tip();
        storage.recv_lookup().expect("recv_lookup");

        let mut coins: PrehashedMap<OutPoint, Option<Coin>> =
            PrehashedMap::with_capacity_and_hasher(
                all_ops.len() + intra.len(),
                BuildPrehashedHasher,
            );
        for r in lookup.drain(..) {
            coins.insert(r.outpoint, r.coin);
        }
        coins.extend(intra);

        let view = DummyView {
            coins,
            snap,
            tip,
            dummy: Coin {
                value: Satoshi::new(2_100_000_000_000_000),
                script_pubkey: vec![0x51].into(),
                height: BlockHeight::new(0),
                coinbase: false,
            },
        };
        let mut scratch2 = Vec::new();
        let result = connect_block(
            block,
            height,
            &view,
            &mut scratch2,
            &mut ConnectScratch::new(),
            true,
            Some(cache),
            None,
        )
        .unwrap_or_else(|e| panic!("connect_block {}: {e}", height.to_u32()));
        storage
            .commit_block_borrowed(CommitBlockReq {
                token: ReqToken(token),
                height,
                hash,
                prev_hash: block.header.prev_block(),
                header: block.header,
                created: &result.created,
                spent: &result.spent,
                block_bytes: None,
                durability: Durability::Memory,
            })
            .unwrap_or_else(|e| panic!("commit_block {}: {e}", height.to_u32()));
    }

    // Indices into the fixture block array (0 = height 767430).
    // 0   → 767430 first block in range
    // 50  → 767480 light/typical block
    // 179 → 767609 heaviest block (~3.3 MB)
    // 273 → 767703 second heaviest (~3.0 MB)
    // 500 → 767930 mid-range sample
    #[divan::bench(args = [0usize, 50, 179, 273, 500])]
    fn ordinals_block(bencher: divan::Bencher, idx: usize) {
        let Some(fix) = load() else {
            eprintln!("fixtures/ordinals/ not found — skipping");
            return;
        };
        if idx >= fix.blocks.len() {
            eprintln!(
                "fixture index {idx} out of range ({} blocks)",
                fix.blocks.len()
            );
            return;
        }
        let block = &fix.blocks[idx];
        let height = BlockHeight::new(fix.start + u32::try_from(idx).expect("fits"));

        bencher.bench_local(|| {
            let (mut storage, _dir) = tmp_storage();
            let mut cache = ScriptExecutionCache::new(64 * 1024);
            replay_block(
                black_box(block),
                height,
                &mut storage,
                &fix.snap,
                &mut cache,
                1,
            );
            storage.shutdown().expect("shutdown");
        });
    }
}
