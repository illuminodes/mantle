//! Production UTXO engine — fully disk-backed with bloom filter and LRU cache.

use std::io;
use std::path::Path;

use mantle::collections::{BuildPrehashedHasher, PrehashedMap};
use mantle::primitives::{
    BlockHeader, BlockHeight, Hash256, OutPoint, Satoshi, ScriptPubKey,
};
use mantle_bloom::BloomFilter;
use mantle_consensus::chain_view::{Coin, TipInfo};
use mantle_lru::LruCache;
use mantle_utxo_set::disk_arena::{DiskArena, DiskSpan, DiskTxHandle};
use mantle_utxo_set::tx_index::TxIndex;

use mantle_storage::engine::header_io::HeaderStore;
use mantle_storage::engine::ring_budget::RingBudget;
use mantle_storage::engine::{Engine, EngineError};
use mantle_storage::types::{CommitBlockReq, Durability, LookupResult};
const WRITE_BUFFER_CAP: usize = 100_000;
const LRU_CAPACITY: usize = 12_000_000;
const BLOOM_EXPECTED_ITEMS: usize = 85_000_000;
const BLOOM_FP_RATE: f64 = 0.001;
const TX_INDEX_INITIAL_SLOTS: u64 = 1 << 20;

struct BufferedCoin {
    value: Satoshi,
    script_pubkey: ScriptPubKey,
    height: BlockHeight,
    coinbase: bool,
}

struct TxFlush {
    txid: Hash256,
    span: DiskSpan,
    outputs: Vec<(u32, BufferedCoin)>,
    live: u64,
    height: BlockHeight,
    coinbase: bool,
}

pub struct ProductionEngine {
    arena: DiskArena,
    tx_index: TxIndex,
    bloom: BloomFilter,
    lru: LruCache<DiskTxHandle>,
    ring: ququmatz::IoUring,

    write_buf: PrehashedMap<OutPoint, BufferedCoin>,
    pending_spends: Vec<OutPoint>,

    io_buf: Vec<u8>,
    write_io_buf: Vec<u8>,

    headers: HeaderStore,
}

impl ProductionEngine {
    /// # Errors
    /// Returns `EngineError` if any file I/O fails.
    pub fn open(data_dir: &Path) -> Result<Self, EngineError> {
        std::fs::create_dir_all(data_dir)?;

        let arena_path = data_dir.join("coins.bin");
        let tx_index_path = data_dir.join("tx_index.bin");

        let arena = DiskArena::open(&arena_path)?;
        let tx_index = TxIndex::open_with_capacity(&tx_index_path, TX_INDEX_INITIAL_SLOTS)?;

        let bloom = BloomFilter::with_fp_rate(BLOOM_EXPECTED_ITEMS, BLOOM_FP_RATE);

        let blank_handle = DiskTxHandle {
            span: DiskSpan { base: 0, count: 0 },
            height: BlockHeight::ZERO,
            live: 0,
            coinbase: false,
        };
        let lru = LruCache::new(LRU_CAPACITY, blank_handle);

        let headers = HeaderStore::open(data_dir)?;

        let ring = RingBudget::new(256, 64).build()?;

        let mut engine = Self {
            arena,
            tx_index,
            bloom,
            lru,
            ring,
            write_buf: PrehashedMap::with_capacity_and_hasher(WRITE_BUFFER_CAP, BuildPrehashedHasher),
            pending_spends: Vec::new(),
            io_buf: Vec::new(),
            write_io_buf: Vec::new(),
            headers,
        };
        engine.recover()?;
        Ok(engine)
    }

    fn lookup_handle(&mut self, txid: &Hash256) -> Result<Option<DiskTxHandle>, EngineError> {
        if let Some(h) = self.lru.get(txid.as_bytes()) {
            return Ok(Some(h));
        }
        if !self.bloom.maybe_contains(txid.as_bytes()) {
            return Ok(None);
        }
        let handle = self.tx_index.get(txid)?;
        if let Some(h) = handle {
            self.lru.insert(*txid.as_bytes(), h);
        }
        Ok(handle)
    }

    #[allow(clippy::cast_possible_truncation)]
    fn flush_write_buffer(&mut self) -> Result<(), EngineError> {
        if self.write_buf.is_empty() && self.pending_spends.is_empty() {
            return Ok(());
        }

        // Group buffered coins by txid.
        let mut tx_groups: PrehashedMap<Hash256, Vec<(u32, BufferedCoin)>> =
            PrehashedMap::default();
        for (op, coin) in self.write_buf.drain() {
            tx_groups.entry(op.txid).or_default().push((op.vout, coin));
        }

        let mut flushes: Vec<TxFlush> = Vec::with_capacity(tx_groups.len());

        for (txid, mut outputs) in tx_groups {
            outputs.sort_by_key(|(vout, _)| *vout);
            let max_vout = outputs.last().map_or(0, |(v, _)| *v);
            let count = u16::try_from(max_vout).expect("max_vout fits u16") + 1;
            let span = self.arena.alloc(count);

            let mut live = 0u64;
            let mut height = BlockHeight::ZERO;
            let mut coinbase = false;
            for (vout, coin) in &outputs {
                if *vout < 64 { live |= 1 << vout; }
                height = coin.height;
                coinbase = coin.coinbase;
            }

            flushes.push(TxFlush { txid, span, outputs, live, height, coinbase });
        }

        flushes.sort_by_key(|f| f.span.base);

        self.flush_coins_to_disk(&flushes)?;
        self.process_pending_spends()
    }

    #[allow(clippy::cast_possible_truncation)]
    fn flush_coins_to_disk(&mut self, flushes: &[TxFlush]) -> Result<(), EngineError> {
        // Encode coin data.
        self.io_buf.clear();
        for flush in flushes {
            let span_bytes = usize::from(flush.span.count) * 56;
            let buf_offset = self.io_buf.len();
            self.io_buf.resize(buf_offset + span_bytes, 0u8);
            for (vout, coin) in &flush.outputs {
                let slot_start = buf_offset + usize::try_from(*vout).expect("vout fits usize") * 56;
                let slot_buf: &mut [u8; 56] =
                    (&mut self.io_buf[slot_start..slot_start + 56]).try_into().expect("slot-aligned slice");
                mantle_utxo_set::disk_arena::encode_coin_slot(
                    slot_buf, coin.value, coin.height, coin.coinbase,
                    coin.script_pubkey.as_slice(),
                );
            }
        }

        // Write coins to disk.
        if !flushes.is_empty() {
            use std::os::unix::fs::FileExt;

            let all_contiguous = flushes.windows(2).all(|w| {
                w[0].span.base + u32::from(w[0].span.count) == w[1].span.base
            });

            if all_contiguous {
                let start_offset = u64::from(flushes[0].span.base) * 56;
                self.arena.fd().write_all_at(&self.io_buf, start_offset)?;
            } else {
                use std::os::unix::io::AsRawFd;
                #[allow(clippy::cast_sign_loss)]
                let fd = ququmatz::types::RawFd::from_raw(self.arena.fd().as_raw_fd() as usize);
                let mut submitted = 0u32;
                let mut buf_offset = 0usize;

                for flush in flushes {
                    let span_bytes = usize::from(flush.span.count) * 56;
                    let file_offset = u64::from(flush.span.base) * 56;
                    let sqe = unsafe {
                        ququmatz::Sqe::write_ptr(
                            fd,
                            self.io_buf[buf_offset..].as_ptr(),
                            u32::try_from(span_bytes).expect("span fits u32"),
                            file_offset,
                        )
                    }.user_data(u64::MAX);
                    self.ring.push(sqe)
                        .map_err(|e| EngineError::Io(io::Error::other(format!("{e:?}"))))?;
                    submitted += 1;
                    buf_offset += span_bytes;

                    if submitted >= 200 {
                        self.ring.submit_and_wait(submitted)
                            .map_err(|e| EngineError::Io(io::Error::other(format!("{e:?}"))))?;
                        while self.ring.complete().is_some() {}
                        submitted = 0;
                    }
                }

                if submitted > 0 {
                    self.ring.submit_and_wait(submitted)
                        .map_err(|e| EngineError::Io(io::Error::other(format!("{e:?}"))))?;
                    while self.ring.complete().is_some() {}
                }
            }
        }

        // Insert handles into tx_index, bloom, and LRU.
        let pairs: Vec<(Hash256, DiskTxHandle)> = flushes.iter().map(|f| {
            (f.txid, DiskTxHandle {
                span: f.span,
                height: f.height,
                live: f.live,
                coinbase: f.coinbase,
            })
        }).collect();

        self.tx_index.insert_batch_uring(
            &pairs,
            &mut self.ring,
            &mut self.io_buf,
            &mut self.write_io_buf,
        )?;

        for (txid, handle) in &pairs {
            self.bloom.insert(txid.as_bytes());
            self.lru.insert(*txid.as_bytes(), *handle);
        }

        Ok(())
    }

    fn process_pending_spends(&mut self) -> Result<(), EngineError> {
        let spends: Vec<OutPoint> = self.pending_spends.drain(..).collect();
        for op in spends {
            let Some(mut handle) = self.lookup_handle(&op.txid)? else {
                continue;
            };
            handle.mark_spent(op.vout);
            if handle.is_fully_spent() {
                self.tx_index.remove(&op.txid)?;
                self.lru.remove(op.txid.as_bytes());
                self.arena.free(handle.span);
            } else {
                self.tx_index.update(&op.txid, &handle)?;
                self.lru.insert(*op.txid.as_bytes(), handle);
            }
        }

        Ok(())
    }
}

impl Engine for ProductionEngine {
    fn read_coin(&mut self, op: &OutPoint) -> Result<Option<Coin>, EngineError> {
        if let Some(bc) = self.write_buf.get(op) {
            return Ok(Some(Coin {
                value: bc.value,
                script_pubkey: bc.script_pubkey.clone(),
                height: bc.height,
                coinbase: bc.coinbase,
            }));
        }

        let Some(handle) = self.lookup_handle(&op.txid)? else {
            return Ok(None);
        };
        if !handle.is_unspent(op.vout) {
            return Ok(None);
        }
        self.arena.read_coin(handle.span.base + op.vout).map_err(EngineError::from)
    }

    fn read_coins(
        &mut self,
        ops: &[OutPoint],
        out: &mut Vec<LookupResult>,
    ) -> Result<(), EngineError> {
        for &op in ops {
            let coin = self.read_coin(&op)?;
            out.push(LookupResult { outpoint: op, coin });
        }
        Ok(())
    }

    fn write_block(&mut self, req: &CommitBlockReq) -> Result<(), EngineError> {
        for nc in req.created {
            self.write_buf.insert(nc.outpoint, BufferedCoin {
                value: nc.value,
                script_pubkey: ScriptPubKey::from_slice(nc.script_pubkey),
                height: nc.height,
                coinbase: nc.coinbase,
            });
        }

        for op in req.spent {
            if self.write_buf.remove(op).is_none() {
                self.pending_spends.push(*op);
            }
        }

        if self.write_buf.len() >= WRITE_BUFFER_CAP {
            self.flush_write_buffer()?;
        }

        debug_assert_eq!(req.header.prev_block(), req.prev_hash);
        self.headers.write_block_header(req.height, &req.header, req.hash)?;
        Ok(())
    }

    fn read_header(&self, hash: &Hash256) -> Result<Option<BlockHeader>, EngineError> {
        self.headers.read_header(hash)
    }

    fn read_header_at(&self, h: BlockHeight) -> Result<Option<BlockHeader>, EngineError> {
        self.headers.read_header_at(h)
    }

    fn write_header(&mut self, h: BlockHeight, header: &BlockHeader) -> Result<(), EngineError> {
        self.headers.write_header(h, header)
    }

    fn flush(&mut self, d: Durability) -> Result<(), EngineError> {
        self.flush_write_buffer()?;
        if d == Durability::Synced {
            self.arena.fd().sync_all()?;
            self.tx_index.sync()?;
            self.headers.sync_checkpoint()?;
        }
        Ok(())
    }

    fn recover(&mut self) -> Result<TipInfo, EngineError> {
        self.headers.recover()?;

        // Rebuild bloom filter from tx_index scan.
        self.bloom.clear();
        self.tx_index.for_each(|txid, handle| {
            self.bloom.insert(txid.as_bytes());
            self.lru.insert(*txid.as_bytes(), handle);
        })?;

        Ok(self.headers.tip.clone())
    }

    fn tip(&self) -> TipInfo {
        self.headers.tip.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use mantle::primitives::{BlockTime, BlockVersion, CompactBits, Nonce};
    use mantle_consensus::chain_view::NewCoin;

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new() -> Self {
            use std::time::{SystemTime, UNIX_EPOCH};
            let ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
            let path = std::env::temp_dir()
                .join(format!("mantle-prod-eng-{}-{}", std::process::id(), ns));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path { &self.0 }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    fn make_header(time: u32) -> BlockHeader {
        BlockHeader::new(
            BlockVersion::new(1), Hash256::ZERO, Hash256::ZERO,
            BlockTime::new(time), CompactBits::new(0x1d00_ffff), Nonce::new(0),
        )
    }

    fn make_outpoint(i: u32) -> OutPoint {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&i.to_le_bytes());
        OutPoint { txid: Hash256::from_bytes(b), vout: 0 }
    }

    fn make_block_hash(i: u32) -> Hash256 {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&(i + 10_000).to_le_bytes());
        Hash256::from_bytes(b)
    }

    #[test]
    fn write_and_read_from_buffer() {
        let dir = TmpDir::new();
        let mut eng = ProductionEngine::open(dir.path()).unwrap();
        let op = make_outpoint(1);
        let nc = NewCoin {
            outpoint: op,
            value: Satoshi::new(5_000_000_000),
            script_pubkey: &[0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                             0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                             0x0f, 0x10, 0x11, 0x12, 0x13, 0x14],
            coinbase: true,
            height: BlockHeight::new(1),
        };
        eng.write_block(&CommitBlockReq {
            token: mantle_storage::types::ReqToken(1),
            height: BlockHeight::new(1),
            hash: make_block_hash(1),
            prev_hash: Hash256::ZERO,
            header: make_header(0),
            created: &[nc],
            spent: &[],
            block_bytes: None,
            durability: Durability::Memory,
        }).unwrap();

        let coin = eng.read_coin(&op).unwrap().unwrap();
        assert_eq!(coin.value.to_u64(), 5_000_000_000);
        assert!(coin.coinbase);
    }

    #[test]
    fn flush_moves_to_disk_and_recovers() {
        let dir = TmpDir::new();
        let op = make_outpoint(1);
        {
            let mut eng = ProductionEngine::open(dir.path()).unwrap();
            let nc = NewCoin {
                outpoint: op,
                value: Satoshi::new(1000),
                script_pubkey: &[0x51],
                coinbase: false,
                height: BlockHeight::new(5),
            };
            eng.write_block(&CommitBlockReq {
                token: mantle_storage::types::ReqToken(1),
                height: BlockHeight::new(5),
                hash: make_block_hash(5),
                prev_hash: Hash256::ZERO,
                header: make_header(0),
                created: &[nc],
                spent: &[],
                block_bytes: None,
                durability: Durability::Memory,
            }).unwrap();
            eng.flush(Durability::Synced).unwrap();
        }

        // Reopen — should recover from disk.
        let mut eng = ProductionEngine::open(dir.path()).unwrap();
        let coin = eng.read_coin(&op).unwrap().unwrap();
        assert_eq!(coin.value.to_u64(), 1000);
        assert_eq!(eng.tip().height, BlockHeight::new(5));
    }

    #[test]
    fn spend_elides_buffered_coin() {
        let dir = TmpDir::new();
        let mut eng = ProductionEngine::open(dir.path()).unwrap();
        let op = make_outpoint(1);
        let nc = NewCoin {
            outpoint: op,
            value: Satoshi::new(1000),
            script_pubkey: &[0x51],
            coinbase: false,
            height: BlockHeight::new(1),
        };
        eng.write_block(&CommitBlockReq {
            token: mantle_storage::types::ReqToken(1),
            height: BlockHeight::new(1),
            hash: make_block_hash(1),
            prev_hash: Hash256::ZERO,
            header: make_header(0),
            created: &[nc],
            spent: &[],
            block_bytes: None,
            durability: Durability::Memory,
        }).unwrap();

        let mut h2 = make_header(1);
        h2.set_prev_block(make_block_hash(1));
        eng.write_block(&CommitBlockReq {
            token: mantle_storage::types::ReqToken(2),
            height: BlockHeight::new(2),
            hash: make_block_hash(2),
            prev_hash: make_block_hash(1),
            header: h2,
            created: &[],
            spent: &[op],
            block_bytes: None,
            durability: Durability::Memory,
        }).unwrap();

        assert!(eng.read_coin(&op).unwrap().is_none());
        assert!(eng.write_buf.is_empty());
        assert!(eng.pending_spends.is_empty());
    }

    #[test]
    fn spend_on_disk_after_flush() {
        let dir = TmpDir::new();
        let mut eng = ProductionEngine::open(dir.path()).unwrap();
        let op = make_outpoint(1);
        let nc = NewCoin {
            outpoint: op,
            value: Satoshi::new(2000),
            script_pubkey: &[0x51],
            coinbase: false,
            height: BlockHeight::new(1),
        };
        eng.write_block(&CommitBlockReq {
            token: mantle_storage::types::ReqToken(1),
            height: BlockHeight::new(1),
            hash: make_block_hash(1),
            prev_hash: Hash256::ZERO,
            header: make_header(0),
            created: &[nc],
            spent: &[],
            block_bytes: None,
            durability: Durability::Memory,
        }).unwrap();
        eng.flush_write_buffer().unwrap();

        let mut h2 = make_header(1);
        h2.set_prev_block(make_block_hash(1));
        eng.write_block(&CommitBlockReq {
            token: mantle_storage::types::ReqToken(2),
            height: BlockHeight::new(2),
            hash: make_block_hash(2),
            prev_hash: make_block_hash(1),
            header: h2,
            created: &[],
            spent: &[op],
            block_bytes: None,
            durability: Durability::Memory,
        }).unwrap();
        eng.flush_write_buffer().unwrap();

        assert!(eng.read_coin(&op).unwrap().is_none());
        assert!(eng.arena.free_list_len() > 0);
    }

    #[test]
    fn bloom_filters_misses() {
        let dir = TmpDir::new();
        let mut eng = ProductionEngine::open(dir.path()).unwrap();
        let op = make_outpoint(1);
        let nc = NewCoin {
            outpoint: op,
            value: Satoshi::new(1000),
            script_pubkey: &[0x51],
            coinbase: false,
            height: BlockHeight::new(1),
        };
        eng.write_block(&CommitBlockReq {
            token: mantle_storage::types::ReqToken(1),
            height: BlockHeight::new(1),
            hash: make_block_hash(1),
            prev_hash: Hash256::ZERO,
            header: make_header(0),
            created: &[nc],
            spent: &[],
            block_bytes: None,
            durability: Durability::Memory,
        }).unwrap();
        eng.flush_write_buffer().unwrap();

        // Existing coin found.
        assert!(eng.read_coin(&op).unwrap().is_some());

        // Non-existent txid — bloom should reject quickly.
        let missing = make_outpoint(9999);
        assert!(eng.read_coin(&missing).unwrap().is_none());
    }

    #[test]
    fn header_write_and_read_at() {
        let dir = TmpDir::new();
        let mut eng = ProductionEngine::open(dir.path()).unwrap();
        let header = make_header(12345);
        eng.write_header(BlockHeight::new(0), &header).unwrap();
        let got = eng.read_header_at(BlockHeight::new(0)).unwrap().unwrap();
        assert_eq!(got.time().to_u32(), 12345);
        assert!(eng.read_header_at(BlockHeight::new(999)).unwrap().is_none());
    }

    #[test]
    fn read_coins_batch() {
        let dir = TmpDir::new();
        let mut eng = ProductionEngine::open(dir.path()).unwrap();
        let op1 = make_outpoint(20);
        let op2 = make_outpoint(21);
        let op_miss = make_outpoint(99);
        let nc1 = NewCoin {
            outpoint: op1, value: Satoshi::new(100), script_pubkey: &[0x51],
            coinbase: false, height: BlockHeight::new(1),
        };
        let nc2 = NewCoin {
            outpoint: op2, value: Satoshi::new(200), script_pubkey: &[0x51],
            coinbase: false, height: BlockHeight::new(1),
        };
        eng.write_block(&CommitBlockReq {
            token: mantle_storage::types::ReqToken(1),
            height: BlockHeight::new(1),
            hash: make_block_hash(1),
            prev_hash: Hash256::ZERO,
            header: make_header(0),
            created: &[nc1, nc2],
            spent: &[],
            block_bytes: None,
            durability: Durability::Memory,
        }).unwrap();
        let mut out = Vec::new();
        eng.read_coins(&[op1, op2, op_miss], &mut out).unwrap();
        assert_eq!(out.len(), 3);
        assert!(out[0].coin.is_some());
        assert!(out[1].coin.is_some());
        assert!(out[2].coin.is_none());
    }

    #[test]
    fn flush_scattered_write_via_uring() {
        // Force the io_uring scattered-write path by creating non-contiguous
        // arena spans within a single flush_write_buffer call.
        //
        // Strategy:
        // 1. Block 1: create txid-A (1 output), flush -> arena span [0..1)
        // 2. Block 2: create txid-B (1 output), flush -> arena span [1..2)
        // 3. Block 3: spend txid-A -> frees span [0..1)
        // 4. Block 4: create txid-C (1 output) + txid-D (1 output)
        //    txid-C allocs from free list at base 0, txid-D appends at base 2.
        //    flush_write_buffer sees two flushes with non-contiguous spans
        //    [0..1) and [2..3) -> triggers the uring scatter path.
        let dir = TmpDir::new();
        let mut eng = ProductionEngine::open(dir.path()).unwrap();

        // Block 1: txid-A
        let op_a = make_outpoint(100);
        eng.write_block(&CommitBlockReq {
            token: mantle_storage::types::ReqToken(1),
            height: BlockHeight::new(1),
            hash: make_block_hash(1),
            prev_hash: Hash256::ZERO,
            header: make_header(0),
            created: &[NewCoin {
                outpoint: op_a, value: Satoshi::new(1000), script_pubkey: &[0x51],
                coinbase: true, height: BlockHeight::new(1),
            }],
            spent: &[],
            block_bytes: None,
            durability: Durability::Memory,
        }).unwrap();
        eng.flush_write_buffer().unwrap();

        // Block 2: txid-B
        let op_b = make_outpoint(200);
        let mut h2 = make_header(1);
        h2.set_prev_block(make_block_hash(1));
        eng.write_block(&CommitBlockReq {
            token: mantle_storage::types::ReqToken(2),
            height: BlockHeight::new(2),
            hash: make_block_hash(2),
            prev_hash: make_block_hash(1),
            header: h2,
            created: &[NewCoin {
                outpoint: op_b, value: Satoshi::new(2000), script_pubkey: &[0x51],
                coinbase: true, height: BlockHeight::new(2),
            }],
            spent: &[],
            block_bytes: None,
            durability: Durability::Memory,
        }).unwrap();
        eng.flush_write_buffer().unwrap();

        // Block 3: spend txid-A -> frees its arena span
        let mut h3 = make_header(2);
        h3.set_prev_block(make_block_hash(2));
        eng.write_block(&CommitBlockReq {
            token: mantle_storage::types::ReqToken(3),
            height: BlockHeight::new(3),
            hash: make_block_hash(3),
            prev_hash: make_block_hash(2),
            header: h3,
            created: &[],
            spent: &[op_a],
            block_bytes: None,
            durability: Durability::Memory,
        }).unwrap();
        eng.flush_write_buffer().unwrap();
        assert!(eng.read_coin(&op_a).unwrap().is_none(), "txid-A should be spent");

        // Block 4: create txid-C and txid-D in one block (one flush).
        // txid-C should reuse the freed span from txid-A (base 0).
        // txid-D should allocate a new span after txid-B (base 2).
        // This makes the flush have non-contiguous spans.
        let op_c = make_outpoint(300);
        let op_d = make_outpoint(400);
        let mut h4 = make_header(3);
        h4.set_prev_block(make_block_hash(3));
        eng.write_block(&CommitBlockReq {
            token: mantle_storage::types::ReqToken(4),
            height: BlockHeight::new(4),
            hash: make_block_hash(4),
            prev_hash: make_block_hash(3),
            header: h4,
            created: &[
                NewCoin {
                    outpoint: op_c, value: Satoshi::new(3000), script_pubkey: &[0x51],
                    coinbase: false, height: BlockHeight::new(4),
                },
                NewCoin {
                    outpoint: op_d, value: Satoshi::new(4000), script_pubkey: &[0x51],
                    coinbase: false, height: BlockHeight::new(4),
                },
            ],
            spent: &[],
            block_bytes: None,
            durability: Durability::Memory,
        }).unwrap();
        // This flush should hit the scattered-write (uring) path because
        // the two txids got non-contiguous spans.
        eng.flush_write_buffer().unwrap();

        // Verify both coins are readable from disk.
        let coin_c = eng.read_coin(&op_c).unwrap().expect("txid-C must exist");
        assert_eq!(coin_c.value.to_u64(), 3000);
        let coin_d = eng.read_coin(&op_d).unwrap().expect("txid-D must exist");
        assert_eq!(coin_d.value.to_u64(), 4000);
        // txid-B should still be intact.
        let coin_b = eng.read_coin(&op_b).unwrap().expect("txid-B must exist");
        assert_eq!(coin_b.value.to_u64(), 2000);
    }

    #[test]
    fn flush_empty_is_noop() {
        // Flushing with nothing buffered should succeed without error.
        let dir = TmpDir::new();
        let mut eng = ProductionEngine::open(dir.path()).unwrap();
        eng.flush_write_buffer().unwrap();
    }

    #[test]
    fn flush_multiple_outputs_same_txid() {
        // A single txid with multiple vouts triggers a single TxFlush with
        // a larger span, covering the live-bitfield and multi-slot encoding.
        let dir = TmpDir::new();
        let mut eng = ProductionEngine::open(dir.path()).unwrap();

        let mut txid_bytes = [0u8; 32];
        txid_bytes[0] = 0x42;
        let txid = Hash256::from_bytes(txid_bytes);
        let op0 = OutPoint { txid, vout: 0 };
        let op2 = OutPoint { txid, vout: 2 };

        eng.write_block(&CommitBlockReq {
            token: mantle_storage::types::ReqToken(1),
            height: BlockHeight::new(1),
            hash: make_block_hash(1),
            prev_hash: Hash256::ZERO,
            header: make_header(0),
            created: &[
                NewCoin {
                    outpoint: op0, value: Satoshi::new(100), script_pubkey: &[0x51],
                    coinbase: false, height: BlockHeight::new(1),
                },
                NewCoin {
                    outpoint: op2, value: Satoshi::new(200), script_pubkey: &[0x51],
                    coinbase: false, height: BlockHeight::new(1),
                },
            ],
            spent: &[],
            block_bytes: None,
            durability: Durability::Memory,
        }).unwrap();
        eng.flush_write_buffer().unwrap();

        let c0 = eng.read_coin(&op0).unwrap().expect("vout 0 must exist");
        assert_eq!(c0.value.to_u64(), 100);
        let c2 = eng.read_coin(&op2).unwrap().expect("vout 2 must exist");
        assert_eq!(c2.value.to_u64(), 200);
        // vout 1 was never created.
        let op1 = OutPoint { txid, vout: 1 };
        assert!(eng.read_coin(&op1).unwrap().is_none());
    }
}
