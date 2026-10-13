//! Shared helpers for loading mainnet fixture blocks and replaying them.
//!
//! Included into binaries via `#[path = "fixtures_common.rs"] mod fixtures_common;`.
#![allow(dead_code)]
#![allow(clippy::cast_precision_loss)]

use std::path::{Path, PathBuf};

use mantle::codec::Decode;
use mantle::collections::{BuildPrehashedHasher, PrehashedMap, PrehashedSet};
use mantle::primitives::{
    Block, BlockHeader, BlockHeight, BlockRef, BlockTime, Hash256, OutPoint, Satoshi,
    TransactionRef, TxHash,
};
use mantle_consensus::chain_view::{ChainView, Coin, ConnectScratch, TipInfo};
use mantle_consensus::error::ChainViewError;
use mantle_consensus::validation::{Bip30, connect_block};
use mantle_storage::StorageHandle;
use mantle_storage::types::{CommitBlockReq, Durability, LookupResult, ReqToken};
use mantle_validator::prefetched_view::HeaderSnapshot;

// ── representative sample indices ────────────────────────────────────────────

/// Offsets from `start_height` that cover the ordinals fixture range:
/// tiny (near-empty), light, mid, heavy, and the heaviest block.
/// Used by perf and dhat drivers to avoid replaying all 1001 blocks.
pub const ORDINALS_SAMPLE_OFFSETS: &[u32] = &[568, 50, 119, 273, 179];

// ── paths ─────────────────────────────────────────────────────────────────────

pub fn fixtures_dir(preset: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(preset)
}

// ── fixture loading ───────────────────────────────────────────────────────────

pub fn load_metadata(fixtures: &Path) -> u32 {
    let path = fixtures.join("metadata.bin");
    match std::fs::read(&path) {
        Ok(b) if b.len() >= 4 => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        _ => 1,
    }
}

pub fn load_headers(fixtures: &Path) -> Vec<BlockHeader> {
    let bytes = std::fs::read(fixtures.join("headers.bin"))
        .expect("headers.bin not found — run fetch-fixtures first");
    assert!(
        bytes.len().is_multiple_of(80),
        "headers.bin size not a multiple of 80"
    );
    bytes
        .chunks_exact(80)
        .map(|chunk| BlockHeader::from_bytes(chunk.try_into().expect("chunk is 80 bytes")))
        .collect()
}

pub fn load_block(fixtures: &Path, height: u32) -> Block {
    let path = fixtures.join("blocks").join(format!("{height:07}.bin"));
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|_| panic!("{} not found — run fetch-fixtures first", path.display()));
    Block::decode(&mut std::io::Cursor::new(&bytes))
        .unwrap_or_else(|e| panic!("decode block {height}: {e}"))
}

pub fn load_block_bytes(fixtures: &Path, height: u32) -> Vec<u8> {
    let path = fixtures.join("blocks").join(format!("{height:07}.bin"));
    std::fs::read(&path)
        .unwrap_or_else(|_| panic!("{} not found — run fetch-fixtures first", path.display()))
}

pub fn load_all_blocks(fixtures: &Path, start: u32, end: u32) -> Vec<Block> {
    (start..=end).map(|h| load_block(fixtures, h)).collect()
}

// ── HeaderSnapshot construction ───────────────────────────────────────────────

pub fn make_snapshot_from_genesis(headers: &[BlockHeader]) -> HeaderSnapshot {
    let mut entries: Vec<(Hash256, BlockHeader)> = Vec::with_capacity(headers.len() + 1);
    let genesis_hash = headers[0].prev_block();
    entries.push((genesis_hash, headers[0]));
    for hdr in headers {
        entries.push((hdr.hash(), *hdr));
    }
    HeaderSnapshot::new(BlockHeight::new(0), entries).expect("snapshot fits u32")
}

pub fn make_snapshot_mid_chain(headers: &[BlockHeader], start: u32) -> HeaderSnapshot {
    let entries: Vec<(Hash256, BlockHeader)> =
        headers.iter().map(|hdr| (hdr.hash(), *hdr)).collect();
    HeaderSnapshot::new(BlockHeight::new(start), entries).expect("snapshot fits u32")
}

pub fn make_snapshot(headers: &[BlockHeader], start: u32) -> HeaderSnapshot {
    if start == 1 {
        make_snapshot_from_genesis(headers)
    } else {
        make_snapshot_mid_chain(headers, start)
    }
}

pub fn headers_from_blocks(dir: &Path, start: u32, end: u32) -> Vec<BlockHeader> {
    (start..=end)
        .map(|h| {
            let path = dir.join("blocks").join(format!("{h:07}.bin"));
            let bytes =
                std::fs::read(&path).unwrap_or_else(|_| panic!("{} not found", path.display()));
            BlockHeader::from_bytes(
                bytes[..80]
                    .try_into()
                    .expect("block file is at least 80 bytes"),
            )
        })
        .collect()
}

// ── BenchView ────────────────────────────────────────────────────────────────

/// `ChainView` that falls back to a dummy mature coin for unknown outpoints.
/// Used when replaying mid-chain blocks without the full historical UTXO set.
pub struct BenchView<'a> {
    coins: &'a PrehashedMap<OutPoint, Option<Coin>>,
    headers: &'a HeaderSnapshot,
    tip: TipInfo,
    dummy_on_miss: bool,
    dummy: Coin,
}

impl<'a> BenchView<'a> {
    pub fn new(
        coins: &'a PrehashedMap<OutPoint, Option<Coin>>,
        headers: &'a HeaderSnapshot,
        tip: TipInfo,
        dummy_on_miss: bool,
    ) -> Self {
        Self {
            coins,
            headers,
            tip,
            dummy_on_miss,
            dummy: Coin {
                value: Satoshi::new(2_100_000_000_000_000),
                script_pubkey: vec![0x51].into(),
                height: BlockHeight::new(0),
                coinbase: false,
            },
        }
    }
}

impl ChainView for BenchView<'_> {
    fn get_coin(&self, outpoint: &OutPoint) -> Result<Option<&Coin>, ChainViewError> {
        match self.coins.get(outpoint) {
            Some(Some(c)) => Ok(Some(c)),
            Some(None) | None if self.dummy_on_miss => Ok(Some(&self.dummy)),
            Some(None) => Ok(None),
            None => Err(ChainViewError::NotFound),
        }
    }

    fn get_header(&self, hash: &Hash256) -> Result<Option<BlockHeader>, ChainViewError> {
        Ok(self.headers.get_header(hash))
    }

    fn get_header_at(&self, height: BlockHeight) -> Result<Option<BlockHeader>, ChainViewError> {
        Ok(self.headers.get_header_at(height))
    }

    fn height_of(&self, hash: &Hash256) -> Result<Option<BlockHeight>, ChainViewError> {
        Ok(self.headers.height_of(hash))
    }

    fn median_time_past(&self, header: &BlockHeader) -> Result<BlockTime, ChainViewError> {
        self.headers
            .median_time_past(header)
            .ok_or(ChainViewError::NotFound)
    }

    fn tip(&self) -> TipInfo {
        self.tip.clone()
    }
}

// ── replay_block ──────────────────────────────────────────────────────────────

pub fn replay_block(
    block: &Block,
    height: BlockHeight,
    storage: &mut StorageHandle<'static>,
    snap: &HeaderSnapshot,
    token: u64,
    dummy_on_miss: bool,
) {
    use mantle::primitives::TxHash as _;

    let mut spent_set: PrehashedSet<OutPoint> = PrehashedSet::default();
    for tx in block.transactions.iter().skip(1) {
        for inp in &tx.inputs {
            spent_set.insert(inp.previous_output);
        }
    }

    let mut intra: PrehashedMap<OutPoint, Option<Coin>> =
        PrehashedMap::with_capacity_and_hasher(spent_set.len(), BuildPrehashedHasher);
    let mut scratch = Vec::new();
    for (tx_index, tx) in block.transactions.iter().enumerate() {
        let Ok(txid) = tx.txid_into(&mut scratch) else {
            continue;
        };
        for (vout, output) in tx.outputs.iter().enumerate() {
            let Ok(vout_u32) = u32::try_from(vout) else {
                continue;
            };
            let op = OutPoint {
                txid,
                vout: vout_u32,
            };
            if spent_set.contains(&op) {
                intra.insert(
                    op,
                    Some(Coin {
                        value: output.value,
                        script_pubkey: output.script_pubkey.clone(),
                        height: BlockHeight::ZERO,
                        coinbase: tx_index == 0,
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

    let spend_op_set: PrehashedSet<OutPoint> = spend_ops.iter().copied().collect();
    let txids: Vec<Hash256> = block
        .transactions
        .iter()
        .map(|tx| tx.txid_into(&mut scratch).expect("txid hash never fails"))
        .collect();
    let bip30_ops: Vec<OutPoint> = Bip30::new(height, &block.header)
        .probes(block, &txids)
        .filter(|op| !intra.contains_key(op) && !spend_op_set.contains(op))
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
        PrehashedMap::with_capacity_and_hasher(all_ops.len() + intra.len(), BuildPrehashedHasher);
    for r in lookup.drain(..) {
        coins.insert(r.outpoint, r.coin);
    }
    coins.extend(intra);

    let view = BenchView::new(&coins, snap, tip, dummy_on_miss);

    let mut scratch2 = Vec::new();
    let result = connect_block(
        block,
        height,
        &view,
        &mut scratch2,
        &mut ConnectScratch::new(),
        &mut mantle_consensus::validation::SkippedScripts,
        None,
    )
    .unwrap_or_else(|e| panic!("connect_block at height {}: {e}", height.to_u32()));

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
        .unwrap_or_else(|e| panic!("commit_block at height {}: {e}", height.to_u32()));
}

// ── replay_block_ref (zero-copy / wire-bytes path) ───────────────────────────

/// Replay a block via `BlockRef` over the wire bytes — no `Block::decode`,
/// no per-tx materialisation, txids hashed once over `non_witness_raw`.
///
/// `wire` is the raw block bytes (BIP144 wire form). `arena` is a caller-owned
/// scratch buffer that holds non-witness preimages for any segwit txs in the
/// block; reuse it across calls so its capacity amortises.
pub fn replay_block_ref(
    wire: &[u8],
    height: BlockHeight,
    storage: &mut StorageHandle<'static>,
    snap: &HeaderSnapshot,
    token: u64,
    dummy_on_miss: bool,
    arena: &mut Vec<u8>,
) {
    let mut txs_buf = Vec::new();
    let block_ref = BlockRef::decode_with_arena(wire, arena, &mut txs_buf)
        .unwrap_or_else(|e| panic!("BlockRef decode at height {}: {e}", height.to_u32()));

    let (txids, intra, all_ops) = build_ref_outpoints(&block_ref, height);

    let mut lookup = Vec::new();
    storage
        .send_lookup_borrowed(&all_ops, &mut lookup)
        .expect("send_lookup");
    let hash = block_ref.header.hash();
    let prev_hash = block_ref.header.prev_block();
    let tip = storage.tip();
    storage.recv_lookup().expect("recv_lookup");

    let mut coins: PrehashedMap<OutPoint, Option<Coin>> =
        PrehashedMap::with_capacity_and_hasher(all_ops.len() + intra.len(), BuildPrehashedHasher);
    for r in lookup.drain(..) {
        coins.insert(r.outpoint, r.coin);
    }
    coins.extend(intra);

    let view = BenchView::new(&coins, snap, tip, dummy_on_miss);
    let mut scratch = Vec::new();
    let result = connect_block(
        &block_ref,
        height,
        &view,
        &mut scratch,
        &mut ConnectScratch::new(),
        &mut mantle_consensus::validation::SkippedScripts,
        Some(&txids),
    )
    .unwrap_or_else(|e| panic!("connect_block at height {}: {e}", height.to_u32()));

    storage
        .commit_block_borrowed(CommitBlockReq {
            token: ReqToken(token),
            height,
            hash,
            prev_hash,
            header: block_ref.header,
            created: &result.created,
            spent: &result.spent,
            block_bytes: None,
            durability: Durability::Memory,
        })
        .unwrap_or_else(|e| panic!("commit_block at height {}: {e}", height.to_u32()));
}

fn build_ref_outpoints(
    block_ref: &BlockRef<'_, '_>,
    height: BlockHeight,
) -> (
    Vec<Hash256>,
    PrehashedMap<OutPoint, Option<Coin>>,
    Vec<OutPoint>,
) {
    let tx_count = block_ref.tx_count();
    let total_inputs: usize = block_ref
        .transactions()
        .skip(1)
        .map(mantle::primitives::TransactionRef::input_count)
        .sum();

    let mut hash_scratch = Vec::new();
    let mut txids: Vec<Hash256> = Vec::with_capacity(tx_count);
    for tx in block_ref.transactions() {
        txids.push(
            tx.txid_into(&mut hash_scratch)
                .expect("txid hash never fails"),
        );
    }

    let mut spent_set: PrehashedSet<OutPoint> =
        PrehashedSet::with_capacity_and_hasher(total_inputs, BuildPrehashedHasher);
    for tx in block_ref.transactions().skip(1) {
        for i in tx.inputs().flatten() {
            spent_set.insert(i.previous_output);
        }
    }

    let mut intra: PrehashedMap<OutPoint, Option<Coin>> =
        PrehashedMap::with_capacity_and_hasher(spent_set.len(), BuildPrehashedHasher);
    for (tx_index, tx) in block_ref.transactions().enumerate() {
        let txid = txids[tx_index];
        for (vout, output) in tx.outputs().enumerate() {
            let Ok(out) = output else { continue };
            let Ok(vout_u32) = u32::try_from(vout) else {
                continue;
            };
            let op = OutPoint {
                txid,
                vout: vout_u32,
            };
            if spent_set.contains(&op) {
                intra.insert(
                    op,
                    Some(Coin {
                        value: out.value,
                        script_pubkey: out.script_pubkey.into(),
                        height: BlockHeight::ZERO,
                        coinbase: tx_index == 0,
                    }),
                );
            }
        }
    }

    let mut spend_ops: Vec<OutPoint> = Vec::with_capacity(total_inputs);
    for tx in block_ref.transactions().skip(1) {
        for inp in tx.inputs() {
            let Ok(i) = inp else { continue };
            if !intra.contains_key(&i.previous_output) {
                spend_ops.push(i.previous_output);
            }
        }
    }

    let mut spend_op_set: PrehashedSet<OutPoint> =
        PrehashedSet::with_capacity_and_hasher(spend_ops.len(), BuildPrehashedHasher);
    spend_op_set.extend(spend_ops.iter().copied());
    let mut bip30_ops: Vec<OutPoint> = Vec::with_capacity(tx_count);
    for op in Bip30::new(height, &block_ref.header).probes(block_ref, &txids) {
        if !intra.contains_key(&op) && !spend_op_set.contains(&op) {
            bip30_ops.push(op);
        }
    }

    let mut all_ops = spend_ops;
    all_ops.extend_from_slice(&bip30_ops);
    (txids, intra, all_ops)
}

// ── reusable buffers for the bench replay loop ──────────────────────────────

pub struct BenchReplayBufs {
    pub spent_set: PrehashedSet<OutPoint>,
    pub txids: Vec<Hash256>,
    pub hash_scratch: Vec<u8>,
    pub intra: PrehashedMap<OutPoint, Option<Coin>>,
    pub spend_ops: Vec<OutPoint>,
    pub spend_op_set: PrehashedSet<OutPoint>,
    pub bip30_ops: Vec<OutPoint>,
    pub lookup: Vec<LookupResult>,
    pub coins: PrehashedMap<OutPoint, Option<Coin>>,
    pub txid_scratch: Vec<u8>,
    pub connect_scratch: ConnectScratch,
}

impl BenchReplayBufs {
    pub fn new() -> Self {
        Self {
            spent_set: PrehashedSet::with_hasher(BuildPrehashedHasher),
            txids: Vec::new(),
            hash_scratch: Vec::new(),
            intra: PrehashedMap::with_hasher(BuildPrehashedHasher),
            spend_ops: Vec::new(),
            spend_op_set: PrehashedSet::with_hasher(BuildPrehashedHasher),
            bip30_ops: Vec::new(),
            lookup: Vec::new(),
            coins: PrehashedMap::with_hasher(BuildPrehashedHasher),
            txid_scratch: Vec::new(),
            connect_scratch: ConnectScratch::new(),
        }
    }

    fn clear(&mut self) {
        self.spent_set.clear();
        self.txids.clear();
        self.intra.clear();
        self.spend_ops.clear();
        self.spend_op_set.clear();
        self.bip30_ops.clear();
        self.coins.clear();
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn replay_block_ref_reusing(
    wire: &[u8],
    height: BlockHeight,
    storage: &mut StorageHandle<'static>,
    snap: &HeaderSnapshot,
    token: u64,
    dummy_on_miss: bool,
    durability: Durability,
    arena: &mut Vec<u8>,
    bufs: &mut BenchReplayBufs,
    txs_scratch: &mut Vec<TransactionRef<'static, 'static>>,
) {
    bufs.clear();

    // SAFETY: txs_scratch is cleared inside decode_with_arena on entry.
    // Between calls the vec is empty — no dangling lifetime references.
    // TransactionRef layout is identical for all lifetimes.
    let txs_buf: &mut Vec<TransactionRef<'_, '_>> =
        unsafe { &mut *std::ptr::from_mut(txs_scratch).cast::<Vec<TransactionRef<'_, '_>>>() };
    let block_ref = BlockRef::decode_with_arena(wire, arena, txs_buf)
        .unwrap_or_else(|e| panic!("BlockRef decode at height {}: {e}", height.to_u32()));

    let tx_count = block_ref.tx_count();
    let total_inputs: usize = block_ref
        .transactions()
        .skip(1)
        .map(mantle::primitives::TransactionRef::input_count)
        .sum();

    for tx in block_ref.transactions() {
        bufs.txids.push(
            tx.txid_into(&mut bufs.hash_scratch)
                .expect("txid hash never fails"),
        );
    }

    bufs.spent_set.reserve(total_inputs);
    for tx in block_ref.transactions().skip(1) {
        for i in tx.inputs().flatten() {
            bufs.spent_set.insert(i.previous_output);
        }
    }

    for (tx_index, tx) in block_ref.transactions().enumerate() {
        let txid = bufs.txids[tx_index];
        for (vout, output) in tx.outputs().enumerate() {
            let Ok(out) = output else { continue };
            let Ok(vout_u32) = u32::try_from(vout) else {
                continue;
            };
            let op = OutPoint {
                txid,
                vout: vout_u32,
            };
            if bufs.spent_set.contains(&op) {
                bufs.intra.insert(
                    op,
                    Some(Coin {
                        value: out.value,
                        script_pubkey: out.script_pubkey.into(),
                        height: BlockHeight::ZERO,
                        coinbase: tx_index == 0,
                    }),
                );
            }
        }
    }

    bufs.spend_ops.reserve(total_inputs);
    for tx in block_ref.transactions().skip(1) {
        for inp in tx.inputs() {
            let Ok(i) = inp else { continue };
            if !bufs.intra.contains_key(&i.previous_output) {
                bufs.spend_ops.push(i.previous_output);
            }
        }
    }

    bufs.spend_op_set.reserve(bufs.spend_ops.len());
    bufs.spend_op_set.extend(bufs.spend_ops.iter().copied());
    bufs.bip30_ops.reserve(tx_count);
    for op in Bip30::new(height, &block_ref.header).probes(&block_ref, &bufs.txids) {
        if !bufs.intra.contains_key(&op) && !bufs.spend_op_set.contains(&op) {
            bufs.bip30_ops.push(op);
        }
    }

    bufs.spend_ops.extend_from_slice(&bufs.bip30_ops);

    storage
        .send_lookup_borrowed(&bufs.spend_ops, &mut bufs.lookup)
        .expect("send_lookup");
    let hash = block_ref.header.hash();
    let prev_hash = block_ref.header.prev_block();
    let tip = storage.tip();
    storage.recv_lookup().expect("recv_lookup");

    bufs.coins.reserve(bufs.spend_ops.len() + bufs.intra.len());
    for r in bufs.lookup.drain(..) {
        bufs.coins.insert(r.outpoint, r.coin);
    }
    for (k, v) in bufs.intra.drain() {
        bufs.coins.insert(k, v);
    }

    let view = BenchView::new(&bufs.coins, snap, tip, dummy_on_miss);
    let result = connect_block(
        &block_ref,
        height,
        &view,
        &mut bufs.hash_scratch,
        &mut bufs.connect_scratch,
        &mut mantle_consensus::validation::SkippedScripts,
        Some(&bufs.txids),
    )
    .unwrap_or_else(|e| panic!("connect_block at height {}: {e}", height.to_u32()));

    storage
        .commit_block_borrowed(CommitBlockReq {
            token: ReqToken(token),
            height,
            hash,
            prev_hash,
            header: block_ref.header,
            created: &result.created,
            spent: &result.spent,
            block_bytes: None,
            durability,
        })
        .unwrap_or_else(|e| panic!("commit_block at height {}: {e}", height.to_u32()));
    bufs.connect_scratch.reclaim(result);
}

// ── tmp storage ───────────────────────────────────────────────────────────────

pub struct TmpDir(pub PathBuf);
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn tmp_storage(tag: &str) -> (StorageHandle<'static>, TmpDir) {
    tmp_storage_engine(tag, false)
}

pub fn tmp_storage_robin_hood(tag: &str) -> (StorageHandle<'static>, TmpDir) {
    tmp_storage_engine(tag, true)
}

fn tmp_storage_engine(tag: &str, robin_hood: bool) -> (StorageHandle<'static>, TmpDir) {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let path = std::env::temp_dir().join(format!("mantle-{tag}-{}-{ns}", std::process::id()));
    std::fs::create_dir_all(&path).expect("create tmp dir");
    let handle = if robin_hood {
        StorageHandle::open_robin_hood(&path).expect("StorageHandle::open_robin_hood")
    } else {
        StorageHandle::open(&path).expect("StorageHandle::open")
    };
    (handle, TmpDir(path))
}
