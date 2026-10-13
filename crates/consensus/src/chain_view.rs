use mantle::collections::PrehashedMap;
use mantle::primitives::{
    BlockHeader, BlockHeight, BlockTime, Hash256, OutPoint, Satoshi, ScriptPubKey,
};

use crate::error::ChainViewError;

// ── Coin ──────────────────────────────────────────────────────────────────────

/// A spendable output in the UTXO set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coin {
    pub value: Satoshi,
    pub script_pubkey: ScriptPubKey,
    /// Height at which this output was created.
    pub height: BlockHeight,
    /// True if this output was created by a coinbase transaction.
    pub coinbase: bool,
}

// ── ConnectResult ─────────────────────────────────────────────────────────────

/// A new unspent output created by a connected block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCoin<'a> {
    pub outpoint: OutPoint,
    pub value: Satoshi,
    pub script_pubkey: &'a [u8],
    pub coinbase: bool,
    pub height: BlockHeight,
}

/// Output of [`connect_block`](crate::validation::connect_block): the UTXO
/// delta and fee total needed by the storage layer to apply the block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectResult<'a> {
    /// Outputs created by this block (to insert into the UTXO set).
    pub created: Vec<NewCoin<'a>>,
    /// Inputs consumed by this block (to remove from the UTXO set).
    pub spent: Vec<OutPoint>,
    /// Total fees collected (sum of inputs minus sum of outputs, excluding coinbase).
    pub fees: Satoshi,
}

/// Scratch buffers reused across [`connect_block`](crate::validation::connect_block)
/// calls to eliminate per-block allocations for the spent-outpoints,
/// created-coins, and per-tx outpoint-lookup vecs.
#[derive(Default)]
pub struct ConnectScratch {
    /// Reused as the `spent` vec; swapped into [`ConnectResult`] each call.
    pub(crate) spent: Vec<OutPoint>,
    /// Reused across the per-tx input-lookup loop within each block.
    pub(crate) outpoints: Vec<OutPoint>,
    /// Backing buffer for `created` in [`ConnectResult`]. Stored as `'static`
    /// between calls; transmuted to `'blk` inside `connect_block`. The layout
    /// of `NewCoin` is identical for all lifetimes (it's just a `&[u8]`
    /// pointer+len), so this is safe as long as we clear before returning.
    pub(crate) created: Vec<NewCoin<'static>>,
    /// Reused for per-tx coin lookups within each block.
    pub(crate) coins: Vec<Option<&'static Coin>>,
    /// Same-block created and spent outpoints for the block being connected.
    pub(crate) in_block: crate::validation::block_coins::InBlockCoins,
}

impl ConnectScratch {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return consumed `ConnectResult` vecs so their capacity is reused on
    /// the next `connect_block` call. Call this after `commit_block` has
    /// finished with the result's data.
    pub fn reclaim(&mut self, mut result: ConnectResult<'_>) {
        result.created.clear();
        // SAFETY: the vec is empty — no elements carry the `'blk` lifetime.
        self.created = unsafe {
            std::mem::transmute::<Vec<NewCoin<'_>>, Vec<NewCoin<'static>>>(result.created)
        };
        self.spent = result.spent;
        self.spent.clear();
    }
}

// ── TipInfo ───────────────────────────────────────────────────────────────────

/// Snapshot of the chain tip as seen by a `ChainView`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TipInfo {
    pub hash: Hash256,
    pub height: BlockHeight,
}

// ── ChainView ─────────────────────────────────────────────────────────────────

/// Read-only view into chain state required by the validator.
///
/// The production implementation wraps the storage-thread ring-buffer API.
/// Test implementations (`MemoryChainView`) satisfy the trait in-process with
/// no I/O. The validator is generic over this trait so neither side needs the
/// other to be present at compile time.
pub trait ChainView {
    /// Look up a single UTXO by outpoint.
    ///
    /// Returns a borrow into the view's backing store. No `Coin` is cloned.
    ///
    /// # Errors
    /// Returns `Err` on storage failure. Returns `Ok(None)` if the coin does
    /// not exist (spent or never created).
    fn get_coin(&self, outpoint: &OutPoint) -> Result<Option<&Coin>, ChainViewError>;

    /// Batched UTXO lookup — writes borrowed coins into a caller-owned vec.
    ///
    /// `out` is cleared on entry; capacity is preserved so a hot loop can
    /// reuse one buffer across thousands of calls.
    ///
    /// # Errors
    /// Returns `Err` on any storage failure.
    fn get_coins_into<'a>(
        &'a self,
        outpoints: &[OutPoint],
        out: &mut Vec<Option<&'a Coin>>,
    ) -> Result<(), ChainViewError> {
        out.clear();
        out.reserve(outpoints.len());
        for op in outpoints {
            out.push(self.get_coin(op)?);
        }
        Ok(())
    }

    /// Header by hash.
    ///
    /// # Errors
    /// Returns `Err` on storage failure. Returns `Ok(None)` if not found.
    fn get_header(&self, hash: &Hash256) -> Result<Option<BlockHeader>, ChainViewError>;

    /// Header by height on the canonical chain.
    ///
    /// # Errors
    /// Returns `Err` on storage failure. Returns `Ok(None)` if height exceeds
    /// current tip or is otherwise absent.
    fn get_header_at(&self, height: BlockHeight) -> Result<Option<BlockHeader>, ChainViewError>;

    /// Height of a header on the canonical chain, by hash.
    ///
    /// This is the inverse of `get_header_at`. Implementations are expected
    /// to satisfy this in O(1) — Stage 2 contextual validation calls it
    /// for every block, so a linear scan would make IBD quadratic.
    ///
    /// # Errors
    /// Returns `Err` on storage failure. Returns `Ok(None)` if no header
    /// with that hash exists in the canonical chain.
    fn height_of(&self, hash: &Hash256) -> Result<Option<BlockHeight>, ChainViewError>;

    /// Median-time-past for BIP113: median of the timestamps of the 11 blocks
    /// immediately preceding `header` (or fewer if near genesis).
    ///
    /// # Errors
    /// Returns `Err` if headers cannot be retrieved.
    fn median_time_past(&self, header: &BlockHeader) -> Result<BlockTime, ChainViewError>;

    /// Current tip of the chain as seen by this view.
    fn tip(&self) -> TipInfo;
}

// ── MemoryChainView ───────────────────────────────────────────────────────────

/// In-memory `ChainView` for tests and fuzz harnesses.
///
/// Headers are stored in a `Vec` indexed by height (canonical chain only).
/// UTXOs are stored in a `HashMap`. Neither grows without bound in tests.
///
/// Use `with_height_base` to start the chain at an arbitrary height so tests
/// that exercise height-gated rules (BIP34, version floors) don't need to push
/// hundreds of thousands of dummy headers.
#[derive(Debug, Default)]
pub struct MemoryChainView {
    /// The block height of `headers[0]`.
    height_base: BlockHeight,
    /// Headers in insertion order. `headers[0]` is at height `height_base`.
    headers: Vec<BlockHeader>,
    /// Hash → absolute height on the canonical chain.
    header_index: PrehashedMap<Hash256, BlockHeight>,
    /// Live UTXO set.
    utxos: PrehashedMap<OutPoint, Coin>,
}

impl MemoryChainView {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a view whose first pushed header will be treated as being at
    /// `base_height`. Use this in tests that need to exercise height-gated
    /// rules without building a full-length chain.
    #[must_use]
    pub fn with_height_base(base_height: BlockHeight) -> Self {
        Self {
            height_base: base_height,
            ..Self::default()
        }
    }

    /// Append a header to the canonical chain. Must be called in order.
    ///
    /// # Panics
    /// Panics if the chain grows beyond `u32::MAX` headers (impossible in practice).
    pub fn push_header(&mut self, header: BlockHeader) {
        let height = BlockHeight::new(
            self.height_base
                .to_u32()
                .checked_add(u32::try_from(self.headers.len()).expect("chain height exceeds u32"))
                .expect("chain height exceeds u32"),
        );
        let hash = header.hash();
        self.header_index.insert(hash, height);
        self.headers.push(header);
    }

    /// Insert a UTXO into the set.
    pub fn insert_coin(&mut self, outpoint: OutPoint, coin: Coin) {
        self.utxos.insert(outpoint, coin);
    }

    /// Remove a UTXO from the set (spend it).
    pub fn spend_coin(&mut self, outpoint: &OutPoint) -> Option<Coin> {
        self.utxos.remove(outpoint)
    }
}

impl ChainView for MemoryChainView {
    fn get_coin(&self, outpoint: &OutPoint) -> Result<Option<&Coin>, ChainViewError> {
        Ok(self.utxos.get(outpoint))
    }

    fn get_header(&self, hash: &Hash256) -> Result<Option<BlockHeader>, ChainViewError> {
        Ok(self
            .header_index
            .get(hash)
            .and_then(|h| h.to_u32().checked_sub(self.height_base.to_u32()))
            .and_then(|i| self.headers.get(i as usize))
            .copied())
    }

    fn get_header_at(&self, height: BlockHeight) -> Result<Option<BlockHeader>, ChainViewError> {
        let idx = height
            .to_u32()
            .checked_sub(self.height_base.to_u32())
            .map(|i| i as usize);
        Ok(idx.and_then(|i| self.headers.get(i)).copied())
    }

    fn height_of(&self, hash: &Hash256) -> Result<Option<BlockHeight>, ChainViewError> {
        Ok(self.header_index.get(hash).copied())
    }

    fn median_time_past(&self, header: &BlockHeader) -> Result<BlockTime, ChainViewError> {
        // Find the height of the parent of `header`, then collect up to 11
        // ancestor timestamps ending at that parent.
        let parent_height = match self.header_index.get(&header.prev_block()) {
            Some(&h) => h,
            None if header.prev_block() == Hash256::ZERO => {
                // Genesis parent — MTP of genesis is genesis timestamp itself.
                return Ok(self
                    .headers
                    .first()
                    .map_or(BlockTime::new(0), BlockHeader::time));
            }
            None => return Err(ChainViewError::NotFound),
        };

        // Convert absolute height to Vec index.
        let ph_abs = parent_height.to_u32();
        let ph_idx = ph_abs.saturating_sub(self.height_base.to_u32()) as usize;

        // Window of up to 11, but capped by how many headers we actually have.
        let count = (ph_idx + 1).min(11);
        let start = (ph_idx + 1).saturating_sub(11);
        let mut times: Vec<BlockTime> = self.headers[start..=ph_idx]
            .iter()
            .map(BlockHeader::time)
            .collect();
        debug_assert_eq!(times.len(), count);
        times.sort_unstable();
        Ok(times[times.len() / 2])
    }

    fn tip(&self) -> TipInfo {
        match self.headers.last() {
            None => TipInfo {
                hash: Hash256::ZERO,
                height: BlockHeight::ZERO,
            },
            Some(h) => {
                let idx = u32::try_from(self.headers.len() - 1).expect("chain height exceeds u32");
                let height = BlockHeight::new(self.height_base.to_u32().saturating_add(idx));
                TipInfo {
                    hash: h.hash(),
                    height,
                }
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use mantle::primitives::{BlockTime, BlockVersion, Nonce};

    fn header(time: u32, prev: Hash256) -> BlockHeader {
        BlockHeader::new(
            BlockVersion::new(1),
            prev,
            Hash256::ZERO,
            BlockTime::new(time),
            mantle::primitives::CompactBits::new(0x1d00_ffff),
            Nonce::new(0),
        )
    }

    fn push_chain(view: &mut MemoryChainView, times: &[u32]) {
        let mut prev = Hash256::ZERO;
        for &t in times {
            let h = header(t, prev);
            prev = h.hash();
            view.push_header(h);
        }
    }

    #[test]
    fn empty_view_tip() {
        let view = MemoryChainView::new();
        let tip = view.tip();
        assert_eq!(tip.height, BlockHeight::ZERO);
        assert_eq!(tip.hash, Hash256::ZERO);
    }

    #[test]
    fn get_header_by_height() {
        let mut view = MemoryChainView::new();
        push_chain(&mut view, &[1_000, 2_000, 3_000]);
        assert_eq!(
            view.get_header_at(BlockHeight::new(0))
                .expect("no error")
                .expect("height 0 exists")
                .time(),
            BlockTime::new(1_000)
        );
        assert_eq!(
            view.get_header_at(BlockHeight::new(2))
                .expect("no error")
                .expect("height 2 exists")
                .time(),
            BlockTime::new(3_000)
        );
        assert!(
            view.get_header_at(BlockHeight::new(3))
                .expect("no error")
                .is_none()
        );
    }

    #[test]
    fn get_header_by_hash() {
        let mut view = MemoryChainView::new();
        let h = header(9_999, Hash256::ZERO);
        view.push_header(h);
        let hash = h.hash();
        assert_eq!(
            view.get_header(&hash)
                .expect("no error")
                .expect("header exists")
                .time(),
            BlockTime::new(9_999)
        );
        assert!(view.get_header(&Hash256::ZERO).expect("no error").is_none());
    }

    #[test]
    fn coin_insert_lookup_spend() {
        let mut view = MemoryChainView::new();
        let op = OutPoint {
            txid: Hash256::from_bytes([1u8; 32]),
            vout: 0,
        };
        let coin = Coin {
            value: Satoshi::new(5_000_000_000),
            script_pubkey: vec![0xac].into(),
            height: BlockHeight::new(100),
            coinbase: false,
        };
        assert!(view.get_coin(&op).expect("no error").is_none());
        view.insert_coin(op, coin.clone());
        assert_eq!(
            *view.get_coin(&op).expect("no error").expect("coin exists"),
            coin
        );
        view.spend_coin(&op);
        assert!(view.get_coin(&op).expect("no error").is_none());
    }

    #[test]
    fn mtp_single_block() {
        let mut view = MemoryChainView::new();
        push_chain(&mut view, &[1_000]);
        // Block at height 1 whose parent is genesis.
        let genesis_hash = view.tip().hash;
        let next = header(2_000, genesis_hash);
        // MTP for `next` = median of [1_000] = 1_000.
        assert_eq!(
            view.median_time_past(&next).expect("mtp must succeed"),
            BlockTime::new(1_000)
        );
    }

    #[test]
    fn mtp_eleven_blocks() {
        let mut view = MemoryChainView::new();
        // Push 11 blocks with times 1..=11.
        push_chain(&mut view, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        let tip_hash = view.tip().hash;
        let next = header(99, tip_hash);
        // Median of [1..=11] = 6.
        assert_eq!(
            view.median_time_past(&next).expect("mtp must succeed"),
            BlockTime::new(6)
        );
    }

    #[test]
    fn mtp_more_than_eleven_uses_last_eleven() {
        let mut view = MemoryChainView::new();
        // 15 blocks with times 1..=15. MTP for next block uses heights 4..=14,
        // i.e., times [5,6,7,8,9,10,11,12,13,14,15], median = 10.
        push_chain(
            &mut view,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        );
        let tip_hash = view.tip().hash;
        let next = header(99, tip_hash);
        assert_eq!(
            view.median_time_past(&next).expect("mtp must succeed"),
            BlockTime::new(10)
        );
    }

    #[test]
    fn batched_get_coins() {
        let mut view = MemoryChainView::new();
        let op1 = OutPoint {
            txid: Hash256::from_bytes([1u8; 32]),
            vout: 0,
        };
        let op2 = OutPoint {
            txid: Hash256::from_bytes([2u8; 32]),
            vout: 0,
        };
        let coin = Coin {
            value: Satoshi::new(1000),
            script_pubkey: vec![].into(),
            height: BlockHeight::new(1),
            coinbase: false,
        };
        view.insert_coin(op1, coin.clone());

        let mut results = Vec::new();
        view.get_coins_into(&[op1, op2], &mut results)
            .expect("get_coins_into must succeed");
        assert_eq!(results[0], Some(&coin));
        assert_eq!(results[1], None);
    }
}
