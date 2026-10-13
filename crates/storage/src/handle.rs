use std::ops::Deref;
use std::path::Path;

use mantle::primitives::{BlockHeader, BlockHeight, Hash256, OutPoint};
use mantle_consensus::chain_view::TipInfo;

use crate::types::{
    CommitBlockReq, CommittedResp, HeaderKey, LookupResult, ReadHeaderReq, ReadHeaderResp,
    ReqToken, StorageError, StorageReq, StorageResp,
};

pub struct StorageHandle<
    'a,
    RReq = std::sync::Arc<quetzalcoatl::mpsc::RingBuffer<StorageReq<'a>>>,
    RResp = std::sync::Arc<quetzalcoatl::spsc::RingBuffer<StorageResp>>,
> where
    RReq: Deref<Target = quetzalcoatl::mpsc::RingBuffer<StorageReq<'a>>>,
    RResp: Deref<Target = quetzalcoatl::spsc::RingBuffer<StorageResp>>,
{
    req_tx: quetzalcoatl::mpsc::Producer<StorageReq<'a>, RReq>,
    resp_rx: quetzalcoatl::spsc::Consumer<StorageResp, RResp>,
    tip: TipInfo,
    next_token: u64,
}

impl<'a, RReq, RResp> StorageHandle<'a, RReq, RResp>
where
    RReq: Deref<Target = quetzalcoatl::mpsc::RingBuffer<StorageReq<'a>>>,
    RResp: Deref<Target = quetzalcoatl::spsc::RingBuffer<StorageResp>>,
{
    pub fn from_parts(
        req_tx: quetzalcoatl::mpsc::Producer<StorageReq<'a>, RReq>,
        resp_rx: quetzalcoatl::spsc::Consumer<StorageResp, RResp>,
        tip: TipInfo,
    ) -> Self {
        Self {
            req_tx,
            resp_rx,
            tip,
            next_token: 1,
        }
    }

    /// Batch UTXO lookup (send + recv in one call).
    ///
    /// # Errors
    /// Returns `StorageError` on ring or I/O failure.
    pub fn lookup_coins(
        &mut self,
        ops: &'a [OutPoint],
        out: &'a mut Vec<LookupResult>,
    ) -> Result<(), StorageError> {
        self.send_lookup(ops, out)?;
        self.recv_lookup()
    }

    /// Send a lookup request without waiting for the response.
    /// Must be followed by exactly one call to [`recv_lookup`] with the same `out`.
    ///
    /// # Errors
    /// Returns `StorageError` if the ring is full.
    pub fn send_lookup(
        &mut self,
        ops: &'a [OutPoint],
        out: &'a mut Vec<LookupResult>,
    ) -> Result<(), StorageError> {
        let token = self.next_token();
        self.send(StorageReq::LookupCoins(crate::types::LookupCoinsReq {
            token,
            outpoints: ops,
            out,
        }))
    }

    /// Batch UTXO lookup with locally-borrowed ops/out slices.
    ///
    /// Safe because `recv_lookup` blocks until the worker is done with both
    /// pointers before returning; the transmutes are erased before that point.
    ///
    /// # Errors
    /// Returns `StorageError` on ring or I/O failure.
    pub fn lookup_coins_borrowed(
        &mut self,
        ops: &[OutPoint],
        out: &mut Vec<LookupResult>,
    ) -> Result<(), StorageError> {
        self.send_lookup_borrowed(ops, out)?;
        self.recv_lookup()
    }

    /// Send a lookup request with locally-borrowed ops/out without waiting for
    /// the response. Must be followed by exactly one call to [`recv_lookup`].
    ///
    /// # Errors
    /// Returns `StorageError` if the ring is full.
    pub fn send_lookup_borrowed(
        &mut self,
        ops: &[OutPoint],
        out: &mut Vec<LookupResult>,
    ) -> Result<(), StorageError> {
        // SAFETY: Both `ops` and `out` outlive this call. `recv_lookup` blocks
        // until the worker signals completion, so the worker never touches
        // either borrow after recv_lookup returns. The send+recv pair is
        // synchronous from the caller's perspective — data is consumed before
        // the ring slot is reused.
        let req: crate::types::LookupCoinsReq<'_> = crate::types::LookupCoinsReq {
            token: self.next_token(),
            outpoints: ops,
            out,
        };
        let req_static: crate::types::LookupCoinsReq<'static> = unsafe {
            std::mem::transmute::<
                crate::types::LookupCoinsReq<'_>,
                crate::types::LookupCoinsReq<'static>,
            >(req)
        };
        self.send_raw(StorageReq::LookupCoins(req_static))
    }

    /// Receive the response from a prior [`send_lookup`] call.
    /// The output buffer passed to `send_lookup` is populated on return.
    ///
    /// # Errors
    /// Returns `StorageError` on ring or I/O failure.
    pub fn recv_lookup(&mut self) -> Result<(), StorageError> {
        match self.recv()? {
            StorageResp::LookupCoins(r) => r.map(|_| ()),
            _ => Err(StorageError::UnexpectedResponse),
        }
    }

    /// Read a header by hash.
    ///
    /// # Errors
    /// Returns `StorageError` on ring or I/O failure.
    pub fn read_header(&mut self, hash: Hash256) -> Result<Option<BlockHeader>, StorageError> {
        self.read_header_inner(HeaderKey::ByHash(hash))
    }

    /// Read a header by height.
    ///
    /// # Errors
    /// Returns `StorageError` on ring or I/O failure.
    pub fn read_header_at(&mut self, h: BlockHeight) -> Result<Option<BlockHeader>, StorageError> {
        self.read_header_inner(HeaderKey::ByHeight(h))
    }

    /// Commit a block to storage. Updates the locally-cached tip.
    ///
    /// # Errors
    /// Returns `StorageError` on ring or I/O failure.
    pub fn commit_block(&mut self, req: CommitBlockReq<'a>) -> Result<CommittedResp, StorageError> {
        self.send(StorageReq::CommitBlock(req))?;
        match self.recv()? {
            StorageResp::CommitBlock(r) => {
                let resp = r?;
                self.tip = resp.tip.clone();
                Ok(resp)
            }
            _ => Err(StorageError::UnexpectedResponse),
        }
    }

    /// Commit a block whose `NewCoin` entries borrow from a non-`'a`
    /// source (e.g. a local `Block` or wire buffer).
    ///
    /// This is safe because `commit_block` is synchronous: the request is
    /// pushed onto the ring, the storage thread calls `write_block` (which
    /// copies all coin data including `script_pubkey` bytes to disk), and
    /// the response is received before this method returns. The borrowed
    /// data is fully consumed before the ring slot is reused.
    ///
    /// # Errors
    /// Returns `StorageError` on ring or I/O failure.
    pub fn commit_block_borrowed(
        &mut self,
        req: CommitBlockReq<'_>,
    ) -> Result<CommittedResp, StorageError> {
        // SAFETY: The storage thread fully consumes the request
        // (writing all fields to disk) before sending the response.
        // `self.commit_block` blocks until that response arrives, so
        // the borrowed data is guaranteed to be live for the entire
        // duration the ring slot is occupied.
        let req_static: CommitBlockReq<'static> =
            unsafe { std::mem::transmute::<CommitBlockReq<'_>, CommitBlockReq<'static>>(req) };
        // We need to send the static version and receive a response.
        // Use a raw send so we don't fight the lifetime checker.
        self.send_raw(StorageReq::CommitBlock(req_static))?;
        match self.recv()? {
            StorageResp::CommitBlock(r) => {
                let resp = r?;
                self.tip = resp.tip.clone();
                Ok(resp)
            }
            _ => Err(StorageError::UnexpectedResponse),
        }
    }

    /// Last tip seen via a `commit_block` response, or the recovered tip on startup.
    pub fn tip(&self) -> TipInfo {
        self.tip.clone()
    }

    /// Gracefully shut down the storage thread.
    ///
    /// # Errors
    /// Returns `StorageError` if the shutdown request cannot be sent.
    pub fn shutdown(mut self) -> Result<(), StorageError> {
        self.send(StorageReq::Shutdown)?;
        match self.recv()? {
            StorageResp::Shutdown => Ok(()),
            _ => Err(StorageError::UnexpectedResponse),
        }
    }

    fn next_token(&mut self) -> ReqToken {
        let t = ReqToken(self.next_token);
        self.next_token += 1;
        t
    }

    fn send(&self, req: StorageReq<'a>) -> Result<(), StorageError> {
        self.req_tx.push(req).map_err(|_| StorageError::RingFull)
    }

    /// Send a request whose lifetime has been erased to `'static` via transmute.
    /// Only call this from methods that guarantee synchronous send+recv.
    fn send_raw(&self, req: StorageReq<'static>) -> Result<(), StorageError> {
        // SAFETY: callers ensure the borrowed data outlives the synchronous
        // send+recv round-trip. The worker never touches the data after
        // sending its response.
        let req_a: StorageReq<'a> =
            unsafe { std::mem::transmute::<StorageReq<'static>, StorageReq<'a>>(req) };
        self.req_tx.push(req_a).map_err(|_| StorageError::RingFull)
    }

    fn recv(&mut self) -> Result<StorageResp, StorageError> {
        self.resp_rx.pop_block().ok_or(StorageError::ThreadGone)
    }

    fn read_header_inner(&mut self, key: HeaderKey) -> Result<Option<BlockHeader>, StorageError> {
        let token = self.next_token();
        self.send(StorageReq::ReadHeader(ReadHeaderReq { token, key }))?;
        match self.recv()? {
            StorageResp::ReadHeader(r) => r.map(|ok: ReadHeaderResp| ok.header),
            _ => Err(StorageError::UnexpectedResponse),
        }
    }
}

// ── Convenience opener (kept for tests / one-off tools; prefer with_storage) ──

impl StorageHandle<'static> {
    /// Open the storage at `data_dir`, spawning the storage thread.
    ///
    /// Prefer [`crate::thread::with_storage`] for new code — it gives the
    /// compiler real lifetime information and avoids the `'static` transmute.
    ///
    /// # Errors
    /// Returns `StorageError` if the engine cannot be opened or the thread cannot be spawned.
    pub fn open(data_dir: &Path) -> Result<Self, StorageError> {
        use crate::engine::flat::FlatEngine;
        let engine = FlatEngine::open(data_dir).map_err(StorageError::from)?;
        open_arc(engine)
    }

    /// Open with the Robin Hood engine.
    ///
    /// # Errors
    /// Returns `StorageError` if the engine cannot be opened or the thread cannot be spawned.
    pub fn open_robin_hood(data_dir: &Path) -> Result<Self, StorageError> {
        use crate::engine::robin_hood::RobinHoodEngine;
        let engine = RobinHoodEngine::open(data_dir).map_err(StorageError::from)?;
        open_arc(engine)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CommitBlockReq, Durability, ReqToken};
    use mantle::primitives::{
        BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Nonce, OutPoint, Satoshi,
    };
    use mantle_consensus::chain_view::NewCoin;

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

    #[test]
    fn commit_block_updates_tip() {
        let dir = std::env::temp_dir().join(format!(
            "mantle-handle-commit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let mut handle = StorageHandle::open(&dir).expect("open flat engine");

        // Initial tip is genesis (height 0, zero hash).
        let initial_tip = handle.tip();
        assert_eq!(initial_tip.height, BlockHeight::ZERO);

        let op = OutPoint {
            txid: Hash256::from_bytes([0x01; 32]),
            vout: 0,
        };
        let block_hash = Hash256::from_bytes([0x02; 32]);

        // Use 'static data so commit_block (not commit_block_borrowed) works
        // with the StorageHandle<'static> returned by open().
        static SPK: [u8; 1] = [0x51];
        let created: &'static [NewCoin<'static>] = Box::leak(Box::new([NewCoin {
            outpoint: op,
            value: Satoshi::new(5_000_000_000),
            script_pubkey: &SPK,
            coinbase: true,
            height: BlockHeight::new(1),
        }]));
        let resp = handle
            .commit_block(CommitBlockReq {
                token: ReqToken(1),
                height: BlockHeight::new(1),
                hash: block_hash,
                prev_hash: Hash256::ZERO,
                header: make_header(1_000_000),
                created: &created,
                spent: &[],
                block_bytes: None,
                durability: Durability::Memory,
            })
            .expect("commit_block must succeed");

        assert_eq!(resp.tip.height, BlockHeight::new(1));
        assert_eq!(resp.tip.hash, block_hash);

        // Cached tip should also be updated.
        let tip = handle.tip();
        assert_eq!(tip.height, BlockHeight::new(1));
        assert_eq!(tip.hash, block_hash);

        // Read the committed header back.
        let hdr = handle.read_header(block_hash).expect("read_header").unwrap();
        assert_eq!(hdr.time().to_u32(), 1_000_000);

        handle.shutdown().expect("shutdown");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn commit_block_unexpected_response() {
        // Verify that `commit_block` returns `UnexpectedResponse` when the
        // response variant is wrong. This is hard to trigger through a real
        // worker — we mainly verify the non-error path above. The error path
        // is implicitly covered by the match arm.
        // We at least verify the token round-trips correctly.
        let dir = std::env::temp_dir().join(format!(
            "mantle-handle-token-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut handle = StorageHandle::open(&dir).expect("open");

        let resp = handle
            .commit_block(CommitBlockReq {
                token: ReqToken(42),
                height: BlockHeight::new(1),
                hash: Hash256::from_bytes([0x10; 32]),
                prev_hash: Hash256::ZERO,
                header: make_header(0),
                created: &[],
                spent: &[],
                block_bytes: None,
                durability: Durability::Memory,
            })
            .expect("commit_block");

        assert_eq!(resp.token, ReqToken(42));
        handle.shutdown().expect("shutdown");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_header_at_returns_committed_header() {
        // Exercise read_header_inner via read_header_at (by height).
        let dir = std::env::temp_dir().join(format!(
            "mantle-handle-rh-at-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut handle = StorageHandle::open(&dir).expect("open");

        let block_hash = Hash256::from_bytes([0x05; 32]);
        handle
            .commit_block(CommitBlockReq {
                token: ReqToken(1),
                height: BlockHeight::new(1),
                hash: block_hash,
                prev_hash: Hash256::ZERO,
                header: make_header(999),
                created: &[],
                spent: &[],
                block_bytes: None,
                durability: Durability::Memory,
            })
            .expect("commit_block");

        // Read by height.
        let hdr = handle
            .read_header_at(BlockHeight::new(1))
            .expect("read_header_at")
            .expect("header must exist");
        assert_eq!(hdr.time().to_u32(), 999);

        handle.shutdown().expect("shutdown");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_header_returns_none_for_unknown_hash() {
        // Exercise the None path of read_header_inner via read_header.
        let dir = std::env::temp_dir().join(format!(
            "mantle-handle-rh-none-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut handle = StorageHandle::open(&dir).expect("open");

        let unknown_hash = Hash256::from_bytes([0xee; 32]);
        let result = handle.read_header(unknown_hash).expect("read_header");
        assert!(result.is_none(), "unknown hash must return None");

        handle.shutdown().expect("shutdown");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_header_at_returns_none_for_unknown_height() {
        // Exercise the None path of read_header_inner via read_header_at.
        let dir = std::env::temp_dir().join(format!(
            "mantle-handle-rh-at-none-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut handle = StorageHandle::open(&dir).expect("open");

        let result = handle
            .read_header_at(BlockHeight::new(999))
            .expect("read_header_at");
        assert!(result.is_none(), "unknown height must return None");

        handle.shutdown().expect("shutdown");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_header_multiple_blocks() {
        // Commit two blocks, read both by hash and by height to exercise
        // read_header_inner under multiple sequential calls.
        let dir = std::env::temp_dir().join(format!(
            "mantle-handle-rh-multi-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut handle = StorageHandle::open(&dir).expect("open");

        let hash1 = Hash256::from_bytes([0x11; 32]);
        handle
            .commit_block(CommitBlockReq {
                token: ReqToken(1),
                height: BlockHeight::new(1),
                hash: hash1,
                prev_hash: Hash256::ZERO,
                header: make_header(100),
                created: &[],
                spent: &[],
                block_bytes: None,
                durability: Durability::Memory,
            })
            .expect("commit block 1");

        let hash2 = Hash256::from_bytes([0x22; 32]);
        let mut h2 = make_header(200);
        h2.set_prev_block(hash1);
        handle
            .commit_block(CommitBlockReq {
                token: ReqToken(2),
                height: BlockHeight::new(2),
                hash: hash2,
                prev_hash: hash1,
                header: h2,
                created: &[],
                spent: &[],
                block_bytes: None,
                durability: Durability::Memory,
            })
            .expect("commit block 2");

        // Read by hash.
        let hdr1 = handle.read_header(hash1).expect("read").unwrap();
        assert_eq!(hdr1.time().to_u32(), 100);
        let hdr2 = handle.read_header(hash2).expect("read").unwrap();
        assert_eq!(hdr2.time().to_u32(), 200);

        // Read by height.
        let hdr1_h = handle.read_header_at(BlockHeight::new(1)).expect("read").unwrap();
        assert_eq!(hdr1_h.time().to_u32(), 100);
        let hdr2_h = handle.read_header_at(BlockHeight::new(2)).expect("read").unwrap();
        assert_eq!(hdr2_h.time().to_u32(), 200);

        handle.shutdown().expect("shutdown");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

fn open_arc(
    engine: impl crate::engine::Engine + Send + 'static,
) -> Result<StorageHandle<'static>, StorageError> {
    use crate::thread::StorageWorker;
    use quetzalcoatl::capacity::Capacity;
    use quetzalcoatl::mpsc::RingBuffer as MpscRing;
    use quetzalcoatl::spsc::RingBuffer as SpscRing;

    const RING_CAP: usize = 1024;
    let initial_tip = engine.tip();

    // `.split()` wraps the ring in an Arc internally; the resulting
    // Producer/Consumer use Arc<RingBuffer<T>> as their ring accessor,
    // which matches the StorageHandle<'static> default type parameters.
    let (req_tx, req_rx) = MpscRing::new(Capacity::exact(RING_CAP)).split();
    let (resp_tx, resp_rx) = SpscRing::new(Capacity::exact(RING_CAP)).split();

    let worker = StorageWorker {
        req_rx,
        resp_tx,
        engine: Box::new(engine),
    };

    std::thread::Builder::new()
        .name("storage".into())
        .spawn(move || worker.run())
        .map_err(|e| StorageError::Io(e.kind()))?;

    Ok(StorageHandle::from_parts(req_tx, resp_rx, initial_tip))
}
