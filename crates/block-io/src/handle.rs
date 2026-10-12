use std::io;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mantle::codec::Decode;
use mantle::primitives::{Block, BlockHeader, BlockHeight, Hash256};
use quetzalcoatl::capacity::Capacity;
use quetzalcoatl::mpsc::RingBuffer as MpscRing;
use quetzalcoatl::spsc::RingBuffer as SpscRing;
use ququmatz::IoUring;

use crate::slab::{Slab, SlabWriter};
use crate::store::{BlockStore, HeaderStore};

pub enum FileReq {
    WriteBlock {
        height: BlockHeight,
        data: Vec<u8>,
    },
    WriteBlockAsync {
        height: BlockHeight,
        data: Vec<u8>,
    },
    ReadBlock {
        height: BlockHeight,
    },
    ReadBlockDecoded {
        height: BlockHeight,
        expected_hash: Hash256,
    },
    ReadBlockSlab {
        height: BlockHeight,
    },
    HasBlock {
        height: BlockHeight,
    },
    WriteHeaders {
        start: BlockHeight,
        data: Vec<u8>,
    },
    AppendHeaders {
        data: Vec<u8>,
    },
    LoadCachedHeaders {
        start: BlockHeight,
    },
    FlushBlockIndex,
    DiscardBlocks,
    ReleaseSlab {
        slot: u16,
    },
    Shutdown,
}

pub enum FileResp {
    Ok,
    Bool(bool),
    BlockData(Vec<u8>),
    DecodedBlock(Block),
    SlabReady(crate::slab::SlabToken),
    Headers(Vec<(BlockHeight, BlockHeader)>),
    Err(io::Error),
}

const FILE_RING_CAP: usize = 4096;
const BLOCK_INDEX_FLUSH_INTERVAL: u64 = 2_000;

// ── Generic handle ───────────────────────────────────────────────────────────

pub struct FileIoHandle<RReq = Arc<MpscRing<FileReq>>, RResp = Arc<SpscRing<FileResp>>>
where
    RReq: Deref<Target = MpscRing<FileReq>>,
    RResp: Deref<Target = SpscRing<FileResp>>,
{
    tx: quetzalcoatl::mpsc::Producer<FileReq, RReq>,
    rx: quetzalcoatl::spsc::Consumer<FileResp, RResp>,
}

impl<RReq, RResp> FileIoHandle<RReq, RResp>
where
    RReq: Deref<Target = MpscRing<FileReq>>,
    RResp: Deref<Target = SpscRing<FileResp>>,
{
    pub(crate) fn from_parts(
        tx: quetzalcoatl::mpsc::Producer<FileReq, RReq>,
        rx: quetzalcoatl::spsc::Consumer<FileResp, RResp>,
    ) -> Self {
        Self { tx, rx }
    }

    pub fn write_block(&mut self, height: BlockHeight, data: Vec<u8>) -> io::Result<()> {
        self.tx
            .push(FileReq::WriteBlock { height, data })
            .map_err(|_| io::Error::other("file-io ring full"))?;
        match self.rx.pop_block() {
            Some(FileResp::Ok) => Ok(()),
            Some(FileResp::Err(e)) => Err(e),
            _ => Err(io::Error::other("file-io unexpected response")),
        }
    }

    pub fn write_block_async(&self, height: BlockHeight, data: Vec<u8>) -> io::Result<()> {
        self.tx
            .push(FileReq::WriteBlockAsync { height, data })
            .map_err(|_| io::Error::other("file-io ring full"))
    }

    pub fn read_block(&mut self, height: BlockHeight) -> io::Result<Vec<u8>> {
        self.tx
            .push(FileReq::ReadBlock { height })
            .map_err(|_| io::Error::other("file-io ring full"))?;
        match self.rx.pop_block() {
            Some(FileResp::BlockData(data)) => Ok(data),
            Some(FileResp::Err(e)) => Err(e),
            _ => Err(io::Error::other("file-io unexpected response")),
        }
    }

    pub fn read_block_decoded(
        &mut self,
        height: BlockHeight,
        expected_hash: Hash256,
    ) -> io::Result<Block> {
        self.tx
            .push(FileReq::ReadBlockDecoded {
                height,
                expected_hash,
            })
            .map_err(|_| io::Error::other("file-io ring full"))?;
        match self.rx.pop_block() {
            Some(FileResp::DecodedBlock(block)) => Ok(block),
            Some(FileResp::Err(e)) => Err(e),
            _ => Err(io::Error::other("file-io unexpected response")),
        }
    }

    /// Read block bytes into a slab slot and return a token.
    ///
    /// The caller uses [`SlabReader::handle`] with the token to get a
    /// zero-copy `BufHandle<'a>` borrowing the block bytes directly from
    /// the pre-allocated slab.  After processing, send the slot index
    /// back via [`release_slab`](Self::release_slab) so the worker can
    /// reuse it.
    pub fn read_block_slab(&mut self, height: BlockHeight) -> io::Result<crate::slab::SlabToken> {
        self.tx
            .push(FileReq::ReadBlockSlab { height })
            .map_err(|_| io::Error::other("file-io ring full"))?;
        match self.rx.pop_block() {
            Some(FileResp::SlabReady(token)) => Ok(token),
            Some(FileResp::Err(e)) => Err(e),
            _ => Err(io::Error::other("file-io unexpected response")),
        }
    }

    pub fn release_slab(&self, slot: u16) {
        let _ = self.tx.push(FileReq::ReleaseSlab { slot });
    }

    pub fn write_headers(&mut self, start: BlockHeight, data: Vec<u8>) -> io::Result<()> {
        self.tx
            .push(FileReq::WriteHeaders { start, data })
            .map_err(|_| io::Error::other("file-io ring full"))?;
        match self.rx.pop_block() {
            Some(FileResp::Ok) => Ok(()),
            Some(FileResp::Err(e)) => Err(e),
            _ => Err(io::Error::other("file-io unexpected response")),
        }
    }

    pub fn append_headers(&mut self, data: Vec<u8>) -> io::Result<()> {
        self.tx
            .push(FileReq::AppendHeaders { data })
            .map_err(|_| io::Error::other("file-io ring full"))?;
        match self.rx.pop_block() {
            Some(FileResp::Ok) => Ok(()),
            Some(FileResp::Err(e)) => Err(e),
            _ => Err(io::Error::other("file-io unexpected response")),
        }
    }

    pub fn flush_block_index(&mut self) -> io::Result<()> {
        self.tx
            .push(FileReq::FlushBlockIndex)
            .map_err(|_| io::Error::other("file-io ring full"))?;
        match self.rx.pop_block() {
            Some(FileResp::Ok) => Ok(()),
            Some(FileResp::Err(e)) => Err(e),
            _ => Err(io::Error::other("file-io unexpected response")),
        }
    }

    pub fn discard_blocks(&mut self) -> io::Result<()> {
        self.tx
            .push(FileReq::DiscardBlocks)
            .map_err(|_| io::Error::other("file-io ring full"))?;
        match self.rx.pop_block() {
            Some(FileResp::Ok) => Ok(()),
            Some(FileResp::Err(e)) => Err(e),
            _ => Err(io::Error::other("file-io unexpected response")),
        }
    }

    pub fn has_block(&mut self, height: BlockHeight) -> bool {
        if self.tx.push(FileReq::HasBlock { height }).is_err() {
            return false;
        }
        matches!(self.rx.pop_block(), Some(FileResp::Bool(true)))
    }

    pub fn load_cached_headers(
        &mut self,
        start: BlockHeight,
    ) -> io::Result<Vec<(BlockHeight, BlockHeader)>> {
        self.tx
            .push(FileReq::LoadCachedHeaders { start })
            .map_err(|_| io::Error::other("file-io ring full"))?;
        match self.rx.pop_block() {
            Some(FileResp::Headers(h)) => Ok(h),
            Some(FileResp::Err(e)) => Err(e),
            _ => Ok(Vec::new()),
        }
    }

    pub fn shutdown(&mut self) {
        let _ = self.tx.push(FileReq::Shutdown);
        let _ = self.rx.pop_block();
    }
}

// ── Arc-based spawn (backward compat) ────────────────────────────────────────

impl FileIoHandle {
    pub fn spawn(data_dir: &Path) -> io::Result<Self> {
        let blocks = BlockStore::open(data_dir)?;
        let headers = HeaderStore::open(data_dir)?;
        let data_dir = data_dir.to_owned();

        let req_ring = MpscRing::new(Capacity::exact(FILE_RING_CAP));
        let resp_ring = SpscRing::new(Capacity::exact(FILE_RING_CAP));
        let (req_tx, req_rx) = req_ring.split();
        let (resp_tx, resp_rx) = resp_ring.split();

        // Leak a Slab for the 'static detached-thread path.
        let slab: &'static Slab = Box::leak(Box::new(Slab::new()));
        let (slab_writer, _slab_reader) = slab.split();

        std::thread::Builder::new()
            .name("file-io".into())
            .spawn(move || {
                FileIoWorker {
                    req_rx,
                    resp_tx,
                    blocks,
                    headers,
                    data_dir,
                    ring: IoUring::new(256).expect("io_uring"),
                    slab_writer,
                }
                .run();
            })
            .map_err(|e| io::Error::other(format!("spawn file-io: {e}")))?;

        Ok(Self::from_parts(req_tx, resp_rx))
    }
}

// ── Scoped-thread entry point ────────────────────────────────────────────────

pub fn with_file_io<F, R>(data_dir: &Path, f: F) -> io::Result<R>
where
    F: FnOnce(
        &mut FileIoHandle<&MpscRing<FileReq>, &SpscRing<FileResp>>,
        &crate::slab::SlabReader<'_>,
    ) -> R,
{
    let blocks = BlockStore::open(data_dir)?;
    let headers = HeaderStore::open(data_dir)?;
    let data_dir_owned = data_dir.to_owned();
    let slab = Slab::new();

    let mut req_ring: MpscRing<FileReq> = MpscRing::new(Capacity::exact(FILE_RING_CAP));
    let mut resp_ring: SpscRing<FileResp> = SpscRing::new(Capacity::exact(FILE_RING_CAP));

    let result = std::thread::scope(|s| {
        let (slab_writer, slab_reader) = slab.split();
        let (req_tx, req_rx) = req_ring.split_borrowed();
        let (resp_tx, resp_rx) = resp_ring.split_borrowed();

        s.spawn(|| {
            FileIoWorker {
                req_rx,
                resp_tx,
                blocks,
                headers,
                data_dir: data_dir_owned,
                ring: IoUring::new(256).expect("io_uring"),
                slab_writer,
            }
            .run();
        });

        let mut handle = FileIoHandle::from_parts(req_tx, resp_rx);
        f(&mut handle, &slab_reader)
    });

    Ok(result)
}

// ── Worker ───────────────────────────────────────────────────────────────────

struct FileIoWorker<
    'slab,
    RReq: Deref<Target = MpscRing<FileReq>>,
    RResp: Deref<Target = SpscRing<FileResp>>,
> {
    req_rx: quetzalcoatl::mpsc::Consumer<FileReq, RReq>,
    resp_tx: quetzalcoatl::spsc::Producer<FileResp, RResp>,
    blocks: BlockStore,
    headers: HeaderStore,
    data_dir: PathBuf,
    ring: IoUring,
    slab_writer: SlabWriter<'slab>,
}

impl<RReq, RResp> FileIoWorker<'_, RReq, RResp>
where
    RReq: Deref<Target = MpscRing<FileReq>>,
    RResp: Deref<Target = SpscRing<FileResp>>,
{
    fn run(mut self) {
        let mut writes_since_flush: u64 = 0;

        while let Some(req) = self.req_rx.pop_block() {
            let resp = match req {
                FileReq::WriteBlock { height, data } => {
                    self.handle_write_block(height, &data, &mut writes_since_flush)
                }
                FileReq::WriteBlockAsync { height, data } => {
                    self.handle_write_block_async(height, &data, &mut writes_since_flush);
                    continue;
                }
                FileReq::ReadBlock { height } => self.handle_read_block(height),
                FileReq::ReadBlockDecoded {
                    height,
                    expected_hash,
                } => self.handle_read_block_decoded(height, expected_hash),
                FileReq::ReadBlockSlab { height } => self.handle_read_block_slab(height),
                FileReq::HasBlock { height } => self.handle_has_block(height),
                FileReq::WriteHeaders { start, data } => self.handle_write_headers(start, &data),
                FileReq::AppendHeaders { data } => self.handle_append_headers(&data),
                FileReq::LoadCachedHeaders { start } => self.handle_load_cached_headers(start),
                FileReq::FlushBlockIndex => self.handle_flush_block_index(),
                FileReq::DiscardBlocks => self.handle_discard_blocks(&mut writes_since_flush),
                FileReq::ReleaseSlab { slot } => {
                    self.slab_writer.release(slot);
                    continue;
                }
                FileReq::Shutdown => {
                    let _ = self.resp_tx.push(FileResp::Ok);
                    return;
                }
            };
            if self.resp_tx.push(resp).is_err() {
                eprintln!("[file-io] FAILED to push response!");
            }
        }
    }

    // ── Individual request handlers ─────────────────────────────────────────

    fn handle_write_block(
        &mut self,
        height: BlockHeight,
        data: &[u8],
        writes_since_flush: &mut u64,
    ) -> FileResp {
        match self.blocks.write(&mut self.ring, height, data) {
            Ok(()) => {
                *writes_since_flush += 1;
                if *writes_since_flush >= BLOCK_INDEX_FLUSH_INTERVAL {
                    let _ = self.blocks.flush_index(&self.data_dir);
                    *writes_since_flush = 0;
                }
                FileResp::Ok
            }
            Err(e) => FileResp::Err(e),
        }
    }

    fn handle_write_block_async(
        &mut self,
        height: BlockHeight,
        data: &[u8],
        writes_since_flush: &mut u64,
    ) {
        let _ = self.blocks.write(&mut self.ring, height, data);
        *writes_since_flush += 1;
        if *writes_since_flush >= BLOCK_INDEX_FLUSH_INTERVAL {
            let _ = self.blocks.flush_index(&self.data_dir);
            *writes_since_flush = 0;
        }
    }

    fn handle_read_block(&mut self, height: BlockHeight) -> FileResp {
        match self.blocks.block_location(height) {
            Ok((offset, length)) => match self.slab_writer.alloc() {
                Some(slot) => {
                    match self.slab_writer.fill_from_disk(
                        slot,
                        self.blocks.file_store(),
                        &mut self.ring,
                        offset,
                        length,
                    ) {
                        Ok(_token) => {
                            let data =
                                self.slab_writer.slot_buf_mut(slot)[..length as usize].to_vec();
                            self.slab_writer.release(slot);
                            FileResp::BlockData(data)
                        }
                        Err(e) => {
                            self.slab_writer.release(slot);
                            FileResp::Err(e)
                        }
                    }
                }
                None => FileResp::Err(io::Error::other("slab full")),
            },
            Err(e) => FileResp::Err(e),
        }
    }

    fn handle_read_block_decoded(
        &mut self,
        height: BlockHeight,
        expected_hash: Hash256,
    ) -> FileResp {
        match self.blocks.block_location(height) {
            Ok((offset, length)) => match self.slab_writer.alloc() {
                Some(slot) => {
                    match self.slab_writer.fill_from_disk(
                        slot,
                        self.blocks.file_store(),
                        &mut self.ring,
                        offset,
                        length,
                    ) {
                        Ok(_token) => {
                            let data = &self.slab_writer.slot_buf_mut(slot)[..length as usize];
                            let result = Block::decode(&mut std::io::Cursor::new(data));
                            self.slab_writer.release(slot);
                            match result {
                                Ok(block) => {
                                    if block.header.hash() == expected_hash {
                                        FileResp::DecodedBlock(block)
                                    } else {
                                        FileResp::Err(io::Error::other("hash mismatch"))
                                    }
                                }
                                Err(e) => FileResp::Err(io::Error::other(format!("decode: {e}"))),
                            }
                        }
                        Err(e) => {
                            self.slab_writer.release(slot);
                            FileResp::Err(e)
                        }
                    }
                }
                None => FileResp::Err(io::Error::other("slab full")),
            },
            Err(e) => FileResp::Err(e),
        }
    }

    fn handle_read_block_slab(&mut self, height: BlockHeight) -> FileResp {
        match self.blocks.block_location(height) {
            Ok((offset, length)) => match self.slab_writer.alloc() {
                Some(slot) => {
                    match self.slab_writer.fill_from_disk(
                        slot,
                        self.blocks.file_store(),
                        &mut self.ring,
                        offset,
                        length,
                    ) {
                        Ok(token) => FileResp::SlabReady(token),
                        Err(e) => {
                            self.slab_writer.release(slot);
                            FileResp::Err(e)
                        }
                    }
                }
                None => FileResp::Err(io::Error::other("slab full")),
            },
            Err(e) => FileResp::Err(e),
        }
    }

    fn handle_has_block(&self, height: BlockHeight) -> FileResp {
        FileResp::Bool(self.blocks.has_block(height))
    }

    fn handle_write_headers(&mut self, start: BlockHeight, data: &[u8]) -> FileResp {
        match self.headers.write_raw(&mut self.ring, start, data) {
            Ok(()) => FileResp::Ok,
            Err(e) => FileResp::Err(e),
        }
    }

    fn handle_append_headers(&mut self, data: &[u8]) -> FileResp {
        match self.headers.append_raw(&mut self.ring, data) {
            Ok(()) => FileResp::Ok,
            Err(error) => FileResp::Err(error),
        }
    }

    fn handle_load_cached_headers(&mut self, start: BlockHeight) -> FileResp {
        match self.headers.load_cached(&mut self.ring, start) {
            Ok(h) => FileResp::Headers(h),
            Err(e) => FileResp::Err(e),
        }
    }

    fn handle_flush_block_index(&mut self) -> FileResp {
        match self.blocks.flush_index(&self.data_dir) {
            Ok(()) => FileResp::Ok,
            Err(e) => FileResp::Err(e),
        }
    }

    fn handle_discard_blocks(&mut self, writes_since_flush: &mut u64) -> FileResp {
        *writes_since_flush = 0;
        match self.blocks.discard_all(&self.data_dir) {
            Ok(()) => FileResp::Ok,
            Err(e) => FileResp::Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    use mantle::codec::Encode;
    use mantle::primitives::{
        BlockHeader, BlockTime, BlockVersion, CompactBits, Hash256, Locktime, Nonce, OutPoint,
        Satoshi, Sequence, Transaction, TxIn, TxOut, TxVersion, Witness,
    };

    /// Unique temp directory per test to avoid conflicts with parallel runs.
    fn test_data_dir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("mantle_block_io_test_{pid}_{id}"));
        std::fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    fn sample_block() -> Block {
        Block {
            header: BlockHeader::new(
                BlockVersion::new(1),
                Hash256::ZERO,
                Hash256::ZERO,
                BlockTime::new(1_231_006_505),
                CompactBits::new(0x1d00_ffff),
                Nonce::new(2_083_236_893),
            ),
            transactions: vec![Transaction {
                version: TxVersion::new(1),
                inputs: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Hash256::ZERO,
                        vout: 0xffff_ffff,
                    },
                    script_sig: vec![0x04].into(),
                    sequence: Sequence::MAX,
                    witness: Witness::empty(),
                }],
                outputs: vec![TxOut {
                    value: Satoshi::new(5_000_000_000),
                    script_pubkey: vec![0xac].into(),
                }],
                locktime: Locktime::new(0),
            }],
        }
    }

    #[test]
    fn write_then_read_block_roundtrips() {
        let dir = test_data_dir();
        let block = sample_block();
        let mut encoded = Vec::new();
        block.encode(&mut encoded).expect("encode block");
        let expected = encoded.clone();

        let result = with_file_io(&dir, |handle, _slab_reader| {
            handle
                .write_block(BlockHeight::ZERO, encoded)
                .expect("write_block");
            let data = handle.read_block(BlockHeight::ZERO).expect("read_block");
            assert_eq!(data, expected, "read_block should return the written bytes");
        });
        assert!(result.is_ok());
        cleanup(&dir);
    }

    #[test]
    fn read_block_decoded_returns_matching_block() {
        let dir = test_data_dir();
        let block = sample_block();
        let expected_hash = block.header.hash();
        let mut encoded = Vec::new();
        block.encode(&mut encoded).expect("encode block");

        let result = with_file_io(&dir, |handle, _slab_reader| {
            handle
                .write_block(BlockHeight::ZERO, encoded)
                .expect("write_block");
            let decoded = handle
                .read_block_decoded(BlockHeight::ZERO, expected_hash)
                .expect("read_block_decoded");
            assert_eq!(decoded, block, "decoded block should match original");
        });
        assert!(result.is_ok());
        cleanup(&dir);
    }

    #[test]
    fn read_block_decoded_rejects_wrong_hash() {
        let dir = test_data_dir();
        let block = sample_block();
        let wrong_hash = Hash256::from_bytes([0xff; 32]);
        let mut encoded = Vec::new();
        block.encode(&mut encoded).expect("encode block");

        let result = with_file_io(&dir, |handle, _slab_reader| {
            handle
                .write_block(BlockHeight::ZERO, encoded)
                .expect("write_block");
            let err = handle
                .read_block_decoded(BlockHeight::ZERO, wrong_hash)
                .expect_err("should fail with wrong hash");
            assert!(
                err.to_string().contains("hash mismatch"),
                "error should mention hash mismatch, got: {err}"
            );
        });
        assert!(result.is_ok());
        cleanup(&dir);
    }

    #[test]
    fn read_nonexistent_block_returns_error() {
        let dir = test_data_dir();

        let result = with_file_io(&dir, |handle, _slab_reader| {
            let err = handle
                .read_block(BlockHeight::ZERO)
                .expect_err("reading nonexistent block should fail");
            assert_eq!(err.kind(), io::ErrorKind::NotFound);
        });
        assert!(result.is_ok());
        cleanup(&dir);
    }

    #[test]
    fn has_block_reports_correctly() {
        let dir = test_data_dir();
        let block = sample_block();
        let mut encoded = Vec::new();
        block.encode(&mut encoded).expect("encode block");

        let result = with_file_io(&dir, |handle, _slab_reader| {
            assert!(
                !handle.has_block(BlockHeight::ZERO),
                "has_block should be false before write"
            );
            handle
                .write_block(BlockHeight::ZERO, encoded)
                .expect("write_block");
            assert!(
                handle.has_block(BlockHeight::ZERO),
                "has_block should be true after write"
            );
        });
        assert!(result.is_ok());
        cleanup(&dir);
    }

    #[test]
    fn write_then_read_block_slab_roundtrips() {
        let dir = test_data_dir();
        let block = sample_block();
        let mut encoded = Vec::new();
        block.encode(&mut encoded).expect("encode block");
        let expected_len = encoded.len();

        let result = with_file_io(&dir, |handle, slab_reader| {
            handle
                .write_block(BlockHeight::ZERO, encoded)
                .expect("write_block");
            let token = handle
                .read_block_slab(BlockHeight::ZERO)
                .expect("read_block_slab");
            let slot = token.slot;
            let buf_handle = slab_reader.handle(token);
            assert_eq!(buf_handle.as_slice().len(), expected_len);
            handle.release_slab(slot);
        });
        assert!(result.is_ok());
        cleanup(&dir);
    }

    #[test]
    fn write_block_async_stores_data() {
        let dir = test_data_dir();
        let block = sample_block();
        let mut encoded = Vec::new();
        block.encode(&mut encoded).expect("encode block");
        let expected = encoded.clone();

        let result = with_file_io(&dir, |handle, _slab_reader| {
            handle
                .write_block_async(BlockHeight::ZERO, encoded)
                .expect("write_block_async");
            // write_block_async is fire-and-forget on the caller side, but the
            // worker processes it before the next synchronous request.
            let data = handle.read_block(BlockHeight::ZERO).expect("read_block");
            assert_eq!(data, expected);
        });
        assert!(result.is_ok());
        cleanup(&dir);
    }

    #[test]
    fn write_and_load_cached_headers_roundtrips() {
        let dir = test_data_dir();
        let hdr = sample_block().header;
        let mut hdr_bytes = Vec::new();
        hdr.encode(&mut hdr_bytes).expect("encode header");

        let result = with_file_io(&dir, |handle, _slab_reader| {
            handle
                .write_headers(BlockHeight::new(5), hdr_bytes.clone())
                .expect("write_headers");
            let headers = handle
                .load_cached_headers(BlockHeight::new(5))
                .expect("load_cached_headers");
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].0, BlockHeight::new(5));
            assert_eq!(headers[0].1, hdr);
        });
        assert!(result.is_ok());
        cleanup(&dir);
    }

    #[test]
    fn flush_block_index_succeeds() {
        let dir = test_data_dir();
        let block = sample_block();
        let mut encoded = Vec::new();
        block.encode(&mut encoded).expect("encode block");

        let result = with_file_io(&dir, |handle, _slab_reader| {
            handle
                .write_block(BlockHeight::ZERO, encoded)
                .expect("write_block");
            handle.flush_block_index().expect("flush_block_index");
        });
        assert!(result.is_ok());
        cleanup(&dir);
    }

    #[test]
    fn discard_blocks_empties_cache_and_frees_disk() {
        let dir = test_data_dir();
        let block = sample_block();
        let mut encoded = Vec::new();
        block.encode(&mut encoded).expect("encode block");
        let refill = encoded.clone();

        let result = with_file_io(&dir, |handle, _slab_reader| {
            handle
                .write_block(BlockHeight::new(7), encoded)
                .expect("write_block");
            handle.discard_blocks().expect("discard_blocks");
            assert!(!handle.has_block(BlockHeight::new(7)));
            assert_eq!(std::fs::metadata(dir.join("blocks.bin")).unwrap().len(), 0);
            handle
                .write_block(BlockHeight::new(8), refill.clone())
                .expect("write after discard");
            assert_eq!(
                handle.read_block(BlockHeight::new(8)).expect("read"),
                refill
            );
        });
        assert!(result.is_ok());
        cleanup(&dir);
    }

    #[test]
    fn shutdown_is_clean() {
        let dir = test_data_dir();

        let result = with_file_io(&dir, |handle, _slab_reader| {
            handle.shutdown();
        });
        assert!(result.is_ok());
        cleanup(&dir);
    }
}
