//! Shared header-record serialization for all engine implementations.
//!
//! [`HeaderStore`] owns the header file, checkpoint file, header index, tip,
//! and write position — fields that were previously duplicated across every
//! engine struct. Engines embed a `HeaderStore` and delegate the `Engine`
//! trait's header methods to it.
//!
//! Fixed 116 bytes per record:
//! hash(32) + version(4) + prev\_block(32) + merkle\_root(32) +
//! time(4) + bits(4) + nonce(4) + height(4).

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use mantle::collections::{BuildPrehashedHasher, PrehashedMap};
use mantle::hash::ByteSliceExt;
use mantle::primitives::{
    BlockHeader, BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Nonce,
};
use mantle_consensus::chain_view::TipInfo;

use super::EngineError;

/// Fixed size of a header record in bytes.
pub const HEADER_RECORD_SIZE: usize = 116;

/// Same as [`HEADER_RECORD_SIZE`] but as `u64` for offset arithmetic.
pub const HEADER_RECORD_SIZE_U64: u64 = HEADER_RECORD_SIZE as u64;

/// Shared header persistence owned by every engine implementation.
pub struct HeaderStore {
    header_file: File,
    pub write_len: u64,
    pub index: PrehashedMap<Hash256, u32>,
    checkpoint_file: File,
    pub tip: TipInfo,
    data_dir: PathBuf,
}

impl HeaderStore {
    /// Open (or create) the header and checkpoint files in `data_dir`.
    ///
    /// # Errors
    /// Returns `EngineError::Io` if either file cannot be opened.
    pub fn open(data_dir: &Path) -> Result<Self, EngineError> {
        let header_path = data_dir.join("headers.bin");
        let checkpoint_path = data_dir.join("checkpoint.bin");

        let header_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&header_path)
            ?;

        let checkpoint_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&checkpoint_path)
            ?;

        Ok(Self {
            header_file,
            write_len: 0,
            index: PrehashedMap::with_hasher(BuildPrehashedHasher),
            checkpoint_file,
            tip: TipInfo {
                hash: Hash256::ZERO,
                height: BlockHeight::ZERO,
            },
            data_dir: data_dir.to_owned(),
        })
    }

    fn header_path(&self) -> PathBuf {
        self.data_dir.join("headers.bin")
    }

    /// Rebuild the header index and tip from `headers.bin` + `checkpoint.bin`.
    ///
    /// # Errors
    /// Returns `EngineError::Io` on read or seek failure.
    pub fn recover(&mut self) -> Result<(), EngineError> {
        let mut cp_buf = [0u8; 4];
        let n = self.checkpoint_file.read(&mut cp_buf)?;
        let checkpoint_height = if n == 4 {
            u32::from_le_bytes(cp_buf)
        } else {
            0
        };

        self.index.clear();
        let header_path = self.header_path();
        if let Ok(mut hf) = File::open(&header_path) {
            let file_len = hf.seek(SeekFrom::End(0))?;
            hf.seek(SeekFrom::Start(0))?;
            let record_count = file_len / HEADER_RECORD_SIZE_U64;
            for _i in 0..record_count {
                let mut buf = [0u8; HEADER_RECORD_SIZE];
                if hf.read_exact(&mut buf).is_err() {
                    break;
                }
                let hash = Hash256::from_bytes(buf.read_hash(0));
                let height = buf.read_u32_le(112);
                if height <= checkpoint_height || checkpoint_height == 0 {
                    self.index.insert(hash, height);
                    self.tip = TipInfo {
                        hash,
                        height: BlockHeight::new(height),
                    };
                }
            }
            self.write_len = record_count * HEADER_RECORD_SIZE_U64;
        }

        Ok(())
    }

    /// Read a header by its block hash.
    ///
    /// # Errors
    /// Returns `EngineError::Io` on read failure.
    pub fn read_header(&self, hash: &Hash256) -> Result<Option<BlockHeader>, EngineError> {
        let Some(&height_u32) = self.index.get(hash) else {
            return Ok(None);
        };
        self.read_header_at(BlockHeight::new(height_u32))
    }

    /// Read a header by height, opening the file and seeking.
    ///
    /// # Errors
    /// Returns `EngineError::Io` on open, seek or read failure.
    pub fn read_header_at(&self, h: BlockHeight) -> Result<Option<BlockHeader>, EngineError> {
        let offset = u64::from(h.to_u32()) * HEADER_RECORD_SIZE_U64;
        let mut f = File::open(self.header_path())?;
        let file_len = f.seek(SeekFrom::End(0))?;
        if offset + HEADER_RECORD_SIZE_U64 > file_len {
            return Ok(None);
        }
        f.seek(SeekFrom::Start(offset))?;
        read_header_record(&mut f).map(Some)
    }

    /// Append a header record and update the in-memory index.
    ///
    /// # Errors
    /// Returns `EngineError::Io` on write failure.
    pub fn write_header(
        &mut self,
        h: BlockHeight,
        header: &BlockHeader,
    ) -> Result<(), EngineError> {
        let hash = header.hash();
        self.write_len = write_header_record(
            &mut self.header_file,
            h,
            header,
            hash,
            self.write_len,
        )?;
        self.index.insert(hash, h.to_u32());
        Ok(())
    }

    /// Write a header record and update both index and tip.
    ///
    /// # Errors
    /// Returns `EngineError::Io` on write failure.
    pub fn write_block_header(
        &mut self,
        h: BlockHeight,
        header: &BlockHeader,
        hash: Hash256,
    ) -> Result<(), EngineError> {
        self.write_len = write_header_record(
            &mut self.header_file,
            h,
            header,
            hash,
            self.write_len,
        )?;
        self.index.insert(hash, h.to_u32());
        self.tip = TipInfo { hash, height: h };
        Ok(())
    }

    /// Borrow the underlying header file (e.g. for `pread`-based reads).
    #[must_use]
    pub fn file(&self) -> &File {
        &self.header_file
    }

    /// Flush and sync header + checkpoint files.
    ///
    /// # Errors
    /// Returns `EngineError::Io` on flush, seek, write or sync failure.
    pub fn sync_checkpoint(&mut self) -> Result<(), EngineError> {
        self.header_file.flush()?;
        self.header_file.sync_all()?;
        self.checkpoint_file
            .seek(SeekFrom::Start(0))
            ?;
        let h = self.tip.height.to_u32().to_le_bytes();
        self.checkpoint_file.write_all(&h)?;
        self.checkpoint_file.sync_all()?;
        Ok(())
    }
}

/// Write the record for height `h` at its fixed offset `h * 116`, replacing
/// whatever was there, and return the new logical end of file. Writing in
/// place matters after a restart: records past the last checkpoint are stale
/// and must be overwritten, not followed.
///
/// # Errors
/// Returns `EngineError::Io` on write failure.
pub fn write_header_record(
    f: &mut File,
    h: BlockHeight,
    header: &BlockHeader,
    hash: Hash256,
    file_len: u64,
) -> Result<u64, EngineError> {
    use std::os::unix::fs::FileExt;
    let offset = u64::from(h.to_u32()) * HEADER_RECORD_SIZE_U64;
    let mut buf = [0u8; HEADER_RECORD_SIZE];
    buf[0..32].copy_from_slice(hash.as_bytes());
    buf[32..36].copy_from_slice(&header.version().to_le_bytes());
    buf[36..68].copy_from_slice(header.prev_block().as_bytes());
    buf[68..100].copy_from_slice(header.merkle_root().as_bytes());
    buf[100..104].copy_from_slice(&header.time().to_le_bytes());
    buf[104..108].copy_from_slice(&header.bits().to_le_bytes());
    buf[108..112].copy_from_slice(&header.nonce().to_le_bytes());
    buf[112..116].copy_from_slice(&h.to_u32().to_le_bytes());
    f.write_all_at(&buf, offset)?;
    Ok(file_len.max(offset + HEADER_RECORD_SIZE_U64))
}

/// Read exactly one header record from the current file position.
///
/// # Errors
/// Returns `EngineError::Io` if fewer than 116 bytes are available.
pub fn read_header_record(f: &mut File) -> Result<BlockHeader, EngineError> {
    let mut buf = [0u8; HEADER_RECORD_SIZE];
    f.read_exact(&mut buf)?;
    Ok(parse_header_record(&buf))
}

/// Decode a header record from a raw 116-byte buffer.
#[allow(clippy::cast_possible_wrap)]
#[must_use]
pub fn parse_header_record(buf: &[u8; HEADER_RECORD_SIZE]) -> BlockHeader {
    BlockHeader::new(
        BlockVersion::new(buf.read_u32_le(32) as i32),
        Hash256::from_bytes(buf.read_hash(36)),
        Hash256::from_bytes(buf.read_hash(68)),
        BlockTime::new(buf.read_u32_le(100)),
        CompactBits::new(buf.read_u32_le(104)),
        Nonce::new(buf.read_u32_le(108)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom};

    fn temp_file() -> (File, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = dir.path().join("headers.bin");
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .expect("failed to create temp file");
        (f, dir)
    }

    fn sample_header() -> (BlockHeight, BlockHeader, Hash256) {
        let prev = Hash256::from_bytes([0xAA; 32]);
        let merkle = Hash256::from_bytes([0xBB; 32]);
        let header = BlockHeader::new(
            BlockVersion::new(0x2000_0000),
            prev,
            merkle,
            BlockTime::new(1_700_000_000),
            CompactBits::new(0x1703_FFFF),
            Nonce::new(42),
        );
        let hash = Hash256::from_bytes([0xCC; 32]);
        (BlockHeight::new(0), header, hash)
    }

    #[test]
    fn round_trip() {
        let (height, header, hash) = sample_header();
        let (mut f, _dir) = temp_file();

        let new_len = write_header_record(&mut f, height, &header, hash, 0).unwrap();
        assert_eq!(new_len, HEADER_RECORD_SIZE_U64);

        f.seek(SeekFrom::Start(0)).unwrap();
        let got = read_header_record(&mut f).unwrap();

        assert_eq!(got.version().to_i32(), header.version().to_i32());
        assert_eq!(got.prev_block(), header.prev_block());
        assert_eq!(got.merkle_root(), header.merkle_root());
        assert_eq!(got.time().to_u32(), header.time().to_u32());
        assert_eq!(got.bits().to_u32(), header.bits().to_u32());
        assert_eq!(got.nonce().to_u32(), header.nonce().to_u32());
    }

    #[test]
    fn gap_filling() {
        let height = BlockHeight::new(5);
        let (_, header, hash) = sample_header();
        let (mut f, _dir) = temp_file();

        let new_len = write_header_record(&mut f, height, &header, hash, 0).unwrap();
        let expected = u64::from(5u32) * HEADER_RECORD_SIZE_U64 + HEADER_RECORD_SIZE_U64;
        assert_eq!(new_len, expected);

        let file_len = f.seek(SeekFrom::End(0)).unwrap();
        assert!(file_len >= expected);

        f.seek(SeekFrom::Start(u64::from(5u32) * HEADER_RECORD_SIZE_U64))
            .unwrap();
        let got = read_header_record(&mut f).unwrap();
        assert_eq!(got.version().to_i32(), header.version().to_i32());
        assert_eq!(got.prev_block(), header.prev_block());
    }

    #[test]
    fn parse_known_bytes() {
        let mut buf = [0u8; HEADER_RECORD_SIZE];

        buf[32..36].copy_from_slice(&0x2000_0000_i32.to_le_bytes());
        buf[36..68].copy_from_slice(&[0xAA; 32]);
        buf[68..100].copy_from_slice(&[0xBB; 32]);
        buf[100..104].copy_from_slice(&1_700_000_000_u32.to_le_bytes());
        buf[104..108].copy_from_slice(&0x1703_FFFF_u32.to_le_bytes());
        buf[108..112].copy_from_slice(&42_u32.to_le_bytes());

        let header = parse_header_record(&buf);
        assert_eq!(header.version().to_i32(), 0x2000_0000);
        assert_eq!(header.prev_block(), Hash256::from_bytes([0xAA; 32]));
        assert_eq!(header.merkle_root(), Hash256::from_bytes([0xBB; 32]));
        assert_eq!(header.time().to_u32(), 1_700_000_000);
        assert_eq!(header.bits().to_u32(), 0x1703_FFFF);
        assert_eq!(header.nonce().to_u32(), 42);
    }

    #[test]
    fn header_store_recover_empty() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = HeaderStore::open(dir.path()).unwrap();
        store.recover().unwrap();
        assert_eq!(store.tip.height, BlockHeight::ZERO);
        assert!(store.index.is_empty());
    }

    #[test]
    fn header_store_write_and_read() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = HeaderStore::open(dir.path()).unwrap();

        let (height, header, hash) = sample_header();
        store.write_block_header(height, &header, hash).unwrap();

        assert_eq!(store.tip.hash, hash);
        assert_eq!(store.tip.height, height);
        assert_eq!(store.index.get(&hash), Some(&0));

        let got = store.read_header(&hash).unwrap().unwrap();
        assert_eq!(got.prev_block(), header.prev_block());
    }

    fn chained(count: u32, nonce_base: u32) -> Vec<BlockHeader> {
        let mut prev = Hash256::ZERO;
        (0..count)
            .map(|i| {
                let header = BlockHeader::new(
                    BlockVersion::new(1),
                    prev,
                    Hash256::from_bytes([0x11; 32]),
                    BlockTime::new(1_700_000_000 + i),
                    CompactBits::new(0x1d00_ffff),
                    Nonce::new(nonce_base + i),
                );
                prev = header.hash();
                header
            })
            .collect()
    }

    #[test]
    fn headers_written_after_a_restart_replace_the_unsynced_ones() {
        let dir = tempfile::tempdir().unwrap();
        let headers = chained(10, 0);
        let mut written = headers[..5].to_vec();
        written.extend_from_slice(&chained(8, 1_000)[5..]);
        {
            let mut store = HeaderStore::open(dir.path()).unwrap();
            for (h, header) in (0u32..).zip(&written) {
                store
                    .write_block_header(BlockHeight::new(h), header, header.hash())
                    .unwrap();
                if h == 4 {
                    store.sync_checkpoint().unwrap();
                }
            }
        }
        let mut store = HeaderStore::open(dir.path()).unwrap();
        store.recover().unwrap();
        assert_eq!(store.tip.height, BlockHeight::new(4));
        for (h, header) in (5u32..).zip(&headers[5..]) {
            store
                .write_block_header(BlockHeight::new(h), header, header.hash())
                .unwrap();
        }
        for (h, header) in (0u32..).zip(&headers) {
            let got = store.read_header_at(BlockHeight::new(h)).unwrap().unwrap();
            assert_eq!(got.hash(), header.hash(), "height {h}");
        }
    }

    #[test]
    fn header_store_recover_after_write() {
        let dir = tempfile::tempdir().unwrap();
        let hash;
        {
            let mut store = HeaderStore::open(dir.path()).unwrap();
            let (height, header, h) = sample_header();
            hash = h;
            store.write_block_header(height, &header, hash).unwrap();
            store.sync_checkpoint().unwrap();
        }
        let mut store = HeaderStore::open(dir.path()).unwrap();
        store.recover().unwrap();
        assert_eq!(store.tip.hash, hash);
        assert_eq!(store.index.len(), 1);
    }
}
