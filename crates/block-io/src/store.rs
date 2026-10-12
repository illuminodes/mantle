use std::fs;
use std::io;
use std::path::Path;

use mantle::primitives::{BlockHeader, BlockHeight};
use ququmatz::IoUring;
use ququmatz::types::RawFd;

// ── File-backed store ──────────────────────────────────────────────────────

pub struct FileStore {
    #[allow(dead_code)]
    file: fs::File,
    fd: RawFd,
    pub(crate) write_offset: u64,
}

impl FileStore {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        let write_offset = file.metadata()?.len();
        let fd = file_to_rawfd(&file);
        Ok(Self {
            file,
            fd,
            write_offset,
        })
    }

    pub fn fd(&self) -> RawFd {
        self.fd
    }

    pub fn uring_read(&self, ring: &mut IoUring, offset: u64, len: u32) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; usize::try_from(len).expect("read length fits in usize")];
        // SAFETY: `buf` outlives the loop below, which blocks until this read completes.
        let sqe = unsafe { ququmatz::Sqe::read(self.fd, &mut buf, offset) }.user_data(u64::MAX);
        ring.push(sqe)
            .map_err(|e| io::Error::other(format!("{e:?}")))?;
        loop {
            ring.submit_and_wait(1)
                .map_err(|e| io::Error::other(format!("{e:?}")))?;
            while let Some(cqe) = ring.complete() {
                if cqe.user_data() == u64::MAX {
                    if cqe.raw_result() < 0 {
                        return Err(io::Error::from_raw_os_error(-cqe.raw_result()));
                    }
                    return Ok(buf);
                }
            }
        }
    }

    pub fn uring_write(&self, ring: &mut IoUring, data: &[u8], offset: u64) -> io::Result<()> {
        // SAFETY: `data` outlives the loop below, which blocks until this write completes.
        let sqe = unsafe { ququmatz::Sqe::write(self.fd, data, offset) }.user_data(u64::MAX);
        ring.push(sqe)
            .map_err(|e| io::Error::other(format!("{e:?}")))?;
        loop {
            ring.submit_and_wait(1)
                .map_err(|e| io::Error::other(format!("{e:?}")))?;
            while let Some(cqe) = ring.complete() {
                if cqe.user_data() == u64::MAX {
                    if cqe.raw_result() < 0 {
                        return Err(io::Error::from_raw_os_error(-cqe.raw_result()));
                    }
                    return Ok(());
                }
            }
        }
    }

    pub fn append(&mut self, ring: &mut IoUring, data: &[u8]) -> io::Result<u64> {
        let offset = self.write_offset;
        self.uring_write(ring, data, offset)?;
        self.write_offset += u64::try_from(data.len()).expect("data length fits in u64");
        Ok(offset)
    }

    pub fn truncate_and_write(&mut self, ring: &mut IoUring, data: &[u8]) -> io::Result<()> {
        self.truncate()?;
        self.append(ring, data)?;
        Ok(())
    }

    pub fn truncate(&mut self) -> io::Result<()> {
        self.file.set_len(0)?;
        self.write_offset = 0;
        Ok(())
    }
}

// ── Block store ────────────────────────────────────────────────────────────

const BLOCK_INDEX_ENTRY_SIZE: usize = 12;

#[derive(Clone, Copy, Default)]
struct BlockEntry {
    offset: u64,
    length: u32,
}

impl BlockEntry {
    fn is_present(self) -> bool {
        self.length > 0
    }
}

pub struct BlockStore {
    store: FileStore,
    index: Vec<BlockEntry>,
}

impl BlockStore {
    pub fn open(data_dir: &Path) -> io::Result<Self> {
        let store = FileStore::open(&data_dir.join("blocks.bin"))?;
        let index = load_blocks_index(&data_dir.join("blocks.idx"))?;
        Ok(Self { store, index })
    }

    pub fn has_block(&self, height: BlockHeight) -> bool {
        let h = usize::try_from(height.to_u32()).expect("block height fits in usize");
        self.index.get(h).copied().unwrap_or_default().is_present()
    }

    pub fn read(&self, ring: &mut IoUring, height: BlockHeight) -> io::Result<Vec<u8>> {
        let (offset, length) = self.block_location(height)?;
        self.store.uring_read(ring, offset, length)
    }

    pub fn block_location(&self, height: BlockHeight) -> io::Result<(u64, u32)> {
        let h = usize::try_from(height.to_u32()).expect("block height fits in usize");
        let entry = self.index.get(h).copied().unwrap_or_default();
        if !entry.is_present() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("block {} not in index", height.to_u32()),
            ));
        }
        Ok((entry.offset, entry.length))
    }

    pub fn file_store(&self) -> &FileStore {
        &self.store
    }

    pub fn write(
        &mut self,
        ring: &mut IoUring,
        height: BlockHeight,
        data: &[u8],
    ) -> io::Result<()> {
        let offset = self.store.append(ring, data)?;
        let h = usize::try_from(height.to_u32()).expect("block height fits in usize");
        if h >= self.index.len() {
            self.index.resize(h + 1, BlockEntry::default());
        }
        self.index[h] = BlockEntry {
            offset,
            length: u32::try_from(data.len()).expect("block data length fits in u32"),
        };
        Ok(())
    }

    pub fn flush_index(&self, data_dir: &Path) -> io::Result<()> {
        save_blocks_index(&data_dir.join("blocks.idx"), &self.index)
    }

    pub fn discard_all(&mut self, data_dir: &Path) -> io::Result<()> {
        self.store.truncate()?;
        self.index.clear();
        self.flush_index(data_dir)
    }
}

// ── Header store ───────────────────────────────────────────────────────────

const HEADER_RECORD_SIZE: usize = 80;

pub struct HeaderStore {
    store: FileStore,
    metadata: FileStore,
}

impl HeaderStore {
    pub fn open(data_dir: &Path) -> io::Result<Self> {
        let store = FileStore::open(&data_dir.join("chain_headers.bin"))?;
        let metadata = FileStore::open(&data_dir.join("metadata.bin"))?;
        Ok(Self { store, metadata })
    }

    pub fn load_cached(
        &self,
        ring: &mut IoUring,
        start: BlockHeight,
    ) -> io::Result<Vec<(BlockHeight, BlockHeader)>> {
        if self.metadata.write_offset < 4 || self.store.write_offset == 0 {
            return Ok(Vec::new());
        }
        let meta_bytes = self.metadata.uring_read(ring, 0, 4)?;
        let cached_start = u32::from_le_bytes(
            meta_bytes[..4]
                .try_into()
                .expect("metadata slice is exactly 4 bytes"),
        );
        if cached_start != start.to_u32() {
            return Ok(Vec::new());
        }
        let count = usize::try_from(self.store.write_offset).expect("write_offset fits in usize")
            / HEADER_RECORD_SIZE;
        if count == 0 {
            return Ok(Vec::new());
        }
        let data = self.store.uring_read(
            ring,
            0,
            u32::try_from(self.store.write_offset).expect("header file size fits in u32"),
        )?;
        let mut headers = Vec::with_capacity(count);
        for (i, chunk) in data.chunks_exact(HEADER_RECORD_SIZE).enumerate() {
            let arr: &[u8; 80] = chunk
                .try_into()
                .expect("chunks_exact guarantees 80-byte slice");
            let hdr = BlockHeader::from_slice(arr);
            let idx = u32::try_from(i).expect("header index fits in u32");
            headers.push((BlockHeight::new(start.to_u32() + idx), hdr));
        }
        Ok(headers)
    }

    pub fn write_raw(
        &mut self,
        ring: &mut IoUring,
        start: BlockHeight,
        data: &[u8],
    ) -> io::Result<()> {
        self.store.truncate_and_write(ring, data)?;
        self.store.file.sync_data()?;
        self.metadata
            .truncate_and_write(ring, &start.to_u32().to_le_bytes())?;
        self.metadata.file.sync_data()
    }

    pub fn append_raw(&mut self, ring: &mut IoUring, data: &[u8]) -> io::Result<()> {
        self.store.append(ring, data)?;
        self.store.file.sync_data()
    }
}

// ── Block index I/O ────────────────────────────────────────────────────────

fn load_blocks_index(path: &Path) -> io::Result<Vec<BlockEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read(path)?;
    let count = data.len() / BLOCK_INDEX_ENTRY_SIZE;
    let mut index = Vec::with_capacity(count);
    for chunk in data.chunks_exact(BLOCK_INDEX_ENTRY_SIZE) {
        let offset = u64::from_le_bytes(
            chunk[..8]
                .try_into()
                .expect("index chunk has 8 bytes for offset"),
        );
        let length = u32::from_le_bytes(
            chunk[8..12]
                .try_into()
                .expect("index chunk has 4 bytes for length"),
        );
        index.push(BlockEntry { offset, length });
    }
    Ok(index)
}

fn save_blocks_index(path: &Path, index: &[BlockEntry]) -> io::Result<()> {
    let mut data = Vec::with_capacity(index.len() * BLOCK_INDEX_ENTRY_SIZE);
    for entry in index {
        data.extend_from_slice(&entry.offset.to_le_bytes());
        data.extend_from_slice(&entry.length.to_le_bytes());
    }
    fs::write(path, &data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_store_open_creates_file() {
        let dir = std::env::temp_dir().join(format!("mantle_store_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("test_store.bin");

        let store = FileStore::open(&path).expect("FileStore::open");
        assert_eq!(store.write_offset, 0);
        assert!(path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(unix)]
fn file_to_rawfd(file: &fs::File) -> RawFd {
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    RawFd::from_raw(usize::try_from(fd).expect("file descriptor is non-negative"))
}
