#![allow(dead_code)]

use std::path::PathBuf;

use mantle::primitives::BlockHeight;
use mantle_block_io::FileIoHandle;

pub const ITERS_SMALL: u32 = 200;
pub const ITERS_MEDIUM: u32 = 1_000;

pub const SMALL_BLOCK: usize = 500;
pub const TYPICAL_BLOCK: usize = 1_500_000;
pub const LARGE_BLOCK: usize = 4_000_000;

pub fn make_block_data(size: usize) -> Vec<u8> {
    #[allow(clippy::cast_possible_truncation)]
    (0..size).map(|i| (i % 251) as u8).collect()
}

pub struct TmpDir(pub PathBuf);
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn tmp_dir(tag: &str) -> TmpDir {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let path = std::env::temp_dir().join(format!("mantle-blockio-{tag}-{}-{ns}", std::process::id()));
    std::fs::create_dir_all(&path).expect("create tmp dir");
    TmpDir(path)
}

pub fn spawn_handle(dir: &TmpDir) -> FileIoHandle {
    FileIoHandle::spawn(&dir.0).expect("FileIoHandle::spawn")
}

pub fn seed_blocks(handle: &mut FileIoHandle, count: u32, data: &[u8]) {
    for h in 0..count {
        handle
            .write_block(BlockHeight::new(h), data.to_vec())
            .expect("write_block");
    }
}

pub fn make_header_bytes(count: usize) -> Vec<u8> {
    vec![0xABu8; count * 80]
}
