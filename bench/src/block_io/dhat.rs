//! Block-IO heap profiler — dhat allocation analysis.
//!
//! Exercises the zero-copy `ReadBlockSlab` → `BlockRef` path.
//!
//! Run with:
//!   cargo build --release --bin block-io-dhat
//!   ./target/release/block-io-dhat

#[path = "fixtures.rs"]
mod fixtures;

use fixtures::tmp_dir;
use mantle::primitives::{BlockHeader, BlockHeight, BlockRef, Hash256};
use std::hint::black_box;
use std::path::{Path, PathBuf};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("ordinals")
}

struct FixtureBlocks {
    start: u32,
    raw: Vec<Vec<u8>>,
    hashes: Vec<Hash256>,
}

fn load_fixtures(n: usize) -> Option<FixtureBlocks> {
    let dir = fixtures_dir();
    let meta = std::fs::read(dir.join("metadata.bin")).ok()?;
    if meta.len() < 4 {
        return None;
    }
    let start = u32::from_le_bytes([meta[0], meta[1], meta[2], meta[3]]);
    let blocks_dir = dir.join("blocks");
    let mut raw = Vec::with_capacity(n);
    let mut hashes = Vec::with_capacity(n);
    for h in start..start + u32::try_from(n).unwrap() {
        let bytes = std::fs::read(blocks_dir.join(format!("{h:07}.bin"))).ok()?;
        let header = BlockHeader::from_bytes(bytes[..80].try_into().unwrap());
        hashes.push(header.hash());
        raw.push(bytes);
    }
    Some(FixtureBlocks { start, raw, hashes })
}

fn main() {
    let _profiler = dhat::Profiler::new_heap();

    let Some(fix) = load_fixtures(20) else {
        eprintln!("fixtures/ordinals/ not found — nothing to profile");
        return;
    };
    let dir = tmp_dir("dhat-slab");

    mantle_block_io::with_file_io(&dir.0, |handle, slab_reader| {
        for (i, bytes) in fix.raw.iter().enumerate() {
            let h = fix.start + u32::try_from(i).unwrap();
            handle
                .write_block(BlockHeight::new(h), bytes.clone())
                .expect("seed");
        }
        handle.flush_block_index().expect("flush");

        for _ in 0..20 {
            for i in 0..fix.raw.len() {
                let h = fix.start + u32::try_from(i).unwrap();
                let token = handle
                    .read_block_slab(BlockHeight::new(h))
                    .expect("read_slab");
                let buf_handle = slab_reader.handle(token);
                let mut arena = Vec::new();
                let mut txs_buf = Vec::new();
                let block_ref = BlockRef::decode_with_arena(
                    buf_handle.as_slice(),
                    &mut arena,
                    &mut txs_buf,
                )
                .expect("decode");
                assert_eq!(block_ref.header.hash(), fix.hashes[i]);
                black_box(&block_ref);
                handle.release_slab(buf_handle.slot);
            }
        }
        eprintln!("read_slab + BlockRef::decode (20 blocks): 20 iters done");
        handle.shutdown();
    })
    .expect("with_file_io");

    eprintln!("done — dhat summary follows");
}
