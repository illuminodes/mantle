use mantle::primitives::{BlockHeader, BlockHeight, Hash256};
use mantle_block_io::FileIoHandle;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

fn main() {
    divan::main();
}

struct TmpDir(PathBuf);
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tmp_dir(tag: &str) -> TmpDir {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let path =
        std::env::temp_dir().join(format!("mantle-blockio-{tag}-{}-{ns}", std::process::id()));
    std::fs::create_dir_all(&path).expect("create tmp dir");
    TmpDir(path)
}

fn make_block_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

// ── Write throughput ─────────────────────────────────────────────────────────

mod write {
    use super::*;

    #[divan::bench(args = [500usize, 1_500_000, 4_000_000])]
    fn write_block_sync(bencher: divan::Bencher, size: usize) {
        let data = make_block_data(size);
        bencher.bench_local(|| {
            let dir = tmp_dir("write-sync");
            let mut handle = FileIoHandle::spawn(&dir.0).expect("spawn");
            for h in 0..100u32 {
                handle
                    .write_block(BlockHeight::new(h), black_box(data.clone()))
                    .expect("write_block");
            }
            handle.shutdown();
        });
    }

    #[divan::bench(args = [500usize, 1_500_000, 4_000_000])]
    fn write_block_async(bencher: divan::Bencher, size: usize) {
        let data = make_block_data(size);
        bencher.bench_local(|| {
            let dir = tmp_dir("write-async");
            let handle = FileIoHandle::spawn(&dir.0).expect("spawn");
            for h in 0..100u32 {
                handle
                    .write_block_async(BlockHeight::new(h), black_box(data.clone()))
                    .expect("write_block_async");
            }
            // shutdown flushes the worker queue
            let mut handle = handle;
            handle.shutdown();
        });
    }
}

// ── Read throughput ──────────────────────────────────────────────────────────

mod read {
    use super::*;

    #[divan::bench(args = [500usize, 1_500_000, 4_000_000])]
    fn read_block_sequential(bencher: divan::Bencher, size: usize) {
        let data = make_block_data(size);
        let dir = tmp_dir("read-seq");
        let mut handle = FileIoHandle::spawn(&dir.0).expect("spawn");
        for h in 0..100u32 {
            handle
                .write_block(BlockHeight::new(h), data.clone())
                .expect("seed");
        }
        handle.flush_block_index().expect("flush");

        bencher.bench_local(|| {
            for h in 0..100u32 {
                black_box(handle.read_block(BlockHeight::new(h)).expect("read"));
            }
        });

        handle.shutdown();
    }

    #[divan::bench(args = [500usize, 1_500_000])]
    fn read_block_random(bencher: divan::Bencher, size: usize) {
        let data = make_block_data(size);
        let dir = tmp_dir("read-rand");
        let mut handle = FileIoHandle::spawn(&dir.0).expect("spawn");
        for h in 0..100u32 {
            handle
                .write_block(BlockHeight::new(h), data.clone())
                .expect("seed");
        }
        handle.flush_block_index().expect("flush");

        let pattern: Vec<u32> = (0..100u32)
            .map(|i| (i.wrapping_mul(37).wrapping_add(13)) % 100)
            .collect();

        bencher.bench_local(|| {
            for &h in &pattern {
                black_box(handle.read_block(BlockHeight::new(h)).expect("read"));
            }
        });

        handle.shutdown();
    }
}

// ── Index operations ─────────────────────────────────────────────────────────

mod index {
    use super::*;

    #[divan::bench(args = [100u32, 1000, 5000])]
    fn flush_block_index(bencher: divan::Bencher, count: u32) {
        let data = make_block_data(500);
        let dir = tmp_dir("idx-flush");
        let mut handle = FileIoHandle::spawn(&dir.0).expect("spawn");
        for h in 0..count {
            handle
                .write_block(BlockHeight::new(h), data.clone())
                .expect("seed");
        }

        bencher.bench_local(|| {
            handle.flush_block_index().expect("flush");
        });

        handle.shutdown();
    }

    #[divan::bench(args = [100u32, 1000])]
    fn has_block(bencher: divan::Bencher, count: u32) {
        let data = make_block_data(500);
        let dir = tmp_dir("idx-has");
        let mut handle = FileIoHandle::spawn(&dir.0).expect("spawn");
        for h in 0..count {
            handle
                .write_block(BlockHeight::new(h), data.clone())
                .expect("seed");
        }

        bencher.bench_local(|| {
            for h in 0..count {
                black_box(handle.has_block(BlockHeight::new(h)));
            }
        });

        handle.shutdown();
    }
}

// ── Header operations ────────────────────────────────────────────────────────

mod headers {
    use super::*;

    #[divan::bench(args = [100usize, 1000, 10_000])]
    fn write_headers(bencher: divan::Bencher, count: usize) {
        let data = vec![0xABu8; count * 80];
        bencher.bench_local(|| {
            let dir = tmp_dir("hdr-write");
            let mut handle = FileIoHandle::spawn(&dir.0).expect("spawn");
            handle
                .write_headers(BlockHeight::new(1), black_box(data.clone()))
                .expect("write_headers");
            handle.shutdown();
        });
    }

    #[divan::bench(args = [100usize, 1000, 10_000])]
    fn load_cached_headers(bencher: divan::Bencher, count: usize) {
        let data = vec![0xABu8; count * 80];
        let dir = tmp_dir("hdr-load");
        let mut handle = FileIoHandle::spawn(&dir.0).expect("spawn");
        handle
            .write_headers(BlockHeight::new(1), data)
            .expect("seed");

        bencher.bench_local(|| {
            black_box(
                handle
                    .load_cached_headers(BlockHeight::new(1))
                    .expect("load"),
            );
        });

        handle.shutdown();
    }
}

// ── Decoded vs raw read (real mainnet blocks) ────────────────────────────────

struct FixtureBlocks {
    start: u32,
    raw: Vec<Vec<u8>>,
    hashes: Vec<Hash256>,
}

fn load_fixture_blocks() -> Option<&'static FixtureBlocks> {
    static CELL: OnceLock<Option<FixtureBlocks>> = OnceLock::new();
    CELL.get_or_init(|| {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
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
        let n_headers = hdr_bytes.len() / 80;
        let n = n_headers.min(100);
        let blocks_dir = dir.join("blocks");
        let mut raw = Vec::with_capacity(n);
        let mut hashes = Vec::with_capacity(n);
        for h in start..start + u32::try_from(n).unwrap() {
            let bytes = std::fs::read(blocks_dir.join(format!("{h:07}.bin"))).ok()?;
            let header = BlockHeader::from_bytes(bytes[..80].try_into().unwrap());
            hashes.push(header.hash());
            raw.push(bytes);
        }

        Some(FixtureBlocks {
            start,
            raw,
            hashes,
        })
    })
    .as_ref()
}

fn seed_fixture_store(handle: &mut FileIoHandle, fix: &FixtureBlocks) {
    for (i, bytes) in fix.raw.iter().enumerate() {
        let h = fix.start + u32::try_from(i).unwrap();
        handle
            .write_block(BlockHeight::new(h), bytes.clone())
            .expect("seed");
    }
    handle.flush_block_index().expect("flush");
}

mod decoded {
    use super::*;
    use mantle::primitives::BlockRef;

    #[divan::bench]
    fn read_slab_zero_copy_100(bencher: divan::Bencher) {
        let Some(fix) = load_fixture_blocks() else {
            eprintln!("fixtures/ordinals/ not found — skipping");
            return;
        };
        let dir = tmp_dir("dec-slab");

        mantle_block_io::with_file_io(&dir.0, |handle, slab_reader| {
            for (i, bytes) in fix.raw.iter().enumerate() {
                let h = fix.start + u32::try_from(i).unwrap();
                handle
                    .write_block(BlockHeight::new(h), bytes.clone())
                    .expect("seed");
            }
            handle.flush_block_index().expect("flush");

            bencher.bench_local(|| {
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
            });

            handle.shutdown();
        })
        .expect("with_file_io");
    }

    #[divan::bench]
    fn read_then_decode_100(bencher: divan::Bencher) {
        use mantle::codec::Decode;
        use mantle::primitives::Block;

        let Some(fix) = load_fixture_blocks() else {
            eprintln!("fixtures/ordinals/ not found — skipping");
            return;
        };
        let dir = tmp_dir("dec-then");
        let mut handle = FileIoHandle::spawn(&dir.0).expect("spawn");
        seed_fixture_store(&mut handle, fix);

        bencher.bench_local(|| {
            for i in 0..fix.raw.len() {
                let h = fix.start + u32::try_from(i).unwrap();
                let bytes = handle.read_block(BlockHeight::new(h)).expect("read");
                let block = Block::decode(&mut std::io::Cursor::new(&bytes)).expect("decode");
                assert_eq!(block.header.hash(), fix.hashes[i]);
                black_box(block);
            }
        });

        handle.shutdown();
    }

    #[divan::bench]
    fn read_block_decoded_100(bencher: divan::Bencher) {
        let Some(fix) = load_fixture_blocks() else {
            eprintln!("fixtures/ordinals/ not found — skipping");
            return;
        };
        let dir = tmp_dir("dec-decoded");
        let mut handle = FileIoHandle::spawn(&dir.0).expect("spawn");
        seed_fixture_store(&mut handle, fix);

        bencher.bench_local(|| {
            for i in 0..fix.raw.len() {
                let h = fix.start + u32::try_from(i).unwrap();
                black_box(
                    handle
                        .read_block_decoded(BlockHeight::new(h), fix.hashes[i])
                        .expect("read_decoded"),
                );
            }
        });

        handle.shutdown();
    }
}
