//! dhat heap profiler — sustained N-block window replay.
//!
//! Companion to `replay-perf-window`. Replays a contiguous window of blocks
//! through one growing storage instance and writes `dhat-heap.json` on exit
//! showing where allocations come from.
//!
//! Usage:
//!   cargo build --release --bin replay-dhat-window
//!   ./target/release/replay-dhat-window --preset early [--blocks N] [--reuse]

#![allow(clippy::cast_precision_loss)]

use std::path::PathBuf;

use mantle::primitives::BlockHeight;
use mantle_storage::types::Durability;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[path = "fixtures_common.rs"]
mod fixtures_common;
use fixtures_common::{
    BenchReplayBufs, fixtures_dir, headers_from_blocks, load_block_bytes, load_headers,
    make_snapshot, replay_block_ref, replay_block_ref_reusing, tmp_storage, tmp_storage_robin_hood,
};

struct Args {
    preset: String,
    blocks: u32,
    reuse: bool,
    robin_hood: bool,
    synced: bool,
}

fn parse_args() -> Args {
    let mut preset = "early".to_string();
    let mut blocks: u32 = 1000;
    let mut reuse = false;
    let mut robin_hood = false;
    let mut synced = false;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--preset" => preset = it.next().expect("--preset needs value"),
            "--blocks" => {
                blocks = it
                    .next()
                    .expect("--blocks needs value")
                    .parse()
                    .expect("u32");
            }
            "--reuse" => reuse = true,
            "--robin-hood" => robin_hood = true,
            "--synced" => synced = true,
            "--help" | "-h" => {
                eprintln!(
                    "usage: replay-dhat-window --preset {{early|ordinals}} [--blocks N] [--reuse] [--robin-hood] [--synced]"
                );
                std::process::exit(0);
            }
            other => panic!("unknown arg: {other}"),
        }
    }
    Args {
        preset,
        blocks,
        reuse,
        robin_hood,
        synced,
    }
}


#[allow(clippy::too_many_lines)]
fn main() {
    let args = parse_args();

    let dir: PathBuf = fixtures_dir(&args.preset);
    // Load blocks+1 so the first block can be used as a warm-up outside the
    // profiler window, leaving exactly `blocks` measured.
    let total = args.blocks + 1;
    let (start, end, headers, dummy_on_miss) = match args.preset.as_str() {
        "early" => {
            let start = 1u32;
            let end = start + total - 1;
            let headers = headers_from_blocks(&dir, start, end);
            (start, end, headers, false)
        }
        "ordinals" => {
            let start = 767_430u32;
            let end = start + total - 1;
            let headers = load_headers(&dir);
            assert!(
                headers.len() >= total as usize,
                "ordinals headers.bin has {} headers, need {}",
                headers.len(),
                total
            );
            (start, end, headers[..total as usize].to_vec(), true)
        }
        other => panic!("unknown preset: {other} (expected 'early' or 'ordinals')"),
    };

    let snap = make_snapshot(&headers, start);

    eprintln!(
        "[dhat-{}] loading {} blocks (heights {}..={}) reuse={} robin_hood={}",
        args.preset, args.blocks, start, end, args.reuse, args.robin_hood
    );
    let wires: Vec<Vec<u8>> = (start..=end).map(|h| load_block_bytes(&dir, h)).collect();

    let tag = format!("replay-dhat-window-{}", args.preset);
    let (mut storage, _tmp) = if args.robin_hood {
        tmp_storage_robin_hood(&tag)
    } else {
        tmp_storage(&tag)
    };
    let mut arena: Vec<u8> = Vec::new();

    // Warm up all scratch buffers (BenchReplayBufs, arena, engine internals) with
    // the first block before starting the profiler, so harness growth doesn't
    // pollute the allocation profile.
    let block_durability = |h: u32| {
        if args.synced && h.is_multiple_of(2016) {
            Durability::Synced
        } else {
            Durability::Memory
        }
    };

    eprintln!(
        "[dhat-{}] warming up... synced={}",
        args.preset, args.synced
    );
    if args.reuse {
        let mut bufs = BenchReplayBufs::new();
        let mut txs_scratch = Vec::new();
        replay_block_ref_reusing(
            &wires[0],
            BlockHeight::new(start),
            &mut storage,
            &snap,
            1,
            dummy_on_miss,
            block_durability(start),
            &mut arena,
            &mut bufs,
            &mut txs_scratch,
        );

        eprintln!("[dhat-{}] replaying...", args.preset);
        let _profiler = dhat::Profiler::new_heap();
        for (i, wire) in wires[1..].iter().enumerate() {
            let h = start + 1 + u32::try_from(i).expect("fits");
            let height = BlockHeight::new(h);
            let token = u64::try_from(i + 2).expect("fits");
            replay_block_ref_reusing(
                wire,
                height,
                &mut storage,
                &snap,
                token,
                dummy_on_miss,
                block_durability(h),
                &mut arena,
                &mut bufs,
                &mut txs_scratch,
            );
        }
    } else {
        replay_block_ref(
            &wires[0],
            BlockHeight::new(start),
            &mut storage,
            &snap,
            1,
            dummy_on_miss,
            &mut arena,
        );

        eprintln!("[dhat-{}] replaying...", args.preset);
        let _profiler = dhat::Profiler::new_heap();
        for (i, wire) in wires[1..].iter().enumerate() {
            let height = BlockHeight::new(start + 1 + u32::try_from(i).expect("fits"));
            let token = u64::try_from(i + 2).expect("fits");
            replay_block_ref(
                wire,
                height,
                &mut storage,
                &snap,
                token,
                dummy_on_miss,
                &mut arena,
            );
        }
    }

    storage.shutdown().expect("shutdown");
    eprintln!("[dhat-{}] done; dhat-heap.json written", args.preset);
}
