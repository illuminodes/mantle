//! Block-IO CPU profiler — pprof-rs sampling analysis.
//!
//! Run with:
//!   cargo build --release --bin block-io-pprof
//!   ./target/release/block-io-pprof [SCENARIO]
//!
//! Without arguments, runs all scenarios. Pass a scenario name to run just one:
//!   ./target/release/block-io-pprof `write_sync_1m`
//!   ./target/release/block-io-pprof `read_sequential_1m`

#[path = "fixtures.rs"]
mod fixtures;

use fixtures::{make_block_data, make_header_bytes, seed_blocks, spawn_handle, tmp_dir};
use mantle::primitives::BlockHeight;
use std::hint::black_box;

#[path = "../pprof_common.rs"]
mod pprof_common;
use pprof_common::profile;

fn run_write_sync_1m() {
    let data = make_block_data(1_500_000);
    profile("write_sync_1m(100 blocks)", 5, || {
        let dir = tmp_dir("pprof-ws");
        let mut handle = spawn_handle(&dir);
        for h in 0..100u32 {
            handle
                .write_block(BlockHeight::new(h), black_box(data.clone()))
                .expect("write_block");
        }
        handle.shutdown();
    });
}

fn run_write_async_1m() {
    let data = make_block_data(1_500_000);
    profile("write_async_1m(100 blocks)", 5, || {
        let dir = tmp_dir("pprof-wa");
        let mut handle = spawn_handle(&dir);
        for h in 0..100u32 {
            handle
                .write_block_async(BlockHeight::new(h), black_box(data.clone()))
                .expect("write_block_async");
        }
        handle.shutdown();
    });
}

fn run_read_sequential_1m() {
    let data = make_block_data(1_500_000);
    let dir = tmp_dir("pprof-rs");
    let mut handle = spawn_handle(&dir);
    seed_blocks(&mut handle, 100, &data);
    handle.flush_block_index().expect("flush");

    profile("read_sequential_1m(100 blocks)", 5, || {
        for h in 0..100u32 {
            black_box(handle.read_block(BlockHeight::new(h)).expect("read"));
        }
    });

    handle.shutdown();
}

fn run_write_read_roundtrip() {
    let data = make_block_data(1_500_000);
    profile("write_read_roundtrip_1m(50 blocks)", 5, || {
        let dir = tmp_dir("pprof-rt");
        let mut handle = spawn_handle(&dir);
        for h in 0..50u32 {
            handle
                .write_block(BlockHeight::new(h), data.clone())
                .expect("write");
        }
        for h in 0..50u32 {
            black_box(handle.read_block(BlockHeight::new(h)).expect("read"));
        }
        handle.shutdown();
    });
}

fn run_header_load_10k() {
    let hdr_data = make_header_bytes(10_000);
    let dir = tmp_dir("pprof-hdr");
    let mut handle = spawn_handle(&dir);
    handle
        .write_headers(BlockHeight::new(1), hdr_data)
        .expect("write_headers");

    profile("header_load_10k", 3, || {
        black_box(
            handle
                .load_cached_headers(BlockHeight::new(1))
                .expect("load"),
        );
    });

    handle.shutdown();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let filter = args.get(1).map(String::as_str);

    let scenarios: &[(&str, fn())] = &[
        ("write_sync_1m", run_write_sync_1m),
        ("write_async_1m", run_write_async_1m),
        ("read_sequential_1m", run_read_sequential_1m),
        ("write_read_roundtrip", run_write_read_roundtrip),
        ("header_load_10k", run_header_load_10k),
    ];

    let mut ran = 0;
    for &(name, f) in scenarios {
        if filter.is_none() || filter == Some(name) {
            f();
            ran += 1;
        }
    }

    if ran == 0 {
        eprintln!("no matching scenario — available:");
        for &(name, _) in scenarios {
            eprintln!("  {name}");
        }
        std::process::exit(1);
    }
}
