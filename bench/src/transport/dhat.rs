//! Transport heap profiler — dhat allocation analysis.
//!
//! Run with:
//!   cargo build --release --bin transport-dhat
//!   ./target/release/transport-dhat

#[path = "fixtures.rs"]
#[allow(clippy::wildcard_imports)]
mod fixtures;

use fixtures::{make_pool_half_full, mainnet_magic, ITERS_LARGE, ITERS_MEDIUM, ITERS_SMALL};
use mantle::network::Command;
use mantle_transport::{CqeData, Op, SendArena};
use std::hint::black_box;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[allow(clippy::too_many_lines)]
fn main() {
    let _profiler = dhat::Profiler::new_heap();

    // ── CqeData encode/decode (10000 iters) ────────────────────────────────
    {
        for i in 0..ITERS_LARGE {
            #[allow(clippy::cast_possible_truncation)]
            let slot = i as u16;
            let raw = CqeData::encode(black_box(slot), black_box(7), Op::Recv);
            black_box(CqeData::decode(raw));
        }
        eprintln!("cqe_roundtrip: {ITERS_LARGE} iters done");
    }

    // ── CqeData encode_send/decode_send_seq (10000 iters) ──────────────────
    {
        for i in 0..ITERS_LARGE {
            #[allow(clippy::cast_possible_truncation)]
            let slot = i as u16;
            let raw = CqeData::encode_send(black_box(slot), black_box(7), black_box(slot));
            black_box(CqeData::decode_send_seq(raw));
        }
        eprintln!("cqe_send_roundtrip: {ITERS_LARGE} iters done");
    }

    // ── SendArena: alloc/release cycle (10000 iters) ───────────────────────
    {
        let mut arena = SendArena::new();
        let magic = mainnet_magic();
        for _ in 0..ITERS_LARGE {
            let seq = arena
                .frame_into(magic, Command::Verack, &[])
                .expect("should allocate");
            arena.release(seq);
        }
        eprintln!("arena_alloc_release: {ITERS_LARGE} iters done");
    }

    // ── SendArena: frame_into with payload (2000 iters) ────────────────────
    {
        let mut arena = SendArena::new();
        let magic = mainnet_magic();
        let payload = vec![0xab_u8; 256];
        for _ in 0..ITERS_MEDIUM {
            let seq = arena
                .frame_into(magic, Command::Inv, &payload)
                .expect("should allocate");
            arena.release(seq);
        }
        eprintln!("arena_frame_256b: {ITERS_MEDIUM} iters done");
    }

    // ── SendArena: burst alloc then release (500 bursts of 64) ─────────────
    {
        let mut arena = SendArena::new();
        let magic = mainnet_magic();
        let mut seqs = Vec::with_capacity(64);
        for _ in 0..ITERS_SMALL {
            seqs.clear();
            for _ in 0..64 {
                if let Some(seq) = arena.frame_into(magic, Command::Verack, &[]) {
                    seqs.push(seq);
                }
            }
            for &seq in &seqs {
                arena.release(seq);
            }
        }
        eprintln!("arena_burst_64: {ITERS_SMALL} bursts done");
    }

    // ── PeerPool: iter_mut scan (2000 iters) ───────────────────────────────
    {
        let mut pool = make_pool_half_full();
        for _ in 0..ITERS_MEDIUM {
            for (_slot, peer) in pool.iter_mut() {
                black_box(&peer.state);
            }
        }
        eprintln!("pool_iter_mut: {ITERS_MEDIUM} iters done");
    }

    // ── PeerPool: dead_slots collection (2000 iters) ───────────────────────
    {
        let mut pool = make_pool_half_full();
        for _ in 0..ITERS_MEDIUM {
            black_box(pool.dead_slots());
        }
        eprintln!("pool_dead_slots: {ITERS_MEDIUM} iters done");
    }

    // ── Version message encoding (2000 iters) ──────────────────────────────
    {
        let mut buf = Vec::new();
        for _ in 0..ITERS_MEDIUM {
            mantle_transport::encode_version("mantle:0.1.0", &mut buf);
            black_box(buf.len());
        }
        eprintln!("encode_version: {ITERS_MEDIUM} iters done");
    }

    eprintln!("all scenarios complete — dhat summary follows");
}
