use std::hint::black_box;
use std::net::SocketAddrV4;
use std::time::Instant;

use mantle::network::{Command, Magic, Network};
use mantle_transport::{CqeData, Op, Peer, PeerPool, PeerState, SendArena};
use ququmatz::types::SockAddrIn;

fn main() {
    divan::main();
}

// ── CqeData bitpacking ───────────────────────────────────────────────────

#[divan::bench]
fn cqe_encode(bencher: divan::Bencher) {
    bencher.bench(|| CqeData::encode(black_box(42), black_box(7), Op::Recv));
}

#[divan::bench]
fn cqe_decode(bencher: divan::Bencher) {
    let raw = CqeData::encode(42, 7, Op::Recv);
    bencher.bench(|| CqeData::decode(black_box(raw)));
}

#[divan::bench]
fn cqe_encode_decode_roundtrip(bencher: divan::Bencher) {
    bencher.bench(|| {
        let raw = CqeData::encode(black_box(100), black_box(200), Op::Send);
        CqeData::decode(black_box(raw))
    });
}

#[divan::bench]
fn cqe_encode_send(bencher: divan::Bencher) {
    bencher.bench(|| CqeData::encode_send(black_box(10), black_box(20), black_box(300)));
}

#[divan::bench]
fn cqe_decode_send_seq(bencher: divan::Bencher) {
    let raw = CqeData::encode_send(10, 20, 300);
    bencher.bench(|| CqeData::decode_send_seq(black_box(raw)));
}

// ── SendArena ─────────────────────────────────────────────────────────────

#[divan::bench]
fn arena_frame_into(bencher: divan::Bencher) {
    let mut arena = SendArena::new();
    let payload = vec![0xab_u8; 256];
    let magic = Magic::Mainnet;
    bencher.bench_local(|| {
        if let Some(seq) = arena.frame_into(magic, Command::Inv, black_box(&payload)) {
            arena.release(seq);
        }
    });
}

#[divan::bench(args = [0usize, 64, 256, 1024, 4000])]
fn arena_frame_into_sizes(bencher: divan::Bencher, len: usize) {
    let mut arena = SendArena::new();
    let payload = vec![0xab_u8; len];
    let magic = Magic::Mainnet;
    bencher.bench_local(|| {
        if let Some(seq) = arena.frame_into(magic, Command::Inv, black_box(&payload)) {
            arena.release(seq);
        }
    });
}

#[divan::bench]
fn arena_slice(bencher: divan::Bencher) {
    let mut arena = SendArena::new();
    let seq = arena
        .frame_into(Magic::Mainnet, Command::Verack, &[])
        .unwrap();
    bencher.bench(|| black_box(arena.slice(black_box(seq))));
}

#[divan::bench]
fn arena_alloc_release_cycle(bencher: divan::Bencher) {
    let mut arena = SendArena::new();
    let magic = Magic::Mainnet;
    bencher.bench_local(|| {
        let seq = arena
            .frame_into(magic, Command::Verack, &[])
            .expect("should allocate");
        arena.release(seq);
    });
}

#[divan::bench]
fn arena_burst_alloc_then_release(bencher: divan::Bencher) {
    let mut arena = SendArena::new();
    let magic = Magic::Mainnet;
    let mut seqs = Vec::with_capacity(64);
    bencher.bench_local(|| {
        seqs.clear();
        for _ in 0..64 {
            if let Some(seq) = arena.frame_into(magic, Command::Verack, &[]) {
                seqs.push(seq);
            }
        }
        for &seq in &seqs {
            arena.release(seq);
        }
    });
}

// ── PeerPool ──────────────────────────────────────────────────────────────

fn make_peer(slot: u16) -> Peer<()> {
    Peer {
        addr: SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 8333),
        sock: None,
        sockaddr: SockAddrIn {
            sin_family: 2, // AF_INET
            sin_port: 8333u16.to_be(),
            sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            sin_zero: [0; 8],
        },
        state: PeerState::Ready,
        recv_buf: Vec::new(),
        recv_armed: false,
        connected_at: Instant::now(),
        generation: slot,
        pending_send_seqs: Vec::new(),
        app: (),
    }
}

#[divan::bench]
fn pool_get_mut(bencher: divan::Bencher) {
    let mut pool: PeerPool<(), 128> = PeerPool::new();
    for i in 0..64u16 {
        pool.insert(i, make_peer(i));
    }
    bencher.bench_local(|| black_box(pool.get_mut(black_box(32)).is_some()));
}

#[divan::bench]
fn pool_free_slot(bencher: divan::Bencher) {
    let mut pool: PeerPool<(), 128> = PeerPool::new();
    for i in 0..64u16 {
        pool.insert(i, make_peer(i));
    }
    bencher.bench(|| black_box(pool.free_slot()));
}

#[divan::bench]
fn pool_iter_mut(bencher: divan::Bencher) {
    let mut pool: PeerPool<(), 128> = PeerPool::new();
    for i in 0..64u16 {
        pool.insert(i, make_peer(i));
    }
    bencher.bench_local(|| {
        for (slot, peer) in pool.iter_mut() {
            black_box((slot, &peer.state));
        }
    });
}

#[divan::bench]
fn pool_dead_slots(bencher: divan::Bencher) {
    let mut pool: PeerPool<(), 128> = PeerPool::new();
    for i in 0..64u16 {
        let mut p = make_peer(i);
        if i % 4 == 0 {
            p.state = PeerState::Dead;
        }
        pool.insert(i, p);
    }
    bencher.bench_local(|| black_box(pool.dead_slots().len()));
}

#[divan::bench]
fn pool_live_count(bencher: divan::Bencher) {
    let mut pool: PeerPool<(), 128> = PeerPool::new();
    for i in 0..64u16 {
        let mut p = make_peer(i);
        if i % 4 == 0 {
            p.state = PeerState::Dead;
        }
        pool.insert(i, p);
    }
    bencher.bench(|| black_box(pool.live_count()));
}

// ── Version message encoding ──────────────────────────────────────────────

#[divan::bench]
fn encode_version(bencher: divan::Bencher) {
    let mut buf = Vec::new();
    bencher.bench_local(|| {
        mantle_transport::encode_version("mantle:0.1.0", &mut buf);
        black_box(buf.len());
    });
}

// ── Handshake framing (header parse + checksum) ───────────────────────────

#[divan::bench]
fn handshake_frame_verack(bencher: divan::Bencher) {
    let network = Network::Mainnet;
    let mut arena = SendArena::new();
    let seq = arena
        .frame_into(network.magic(), Command::Verack, &[])
        .unwrap();
    let wire = arena.slice(seq).to_vec();
    arena.release(seq);

    bencher.bench_local(|| {
        let mut peer: Peer<()> = make_peer(0);
        peer.state = PeerState::HandshakeRecving;
        peer.recv_buf.extend_from_slice(black_box(&wire));
        let mut count = 0u32;
        // consume_handshake_frames needs IoUring, but we can bench the recv_buf
        // parsing portion by measuring the header decode + checksum overhead
        // via the MessageHeader::decode path directly
        use mantle::codec::Decode;
        use mantle::network::MessageHeader;
        if peer.recv_buf.len() >= MessageHeader::ENCODED_LEN {
            let _header = MessageHeader::decode(&mut std::io::Cursor::new(
                &peer.recv_buf[..MessageHeader::ENCODED_LEN],
            ));
            count += 1;
        }
        black_box(count);
    });
}
