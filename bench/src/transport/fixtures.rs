#![allow(dead_code)]

use std::net::SocketAddrV4;
use std::time::Instant;

use mantle::network::{Magic, Network};
use mantle_transport::{Peer, PeerPool, PeerState};
use ququmatz::types::SockAddrIn;

pub const ITERS_SMALL: u32 = 500;
pub const ITERS_MEDIUM: u32 = 2_000;
pub const ITERS_LARGE: u32 = 10_000;

pub fn make_peer(slot: u16) -> Peer<()> {
    Peer {
        addr: SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 8333),
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

pub fn make_pool_half_full() -> PeerPool<(), 128> {
    let mut pool = PeerPool::new();
    for i in 0..64u16 {
        let mut p = make_peer(i);
        if i % 4 == 0 {
            p.state = PeerState::Dead;
        }
        pool.insert(i, p);
    }
    pool
}

pub fn mainnet_magic() -> Magic {
    Magic::Mainnet
}

pub fn mainnet_network() -> Network {
    Network::Mainnet
}
