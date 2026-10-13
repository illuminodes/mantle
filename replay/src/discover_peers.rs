//! `discover-peers` — standalone P2P peer-list harvester.
//!
//! Dials a network's DNS seeds (or `--peer` overrides), completes the version
//! handshake via `mantle-transport`, signals BIP155 support via `sendaddrv2`,
//! asks every connected peer for its peer table via `getaddr`, and accumulates
//! the IPv4 `addr` / `addrv2` responses. Writes a deduped `IP:PORT` list to
//! disk.
//!
//! Usage:
//!     cargo run --release --bin discover-peers -- \
//!         --network testnet4 \
//!         --out peers.txt \
//!         [--peer HOST:PORT]…  [--seconds 60]

use std::collections::BTreeSet;
use std::io::Cursor;
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use mantle::network::{AddrMsg, AddrV2Addr, AddrV2Msg, Command, CommandName, Network};
use mantle_transport::{
    CqeData, IoUringExt, Op, Peer, PeerPool, PeerState, SendArena, consume_handshake_frames,
    encode_version, make_ring,
};
use ququmatz::types::{AddressFamily, SockAddrIn, SocketFlags, SocketType, Timespec};

const HELP: &str = "\
discover-peers — collect a static peer list by talking to DNS seeds.

Usage:
    discover-peers [OPTIONS]

Options:
    --network NAME        mainnet | testnet3 | testnet4 | signet | regtest
                          (default: testnet4).
    --peer HOST:PORT      Extra P2P peer to dial; may be repeated. Combined
                          with the network's default DNS seeds.
    --out FILE            Output path for the deduped IP:PORT list
                          (default: ./peers.txt).
    --seconds N           Wall-clock budget for the discovery loop
                          (default: 60).
    --help                Print this message and exit.
";

const MAX_PEERS: usize = 64;
const PROVIDED_BUF_SIZE: u32 = 256 * 1024;
const PROVIDED_BUF_COUNT: u32 = 512;
const PROVIDED_BUF_GROUP_ID: u16 = 1;
const CONNECT_TIMEOUT_SECS: u64 = 5;
const HANDSHAKE_TIMEOUT_SECS: u64 = 10;
const RECV_BUF_CAPACITY: usize = 64 * 1024;

struct Args {
    network: Network,
    extra_peers: Vec<SocketAddrV4>,
    out: PathBuf,
    seconds: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut network = Network::Testnet4;
    let mut extra_peers: Vec<SocketAddrV4> = Vec::new();
    let mut out = PathBuf::from("./peers.txt");
    let mut seconds: u64 = 60;

    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--help" | "-h" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            "--network" => {
                i += 1;
                let v = raw.get(i).ok_or("--network requires a name")?;
                network = Network::parse(v).ok_or_else(|| format!("unknown network: {v}"))?;
            }
            "--peer" => {
                i += 1;
                let v = raw.get(i).ok_or("--peer requires HOST:PORT")?;
                let addr: SocketAddrV4 =
                    v.parse().map_err(|e| format!("invalid --peer {v}: {e}"))?;
                extra_peers.push(addr);
            }
            "--out" => {
                i += 1;
                let v = raw.get(i).ok_or("--out requires a path")?;
                out = PathBuf::from(v);
            }
            "--seconds" => {
                i += 1;
                let v = raw.get(i).ok_or("--seconds requires N")?;
                seconds = v
                    .parse()
                    .map_err(|e| format!("invalid --seconds {v}: {e}"))?;
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }

    Ok(Args {
        network,
        extra_peers,
        out,
        seconds,
    })
}

fn resolve_peers(network: Network, extras: &[SocketAddrV4]) -> Vec<SocketAddrV4> {
    let mut out: Vec<SocketAddrV4> = extras.to_vec();
    for seed in network.default_seeds() {
        if let Ok(addr) = seed.parse::<SocketAddrV4>() {
            out.push(addr);
            continue;
        }
        match seed.to_socket_addrs() {
            Ok(iter) => {
                let before = out.len();
                for addr in iter {
                    if let SocketAddr::V4(v4) = addr {
                        out.push(v4);
                    }
                }
                let resolved = out.len() - before;
                if resolved == 0 {
                    eprintln!("  seed {seed} resolved to 0 IPv4 addresses (skipped)");
                } else {
                    eprintln!("  seed {seed} resolved to {resolved} address(es)");
                }
            }
            Err(e) => eprintln!("  failed to resolve seed {seed}: {e}"),
        }
    }
    out
}

struct DiscoverState {
    harvest: BTreeSet<SocketAddrV4>,
    asked: Vec<bool>,
}

#[allow(clippy::too_many_lines)]
fn run(args: &Args) -> Result<(), String> {
    eprintln!(
        "discover-peers: network={} budget={}s out={}",
        args.network.name(),
        args.seconds,
        args.out.display()
    );

    let peer_addrs = resolve_peers(args.network, &args.extra_peers);
    if peer_addrs.is_empty() {
        return Err(format!(
            "no peers: {} has no reachable seeds; supply --peer HOST:PORT",
            args.network.name()
        ));
    }
    eprintln!("  dialing {} candidate peer(s)", peer_addrs.len());

    let mut ring = make_ring().map_err(|e| format!("make_ring: {e}"))?;
    let mut pbr = ring
        .register_provided_buffers(PROVIDED_BUF_GROUP_ID, PROVIDED_BUF_COUNT, PROVIDED_BUF_SIZE)
        .map_err(|e| format!("register_provided_buffers: {e:?}"))?;
    let mut send_arena = SendArena::new();
    let mut peers: PeerPool<(), MAX_PEERS> = PeerPool::new();

    let connect_timeout = Timespec::from_millis(CONNECT_TIMEOUT_SECS * 1_000);
    let mut version_payload = Vec::new();
    encode_version("/mantle-discover:0.1.0/", &mut version_payload);
    let mut next_addr_idx = 0usize;
    let mut state = DiscoverState {
        harvest: BTreeSet::new(),
        asked: vec![false; MAX_PEERS],
    };

    let target = MAX_PEERS.min(peer_addrs.len());
    for _ in 0..target {
        let Some(slot) = peers.free_slot() else { break };
        if let Some(peer) = dial_next(
            &mut ring,
            &peer_addrs,
            &mut next_addr_idx,
            slot,
            &connect_timeout,
        )? {
            peers.insert(slot, peer);
        }
    }

    let started = Instant::now();
    let deadline = started + Duration::from_secs(args.seconds);
    let mut last_log = started;

    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }

        ring.push_tick(Duration::from_secs(1)).map_err(|e| format!("push_tick: {e}"))?;
        ring.submit_and_wait(1)
            .map_err(|e| format!("submit_and_wait: {e:?}"))?;

        let mut drained = 0usize;
        while drained < 1024 {
            let Some(cqe) = ring.complete() else { break };
            drained += 1;
            let cqd = CqeData::decode(cqe.user_data());

            if cqd.op == Op::Tick {
                continue;
            }
            if cqd.op == Op::Send {
                let send_seq = CqeData::decode_send_seq(cqe.user_data());
                send_arena.release(send_seq);
                if let Some(p) = peers.get_mut(cqd.slot) {
                    p.pending_send_seqs.retain(|s| *s != send_seq);
                }
            }
            if cqd.op == Op::LinkTimeout || cqd.op == Op::Close {
                continue;
            }

            let res = cqe.raw_result();
            let Some(peer) = peers.get_mut(cqd.slot) else {
                continue;
            };
            if peer.generation != cqd.generation {
                continue;
            }

            match cqd.op {
                Op::Connect => {
                    if res < 0 {
                        peer.state = PeerState::Dead;
                        peer.close(&mut ring, &mut send_arena);
                    } else {
                        ring.push_recv_multishot(
                            cqd.slot,
                            peer.generation,
                            peer.fd().ok_or("no fd on connect")?,
                            PROVIDED_BUF_GROUP_ID,
                        )
                        .map_err(|e| format!("push_recv: {e}"))?;
                        peer.recv_armed = true;
                        let seq = ring.push_send(
                            &mut send_arena,
                            args.network,
                            Command::Version,
                            &version_payload,
                            cqd.slot,
                            peer.generation,
                            peer.fd().ok_or("no fd on connect")?,
                        )
                        .map_err(|e| format!("push_send version: {e}"))?;
                        peer.pending_send_seqs.push(seq);
                        peer.state = PeerState::HandshakeVersionSent;
                    }
                }
                Op::Recv => {
                    peer.ingest_recv_cqe(&mut pbr, &mut send_arena, cqe.flags(), res, &mut ring);
                }
                Op::Send if res < 0 => {
                    peer.state = PeerState::Dead;
                    peer.close(&mut ring, &mut send_arena);
                }
                _ => {}
            }
        }

        for (slot, peer) in peers.iter_mut() {
            if peer.state == PeerState::Dead {
                continue;
            }

            let was_ready = peer.state == PeerState::Ready;
            consume_handshake_frames(
                &mut ring,
                &mut send_arena,
                args.network,
                slot,
                peer,
                |command, payload| {
                    handle_app_frame(command, payload, &mut state.harvest);
                },
            )
            .map_err(|e| format!("consume_frames: {e}"))?;

            if peer.state == PeerState::Ready && !was_ready {
                state.harvest.insert(peer.addr);
            }

            if peer.state == PeerState::Ready && !state.asked[slot as usize] {
                state.asked[slot as usize] = true;
                if let Some(fd) = peer.fd() {
                    if let Ok(seq) = ring.push_send(
                        &mut send_arena,
                        args.network,
                        Command::SendAddrV2,
                        &[],
                        slot,
                        peer.generation,
                        fd,
                    ) {
                        peer.pending_send_seqs.push(seq);
                    }
                    if let Ok(seq) = ring.push_send(
                        &mut send_arena,
                        args.network,
                        Command::GetAddr,
                        &[],
                        slot,
                        peer.generation,
                        fd,
                    ) {
                        peer.pending_send_seqs.push(seq);
                    }
                }
            }

            if !peer.recv_armed
                && peer.state != PeerState::Dead
                && peer.state != PeerState::Connecting
                && let Some(fd) = peer.fd()
            {
                let _ = ring.push_recv_multishot(
                    slot,
                    peer.generation,
                    fd,
                    PROVIDED_BUF_GROUP_ID,
                );
                peer.recv_armed = true;
            }
        }

        let now2 = Instant::now();
        for (slot, peer) in peers.iter_mut() {
            if peer.state == PeerState::Dead {
                continue;
            }
            if peer.state == PeerState::Connecting
                && now2.duration_since(peer.connected_at)
                    > Duration::from_secs(CONNECT_TIMEOUT_SECS + 2)
            {
                peer.close(&mut ring, &mut send_arena);
                peer.state = PeerState::Dead;
            }
            if matches!(
                peer.state,
                PeerState::HandshakeVersionSent | PeerState::HandshakeRecving
            ) && now2.duration_since(peer.connected_at)
                > Duration::from_secs(HANDSHAKE_TIMEOUT_SECS)
            {
                peer.close(&mut ring, &mut send_arena);
                peer.state = PeerState::Dead;
            }
            let _ = slot;
        }

        let dead: Vec<u16> = peers.dead_slots().to_vec();
        for slot in dead {
            peers.remove(slot);
            if (slot as usize) < state.asked.len() {
                state.asked[slot as usize] = false;
            }
            if let Some(new_slot) = peers.free_slot()
                && let Some(p) = dial_next(
                    &mut ring,
                    &peer_addrs,
                    &mut next_addr_idx,
                    new_slot,
                    &connect_timeout,
                )?
            {
                peers.insert(new_slot, p);
            }
        }

        if now2.duration_since(last_log) >= Duration::from_secs(5) {
            let ready = peers
                .values()
                .filter(|p| p.state == PeerState::Ready)
                .count();
            eprintln!(
                "  …{} unique peers harvested, {} ready",
                state.harvest.len(),
                ready
            );
            last_log = now2;
        }
    }

    eprintln!("  collected {} unique IPv4 peers", state.harvest.len());
    if let Some(parent) = args.out.parent()
        && !parent.as_os_str().is_empty()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        return Err(format!("create_dir_all {}: {e}", parent.display()));
    }
    let mut text = String::new();
    for addr in &state.harvest {
        text.push_str(&addr.to_string());
        text.push('\n');
    }
    std::fs::write(&args.out, text).map_err(|e| format!("write {}: {e}", args.out.display()))?;
    eprintln!("  wrote {}", args.out.display());
    Ok(())
}

fn handle_app_frame(command: CommandName, payload: &[u8], harvest: &mut BTreeSet<SocketAddrV4>) {
    let cmd = mantle::network::Command::from_command_name(command);
    match cmd {
        Some(Command::Addr) => {
            if let Ok(msg) = AddrMsg::decode_limited(&mut Cursor::new(payload)) {
                for entry in msg.0 {
                    if let Some(octets) = entry.ip_v4() {
                        let v4 = std::net::Ipv4Addr::from(octets);
                        harvest.insert(SocketAddrV4::new(v4, entry.port().to_u16()));
                    }
                }
            }
        }
        Some(Command::AddrV2) => {
            if let Ok(msg) = AddrV2Msg::decode_limited(&mut Cursor::new(payload)) {
                for entry in msg.0 {
                    if let AddrV2Addr::Ipv4(_) = entry.addr
                        && let Some(v4) = entry.ip_v4()
                    {
                        harvest.insert(v4);
                    }
                }
            }
        }
        _ => {}
    }
}

fn dial_next(
    ring: &mut ququmatz::IoUring,
    addrs: &[SocketAddrV4],
    next_idx: &mut usize,
    slot: u16,
    timeout: &Timespec,
) -> Result<Option<Peer<()>>, String> {
    if addrs.is_empty() {
        return Ok(None);
    }
    if *next_idx >= addrs.len() {
        return Ok(None);
    }
    let addr = addrs[*next_idx];
    *next_idx += 1;

    let sock = ququmatz::Socket::with_typed_flags(
        AddressFamily::Inet,
        SocketType::Stream,
        0,
        SocketFlags::NONBLOCK,
    )
    .map_err(|e| format!("socket: {e:?}"))?;
    let sockaddr = SockAddrIn {
        sin_family: u16::try_from(AddressFamily::Inet.as_raw()).expect("AF_INET fits u16"),
        sin_port: addr.port().to_be(),
        sin_addr: u32::from_ne_bytes(addr.ip().octets()),
        sin_zero: [0; 8],
    };

    let fd = sock.fd();
    let peer = Peer {
        addr,
        sock: Some(sock),
        sockaddr,
        state: PeerState::Connecting,
        recv_buf: Vec::with_capacity(RECV_BUF_CAPACITY),
        recv_armed: false,
        connected_at: Instant::now(),
        generation: 0,
        pending_send_seqs: Vec::with_capacity(8),
        app: (),
    };

    ring.push_connect(slot, peer.generation, fd, &peer.sockaddr, timeout)
        .map_err(|e| format!("push_connect: {e}"))?;

    Ok(Some(peer))
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fatal: {e}");
            ExitCode::FAILURE
        }
    }
}
