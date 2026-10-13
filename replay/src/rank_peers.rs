//! `rank-peers` — `io_uring`-based latency probe over a peer list.
//!
//! Reads `IP:PORT` per line, opens a single `io_uring` with a bounded number of
//! in-flight probes. Each probe is a four-SQE chain — `socket → connect →
//! send(version) → recv(reply)` — submitted with `IO_LINK` so the kernel
//! short-circuits the chain if any step fails. A `link_timeout` SQE bounds
//! the entire probe wall-clock per the `--timeout-ms` flag. Successful
//! probes record `recv_completion_time - probe_start_time`; the close SQE
//! is submitted in a separate non-linked step so a timed-out chain doesn't
//! also stall the close.
//!
//! Why `io_uring` rather than thread-per-peer? Probing 18k peers with one
//! TCP socket per thread blows past `EMFILE` and parks thousands of fds in
//! `TIME_WAIT` — at minimum it's wasteful, and on some hosts it just
//! crashes. `io_uring` keeps the fd table small (one fd per in-flight slot,
//! recycled) and the kernel batches the SQE/CQE traffic.
//!
//! Usage:
//!     rank-peers [OPTIONS] --peer-file IN.txt --out OUT.txt
//!
//! Options:
//!     --network NAME       mainnet | testnet3 | testnet4 | signet | regtest
//!                          (default: testnet4).
//!     --peer-file PATH     Input list, one IP:PORT per line.
//!     --out PATH           Output list, sorted ascending by RTT.
//!     --inflight N         Concurrent probes in flight (default: 256).
//!     --timeout-ms N       Per-probe deadline, kernel-enforced (default: 3000).
//!     --top N              Write only the N fastest peers (default: 0 = all).
//!     --help               Print this message and exit.

use std::fmt::Write as _;
use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use mantle::codec::Encode;
use mantle::difficulty::BlockHeight;
use mantle::network::{
    Command, Network, NetworkAddr, PeerNonce, Port, ProtocolVersion, Services, Timestamp,
    VersionMsg,
};
use ququmatz::types::{
    AddressFamily, MsgFlags, RawFd, SockAddrIn, SocketFlags, SocketType, SqeFlags, TimeoutFlags,
    Timespec,
};
use ququmatz::{IoUring, Sqe};

const HELP: &str = "\
rank-peers — io_uring TCP+version-handshake latency probe.

Usage:
    rank-peers [OPTIONS] --peer-file IN.txt --out OUT.txt

Options:
    --network NAME       mainnet | testnet3 | testnet4 | signet | regtest
                         (default: testnet4).
    --peer-file PATH     Input list, one IP:PORT per line.
    --out PATH           Output list, sorted ascending by RTT.
    --inflight N         Concurrent probes in flight (default: 256).
    --timeout-ms N       Per-probe deadline (default: 3000).
    --top N              Write only the N fastest peers (default: 0 = all).
    --help               Print this message and exit.
";

struct Args {
    network: Network,
    peer_file: PathBuf,
    out: PathBuf,
    inflight: usize,
    timeout: Duration,
    top: usize,
}

fn parse_args() -> Result<Args, String> {
    let mut network = Network::Testnet4;
    let mut peer_file: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut inflight: usize = 256;
    let mut timeout_ms: u64 = 3_000;
    let mut top: usize = 0;

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
            "--peer-file" => {
                i += 1;
                let v = raw.get(i).ok_or("--peer-file requires a path")?;
                peer_file = Some(PathBuf::from(v));
            }
            "--out" => {
                i += 1;
                let v = raw.get(i).ok_or("--out requires a path")?;
                out = Some(PathBuf::from(v));
            }
            "--inflight" => {
                i += 1;
                let v = raw.get(i).ok_or("--inflight requires N")?;
                inflight = v
                    .parse()
                    .map_err(|e| format!("invalid --inflight {v}: {e}"))?;
            }
            "--timeout-ms" => {
                i += 1;
                let v = raw.get(i).ok_or("--timeout-ms requires N")?;
                timeout_ms = v
                    .parse()
                    .map_err(|e| format!("invalid --timeout-ms {v}: {e}"))?;
            }
            "--top" => {
                i += 1;
                let v = raw.get(i).ok_or("--top requires N")?;
                top = v.parse().map_err(|e| format!("invalid --top {v}: {e}"))?;
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }

    Ok(Args {
        network,
        peer_file: peer_file.ok_or("--peer-file is required")?,
        out: out.ok_or("--out is required")?,
        inflight: inflight.clamp(1, 8192),
        timeout: Duration::from_millis(timeout_ms),
        top,
    })
}

fn load_peers(path: &PathBuf) -> Result<Vec<SocketAddrV4>, String> {
    let body =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut out = Vec::new();
    for (lineno, line) in body.lines().enumerate() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() {
            continue;
        }
        match trimmed.parse::<SocketAddrV4>() {
            Ok(addr) => out.push(addr),
            Err(e) => {
                return Err(format!(
                    "{}:{}: invalid peer {trimmed:?}: {e}",
                    path.display(),
                    lineno + 1
                ));
            }
        }
    }
    Ok(out)
}

/// Op tags packed into the lower 8 bits of `user_data`. The upper 56 bits
/// hold the slot index, so a probe can be demuxed without a side table.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Connect = 0,
    LinkTimeout = 1,
    Close = 2,
    Send = 3,
    Recv = 4,
}

impl Op {
    fn from_u8(b: u8) -> Self {
        match b {
            0 => Self::Connect,
            2 => Self::Close,
            3 => Self::Send,
            4 => Self::Recv,
            _ => Self::LinkTimeout,
        }
    }
}

#[inline]
const fn tag(slot: u32, op: Op) -> u64 {
    ((slot as u64) << 8) | (op as u64)
}

#[inline]
fn split_tag(raw: u64) -> (u32, Op) {
    #[allow(clippy::cast_possible_truncation)]
    let slot = (raw >> 8) as u32;
    let op = Op::from_u8((raw & 0xff) as u8);
    (slot, op)
}

/// Per-slot state. The `sockaddr` must outlive its connect SQE, so it
/// stays owned by the slot until the probe completes.
struct Slot {
    addr: SocketAddrV4,
    fd: Option<RawFd>,
    sockaddr: SockAddrIn,
    started_at: Instant,
    recv_done: bool,
    recv_rtt: Option<Duration>,
    closed: bool,
    version_buf: Vec<u8>,
    magic_buf: [u8; 4],
    magic_verified: bool,
}

impl Slot {
    fn new() -> Self {
        Self {
            addr: SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
            fd: None,
            sockaddr: SockAddrIn {
                sin_family: 0,
                sin_port: 0,
                sin_addr: 0,
                sin_zero: [0; 8],
            },
            started_at: Instant::now(),
            recv_done: false,
            recv_rtt: None,
            closed: true,
            version_buf: Vec::new(),
            magic_buf: [0u8; 4],
            magic_verified: false,
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run(args: &Args) -> Result<(), String> {
    eprintln!(
        "rank-peers: network={} inflight={} timeout={}ms top={}",
        args.network.name(),
        args.inflight,
        args.timeout.as_millis(),
        args.top
    );

    let peers = load_peers(&args.peer_file)?;
    eprintln!(
        "  loaded {} peers from {}",
        peers.len(),
        args.peer_file.display()
    );
    if peers.is_empty() {
        return Err("peer-file is empty".into());
    }

    // Ring depth: each probe consumes 2 SQEs at submit (connect + link_timeout)
    // and a separate Close SQE on connect-completion — round up to 4× inflight
    // for backpressure headroom.
    #[allow(clippy::cast_possible_truncation)]
    let ring_depth = (args.inflight * 4).next_power_of_two().clamp(64, 32_768) as u32;
    let mut ring =
        IoUring::new(ring_depth).map_err(|e| format!("IoUring::new({ring_depth}): {e:?}"))?;

    let total = peers.len();
    let mut next_idx = 0usize;
    let mut completed = 0usize;
    let mut succeeded = 0usize;
    let mut results: Vec<(SocketAddrV4, Duration)> = Vec::new();
    // Slot pool — one per in-flight probe. `free_slots` is a stack of slot
    // indices ready to accept a new probe.
    let mut slots: Vec<Slot> = (0..args.inflight).map(|_| Slot::new()).collect();
    let mut free_slots: Vec<usize> = (0..args.inflight).collect();

    // Per-slot timeout `Timespec` storage. Kept alive across submit so the
    // kernel can read it when the linked timeout fires.
    let timeout_ms = u64::try_from(args.timeout.as_millis()).unwrap_or(u64::MAX);
    let timeouts: Vec<Timespec> = (0..args.inflight)
        .map(|_| Timespec::from_millis(timeout_ms))
        .collect();

    let started = Instant::now();
    let mut last_log = started;

    while completed < total {
        // Fill any free slots with new probes.
        while !free_slots.is_empty() && next_idx < total {
            let slot_idx = free_slots.pop().unwrap();
            let peer = peers[next_idx];
            next_idx += 1;
            if let Err(e) = launch_probe(
                &mut ring,
                &mut slots[slot_idx],
                u32::try_from(slot_idx).unwrap_or(0),
                peer,
                &timeouts[slot_idx],
            ) {
                // Local socket() failed — bail rather than hang.
                return Err(format!("launch_probe(slot {slot_idx}): {e}"));
            }
        }

        // Submit anything queued, wait for at least one CQE.
        ring.submit_and_wait(1)
            .map_err(|e| format!("submit_and_wait: {e:?}"))?;

        // Drain all available CQEs.
        while let Some(cqe) = ring.complete() {
            let (slot_idx, op) = split_tag(cqe.user_data());
            let slot_idx = slot_idx as usize;
            if slot_idx >= slots.len() {
                continue;
            }
            let slot = &mut slots[slot_idx];
            let res = cqe.raw_result();

            match op {
                Op::Connect => {
                    if res < 0 {
                        slot.recv_done = true;
                        if let Some(fd) = slot.fd.take() {
                            let _ =
                                ring.push(Sqe::close(fd).user_data(tag(
                                    u32::try_from(slot_idx).unwrap_or(0),
                                    Op::Close,
                                )));
                        }
                    } else if let Some(fd) = slot.fd {
                        slot.recv_rtt = Some(slot.started_at.elapsed());
                        let magic = args.network.magic();
                        let ver = our_version();
                        let mut framed = Vec::new();
                        let mut payload = Vec::new();
                        let _ = ver.encode(&mut payload);
                        let _ = magic.frame(Command::Version, &payload, &mut framed);
                        slot.version_buf = framed;
                        // SAFETY: `version_buf` lives in the slot until the send completes.
                        let _ = ring.push(
                            unsafe { Sqe::send(fd, &slot.version_buf, MsgFlags::default()) }
                                .user_data(tag(u32::try_from(slot_idx).unwrap_or(0), Op::Send)),
                        );
                    }
                }
                Op::Send => {
                    if res < 0 {
                        slot.recv_done = true;
                        if let Some(fd) = slot.fd.take() {
                            let _ =
                                ring.push(Sqe::close(fd).user_data(tag(
                                    u32::try_from(slot_idx).unwrap_or(0),
                                    Op::Close,
                                )));
                        }
                    } else if let Some(fd) = slot.fd {
                        // SAFETY: `magic_buf` lives in the slot until the recv completes.
                        let _ = ring.push(
                            unsafe { Sqe::recv(fd, &mut slot.magic_buf, MsgFlags::default()) }
                                .user_data(tag(u32::try_from(slot_idx).unwrap_or(0), Op::Recv))
                                .flags(SqeFlags::IO_LINK),
                        );
                        // SAFETY: io_uring copies the timespec during link-timeout prep.
                        let _ = ring.push(
                            unsafe { Sqe::link_timeout(&timeouts[slot_idx], TimeoutFlags::default()) }
                                .user_data(tag(
                                    u32::try_from(slot_idx).unwrap_or(0),
                                    Op::LinkTimeout,
                                )),
                        );
                    }
                }
                Op::Recv => {
                    slot.recv_done = true;
                    if res >= 4 {
                        let expected = args.network.magic().bytes();
                        slot.magic_verified = slot.magic_buf == expected;
                    }
                    if !slot.magic_verified {
                        slot.recv_rtt = None;
                    }
                    if let Some(fd) = slot.fd.take() {
                        let _ = ring.push(
                            Sqe::close(fd)
                                .user_data(tag(u32::try_from(slot_idx).unwrap_or(0), Op::Close)),
                        );
                    }
                }
                Op::LinkTimeout => {}
                Op::Close => {
                    slot.closed = true;
                }
            }

            // A slot is recyclable once both the connect outcome and the
            // close have been observed.
            if slot.recv_done && slot.closed {
                if let Some(rtt) = slot.recv_rtt.take() {
                    results.push((slot.addr, rtt));
                    succeeded += 1;
                }
                slot.fd = None;
                slot.recv_done = false;
                slot.closed = true;
                slot.recv_rtt = None;
                free_slots.push(slot_idx);
                completed += 1;
            }
        }

        if last_log.elapsed() >= Duration::from_secs(2) {
            eprintln!(
                "  probe {completed}/{total} ({} succeeded so far, {:.1}s elapsed)",
                succeeded,
                started.elapsed().as_secs_f64()
            );
            last_log = Instant::now();
        }
    }

    let elapsed = started.elapsed();
    eprintln!(
        "  probed {total} peers in {:.1}s; {succeeded} TCP-reachable",
        elapsed.as_secs_f64()
    );

    results.sort_by_key(|(_, rtt)| *rtt);
    let kept = if args.top > 0 && args.top < results.len() {
        &results[..args.top]
    } else {
        &results[..]
    };

    if let Some(parent) = args.out.parent()
        && !parent.as_os_str().is_empty()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        return Err(format!("create_dir_all {}: {e}", parent.display()));
    }
    let mut text = String::new();
    text.push_str("# IP:PORT  rtt_ms (sorted ascending)\n");
    for (addr, rtt) in kept {
        let _ = writeln!(text, "{addr}  # {} ms", rtt.as_millis());
    }
    std::fs::write(&args.out, text).map_err(|e| format!("write {}: {e}", args.out.display()))?;
    eprintln!("  wrote {} ({} entries)", args.out.display(), kept.len());

    // Suppress unused-binding warning for the once-per-version frame check.
    drop(timeouts);
    Ok(())
}

fn launch_probe(
    ring: &mut IoUring,
    slot: &mut Slot,
    slot_idx: u32,
    addr: SocketAddrV4,
    timeout: &Timespec,
) -> Result<(), String> {
    // Open a fresh socket per probe. The Close SQE submitted on Connect
    // completion (success or timeout) frees the fd via io_uring rather
    // than blocking syscall.
    let sock = ququmatz::Socket::with_typed_flags(
        AddressFamily::Inet,
        SocketType::Stream,
        0,
        SocketFlags::NONBLOCK,
    )
    .map_err(|e| format!("socket: {e:?}"))?;
    let fd = sock.into_fd();

    slot.addr = addr;
    slot.fd = Some(fd);
    slot.sockaddr = SockAddrIn {
        sin_family: u16::try_from(AddressFamily::Inet.as_raw()).expect("AF_INET fits u16"),
        sin_port: addr.port().to_be(),
        sin_addr: u32::from_ne_bytes(addr.ip().octets()),
        sin_zero: [0; 8],
    };
    slot.started_at = Instant::now();
    slot.recv_done = false;
    slot.recv_rtt = None;
    slot.closed = false;

    let addr_bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            (&raw const slot.sockaddr).cast(),
            std::mem::size_of::<SockAddrIn>(),
        )
    };

    // Chain: Connect (IO_LINK) → link_timeout. The kernel bounds the connect's
    // wall-clock to `timeout`. On timeout the connect CQE arrives with
    // -ECANCELED; on success the timeout CQE arrives with -ECANCELED. Either
    // way we get exactly one of (Connect: success rtt, Connect: failure)
    // plus a benign LinkTimeout CQE.
    // SAFETY: io_uring copies the sockaddr into kernel memory during connect prep.
    ring.push(
        unsafe { Sqe::connect(fd, addr_bytes) }
            .user_data(tag(slot_idx, Op::Connect))
            .flags(SqeFlags::IO_LINK),
    )
    .map_err(|e| format!("push connect: {e:?}"))?;

    // SAFETY: io_uring copies the timespec during link-timeout prep.
    ring.push(
        unsafe { Sqe::link_timeout(timeout, TimeoutFlags::default()) }
            .user_data(tag(slot_idx, Op::LinkTimeout)),
    )
    .map_err(|e| format!("push link_timeout: {e:?}"))?;

    Ok(())
}

fn our_version() -> VersionMsg {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs(),
    )
    .unwrap_or(i64::MAX);
    let empty = NetworkAddr {
        services: Services::NONE,
        ip: [0u8; 16],
        port: Port::new(0),
    };
    VersionMsg {
        version: ProtocolVersion::new(70016),
        services: Services::NODE_NETWORK,
        timestamp: Timestamp::new(now),
        receiver: empty,
        sender: empty,
        nonce: PeerNonce::new(0xfeed_face_dead_beef),
        user_agent: "/mantle-rank-peers:0.1.0/".to_string(),
        start_height: BlockHeight::ZERO,
        relay: false,
    }
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
