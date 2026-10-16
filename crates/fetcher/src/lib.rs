//! Single-ring `io_uring` block fetcher.
//!
//! Uses `mantle-transport` for the `io_uring` peer lifecycle (connect, handshake,
//! send arena, provided-buffer recv, peer pool) and adds fetcher-specific logic:
//! header sync, pipelined block download with hedging/reclaim, and file I/O.
//!
//! Consumers supply a peer list and a cache directory; [`Fetcher`] resolves
//! headers over `getheaders`, downloads any blocks missing from the cache, and
//! serves block bytes back by height.

mod block_feed;
mod ewma_latency;
mod feed_item;
mod feed_request;
mod feed_worker;
mod header_admission;
mod hedge_policy;
mod in_flight;
mod peer_book;
mod peer_liveness;
mod peer_score;
mod routable;
mod tip_quorum;

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use mantle::codec::{Decode, Encode};
use mantle::collections::{BuildPrehashedHasher, PrehashedMap};
use mantle::network::{
    Command, GetHeadersMsg, HeadersMsg, InvEntry, InvMsg, InvType, MessageHeader, Network,
};
use mantle::primitives::{BlockHeader, BlockHeight, Hash256};
use std::ops::Deref;

use mantle_block_io::{FileIoHandle, FileReq, FileResp};
use mantle_transport::{
    CqeData, IoUringExt, Op, Peer, PeerPool, PeerState, SendArena, consume_handshake_frames,
    decode_cqe_buffer_id, encode_version, make_ring,
};
use quetzalcoatl::mpsc::RingBuffer as MpscRing;
use quetzalcoatl::spsc::RingBuffer as SpscRing;
use ququmatz::IoUring;
use ququmatz::types::{AddressFamily, SockAddrIn, SocketFlags, SocketType, Timespec};

pub use crate::block_feed::BlockFeed;
pub use crate::feed_item::{FedBlock, FeedItem};
pub use crate::feed_request::{BlocksRequest, HeaderRequest};
pub use crate::feed_worker::FeedSpec;
pub use crate::header_admission::{AdmitAll, HeaderAdmission};

use crate::ewma_latency::EwmaLatency;
use crate::header_admission::HeaderPage;
use crate::hedge_policy::{HedgeAction, HedgePolicy};
use crate::in_flight::InFlight;
use crate::peer_book::PeerBook;
use crate::peer_liveness::PeerLiveness;
use crate::peer_score::PeerScore;
use crate::tip_quorum::TipQuorum;

// ── Constants ──────────────────────────────────────────────────────────────

const PROVIDED_BUF_SIZE: u32 = 256 * 1024;
const PROVIDED_BUF_COUNT: u32 = 4_096;
const PROVIDED_BUF_GROUP_ID: u16 = 1;
const CQE_DRAIN_CAP: usize = 1024;
const CONNECT_TIMEOUT_SECS: u64 = 5;
const HEADERS_RESPONSE_TIMEOUT_SECS: u64 = 10;
const HANDSHAKE_TIMEOUT_SECS: u64 = 10;
const TRIED_LIMIT: usize = 24;
const BLOCK_NO_PROGRESS_TIMEOUT_SECS: u64 = 300;
const HEADERS_PHASE_DEADLINE_SECS: u64 = 120;
const HEADERS_TIP_QUORUM: usize = 8;
const TARGET_LIVE_PEERS: usize = 64;
const RECV_BUF_CAPACITY: usize = 4 * 1024 * 1024;

// ── Error ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum FetchError {
    Io(io::Error),
    UringErr(String),
    NoPeers,
    Timeout(&'static str),
    PoolExhausted,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::UringErr(s) => write!(f, "uring: {s}"),
            Self::NoPeers => f.write_str("no peer addresses configured"),
            Self::Timeout(phase) => write!(f, "{phase}: deadline exceeded"),
            Self::PoolExhausted => f.write_str("peer pool exhausted before phase finished"),
        }
    }
}

impl std::error::Error for FetchError {}

impl From<io::Error> for FetchError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

fn uring_err(e: ququmatz::Error) -> FetchError {
    FetchError::UringErr(format!("{e:?}"))
}

// ── Fetcher-specific peer extension ────────────────────────────────────────

#[derive(Debug)]
struct FetcherExt {
    in_flight: Vec<(Hash256, Instant)>,
    assigned_count: u32,
    delivered_count: u32,
    headers_request: Option<(Hash256, Instant)>,
    headers_empty_for: Option<Hash256>,
    discovery_requested: bool,
    score: PeerScore,
    liveness: PeerLiveness,
}

impl FetcherExt {
    fn new() -> Self {
        Self {
            in_flight: Vec::new(),
            assigned_count: 0,
            delivered_count: 0,
            headers_request: None,
            headers_empty_for: None,
            discovery_requested: false,
            score: PeerScore::new(),
            liveness: PeerLiveness::new(),
        }
    }

    fn record_request(&mut self, hash: Hash256, now: Instant) {
        self.in_flight.push((hash, now));
        self.assigned_count = self.assigned_count.saturating_add(1);
        self.liveness.on_request(now);
    }

    fn record_arrival(&mut self, hash: &Hash256) {
        let now = Instant::now();
        if let Some(index) = self.in_flight.iter().position(|(h, _)| h == hash) {
            let (_, issued) = self.in_flight.swap_remove(index);
            self.score.observe(now.duration_since(issued));
        }
        self.liveness.on_response(now, !self.in_flight.is_empty());
    }

    fn record_delivery(&mut self) {
        self.delivered_count = self.delivered_count.saturating_add(1);
    }

    fn record_beaten(&mut self, hash: &Hash256, waited: Duration) {
        self.score.observe(waited);
        self.cancel(hash);
    }

    fn record_reclaim(&mut self, hash: &Hash256, waited: Duration) {
        self.score.observe(waited);
        self.liveness.on_strike();
        self.cancel(hash);
    }

    fn cancel(&mut self, hash: &Hash256) {
        self.in_flight.retain(|(h, _)| h != hash);
        self.liveness.on_cancel(!self.in_flight.is_empty());
    }
}

type FPeer = Peer<FetcherExt>;
type FPool = PeerPool<FetcherExt, { TARGET_LIVE_PEERS }>;

// ── Fetcher ────────────────────────────────────────────────────────────────

pub struct Fetcher<
    RReq: Deref<Target = MpscRing<FileReq>> = std::sync::Arc<MpscRing<FileReq>>,
    RResp: Deref<Target = SpscRing<FileResp>> = std::sync::Arc<SpscRing<FileResp>>,
> {
    network: Network,
    peer_book: PeerBook,
    next_peer_generation: u16,
    connect_timeout: Timespec,
    ring: IoUring,
    pbr: ququmatz::ProvidedBufferRing,
    send_arena: SendArena,
    peers: FPool,
    file_io: FileIoHandle<RReq, RResp>,
}

impl Fetcher {
    /// Spawn a file-I/O worker rooted at `data_dir` and build a fetcher over it.
    ///
    /// # Errors
    /// Returns an error if the file-I/O worker cannot be spawned or the
    /// `io_uring` ring cannot be created.
    pub fn new(
        network: Network,
        peer_addrs: Vec<SocketAddrV4>,
        data_dir: &std::path::Path,
    ) -> io::Result<Self> {
        let file_io = FileIoHandle::spawn(data_dir)?;
        let mut fetcher = Self::with_handle(network, peer_addrs.clone(), file_io)?;
        fetcher.peer_book = PeerBook::persistent(peer_addrs, data_dir)?;
        Ok(fetcher)
    }
}

impl<RReq, RResp> Fetcher<RReq, RResp>
where
    RReq: Deref<Target = MpscRing<FileReq>>,
    RResp: Deref<Target = SpscRing<FileResp>>,
{
    /// Build a fetcher over an already-running file-I/O worker.
    ///
    /// # Errors
    /// Returns an error if the `io_uring` ring cannot be created or its
    /// provided-buffer group cannot be registered.
    pub fn with_handle(
        network: Network,
        peer_addrs: Vec<SocketAddrV4>,
        file_io: FileIoHandle<RReq, RResp>,
    ) -> io::Result<Self> {
        let mut ring = make_ring()?;
        let pbr = ring
            .register_provided_buffers(PROVIDED_BUF_GROUP_ID, PROVIDED_BUF_COUNT, PROVIDED_BUF_SIZE)
            .map_err(|e| io::Error::other(format!("register_provided_buffers: {e:?}")))?;

        Ok(Self {
            network,
            peer_book: PeerBook::memory(peer_addrs),
            next_peer_generation: 1,
            connect_timeout: Timespec::from_millis(CONNECT_TIMEOUT_SECS * 1_000),
            ring,
            pbr,
            send_arena: SendArena::new(),
            peers: FPool::new(),
            file_io,
        })
    }

    fn ensure_peers(&mut self) -> Result<(), FetchError> {
        let live = self.peers.live_count();
        let target = TARGET_LIVE_PEERS.min(self.peer_book.len());
        for _ in live..target {
            let Some(slot) = self.peers.free_slot() else {
                break;
            };
            let active: Vec<SocketAddrV4> = self.peers.values().map(|p| p.addr).collect();
            let Some(peer) = self.dial_next_avoiding_inner(slot, &active)? else {
                break;
            };
            self.peers.insert(slot, peer);
        }
        Ok(())
    }

    fn dial_next_inner(&mut self, slot: u16) -> Result<Option<FPeer>, FetchError> {
        self.dial_next_avoiding_inner(slot, &[])
    }

    fn dial_next_avoiding_inner(
        &mut self,
        slot: u16,
        active: &[SocketAddrV4],
    ) -> Result<Option<FPeer>, FetchError> {
        let Some(addr) = self.next_pool_addr(active) else {
            return Ok(None);
        };
        let sock = ququmatz::Socket::with_typed_flags(
            AddressFamily::Inet,
            SocketType::Stream,
            0,
            SocketFlags::NONBLOCK,
        )
        .map_err(|e| FetchError::UringErr(format!("socket: {e:?}")))?;
        let sockaddr = SockAddrIn {
            sin_family: u16::try_from(AddressFamily::Inet.as_raw()).expect("AF_INET fits u16"),
            sin_port: addr.port().to_be(),
            sin_addr: u32::from_ne_bytes(addr.ip().octets()),
            sin_zero: [0; 8],
        };

        let fd = sock.fd();
        let generation = self.next_peer_generation;
        self.next_peer_generation = self.next_peer_generation.wrapping_add(1).max(1);
        let peer = FPeer {
            addr,
            sock: Some(sock),
            sockaddr,
            state: PeerState::Connecting,
            recv_buf: Vec::with_capacity(RECV_BUF_CAPACITY),
            recv_armed: false,
            connected_at: Instant::now(),
            generation,
            pending_send_seqs: Vec::with_capacity(8),
            app: FetcherExt::new(),
        };

        self.ring.push_connect(
            slot,
            peer.generation,
            fd,
            &peer.sockaddr,
            &self.connect_timeout,
        )?;

        Ok(Some(peer))
    }

    /// Read the cached raw bytes of the block at `height`.
    ///
    /// # Errors
    /// Returns an error if the block is not cached or cannot be read.
    pub fn read_block_bytes(&mut self, height: BlockHeight) -> io::Result<Vec<u8>> {
        self.file_io.read_block(height)
    }

    /// Read and decode the cached block at `height`, checking it hashes to
    /// `expected_hash`.
    ///
    /// # Errors
    /// Returns an error if the block is not cached, cannot be read, fails to
    /// decode, or does not match `expected_hash`.
    pub fn read_block_decoded(
        &mut self,
        height: BlockHeight,
        expected_hash: Hash256,
    ) -> io::Result<mantle::primitives::Block> {
        self.file_io.read_block_decoded(height, expected_hash)
    }

    /// Resolve headers for `start..=end`, serving cached ones from disk and
    /// requesting the remainder from peers via `getheaders`.
    ///
    /// Each page is checked for `prev_block` continuity before being accepted,
    /// so the returned chain is contiguous from `locator`.
    ///
    /// # Errors
    /// Returns [`FetchError`] if no peers are configured, the peer pool is
    /// exhausted, a peer serves a discontiguous page, or the phase deadline
    /// expires.
    pub fn sync_headers(
        &mut self,
        start: BlockHeight,
        end: BlockHeight,
        locator: Hash256,
    ) -> Result<Vec<(BlockHeight, BlockHeader)>, FetchError> {
        self.sync_headers_admitted(start, end, locator, &mut AdmitAll)
    }

    /// [`Self::sync_headers`], with every page, cached or fetched, passed
    /// through `admission` before it is kept. A cached run that is refused is
    /// discarded and fetched again; a peer whose page is refused is banned.
    ///
    /// # Errors
    /// As [`Self::sync_headers`].
    pub fn sync_headers_admitted(
        &mut self,
        start: BlockHeight,
        end: BlockHeight,
        locator: Hash256,
        admission: &mut impl HeaderAdmission,
    ) -> Result<Vec<(BlockHeight, BlockHeader)>, FetchError> {
        if self.peer_book.is_empty() {
            return Err(FetchError::NoPeers);
        }

        let mut collected = self.admitted_cache(start, locator, admission)?;
        if let Some(&(cached_end, _)) = collected.last() {
            eprintln!(
                "  headers: loaded {} cached ({}..={})",
                collected.len(),
                start.to_u32(),
                cached_end.to_u32(),
            );
            if cached_end >= end {
                return Ok(collected);
            }
        }

        let (mut next_height, mut current_locator) = match collected.last() {
            None => (start.to_u32(), locator),
            Some((h, hdr)) => (h.to_u32().saturating_add(1), hdr.hash()),
        };

        loop {
            let remaining = usize::try_from(
                end.to_u32().saturating_sub(next_height).saturating_add(1),
            )
            .unwrap_or(usize::MAX);
            let page = self.run_getheaders_session(
                current_locator,
                BlockHeight::new(next_height),
                remaining,
                admission,
            )?;
            if page.is_empty() {
                eprintln!(
                    "  headers: peers agree there are no headers past height {} — at tip",
                    next_height.saturating_sub(1)
                );
                break;
            }
            let page_len = page.len();
            let mut page_bytes = Vec::with_capacity(page_len * 80);
            let mut expected_prev = current_locator;
            for (page_index, hdr) in page.into_iter().enumerate() {
                if hdr.prev_block() != expected_prev {
                    return Err(FetchError::UringErr(format!(
                        "header continuity failure at requested height {} (page index {}): expected prev {}, got {}",
                        next_height,
                        page_index,
                        expected_prev,
                        hdr.prev_block(),
                    )));
                }
                expected_prev = hdr.hash();
                let h = BlockHeight::new(next_height);
                if h > end {
                    break;
                }
                page_bytes.extend_from_slice(&hdr.to_bytes());
                collected.push((h, hdr));
                next_height = next_height.wrapping_add(1);
            }
            if page_len == 0 {
                return Err(FetchError::UringErr(
                    "peer returned an empty header page unexpectedly".to_string(),
                ));
            }
            if !page_bytes.is_empty() {
                if collected.len() == page_bytes.len() / 80 {
                    self.file_io.write_headers(start, page_bytes)?;
                } else {
                    self.file_io.append_headers(page_bytes)?;
                }
            }
            eprintln!(
                "  headers: got {page_len} in page, {} durable total (height {}..={})",
                collected.len(),
                start.to_u32(),
                next_height.saturating_sub(1),
            );
            if collected.last().is_some_and(|(h, _)| *h >= end) {
                break;
            }
            let Some(last) = collected.last() else { break };
            current_locator = last.1.hash();
        }

        Ok(collected)
    }

    /// Download every block in `headers` that is not already cached, then
    /// flush the block index.
    ///
    /// Requests are pipelined across the peer pool with hedging for slow
    /// peers and reclaim for stalled ones; black-holing peers are evicted.
    ///
    /// # Errors
    /// Returns [`FetchError`] if no peers are configured, the peer pool is
    /// exhausted, or no block arrives before the no-progress deadline.
    pub fn fetch_blocks(
        &mut self,
        headers: &[(BlockHeight, BlockHeader)],
    ) -> Result<(), FetchError> {
        let wanted: Vec<(BlockHeight, Hash256)> =
            headers.iter().map(|(h, hdr)| (*h, hdr.hash())).collect();
        self.fetch_blocks_by_hash(&wanted)
    }

    /// Download the blocks with the given hashes, without syncing headers.
    /// Each block is cached under the paired height, which is only used as
    /// the cache key and is not checked against the chain.
    ///
    /// # Errors
    /// Returns [`FetchError`] if no peers are configured, the peer pool is
    /// exhausted, or no block arrives before the no-progress deadline. Blocks
    /// that arrived before the error stay cached.
    pub fn fetch_blocks_by_hash(
        &mut self,
        wanted: &[(BlockHeight, Hash256)],
    ) -> Result<(), FetchError> {
        if self.peer_book.is_empty() {
            return Err(FetchError::NoPeers);
        }
        let needed: Vec<(BlockHeight, Hash256)> = wanted
            .iter()
            .filter(|(h, _)| !self.file_io.has_block(*h))
            .copied()
            .collect();
        if needed.is_empty() {
            return Ok(());
        }
        self.run_block_download_session(&needed)?;
        self.file_io.flush_block_index()?;
        Ok(())
    }

    /// Drop every cached block and truncate the block file, keeping headers.
    ///
    /// # Errors
    /// Returns an error if the block file cannot be truncated.
    pub fn discard_cached_blocks(&mut self) -> io::Result<()> {
        self.file_io.discard_blocks()
    }

    // ── headers session ────────────────────────────────────────────────

    fn admitted_cache(
        &mut self,
        start: BlockHeight,
        locator: Hash256,
        admission: &mut impl HeaderAdmission,
    ) -> Result<Vec<(BlockHeight, BlockHeader)>, FetchError> {
        let cached = self.file_io.load_cached_headers(start)?;
        if cached.is_empty() {
            return Ok(cached);
        }
        let headers: Vec<BlockHeader> = cached.iter().map(|(_, header)| *header).collect();
        match HeaderPage::new(locator, &headers).admit(start, admission) {
            Ok(()) => Ok(cached),
            Err(reason) => {
                eprintln!("  headers: discarding {} cached headers: {reason}", cached.len());
                self.file_io.write_headers(start, Vec::new())?;
                Ok(Vec::new())
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn run_getheaders_session(
        &mut self,
        locator: Hash256,
        first: BlockHeight,
        limit: usize,
        admission: &mut impl HeaderAdmission,
    ) -> Result<Vec<BlockHeader>, FetchError> {
        self.ensure_peers()?;
        if self.peers.is_empty() {
            return Err(FetchError::PoolExhausted);
        }
        for (_slot, peer) in self.peers.iter_mut() {
            if peer.app.headers_request.is_some_and(|(l, _)| l != locator) {
                peer.app.headers_request = None;
            }
        }
        eprintln!(
            "  headers: requesting next page with {} active peers and {} candidates",
            self.peers.live_count(),
            self.peer_book.len(),
        );
        for (slot, peer) in self.peers.iter_mut() {
            if !peer.recv_armed
                && peer.state != PeerState::Dead
                && peer.state != PeerState::Connecting
                && peer.fd().is_some()
            {
                self.ring.push_recv_multishot(
                    slot,
                    peer.generation,
                    peer.fd().ok_or(FetchError::NoPeers)?,
                    PROVIDED_BUF_GROUP_ID,
                )?;
                peer.recv_armed = true;
            }
        }

        let phase_deadline = Instant::now() + Duration::from_secs(HEADERS_PHASE_DEADLINE_SECS);
        let payload = getheaders_payload(locator);
        let mut version_payload = Vec::new();
        encode_version("/mantle-replay-iouring:0.1.0/", &mut version_payload);
        let mut last_status = Instant::now();

        loop {
            self.ring.push_tick(Duration::from_secs(1))?;
            self.ring.submit_and_wait(1).map_err(uring_err)?;

            let mut drained = 0usize;
            while drained < CQE_DRAIN_CAP {
                let Some(cqe) = self.ring.complete() else {
                    break;
                };
                drained += 1;
                let cqd = CqeData::decode(cqe.user_data());
                if cqd.op == Op::Tick {
                    continue;
                }
                if cqd.op == Op::Send {
                    let send_seq = CqeData::decode_send_seq(cqe.user_data());
                    self.send_arena.release(send_seq);
                    if let Some(p) = self.peers.get_mut(cqd.slot) {
                        p.pending_send_seqs.retain(|s| *s != send_seq);
                    }
                }
                if cqd.op == Op::LinkTimeout || cqd.op == Op::Close {
                    continue;
                }
                let res = cqe.raw_result();
                let owned = self
                    .peers
                    .get_mut(cqd.slot)
                    .is_some_and(|peer| peer.generation == cqd.generation);
                if !owned {
                    self.recycle_orphan_buffer(cqd.op, cqe.flags());
                    continue;
                }
                let Some(peer) = self.peers.get_mut(cqd.slot) else {
                    continue;
                };
                handle_connect_or_recv(
                    &mut self.ring,
                    &mut self.pbr,
                    &mut self.send_arena,
                    self.network,
                    cqd.slot,
                    peer,
                    cqd.op,
                    res,
                    cqe.flags(),
                    &version_payload,
                )?;
            }

            // Parse frames: handshake + headers
            let mut got_headers: Option<Vec<BlockHeader>> = None;
            let mut discovered = Vec::new();
            for (slot, peer) in self.peers.iter_mut() {
                if peer.state == PeerState::Dead {
                    continue;
                }
                let mut peer_headers = None;
                consume_handshake_frames(
                    &mut self.ring,
                    &mut self.send_arena,
                    self.network,
                    slot,
                    peer,
                    |cmd, payload| {
                        discovered.extend(PeerBook::decode(cmd, payload));
                        if cmd.as_str() == "headers" {
                            let mut headers = Vec::new();
                            if HeadersMsg::decode_into_limited::<2_000>(
                                &mut std::io::Cursor::new(payload),
                                &mut headers,
                            )
                            .is_ok()
                                && headers.first().is_none_or(|h| h.prev_block() == locator)
                            {
                                peer_headers = Some(headers);
                            }
                        }
                    },
                )?;
                if let Some(mut headers) = peer_headers {
                    peer.app.headers_request = None;
                    headers.truncate(limit);
                    if headers.is_empty() {
                        peer.app.headers_empty_for = Some(locator);
                    } else if got_headers.is_none() {
                        match HeaderPage::new(locator, &headers).admit(first, admission) {
                            Ok(()) => got_headers = Some(headers),
                            Err(reason) => {
                                eprintln!("  headers: banning {} for its page: {reason}", peer.addr);
                                self.peer_book.ban(peer.addr);
                                peer.close(&mut self.ring, &mut self.send_arena);
                                peer.state = PeerState::Dead;
                                continue;
                            }
                        }
                    }
                }
                if peer.state == PeerState::Ready && !peer.app.discovery_requested {
                    let fd = peer.fd().ok_or(FetchError::NoPeers)?;
                    let sequence = self.ring.push_send(
                        &mut self.send_arena,
                        self.network,
                        Command::GetAddr,
                        &[],
                        slot,
                        peer.generation,
                        fd,
                    )?;
                    peer.pending_send_seqs.push(sequence);
                    peer.app.discovery_requested = true;
                }
            }
            let added = self.peer_book.extend(discovered)?;
            if added > 0 {
                eprintln!(
                    "  headers: discovered {added} new peers ({} candidates)",
                    self.peer_book.len()
                );
                self.ensure_peers()?;
            }

            if let Some(headers) = got_headers {
                return Ok(headers);
            }

            let empty_votes = self
                .peers
                .values()
                .filter(|peer| peer.app.headers_empty_for == Some(locator))
                .count();
            let ready_peers = self
                .peers
                .values()
                .filter(|peer| peer.state == PeerState::Ready)
                .count();
            if TipQuorum::new(HEADERS_TIP_QUORUM).reached(empty_votes, ready_peers) {
                return Ok(Vec::new());
            }

            let now = Instant::now();
            if now > phase_deadline {
                if empty_votes > 0 {
                    eprintln!(
                        "  headers: deadline passed with {empty_votes} empty replies and no headers; treating as tip"
                    );
                    return Ok(Vec::new());
                }
                return Err(FetchError::Timeout("headers"));
            }
            if now.duration_since(last_status) >= Duration::from_secs(5) {
                let ready = self
                    .peers
                    .values()
                    .filter(|p| p.state == PeerState::Ready)
                    .count();
                let connecting = self
                    .peers
                    .values()
                    .filter(|p| p.state == PeerState::Connecting)
                    .count();
                let handshaking = self
                    .peers
                    .values()
                    .filter(|p| {
                        matches!(
                            p.state,
                            PeerState::HandshakeVersionSent | PeerState::HandshakeRecving
                        )
                    })
                    .count();
                let dead = self
                    .peers
                    .values()
                    .filter(|p| p.state == PeerState::Dead)
                    .count();
                let waiting = self
                    .peers
                    .values()
                    .filter(|peer| peer.app.headers_request.is_some())
                    .count();
                eprintln!(
                    "  headers: ready={ready} connecting={connecting} handshaking={handshaking} \
                     waiting={waiting} dead={dead}"
                );
                last_status = now;
            }

            // Timeout stale peers.
            for (_slot, peer) in self.peers.iter_mut() {
                if peer.state == PeerState::Dead {
                    continue;
                }
                if peer.state == PeerState::Connecting
                    && now.duration_since(peer.connected_at)
                        > Duration::from_secs(CONNECT_TIMEOUT_SECS + 2)
                {
                    peer.close(&mut self.ring, &mut self.send_arena);
                    peer.state = PeerState::Dead;
                }
                if Self::handshake_stalled(peer, now) {
                    peer.close(&mut self.ring, &mut self.send_arena);
                    peer.state = PeerState::Dead;
                }
            }

            for (slot, peer) in self.peers.iter_mut() {
                if peer.app.headers_request.is_some_and(|(_, sent)| {
                    now.duration_since(sent) > Duration::from_secs(HEADERS_RESPONSE_TIMEOUT_SECS)
                }) {
                    eprintln!("  headers: peer {slot} response timeout; retrying");
                    peer.app.headers_request = None;
                }
            }

            let dead: Vec<u16> = self.peers.dead_slots().to_vec();
            for slot in dead {
                self.peers.remove(slot);
                if let Some(peer) = self.dial_next_inner(slot)? {
                    self.peers.insert(slot, peer);
                }
            }
            if self.peers.live_count() == 0 {
                eprintln!("  iouring-fetcher: all header peers dead, recycling the pool");
                self.peer_book.reset();
                self.ensure_peers()?;
                if self.peers.is_empty() {
                    return Err(FetchError::PoolExhausted);
                }
            }

            for (slot, peer) in self.peers.iter_mut() {
                if peer.state != PeerState::Ready
                    || peer.app.headers_request.is_some()
                    || peer.app.headers_empty_for == Some(locator)
                {
                    continue;
                }
                let sequence = self.ring.push_send(
                    &mut self.send_arena,
                    self.network,
                    Command::GetHeaders,
                    &payload,
                    slot,
                    peer.generation,
                    peer.fd().ok_or(FetchError::NoPeers)?,
                )?;
                peer.pending_send_seqs.push(sequence);
                peer.app.headers_request = Some((locator, Instant::now()));
            }

            // Re-arm recv.
            for (slot, peer) in self.peers.iter_mut() {
                if !peer.recv_armed
                    && peer.state != PeerState::Dead
                    && peer.state != PeerState::Connecting
                    && peer.fd().is_some()
                {
                    self.ring.push_recv_multishot(
                        slot,
                        peer.generation,
                        peer.fd().ok_or(FetchError::NoPeers)?,
                        PROVIDED_BUF_GROUP_ID,
                    )?;
                    peer.recv_armed = true;
                }
            }

            self.pbr.commit();
        }
    }

    // ── block download session ─────────────────────────────────────────

    #[allow(clippy::too_many_lines)]
    fn run_block_download_session(
        &mut self,
        needed: &[(BlockHeight, Hash256)],
    ) -> Result<(), FetchError> {
        self.ensure_peers()?;
        if self.peers.is_empty() {
            return Err(FetchError::PoolExhausted);
        }

        let mut pending: PrehashedMap<Hash256, BlockHeight> =
            HashMap::with_capacity_and_hasher(needed.len(), BuildPrehashedHasher);
        for (h, hash) in needed {
            pending.insert(*hash, *h);
        }

        let mut todo: VecDeque<Hash256> = needed.iter().map(|(_, h)| *h).collect();
        let mut in_flight: PrehashedMap<Hash256, InFlight> =
            HashMap::with_capacity_and_hasher(needed.len() / 4 + 16, BuildPrehashedHasher);
        let mut ewma = EwmaLatency::new();
        let mut tried: PrehashedMap<Hash256, Vec<SocketAddrV4>> =
            HashMap::with_hasher(BuildPrehashedHasher);

        let mut saved = 0usize;
        let total = needed.len();
        let mut last_progress = Instant::now();
        let mut last_log = Instant::now();
        let mut saved_at_last_log = 0usize;
        let log_interval = Duration::from_secs(2);
        let mut version_payload = Vec::new();
        encode_version("/mantle-replay-iouring:0.1.0/", &mut version_payload);

        loop {
            self.ring.push_tick(Duration::from_secs(1))?;
            self.ring.submit_and_wait(1).map_err(uring_err)?;

            let mut arrivals: Vec<(Hash256, u16)> = Vec::new();
            let mut drained = 0usize;
            while drained < CQE_DRAIN_CAP {
                let Some(cqe) = self.ring.complete() else {
                    break;
                };
                drained += 1;
                let cqd = CqeData::decode(cqe.user_data());
                if cqd.op == Op::Tick {
                    continue;
                }
                if cqd.op == Op::Send {
                    let send_seq = CqeData::decode_send_seq(cqe.user_data());
                    self.send_arena.release(send_seq);
                    if let Some(p) = self.peers.get_mut(cqd.slot) {
                        p.pending_send_seqs.retain(|s| *s != send_seq);
                    }
                }
                if cqd.op == Op::LinkTimeout || cqd.op == Op::Close {
                    continue;
                }
                let owned = self
                    .peers
                    .get_mut(cqd.slot)
                    .is_some_and(|peer| peer.generation == cqd.generation);
                if !owned {
                    self.recycle_orphan_buffer(cqd.op, cqe.flags());
                    continue;
                }
                let Some(peer) = self.peers.get_mut(cqd.slot) else {
                    continue;
                };
                handle_connect_or_recv(
                    &mut self.ring,
                    &mut self.pbr,
                    &mut self.send_arena,
                    self.network,
                    cqd.slot,
                    peer,
                    cqd.op,
                    cqe.raw_result(),
                    cqe.flags(),
                    &version_payload,
                )?;
            }

            self.pbr.commit();

            // Parse frames: handshake + blocks.
            for (slot, peer) in self.peers.iter_mut() {
                if peer.state == PeerState::Dead {
                    continue;
                }
                consume_block_frames(
                    &mut self.ring,
                    &mut self.send_arena,
                    self.network,
                    slot,
                    peer,
                    &mut pending,
                    &mut saved,
                    &mut arrivals,
                    &mut self.file_io,
                )?;
            }

            if !arrivals.is_empty() {
                let arrived_at = Instant::now();
                last_progress = arrived_at;
                for (hash, winner) in &arrivals {
                    tried.remove(hash);
                    let Some(info) = in_flight.remove(hash) else {
                        continue;
                    };
                    ewma.observe(arrived_at.duration_since(info.issued_at(*winner)));
                    for (slot, issued) in info.beaten_by(*winner) {
                        if let Some(peer) = self.peers.get_mut(slot) {
                            peer.app
                                .record_beaten(hash, arrived_at.duration_since(issued));
                        }
                    }
                    for slot in info.outrun_by(*winner) {
                        if let Some(peer) = self.peers.get_mut(slot) {
                            peer.app.cancel(hash);
                        }
                    }
                }
            }
            if saved == total {
                return Ok(());
            }
            if last_progress.elapsed() > Duration::from_secs(BLOCK_NO_PROGRESS_TIMEOUT_SECS) {
                return Err(FetchError::Timeout("block-download"));
            }

            let now = Instant::now();

            if now.duration_since(last_log) >= log_interval {
                let window = now.duration_since(last_log).as_secs_f64().max(1e-9);
                #[allow(clippy::cast_precision_loss)]
                let bps = (saved - saved_at_last_log) as f64 / window;
                let ready = self
                    .peers
                    .values()
                    .filter(|p| p.state == PeerState::Ready)
                    .count();
                let in_flight_count = in_flight.len();
                let connecting = self
                    .peers
                    .values()
                    .filter(|p| p.state == PeerState::Connecting)
                    .count();
                let handshaking = self
                    .peers
                    .values()
                    .filter(|p| {
                        matches!(
                            p.state,
                            PeerState::HandshakeVersionSent | PeerState::HandshakeRecving
                        )
                    })
                    .count();
                let dead = self
                    .peers
                    .values()
                    .filter(|p| p.state == PeerState::Dead)
                    .count();
                eprintln!(
                    "  iouring-fetcher: {saved}/{total}  {bps:.1} blk/s  ready={ready} \
                     connecting={connecting} handshaking={handshaking} dead={dead} \
                     in_flight={in_flight_count} todo={} ewma={}ms median={}ms \
                     book={} banned={}",
                    todo.len(),
                    ewma.as_millis(),
                    PeerScore::median_ms(self.peers.values().map(|p| p.app.score)).unwrap_or(0),
                    self.peer_book.len(),
                    self.peer_book.banned_count(),
                );
                last_log = now;
                saved_at_last_log = saved;
            }

            let fleet_median = PeerScore::median_ms(self.peers.values().map(|p| p.app.score));
            let policy = HedgePolicy::select(todo.is_empty(), fleet_median, ewma.as_millis());
            let fanout = policy.fanout();
            let mut to_hedge: Vec<Hash256> = Vec::new();
            let mut to_reclaim: Vec<Hash256> = Vec::new();
            for (hash, info) in &in_flight {
                match policy.action(
                    now.duration_since(info.first_issued()),
                    now.duration_since(info.last_issued()),
                    info.holders().len(),
                ) {
                    HedgeAction::Reclaim => to_reclaim.push(*hash),
                    HedgeAction::Hedge => to_hedge.push(*hash),
                    HedgeAction::Wait => {}
                }
            }
            for hash in to_reclaim {
                if let Some(info) = in_flight.remove(&hash) {
                    for &(slot, issued) in info.holders() {
                        if let Some(peer) = self.peers.get_mut(slot) {
                            peer.app.record_reclaim(&hash, now.duration_since(issued));
                        }
                    }
                }
                if tried.get(&hash).is_some_and(|t| t.len() >= TRIED_LIMIT) {
                    tried.remove(&hash);
                }
                todo.push_front(hash);
            }

            // Timeout / black-hole / slow-peer detection.
            for (slot, peer) in self.peers.iter_mut() {
                if peer.state == PeerState::Connecting
                    && now.duration_since(peer.connected_at)
                        > Duration::from_secs(CONNECT_TIMEOUT_SECS + 2)
                {
                    peer.close(&mut self.ring, &mut self.send_arena);
                    peer.state = PeerState::Dead;
                    continue;
                }
                if Self::handshake_stalled(peer, now) {
                    peer.close(&mut self.ring, &mut self.send_arena);
                    peer.state = PeerState::Dead;
                    continue;
                }
                if peer.state == PeerState::Ready
                    && peer.app.liveness.is_unresponsive(now, fleet_median)
                {
                    eprintln!(
                        "  iouring-fetcher: peer slot={slot} ({}) is unresponsive \
                         (owed {}s, strikes={} assigned={} delivered={}) — evicting",
                        peer.addr,
                        peer.app
                            .liveness
                            .owed_for(now)
                            .unwrap_or_default()
                            .as_secs(),
                        peer.app.liveness.strikes(),
                        peer.app.assigned_count,
                        peer.app.delivered_count,
                    );
                    self.peer_book.ban(peer.addr);
                    peer.close(&mut self.ring, &mut self.send_arena);
                    peer.state = PeerState::Dead;
                    continue;
                }
                if peer.state == PeerState::Ready && peer.app.score.is_slow(fleet_median) {
                    eprintln!(
                        "  iouring-fetcher: peer slot={slot} ({}) is slow \
                         (expected {}ms, fleet median {}ms) — evicting",
                        peer.addr,
                        peer.app.score.expected_ms(),
                        fleet_median.unwrap_or(0),
                    );
                    self.peer_book.ban(peer.addr);
                    peer.close(&mut self.ring, &mut self.send_arena);
                    peer.state = PeerState::Dead;
                }
            }

            let dead: Vec<u16> = self.peers.dead_slots().to_vec();
            for slot in dead {
                if let Some(p) = self.peers.remove(slot) {
                    for (h, _) in p.app.in_flight {
                        if let Some(info) = in_flight.get_mut(&h) {
                            info.drop_holder(slot);
                            if info.holders().is_empty() {
                                in_flight.remove(&h);
                                todo.push_front(h);
                            }
                        }
                    }
                }
            }
            self.ensure_peers()?;

            for hash in to_hedge {
                let Some(info) = in_flight.get(&hash).cloned() else {
                    continue;
                };
                if info.holders().len() >= fanout {
                    continue;
                }
                let tried_addrs = tried.entry(hash).or_default().clone();
                let pick = self
                    .peers
                    .iter_mut()
                    .filter(|(slot, peer)| {
                        peer.state == PeerState::Ready
                            && peer.app.in_flight.len() < peer.app.score.inflight_cap(fleet_median)
                            && !info.holds(*slot)
                            && !tried_addrs.contains(&peer.addr)
                    })
                    .min_by_key(|(_, peer)| peer.app.score.expected_ms());
                if let Some((slot, peer)) = pick {
                    let pl = encode_getdata(&[hash]);
                    let seq = self.ring.push_send(
                        &mut self.send_arena,
                        self.network,
                        Command::GetData,
                        &pl,
                        slot,
                        peer.generation,
                        peer.fd().ok_or(FetchError::NoPeers)?,
                    )?;
                    peer.pending_send_seqs.push(seq);
                    peer.app.record_request(hash, now);
                    tried.entry(hash).or_default().push(peer.addr);
                    if let Some(info) = in_flight.get_mut(&hash) {
                        info.add_holder(slot, now);
                    }
                }
            }

            let mut by_speed: Vec<u16> = self
                .peers
                .iter_mut()
                .filter(|(_, peer)| peer.state == PeerState::Ready)
                .map(|(slot, _)| slot)
                .collect();
            by_speed.sort_by_key(|slot| {
                self.peers
                    .get_mut(*slot)
                    .map_or(u64::MAX, |peer| peer.app.score.expected_ms())
            });
            for slot in by_speed {
                let Some(peer) = self.peers.get_mut(slot) else {
                    continue;
                };
                let cap = peer.app.score.inflight_cap(fleet_median);
                while peer.app.in_flight.len() < cap {
                    let Some(index) = todo
                        .iter()
                        .position(|hash| tried.get(hash).is_none_or(|t| !t.contains(&peer.addr)))
                    else {
                        break;
                    };
                    let Some(hash) = todo.remove(index) else {
                        break;
                    };
                    tried.entry(hash).or_default().push(peer.addr);
                    let pl = encode_getdata(&[hash]);
                    let seq = self.ring.push_send(
                        &mut self.send_arena,
                        self.network,
                        Command::GetData,
                        &pl,
                        slot,
                        peer.generation,
                        peer.fd().ok_or(FetchError::NoPeers)?,
                    )?;
                    peer.pending_send_seqs.push(seq);
                    peer.app.record_request(hash, now);
                    in_flight.insert(hash, InFlight::new(slot, now));
                }
            }

            // Re-arm recv.
            for (slot, peer) in self.peers.iter_mut() {
                if !peer.recv_armed
                    && peer.state != PeerState::Dead
                    && peer.state != PeerState::Connecting
                    && peer.fd().is_some()
                {
                    self.ring.push_recv_multishot(
                        slot,
                        peer.generation,
                        peer.fd().ok_or(FetchError::NoPeers)?,
                        PROVIDED_BUF_GROUP_ID,
                    )?;
                    peer.recv_armed = true;
                }
            }

            self.pbr.commit();

            if self.peers.is_empty() && in_flight.is_empty() && todo.is_empty() {
                return Ok(());
            }
            if self.peers.live_count() == 0 {
                eprintln!("  iouring-fetcher: all peers dead, recycling the pool");
                self.peer_book.reset();
                self.ensure_peers()?;
                if self.peers.is_empty() {
                    return Err(FetchError::PoolExhausted);
                }
            }
        }
    }

    fn recycle_orphan_buffer(&mut self, op: Op, flags: ququmatz::types::CqeFlags) {
        if op != Op::Recv {
            return;
        }
        if let Some(buf_id) = decode_cqe_buffer_id(flags) {
            self.pbr.recycle(buf_id);
        }
    }

    fn handshake_stalled(peer: &FPeer, now: Instant) -> bool {
        matches!(
            peer.state,
            PeerState::HandshakeVersionSent | PeerState::HandshakeRecving
        ) && now.duration_since(peer.connected_at) > Duration::from_secs(HANDSHAKE_TIMEOUT_SECS)
    }

    fn next_pool_addr(&mut self, avoid: &[SocketAddrV4]) -> Option<SocketAddrV4> {
        self.peer_book.next_avoiding(avoid)
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn handle_connect_or_recv(
    ring: &mut IoUring,
    pbr: &mut ququmatz::ProvidedBufferRing,
    send_arena: &mut SendArena,
    network: Network,
    slot: u16,
    peer: &mut FPeer,
    op: Op,
    res: i32,
    cqe_flags: ququmatz::types::CqeFlags,
    version_payload: &[u8],
) -> Result<(), FetchError> {
    match op {
        Op::Connect => {
            if res < 0 {
                peer.state = PeerState::Dead;
                peer.close(ring, send_arena);
                return Ok(());
            }
            ring.push_recv_multishot(
                slot,
                peer.generation,
                peer.fd().ok_or(FetchError::NoPeers)?,
                PROVIDED_BUF_GROUP_ID,
            )?;
            peer.recv_armed = true;
            let seq = ring.push_send(
                send_arena,
                network,
                Command::Version,
                version_payload,
                slot,
                peer.generation,
                peer.fd().ok_or(FetchError::NoPeers)?,
            )?;
            peer.pending_send_seqs.push(seq);
            peer.state = PeerState::HandshakeVersionSent;
            Ok(())
        }
        Op::Send if res < 0 => {
            peer.state = PeerState::Dead;
            peer.close(ring, send_arena);
            Ok(())
        }
        Op::Recv => {
            peer.ingest_recv_cqe(pbr, send_arena, cqe_flags, res, ring);
            Ok(())
        }
        _ => Ok(()),
    }
}

#[allow(clippy::too_many_arguments)]
fn consume_block_frames<RReq, RResp>(
    ring: &mut IoUring,
    send_arena: &mut SendArena,
    network: Network,
    slot: u16,
    peer: &mut FPeer,
    pending: &mut PrehashedMap<Hash256, BlockHeight>,
    saved: &mut usize,
    arrived: &mut Vec<(Hash256, u16)>,
    file_io: &mut FileIoHandle<RReq, RResp>,
) -> Result<(), FetchError>
where
    RReq: Deref<Target = MpscRing<FileReq>>,
    RResp: Deref<Target = SpscRing<FileResp>>,
{
    while peer.recv_buf.len() >= MessageHeader::ENCODED_LEN {
        let Ok(header) = MessageHeader::decode(&mut std::io::Cursor::new(
            &peer.recv_buf[..MessageHeader::ENCODED_LEN],
        )) else {
            break;
        };
        let total = MessageHeader::ENCODED_LEN + header.length() as usize;
        if peer.recv_buf.len() < total {
            break;
        }
        let payload_slice = &peer.recv_buf[MessageHeader::ENCODED_LEN..total];
        if Hash256::checksum(payload_slice) != header.checksum() {
            eprintln!(
                "  iouring-fetcher: checksum mismatch on {} from slot={slot} ({} bytes) — dropping peer",
                header.command().as_str(),
                payload_slice.len()
            );
            peer.state = PeerState::Dead;
            peer.close(ring, send_arena);
            return Ok(());
        }
        let command = header.command();
        let cmd = command.as_str();
        match (peer.state, cmd) {
            (PeerState::HandshakeVersionSent | PeerState::HandshakeRecving, "version") => {
                let seq = ring.push_send(
                    send_arena,
                    network,
                    Command::Verack,
                    &[],
                    slot,
                    peer.generation,
                    peer.fd().ok_or(FetchError::NoPeers)?,
                )?;
                peer.pending_send_seqs.push(seq);
                peer.state = PeerState::HandshakeRecving;
            }
            (PeerState::HandshakeRecving | PeerState::HandshakeVersionSent, "verack") => {
                peer.state = PeerState::Ready;
            }
            (PeerState::Ready, "block") => {
                use mantle::primitives::Block;
                let block = match Block::decode(&mut std::io::Cursor::new(payload_slice)) {
                    Ok(block) => block,
                    Err(error) => {
                        eprintln!(
                            "  iouring-fetcher: undecodable block from slot={slot} ({} bytes): {error}",
                            payload_slice.len()
                        );
                        peer.recv_buf.drain(..total);
                        continue;
                    }
                };
                let hash = block.header.hash();
                peer.app.record_arrival(&hash);
                if let Some(height) = pending.remove(&hash) {
                    file_io.write_block_async(height, payload_slice.to_vec())?;
                    *saved += 1;
                    peer.app.record_delivery();
                    arrived.push((hash, slot));
                }
            }
            (_, "ping") => {
                if peer.pending_send_seqs.len() >= mantle_transport::PEER_SEND_OUTSTANDING_CAP {
                    peer.state = PeerState::Dead;
                    peer.close(ring, send_arena);
                    return Ok(());
                }
                let mut nonce = [0u8; 8];
                let copy_len = payload_slice.len().min(8);
                nonce[..copy_len].copy_from_slice(&payload_slice[..copy_len]);
                let seq = ring.push_send(
                    send_arena,
                    network,
                    Command::Pong,
                    &nonce[..copy_len],
                    slot,
                    peer.generation,
                    peer.fd().ok_or(FetchError::NoPeers)?,
                )?;
                peer.pending_send_seqs.push(seq);
            }
            _ => {}
        }
        peer.recv_buf.drain(..total);
    }
    Ok(())
}

fn encode_getdata(hashes: &[Hash256]) -> Vec<u8> {
    let entries: Vec<InvEntry> = hashes
        .iter()
        .map(|&hash| InvEntry::new(InvType::WitnessBlock, hash))
        .collect();
    let mut buf = Vec::new();
    InvMsg(entries)
        .encode(&mut buf)
        .expect("Vec write cannot fail");
    buf
}

fn getheaders_payload(locator: Hash256) -> Vec<u8> {
    let msg = GetHeadersMsg {
        version: mantle::network::ProtocolVersion::new(70016),
        locator_hashes: vec![locator],
        stop_hash: Hash256::ZERO,
    };
    let mut buf = Vec::new();
    msg.encode(&mut buf).expect("Vec<u8> Write is infallible");
    buf
}
