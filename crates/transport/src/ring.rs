use std::io;
use std::time::Duration;

use mantle::network::{Command, Network};
use ququmatz::types::{MsgFlags, RawFd, SockAddrIn, SqeFlags, TimeoutFlags, Timespec};
use ququmatz::{IoUring, ProvidedBufferRing, Sqe};

use crate::arena::SendArena;
use crate::ops::{CqeData, Op, decode_cqe_buffer_id};
use crate::peer::{Peer, PeerState};

const RING_ENTRIES: u32 = 32_768;

pub fn make_ring() -> Result<IoUring, io::Error> {
    let bare = std::env::var_os("MANTLE_URING_BARE").is_some_and(|v| v == "1");
    if bare {
        eprintln!("  io_uring: bare (MANTLE_URING_BARE=1)");
    } else if let Ok(ring) = ququmatz::IoUringBuilder::new(RING_ENTRIES).single_issuer().build() {
        return Ok(ring);
    }
    IoUring::new(RING_ENTRIES).map_err(|e| io::Error::other(format!("IoUring::new: {e:?}")))
}

pub trait IoUringExt {
    fn push_connect(
        &mut self,
        slot: u16,
        g: u16,
        fd: RawFd,
        sockaddr: &SockAddrIn,
        timeout: &Timespec,
    ) -> Result<(), io::Error>;

    #[allow(clippy::too_many_arguments)]
    fn push_send(
        &mut self,
        arena: &mut SendArena,
        network: Network,
        cmd: Command,
        payload: &[u8],
        slot: u16,
        g: u16,
        fd: RawFd,
    ) -> Result<u16, io::Error>;

    fn push_recv_multishot(
        &mut self,
        slot: u16,
        g: u16,
        fd: RawFd,
        buf_group_id: u16,
    ) -> Result<(), io::Error>;

    fn push_tick(&mut self, dur: Duration) -> Result<(), io::Error>;
}

impl IoUringExt for IoUring {
    fn push_connect(
        &mut self,
        slot: u16,
        g: u16,
        fd: RawFd,
        sockaddr: &SockAddrIn,
        timeout: &Timespec,
    ) -> Result<(), io::Error> {
        let address = sockaddr.to_bytes();
        // SAFETY: the kernel copies `address` and `timeout` when it prepares
        // these SQEs, which happens inside the `submit` below, while both are
        // still borrowed here.
        let sqe = unsafe { Sqe::connect(fd, &address) }
            .user_data(CqeData::encode(slot, g, Op::Connect))
            .flags(SqeFlags::IO_LINK);
        self.push(sqe).map_err(uring_err)?;
        let deadline = unsafe { Sqe::link_timeout(timeout, TimeoutFlags::default()) };
        self.push(deadline.user_data(CqeData::encode(slot, g, Op::LinkTimeout)))
            .map_err(uring_err)?;
        self.submit().map_err(uring_err)?;
        Ok(())
    }

    fn push_send(
        &mut self,
        arena: &mut SendArena,
        network: Network,
        cmd: Command,
        payload: &[u8],
        slot: u16,
        g: u16,
        fd: RawFd,
    ) -> Result<u16, io::Error> {
        let send_seq = arena
            .frame_into(network.magic(), cmd, payload)
            .ok_or_else(|| {
                io::Error::other(format!(
                    "send arena exhausted (peer slot={slot} g={g}, free={} cap={})",
                    arena.free_count(),
                    SendArena::slot_count()
                ))
            })?;
        let handle = arena.handle(send_seq);
        // SAFETY: the arena slot stays reserved until the send completion releases it.
        let sqe = unsafe { Sqe::send(fd, handle.as_slice(), MsgFlags::default()) }
            .user_data(CqeData::encode_send(slot, g, send_seq));
        let r = self.push(sqe).map_err(uring_err);
        match r {
            Ok(()) => Ok(send_seq),
            Err(e) => {
                arena.release(send_seq);
                Err(e)
            }
        }
    }

    fn push_recv_multishot(
        &mut self,
        slot: u16,
        g: u16,
        fd: RawFd,
        buf_group_id: u16,
    ) -> Result<(), io::Error> {
        self.push(
            Sqe::recv_multishot(fd, MsgFlags::default())
                .buffer_select(buf_group_id)
                .user_data(CqeData::encode(slot, g, Op::Recv)),
        )
        .map_err(uring_err)
    }

    fn push_tick(&mut self, dur: Duration) -> Result<(), io::Error> {
        let ts = Timespec::from_millis(u64::try_from(dur.as_millis()).unwrap_or(u64::MAX));
        // SAFETY: the kernel copies `ts` when it prepares the SQE, inside the
        // `submit` below, while `ts` is still alive.
        let tick = unsafe { Sqe::timeout(&ts, 1, TimeoutFlags::default()) };
        self.push(tick.user_data(CqeData::encode(0, 0, Op::Tick)))
            .map_err(uring_err)?;
        self.submit().map(|_| ()).map_err(uring_err)
    }
}

impl<T> Peer<T> {
    pub fn close(&mut self, ring: &mut IoUring, send_arena: &mut SendArena) {
        for seq in self.pending_send_seqs.drain(..) {
            send_arena.release(seq);
        }
        if let Some(sock) = self.sock.take() {
            let fd = sock.fd();
            if let Err(e) = ring.push(
                Sqe::cancel(CqeData::encode(0, self.generation, Op::Recv)).user_data(
                    CqeData::encode(0, self.generation, Op::Close),
                ),
            ) {
                eprintln!("  transport: close cancel-recv push failed for fd={fd:?}: {e:?}");
            }
            if ring
                .push(Sqe::close(fd).user_data(CqeData::encode(0, self.generation, Op::Close)))
                .is_ok()
            {
                // Async close SQE accepted — the kernel owns the fd now.
                // Prevent Socket::drop from closing it synchronously.
                let _ = sock.into_fd();
            } else {
                // Ring full — Socket::drop will close synchronously.
                eprintln!(
                    "  transport: close push failed for fd={fd:?} (closed synchronously)"
                );
            }
        }
    }

    pub fn ingest_recv_cqe(
        &mut self,
        pbr: &mut ProvidedBufferRing,
        send_arena: &mut SendArena,
        cqe_flags: ququmatz::types::CqeFlags,
        res: i32,
        ring: &mut IoUring,
    ) {
        use ququmatz::types::CqeFlags;
        if res <= 0 {
            if res < 0 {
                eprintln!(
                    "  transport: recv failed for {} with errno {}",
                    self.addr, -res
                );
            }
            self.state = PeerState::Dead;
            self.recv_armed = false;
            self.close(ring, send_arena);
            return;
        }
        #[allow(clippy::cast_sign_loss)]
        let n = res as u32;
        if let Some(buf_id) = decode_cqe_buffer_id(cqe_flags) {
            match pbr.buffer(buf_id, n) {
                Some(bytes) => self.recv_buf.extend_from_slice(bytes),
                None => {
                    eprintln!(
                        "  transport: pbr.buffer({buf_id}, {n}) returned None \
                         (buf_size={}, entries={})",
                        pbr.buf_size(),
                        pbr.entries(),
                    );
                }
            }
            pbr.recycle(buf_id);
        } else {
            eprintln!(
                "  transport: recv CQE with res={n} has no BUFFER flag \
                 (multishot setup is broken)"
            );
        }
        if !cqe_flags.contains(CqeFlags::MORE) {
            self.recv_armed = false;
        }
    }
}

fn uring_err(e: ququmatz::Error) -> io::Error {
    io::Error::other(format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;
    use std::time::Instant;

    /// Build a `Peer` with no socket and the given pending send sequences.
    fn peer_no_socket(pending: Vec<u16>) -> Peer<()> {
        Peer {
            addr: SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 8333),
            sock: None,
            sockaddr: SockAddrIn {
                sin_family: 2,
                sin_port: 8333u16.to_be(),
                sin_addr: u32::from(std::net::Ipv4Addr::LOCALHOST).to_be(),
                sin_zero: [0; 8],
            },
            state: PeerState::Ready,
            recv_buf: Vec::new(),
            recv_armed: false,
            connected_at: Instant::now(),
            generation: 1,
            pending_send_seqs: pending,
            app: (),
        }
    }

    #[test]
    fn close_drains_pending_sends_no_socket() {
        let mut ring = IoUring::new(64).unwrap();
        let mut arena = SendArena::new();

        // Allocate a couple of send-arena slots so `release` has something to do.
        let s0 = arena.frame_into(
            mantle::network::Network::Mainnet.magic(),
            mantle::network::Command::Verack,
            &[],
        ).unwrap();
        let s1 = arena.frame_into(
            mantle::network::Network::Mainnet.magic(),
            mantle::network::Command::Verack,
            &[],
        ).unwrap();

        let free_before = arena.free_count();
        let mut peer = peer_no_socket(vec![s0, s1]);

        peer.close(&mut ring, &mut arena);

        // After close: pending_send_seqs is drained, arena slots released.
        assert!(peer.pending_send_seqs.is_empty());
        assert_eq!(arena.free_count(), free_before + 2);
        // sock was None, so it remains None.
        assert!(peer.sock.is_none());
    }

    #[test]
    fn close_with_empty_pending_is_noop() {
        let mut ring = IoUring::new(64).unwrap();
        let mut arena = SendArena::new();
        let free_before = arena.free_count();

        let mut peer = peer_no_socket(vec![]);
        peer.close(&mut ring, &mut arena);

        assert!(peer.pending_send_seqs.is_empty());
        assert_eq!(arena.free_count(), free_before);
    }

    // ── helpers for ingest_recv_cqe tests ──────────────────────────────

    use ququmatz::types::CqeFlags;

    /// Construct a `CqeFlags` value with arbitrary raw bits.
    ///
    /// `CqeFlags` is a newtype around `u32` with a private field, so we
    /// use `transmute` to set the buffer-id bits in the upper 16 bits.
    fn cqe_flags_raw(raw: u32) -> CqeFlags {
        // SAFETY: CqeFlags is #[derive(Copy, Clone)] struct CqeFlags(u32).
        unsafe { std::mem::transmute::<u32, CqeFlags>(raw) }
    }

    /// Build `CqeFlags` with the BUFFER flag set and the given buffer id
    /// encoded in the upper 16 bits.  Optionally includes MORE.
    fn cqe_flags_with_buffer(buf_id: u16, more: bool) -> CqeFlags {
        let mut bits = CqeFlags::BUFFER.bits() | (u32::from(buf_id) << 16);
        if more {
            bits |= CqeFlags::MORE.bits();
        }
        cqe_flags_raw(bits)
    }

    // ── ingest_recv_cqe tests ──────────────────────────────────────────

    /// Branch 1: res <= 0 makes the peer Dead and calls close.
    #[test]
    fn ingest_recv_cqe_negative_res_kills_peer() {
        let mut ring = IoUring::new(64).unwrap();
        let mut pbr = ring.register_provided_buffers(1, 4, 64).unwrap();
        let mut arena = SendArena::new();

        let mut peer = peer_no_socket(vec![]);
        peer.state = PeerState::Ready;
        peer.recv_armed = true;

        peer.ingest_recv_cqe(&mut pbr, &mut arena, CqeFlags::default(), -1, &mut ring);

        assert_eq!(peer.state, PeerState::Dead);
        assert!(!peer.recv_armed);
    }

    /// Branch 1 (edge): res == 0 (EOF) also kills the peer.
    #[test]
    fn ingest_recv_cqe_zero_res_kills_peer() {
        let mut ring = IoUring::new(64).unwrap();
        let mut pbr = ring.register_provided_buffers(2, 4, 64).unwrap();
        let mut arena = SendArena::new();

        let mut peer = peer_no_socket(vec![]);
        peer.state = PeerState::Ready;
        peer.recv_armed = true;

        peer.ingest_recv_cqe(&mut pbr, &mut arena, CqeFlags::default(), 0, &mut ring);

        assert_eq!(peer.state, PeerState::Dead);
        assert!(!peer.recv_armed);
    }

    /// Branch 1: pending send-arena slots are released on death.
    #[test]
    fn ingest_recv_cqe_error_releases_pending_sends() {
        let mut ring = IoUring::new(64).unwrap();
        let mut pbr = ring.register_provided_buffers(3, 4, 64).unwrap();
        let mut arena = SendArena::new();

        let s0 = arena
            .frame_into(
                mantle::network::Network::Mainnet.magic(),
                mantle::network::Command::Verack,
                &[],
            )
            .unwrap();

        let free_before = arena.free_count();
        let mut peer = peer_no_socket(vec![s0]);
        peer.recv_armed = true;

        peer.ingest_recv_cqe(&mut pbr, &mut arena, CqeFlags::default(), -104, &mut ring);

        assert_eq!(peer.state, PeerState::Dead);
        assert!(peer.pending_send_seqs.is_empty());
        assert_eq!(arena.free_count(), free_before + 1);
    }

    /// Branch 2: positive res with BUFFER flag appends bytes to recv_buf.
    #[test]
    fn ingest_recv_cqe_positive_res_appends_to_recv_buf() {
        let mut ring = IoUring::new(64).unwrap();
        let mut pbr = ring.register_provided_buffers(4, 4, 64).unwrap();
        let mut arena = SendArena::new();

        // Write known data into the provided-buffer slot so that
        // pbr.buffer(buf_id, n) returns it.
        let buf_id: u16 = 0;
        {
            // Get a mutable handle to write test data.
            let slot = pbr.buffer_mut(buf_id, 5).unwrap();
            slot.copy_from_slice(b"hello");
        }

        let flags = cqe_flags_with_buffer(buf_id, true);
        let mut peer = peer_no_socket(vec![]);
        peer.recv_armed = true;

        peer.ingest_recv_cqe(&mut pbr, &mut arena, flags, 5, &mut ring);

        assert_eq!(&peer.recv_buf, b"hello");
        // MORE was set, so recv_armed stays true.
        assert!(peer.recv_armed);
        assert_eq!(peer.state, PeerState::Ready);
    }

    /// Branch 2 + 4: positive res without MORE clears recv_armed.
    #[test]
    fn ingest_recv_cqe_no_more_flag_disarms_recv() {
        let mut ring = IoUring::new(64).unwrap();
        let mut pbr = ring.register_provided_buffers(5, 4, 64).unwrap();
        let mut arena = SendArena::new();

        let buf_id: u16 = 1;
        {
            let slot = pbr.buffer_mut(buf_id, 3).unwrap();
            slot.copy_from_slice(b"abc");
        }

        // BUFFER flag set, but NOT MORE.
        let flags = cqe_flags_with_buffer(buf_id, false);
        let mut peer = peer_no_socket(vec![]);
        peer.recv_armed = true;

        peer.ingest_recv_cqe(&mut pbr, &mut arena, flags, 3, &mut ring);

        assert_eq!(&peer.recv_buf, b"abc");
        // No MORE → recv_armed is cleared.
        assert!(!peer.recv_armed);
    }

    /// Branch 3: positive res without BUFFER flag (decode returns None).
    /// The peer stays alive but recv_buf is not extended.
    #[test]
    fn ingest_recv_cqe_no_buffer_flag_does_not_extend() {
        let mut ring = IoUring::new(64).unwrap();
        let mut pbr = ring.register_provided_buffers(6, 4, 64).unwrap();
        let mut arena = SendArena::new();

        // No BUFFER flag, no MORE flag — just zero flags.
        let flags = CqeFlags::default();
        let mut peer = peer_no_socket(vec![]);
        peer.recv_armed = true;

        peer.ingest_recv_cqe(&mut pbr, &mut arena, flags, 10, &mut ring);

        // recv_buf untouched — the eprintln fires but no data is appended.
        assert!(peer.recv_buf.is_empty());
        // No MORE → recv_armed cleared.
        assert!(!peer.recv_armed);
    }

    /// Multiple successive ingestions accumulate in recv_buf.
    #[test]
    fn ingest_recv_cqe_accumulates_across_calls() {
        let mut ring = IoUring::new(64).unwrap();
        let mut pbr = ring.register_provided_buffers(7, 4, 64).unwrap();
        let mut arena = SendArena::new();

        let mut peer = peer_no_socket(vec![]);
        peer.recv_armed = true;

        // First chunk — buf_id 0
        {
            let slot = pbr.buffer_mut(0, 3).unwrap();
            slot.copy_from_slice(b"foo");
        }
        let flags = cqe_flags_with_buffer(0, true);
        peer.ingest_recv_cqe(&mut pbr, &mut arena, flags, 3, &mut ring);

        // Second chunk — buf_id 1
        {
            let slot = pbr.buffer_mut(1, 3).unwrap();
            slot.copy_from_slice(b"bar");
        }
        let flags = cqe_flags_with_buffer(1, false);
        peer.ingest_recv_cqe(&mut pbr, &mut arena, flags, 3, &mut ring);

        assert_eq!(&peer.recv_buf, b"foobar");
        assert!(!peer.recv_armed); // last CQE had no MORE
    }
}
