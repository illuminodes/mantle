use std::net::SocketAddrV4;
use std::time::Instant;

use ququmatz::Socket;
use ququmatz::types::{RawFd, SockAddrIn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Connecting,
    HandshakeVersionSent,
    HandshakeRecving,
    Ready,
    Dead,
}

pub const PEER_SEND_OUTSTANDING_CAP: usize = 8;

pub struct Peer<T> {
    pub addr: SocketAddrV4,
    pub sock: Option<Socket>,
    pub sockaddr: SockAddrIn,
    pub state: PeerState,
    pub recv_buf: Vec<u8>,
    pub recv_armed: bool,
    pub connected_at: Instant,
    pub generation: u16,
    pub pending_send_seqs: Vec<u16>,
    pub app: T,
}

impl<T> Peer<T> {
    #[must_use]
    pub fn fd(&self) -> Option<RawFd> {
        self.sock.as_ref().map(Socket::fd)
    }
}

impl<T> std::fmt::Debug for Peer<T>
where
    T: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer")
            .field("addr", &self.addr)
            .field("fd", &self.fd())
            .field("state", &self.state)
            .field("recv_armed", &self.recv_armed)
            .field("generation", &self.generation)
            .field("app", &self.app)
            .finish_non_exhaustive()
    }
}

pub struct PeerPool<T, const MAX: usize> {
    slots: [Option<Peer<T>>; MAX],
    dead_buf: Vec<u16>,
}

impl<T, const MAX: usize> PeerPool<T, MAX> {
    #[allow(clippy::cast_possible_truncation)]
    pub fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| None),
            dead_buf: Vec::with_capacity(MAX),
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub fn get_mut(&mut self, slot: u16) -> Option<&mut Peer<T>> {
        self.slots.get_mut(slot as usize)?.as_mut()
    }

    pub fn insert(&mut self, slot: u16, peer: Peer<T>) {
        self.slots[slot as usize] = Some(peer);
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn remove(&mut self, slot: u16) -> Option<Peer<T>> {
        self.slots.get_mut(slot as usize)?.take()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(Option::is_none)
    }

    #[must_use]
    pub fn live_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.as_ref().is_some_and(|p| p.state != PeerState::Dead))
            .count()
    }

    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub fn free_slot(&self) -> Option<u16> {
        self.slots
            .iter()
            .position(Option::is_none)
            .map(|i| i as u16)
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (u16, &mut Peer<T>)> {
        self.slots
            .iter_mut()
            .enumerate()
            .filter_map(|(i, s)| s.as_mut().map(|p| (i as u16, p)))
    }

    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut Peer<T>> {
        self.slots.iter_mut().filter_map(|s| s.as_mut())
    }

    pub fn values(&self) -> impl Iterator<Item = &Peer<T>> {
        self.slots.iter().filter_map(|s| s.as_ref())
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn dead_slots(&mut self) -> &[u16] {
        self.dead_buf.clear();
        for (i, s) in self.slots.iter().enumerate() {
            if s.as_ref().is_some_and(|p| p.state == PeerState::Dead) {
                self.dead_buf.push(i as u16);
            }
        }
        &self.dead_buf
    }
}

impl<T, const MAX: usize> Default for PeerPool<T, MAX> {
    fn default() -> Self {
        Self::new()
    }
}
