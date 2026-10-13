#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

mod arena;
mod handshake;
mod ops;
mod peer;
mod ring;

pub use arena::{BufHandle, SendAlloc, SendArena, SendSlab};
pub use handshake::{consume_handshake_frames, encode_version, our_version};
pub use ops::{CqeData, Op, decode_cqe_buffer_id};
pub use peer::{PEER_SEND_OUTSTANDING_CAP, Peer, PeerPool, PeerState};
pub use ring::{IoUringExt, make_ring};

pub use ququmatz;
