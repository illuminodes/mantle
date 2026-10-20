use std::net::SocketAddrV4;

use mantle::primitives::{BlockHeader, BlockHeight};

use crate::header_round::RoundCandidate;

/// One page of headers that peers sent in reply to a survey, and every peer
/// that sent exactly it. `headers[0]` sits at height `first`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurveyedPage {
    pub first: BlockHeight,
    pub headers: Vec<BlockHeader>,
    pub senders: Vec<SocketAddrV4>,
}

impl From<RoundCandidate> for SurveyedPage {
    fn from(candidate: RoundCandidate) -> Self {
        Self {
            first: candidate.attachment.first,
            headers: candidate.headers,
            senders: candidate.senders,
        }
    }
}
