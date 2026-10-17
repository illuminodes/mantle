use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use mantle::primitives::{BlockHeader, ChainWork, Hash256};

use crate::header_locator::Attachment;
use crate::peer_page::PeerPage;

/// One `getheaders` round across the peer pool: every reply is collected,
/// and once the round is over the pages are ranked by the work they add.
///
/// The round is over when every ready peer has answered, or
/// `page_window` after the first page, or `empty_window` after the first
/// "nothing better" when no page has come. Peers that send the same page
/// share one candidate.
#[derive(Debug)]
pub(crate) struct HeaderRound {
    page_window: Duration,
    empty_window: Duration,
    first_page: Option<Instant>,
    first_empty: Option<Instant>,
    candidates: Vec<RoundCandidate>,
}

/// A page some peers offered, and who offered it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RoundCandidate {
    pub(crate) attachment: Attachment,
    pub(crate) parent: Hash256,
    pub(crate) headers: Vec<BlockHeader>,
    pub(crate) gain: ChainWork,
    pub(crate) senders: Vec<SocketAddrV4>,
}

impl HeaderRound {
    pub(crate) const fn new(page_window: Duration, empty_window: Duration) -> Self {
        Self {
            page_window,
            empty_window,
            first_page: None,
            first_empty: None,
            candidates: Vec::new(),
        }
    }

    pub(crate) fn offer(&mut self, page: PeerPage, from: SocketAddrV4, now: Instant) {
        let PeerPage::Better {
            attachment,
            parent,
            headers,
            gain,
        } = page
        else {
            self.first_empty.get_or_insert(now);
            return;
        };
        self.first_page.get_or_insert(now);
        let last = headers.last().map(BlockHeader::hash);
        let same = self.candidates.iter_mut().find(|candidate| {
            candidate.attachment == attachment
                && candidate.headers.len() == headers.len()
                && candidate.headers.last().map(BlockHeader::hash) == last
        });
        match same {
            Some(candidate) => candidate.senders.push(from),
            None => self.candidates.push(RoundCandidate {
                attachment,
                parent,
                headers,
                gain,
                senders: vec![from],
            }),
        }
    }

    pub(crate) fn is_over(&self, answered: usize, ready: usize, now: Instant) -> bool {
        if answered == 0 {
            return false;
        }
        if answered >= ready {
            return true;
        }
        match (self.first_page, self.first_empty) {
            (Some(first), _) => now.duration_since(first) >= self.page_window,
            (None, Some(first)) => now.duration_since(first) >= self.empty_window,
            (None, None) => false,
        }
    }

    pub(crate) fn distinct_pages(&self) -> usize {
        self.candidates.len()
    }

    /// The candidates with the most work first; among equal work, the one
    /// more peers sent, then the one that came first.
    pub(crate) fn into_ranked(mut self) -> Vec<RoundCandidate> {
        self.candidates
            .sort_by(|a, b| b.gain.cmp(&a.gain).then(b.senders.len().cmp(&a.senders.len())));
        self.candidates
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::time::{Duration, Instant};

    use mantle::primitives::{BlockHeader, BlockHeight, BlockTime, BlockVersion, ChainWork, CompactBits, Hash256, Nonce};

    use super::HeaderRound;
    use crate::header_locator::Attachment;
    use crate::peer_page::PeerPage;

    const PAGE: Duration = Duration::from_secs(2);
    const EMPTY: Duration = Duration::from_secs(15);

    struct RoundFixture;

    impl RoundFixture {
        fn peer(octet: u8) -> SocketAddrV4 {
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, octet), 8333)
        }

        fn page(length: u32, salt: u32, gain: u128) -> PeerPage {
            let mut prev = Hash256::from_bytes([1; 32]);
            let headers = (0..length)
                .map(|index| {
                    let header = BlockHeader::new(
                        BlockVersion::new(1),
                        prev,
                        Hash256::ZERO,
                        BlockTime::new(index),
                        CompactBits::new(0x207f_ffff),
                        Nonce::new(salt),
                    );
                    prev = header.hash();
                    header
                })
                .collect();
            PeerPage::Better {
                attachment: Attachment { keep: 0, first: BlockHeight::new(1) },
                parent: Hash256::from_bytes([1; 32]),
                headers,
                gain: ChainWork::new(gain),
            }
        }
    }

    #[test]
    fn the_round_waits_for_every_ready_peer() {
        let now = Instant::now();
        let mut round = HeaderRound::new(PAGE, EMPTY);
        round.offer(RoundFixture::page(2, 0, 4), RoundFixture::peer(1), now);

        assert!(!round.is_over(1, 2, now));
        assert!(round.is_over(2, 2, now));
    }

    #[test]
    fn a_page_in_hand_ends_the_round_after_the_short_window() {
        let start = Instant::now();
        let mut round = HeaderRound::new(PAGE, EMPTY);
        round.offer(RoundFixture::page(2, 0, 4), RoundFixture::peer(1), start);

        assert!(!round.is_over(1, 8, start + Duration::from_secs(1)));
        assert!(round.is_over(1, 8, start + PAGE));
    }

    #[test]
    fn only_empty_replies_wait_the_long_window() {
        let start = Instant::now();
        let mut round = HeaderRound::new(PAGE, EMPTY);
        round.offer(PeerPage::NothingBetter, RoundFixture::peer(1), start);

        assert!(!round.is_over(1, 8, start + PAGE));
        assert!(round.is_over(1, 8, start + EMPTY));
    }

    #[test]
    fn no_answer_never_ends_the_round() {
        assert!(!HeaderRound::new(PAGE, EMPTY).is_over(0, 0, Instant::now() + EMPTY * 2));
    }

    #[test]
    fn the_page_with_the_most_work_ranks_first_whoever_sent_it_first() {
        let now = Instant::now();
        let mut round = HeaderRound::new(PAGE, EMPTY);
        round.offer(RoundFixture::page(3, 0, 6), RoundFixture::peer(1), now);
        round.offer(RoundFixture::page(4, 1, 8), RoundFixture::peer(2), now);
        round.offer(PeerPage::NothingBetter, RoundFixture::peer(3), now);

        let ranked = round.into_ranked();

        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].gain, ChainWork::new(8));
        assert_eq!(ranked[0].senders, vec![RoundFixture::peer(2)]);
    }

    #[test]
    fn peers_sending_the_same_page_share_one_candidate() {
        let now = Instant::now();
        let mut round = HeaderRound::new(PAGE, EMPTY);
        round.offer(RoundFixture::page(3, 0, 6), RoundFixture::peer(1), now);
        round.offer(RoundFixture::page(3, 0, 6), RoundFixture::peer(2), now);
        round.offer(RoundFixture::page(3, 5, 6), RoundFixture::peer(3), now);

        assert_eq!(round.distinct_pages(), 2);
        let ranked = round.into_ranked();
        assert_eq!(ranked[0].senders, vec![RoundFixture::peer(1), RoundFixture::peer(2)]);
    }
}
