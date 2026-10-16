use mantle::primitives::{BlockHeader, BlockHeight, Hash256};

use crate::header_locator::{Attachment, HeaderLocator};

/// What a peer's `headers` reply says about the chain we hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PeerPage {
    /// The peer has nothing past our tip, or only a branch that ends at or
    /// below it.
    NothingBetter,
    /// Headers that attach to the locator and end above our tip.
    Better {
        attachment: Attachment,
        parent: Hash256,
        headers: Vec<BlockHeader>,
    },
}

impl PeerPage {
    /// Read a reply to `request`, keeping only headers up to `end`; `None`
    /// when the reply does not attach to the locator at all.
    pub(crate) fn read(request: &HeaderLocator, end: BlockHeight, mut headers: Vec<BlockHeader>) -> Option<Self> {
        let Some(first) = headers.first() else {
            return Some(Self::NothingBetter);
        };
        let parent = first.prev_block();
        let attachment = request.attach(parent)?;
        headers.truncate(attachment.room(end));
        if headers.is_empty() || !request.extends(attachment, headers.len()) {
            return Some(Self::NothingBetter);
        }
        Some(Self::Better {
            attachment,
            parent,
            headers,
        })
    }
}

#[cfg(test)]
mod tests {
    use mantle::primitives::{BlockHeader, BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Nonce};

    use super::PeerPage;
    use crate::header_locator::{Attachment, HeaderLocator};

    struct BranchFixture;

    impl BranchFixture {
        fn base() -> Hash256 {
            Hash256::from_bytes([1; 32])
        }

        fn branch(parent: Hash256, length: u32, salt: u32) -> Vec<BlockHeader> {
            let mut prev = parent;
            (0..length)
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
                .collect()
        }

        fn held(length: u32) -> Vec<(BlockHeight, BlockHeader)> {
            (1..).map(BlockHeight::new).zip(Self::branch(Self::base(), length, 0)).collect()
        }
    }

    #[test]
    fn an_empty_reply_has_nothing_better() {
        let locator = HeaderLocator::new(BlockHeight::new(1), BranchFixture::base(), &BranchFixture::held(3));

        assert_eq!(PeerPage::read(&locator, BlockHeight::new(100), Vec::new()), Some(PeerPage::NothingBetter));
    }

    #[test]
    fn a_reply_from_our_tip_extends_it() {
        let held = BranchFixture::held(3);
        let locator = HeaderLocator::new(BlockHeight::new(1), BranchFixture::base(), &held);
        let next = BranchFixture::branch(held[2].1.hash(), 2, 0);

        assert_eq!(
            PeerPage::read(&locator, BlockHeight::new(100), next.clone()),
            Some(PeerPage::Better {
                attachment: Attachment { keep: 3, first: BlockHeight::new(4) },
                parent: held[2].1.hash(),
                headers: next,
            })
        );
    }

    #[test]
    fn a_longer_branch_from_below_the_tip_replaces_it() {
        let held = BranchFixture::held(3);
        let locator = HeaderLocator::new(BlockHeight::new(1), BranchFixture::base(), &held);
        let fork = BranchFixture::branch(held[1].1.hash(), 2, 7);

        let Some(PeerPage::Better { attachment, .. }) = PeerPage::read(&locator, BlockHeight::new(100), fork) else {
            panic!("a longer branch is better");
        };
        assert_eq!(attachment, Attachment { keep: 2, first: BlockHeight::new(3) });
    }

    #[test]
    fn a_branch_no_longer_than_ours_is_nothing_better() {
        let held = BranchFixture::held(3);
        let locator = HeaderLocator::new(BlockHeight::new(1), BranchFixture::base(), &held);
        let fork = BranchFixture::branch(held[1].1.hash(), 1, 7);

        assert_eq!(PeerPage::read(&locator, BlockHeight::new(100), fork), Some(PeerPage::NothingBetter));
    }

    #[test]
    fn a_reply_off_the_locator_is_ignored() {
        let locator = HeaderLocator::new(BlockHeight::new(1), BranchFixture::base(), &BranchFixture::held(3));
        let stray = BranchFixture::branch(Hash256::from_bytes([9; 32]), 2, 0);

        assert_eq!(PeerPage::read(&locator, BlockHeight::new(100), stray), None);
    }

    #[test]
    fn headers_past_the_end_are_dropped() {
        let held = BranchFixture::held(3);
        let locator = HeaderLocator::new(BlockHeight::new(1), BranchFixture::base(), &held);
        let next = BranchFixture::branch(held[2].1.hash(), 5, 0);

        let Some(PeerPage::Better { headers, .. }) = PeerPage::read(&locator, BlockHeight::new(5), next) else {
            panic!("extends the tip");
        };
        assert_eq!(headers.len(), 2);
    }
}
