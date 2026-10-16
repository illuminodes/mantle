use mantle::network::{GetHeadersMsg, ProtocolVersion};
use mantle::primitives::{BlockHeader, BlockHeight, ChainWork, Hash256};

/// The block locator for a `getheaders` request, built from the chain held
/// so far, and the place a peer's answer attaches to that chain.
///
/// The newest [`Self::DENSE`] headers are listed one by one, then the gaps
/// double back to the header before `start`. A peer on another branch
/// answers from the newest hash it shares with us, so a page may replace
/// the headers above that hash instead of extending the tip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeaderLocator<'a> {
    start: BlockHeight,
    chain: &'a [(BlockHeight, BlockHeader)],
    hashes: Vec<Hash256>,
    keeps: Vec<usize>,
}

/// Where a page attaches: the headers held below it, and its first height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Attachment {
    pub(crate) keep: usize,
    pub(crate) first: BlockHeight,
}

impl<'a> HeaderLocator<'a> {
    pub(crate) const DENSE: usize = 10;

    /// `chain` holds heights `start..` in order; `base` is the hash of the
    /// header before `start`.
    pub(crate) fn new(start: BlockHeight, base: Hash256, chain: &'a [(BlockHeight, BlockHeader)]) -> Self {
        let mut hashes = Vec::new();
        let mut keeps = Vec::new();
        let mut keep = chain.len();
        let mut step = 1;
        while keep > 0 {
            hashes.push(chain[keep - 1].1.hash());
            keeps.push(keep);
            if hashes.len() >= Self::DENSE {
                step *= 2;
            }
            keep = keep.saturating_sub(step);
        }
        hashes.push(base);
        keeps.push(0);
        Self {
            start,
            chain,
            hashes,
            keeps,
        }
    }

    /// The newest locator hash, naming the request this locator makes.
    pub(crate) fn tip(&self) -> Hash256 {
        self.hashes[0]
    }

    #[cfg(test)]
    pub(crate) fn hashes(&self) -> &[Hash256] {
        &self.hashes
    }

    /// The attachment of a page whose first header has parent `parent`, or
    /// `None` when the parent is not on the locator.
    pub(crate) fn attach(&self, parent: Hash256) -> Option<Attachment> {
        let index = self.hashes.iter().position(|hash| *hash == parent)?;
        let keep = self.keeps[index];
        let offset = u32::try_from(keep).ok()?;
        Some(Attachment {
            keep,
            first: BlockHeight::new(self.start.to_u32().checked_add(offset)?),
        })
    }

    /// Whether `page`, attached at `attachment`, carries more work than the
    /// held headers it would replace; a branch with equal or less work is
    /// not taken.
    pub(crate) fn outworks(&self, attachment: Attachment, page: &[BlockHeader]) -> bool {
        let replaced = ChainWork::of_headers(self.chain.iter().skip(attachment.keep).map(|(_, header)| header));
        !page.is_empty() && ChainWork::of_headers(page) > replaced
    }

    pub(crate) fn payload(&self) -> Vec<u8> {
        GetHeadersMsg {
            version: ProtocolVersion::new(70016),
            locator_hashes: self.hashes.clone(),
            stop_hash: Hash256::ZERO,
        }
        .encode_to_vec()
    }
}

impl Attachment {
    /// How many headers of a page fit at or below `end`.
    pub(crate) fn room(self, end: BlockHeight) -> usize {
        if end < self.first {
            return 0;
        }
        usize::try_from(end.to_u32() - self.first.to_u32())
            .map_or(usize::MAX, |gap| gap.saturating_add(1))
    }
}

#[cfg(test)]
mod tests {
    use mantle::primitives::{BlockHeader, BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Nonce};

    use super::{Attachment, HeaderLocator};

    struct ChainFixture;

    impl ChainFixture {
        fn base() -> Hash256 {
            Hash256::from_bytes([1; 32])
        }

        fn chain(length: u32) -> Vec<(BlockHeight, BlockHeader)> {
            let mut prev = Self::base();
            (1..=length)
                .map(|height| {
                    let header = BlockHeader::new(
                        BlockVersion::new(1),
                        prev,
                        Hash256::ZERO,
                        BlockTime::new(height),
                        CompactBits::new(0x207f_ffff),
                        Nonce::new(0),
                    );
                    prev = header.hash();
                    (BlockHeight::new(height), header)
                })
                .collect()
        }
    }

    #[test]
    fn an_empty_chain_locates_by_its_base_alone() {
        let locator = HeaderLocator::new(BlockHeight::new(1), ChainFixture::base(), &[]);

        assert_eq!(locator.hashes(), &[ChainFixture::base()]);
        assert_eq!(
            locator.attach(ChainFixture::base()),
            Some(Attachment { keep: 0, first: BlockHeight::new(1) })
        );
    }

    #[test]
    fn the_newest_headers_are_dense_and_older_ones_double_back_to_the_base() {
        let chain = ChainFixture::chain(100);
        let locator = HeaderLocator::new(BlockHeight::new(1), ChainFixture::base(), &chain);
        let heights: Vec<u32> = locator
            .hashes()
            .iter()
            .filter_map(|hash| locator.attach(*hash))
            .map(|attachment| attachment.first.to_u32() - 1)
            .collect();

        assert_eq!(heights, [100, 99, 98, 97, 96, 95, 94, 93, 92, 91, 89, 85, 77, 61, 29, 0]);
        assert_eq!(locator.tip(), chain[99].1.hash());
    }

    #[test]
    fn a_page_from_a_shared_header_replaces_what_is_above_it() {
        let chain = ChainFixture::chain(5);
        let locator = HeaderLocator::new(BlockHeight::new(1), ChainFixture::base(), &chain);
        let attachment = locator.attach(chain[3].1.hash()).expect("on the locator");

        let rival = |length: u32| -> Vec<BlockHeader> { ChainFixture::chain(length).into_iter().map(|(_, header)| header).collect() };

        assert_eq!(attachment, Attachment { keep: 4, first: BlockHeight::new(5) });
        assert!(!locator.outworks(attachment, &rival(1)));
        assert!(locator.outworks(attachment, &rival(2)));
    }

    #[test]
    fn a_shorter_branch_on_a_harder_target_outworks_a_longer_easy_one() {
        let chain = ChainFixture::chain(5);
        let locator = HeaderLocator::new(BlockHeight::new(1), ChainFixture::base(), &chain);
        let attachment = locator.attach(chain[1].1.hash()).expect("on the locator");
        let mut hard = chain[2].1;
        hard.set_bits(CompactBits::new(0x2000_ffff));

        assert!(locator.outworks(attachment, &[hard]));
        assert!(!locator.outworks(attachment, &[]));
    }

    #[test]
    fn an_unknown_parent_does_not_attach() {
        let chain = ChainFixture::chain(3);
        let locator = HeaderLocator::new(BlockHeight::new(1), ChainFixture::base(), &chain);

        assert_eq!(locator.attach(Hash256::from_bytes([9; 32])), None);
    }

    #[test]
    fn room_counts_the_heights_left_up_to_the_end() {
        let attachment = Attachment { keep: 4, first: BlockHeight::new(5) };

        assert_eq!(attachment.room(BlockHeight::new(7)), 3);
        assert_eq!(attachment.room(BlockHeight::new(5)), 1);
        assert_eq!(attachment.room(BlockHeight::new(4)), 0);
    }
}
