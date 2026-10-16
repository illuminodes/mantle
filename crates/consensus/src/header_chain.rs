use mantle::collections::PrehashedMap;
use mantle::network::Network;
use mantle::primitives::{BlockHeader, BlockHeight, BlockTime, ChainWork, Hash256, OutPoint};

use crate::chain_view::{ChainView, Coin, TipInfo};
use crate::error::{ChainViewError, ValidationError};
use crate::validation::{Clock, HeaderContextExt, HeaderValidationExt};

/// A header chain grown from genesis that admits a header only when it
/// extends the tip, meets its proof-of-work target, carries the difficulty
/// the retarget rules require, passes the timestamp and version rules, and
/// agrees with the network checkpoint. A branch replaces held headers only
/// when it carries more work than they do.
pub struct HeaderChain {
    headers: Vec<BlockHeader>,
    work: Vec<ChainWork>,
    heights: PrehashedMap<Hash256, BlockHeight>,
    checkpoint: Option<(BlockHeight, Hash256)>,
    minimum_work: ChainWork,
    allow_min_difficulty: bool,
}

impl HeaderChain {
    /// The chain holding only `network`'s genesis header, or `None` for a
    /// network without one.
    #[must_use]
    pub fn for_network(network: Network) -> Option<Self> {
        let genesis = network.genesis_header()?;
        let allow_min_difficulty = matches!(network, Network::Testnet3 | Network::Testnet4);
        Some(
            Self::from_genesis(genesis, allow_min_difficulty)
                .with_checkpoint(network.checkpoint())
                .with_minimum_work(network.minimum_chain_work()),
        )
    }

    #[must_use]
    pub fn from_genesis(genesis: BlockHeader, allow_min_difficulty: bool) -> Self {
        let mut heights = PrehashedMap::default();
        heights.insert(genesis.hash(), BlockHeight::ZERO);
        Self {
            work: vec![ChainWork::of_header(&genesis)],
            headers: vec![genesis],
            heights,
            checkpoint: None,
            minimum_work: ChainWork::ZERO,
            allow_min_difficulty,
        }
    }

    #[must_use]
    pub const fn with_minimum_work(mut self, minimum_work: ChainWork) -> Self {
        self.minimum_work = minimum_work;
        self
    }

    /// Whether the chain carries the network's minimum work.
    #[must_use]
    pub fn has_minimum_work(&self) -> bool {
        self.tip_work() >= self.minimum_work
    }

    #[must_use]
    pub const fn minimum_work(&self) -> ChainWork {
        self.minimum_work
    }

    #[must_use]
    pub const fn with_checkpoint(mut self, checkpoint: Option<(BlockHeight, Hash256)>) -> Self {
        self.checkpoint = checkpoint;
        self
    }

    /// Append `header` at the tip once every rule passes.
    ///
    /// # Errors
    /// `UnknownParent` when it does not extend the tip, `CheckpointMismatch`,
    /// or the first proof-of-work or contextual rule it breaks.
    pub fn extend(
        &mut self,
        header: BlockHeader,
        clock: &impl Clock,
    ) -> Result<BlockHeight, ValidationError> {
        if header.prev_block() != self.tip().hash {
            return Err(ValidationError::UnknownParent);
        }
        header.check_pow()?;
        let context = header.check_context(self, clock, self.allow_min_difficulty)?;
        let hash = header.hash();
        if self
            .checkpoint
            .is_some_and(|(height, expected)| height == context.height && hash != expected)
        {
            return Err(ValidationError::CheckpointMismatch);
        }
        self.push(header);
        Ok(context.height)
    }

    /// Put `headers` at heights `first..`, replacing every header held from
    /// `first` up. Either all of them are taken or the chain is left as it
    /// was.
    ///
    /// # Errors
    /// `UnknownParent` when `first` is genesis or above the next height,
    /// the first rule a header breaks, with that header's index, or
    /// `InsufficientChainWork` (index of the last header) when the branch
    /// replaces headers without carrying more work than they do.
    pub fn replace_from(
        &mut self,
        first: BlockHeight,
        headers: &[BlockHeader],
        clock: &impl Clock,
    ) -> Result<(), (usize, ValidationError)> {
        let base = match first.to_u32().checked_sub(1) {
            Some(base) if base <= self.tip_height().to_u32() => BlockHeight::new(base),
            _ => return Err((0, ValidationError::UnknownParent)),
        };
        let keep = usize::try_from(base.to_u32()).map_or(self.headers.len(), |index| index + 1);
        let replaced_work = ChainWork::of_headers(&self.headers[keep..]);
        let replaced = self.headers.split_off(keep);
        self.work.truncate(keep);
        for header in &replaced {
            self.heights.remove(&header.hash());
        }
        let outcome = headers
            .iter()
            .enumerate()
            .try_for_each(|(index, header)| self.extend(*header, clock).map(|_| ()).map_err(|error| (index, error)))
            .and_then(|()| {
                let more = replaced.is_empty() || ChainWork::of_headers(headers) > replaced_work;
                more.then_some(())
                    .ok_or((headers.len().saturating_sub(1), ValidationError::InsufficientChainWork))
            });
        if outcome.is_err() {
            self.truncate(base);
            for header in replaced {
                self.push(header);
            }
        }
        outcome
    }

    fn push(&mut self, header: BlockHeader) {
        let height = BlockHeight::new(u32::try_from(self.headers.len()).unwrap_or(u32::MAX));
        self.heights.insert(header.hash(), height);
        let total = self.tip_work() + ChainWork::of_header(&header);
        self.work.push(total);
        self.headers.push(header);
    }

    /// The work of every header from genesis to the tip.
    #[must_use]
    pub fn tip_work(&self) -> ChainWork {
        self.work.last().copied().unwrap_or(ChainWork::ZERO)
    }

    /// Drop every header above `height`.
    pub fn truncate(&mut self, height: BlockHeight) {
        let keep = usize::try_from(height.to_u32())
            .map_or(self.headers.len(), |index| index.saturating_add(1));
        for header in self.headers.iter().skip(keep) {
            self.heights.remove(&header.hash());
        }
        self.headers.truncate(keep.max(1));
        self.work.truncate(keep.max(1));
    }

    #[must_use]
    pub fn header_at(&self, height: BlockHeight) -> Option<&BlockHeader> {
        self.headers.get(usize::try_from(height.to_u32()).ok()?)
    }

    #[must_use]
    pub fn tip_height(&self) -> BlockHeight {
        BlockHeight::new(u32::try_from(self.headers.len() - 1).unwrap_or(u32::MAX))
    }

    /// Whether the chain is long enough to have passed the checkpoint.
    #[must_use]
    pub fn reached_checkpoint(&self) -> bool {
        self.checkpoint
            .is_none_or(|(height, _)| self.tip_height() >= height)
    }

    #[must_use]
    pub fn checkpoint(&self) -> Option<(BlockHeight, Hash256)> {
        self.checkpoint
    }
}

impl ChainView for HeaderChain {
    fn get_coin(&self, _outpoint: &OutPoint) -> Result<Option<&Coin>, ChainViewError> {
        Ok(None)
    }

    fn get_header(&self, hash: &Hash256) -> Result<Option<BlockHeader>, ChainViewError> {
        Ok(self
            .heights
            .get(hash)
            .and_then(|height| self.header_at(*height))
            .copied())
    }

    fn get_header_at(&self, height: BlockHeight) -> Result<Option<BlockHeader>, ChainViewError> {
        Ok(self.header_at(height).copied())
    }

    fn height_of(&self, hash: &Hash256) -> Result<Option<BlockHeight>, ChainViewError> {
        Ok(self.heights.get(hash).copied())
    }

    fn median_time_past(&self, header: &BlockHeader) -> Result<BlockTime, ChainViewError> {
        let parent = self
            .heights
            .get(&header.prev_block())
            .ok_or(ChainViewError::NotFound)?;
        let end = usize::try_from(parent.to_u32()).map_err(|_| ChainViewError::NotFound)? + 1;
        let mut times: Vec<BlockTime> = self.headers[end.saturating_sub(11)..end]
            .iter()
            .map(BlockHeader::time)
            .collect();
        times.sort_unstable();
        Ok(times[times.len() / 2])
    }

    fn tip(&self) -> TipInfo {
        let height = self.tip_height();
        let hash = self.headers.last().map_or(Hash256::ZERO, BlockHeader::hash);
        TipInfo { hash, height }
    }
}

#[cfg(test)]
mod tests {
    use mantle::network::Network;
    use mantle::primitives::{BlockHeader, BlockHeight, BlockTime, BlockVersion, ChainWork, CompactBits, Hash256, Nonce};

    use super::HeaderChain;
    use crate::chain_view::ChainView;
    use crate::error::ValidationError;
    use crate::test_helpers::decode_hex;
    use crate::validation::FixedClock;

    const MAINNET_HEADERS: [&str; 3] = [
        "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
        "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61",
        "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d",
    ];
    const CLOCK: FixedClock = FixedClock(1_231_500_000);

    struct MainnetFixture;

    impl MainnetFixture {
        fn header(height: usize) -> BlockHeader {
            let bytes = decode_hex(MAINNET_HEADERS[height - 1]);
            BlockHeader::from_bytes(bytes.try_into().expect("80 bytes"))
        }

        fn chain() -> HeaderChain {
            HeaderChain::for_network(Network::Mainnet).expect("mainnet has a genesis header")
        }

        fn easy_genesis() -> BlockHeader {
            BlockHeader::new(
                BlockVersion::new(1), Hash256::ZERO, Hash256::ZERO,
                BlockTime::new(1_231_006_505), CompactBits::new(0x207f_ffff), Nonce::new(0),
            )
        }

        fn easy_branch(parent: &BlockHeader, length: u32, salt: u8) -> Vec<BlockHeader> {
            let mut prev = *parent;
            (1..=length)
                .map(|step| {
                    let header = Self::mined(BlockHeader::new(
                        BlockVersion::new(1), prev.hash(), Hash256::from_bytes([salt; 32]),
                        prev.time() + step, prev.bits(), Nonce::new(0),
                    ));
                    prev = header;
                    header
                })
                .collect()
        }

        fn mined(mut header: BlockHeader) -> BlockHeader {
            for nonce in 0..10_000 {
                header.set_nonce(Nonce::new(nonce));
                if crate::validation::HeaderValidationExt::check_pow(&header).is_ok() {
                    return header;
                }
            }
            panic!("no nonce meets the target");
        }
    }

    #[test]
    fn the_first_mainnet_headers_extend_genesis() {
        let mut chain = MainnetFixture::chain();
        for height in 1..=3 {
            let admitted = chain.extend(MainnetFixture::header(height), &CLOCK);
            assert_eq!(admitted, Ok(BlockHeight::new(u32::try_from(height).expect("small"))));
        }
        assert_eq!(chain.tip().hash, MainnetFixture::header(3).hash());
    }

    #[test]
    fn a_header_that_misses_its_target_is_refused() {
        let mut chain = MainnetFixture::chain();
        let mut forged = MainnetFixture::header(1);
        forged.set_nonce(Nonce::new(forged.nonce().to_u32().wrapping_add(1)));

        assert_eq!(chain.extend(forged, &CLOCK), Err(ValidationError::InsufficientProofOfWork));
        assert_eq!(chain.tip_height(), BlockHeight::ZERO);
    }

    #[test]
    fn a_header_mined_at_an_easier_difficulty_is_refused() {
        let mut chain = MainnetFixture::chain();
        let mut easy = MainnetFixture::header(1);
        easy.set_bits(CompactBits::new(0x207f_ffff));

        assert_eq!(
            chain.extend(MainnetFixture::mined(easy), &CLOCK),
            Err(ValidationError::UnexpectedDifficulty)
        );
    }

    #[test]
    fn a_header_that_skips_the_tip_is_refused() {
        let mut chain = MainnetFixture::chain();

        assert_eq!(
            chain.extend(MainnetFixture::header(2), &CLOCK),
            Err(ValidationError::UnknownParent)
        );
    }

    #[test]
    fn a_header_from_too_far_in_the_future_is_refused() {
        let mut chain = MainnetFixture::chain();
        let early = FixedClock(u64::from(MainnetFixture::header(1).time().to_u32()) - 3 * 60 * 60);

        assert_eq!(
            chain.extend(MainnetFixture::header(1), &early),
            Err(ValidationError::TimestampTooFarFuture)
        );
    }

    #[test]
    fn a_header_no_later_than_the_median_time_past_is_refused() {
        let bits = CompactBits::new(0x207f_ffff);
        let genesis = BlockHeader::new(
            BlockVersion::new(1), Hash256::ZERO, Hash256::ZERO,
            BlockTime::new(1_231_006_505), bits, Nonce::new(0),
        );
        let mut chain = HeaderChain::from_genesis(genesis, false);
        let stale = BlockHeader::new(
            BlockVersion::new(1), genesis.hash(), Hash256::ZERO,
            genesis.time(), bits, Nonce::new(0),
        );

        assert_eq!(
            chain.extend(MainnetFixture::mined(stale), &CLOCK),
            Err(ValidationError::TimestampTooEarly)
        );
    }

    #[test]
    fn the_checkpoint_admits_only_its_own_hash() {
        let real = MainnetFixture::header(2).hash();
        let mut agreeing = MainnetFixture::chain().with_checkpoint(Some((BlockHeight::new(2), real)));
        let mut disagreeing = MainnetFixture::chain()
            .with_checkpoint(Some((BlockHeight::new(2), Hash256::from_bytes([7; 32]))));
        for chain in [&mut agreeing, &mut disagreeing] {
            chain.extend(MainnetFixture::header(1), &CLOCK).expect("block 1");
            assert!(!chain.reached_checkpoint());
        }

        assert!(agreeing.extend(MainnetFixture::header(2), &CLOCK).is_ok());
        assert!(agreeing.reached_checkpoint());
        assert_eq!(
            disagreeing.extend(MainnetFixture::header(2), &CLOCK),
            Err(ValidationError::CheckpointMismatch)
        );
    }

    #[test]
    fn a_valid_branch_replaces_the_headers_above_its_parent() {
        let mut chain = MainnetFixture::chain();
        chain.extend(MainnetFixture::header(1), &CLOCK).expect("block 1");
        let mut stale = MainnetFixture::header(1);
        stale.set_prev_block(MainnetFixture::header(1).hash());
        chain.push(stale);

        let replaced = chain.replace_from(
            BlockHeight::new(2),
            &[MainnetFixture::header(2), MainnetFixture::header(3)],
            &CLOCK,
        );

        assert_eq!(replaced, Ok(()));
        assert_eq!(chain.tip().hash, MainnetFixture::header(3).hash());
        assert!(chain.height_of(&stale.hash()).expect("view").is_none());
    }

    #[test]
    fn an_invalid_branch_leaves_the_chain_as_it_was() {
        let mut chain = MainnetFixture::chain();
        for height in 1..=2 {
            chain.extend(MainnetFixture::header(height), &CLOCK).expect("valid");
        }
        let mut forged = MainnetFixture::header(2);
        forged.set_nonce(Nonce::new(forged.nonce().to_u32().wrapping_add(1)));

        let replaced = chain.replace_from(BlockHeight::new(2), &[forged], &CLOCK);

        assert_eq!(replaced, Err((0, ValidationError::InsufficientProofOfWork)));
        assert_eq!(chain.tip().hash, MainnetFixture::header(2).hash());
        assert_eq!(
            chain.height_of(&MainnetFixture::header(2).hash()).expect("view"),
            Some(BlockHeight::new(2))
        );
        assert!(chain.extend(MainnetFixture::header(3), &CLOCK).is_ok());
    }

    #[test]
    fn a_branch_with_no_more_work_than_the_headers_it_replaces_is_refused() {
        let genesis = MainnetFixture::easy_genesis();
        let mut chain = HeaderChain::from_genesis(genesis, false);
        let held = MainnetFixture::easy_branch(&genesis, 2, 1);
        for header in &held {
            chain.extend(*header, &CLOCK).expect("held");
        }
        let work = chain.tip_work();
        let rival = MainnetFixture::easy_branch(&held[0], 1, 2);

        assert_eq!(
            chain.replace_from(BlockHeight::new(2), &rival, &CLOCK),
            Err((0, ValidationError::InsufficientChainWork))
        );
        assert_eq!(chain.tip().hash, held[1].hash());
        assert_eq!(chain.tip_work(), work);
    }

    #[test]
    fn a_branch_with_more_work_replaces_and_adds_its_work() {
        let genesis = MainnetFixture::easy_genesis();
        let mut chain = HeaderChain::from_genesis(genesis, false);
        let held = MainnetFixture::easy_branch(&genesis, 2, 1);
        for header in &held {
            chain.extend(*header, &CLOCK).expect("held");
        }
        let rival = MainnetFixture::easy_branch(&held[0], 2, 2);

        assert_eq!(chain.replace_from(BlockHeight::new(2), &rival, &CLOCK), Ok(()));
        assert_eq!(chain.tip().hash, rival[1].hash());
        assert_eq!(chain.tip_work().to_u128(), 4 * 2);
    }

    #[test]
    fn the_tip_work_sums_every_header_from_genesis() {
        let mut chain = MainnetFixture::chain();
        for height in 1..=3 {
            chain.extend(MainnetFixture::header(height), &CLOCK).expect("valid");
        }

        assert_eq!(chain.tip_work().to_u128(), 4 * 0x1_0001_0001);
        chain.truncate(BlockHeight::new(1));
        assert_eq!(chain.tip_work().to_u128(), 2 * 0x1_0001_0001);
    }

    #[test]
    fn the_minimum_work_is_met_once_the_tip_work_reaches_it() {
        let mut chain = MainnetFixture::chain().with_minimum_work(ChainWork::new(3 * 0x1_0001_0001));
        chain.extend(MainnetFixture::header(1), &CLOCK).expect("block 1");

        assert!(!chain.has_minimum_work());
        chain.extend(MainnetFixture::header(2), &CLOCK).expect("block 2");
        assert!(chain.has_minimum_work());
    }

    #[test]
    fn mainnet_starts_far_below_its_minimum_work() {
        let chain = MainnetFixture::chain();

        assert_eq!(chain.minimum_work(), Network::Mainnet.minimum_chain_work());
        assert!(!chain.has_minimum_work());
    }

    #[test]
    fn a_branch_must_attach_to_a_held_header_above_genesis() {
        let mut chain = MainnetFixture::chain();

        assert_eq!(
            chain.replace_from(BlockHeight::ZERO, &[], &CLOCK),
            Err((0, ValidationError::UnknownParent))
        );
        assert_eq!(
            chain.replace_from(BlockHeight::new(2), &[MainnetFixture::header(2)], &CLOCK),
            Err((0, ValidationError::UnknownParent))
        );
    }

    #[test]
    fn truncating_forgets_the_dropped_headers() {
        let mut chain = MainnetFixture::chain();
        for height in 1..=3 {
            chain.extend(MainnetFixture::header(height), &CLOCK).expect("valid");
        }

        chain.truncate(BlockHeight::new(1));

        assert_eq!(chain.tip_height(), BlockHeight::new(1));
        assert!(chain.height_of(&MainnetFixture::header(3).hash()).expect("view").is_none());
        assert!(chain.extend(MainnetFixture::header(2), &CLOCK).is_ok());
    }
}
