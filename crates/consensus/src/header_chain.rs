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
///
/// The chain may hold only a tail: `headers[0]` sits at `base`, and its
/// work entry is the total work from genesis through it. Headers below the
/// base are not held, so a branch must attach above it.
pub struct HeaderChain {
    base: BlockHeight,
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
        Some(Self::from_genesis(genesis, Self::allows_min_difficulty(network)).under_rules_of(network))
    }

    /// [`Self::from_tail`] under `network`'s difficulty rules, checkpoint and
    /// minimum work.
    #[must_use]
    pub fn tail_for_network(
        network: Network,
        base: BlockHeight,
        work: ChainWork,
        headers: &[BlockHeader],
    ) -> Option<Self> {
        Self::from_tail(base, work, headers, Self::allows_min_difficulty(network))
            .map(|chain| chain.under_rules_of(network))
    }

    const fn allows_min_difficulty(network: Network) -> bool {
        matches!(network, Network::Testnet3 | Network::Testnet4)
    }

    fn under_rules_of(self, network: Network) -> Self {
        self.with_checkpoint(network.checkpoint())
            .with_minimum_work(network.minimum_chain_work())
    }

    #[must_use]
    pub fn from_genesis(genesis: BlockHeader, allow_min_difficulty: bool) -> Self {
        Self::single(BlockHeight::ZERO, ChainWork::of_header(&genesis), genesis, allow_min_difficulty)
    }

    fn single(base: BlockHeight, work: ChainWork, header: BlockHeader, allow_min_difficulty: bool) -> Self {
        let mut heights = PrehashedMap::default();
        heights.insert(header.hash(), base);
        Self {
            base,
            headers: vec![header],
            work: vec![work],
            heights,
            checkpoint: None,
            minimum_work: ChainWork::ZERO,
            allow_min_difficulty,
        }
    }

    /// A chain holding `headers` from `base` up, taken as they are, whose
    /// first header carries `work` in total from genesis. `None` when
    /// `headers` is empty or does not link header to header.
    #[must_use]
    pub fn from_tail(
        base: BlockHeight,
        work: ChainWork,
        headers: &[BlockHeader],
        allow_min_difficulty: bool,
    ) -> Option<Self> {
        let (first, rest) = headers.split_first()?;
        let mut chain = Self::single(base, work, *first, allow_min_difficulty);
        for header in rest {
            if header.prev_block() != chain.tip().hash {
                return None;
            }
            chain.push(*header);
        }
        Some(chain)
    }

    /// The height of the oldest header held.
    #[must_use]
    pub const fn base(&self) -> BlockHeight {
        self.base
    }

    /// The total work from genesis through the header at `height`.
    #[must_use]
    pub fn work_at(&self, height: BlockHeight) -> Option<ChainWork> {
        self.work.get(self.index_of(height)?).copied()
    }

    /// The held headers from `height` up, oldest first.
    #[must_use]
    pub fn headers_from(&self, height: BlockHeight) -> &[BlockHeader] {
        let start = self.index_of(height.max(self.base)).unwrap_or(self.headers.len());
        &self.headers[start..]
    }

    /// Drop the headers below the start of the retarget period holding
    /// `height`, keeping at least the eleven headers behind the tip that
    /// the next header's median time reads. The base lands on a period
    /// start, so it moves once a period however often this is called, and
    /// the next retarget still finds the first header of its period.
    pub fn forget_below(&mut self, height: BlockHeight) {
        let tip = self.tip_height().to_u32();
        let wanted = height.to_u32().min(tip.saturating_sub(Self::MEDIAN_SPAN - 1));
        let floor = (wanted - wanted % Self::RETARGET_INTERVAL).max(self.base.to_u32());
        let Some(drop) = self.index_of(BlockHeight::new(floor)) else {
            return;
        };
        for header in self.headers.drain(..drop) {
            self.heights.remove(&header.hash());
        }
        self.work.drain(..drop);
        self.base = BlockHeight::new(floor);
    }

    const RETARGET_INTERVAL: u32 = 2_016;
    const MEDIAN_SPAN: u32 = 11;

    fn index_of(&self, height: BlockHeight) -> Option<usize> {
        let offset = usize::try_from(height.to_u32().checked_sub(self.base.to_u32())?).ok()?;
        (offset < self.headers.len()).then_some(offset)
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
    /// `UnknownParent` when `first` is at or below the base, or above the
    /// next height,
    /// the first rule a header breaks, with that header's index, or
    /// `InsufficientChainWork` (index of the last header) when the branch
    /// replaces headers without carrying more work than they do.
    pub fn replace_from(
        &mut self,
        first: BlockHeight,
        headers: &[BlockHeader],
        clock: &impl Clock,
    ) -> Result<(), (usize, ValidationError)> {
        let Some(keep) = first
            .to_u32()
            .checked_sub(1)
            .and_then(|parent| self.index_of(BlockHeight::new(parent)))
            .map(|index| index + 1)
        else {
            return Err((0, ValidationError::UnknownParent));
        };
        let base = BlockHeight::new(first.to_u32() - 1);
        let replaced_work = ChainWork::of_headers(&self.headers[keep..]);
        let replaced = self.headers.split_off(keep);
        self.work.truncate(keep);
        for header in &replaced {
            self.heights.remove(&header.hash());
        }
        let outcome = headers
            .iter()
            .enumerate()
            .try_for_each(|(index, header)| {
                self.extend(*header, clock)
                    .map(|_| ())
                    .map_err(|error| (index, error))
            })
            .and_then(|()| {
                let more = replaced.is_empty() || ChainWork::of_headers(headers) > replaced_work;
                more.then_some(()).ok_or((
                    headers.len().saturating_sub(1),
                    ValidationError::InsufficientChainWork,
                ))
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
        let height = BlockHeight::new(self.tip_height().to_u32() + 1);
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
        let keep = self.index_of(height).map_or(
            if height < self.base { 1 } else { self.headers.len() },
            |index| index + 1,
        );
        for header in self.headers.iter().skip(keep) {
            self.heights.remove(&header.hash());
        }
        self.headers.truncate(keep.max(1));
        self.work.truncate(keep.max(1));
    }

    #[must_use]
    pub fn header_at(&self, height: BlockHeight) -> Option<&BlockHeader> {
        self.headers.get(self.index_of(height)?)
    }

    #[must_use]
    pub fn tip_height(&self) -> BlockHeight {
        let above = u32::try_from(self.headers.len() - 1).unwrap_or(u32::MAX);
        BlockHeight::new(self.base.to_u32() + above)
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
        let end = self.index_of(*parent).ok_or(ChainViewError::NotFound)? + 1;
        let needed = usize::try_from(parent.to_u32().saturating_add(1).min(Self::MEDIAN_SPAN)).unwrap_or(11);
        if end < needed {
            return Err(ChainViewError::NotFound);
        }
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
    use mantle::primitives::{
        BlockHeader, BlockHeight, BlockTime, BlockVersion, ChainWork, CompactBits, Hash256, Nonce,
    };

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
                BlockVersion::new(1),
                Hash256::ZERO,
                Hash256::ZERO,
                BlockTime::new(1_231_006_505),
                CompactBits::new(0x207f_ffff),
                Nonce::new(0),
            )
        }

        fn easy_branch(parent: &BlockHeader, length: u32, salt: u8) -> Vec<BlockHeader> {
            let mut prev = *parent;
            (1..=length)
                .map(|step| {
                    let header = Self::mined(BlockHeader::new(
                        BlockVersion::new(1),
                        prev.hash(),
                        Hash256::from_bytes([salt; 32]),
                        prev.time() + step,
                        prev.bits(),
                        Nonce::new(0),
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
            assert_eq!(
                admitted,
                Ok(BlockHeight::new(u32::try_from(height).expect("small")))
            );
        }
        assert_eq!(chain.tip().hash, MainnetFixture::header(3).hash());
    }

    #[test]
    fn a_header_that_misses_its_target_is_refused() {
        let mut chain = MainnetFixture::chain();
        let mut forged = MainnetFixture::header(1);
        forged.set_nonce(Nonce::new(forged.nonce().to_u32().wrapping_add(1)));

        assert_eq!(
            chain.extend(forged, &CLOCK),
            Err(ValidationError::InsufficientProofOfWork)
        );
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
            BlockVersion::new(1),
            Hash256::ZERO,
            Hash256::ZERO,
            BlockTime::new(1_231_006_505),
            bits,
            Nonce::new(0),
        );
        let mut chain = HeaderChain::from_genesis(genesis, false);
        let stale = BlockHeader::new(
            BlockVersion::new(1),
            genesis.hash(),
            Hash256::ZERO,
            genesis.time(),
            bits,
            Nonce::new(0),
        );

        assert_eq!(
            chain.extend(MainnetFixture::mined(stale), &CLOCK),
            Err(ValidationError::TimestampTooEarly)
        );
    }

    #[test]
    fn the_checkpoint_admits_only_its_own_hash() {
        let real = MainnetFixture::header(2).hash();
        let mut agreeing =
            MainnetFixture::chain().with_checkpoint(Some((BlockHeight::new(2), real)));
        let mut disagreeing = MainnetFixture::chain()
            .with_checkpoint(Some((BlockHeight::new(2), Hash256::from_bytes([7; 32]))));
        for chain in [&mut agreeing, &mut disagreeing] {
            chain
                .extend(MainnetFixture::header(1), &CLOCK)
                .expect("block 1");
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
        chain
            .extend(MainnetFixture::header(1), &CLOCK)
            .expect("block 1");
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
            chain
                .extend(MainnetFixture::header(height), &CLOCK)
                .expect("valid");
        }
        let mut forged = MainnetFixture::header(2);
        forged.set_nonce(Nonce::new(forged.nonce().to_u32().wrapping_add(1)));

        let replaced = chain.replace_from(BlockHeight::new(2), &[forged], &CLOCK);

        assert_eq!(replaced, Err((0, ValidationError::InsufficientProofOfWork)));
        assert_eq!(chain.tip().hash, MainnetFixture::header(2).hash());
        assert_eq!(
            chain
                .height_of(&MainnetFixture::header(2).hash())
                .expect("view"),
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

        assert_eq!(
            chain.replace_from(BlockHeight::new(2), &rival, &CLOCK),
            Ok(())
        );
        assert_eq!(chain.tip().hash, rival[1].hash());
        assert_eq!(chain.tip_work().to_u128(), 4 * 2);
    }

    #[test]
    fn the_tip_work_sums_every_header_from_genesis() {
        let mut chain = MainnetFixture::chain();
        for height in 1..=3 {
            chain
                .extend(MainnetFixture::header(height), &CLOCK)
                .expect("valid");
        }

        assert_eq!(chain.tip_work().to_u128(), 4 * 0x1_0001_0001);
        chain.truncate(BlockHeight::new(1));
        assert_eq!(chain.tip_work().to_u128(), 2 * 0x1_0001_0001);
    }

    #[test]
    fn the_minimum_work_is_met_once_the_tip_work_reaches_it() {
        let mut chain =
            MainnetFixture::chain().with_minimum_work(ChainWork::new(3 * 0x1_0001_0001));
        chain
            .extend(MainnetFixture::header(1), &CLOCK)
            .expect("block 1");

        assert!(!chain.has_minimum_work());
        chain
            .extend(MainnetFixture::header(2), &CLOCK)
            .expect("block 2");
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
    fn a_tail_extends_like_the_whole_chain_and_reports_its_heights() {
        let genesis = MainnetFixture::easy_genesis();
        let branch = MainnetFixture::easy_branch(&genesis, 30, 1);
        let mut whole = HeaderChain::from_genesis(genesis, false);
        for header in &branch[..29] {
            whole.extend(*header, &CLOCK).expect("whole");
        }
        let base = BlockHeight::new(10);
        let mut tail = HeaderChain::from_tail(
            base,
            whole.work_at(base).expect("held"),
            whole.headers_from(base),
            false,
        )
        .expect("linked");

        assert_eq!(tail.base(), base);
        assert_eq!(tail.tip_height(), BlockHeight::new(29));
        assert_eq!(tail.tip_work(), whole.tip_work());
        assert_eq!(tail.header_at(BlockHeight::new(9)), None);
        assert_eq!(tail.header_at(BlockHeight::new(12)), whole.header_at(BlockHeight::new(12)));
        assert_eq!(tail.extend(branch[29], &CLOCK), Ok(BlockHeight::new(30)));
        assert_eq!(tail.height_of(&branch[29].hash()).expect("view"), Some(BlockHeight::new(30)));
    }

    #[test]
    fn a_tail_refuses_a_branch_below_its_base_and_one_too_short_for_its_median() {
        let genesis = MainnetFixture::easy_genesis();
        let held = MainnetFixture::easy_branch(&genesis, 30, 1);
        let mut whole = HeaderChain::from_genesis(genesis, false);
        for header in &held {
            whole.extend(*header, &CLOCK).expect("whole");
        }
        let base = BlockHeight::new(20);
        let mut tail =
            HeaderChain::from_tail(base, whole.work_at(base).expect("held"), whole.headers_from(base), false)
                .expect("linked");
        let below = MainnetFixture::easy_branch(&held[14], 20, 2);
        let mut short = HeaderChain::from_tail(base, ChainWork::ZERO, &held[19..25], false).expect("linked");

        assert_eq!(
            tail.replace_from(BlockHeight::new(16), &below, &CLOCK),
            Err((0, ValidationError::UnknownParent))
        );
        assert_eq!(tail.tip().hash, held[29].hash());
        assert_eq!(
            short.extend(held[25], &CLOCK).map_err(|error| matches!(error, ValidationError::ChainView(_))),
            Err(true)
        );
    }

    #[test]
    fn a_broken_tail_is_refused() {
        let genesis = MainnetFixture::easy_genesis();
        let mut branch = MainnetFixture::easy_branch(&genesis, 3, 1);
        branch.swap(1, 2);

        assert!(HeaderChain::from_tail(BlockHeight::new(1), ChainWork::ZERO, &branch, false).is_none());
        assert!(HeaderChain::from_tail(BlockHeight::new(1), ChainWork::ZERO, &[], false).is_none());
    }

    #[test]
    fn forgetting_keeps_the_start_of_the_retarget_period() {
        let genesis = MainnetFixture::easy_genesis();
        let branch = MainnetFixture::easy_branch(&genesis, 40, 1);
        let mut chain = HeaderChain::from_genesis(genesis, false);
        for header in &branch[..39] {
            chain.extend(*header, &CLOCK).expect("held");
        }
        let work = chain.tip_work();

        chain.forget_below(BlockHeight::new(35));

        assert_eq!(chain.base(), BlockHeight::ZERO);
        assert_eq!(chain.tip_work(), work);
        assert_eq!(chain.extend(branch[39], &CLOCK), Ok(BlockHeight::new(40)));
    }

    #[test]
    fn forgetting_past_a_retarget_keeps_its_first_header_and_eleven_behind_the_tip() {
        let genesis = MainnetFixture::easy_genesis();
        let branch = MainnetFixture::easy_branch(&genesis, 61, 1);
        let mut chain =
            HeaderChain::from_tail(BlockHeight::new(2_000), ChainWork::ZERO, &branch[..60], false).expect("linked");

        chain.forget_below(BlockHeight::new(2_059));

        assert_eq!(chain.base(), BlockHeight::new(2_016));
        assert_eq!(chain.tip_height(), BlockHeight::new(2_059));
        chain.forget_below(BlockHeight::new(2_059));
        assert_eq!(chain.base(), BlockHeight::new(2_016));
        assert_eq!(chain.extend(branch[60], &CLOCK), Ok(BlockHeight::new(2_060)));
    }

    #[test]
    fn truncating_forgets_the_dropped_headers() {
        let mut chain = MainnetFixture::chain();
        for height in 1..=3 {
            chain
                .extend(MainnetFixture::header(height), &CLOCK)
                .expect("valid");
        }

        chain.truncate(BlockHeight::new(1));

        assert_eq!(chain.tip_height(), BlockHeight::new(1));
        assert!(
            chain
                .height_of(&MainnetFixture::header(3).hash())
                .expect("view")
                .is_none()
        );
        assert!(chain.extend(MainnetFixture::header(2), &CLOCK).is_ok());
    }
}
