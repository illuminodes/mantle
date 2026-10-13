use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub(crate) struct PeerScore {
    latency_ms: u64,
    samples: u32,
}

impl PeerScore {
    const UNPROVEN_MS: u64 = 2_000;
    const EWMA_WEIGHT: u64 = 4;
    const MIN_SAMPLES: u32 = 3;
    const MIN_FLEET: usize = 8;
    const SLOW_FACTOR: u64 = 4;
    const SLOW_FLOOR_MS: u64 = 5_000;
    const STALL_FLOOR_MS: u64 = 20_000;
    const BASE_CAP: usize = 2;
    const FAST_CAP: usize = 4;

    pub(crate) const fn new() -> Self {
        Self {
            latency_ms: Self::UNPROVEN_MS,
            samples: 0,
        }
    }

    pub(crate) fn observe(&mut self, sample: Duration) {
        let sample_ms = u64::try_from(sample.as_millis()).unwrap_or(u64::MAX);
        self.latency_ms = if self.samples == 0 {
            sample_ms
        } else if sample_ms >= self.latency_ms {
            self.latency_ms + (sample_ms - self.latency_ms) / Self::EWMA_WEIGHT
        } else {
            self.latency_ms - (self.latency_ms - sample_ms) / Self::EWMA_WEIGHT
        };
        self.samples = self.samples.saturating_add(1);
    }

    pub(crate) const fn expected_ms(&self) -> u64 {
        self.latency_ms
    }

    const fn is_proven(&self) -> bool {
        self.samples >= Self::MIN_SAMPLES
    }

    pub(crate) fn median_ms(scores: impl Iterator<Item = Self>) -> Option<u64> {
        let mut proven: Vec<u64> = scores
            .filter(Self::is_proven)
            .map(|score| score.latency_ms)
            .collect();
        if proven.len() < Self::MIN_FLEET {
            return None;
        }
        proven.sort_unstable();
        Some(proven[proven.len() / 2])
    }

    pub(crate) fn is_slow(&self, fleet_median_ms: Option<u64>) -> bool {
        let Some(median) = fleet_median_ms else {
            return false;
        };
        self.is_proven()
            && self.latency_ms > median.saturating_mul(Self::SLOW_FACTOR).max(Self::SLOW_FLOOR_MS)
    }

    pub(crate) fn is_stalled(oldest_request: Duration, fleet_median_ms: Option<u64>) -> bool {
        let Some(median) = fleet_median_ms else {
            return false;
        };
        let limit_ms = median
            .saturating_mul(Self::SLOW_FACTOR * 2)
            .max(Self::STALL_FLOOR_MS);
        oldest_request > Duration::from_millis(limit_ms)
    }

    pub(crate) fn inflight_cap(&self, fleet_median_ms: Option<u64>) -> usize {
        match fleet_median_ms {
            Some(median) if self.is_proven() && self.latency_ms <= median => Self::FAST_CAP,
            _ => Self::BASE_CAP,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::PeerScore;

    struct ScoreFixture;

    impl ScoreFixture {
        fn proven(latency_ms: u64) -> PeerScore {
            let mut score = PeerScore::new();
            for _ in 0..PeerScore::MIN_SAMPLES {
                score.observe(Duration::from_millis(latency_ms));
            }
            score
        }

        fn fleet(latency_ms: u64) -> Vec<PeerScore> {
            (0..PeerScore::MIN_FLEET)
                .map(|_| Self::proven(latency_ms))
                .collect()
        }
    }

    #[test]
    fn first_sample_replaces_the_prior() {
        let mut score = PeerScore::new();
        score.observe(Duration::from_millis(400));
        assert_eq!(score.expected_ms(), 400);
    }

    #[test]
    fn later_samples_move_the_average_partway() {
        let mut score = PeerScore::new();
        score.observe(Duration::from_millis(400));
        score.observe(Duration::from_millis(800));
        assert_eq!(score.expected_ms(), 500);
    }

    #[test]
    fn median_needs_a_proven_fleet() {
        let small = ScoreFixture::fleet(1_000)[..PeerScore::MIN_FLEET - 1].to_vec();
        assert_eq!(PeerScore::median_ms(small.into_iter()), None);
        let full = ScoreFixture::fleet(1_000);
        assert_eq!(PeerScore::median_ms(full.into_iter()), Some(1_000));
    }

    #[test]
    fn unproven_peers_are_not_slow() {
        let mut score = PeerScore::new();
        score.observe(Duration::from_mins(1));
        assert!(!score.is_slow(Some(1_000)));
    }

    #[test]
    fn proven_peer_far_above_the_median_is_slow() {
        assert!(ScoreFixture::proven(20_000).is_slow(Some(1_000)));
        assert!(!ScoreFixture::proven(3_000).is_slow(Some(1_000)));
        assert!(!ScoreFixture::proven(20_000).is_slow(None));
    }

    #[test]
    fn slow_floor_protects_a_fast_fleet() {
        assert!(!ScoreFixture::proven(4_000).is_slow(Some(200)));
    }

    #[test]
    fn old_requests_stall_only_past_the_floor_and_scaled_median() {
        assert!(!PeerScore::is_stalled(Duration::from_secs(19), Some(1_000)));
        assert!(PeerScore::is_stalled(Duration::from_secs(21), Some(1_000)));
        assert!(!PeerScore::is_stalled(Duration::from_secs(21), Some(5_000)));
        assert!(!PeerScore::is_stalled(Duration::from_mins(5), None));
    }

    #[test]
    fn only_proven_fast_peers_get_the_deep_pipeline() {
        assert_eq!(ScoreFixture::proven(500).inflight_cap(Some(1_000)), PeerScore::FAST_CAP);
        assert_eq!(ScoreFixture::proven(2_000).inflight_cap(Some(1_000)), PeerScore::BASE_CAP);
        assert_eq!(PeerScore::new().inflight_cap(Some(1_000)), PeerScore::BASE_CAP);
        assert_eq!(ScoreFixture::proven(500).inflight_cap(None), PeerScore::BASE_CAP);
    }
}
