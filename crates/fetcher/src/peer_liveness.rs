use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub(crate) struct PeerLiveness {
    owed_since: Option<Instant>,
    strikes: u32,
}

impl PeerLiveness {
    const FLOOR_MS: u64 = 15_000;
    const MEDIAN_FACTOR: u64 = 8;
    const STRIKE_LIMIT: u32 = 3;

    pub(crate) const fn new() -> Self {
        Self {
            owed_since: None,
            strikes: 0,
        }
    }

    pub(crate) fn on_request(&mut self, now: Instant) {
        self.owed_since.get_or_insert(now);
    }

    pub(crate) fn on_response(&mut self, now: Instant, outstanding: bool) {
        self.strikes = 0;
        self.owed_since = outstanding.then_some(now);
    }

    pub(crate) const fn on_strike(&mut self) {
        self.strikes = self.strikes.saturating_add(1);
    }

    pub(crate) const fn on_cancel(&mut self, outstanding: bool) {
        if !outstanding {
            self.owed_since = None;
        }
    }

    pub(crate) const fn strikes(&self) -> u32 {
        self.strikes
    }

    pub(crate) fn owed_for(&self, now: Instant) -> Option<Duration> {
        self.owed_since
            .map(|since| now.saturating_duration_since(since))
    }

    pub(crate) fn is_unresponsive(&self, now: Instant, fleet_median_ms: Option<u64>) -> bool {
        let limit_ms = fleet_median_ms.map_or(Self::FLOOR_MS, |median| {
            median
                .saturating_mul(Self::MEDIAN_FACTOR)
                .max(Self::FLOOR_MS)
        });
        self.strikes >= Self::STRIKE_LIMIT
            || self
                .owed_for(now)
                .is_some_and(|owed| owed > Duration::from_millis(limit_ms))
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::PeerLiveness;

    struct Clock(Instant);

    impl Clock {
        fn at(&self, secs: u64) -> Instant {
            self.0 + Duration::from_secs(secs)
        }
    }

    #[test]
    fn idle_peer_owes_nothing() {
        let clock = Clock(Instant::now());
        assert!(!PeerLiveness::new().is_unresponsive(clock.at(600), None));
    }

    #[test]
    fn debt_starts_at_the_first_request() {
        let clock = Clock(Instant::now());
        let mut liveness = PeerLiveness::new();
        liveness.on_request(clock.at(0));
        liveness.on_request(clock.at(10));
        assert_eq!(
            liveness.owed_for(clock.at(16)),
            Some(Duration::from_secs(16))
        );
        assert!(liveness.is_unresponsive(clock.at(16), None));
        assert!(!liveness.is_unresponsive(clock.at(15), None));
    }

    #[test]
    fn response_restarts_or_clears_the_clock() {
        let clock = Clock(Instant::now());
        let mut liveness = PeerLiveness::new();
        liveness.on_request(clock.at(0));
        liveness.on_response(clock.at(10), true);
        assert!(!liveness.is_unresponsive(clock.at(20), None));
        assert!(liveness.is_unresponsive(clock.at(26), None));
        liveness.on_response(clock.at(26), false);
        assert_eq!(liveness.owed_for(clock.at(100)), None);
    }

    #[test]
    fn a_peer_idled_by_a_lost_race_is_not_timed_out() {
        let clock = Clock(Instant::now());
        let mut liveness = PeerLiveness::new();
        liveness.on_request(clock.at(0));
        liveness.on_strike();
        liveness.on_cancel(false);
        assert!(!liveness.is_unresponsive(clock.at(600), None));
    }

    #[test]
    fn consecutive_lost_races_evict_even_while_idle() {
        let clock = Clock(Instant::now());
        let mut liveness = PeerLiveness::new();
        for _ in 0..PeerLiveness::STRIKE_LIMIT - 1 {
            liveness.on_strike();
        }
        assert!(!liveness.is_unresponsive(clock.at(1), None));
        liveness.on_strike();
        assert!(liveness.is_unresponsive(clock.at(1), None));
    }

    #[test]
    fn a_delivery_forgives_earlier_strikes() {
        let clock = Clock(Instant::now());
        let mut liveness = PeerLiveness::new();
        liveness.on_strike();
        liveness.on_strike();
        liveness.on_response(clock.at(1), false);
        liveness.on_strike();
        assert!(!liveness.is_unresponsive(clock.at(2), None));
        assert_eq!(liveness.strikes(), 1);
    }

    #[test]
    fn slow_fleet_raises_the_limit() {
        let clock = Clock(Instant::now());
        let mut liveness = PeerLiveness::new();
        liveness.on_request(clock.at(0));
        assert!(!liveness.is_unresponsive(clock.at(20), Some(3_000)));
        assert!(liveness.is_unresponsive(clock.at(25), Some(3_000)));
    }
}
