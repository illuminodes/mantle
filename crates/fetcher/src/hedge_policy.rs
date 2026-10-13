use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HedgeAction {
    Wait,
    Hedge,
    Reclaim,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HedgePolicy {
    Steady { reference_ms: u64 },
    Tail { reference_ms: u64 },
}

impl HedgePolicy {
    const STEADY_FLOOR_MS: u64 = 2_000;
    const STEADY_FACTOR: u64 = 2;
    const STEADY_FANOUT: usize = 2;
    const TAIL_FLOOR_MS: u64 = 500;
    const TAIL_FACTOR: u64 = 1;
    const TAIL_FANOUT: usize = 6;
    const RECLAIM_FLOOR_MS: u64 = 8_000;
    const RECLAIM_FACTOR: u64 = 4;

    pub(crate) const fn select(
        queue_drained: bool,
        fleet_median_ms: Option<u64>,
        ewma_ms: u64,
    ) -> Self {
        let reference_ms = match fleet_median_ms {
            Some(median) => median,
            None => ewma_ms,
        };
        if queue_drained {
            Self::Tail { reference_ms }
        } else {
            Self::Steady { reference_ms }
        }
    }

    pub(crate) const fn fanout(self) -> usize {
        match self {
            Self::Steady { .. } => Self::STEADY_FANOUT,
            Self::Tail { .. } => Self::TAIL_FANOUT,
        }
    }

    pub(crate) fn action(
        self,
        since_first: Duration,
        since_last: Duration,
        holders: usize,
    ) -> HedgeAction {
        if since_first >= self.reclaim_after() {
            HedgeAction::Reclaim
        } else if holders < self.fanout() && since_last >= self.hedge_after() {
            HedgeAction::Hedge
        } else {
            HedgeAction::Wait
        }
    }

    fn hedge_after(self) -> Duration {
        let (reference_ms, factor, floor_ms) = match self {
            Self::Steady { reference_ms } => {
                (reference_ms, Self::STEADY_FACTOR, Self::STEADY_FLOOR_MS)
            }
            Self::Tail { reference_ms } => (reference_ms, Self::TAIL_FACTOR, Self::TAIL_FLOOR_MS),
        };
        Duration::from_millis(reference_ms.saturating_mul(factor).max(floor_ms))
    }

    fn reclaim_after(self) -> Duration {
        let (Self::Steady { reference_ms } | Self::Tail { reference_ms }) = self;
        Duration::from_millis(
            reference_ms
                .saturating_mul(Self::RECLAIM_FACTOR)
                .max(Self::RECLAIM_FLOOR_MS),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{HedgeAction, HedgePolicy};

    const MS: fn(u64) -> Duration = Duration::from_millis;

    #[test]
    fn fleet_median_wins_over_ewma() {
        assert_eq!(
            HedgePolicy::select(false, Some(300), 5_000),
            HedgePolicy::Steady { reference_ms: 300 }
        );
        assert_eq!(
            HedgePolicy::select(true, None, 700),
            HedgePolicy::Tail { reference_ms: 700 }
        );
    }

    #[test]
    fn steady_waits_for_the_floor_and_caps_fanout() {
        let policy = HedgePolicy::Steady { reference_ms: 200 };
        assert_eq!(policy.action(MS(1_999), MS(1_999), 1), HedgeAction::Wait);
        assert_eq!(policy.action(MS(2_000), MS(2_000), 1), HedgeAction::Hedge);
        assert_eq!(policy.action(MS(3_000), MS(3_000), 2), HedgeAction::Wait);
    }

    #[test]
    fn tail_hedges_early_and_one_copy_per_interval() {
        let policy = HedgePolicy::Tail { reference_ms: 200 };
        assert_eq!(policy.action(MS(500), MS(500), 1), HedgeAction::Hedge);
        assert_eq!(policy.action(MS(900), MS(400), 2), HedgeAction::Wait);
        assert_eq!(policy.action(MS(1_000), MS(500), 5), HedgeAction::Hedge);
        assert_eq!(policy.action(MS(3_000), MS(3_000), 6), HedgeAction::Wait);
    }

    #[test]
    fn tail_interval_scales_with_a_slow_fleet() {
        let policy = HedgePolicy::Tail {
            reference_ms: 1_500,
        };
        assert_eq!(policy.action(MS(1_000), MS(1_000), 1), HedgeAction::Wait);
        assert_eq!(policy.action(MS(1_500), MS(1_500), 1), HedgeAction::Hedge);
    }

    #[test]
    fn reclaim_is_measured_from_the_first_issue() {
        let policy = HedgePolicy::Tail { reference_ms: 200 };
        assert_eq!(policy.action(MS(8_000), MS(100), 6), HedgeAction::Reclaim);
        let slow = HedgePolicy::Steady {
            reference_ms: 3_000,
        };
        assert_eq!(slow.action(MS(11_000), MS(11_000), 2), HedgeAction::Wait);
        assert_eq!(slow.action(MS(12_000), MS(12_000), 2), HedgeAction::Reclaim);
    }
}
