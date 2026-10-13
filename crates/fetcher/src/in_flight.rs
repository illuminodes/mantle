use std::time::Instant;

#[derive(Debug, Clone)]
pub(crate) struct InFlight {
    holders: Vec<(u16, Instant)>,
    first_issued: Instant,
    last_issued: Instant,
}

impl InFlight {
    pub(crate) fn new(slot: u16, now: Instant) -> Self {
        Self {
            holders: vec![(slot, now)],
            first_issued: now,
            last_issued: now,
        }
    }

    pub(crate) fn add_holder(&mut self, slot: u16, now: Instant) {
        self.holders.push((slot, now));
        self.last_issued = now;
    }

    pub(crate) fn drop_holder(&mut self, slot: u16) {
        self.holders.retain(|(held_by, _)| *held_by != slot);
    }

    pub(crate) fn holders(&self) -> &[(u16, Instant)] {
        &self.holders
    }

    pub(crate) fn holds(&self, slot: u16) -> bool {
        self.holders.iter().any(|(held_by, _)| *held_by == slot)
    }

    pub(crate) fn issued_at(&self, slot: u16) -> Instant {
        self.holders
            .iter()
            .find(|(held_by, _)| *held_by == slot)
            .map_or(self.first_issued, |(_, issued)| *issued)
    }

    pub(crate) fn beaten_by(&self, winner: u16) -> impl Iterator<Item = (u16, Instant)> + '_ {
        let winner_issued = self.issued_at(winner);
        self.holders
            .iter()
            .copied()
            .filter(move |(slot, issued)| *slot != winner && *issued < winner_issued)
    }

    pub(crate) fn outrun_by(&self, winner: u16) -> impl Iterator<Item = u16> + '_ {
        let winner_issued = self.issued_at(winner);
        self.holders
            .iter()
            .filter(move |(slot, issued)| *slot != winner && *issued >= winner_issued)
            .map(|(slot, _)| *slot)
    }

    pub(crate) const fn first_issued(&self) -> Instant {
        self.first_issued
    }

    pub(crate) const fn last_issued(&self) -> Instant {
        self.last_issued
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::InFlight;

    struct Clock(Instant);

    impl Clock {
        fn at(&self, ms: u64) -> Instant {
            self.0 + Duration::from_millis(ms)
        }
    }

    #[test]
    fn hedge_moves_last_issued_but_not_first() {
        let clock = Clock(Instant::now());
        let mut info = InFlight::new(1, clock.at(0));
        info.add_holder(2, clock.at(900));
        assert_eq!(info.first_issued(), clock.at(0));
        assert_eq!(info.last_issued(), clock.at(900));
        assert!(info.holds(1) && info.holds(2) && !info.holds(3));
    }

    #[test]
    fn issued_at_is_per_holder_with_first_issue_fallback() {
        let clock = Clock(Instant::now());
        let mut info = InFlight::new(1, clock.at(0));
        info.add_holder(2, clock.at(900));
        assert_eq!(info.issued_at(2), clock.at(900));
        assert_eq!(info.issued_at(7), clock.at(0));
    }

    #[test]
    fn only_earlier_holders_are_beaten() {
        let clock = Clock(Instant::now());
        let mut info = InFlight::new(1, clock.at(0));
        info.add_holder(2, clock.at(900));
        info.add_holder(3, clock.at(1_800));
        let beaten: Vec<u16> = info.beaten_by(2).map(|(slot, _)| slot).collect();
        assert_eq!(beaten, vec![1]);
        assert_eq!(info.outrun_by(2).collect::<Vec<_>>(), vec![3]);
        assert_eq!(info.beaten_by(1).count(), 0);
        assert_eq!(info.outrun_by(1).collect::<Vec<_>>(), vec![2, 3]);
    }

    #[test]
    fn foreign_winner_beats_nobody() {
        let clock = Clock(Instant::now());
        let mut info = InFlight::new(1, clock.at(0));
        info.add_holder(2, clock.at(900));
        assert_eq!(info.beaten_by(9).count(), 0);
        assert_eq!(info.outrun_by(9).collect::<Vec<_>>(), vec![1, 2]);
    }

    #[test]
    fn dropping_every_holder_empties_it() {
        let clock = Clock(Instant::now());
        let mut info = InFlight::new(1, clock.at(0));
        info.add_holder(2, clock.at(5));
        info.drop_holder(1);
        info.drop_holder(2);
        assert!(info.holders().is_empty());
    }
}
