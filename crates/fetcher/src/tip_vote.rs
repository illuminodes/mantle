use std::time::{Duration, Instant};

/// Decides when a header round has reached the tip: every ready peer has
/// said it has nothing better, or `window` has passed since the first one
/// did and nobody has sent a better page in the meantime.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TipVote {
    window: Duration,
    first_empty: Option<Instant>,
}

impl TipVote {
    pub(crate) const fn new(window: Duration) -> Self {
        Self {
            window,
            first_empty: None,
        }
    }

    pub(crate) fn reached(&mut self, empty_votes: usize, ready_peers: usize, now: Instant) -> bool {
        if empty_votes == 0 {
            return false;
        }
        let first = *self.first_empty.get_or_insert(now);
        empty_votes >= ready_peers || now.duration_since(first) >= self.window
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::TipVote;

    const WINDOW: Duration = Duration::from_secs(15);

    #[test]
    fn no_votes_is_never_the_tip() {
        let now = Instant::now();

        assert!(!TipVote::new(WINDOW).reached(0, 0, now));
        assert!(!TipVote::new(WINDOW).reached(0, 5, now + WINDOW * 2));
    }

    #[test]
    fn every_ready_peer_saying_nothing_better_is_the_tip_at_once() {
        assert!(TipVote::new(WINDOW).reached(3, 3, Instant::now()));
    }

    #[test]
    fn some_empty_votes_wait_for_the_other_peers_until_the_window_passes() {
        let start = Instant::now();
        let mut vote = TipVote::new(WINDOW);

        assert!(!vote.reached(8, 64, start));
        assert!(!vote.reached(20, 64, start + Duration::from_secs(14)));
        assert!(vote.reached(20, 64, start + WINDOW));
    }

    #[test]
    fn the_window_starts_at_the_first_empty_vote() {
        let start = Instant::now();
        let mut vote = TipVote::new(WINDOW);

        assert!(!vote.reached(0, 64, start));
        assert!(!vote.reached(1, 64, start + WINDOW));
        assert!(vote.reached(1, 64, start + WINDOW * 2));
    }
}
