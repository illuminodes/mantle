#[derive(Debug, Clone, Copy)]
pub(crate) struct TipQuorum {
    required: usize,
}

impl TipQuorum {
    pub(crate) const fn new(required: usize) -> Self {
        Self { required }
    }

    pub(crate) fn reached(self, empty_votes: usize, ready_peers: usize) -> bool {
        empty_votes > 0 && empty_votes >= self.required.min(ready_peers)
    }
}

#[cfg(test)]
mod tests {
    use super::TipQuorum;

    #[test]
    fn one_empty_reply_among_many_peers_is_not_the_tip() {
        assert!(!TipQuorum::new(8).reached(1, 64));
    }

    #[test]
    fn quorum_of_empty_replies_is_the_tip() {
        assert!(TipQuorum::new(8).reached(8, 64));
    }

    #[test]
    fn every_ready_peer_agreeing_is_the_tip_when_fewer_than_quorum() {
        assert!(TipQuorum::new(8).reached(3, 3));
        assert!(!TipQuorum::new(8).reached(2, 3));
    }

    #[test]
    fn no_votes_is_never_the_tip() {
        assert!(!TipQuorum::new(8).reached(0, 0));
    }
}
