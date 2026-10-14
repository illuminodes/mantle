use mantle::primitives::BlockHeight;
use mantle_storage::types::{Durability, ReqToken};

/// How each block's commit is written: in memory, except at every
/// `every`-th height, where the commit uses `boundary`.
#[derive(Clone, Copy, Debug)]
pub struct CommitPlan {
    pub every: u32,
    pub boundary: Durability,
}

impl CommitPlan {
    #[must_use]
    pub fn durability(&self, height: BlockHeight) -> Durability {
        if self.every > 0 && height.to_u32().is_multiple_of(self.every) {
            self.boundary
        } else {
            Durability::Memory
        }
    }

    #[must_use]
    pub fn token(height: BlockHeight) -> ReqToken {
        ReqToken(u64::from(height.to_u32()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_boundary_heights_use_the_boundary_durability() {
        let plan = CommitPlan {
            every: 2016,
            boundary: Durability::Flushed,
        };
        assert_eq!(plan.durability(BlockHeight::new(4032)), Durability::Flushed);
        assert_eq!(plan.durability(BlockHeight::new(4033)), Durability::Memory);
        let never = CommitPlan {
            every: 0,
            boundary: Durability::Synced,
        };
        assert_eq!(never.durability(BlockHeight::new(0)), Durability::Memory);
    }
}
