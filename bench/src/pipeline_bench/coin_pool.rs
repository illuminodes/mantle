use std::collections::VecDeque;

use crate::spendable_coin::SpendableCoin;

/// The coins the synthetic chain can still spend.
///
/// Coins created by the last few blocks are kept apart so a set share of
/// each block's inputs spends them, the way real blocks spend recent
/// outputs. Older coins are spent oldest first.
pub struct CoinPool {
    old: VecDeque<SpendableCoin>,
    recent: VecDeque<Vec<SpendableCoin>>,
    fresh: Vec<SpendableCoin>,
    recent_percent: u32,
}

impl CoinPool {
    const RECENT_BLOCKS: usize = 3;

    pub fn new(seed: Vec<SpendableCoin>, recent_percent: u32) -> Self {
        Self {
            old: seed.into(),
            recent: VecDeque::new(),
            fresh: Vec::new(),
            recent_percent,
        }
    }

    pub fn take(&mut self, count: usize) -> Vec<SpendableCoin> {
        let recent_wanted = count * self.recent_percent as usize / 100;
        let mut taken = Vec::with_capacity(count);
        for bucket in self.recent.iter_mut().rev() {
            while taken.len() < recent_wanted {
                let Some(coin) = bucket.pop() else { break };
                taken.push(coin);
            }
        }
        while taken.len() < count {
            taken.push(self.old.pop_front().expect("seed holds enough coins"));
        }
        taken
    }

    pub fn add(&mut self, coin: SpendableCoin) {
        self.fresh.push(coin);
    }

    pub fn end_block(&mut self) {
        self.recent.push_back(std::mem::take(&mut self.fresh));
        if self.recent.len() > Self::RECENT_BLOCKS {
            let aged = self.recent.pop_front().expect("more than RECENT_BLOCKS buckets");
            self.old.extend(aged);
        }
    }
}
