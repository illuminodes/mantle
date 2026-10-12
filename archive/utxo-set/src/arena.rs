use mantle::primitives::BlockHeight;
use mantle_consensus::chain_view::NewCoin;

use crate::coin_entry::CoinEntry;

/// Index into the coin arena. The entry's outputs occupy slots
/// `base .. base + count` in the arena vec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArenaSpan {
    pub base: u32,
    pub count: u16,
}

/// Compact handle stored in the hashmap. Keeps the map value small (~16 bytes)
/// so resizes are cheap and probing is cache-friendly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxHandle {
    pub span: ArenaSpan,
    pub height: BlockHeight,
    pub live: u64,
    pub coinbase: bool,
}

impl TxHandle {
    #[inline]
    #[must_use]
    pub fn is_fully_spent(&self) -> bool {
        self.live == 0
    }

    #[inline]
    #[must_use]
    pub fn unspent_count(&self) -> u32 {
        self.live.count_ones()
    }

    #[inline]
    #[must_use]
    pub fn is_unspent(&self, vout: u32) -> bool {
        if vout >= 64 {
            return false;
        }
        self.live & (1 << vout) != 0
    }

    #[inline]
    pub fn mark_spent(&mut self, vout: u32) {
        if vout < 64 {
            self.live &= !(1 << vout);
        }
    }

    #[inline]
    pub fn mark_unspent(&mut self, vout: u32) {
        if vout < 64 {
            self.live |= 1 << vout;
        }
    }
}

/// Append-only arena for `CoinEntry` values. Txs are allocated in contiguous
/// spans. Spent coins are replaced with a tombstone (value=0, empty spk) so
/// the arena indices stay stable.
pub struct CoinArena {
    coins: Vec<Option<CoinEntry>>,
}

impl CoinArena {
    #[must_use]
    pub fn new() -> Self {
        Self {
            coins: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            coins: Vec::with_capacity(cap),
        }
    }

    /// Allocate a span for `count` outputs, returning the base index.
    /// Slots are initialized to `None`.
    #[allow(clippy::cast_possible_truncation)]
    pub fn alloc(&mut self, count: u16) -> ArenaSpan {
        let base = self.coins.len();
        self.coins.resize_with(base + count as usize, || None);
        ArenaSpan {
            base: base as u32, // arena won't exceed 4B slots
            count,
        }
    }

    /// Allocate and fill a span directly from `NewCoin` data.
    /// Coins must all share the same txid (contiguous run from a block).
    #[allow(clippy::cast_possible_truncation)]
    pub fn alloc_from_coins(&mut self, coins: &[NewCoin<'_>], max_vout: u32) -> ArenaSpan {
        let count = max_vout + 1;
        let base = self.coins.len();
        self.coins.reserve(count as usize);

        // Push slots sequentially — fill gaps with None, actual coins with Some.
        // Avoids resize_with which would zero all slots before we overwrite them.
        let mut next_vout = 0u32;
        for c in coins {
            let vout = c.outpoint.vout;
            while next_vout < vout {
                self.coins.push(None);
                next_vout += 1;
            }
            self.coins.push(Some(CoinEntry {
                value: c.value,
                script_pubkey: c.script_pubkey.into(),
            }));
            next_vout = vout + 1;
        }
        while next_vout < count {
            self.coins.push(None);
            next_vout += 1;
        }

        ArenaSpan {
            base: base as u32,
            count: count as u16,
        }
    }

    #[inline]
    #[must_use]
    pub fn get(&self, span: ArenaSpan, vout: u32) -> Option<&CoinEntry> {
        if vout >= u32::from(span.count) {
            return None;
        }
        self.coins
            .get(span.base as usize + vout as usize)
            .and_then(Option::as_ref)
    }

    /// Take a coin out of the arena (for spend). Returns `None` if already
    /// spent or out of range.
    pub fn take(&mut self, span: ArenaSpan, vout: u32) -> Option<CoinEntry> {
        if vout >= u32::from(span.count) {
            return None;
        }
        self.coins
            .get_mut(span.base as usize + vout as usize)
            .and_then(Option::take)
    }

    /// Put a coin back into the arena (for disconnect/unspend).
    pub fn put(&mut self, span: ArenaSpan, vout: u32, coin: CoinEntry) {
        let idx = span.base as usize + vout as usize;
        if idx < self.coins.len() {
            self.coins[idx] = Some(coin);
        }
    }

    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.coins.len()
    }

    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.coins.is_empty()
    }
}

impl Default for CoinArena {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use mantle::primitives::Satoshi;

    use super::*;

    fn coin(sats: u64) -> CoinEntry {
        CoinEntry {
            value: Satoshi::new(sats),
            script_pubkey: vec![0x76, 0xa9].into(),
        }
    }

    #[test]
    fn alloc_and_get() {
        let mut arena = CoinArena::new();
        let span = arena.alloc(3);
        assert_eq!(span.base, 0);
        assert_eq!(span.count, 3);

        arena.put(span, 0, coin(1000));
        arena.put(span, 2, coin(3000));

        assert_eq!(arena.get(span, 0).unwrap().value, Satoshi::new(1000));
        assert!(arena.get(span, 1).is_none());
        assert_eq!(arena.get(span, 2).unwrap().value, Satoshi::new(3000));
        assert!(arena.get(span, 3).is_none());
    }

    #[test]
    fn take_removes_coin() {
        let mut arena = CoinArena::new();
        let span = arena.alloc(2);
        arena.put(span, 0, coin(1000));
        arena.put(span, 1, coin(2000));

        let taken = arena.take(span, 0).unwrap();
        assert_eq!(taken.value, Satoshi::new(1000));
        assert!(arena.get(span, 0).is_none());
        assert!(arena.get(span, 1).is_some());
    }

    #[test]
    fn sequential_allocs() {
        let mut arena = CoinArena::new();
        let s1 = arena.alloc(2);
        let s2 = arena.alloc(3);
        assert_eq!(s1.base, 0);
        assert_eq!(s2.base, 2);
        assert_eq!(arena.len(), 5);

        arena.put(s1, 0, coin(100));
        arena.put(s2, 0, coin(200));
        assert_eq!(arena.get(s1, 0).unwrap().value, Satoshi::new(100));
        assert_eq!(arena.get(s2, 0).unwrap().value, Satoshi::new(200));
    }

    #[test]
    fn handle_bitmap() {
        let mut h = TxHandle {
            span: ArenaSpan { base: 0, count: 3 },
            height: BlockHeight::new(100),
            live: 0b111,
            coinbase: false,
        };
        assert_eq!(h.unspent_count(), 3);
        assert!(h.is_unspent(0));
        assert!(h.is_unspent(1));
        assert!(h.is_unspent(2));
        assert!(!h.is_unspent(3));

        h.mark_spent(1);
        assert!(!h.is_unspent(1));
        assert_eq!(h.unspent_count(), 2);

        h.mark_unspent(1);
        assert!(h.is_unspent(1));
        assert_eq!(h.unspent_count(), 3);
    }

    #[test]
    fn handle_fully_spent() {
        let mut h = TxHandle {
            span: ArenaSpan { base: 0, count: 2 },
            height: BlockHeight::new(1),
            live: 0b11,
            coinbase: false,
        };
        h.mark_spent(0);
        h.mark_spent(1);
        assert!(h.is_fully_spent());
    }
}
