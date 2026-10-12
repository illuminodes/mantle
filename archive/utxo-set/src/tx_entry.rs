use mantle::primitives::BlockHeight;
use mantle_consensus::chain_view::NewCoin;

use crate::coin_entry::CoinEntry;

const INLINE_CAP: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Bitmap {
    Inline(u64),
    Heap(Vec<u64>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outputs {
    Inline {
        len: u8,
        slots: [Option<CoinEntry>; INLINE_CAP],
    },
    Heap(Vec<Option<CoinEntry>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxEntry {
    pub height: BlockHeight,
    pub coinbase: bool,
    live: Bitmap,
    outputs: Outputs,
}

impl TxEntry {
    #[must_use]
    pub fn new(height: BlockHeight, coinbase: bool, outputs: Vec<Option<CoinEntry>>) -> Self {
        let count = outputs.len();
        if count <= INLINE_CAP {
            let mut word = 0u64;
            let mut slots: [Option<CoinEntry>; INLINE_CAP] = [None, None, None, None];
            for (i, slot) in outputs.into_iter().enumerate() {
                if slot.is_some() {
                    word |= 1 << i;
                }
                slots[i] = slot;
            }
            return Self {
                height,
                coinbase,
                live: Bitmap::Inline(word),
                #[allow(clippy::cast_possible_truncation)]
                outputs: Outputs::Inline { len: count as u8, slots },
            };
        }
        Self::new_heap(height, coinbase, outputs)
    }

    /// Build a `TxEntry` by draining from a mutable slice. The slots are
    /// `take()`-d so the source vec retains its capacity for reuse.
    #[must_use]
    pub fn drain_from(
        height: BlockHeight,
        coinbase: bool,
        src: &mut [Option<CoinEntry>],
    ) -> Self {
        let count = src.len();
        if count <= INLINE_CAP {
            let mut word = 0u64;
            let mut slots: [Option<CoinEntry>; INLINE_CAP] = [None, None, None, None];
            for (i, slot) in src.iter_mut().enumerate() {
                let taken = slot.take();
                if taken.is_some() {
                    word |= 1 << i;
                }
                slots[i] = taken;
            }
            return Self {
                height,
                coinbase,
                live: Bitmap::Inline(word),
                #[allow(clippy::cast_possible_truncation)]
                outputs: Outputs::Inline { len: count as u8, slots },
            };
        }
        let outputs: Vec<Option<CoinEntry>> = src.iter_mut().map(Option::take).collect();
        Self::new_heap(height, coinbase, outputs)
    }

    /// Build a `TxEntry` directly from a contiguous slice of `NewCoin`s that
    /// all belong to the same transaction. Avoids any intermediate Vec for
    /// the inline case (≤4 outputs with `max_vout` < 4).
    ///
    /// # Panics
    /// Panics if `max_vout` or any coin's `vout` exceeds `usize::MAX`.
    #[must_use]
    pub fn from_new_coins(
        height: BlockHeight,
        coinbase: bool,
        coins: &[NewCoin<'_>],
        max_vout: u32,
    ) -> Self {
        let slot_count = usize::try_from(max_vout).expect("max_vout exceeds usize") + 1;
        if slot_count <= INLINE_CAP {
            let mut word = 0u64;
            let mut slots: [Option<CoinEntry>; INLINE_CAP] = [None, None, None, None];
            for c in coins {
                let idx = usize::try_from(c.outpoint.vout).expect("vout exceeds usize");
                word |= 1 << idx;
                slots[idx] = Some(CoinEntry {
                    value: c.value,
                    script_pubkey: c.script_pubkey.into(),
                });
            }
            return Self {
                height,
                coinbase,
                live: Bitmap::Inline(word),
                #[allow(clippy::cast_possible_truncation)]
                outputs: Outputs::Inline { len: slot_count as u8, slots },
            };
        }
        let mut outputs: Vec<Option<CoinEntry>> = Vec::with_capacity(slot_count);
        outputs.resize_with(slot_count, || None);
        let mut word = 0u64;
        for c in coins {
            let idx = usize::try_from(c.outpoint.vout).expect("vout exceeds usize");
            outputs[idx] = Some(CoinEntry {
                value: c.value,
                script_pubkey: c.script_pubkey.into(),
            });
            if idx < 64 {
                word |= 1 << idx;
            }
        }
        if slot_count <= 64 {
            Self {
                height,
                coinbase,
                live: Bitmap::Inline(word),
                outputs: Outputs::Heap(outputs),
            }
        } else {
            let words = slot_count.div_ceil(64);
            let mut live = vec![0u64; words];
            live[0] = word;
            for c in coins {
                let idx = usize::try_from(c.outpoint.vout).expect("vout exceeds usize");
                if idx >= 64 {
                    live[idx / 64] |= 1 << (idx % 64);
                }
            }
            Self {
                height,
                coinbase,
                live: Bitmap::Heap(live),
                outputs: Outputs::Heap(outputs),
            }
        }
    }

    fn new_heap(height: BlockHeight, coinbase: bool, outputs: Vec<Option<CoinEntry>>) -> Self {
        let count = outputs.len();
        let (live, outs) = if count <= 64 {
            let mut word = 0u64;
            for (i, slot) in outputs.iter().enumerate() {
                if slot.is_some() {
                    word |= 1 << i;
                }
            }
            (Bitmap::Inline(word), Outputs::Heap(outputs))
        } else {
            let words = count.div_ceil(64);
            let mut live = vec![0u64; words];
            for (i, slot) in outputs.iter().enumerate() {
                if slot.is_some() {
                    live[i / 64] |= 1 << (i % 64);
                }
            }
            (Bitmap::Heap(live), Outputs::Heap(outputs))
        };
        Self {
            height,
            coinbase,
            live,
            outputs: outs,
        }
    }

    #[inline]
    #[must_use]
    pub fn is_fully_spent(&self) -> bool {
        match &self.live {
            Bitmap::Inline(w) => *w == 0,
            Bitmap::Heap(v) => v.iter().all(|&w| w == 0),
        }
    }

    #[inline]
    #[must_use]
    pub fn unspent_count(&self) -> u32 {
        match &self.live {
            Bitmap::Inline(w) => w.count_ones(),
            Bitmap::Heap(v) => v.iter().map(|w| w.count_ones()).sum(),
        }
    }

    #[inline]
    #[must_use]
    pub fn is_unspent(&self, vout: u32) -> bool {
        let idx = vout as usize;
        match &self.live {
            Bitmap::Inline(w) => {
                if idx >= 64 {
                    return false;
                }
                w & (1 << idx) != 0
            }
            Bitmap::Heap(v) => {
                let word = idx / 64;
                if word >= v.len() {
                    return false;
                }
                v[word] & (1 << (idx % 64)) != 0
            }
        }
    }

    #[must_use]
    pub fn get(&self, vout: u32) -> Option<&CoinEntry> {
        if !self.is_unspent(vout) {
            return None;
        }
        let idx = vout as usize;
        match &self.outputs {
            Outputs::Inline { len, slots } => {
                if idx >= *len as usize {
                    return None;
                }
                slots[idx].as_ref()
            }
            Outputs::Heap(v) => v.get(idx).and_then(Option::as_ref),
        }
    }

    pub fn spend(&mut self, vout: u32) -> Option<CoinEntry> {
        if !self.is_unspent(vout) {
            return None;
        }
        let idx = vout as usize;
        match &mut self.live {
            Bitmap::Inline(w) => *w &= !(1 << idx),
            Bitmap::Heap(v) => v[idx / 64] &= !(1 << (idx % 64)),
        }
        match &mut self.outputs {
            Outputs::Inline { slots, .. } => slots[idx].take(),
            Outputs::Heap(v) => v.get_mut(idx).and_then(Option::take),
        }
    }

    pub fn unspend(&mut self, vout: u32, coin: CoinEntry) {
        let idx = vout as usize;
        match &mut self.outputs {
            Outputs::Inline { len, slots } => {
                if idx < INLINE_CAP {
                    slots[idx] = Some(coin);
                    if idx >= *len as usize {
                        #[allow(clippy::cast_possible_truncation)]
                        { *len = (idx + 1) as u8; } // idx < INLINE_CAP (4)
                    }
                } else {
                    let mut heap: Vec<Option<CoinEntry>> =
                        slots.iter_mut().map(Option::take).collect();
                    heap.resize_with(idx + 1, || None);
                    heap[idx] = Some(coin);
                    self.outputs = Outputs::Heap(heap);
                }
            }
            Outputs::Heap(v) => {
                if idx >= v.len() {
                    v.resize_with(idx + 1, || None);
                }
                v[idx] = Some(coin);
            }
        }
        match &mut self.live {
            Bitmap::Inline(w) => {
                if idx < 64 {
                    *w |= 1 << idx;
                } else {
                    let words = (idx + 1).div_ceil(64);
                    let mut heap = vec![0u64; words];
                    heap[0] = *w;
                    heap[idx / 64] |= 1 << (idx % 64);
                    self.live = Bitmap::Heap(heap);
                }
            }
            Bitmap::Heap(v) => {
                let word = idx / 64;
                if word >= v.len() {
                    v.resize(word + 1, 0);
                }
                v[word] |= 1 << (idx % 64);
            }
        }
    }

    #[inline]
    #[must_use]
    pub fn output_count(&self) -> usize {
        match &self.outputs {
            Outputs::Inline { len, .. } => *len as usize,
            Outputs::Heap(v) => v.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use mantle::primitives::{BlockHeight, Satoshi};

    use super::*;

    fn coin(sats: u64) -> CoinEntry {
        CoinEntry {
            value: Satoshi::new(sats),
            script_pubkey: vec![0x76, 0xa9].into(),
        }
    }

    #[test]
    fn new_entry_all_unspent() {
        let entry = TxEntry::new(
            BlockHeight::new(100),
            false,
            vec![Some(coin(1000)), Some(coin(2000)), Some(coin(3000))],
        );
        assert_eq!(entry.unspent_count(), 3);
        assert!(!entry.is_fully_spent());
        assert!(entry.is_unspent(0));
        assert!(entry.is_unspent(1));
        assert!(entry.is_unspent(2));
        assert!(!entry.is_unspent(3));
        assert!(matches!(entry.live, Bitmap::Inline(_)));
        assert!(matches!(entry.outputs, Outputs::Inline { .. }));
    }

    #[test]
    fn four_outputs_stays_inline() {
        let entry = TxEntry::new(
            BlockHeight::new(1),
            false,
            vec![
                Some(coin(1)),
                Some(coin(2)),
                Some(coin(3)),
                Some(coin(4)),
            ],
        );
        assert!(matches!(entry.outputs, Outputs::Inline { .. }));
        assert_eq!(entry.unspent_count(), 4);
    }

    #[test]
    fn five_outputs_spills_to_heap() {
        let entry = TxEntry::new(
            BlockHeight::new(1),
            false,
            vec![
                Some(coin(1)),
                Some(coin(2)),
                Some(coin(3)),
                Some(coin(4)),
                Some(coin(5)),
            ],
        );
        assert!(matches!(entry.outputs, Outputs::Heap(_)));
        assert!(matches!(entry.live, Bitmap::Inline(_)));
        assert_eq!(entry.unspent_count(), 5);
    }

    #[test]
    fn spend_marks_bit_and_returns_coin() {
        let mut entry = TxEntry::new(
            BlockHeight::new(100),
            false,
            vec![Some(coin(1000)), Some(coin(2000))],
        );
        let spent = entry.spend(0);
        assert_eq!(spent.unwrap().value, Satoshi::new(1000));
        assert!(!entry.is_unspent(0));
        assert!(entry.is_unspent(1));
        assert_eq!(entry.unspent_count(), 1);
    }

    #[test]
    fn spend_already_spent_returns_none() {
        let mut entry =
            TxEntry::new(BlockHeight::new(100), false, vec![Some(coin(1000))]);
        entry.spend(0);
        assert!(entry.spend(0).is_none());
    }

    #[test]
    fn fully_spent_after_all_outputs_consumed() {
        let mut entry = TxEntry::new(
            BlockHeight::new(100),
            false,
            vec![Some(coin(1000)), Some(coin(2000))],
        );
        entry.spend(0);
        entry.spend(1);
        assert!(entry.is_fully_spent());
        assert_eq!(entry.unspent_count(), 0);
    }

    #[test]
    fn unspend_restores_coin() {
        let mut entry =
            TxEntry::new(BlockHeight::new(100), false, vec![Some(coin(1000))]);
        let spent = entry.spend(0).unwrap();
        assert!(entry.is_fully_spent());

        entry.unspend(0, spent);
        assert!(entry.is_unspent(0));
        assert_eq!(entry.get(0).unwrap().value, Satoshi::new(1000));
    }

    #[test]
    fn get_returns_none_for_spent() {
        let mut entry = TxEntry::new(
            BlockHeight::new(100),
            false,
            vec![Some(coin(1000)), Some(coin(2000))],
        );
        entry.spend(0);
        assert!(entry.get(0).is_none());
        assert!(entry.get(1).is_some());
    }

    #[test]
    fn coinbase_entry() {
        let entry = TxEntry::new(
            BlockHeight::new(50),
            true,
            vec![Some(coin(5_000_000_000))],
        );
        assert!(entry.coinbase);
        assert_eq!(entry.height, BlockHeight::new(50));
    }

    #[test]
    fn sparse_outputs_with_none_slots() {
        let entry = TxEntry::new(
            BlockHeight::new(100),
            false,
            vec![Some(coin(1000)), None, Some(coin(3000))],
        );
        assert!(entry.is_unspent(0));
        assert!(!entry.is_unspent(1));
        assert!(entry.is_unspent(2));
        assert_eq!(entry.unspent_count(), 2);
    }

    #[test]
    fn high_vout_beyond_64() {
        let mut outputs = vec![None; 200];
        outputs[199] = Some(coin(500));
        let entry = TxEntry::new(BlockHeight::new(1), false, outputs);
        assert!(entry.is_unspent(199));
        assert!(!entry.is_unspent(198));
        assert_eq!(entry.unspent_count(), 1);
        assert!(matches!(entry.live, Bitmap::Heap(_)));
    }

    #[test]
    fn high_vout_beyond_256() {
        let mut outputs = vec![None; 300];
        outputs[260] = Some(coin(500));
        let entry = TxEntry::new(BlockHeight::new(1), false, outputs);
        assert!(entry.is_unspent(260));
        assert_eq!(entry.unspent_count(), 1);
        assert_eq!(entry.get(260).unwrap().value, Satoshi::new(500));
    }

    #[test]
    fn many_outputs_spend_and_unspend() {
        let outputs: Vec<_> = (0..500).map(|i| Some(coin(i + 1))).collect();
        let mut entry = TxEntry::new(BlockHeight::new(1), false, outputs);
        assert_eq!(entry.unspent_count(), 500);

        let c = entry.spend(499).unwrap();
        assert_eq!(c.value, Satoshi::new(500));
        assert!(!entry.is_unspent(499));
        assert_eq!(entry.unspent_count(), 499);

        entry.unspend(499, c);
        assert!(entry.is_unspent(499));
        assert_eq!(entry.unspent_count(), 500);
    }

    #[test]
    fn output_count_inline_and_heap() {
        // Inline (<=4 outputs)
        let entry = TxEntry::new(
            BlockHeight::new(1),
            false,
            vec![Some(coin(1)), Some(coin(2)), Some(coin(3))],
        );
        assert_eq!(entry.output_count(), 3);

        // Heap (>4 outputs)
        let entry = TxEntry::new(
            BlockHeight::new(1),
            false,
            vec![
                Some(coin(1)),
                Some(coin(2)),
                Some(coin(3)),
                Some(coin(4)),
                Some(coin(5)),
            ],
        );
        assert_eq!(entry.output_count(), 5);
    }

    #[test]
    fn unspend_promotes_inline_to_heap() {
        let mut entry =
            TxEntry::new(BlockHeight::new(1), false, vec![Some(coin(100))]);
        assert!(matches!(entry.outputs, Outputs::Inline { .. }));

        entry.unspend(10, coin(200));
        assert!(matches!(entry.outputs, Outputs::Heap(_)));
        assert!(entry.is_unspent(10));
        assert!(entry.is_unspent(0));
        assert_eq!(entry.get(10).unwrap().value, Satoshi::new(200));
    }
}
