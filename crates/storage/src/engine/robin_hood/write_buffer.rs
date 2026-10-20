use std::collections::hash_map;

use mantle::collections::{BuildPrehashedHasher, PrehashedMap};
use mantle::primitives::OutPoint;
use mantle_consensus::chain_view::Coin;

pub(super) enum BufferEntry {
    Live(Coin),
    /// Spent here, and present in a layer below: the frozen buffer or the
    /// table.
    Spent,
}

/// Coins created and spent since the last flush began.
pub(super) struct WriteBuffer {
    entries: PrehashedMap<OutPoint, BufferEntry>,
    live: usize,
    capacity: usize,
}

impl WriteBuffer {
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: PrehashedMap::with_capacity_and_hasher(capacity, BuildPrehashedHasher),
            live: 0,
            capacity,
        }
    }

    pub(super) fn create(&mut self, op: OutPoint, coin: Coin) {
        if !matches!(self.entries.insert(op, BufferEntry::Live(coin)), Some(BufferEntry::Live(_))) {
            self.live += 1;
        }
    }

    /// A coin created in this buffer is dropped outright; any other coin
    /// gets a spent marker, deleted from the layers below at the next flush.
    pub(super) fn spend(&mut self, op: OutPoint) {
        match self.entries.entry(op) {
            hash_map::Entry::Occupied(entry) => {
                if matches!(entry.get(), BufferEntry::Live(_)) {
                    entry.remove();
                    self.live -= 1;
                }
            }
            hash_map::Entry::Vacant(entry) => {
                entry.insert(BufferEntry::Spent);
            }
        }
    }

    pub(super) fn get(&self, op: &OutPoint) -> Option<&BufferEntry> {
        self.entries.get(op)
    }

    /// Hand the contents over as a read-only snapshot and start empty.
    pub(super) fn freeze(&mut self) -> FrozenBuffer {
        let entries = std::mem::replace(
            &mut self.entries,
            PrehashedMap::with_capacity_and_hasher(self.capacity, BuildPrehashedHasher),
        );
        FrozenBuffer {
            entries,
            live: std::mem::take(&mut self.live),
        }
    }
}

/// A write buffer being flushed: still answering lookups on the storage
/// thread while the flush thread writes it into the table.
pub(super) struct FrozenBuffer {
    entries: PrehashedMap<OutPoint, BufferEntry>,
    live: usize,
}

impl FrozenBuffer {
    pub(super) fn get(&self, op: &OutPoint) -> Option<&BufferEntry> {
        self.entries.get(op)
    }

    pub(super) fn deletes(&self) -> Vec<OutPoint> {
        self.entries
            .iter()
            .filter(|(_, entry)| matches!(entry, BufferEntry::Spent))
            .map(|(op, _)| *op)
            .collect()
    }

    pub(super) fn inserts(&self) -> LiveCoins<'_> {
        LiveCoins {
            entries: self.entries.iter(),
            remaining: self.live,
        }
    }
}

pub(super) struct LiveCoins<'f> {
    entries: hash_map::Iter<'f, OutPoint, BufferEntry>,
    remaining: usize,
}

impl<'f> Iterator for LiveCoins<'f> {
    type Item = (&'f OutPoint, &'f Coin);

    fn next(&mut self) -> Option<Self::Item> {
        for (op, entry) in self.entries.by_ref() {
            if let BufferEntry::Live(coin) = entry {
                self.remaining -= 1;
                return Some((op, coin));
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for LiveCoins<'_> {}

#[cfg(test)]
mod tests;
