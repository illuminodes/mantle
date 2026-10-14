#![allow(clippy::box_collection)]

use mantle::primitives::{BlockHeight, Hash256, OutPoint};
use mantle_storage::types::LookupResult;

use crate::prefetched_view::CoinMap;
use crate::utxo_overlay::UtxoOverlay;

/// The coins of the next block, looked up in storage while the current block
/// is being connected.
///
/// The storage answer reflects storage when the lookup was served, before
/// the current block, and any later block, reached the overlay. So the
/// overlay is laid over the answer again with [`refresh`](Self::refresh)
/// before every commit, which retires overlay entries, and once more when
/// the coins are used. Each outpoint then holds the newest value any block
/// gave it.
///
/// The storage thread writes the answer through a pointer to the `results`
/// vector itself, not its buffer, and the prefetch moves after the request
/// is sent, so the vector is boxed to keep that address fixed. It also
/// reads `lookups` until the answer is received, so both are leaked rather
/// than freed if the prefetch is dropped before that.
pub(super) struct Prefetch {
    height: BlockHeight,
    hash: Hash256,
    lookups: Vec<OutPoint>,
    results: Box<Vec<LookupResult>>,
    coins: CoinMap,
    awaiting_storage: bool,
}

impl Prefetch {
    pub(super) fn new(
        height: BlockHeight,
        hash: Hash256,
        lookups: Vec<OutPoint>,
        results: Box<Vec<LookupResult>>,
        coins: CoinMap,
    ) -> Self {
        Self {
            height,
            hash,
            lookups,
            results,
            coins,
            awaiting_storage: false,
        }
    }

    pub(super) fn is_for(&self, height: BlockHeight, hash: Hash256) -> bool {
        self.height == height && self.hash == hash
    }

    pub(super) fn has_lookups(&self) -> bool {
        !self.lookups.is_empty()
    }

    /// The buffers the storage request borrows. Call
    /// [`mark_sent`](Self::mark_sent) once the request is sent.
    pub(super) fn request(&mut self) -> (&[OutPoint], &mut Vec<LookupResult>) {
        (&self.lookups, &mut self.results)
    }

    pub(super) fn mark_sent(&mut self) {
        self.awaiting_storage = true;
    }

    pub(super) fn is_awaiting_storage(&self) -> bool {
        self.awaiting_storage
    }

    /// Fold the storage answer, now received, into the coin map.
    pub(super) fn received(&mut self) {
        self.awaiting_storage = false;
        for found in self.results.drain(..) {
            self.coins.insert(found.outpoint, found.coin);
        }
    }

    /// Lay the current overlay over every looked-up coin.
    pub(super) fn refresh(&mut self, overlay: &UtxoOverlay) {
        debug_assert!(!self.awaiting_storage, "refresh before the storage answer arrives");
        for op in &self.lookups {
            if let Some(coin) = overlay.get(op) {
                self.coins.insert(*op, coin.cloned());
            }
        }
    }

    /// The coin map and the buffers, for reuse. Only after the answer is in.
    pub(super) fn into_parts(mut self) -> (CoinMap, Vec<OutPoint>, Box<Vec<LookupResult>>) {
        debug_assert!(!self.awaiting_storage, "taking buffers storage may still write");
        (
            std::mem::take(&mut self.coins),
            std::mem::take(&mut self.lookups),
            std::mem::take(&mut self.results),
        )
    }
}

impl Drop for Prefetch {
    fn drop(&mut self) {
        if self.awaiting_storage {
            std::mem::forget(std::mem::take(&mut self.lookups));
            std::mem::forget(std::mem::take(&mut self.results));
        }
    }
}
