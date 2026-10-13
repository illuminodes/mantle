use mantle::collections::{BuildPrehashedHasher, PrehashedMap};
use mantle::primitives::{BlockHeader, BlockHeight, BlockTime, Hash256, OutPoint};
use mantle_consensus::chain_view::{ChainView, Coin, TipInfo};
use mantle_consensus::error::ChainViewError;

/// A snapshot of headers used to serve `get_header*` and `median_time_past`
/// queries during block validation without hitting storage per-call.
pub struct HeaderSnapshot {
    /// Headers indexed by height (contiguous from some base).
    headers: Vec<(Hash256, BlockHeader)>,
    /// Base height of `headers[0]`.
    base: u32,
    /// hash → absolute height for O(1) reverse lookup.
    by_hash: PrehashedMap<Hash256, u32>,
}

/// Error returned when building a `HeaderSnapshot` would overflow block-height arithmetic.
#[derive(Debug)]
pub struct HeaderSnapshotOverflow;

impl std::fmt::Display for HeaderSnapshotOverflow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("header snapshot exceeds maximum block height (u32::MAX)")
    }
}

impl std::error::Error for HeaderSnapshotOverflow {}

impl HeaderSnapshot {
    /// Build a snapshot from a dense height-ordered list.
    ///
    /// `entries` is `(hash, header)` in ascending height order starting at `base_height`.
    ///
    /// # Errors
    /// Returns `HeaderSnapshotOverflow` if `base_height + entries.len()` would exceed `u32::MAX`.
    ///
    /// # Panics
    /// Cannot panic: the internal index loop is bounded by the same `u32` check above.
    pub fn new(
        base_height: BlockHeight,
        entries: Vec<(Hash256, BlockHeader)>,
    ) -> Result<Self, HeaderSnapshotOverflow> {
        let len = u32::try_from(entries.len()).map_err(|_| HeaderSnapshotOverflow)?;
        base_height
            .to_u32()
            .checked_add(len)
            .ok_or(HeaderSnapshotOverflow)?;
        let mut by_hash = PrehashedMap::with_capacity_and_hasher(entries.len(), BuildPrehashedHasher);
        for (i, (hash, _)) in entries.iter().enumerate() {
            // i < len, and len fits in u32 per the check above.
            let h = base_height.to_u32() + u32::try_from(i).expect("i < len which fits u32");
            by_hash.insert(*hash, h);
        }
        Ok(Self {
            headers: entries,
            base: base_height.to_u32(),
            by_hash,
        })
    }

    #[must_use]
    pub fn get_header(&self, hash: &Hash256) -> Option<BlockHeader> {
        let &h = self.by_hash.get(hash)?;
        let idx = usize::try_from(h.checked_sub(self.base)?).ok()?;
        self.headers.get(idx).map(|(_, hdr)| *hdr)
    }

    #[must_use]
    pub fn get_header_at(&self, height: BlockHeight) -> Option<BlockHeader> {
        let idx = usize::try_from(height.to_u32().checked_sub(self.base)?).ok()?;
        self.headers.get(idx).map(|(_, hdr)| *hdr)
    }

    pub fn height_of(&self, hash: &Hash256) -> Option<BlockHeight> {
        self.by_hash.get(hash).copied().map(BlockHeight::new)
    }

    /// # Panics
    /// Cannot panic: `new` guarantees `headers.len()` fits in `u32`.
    #[must_use]
    pub fn tip(&self) -> TipInfo {
        match self.headers.last() {
            None => TipInfo {
                hash: Hash256::ZERO,
                height: BlockHeight::ZERO,
            },
            Some((hash, _)) => {
                // len was validated to fit u32 in new(); subtraction cannot underflow (len >= 1).
                let last_offset =
                    u32::try_from(self.headers.len()).expect("len fits u32 per new()") - 1;
                TipInfo {
                    hash: *hash,
                    height: BlockHeight::new(self.base + last_offset),
                }
            }
        }
    }

    #[must_use]
    pub fn median_time_past(&self, header: &BlockHeader) -> Option<BlockTime> {
        let parent_height = *self.by_hash.get(&header.prev_block())?;
        let ph_idx = parent_height.checked_sub(self.base)? as usize;
        let start = (ph_idx + 1).saturating_sub(11);
        let mut times: Vec<BlockTime> = self.headers[start..=ph_idx]
            .iter()
            .map(|(_, h)| h.time())
            .collect();
        times.sort_unstable();
        Some(times[times.len() / 2])
    }
}

// ── PrefetchedView ────────────────────────────────────────────────────────────

/// A `ChainView` backed by a prefetched UTXO map and a `HeaderSnapshot`.
///
/// Built once per block: the replay thread sends one `LookupCoinsReq` for all
/// outpoints the block spends, gets back the coins, and wraps them here.
/// `connect_block` then calls `get_coin` which hits only the in-memory map.
pub struct PrefetchedView<'a> {
    coins: &'a PrehashedMap<OutPoint, Option<Coin>>,
    headers: &'a HeaderSnapshot,
    tip: TipInfo,
}

impl<'a> PrefetchedView<'a> {
    /// Build the view from a pre-populated coin map.
    ///
    /// The caller is responsible for sizing and populating the map;
    /// this avoids a redundant allocation + collect on the hot path.
    ///
    /// `tip` should be the storage tip *after* the previous block was committed.
    #[must_use]
    pub fn new(
        coins: &'a PrehashedMap<OutPoint, Option<Coin>>,
        headers: &'a HeaderSnapshot,
        tip: TipInfo,
    ) -> Self {
        Self {
            coins,
            headers,
            tip,
        }
    }
}

impl ChainView for PrefetchedView<'_> {
    fn get_coin(&self, outpoint: &OutPoint) -> Result<Option<&Coin>, ChainViewError> {
        match self.coins.get(outpoint) {
            Some(opt) => Ok(opt.as_ref()),
            None => Err(ChainViewError::NotFound),
        }
    }

    fn get_header(&self, hash: &Hash256) -> Result<Option<BlockHeader>, ChainViewError> {
        Ok(self.headers.get_header(hash))
    }

    fn get_header_at(&self, height: BlockHeight) -> Result<Option<BlockHeader>, ChainViewError> {
        Ok(self.headers.get_header_at(height))
    }

    fn height_of(&self, hash: &Hash256) -> Result<Option<BlockHeight>, ChainViewError> {
        Ok(self.headers.height_of(hash))
    }

    fn median_time_past(&self, header: &BlockHeader) -> Result<BlockTime, ChainViewError> {
        self.headers
            .median_time_past(header)
            .ok_or(ChainViewError::NotFound)
    }

    fn tip(&self) -> TipInfo {
        self.tip.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantle::primitives::{OutPoint, Satoshi, ScriptPubKey};

    #[test]
    fn get_coin_returns_found_and_missing() {
        let op_present = OutPoint {
            txid: Hash256::from_bytes([0xaa; 32]),
            vout: 0,
        };
        let op_none = OutPoint {
            txid: Hash256::from_bytes([0xbb; 32]),
            vout: 0,
        };
        let op_absent = OutPoint {
            txid: Hash256::from_bytes([0xcc; 32]),
            vout: 0,
        };

        let coin = Coin {
            value: Satoshi::new(1000),
            script_pubkey: ScriptPubKey::from(vec![0x76, 0xa9]),
            height: BlockHeight::new(100),
            coinbase: false,
        };

        let mut coins = PrehashedMap::with_hasher(BuildPrehashedHasher);
        coins.insert(op_present, Some(coin.clone()));
        coins.insert(op_none, None);

        let snap = HeaderSnapshot::new(BlockHeight::ZERO, Vec::new())
            .expect("empty snapshot");
        let tip = TipInfo {
            hash: Hash256::ZERO,
            height: BlockHeight::ZERO,
        };
        let view = PrefetchedView::new(&coins, &snap, tip);

        // Present coin returns Ok(Some)
        let result = view.get_coin(&op_present).unwrap();
        assert_eq!(result.unwrap().value, Satoshi::new(1000));

        // Explicitly None coin returns Ok(None)
        let result = view.get_coin(&op_none).unwrap();
        assert!(result.is_none());

        // Absent key returns Err(NotFound)
        let result = view.get_coin(&op_absent);
        assert!(result.is_err());
    }
}
