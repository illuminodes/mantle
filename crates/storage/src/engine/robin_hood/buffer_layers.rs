use std::sync::Arc;

use mantle::primitives::OutPoint;
use mantle_consensus::chain_view::Coin;

use super::write_buffer::{BufferEntry, FrozenBuffer, WriteBuffer};

/// What the buffers say about one coin.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Layered {
    Live(Coin),
    Spent,
    /// Neither buffer knows it; the table must answer.
    Below,
}

/// The coins not yet in the table: the active write buffer on top of the
/// buffer a background flush is writing.
pub(super) struct BufferLayers {
    active: WriteBuffer,
    frozen: Option<Arc<FrozenBuffer>>,
}

impl BufferLayers {
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            active: WriteBuffer::with_capacity(capacity),
            frozen: None,
        }
    }

    pub(super) fn get(&self, op: &OutPoint) -> Layered {
        match self
            .active
            .get(op)
            .or_else(|| self.frozen.as_ref().and_then(|frozen| frozen.get(op)))
        {
            Some(BufferEntry::Live(coin)) => Layered::Live(coin.clone()),
            Some(BufferEntry::Spent) => Layered::Spent,
            None => Layered::Below,
        }
    }

    pub(super) fn create(&mut self, op: OutPoint, coin: Coin) {
        self.active.create(op, coin);
    }

    pub(super) fn spend(&mut self, op: OutPoint) {
        self.active.spend(op);
    }

    /// Move the active buffer under the lookups as the flushing layer.
    pub(super) fn freeze(&mut self) -> Arc<FrozenBuffer> {
        assert!(self.frozen.is_none(), "a flush is already running");
        let frozen = Arc::new(self.active.freeze());
        self.frozen = Some(Arc::clone(&frozen));
        frozen
    }

    /// Take the active buffer for a flush that ends before the next lookup.
    pub(super) fn take(&mut self) -> FrozenBuffer {
        self.active.freeze()
    }

    /// The flushing layer is in the table.
    pub(super) fn release_frozen(&mut self) {
        self.frozen = None;
    }
}

#[cfg(test)]
mod tests {
    use mantle::primitives::{BlockHeight, Hash256, OutPoint, Satoshi, ScriptPubKey};
    use mantle_consensus::chain_view::Coin;

    use super::{BufferLayers, Layered};

    fn op(i: u32) -> OutPoint {
        OutPoint {
            txid: Hash256::hash(&i.to_le_bytes()),
            vout: 0,
        }
    }

    fn coin(i: u32) -> Coin {
        Coin {
            value: Satoshi::new(u64::from(i)),
            script_pubkey: ScriptPubKey::from_slice(&[0x51]),
            height: BlockHeight::new(i),
            coinbase: false,
        }
    }

    #[test]
    fn the_active_layer_shadows_the_frozen_one() {
        let mut layers = BufferLayers::with_capacity(4);
        layers.create(op(1), coin(1));
        layers.create(op(2), coin(2));
        let _frozen = layers.freeze();
        layers.spend(op(1));
        layers.create(op(3), coin(3));
        assert_eq!(layers.get(&op(1)), Layered::Spent);
        assert_eq!(layers.get(&op(2)), Layered::Live(coin(2)));
        assert_eq!(layers.get(&op(3)), Layered::Live(coin(3)));
        assert_eq!(layers.get(&op(4)), Layered::Below);
    }

    #[test]
    fn a_spend_in_the_frozen_layer_hides_the_table() {
        let mut layers = BufferLayers::with_capacity(4);
        layers.spend(op(5));
        let _frozen = layers.freeze();
        assert_eq!(layers.get(&op(5)), Layered::Spent);
        layers.release_frozen();
        assert_eq!(layers.get(&op(5)), Layered::Below);
    }
}
