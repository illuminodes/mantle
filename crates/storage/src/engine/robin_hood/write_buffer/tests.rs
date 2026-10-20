use mantle::primitives::{BlockHeight, Hash256, OutPoint, Satoshi, ScriptPubKey};
use mantle_consensus::chain_view::Coin;

use super::{BufferEntry, WriteBuffer};

struct Sample;

impl Sample {
    fn op(i: u32) -> OutPoint {
        OutPoint {
            txid: Hash256::hash(&i.to_le_bytes()),
            vout: i,
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
}

#[test]
fn a_coin_created_and_spent_in_one_buffer_leaves_no_trace() {
    let mut buffer = WriteBuffer::with_capacity(4);
    buffer.create(Sample::op(1), Sample::coin(1));
    buffer.spend(Sample::op(1));
    assert!(buffer.get(&Sample::op(1)).is_none());
    let frozen = buffer.freeze();
    assert_eq!(frozen.inserts().len(), 0);
    assert!(frozen.deletes().is_empty());
}

#[test]
fn spending_a_coin_from_a_lower_layer_leaves_a_marker() {
    let mut buffer = WriteBuffer::with_capacity(4);
    buffer.spend(Sample::op(2));
    assert!(matches!(buffer.get(&Sample::op(2)), Some(BufferEntry::Spent)));
    let frozen = buffer.freeze();
    assert_eq!(frozen.deletes(), vec![Sample::op(2)]);
    assert_eq!(frozen.inserts().len(), 0);
}

#[test]
fn recreating_a_spent_coin_replaces_the_marker() {
    let mut buffer = WriteBuffer::with_capacity(4);
    buffer.spend(Sample::op(3));
    buffer.create(Sample::op(3), Sample::coin(3));
    let frozen = buffer.freeze();
    assert!(frozen.deletes().is_empty());
    let inserts: Vec<_> = frozen.inserts().collect();
    assert_eq!(inserts, vec![(&Sample::op(3), &Sample::coin(3))]);
}

#[test]
fn freezing_empties_the_buffer_and_counts_live_coins_exactly() {
    let mut buffer = WriteBuffer::with_capacity(4);
    for i in 0..10 {
        buffer.create(Sample::op(i), Sample::coin(i));
    }
    buffer.create(Sample::op(4), Sample::coin(40));
    for i in 0..3 {
        buffer.spend(Sample::op(i));
    }
    buffer.spend(Sample::op(100));
    let frozen = buffer.freeze();
    assert!(buffer.get(&Sample::op(5)).is_none());
    let inserts = frozen.inserts();
    assert_eq!(inserts.len(), 7);
    assert_eq!(inserts.count(), 7);
    assert_eq!(frozen.deletes(), vec![Sample::op(100)]);
    assert!(matches!(
        frozen.get(&Sample::op(4)),
        Some(BufferEntry::Live(coin)) if *coin == Sample::coin(40)
    ));
}
