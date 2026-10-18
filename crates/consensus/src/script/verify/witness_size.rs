//! Serialized size of an input's witness stack.

use mantle::codec::VarInt;

/// Byte length of a witness stack as serialized in a transaction: a
/// compact-size item count, then each item with its compact-size length.
/// BIP342 seeds the validation weight budget from this.
pub struct WitnessSize;

impl WitnessSize {
    /// Serialized length of `items`.
    #[must_use]
    pub fn of(items: &[Vec<u8>]) -> u64 {
        let count = VarInt::from(items.len() as u64).encoded_len() as u64;
        items.iter().fold(count, |total, item| {
            total + VarInt::from(item.len() as u64).encoded_len() as u64 + item.len() as u64
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_the_item_count_lengths_and_bytes() {
        assert_eq!(WitnessSize::of(&[]), 1);
        assert_eq!(WitnessSize::of(&[vec![0; 64]]), 1 + 1 + 64);
        assert_eq!(WitnessSize::of(&[vec![0; 300], vec![]]), 1 + 3 + 300 + 1);
    }
}
