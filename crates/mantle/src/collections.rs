use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};

/// A fast, non-cryptographic hasher for keys that are already uniformly
/// distributed (e.g. `Hash256`, `OutPoint`). Reads 8 bytes starting at a
/// fixed offset and uses them directly as the hash value — no mixing needed
/// because the input bytes are already the output of SHA-256d.
///
/// **Safety**: only use this for types whose byte representation is already
/// cryptographically random. Never use it for user-supplied strings or integers.
#[derive(Clone, Copy, Default)]
pub struct PrehashedHasher {
    state: u64,
}

impl Hasher for PrehashedHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        // Take the first 8 bytes as a little-endian u64. Every type used as a
        // key must write its entropy in a single write() call (not field-by-field
        // via derive) so this overwrite is safe. Hash256 is [u8;32] written as
        // one slice; OutPoint has a custom Hash impl that packs txid+vout into
        // a single [u8;36] write. Pad with zeros if somehow shorter — must not panic.
        let mut buf = [0u8; 8];
        let n = bytes.len().min(8);
        buf[..n].copy_from_slice(&bytes[..n]);
        self.state = u64::from_le_bytes(buf);
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.state
    }
}

/// `BuildHasher` that constructs [`PrehashedHasher`] instances.
#[derive(Clone, Copy, Default)]
pub struct BuildPrehashedHasher;

impl BuildHasher for BuildPrehashedHasher {
    type Hasher = PrehashedHasher;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        PrehashedHasher::default()
    }
}

/// `HashMap` backed by [`PrehashedHasher`]. Only use for keys that are already
/// cryptographically uniform (e.g. `Hash256`, `OutPoint`).
pub type PrehashedMap<K, V> = HashMap<K, V, BuildPrehashedHasher>;

/// `HashSet` backed by [`PrehashedHasher`]. Only use for keys that are already
/// cryptographically uniform (e.g. `Hash256`, `OutPoint`).
pub type PrehashedSet<K> = HashSet<K, BuildPrehashedHasher>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hash256;
    use crate::tx::OutPoint;

    #[test]
    fn hasher_reads_first_8_bytes() {
        let mut h = PrehashedHasher::default();
        h.write(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(h.finish(), 0x0807_0605_0403_0201);
    }

    #[test]
    fn hasher_short_input_pads_with_zeros() {
        let mut h = PrehashedHasher::default();
        h.write(&[0xff, 0xee]);
        assert_eq!(h.finish(), 0x0000_0000_0000_eeff);
    }

    #[test]
    fn hasher_empty_input() {
        let mut h = PrehashedHasher::default();
        h.write(&[]);
        assert_eq!(h.finish(), 0);
    }

    #[test]
    fn hasher_long_input_uses_first_8() {
        let mut h = PrehashedHasher::default();
        h.write(&[0xab; 32]);
        assert_eq!(h.finish(), 0xabab_abab_abab_abab);
    }

    #[test]
    fn prehashed_map_insert_lookup() {
        let mut map: PrehashedMap<Hash256, u32> = PrehashedMap::default();
        let h1 = Hash256::hash(b"key1");
        let h2 = Hash256::hash(b"key2");
        map.insert(h1, 100);
        map.insert(h2, 200);
        assert_eq!(map.get(&h1), Some(&100));
        assert_eq!(map.get(&h2), Some(&200));
        assert_eq!(map.get(&Hash256::ZERO), None);
    }

    #[test]
    fn prehashed_set_insert_contains() {
        let mut set: PrehashedSet<Hash256> = PrehashedSet::default();
        let h = Hash256::hash(b"item");
        assert!(!set.contains(&h));
        set.insert(h);
        assert!(set.contains(&h));
        assert!(!set.contains(&Hash256::ZERO));
    }

    #[test]
    fn prehashed_map_with_outpoint() {
        let mut map: PrehashedMap<OutPoint, String> = PrehashedMap::default();
        let op = OutPoint {
            txid: Hash256::hash(b"tx"),
            vout: 0,
        };
        map.insert(op, "found".into());
        assert_eq!(map.get(&op), Some(&"found".to_string()));
    }

    #[test]
    fn distinct_hashes_produce_distinct_hash_values() {
        let h1 = Hash256::hash(b"a");
        let h2 = Hash256::hash(b"b");
        let mut hasher1 = PrehashedHasher::default();
        let mut hasher2 = PrehashedHasher::default();
        hasher1.write(h1.as_bytes());
        hasher2.write(h2.as_bytes());
        assert_ne!(hasher1.finish(), hasher2.finish());
    }
}
