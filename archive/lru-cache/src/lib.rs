use std::collections::HashMap;

/// Fixed-capacity LRU cache keyed by `[u8; 32]`.
///
/// Backed by a `HashMap` for O(1) lookup and an intrusive doubly-linked
/// list (stored in a `Vec`) for O(1) eviction. No per-operation heap
/// allocations after construction.
pub struct LruCache<V: Copy> {
    map: HashMap<[u8; 32], usize, BuildKeyHasher>,
    entries: Vec<Entry<V>>,
    head: usize,
    tail: usize,
    cap: usize,
    len: usize,
    free: usize,
}

struct Entry<V: Copy> {
    key: [u8; 32],
    value: V,
    prev: usize,
    next: usize,
    occupied: bool,
}

const NONE: usize = usize::MAX;

impl<V: Copy> LruCache<V> {
    /// Create a cache that holds at most `capacity` entries.
    ///
    /// # Panics
    /// Panics if capacity is 0.
    #[must_use]
    pub fn new(capacity: usize, blank: V) -> Self {
        assert!(capacity > 0);
        let entries: Vec<Entry<V>> = (0..capacity)
            .map(|i| Entry {
                key: [0; 32],
                value: blank,
                prev: NONE,
                next: if i + 1 < capacity { i + 1 } else { NONE },
                occupied: false,
            })
            .collect();
        Self {
            map: HashMap::with_capacity_and_hasher(capacity, BuildKeyHasher),
            entries,
            head: NONE,
            tail: NONE,
            cap: capacity,
            len: 0,
            free: 0,
        }
    }

    /// Look up a key. Returns `None` if absent. Promotes to most-recent on hit.
    pub fn get(&mut self, key: &[u8; 32]) -> Option<V> {
        let &idx = self.map.get(key)?;
        self.move_to_head(idx);
        Some(self.entries[idx].value)
    }

    /// Look up without promoting (doesn't change eviction order).
    #[must_use]
    pub fn peek(&self, key: &[u8; 32]) -> Option<V> {
        let &idx = self.map.get(key)?;
        Some(self.entries[idx].value)
    }

    /// Insert or update a key-value pair. Returns the evicted entry if
    /// the cache was full and an eviction occurred.
    pub fn insert(&mut self, key: [u8; 32], value: V) -> Option<([u8; 32], V)> {
        if let Some(&idx) = self.map.get(&key) {
            self.entries[idx].value = value;
            self.move_to_head(idx);
            return None;
        }

        let (idx, evicted) = if self.free == NONE {
            let victim = self.tail;
            debug_assert_ne!(victim, NONE);
            self.detach(victim);
            let evicted_key = self.entries[victim].key;
            let evicted_val = self.entries[victim].value;
            self.map.remove(&evicted_key);
            (victim, Some((evicted_key, evicted_val)))
        } else {
            let idx = self.free;
            self.free = self.entries[idx].next;
            self.len += 1;
            (idx, None)
        };

        self.entries[idx].key = key;
        self.entries[idx].value = value;
        self.entries[idx].occupied = true;
        self.entries[idx].prev = NONE;
        self.entries[idx].next = NONE;
        self.attach_head(idx);
        self.map.insert(key, idx);
        evicted
    }

    /// Remove a key. Returns the value if it was present.
    pub fn remove(&mut self, key: &[u8; 32]) -> Option<V> {
        let idx = self.map.remove(key)?;
        let val = self.entries[idx].value;
        self.detach(idx);
        self.entries[idx].occupied = false;
        self.entries[idx].next = self.free;
        self.free = idx;
        self.len -= 1;
        Some(val)
    }

    /// Number of entries currently in the cache.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Maximum capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.cap
    }

    fn move_to_head(&mut self, idx: usize) {
        if self.head == idx {
            return;
        }
        self.detach(idx);
        self.attach_head(idx);
    }

    fn detach(&mut self, idx: usize) {
        let prev = self.entries[idx].prev;
        let next = self.entries[idx].next;
        if prev != NONE {
            self.entries[prev].next = next;
        } else if self.head == idx {
            self.head = next;
        }
        if next != NONE {
            self.entries[next].prev = prev;
        } else if self.tail == idx {
            self.tail = prev;
        }
        self.entries[idx].prev = NONE;
        self.entries[idx].next = NONE;
    }

    fn attach_head(&mut self, idx: usize) {
        self.entries[idx].prev = NONE;
        self.entries[idx].next = self.head;
        if self.head != NONE {
            self.entries[self.head].prev = idx;
        }
        self.head = idx;
        if self.tail == NONE {
            self.tail = idx;
        }
    }
}

// ── Hasher for [u8; 32] keys ────────────────────────────────────────────────

/// Same prehashed approach as mantle's `PrehashedHasher` — first 8 bytes
/// of the key are already uniformly distributed (`SHA256d` output).
#[derive(Clone)]
struct KeyHasher(u64);

impl std::hash::Hasher for KeyHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut buf = [0u8; 8];
        let n = bytes.len().min(8);
        buf[..n].copy_from_slice(&bytes[..n]);
        self.0 = u64::from_le_bytes(buf);
    }
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

#[derive(Clone)]
struct BuildKeyHasher;

impl std::hash::BuildHasher for BuildKeyHasher {
    type Hasher = KeyHasher;
    fn build_hasher(&self) -> KeyHasher {
        KeyHasher(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = n;
        k[1] = n.wrapping_mul(37);
        k[2] = n.wrapping_mul(73);
        k
    }

    #[test]
    fn insert_and_get() {
        let mut c = LruCache::new(3, 0);
        c.insert(key(1), 100u64);
        c.insert(key(2), 200);
        assert_eq!(c.get(&key(1)), Some(100));
        assert_eq!(c.get(&key(2)), Some(200));
        assert_eq!(c.get(&key(3)), None);
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn eviction() {
        let mut c = LruCache::new(2, 0);
        c.insert(key(1), 10u32);
        c.insert(key(2), 20);
        let evicted = c.insert(key(3), 30);
        assert_eq!(evicted, Some((key(1), 10)));
        assert_eq!(c.get(&key(1)), None);
        assert_eq!(c.get(&key(2)), Some(20));
        assert_eq!(c.get(&key(3)), Some(30));
    }

    #[test]
    fn access_prevents_eviction() {
        let mut c = LruCache::new(2, 0);
        c.insert(key(1), 10u32);
        c.insert(key(2), 20);
        c.get(&key(1)); // promote key(1) — key(2) becomes LRU
        let evicted = c.insert(key(3), 30);
        assert_eq!(evicted, Some((key(2), 20)));
        assert_eq!(c.get(&key(1)), Some(10));
        assert_eq!(c.get(&key(3)), Some(30));
    }

    #[test]
    fn update_existing() {
        let mut c = LruCache::new(2, 0);
        c.insert(key(1), 10u32);
        c.insert(key(1), 99);
        assert_eq!(c.get(&key(1)), Some(99));
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn remove() {
        let mut c = LruCache::new(3, 0);
        c.insert(key(1), 10u32);
        c.insert(key(2), 20);
        assert_eq!(c.remove(&key(1)), Some(10));
        assert_eq!(c.len(), 1);
        assert_eq!(c.get(&key(1)), None);
        assert_eq!(c.get(&key(2)), Some(20));
    }

    #[test]
    fn remove_then_reuse_slot() {
        let mut c = LruCache::new(2, 0);
        c.insert(key(1), 10u32);
        c.insert(key(2), 20);
        c.remove(&key(1));
        assert_eq!(c.len(), 1);
        let evicted = c.insert(key(3), 30);
        assert_eq!(evicted, None); // should reuse free slot, not evict
        assert_eq!(c.len(), 2);
        assert_eq!(c.get(&key(3)), Some(30));
    }

    #[test]
    fn peek_does_not_promote() {
        let mut c = LruCache::new(2, 0);
        c.insert(key(1), 10u32);
        c.insert(key(2), 20);
        let _ = c.peek(&key(1)); // peek doesn't promote
        let evicted = c.insert(key(3), 30);
        assert_eq!(evicted, Some((key(1), 10))); // key(1) still LRU
    }

    #[test]
    fn capacity() {
        let c: LruCache<u32> = LruCache::new(100, 0);
        assert_eq!(c.capacity(), 100);
        assert!(c.is_empty());
    }

    #[test]
    fn fill_and_churn() {
        let mut c = LruCache::new(100, 0);
        for i in 0..200u64 {
            let mut k = [0u8; 32];
            k[0..8].copy_from_slice(&i.to_le_bytes());
            c.insert(k, i);
        }
        assert_eq!(c.len(), 100);
        // Last 100 should be present.
        for i in 100..200u64 {
            let mut k = [0u8; 32];
            k[0..8].copy_from_slice(&i.to_le_bytes());
            assert_eq!(c.get(&k), Some(i));
        }
        // First 100 should be evicted.
        for i in 0..100u64 {
            let mut k = [0u8; 32];
            k[0..8].copy_from_slice(&i.to_le_bytes());
            assert_eq!(c.get(&k), None);
        }
    }
}
