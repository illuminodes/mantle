#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_precision_loss, clippy::missing_panics_doc)]

/// Bloom filter for fast membership testing of 32-byte keys (txids, block hashes).
///
/// Uses the key bytes directly as hash values — no hashing needed since
/// Bitcoin txids are already `SHA256d` output (uniformly distributed).
/// Four independent hash probes from the four 8-byte quadrants of the key.
pub struct BloomFilter {
    bits: Vec<u64>,
    mask: u64,
    len: usize,
}

impl BloomFilter {
    /// Create a bloom filter sized for `expected_items` with the given
    /// target false-positive rate (0.0 to 1.0).
    ///
    /// # Panics
    /// Panics if `fp_rate` is not in (0, 1) or `expected_items` is 0.
    #[must_use]
    pub fn with_fp_rate(expected_items: usize, fp_rate: f64) -> Self {
        assert!(expected_items > 0);
        assert!(fp_rate > 0.0 && fp_rate < 1.0);

        // m = -n * ln(p) / (ln(2)^2), using k=4 fixed hash functions:
        // Adjusted: m = -n * k / ln(1 - p^(1/k))
        let k = 4.0_f64;
        let p_root = fp_rate.powf(1.0 / k);
        #[allow(clippy::cast_precision_loss)]
        let m_bits = (-(expected_items as f64) * k / (1.0 - p_root).ln()).ceil() as usize;

        // Round up to power of two for fast modular indexing.
        let m_bits = m_bits.next_power_of_two().max(64);
        let words = m_bits / 64;

        Self {
            bits: vec![0u64; words],
            mask: (m_bits as u64) - 1,
            len: 0,
        }
    }

    /// Create a bloom filter with a specific bit count (must be power of two).
    #[must_use]
    pub fn with_bit_count(bit_count: usize) -> Self {
        assert!(bit_count >= 64 && bit_count.is_power_of_two());
        Self {
            bits: vec![0u64; bit_count / 64],
            mask: (bit_count as u64) - 1,
            len: 0,
        }
    }

    /// Insert a 32-byte key into the filter.
    pub fn insert(&mut self, key: &[u8; 32]) {
        let (h0, h1, h2, h3) = quadrants(key);
        self.set_bit(h0);
        self.set_bit(h1);
        self.set_bit(h2);
        self.set_bit(h3);
        self.len += 1;
    }

    /// Test if a key might be in the set. Returns `false` if definitely
    /// absent, `true` if possibly present (may be a false positive).
    #[must_use]
    pub fn maybe_contains(&self, key: &[u8; 32]) -> bool {
        let (h0, h1, h2, h3) = quadrants(key);
        self.get_bit(h0) && self.get_bit(h1) && self.get_bit(h2) && self.get_bit(h3)
    }

    /// Number of items inserted.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// True if no items have been inserted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Total bit count.
    #[must_use]
    pub fn bit_count(&self) -> usize {
        self.bits.len() * 64
    }

    /// Approximate memory usage in bytes.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        self.bits.len() * 8
    }

    /// Clear all bits and reset the count.
    pub fn clear(&mut self) {
        self.bits.fill(0);
        self.len = 0;
    }

    #[inline]
    fn set_bit(&mut self, hash: u64) {
        let idx = (hash & self.mask) as usize;
        self.bits[idx / 64] |= 1 << (idx % 64);
    }

    #[inline]
    fn get_bit(&self, hash: u64) -> bool {
        let idx = (hash & self.mask) as usize;
        self.bits[idx / 64] & (1 << (idx % 64)) != 0
    }
}

/// Extract four independent u64 hash values from a 32-byte key by
/// reading the four 8-byte quadrants.
#[inline]
fn quadrants(key: &[u8; 32]) -> (u64, u64, u64, u64) {
    let h0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
    let h1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
    let h2 = u64::from_le_bytes(key[16..24].try_into().unwrap());
    let h3 = u64::from_le_bytes(key[24..32].try_into().unwrap());
    (h0, h1, h2, h3)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(n: u64) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0..8].copy_from_slice(&n.to_le_bytes());
        k[8..16].copy_from_slice(&(n.wrapping_mul(0x517cc1b727220a95)).to_le_bytes());
        k[16..24].copy_from_slice(&(n.wrapping_mul(0x6c62272e07bb0142)).to_le_bytes());
        k[24..32].copy_from_slice(&(n.wrapping_mul(0x8eb44a8768581511)).to_le_bytes());
        k
    }

    #[test]
    fn insert_and_query() {
        let mut bf = BloomFilter::with_fp_rate(1000, 0.01);
        let k1 = make_key(1);
        let k2 = make_key(2);
        let k3 = make_key(3);

        assert!(!bf.maybe_contains(&k1));
        bf.insert(&k1);
        assert!(bf.maybe_contains(&k1));
        assert!(!bf.maybe_contains(&k2));
        bf.insert(&k2);
        assert!(bf.maybe_contains(&k1));
        assert!(bf.maybe_contains(&k2));
        assert!(!bf.maybe_contains(&k3));
    }

    #[test]
    fn false_positive_rate() {
        let n = 100_000;
        let mut bf = BloomFilter::with_fp_rate(n, 0.01);
        for i in 0..n as u64 {
            bf.insert(&make_key(i));
        }
        assert_eq!(bf.len(), n);

        let mut false_positives = 0u64;
        let test_count = 100_000u64;
        for i in n as u64..n as u64 + test_count {
            if bf.maybe_contains(&make_key(i)) {
                false_positives += 1;
            }
        }
        let fp_rate = false_positives as f64 / test_count as f64;
        assert!(
            fp_rate < 0.05,
            "false positive rate {fp_rate:.4} exceeds 5% (target 1%)"
        );
    }

    #[test]
    fn clear_resets() {
        let mut bf = BloomFilter::with_fp_rate(100, 0.01);
        let k = make_key(42);
        bf.insert(&k);
        assert!(bf.maybe_contains(&k));
        assert_eq!(bf.len(), 1);

        bf.clear();
        assert!(!bf.maybe_contains(&k));
        assert_eq!(bf.len(), 0);
    }

    #[test]
    fn heap_size_reasonable() {
        let bf = BloomFilter::with_fp_rate(85_000_000, 0.01);
        let mb = bf.heap_bytes() / (1024 * 1024);
        assert!(mb < 300, "bloom filter for 85M items should be <300 MB, got {mb} MB");
        assert!(mb > 50, "bloom filter for 85M items should be >50 MB, got {mb} MB");
    }

    #[test]
    fn with_bit_count() {
        let bf = BloomFilter::with_bit_count(1024);
        assert_eq!(bf.bit_count(), 1024);
        assert_eq!(bf.heap_bytes(), 128);
    }

    #[test]
    fn empty() {
        let bf = BloomFilter::with_fp_rate(100, 0.01);
        assert!(bf.is_empty());
        assert_eq!(bf.len(), 0);
    }
}
