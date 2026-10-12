//! Script execution cache and signature cache (M5).
//!
//! Two independent caches reduce redundant cryptographic work during IBD and
//! steady-state block validation:
//!
//! - [`SignatureCache`]: remembers whether `(sig, pubkey, sighash)` verified.
//!   Keyed on a 32-byte `SHA256d` digest so the map key is constant-size and
//!   cryptographically uniform — appropriate for [`PrehashedMap`].
//!
//! - [`ScriptExecutionCache`]: remembers which transaction inputs already
//!   verified, keyed on `(wtxid, input index, spent output, flags)`.
//!   Populated by [`ScriptVerifier::verify_cached`] after a successful
//!   cold-path verification. A hit short-circuits the entire interpreter.
//!   Only successes are stored, so a rejection always reports its real error.
//!
//! [`ScriptVerifier::verify_cached`]: super::ScriptVerifier::verify_cached
//!
//! ## Key construction
//!
//! Both caches use `SHA256d` of their inputs as the map key (`[u8; 32]`).
//! `SHA256d` gives 256 bits of preimage resistance — necessary because a fast
//! hash (`SipHash`, `FxHash`) would let a motivated attacker craft scripts that
//! produce false hits. The key bytes are already uniformly distributed, so
//! [`PrehashedMap`] (which takes the first 8 bytes of the key directly as the
//! bucket index) avoids double-hashing.
//!
//! ## Eviction
//!
//! Each cache is a bounded insertion-order eviction structure: a
//! [`PrehashedMap`] for O(1) lookup plus a `VecDeque<[u8;32]>` that records
//! insertion order. When the map is full, the oldest key (front of the deque)
//! is evicted before the new entry is inserted.

use std::collections::VecDeque;

use mantle::collections::{BuildPrehashedHasher, PrehashedMap};
use mantle::hash::Hash256;

// ── SignatureCache ─────────────────────────────────────────────────────────────

/// Remembers whether a `(sig, pubkey, sighash)` triple verified.
///
/// The key is `SHA256d(sighash || sig || pubkey)`. The value is the verdict.
pub struct SignatureCache {
    map: PrehashedMap<[u8; 32], bool>,
    order: VecDeque<[u8; 32]>,
    capacity: usize,
    hits: u64,
    misses: u64,
}

/// Default capacity: ~32 K entries (~1 MB assuming ~33 bytes average overhead).
pub const DEFAULT_SIG_CACHE_ENTRIES: usize = 32_768;

impl SignatureCache {
    /// Create a cache with the given entry capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let init = capacity.min(4096);
        Self {
            map: PrehashedMap::with_capacity_and_hasher(init, BuildPrehashedHasher),
            order: VecDeque::with_capacity(init),
            capacity,
            hits: 0,
            misses: 0,
        }
    }

    /// Create a cache with the default capacity.
    #[must_use]
    pub fn default_sized() -> Self {
        Self::new(DEFAULT_SIG_CACHE_ENTRIES)
    }

    /// Build the 32-byte cache key for a signature check.
    ///
    /// `sighash` — the 32-byte digest the signature commits to.
    /// `sig`     — raw signature bytes (DER or Schnorr).
    /// `pubkey`  — public key bytes.
    #[must_use]
    pub fn key(sighash: &[u8; 32], sig: &[u8], pubkey: &[u8]) -> [u8; 32] {
        let mut preimage = Vec::with_capacity(32 + sig.len() + pubkey.len());
        preimage.extend_from_slice(sighash);
        preimage.extend_from_slice(sig);
        preimage.extend_from_slice(pubkey);
        *Hash256::hash(&preimage).as_bytes()
    }

    /// Look up a previous verdict. Returns `Some(verdict)` on hit, `None` on miss.
    pub fn get(&mut self, key: &[u8; 32]) -> Option<bool> {
        if let Some(&v) = self.map.get(key) {
            self.hits += 1;
            Some(v)
        } else {
            self.misses += 1;
            None
        }
    }

    /// Store a verdict. Evicts the oldest entry if at capacity.
    pub fn insert(&mut self, key: [u8; 32], verdict: bool) {
        if self.map.contains_key(&key) {
            return;
        }
        if self.map.len() >= self.capacity
            && let Some(oldest) = self.order.pop_front()
        {
            self.map.remove(&oldest);
        }
        self.map.insert(key, verdict);
        self.order.push_back(key);
    }

    /// Cumulative hit count since creation.
    #[must_use]
    pub fn hits(&self) -> u64 {
        self.hits
    }

    /// Cumulative miss count since creation.
    #[must_use]
    pub fn misses(&self) -> u64 {
        self.misses
    }

    /// Current number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

// ── ScriptExecutionCache ───────────────────────────────────────────────────────

/// Remembers which transaction inputs have already passed script verification.
///
/// The key is `SHA256d(wtxid || n_in || amount || len(spk) || spk || flags)`.
/// The wtxid commits to every scriptSig, witness and the whole transaction
/// body that legacy, BIP143 and BIP341 sighashes sign over; the index selects
/// the input; the spent output and flags cover the remaining verdict inputs.
pub struct ScriptExecutionCache {
    map: PrehashedMap<[u8; 32], bool>,
    order: VecDeque<[u8; 32]>,
    capacity: usize,
    hits: u64,
    misses: u64,
}

/// Default capacity: ~16 K entries.
pub const DEFAULT_EXEC_CACHE_ENTRIES: usize = 16_384;

impl ScriptExecutionCache {
    /// Create a cache with the given entry capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let init = capacity.min(4096);
        Self {
            map: PrehashedMap::with_capacity_and_hasher(init, BuildPrehashedHasher),
            order: VecDeque::with_capacity(init),
            capacity,
            hits: 0,
            misses: 0,
        }
    }

    /// Create a cache with the default capacity.
    #[must_use]
    pub fn default_sized() -> Self {
        Self::new(DEFAULT_EXEC_CACHE_ENTRIES)
    }

    /// Build the 32-byte cache key for input `n_in` of the transaction with
    /// the given `wtxid`.
    #[must_use]
    pub fn key(
        wtxid: &Hash256,
        n_in: usize,
        script_pubkey: &[u8],
        amount_sats: u64,
        flags_bits: u32,
    ) -> [u8; 32] {
        let mut preimage = Vec::with_capacity(32 + 8 + 8 + 8 + script_pubkey.len() + 4);
        preimage.extend_from_slice(wtxid.as_bytes());
        preimage.extend_from_slice(&(n_in as u64).to_le_bytes());
        preimage.extend_from_slice(&amount_sats.to_le_bytes());
        preimage.extend_from_slice(&(script_pubkey.len() as u64).to_le_bytes());
        preimage.extend_from_slice(script_pubkey);
        preimage.extend_from_slice(&flags_bits.to_le_bytes());
        *Hash256::hash(&preimage).as_bytes()
    }

    /// Look up a previous verdict. Returns `Some(true/false)` on hit.
    pub fn get(&mut self, key: &[u8; 32]) -> Option<bool> {
        if let Some(&v) = self.map.get(key) {
            self.hits += 1;
            Some(v)
        } else {
            self.misses += 1;
            None
        }
    }

    /// Store a verdict. Evicts the oldest entry if at capacity.
    pub fn insert(&mut self, key: [u8; 32], verdict: bool) {
        if self.map.contains_key(&key) {
            return;
        }
        if self.map.len() >= self.capacity
            && let Some(oldest) = self.order.pop_front()
        {
            self.map.remove(&oldest);
        }
        self.map.insert(key, verdict);
        self.order.push_back(key);
    }

    /// Cumulative hit count since creation.
    #[must_use]
    pub fn hits(&self) -> u64 {
        self.hits
    }

    /// Cumulative miss count since creation.
    #[must_use]
    pub fn misses(&self) -> u64 {
        self.misses
    }

    /// Current number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SignatureCache ────────────────────────────────────────────────────────

    #[test]
    fn sig_cache_miss_then_hit() {
        let mut cache = SignatureCache::new(16);
        let key = SignatureCache::key(&[0u8; 32], &[1, 2, 3], &[4, 5, 6]);
        assert_eq!(cache.get(&key), None);
        assert_eq!(cache.misses(), 1);
        cache.insert(key, true);
        assert_eq!(cache.get(&key), Some(true));
        assert_eq!(cache.hits(), 1);
    }

    #[test]
    fn sig_cache_evicts_oldest_at_capacity() {
        let mut cache = SignatureCache::new(2);
        let k1 = SignatureCache::key(&[1u8; 32], &[], &[]);
        let k2 = SignatureCache::key(&[2u8; 32], &[], &[]);
        let k3 = SignatureCache::key(&[3u8; 32], &[], &[]);
        cache.insert(k1, true);
        cache.insert(k2, false);
        cache.insert(k3, true); // evicts k1
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.map.get(&k1), None);
        assert_eq!(cache.map.get(&k2), Some(&false));
        assert_eq!(cache.map.get(&k3), Some(&true));
    }

    #[test]
    fn sig_cache_duplicate_insert_is_noop() {
        let mut cache = SignatureCache::new(8);
        let key = SignatureCache::key(&[9u8; 32], &[0], &[0]);
        cache.insert(key, true);
        cache.insert(key, false); // must not overwrite
        assert_eq!(cache.map.get(&key), Some(&true));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn sig_cache_different_inputs_different_keys() {
        let k1 = SignatureCache::key(&[0u8; 32], &[1], &[2]);
        let k2 = SignatureCache::key(&[0u8; 32], &[1], &[3]);
        assert_ne!(k1, k2);
    }

    // ── ScriptExecutionCache ──────────────────────────────────────────────────

    fn wtxid(b: u8) -> Hash256 {
        Hash256::from_bytes([b; 32])
    }

    #[test]
    fn exec_cache_miss_then_hit() {
        let mut cache = ScriptExecutionCache::new(16);
        let key = ScriptExecutionCache::key(&wtxid(1), 0, &[0xac], 1000, 0);
        assert_eq!(cache.get(&key), None);
        cache.insert(key, true);
        assert_eq!(cache.get(&key), Some(true));
        assert_eq!(cache.hits(), 1);
        assert_eq!(cache.misses(), 1);
    }

    #[test]
    fn exec_cache_evicts_at_capacity() {
        let mut cache = ScriptExecutionCache::new(2);
        let k1 = ScriptExecutionCache::key(&wtxid(1), 0, &[1], 100, 0);
        let k2 = ScriptExecutionCache::key(&wtxid(2), 0, &[2], 100, 0);
        let k3 = ScriptExecutionCache::key(&wtxid(3), 0, &[3], 100, 0);
        cache.insert(k1, true);
        cache.insert(k2, true);
        cache.insert(k3, true); // evicts k1
        assert_eq!(cache.len(), 2);
        assert!(!cache.map.contains_key(&k1));
    }

    #[test]
    fn exec_cache_flags_affect_key() {
        let k1 = ScriptExecutionCache::key(&wtxid(0), 0, &[], 0, 0b0001);
        let k2 = ScriptExecutionCache::key(&wtxid(0), 0, &[], 0, 0b0010);
        assert_ne!(k1, k2);
    }

    #[test]
    fn exec_cache_amount_affects_key() {
        let k1 = ScriptExecutionCache::key(&wtxid(0), 0, &[], 1000, 0);
        let k2 = ScriptExecutionCache::key(&wtxid(0), 0, &[], 2000, 0);
        assert_ne!(k1, k2);
    }

    #[test]
    fn exec_cache_wtxid_affects_key() {
        let k1 = ScriptExecutionCache::key(&wtxid(1), 0, &[0x51], 0, 0);
        let k2 = ScriptExecutionCache::key(&wtxid(2), 0, &[0x51], 0, 0);
        assert_ne!(k1, k2);
    }

    #[test]
    fn exec_cache_input_index_affects_key() {
        let k1 = ScriptExecutionCache::key(&wtxid(1), 0, &[0x51], 0, 0);
        let k2 = ScriptExecutionCache::key(&wtxid(1), 1, &[0x51], 0, 0);
        assert_ne!(k1, k2);
    }

    #[test]
    fn exec_cache_spk_length_is_unambiguous() {
        let k1 = ScriptExecutionCache::key(&wtxid(1), 0, &[0x00, 0x00], 0, 0);
        let k2 = ScriptExecutionCache::key(&wtxid(1), 0, &[0x00], 0, 0);
        assert_ne!(k1, k2);
    }
}
