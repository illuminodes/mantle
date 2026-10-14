use std::collections::BTreeMap;
use std::path::Path;

use mantle::primitives::{BlockHeight, Hash256};

/// Expected UTXO set `MuHash` values by height, as reported by
/// `bitcoin-cli gettxoutsetinfo muhash <height>` on a node with
/// `-coinstatsindex`.
///
/// File format: one `<height> <muhash>` pair per line, separated by
/// whitespace. Blank lines and lines starting with `#` are ignored.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UtxoHashReference {
    expected: BTreeMap<u32, Hash256>,
}

impl UtxoHashReference {
    /// # Errors
    /// Returns a message naming the file and line on a read or parse error.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// # Errors
    /// Returns a message naming the line on a parse error.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut expected = BTreeMap::new();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let lineno = index + 1;
            let mut fields = line.split_whitespace();
            let (Some(height), Some(hash), None) = (fields.next(), fields.next(), fields.next())
            else {
                return Err(format!("line {lineno}: expected `<height> <muhash>`"));
            };
            let height: u32 = height
                .parse()
                .map_err(|e| format!("line {lineno}: bad height {height}: {e}"))?;
            let hash = Hash256::from_display_hex(hash)
                .map_err(|e| format!("line {lineno}: bad muhash {hash}: {e}"))?;
            if expected.insert(height, hash).is_some() {
                return Err(format!("line {lineno}: height {height} listed twice"));
            }
        }
        Ok(Self { expected })
    }

    #[must_use]
    pub fn expected_at(&self, height: BlockHeight) -> Option<Hash256> {
        self.expected.get(&height.to_u32()).copied()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.expected.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.expected.is_empty()
    }
}

/// Result of checking the tracked hash after one block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtxoHashVerdict {
    NotChecked,
    Match(Hash256),
    Mismatch { expected: Hash256, actual: Hash256 },
}

/// Checks the UTXO set hash of a replay against a reference.
///
/// The hash itself is kept by the pipeline and updated as blocks reach
/// storage; the tracker only decides at which heights to finalize it, and
/// compares and prints the result.
pub struct UtxoHashTracker {
    reference: UtxoHashReference,
    print_every: Option<u32>,
    mismatches: u64,
    checked: u64,
    stopped_at: Option<BlockHeight>,
}

impl UtxoHashTracker {
    #[must_use]
    pub fn new(reference: UtxoHashReference, print_every: Option<u32>) -> Self {
        Self {
            reference,
            print_every,
            mismatches: 0,
            checked: 0,
            stopped_at: None,
        }
    }

    /// Stop tracking: a block was committed without its prior coins, so the
    /// hash can no longer follow the UTXO set.
    pub fn stop(&mut self, height: BlockHeight) {
        if self.stopped_at.is_none() {
            self.stopped_at = Some(height);
        }
    }

    /// `true` when the hash after `height` should be finalized.
    #[must_use]
    pub fn wants(&self, height: BlockHeight) -> bool {
        self.stopped_at.is_none()
            && (self
                .print_every
                .is_some_and(|n| height.to_u32().is_multiple_of(n))
                || self.reference.expected_at(height).is_some())
    }

    /// Call after `height` was committed, with the finalized hash when
    /// [`wants`](Self::wants) asked for it.
    pub fn after_block(&mut self, height: BlockHeight, actual: Option<Hash256>) -> UtxoHashVerdict {
        if !self.wants(height) {
            return UtxoHashVerdict::NotChecked;
        }
        let Some(actual) = actual else {
            return UtxoHashVerdict::NotChecked;
        };
        let printing = self
            .print_every
            .is_some_and(|n| height.to_u32().is_multiple_of(n));
        let expected = self.reference.expected_at(height);
        if printing {
            eprintln!("UTXO HASH height={} muhash={actual}", height.to_u32());
        }
        match expected {
            None => UtxoHashVerdict::NotChecked,
            Some(expected) => {
                self.checked += 1;
                if expected == actual {
                    UtxoHashVerdict::Match(actual)
                } else {
                    self.mismatches += 1;
                    UtxoHashVerdict::Mismatch { expected, actual }
                }
            }
        }
    }

    #[must_use]
    pub fn mismatches(&self) -> u64 {
        self.mismatches
    }

    pub fn print_summary(&self) {
        eprintln!(
            "utxo hash: {} of {} reference heights checked, {} mismatch(es)",
            self.checked,
            self.reference.len(),
            self.mismatches
        );
        if let Some(height) = self.stopped_at {
            eprintln!(
                "  tracking stopped at height {}: that block was force-committed after a failure",
                height.to_u32()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{UtxoHashReference, UtxoHashTracker, UtxoHashVerdict};
    use mantle::primitives::{BlockHeight, Hash256};
    use mantle_utxo_hash::UtxoSetHash;

    const EMPTY_SET: &str = "dd5ad2a105c2d29495f577245c357409002329b9f4d6182c0af3dc2f462555c8";

    #[test]
    fn empty_set_hash_is_the_known_constant() {
        assert_eq!(UtxoSetHash::new().finalize().to_display_hex(), EMPTY_SET);
    }

    #[test]
    fn parses_pairs_and_skips_comments() {
        let text = format!("# from bitcoin core\n\n10 {EMPTY_SET}\n  20\t{EMPTY_SET}  \n");
        let reference = UtxoHashReference::parse(&text).expect("parses");
        assert_eq!(reference.len(), 2);
        assert!(reference.expected_at(BlockHeight::new(20)).is_some());
        assert!(reference.expected_at(BlockHeight::new(15)).is_none());
    }

    #[test]
    fn rejects_malformed_lines() {
        assert!(UtxoHashReference::parse("10").is_err());
        assert!(UtxoHashReference::parse(&format!("x {EMPTY_SET}")).is_err());
        assert!(UtxoHashReference::parse("10 nothex").is_err());
        assert!(UtxoHashReference::parse(&format!("10 {EMPTY_SET} extra")).is_err());
        assert!(UtxoHashReference::parse(&format!("10 {EMPTY_SET}\n10 {EMPTY_SET}")).is_err());
    }

    #[test]
    fn reports_matches_and_mismatches() {
        let other = Hash256::from_bytes([7; 32]).to_display_hex();
        let reference =
            UtxoHashReference::parse(&format!("1 {EMPTY_SET}\n2 {other}")).expect("parses");
        let mut tracker = UtxoHashTracker::new(reference, None);
        let empty = Some(UtxoSetHash::new().finalize());
        assert!(matches!(
            tracker.after_block(BlockHeight::new(1), empty),
            UtxoHashVerdict::Match(_)
        ));
        assert!(matches!(
            tracker.after_block(BlockHeight::new(2), empty),
            UtxoHashVerdict::Mismatch { .. }
        ));
        assert!(!tracker.wants(BlockHeight::new(3)));
        assert_eq!(
            tracker.after_block(BlockHeight::new(3), empty),
            UtxoHashVerdict::NotChecked
        );
        assert_eq!(tracker.mismatches(), 1);
    }

    #[test]
    fn stops_checking_after_a_forced_commit() {
        let reference = UtxoHashReference::parse(&format!("5 {EMPTY_SET}")).expect("parses");
        let mut tracker = UtxoHashTracker::new(reference, None);
        tracker.stop(BlockHeight::new(4));
        assert!(!tracker.wants(BlockHeight::new(5)));
        assert_eq!(
            tracker.after_block(BlockHeight::new(5), Some(UtxoSetHash::new().finalize())),
            UtxoHashVerdict::NotChecked
        );
    }
}
