use std::fmt;
use std::io::{Read, Write};

use crate::codec::{Decode, Encode, Error, VarInt};

// ── WitnessBuf ────────────────────────────────────────────────────────────────

/// Inline-optimised witness stack for a single transaction input (BIP141).
///
/// Stores up to `ITEMS` stack items whose total byte size fits within `BYTES`
/// inline (on the stack, via a boxed array to control enum size); falls back
/// to `Vec<Vec<u8>>` otherwise.
///
/// `ends[i]` is the exclusive end offset of item `i` within `data`. Item `i`
/// occupies `data[ends[i-1]..ends[i]]` (item 0: `data[0..ends[0]]`).
///
/// Wire format (BIP144): `VarInt(count)` followed by each item as
/// `VarInt(len) || bytes`. The witness for each input is written after all
/// outputs in the segwit transaction serialisation; it is absent from the
/// non-witness (txid) serialisation.
#[derive(Clone)]
pub enum WitnessBuf<const ITEMS: usize, const BYTES: usize> {
    /// No stack items — the common case for legacy and non-segwit inputs.
    /// Zero allocation; avoids the `Box<[u8; BYTES]>` that `Inline` requires.
    Empty,
    Inline {
        count: u8,
        ends: [u16; ITEMS],
        used: u16,
        data: Box<[u8; BYTES]>,
    },
    Heap(Vec<Vec<u8>>),
}

/// Iterator over the stack items of a [`WitnessBuf`].
pub struct WitnessIter<'a, const ITEMS: usize, const BYTES: usize> {
    witness: &'a WitnessBuf<ITEMS, BYTES>,
    index: usize,
}

impl<'a, const ITEMS: usize, const BYTES: usize> Iterator for WitnessIter<'a, ITEMS, BYTES> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.witness.get(self.index)?;
        self.index += 1;
        Some(item)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.witness.len().saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl<'a, const ITEMS: usize, const BYTES: usize> IntoIterator for &'a WitnessBuf<ITEMS, BYTES> {
    type Item = &'a [u8];
    type IntoIter = WitnessIter<'a, ITEMS, BYTES>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<const ITEMS: usize, const BYTES: usize> WitnessBuf<ITEMS, BYTES> {
    /// An empty witness (no stack items).
    #[must_use]
    pub fn empty() -> Self {
        Self::Empty
    }

    /// Construct from a slice of byte-string items.
    #[must_use]
    pub fn from_slice(items: &[&[u8]]) -> Self {
        let total: usize = items.iter().map(|i| i.len()).sum();
        if items.len() <= ITEMS && total <= BYTES {
            let mut ends = [0u16; ITEMS];
            let mut data = Box::new([0u8; BYTES]);
            let mut offset = 0usize;
            for (idx, item) in items.iter().enumerate() {
                data[offset..offset + item.len()].copy_from_slice(item);
                offset += item.len();
                #[allow(clippy::cast_possible_truncation)]
                {
                    ends[idx] = offset as u16;
                }
            }
            #[allow(clippy::cast_possible_truncation)]
            Self::Inline {
                count: items.len() as u8,
                ends,
                used: offset as u16,
                data,
            }
        } else {
            Self::Heap(items.iter().map(|i| i.to_vec()).collect())
        }
    }

    /// Number of stack items.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Inline { count, .. } => *count as usize,
            Self::Heap(v) => v.len(),
        }
    }

    /// `true` if there are no stack items (e.g. a legacy or non-segwit input).
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Access item `i` by index. Returns `None` if out of bounds.
    #[must_use]
    pub fn get(&self, i: usize) -> Option<&[u8]> {
        match self {
            Self::Empty => None,
            Self::Inline {
                count, ends, data, ..
            } => {
                if i >= *count as usize {
                    return None;
                }
                let start = if i == 0 { 0 } else { ends[i - 1] as usize };
                let end = ends[i] as usize;
                Some(&data[start..end])
            }
            Self::Heap(v) => v.get(i).map(Vec::as_slice),
        }
    }

    /// Iterate over all stack items.
    #[must_use]
    pub fn iter(&self) -> WitnessIter<'_, ITEMS, BYTES> {
        WitnessIter {
            witness: self,
            index: 0,
        }
    }

    /// Materialise as a `Vec<Vec<u8>>`.
    #[must_use]
    pub fn to_vec(&self) -> Vec<Vec<u8>> {
        self.iter().map(<[u8]>::to_vec).collect()
    }

    /// Total byte size of all items (without length prefixes).
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Inline { used, .. } => *used as usize,
            Self::Heap(v) => v.iter().map(Vec::len).sum(),
        }
    }

    /// Encoded byte length for BIP144 witness serialisation of this input's
    /// witness: `VarInt(count)` + per-item `VarInt(len) + bytes`.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let count = self.len();
        VarInt::from(count).encoded_len()
            + self
                .iter()
                .map(|item| VarInt::from(item.len()).encoded_len() + item.len())
                .sum::<usize>()
    }
}

impl<const ITEMS: usize, const BYTES: usize> Default for WitnessBuf<ITEMS, BYTES> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<const ITEMS: usize, const BYTES: usize> PartialEq for WitnessBuf<ITEMS, BYTES> {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        self.iter().zip(other.iter()).all(|(a, b)| a == b)
    }
}

impl<const ITEMS: usize, const BYTES: usize> Eq for WitnessBuf<ITEMS, BYTES> {}

impl<const ITEMS: usize, const BYTES: usize> fmt::Debug for WitnessBuf<ITEMS, BYTES> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let items: Vec<_> = self.iter().collect();
        write!(f, "WitnessBuf({items:?})")
    }
}

impl<const ITEMS: usize, const BYTES: usize> Encode for WitnessBuf<ITEMS, BYTES> {
    fn encode(&self, w: &mut impl Write) -> Result<(), Error> {
        VarInt::from(self.len()).encode(w)?;
        for item in self {
            VarInt::from(item.len()).encode(w)?;
            w.write_all(item)?;
        }
        Ok(())
    }
}

impl<const ITEMS: usize, const BYTES: usize> Decode for WitnessBuf<ITEMS, BYTES> {
    fn decode(r: &mut impl Read) -> Result<Self, Error> {
        let count = VarInt::decode(r)?.to_usize()?;
        let mut items: Vec<Vec<u8>> = Vec::with_capacity(count.min(16));
        for _ in 0..count {
            // Witness stack items have no per-item consensus size limit (unlike
            // script push data). Cap at 4 MiB — the block weight bound.
            let item = VarInt::decode_bytes_limited::<{ 4 * 1024 * 1024 }>(r)?;
            items.push(item);
        }
        let slices: Vec<&[u8]> = items.iter().map(Vec::as_slice).collect();
        Ok(Self::from_slice(&slices))
    }
}

/// Witness stack for a transaction input. Inline up to 4 items / 164 bytes.
///
/// 4 items covers P2WPKH (2), most P2WSH multisig (≤4), and taproot key-path
/// (1, or 2 with annex). 164 bytes covers a P2WPKH witness (sig 73 + pubkey
/// 33 = 106) with room for P2WSH scripts up to ~58 bytes inline.
pub type Witness = WitnessBuf<4, 164>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Decode, Encode};
    use std::io::Cursor;

    fn encode_val<T: Encode>(val: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        val.encode(&mut buf).expect("Vec<u8> write cannot fail");
        buf
    }
    fn decode_val<T: Decode>(bytes: &[u8]) -> T {
        T::decode(&mut Cursor::new(bytes)).expect("test data must decode")
    }

    // ── Empty witness ────────────────────────────────────────────────────

    #[test]
    fn empty_witness_properties() {
        let w = Witness::empty();
        assert_eq!(w.len(), 0);
        assert!(w.is_empty());
        assert_eq!(w.get(0), None);
        assert_eq!(w.iter().count(), 0);
        assert_eq!(w.total_bytes(), 0);
        assert!(matches!(w, WitnessBuf::Empty));
    }

    // ── 2-item P2WPKH witness (sig + pubkey) ────────────────────────────

    #[test]
    fn two_item_p2wpkh_stays_inline() {
        let sig = [0x30u8; 72]; // typical DER sig length
        let pubkey = [0x02u8; 33]; // compressed pubkey
        let w = Witness::from_slice(&[&sig[..], &pubkey[..]]);
        assert!(matches!(w, WitnessBuf::Inline { .. }));
        assert_eq!(w.len(), 2);
        assert!(!w.is_empty());
        assert_eq!(w.get(0).unwrap(), &sig[..]);
        assert_eq!(w.get(1).unwrap(), &pubkey[..]);
        assert_eq!(w.get(2), None);
    }

    // ── Exactly 4 items fitting in 164 bytes stays Inline ────────────────

    #[test]
    fn four_items_within_budget_stays_inline() {
        // 4 items * 41 bytes = 164 bytes total
        let item = [0xAAu8; 41];
        let w = Witness::from_slice(&[&item[..], &item[..], &item[..], &item[..]]);
        assert!(matches!(w, WitnessBuf::Inline { .. }));
        assert_eq!(w.len(), 4);
    }

    // ── 5 items goes to Heap ─────────────────────────────────────────────

    #[test]
    fn five_items_goes_to_heap() {
        let item = [0xBBu8; 10];
        let w = Witness::from_slice(&[&item[..], &item[..], &item[..], &item[..], &item[..]]);
        assert!(matches!(w, WitnessBuf::Heap(_)));
        assert_eq!(w.len(), 5);
    }

    // ── 4 items totaling 165 bytes goes to Heap ──────────────────────────

    #[test]
    fn four_items_exceeding_bytes_goes_to_heap() {
        // 3 items of 41 bytes + 1 item of 42 bytes = 165 bytes > 164
        let small = [0xCCu8; 41];
        let big = [0xDDu8; 42];
        let w = Witness::from_slice(&[&small[..], &small[..], &small[..], &big[..]]);
        assert!(matches!(w, WitnessBuf::Heap(_)));
        assert_eq!(w.len(), 4);
    }

    // ── iter ─────────────────────────────────────────────────────────────

    #[test]
    fn iter_yields_all_items_in_order() {
        let a = [1u8, 2, 3];
        let b = [4u8, 5];
        let c = [6u8];
        let w = Witness::from_slice(&[&a[..], &b[..], &c[..]]);
        let items: Vec<&[u8]> = w.iter().collect();
        assert_eq!(items, vec![&a[..], &b[..], &c[..]]);
    }

    // ── to_vec ───────────────────────────────────────────────────────────

    #[test]
    fn to_vec_matches_input() {
        let a = vec![10u8, 20];
        let b = vec![30u8, 40, 50];
        let w = Witness::from_slice(&[&a[..], &b[..]]);
        let v = w.to_vec();
        assert_eq!(v, vec![a, b]);
    }

    // ── Encode / Decode roundtrip ────────────────────────────────────────

    #[test]
    fn encode_decode_empty() {
        let w = Witness::empty();
        let bytes = encode_val(&w);
        let decoded: Witness = decode_val(&bytes);
        assert_eq!(w, decoded);
    }

    #[test]
    fn encode_decode_two_items() {
        let sig = [0x30u8; 72];
        let pubkey = [0x02u8; 33];
        let w = Witness::from_slice(&[&sig[..], &pubkey[..]]);
        let bytes = encode_val(&w);
        let decoded: Witness = decode_val(&bytes);
        assert_eq!(w, decoded);
    }

    #[test]
    fn encode_decode_heap_witness() {
        let items: Vec<Vec<u8>> = (0u8..5).map(|i| vec![i; 20]).collect();
        let slices: Vec<&[u8]> = items.iter().map(std::vec::Vec::as_slice).collect();
        let w = Witness::from_slice(&slices);
        assert!(matches!(w, WitnessBuf::Heap(_)));
        let bytes = encode_val(&w);
        let decoded: Witness = decode_val(&bytes);
        assert_eq!(w, decoded);
    }

    // ── PartialEq: Inline vs Heap ────────────────────────────────────────

    #[test]
    fn eq_inline_vs_heap_same_items() {
        // Build the same 2-item witness as Inline (via Witness = WitnessBuf<4,164>)
        // and as Heap (via WitnessBuf<1,1> which forces heap for 2 items)
        let a = [0x01u8; 10];
        let b = [0x02u8; 10];
        let inline: Witness = Witness::from_slice(&[&a[..], &b[..]]);
        assert!(matches!(inline, WitnessBuf::Inline { .. }));

        let heap: WitnessBuf<1, 1> = WitnessBuf::from_slice(&[&a[..], &b[..]]);
        assert!(matches!(heap, WitnessBuf::Heap(_)));

        // Compare via iter since different generic params
        let inline_items: Vec<&[u8]> = inline.iter().collect();
        let heap_items: Vec<&[u8]> = heap.iter().collect();
        assert_eq!(inline_items, heap_items);
    }

    // ── Default is Empty ─────────────────────────────────────────────────

    #[test]
    fn default_is_empty() {
        let w = Witness::default();
        assert!(matches!(w, WitnessBuf::Empty));
        assert!(w.is_empty());
    }

    // ── encoded_len matches actual encoded bytes ─────────────────────────

    #[test]
    fn encoded_len_matches_actual_empty() {
        let w = Witness::empty();
        let bytes = encode_val(&w);
        assert_eq!(w.encoded_len(), bytes.len());
    }

    #[test]
    fn encoded_len_matches_actual_two_items() {
        let sig = [0x30u8; 72];
        let pubkey = [0x02u8; 33];
        let w = Witness::from_slice(&[&sig[..], &pubkey[..]]);
        let bytes = encode_val(&w);
        assert_eq!(w.encoded_len(), bytes.len());
    }

    #[test]
    fn encoded_len_matches_actual_heap() {
        let items: Vec<Vec<u8>> = (0u8..5).map(|i| vec![i; 20]).collect();
        let slices: Vec<&[u8]> = items.iter().map(std::vec::Vec::as_slice).collect();
        let w = Witness::from_slice(&slices);
        let bytes = encode_val(&w);
        assert_eq!(w.encoded_len(), bytes.len());
    }
}
