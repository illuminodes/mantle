use mantle::hash::ByteSliceExt;
use mantle::primitives::Hash256;

/// Compute the merkle root from a slice, reusing `buf` as the working buffer.
///
/// `buf` is cleared and refilled on every call; the caller retains ownership
/// so its capacity is amortised across calls. Use this on hot paths where the
/// same buffer can be passed in repeatedly.
///
/// Returns `None` only on an empty input.
#[must_use]
pub fn compute_merkle_root_reusing(txids: &[Hash256], buf: &mut Vec<Hash256>) -> Option<Hash256> {
    if txids.is_empty() {
        return None;
    }
    buf.clear();
    buf.extend_from_slice(txids);
    Some(reduce_in_place(buf))
}

/// Compute the merkle root from a slice, cloning into a temporary working buffer.
///
/// Prefer [`compute_merkle_root_reusing`] on hot paths to avoid the per-call
/// allocation.
///
/// Returns `None` only on an empty input.
#[must_use]
pub fn compute_merkle_root(txids: &[Hash256]) -> Option<Hash256> {
    compute_merkle_root_reusing(txids, &mut Vec::new())
}

/// Compute the merkle root by consuming an already-owned Vec.
///
/// Avoids the clone when the caller already holds ownership of the txid list.
#[must_use]
pub fn merkle_root_owned(mut row: Vec<Hash256>) -> Option<Hash256> {
    if row.is_empty() {
        return None;
    }
    Some(reduce_in_place(&mut row))
}

/// In-place fold: overwrites the front of `row` with parent hashes each round,
/// truncates, repeats until one element remains. `row` must be non-empty.
fn reduce_in_place(row: &mut Vec<Hash256>) -> Hash256 {
    let mut pair = [0u8; 64];
    while row.len() > 1 {
        if row.len() % 2 == 1 {
            let last = row[row.len() - 1];
            row.push(last);
        }
        let parents = row.len() / 2;
        for i in 0..parents {
            pair[..32].copy_from_slice(row[i * 2].as_bytes());
            pair[32..].copy_from_slice(row[i * 2 + 1].as_bytes());
            row[i] = pair.sha256d();
        }
        row.truncate(parents);
    }
    row[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::decode_hex;

    fn h(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn txid_from_hex(s: &str) -> Hash256 {
        let bytes = decode_hex(s);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Hash256::from_bytes(arr)
    }

    #[test]
    fn empty_returns_none() {
        assert_eq!(compute_merkle_root(&[]), None);
    }

    #[test]
    fn single_tx_is_its_own_root() {
        let txid = h(0xab);
        assert_eq!(compute_merkle_root(&[txid]), Some(txid));
    }

    #[test]
    fn two_txs() {
        let a = h(0x01);
        let b = h(0x02);
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(a.as_bytes());
        buf[32..].copy_from_slice(b.as_bytes());
        let expected = buf.sha256d();
        assert_eq!(compute_merkle_root(&[a, b]), Some(expected));
    }

    #[test]
    fn odd_row_duplicates_last() {
        // Three txids: row becomes [h(AB), h(CC)] then root = h(h(AB) || h(CC))
        let a = h(0xaa);
        let b = h(0xbb);
        let c = h(0xcc);

        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(a.as_bytes());
        buf[32..].copy_from_slice(b.as_bytes());
        let ab = buf.sha256d();

        buf[..32].copy_from_slice(c.as_bytes());
        buf[32..].copy_from_slice(c.as_bytes());
        let cc = buf.sha256d();

        buf[..32].copy_from_slice(ab.as_bytes());
        buf[32..].copy_from_slice(cc.as_bytes());
        let expected = buf.sha256d();

        assert_eq!(compute_merkle_root(&[a, b, c]), Some(expected));
    }

    #[test]
    fn genesis_merkle_root() {
        // Genesis block has exactly one transaction. The merkle root equals the
        // txid — no hashing applied. Verify against the known genesis txid.
        // Stored in internal byte order (not display-reversed).
        let genesis_txid_hex = "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a";
        let txid = txid_from_hex(genesis_txid_hex);
        let root = compute_merkle_root(&[txid]).expect("single-tx merkle root must exist");
        assert_eq!(root, txid);
    }
}
