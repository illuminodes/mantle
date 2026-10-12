//! Shared Robin Hood hash-table helpers.
//!
//! The backshift algorithm is identical across every Robin Hood table in the
//! codebase (storage `RobinHoodTable`, utxo-set `TxIndex`).  This module
//! provides a single generic implementation so it cannot drift.

use std::io;

/// Robin Hood backward-shift deletion.
///
/// After removing the entry at `removed_slot`, entries that were displaced
/// past it are shifted back toward their ideal slot (probe distance
/// decremented by one) until we hit an empty bucket or one already at
/// probe distance 1.
///
/// The caller supplies three closures that abstract over the concrete
/// bucket type and I/O layer:
///
/// * `read_bucket(slot)` -- read the bucket at `slot`.
/// * `write_bucket(slot, bucket)` -- overwrite `slot` with `bucket`.
/// * `write_empty(slot)` -- write an empty/tombstone bucket at `slot`.
///
/// `should_stop` inspects a bucket and returns `true` when it is empty or
/// has probe distance 1 (meaning it is already in its ideal slot and the
/// chain terminates).
///
/// `decrement_probe` returns a clone of the bucket with its probe distance
/// decremented by one.
///
/// # Errors
///
/// Returns an I/O error if any of the closure calls fail.
pub fn backshift<B>(
    removed_slot: u64,
    mask: u64,
    mut read_bucket: impl FnMut(u64) -> io::Result<B>,
    mut write_bucket: impl FnMut(u64, &B) -> io::Result<()>,
    mut write_empty: impl FnMut(u64) -> io::Result<()>,
    should_stop: impl Fn(&B) -> bool,
    decrement_probe: impl Fn(&B) -> B,
) -> io::Result<()> {
    let mut prev = removed_slot;
    let mut slot = (removed_slot + 1) & mask;
    loop {
        let bucket = read_bucket(slot)?;
        if should_stop(&bucket) {
            write_empty(prev)?;
            return Ok(());
        }
        let shifted = decrement_probe(&bucket);
        write_bucket(prev, &shifted)?;
        prev = slot;
        slot = (slot + 1) & mask;
    }
}
