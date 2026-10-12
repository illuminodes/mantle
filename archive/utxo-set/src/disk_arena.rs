#![allow(clippy::cast_possible_truncation, clippy::missing_errors_doc, clippy::missing_panics_doc, clippy::must_use_candidate)]

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use mantle::primitives::{BlockHeight, Satoshi, ScriptPubKey};
use mantle_consensus::chain_view::Coin;

use crate::coin_entry::CoinEntry;

const SLOT_SIZE: u64 = 56;
const SLOT_SIZE_U32: u32 = SLOT_SIZE as u32;
const SLOT_SIZE_USIZE: usize = SLOT_SIZE as usize;
const MAX_INLINE_SPK: usize = 34;

/// On-disk arena span — base slot index + output count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskSpan {
    pub base: u32,
    pub count: u16,
}

/// Compact handle stored in the hashmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskTxHandle {
    pub span: DiskSpan,
    pub height: BlockHeight,
    pub live: u64,
    pub coinbase: bool,
}

impl DiskTxHandle {
    #[inline]
    #[must_use]
    pub fn is_fully_spent(&self) -> bool {
        self.live == 0
    }

    #[inline]
    #[must_use]
    pub fn is_unspent(&self, vout: u32) -> bool {
        if vout >= 64 { return false; }
        self.live & (1 << vout) != 0
    }

    #[inline]
    pub fn mark_spent(&mut self, vout: u32) {
        if vout < 64 { self.live &= !(1 << vout); }
    }

    #[inline]
    pub fn mark_unspent(&mut self, vout: u32) {
        if vout < 64 { self.live |= 1 << vout; }
    }

    #[inline]
    #[must_use]
    pub fn unspent_count(&self) -> u32 {
        self.live.count_ones()
    }
}

/// Disk-backed coin arena with free-list reclamation.
pub struct DiskArena {
    file: File,
    file_slots: u32,
    free_list: Vec<DiskSpan>,
}

impl DiskArena {
    /// Open or create the arena file.
    ///
    /// # Errors
    /// Returns I/O errors.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        let file_len = file.metadata()?.len();
        let file_slots = u32::try_from(file_len / SLOT_SIZE).expect("arena file fits u32 slots");
        Ok(Self {
            file,
            file_slots,
            free_list: Vec::new(),
        })
    }

    /// Allocate a span for `count` outputs. Tries the free list first,
    /// then appends to the file.
    #[allow(clippy::cast_possible_truncation)]
    pub fn alloc(&mut self, count: u16) -> DiskSpan {
        // Best-fit from free list: find smallest span that fits.
        let mut best_idx = None;
        let mut best_excess = u16::MAX;
        for (i, span) in self.free_list.iter().enumerate() {
            if span.count >= count && span.count - count < best_excess {
                best_excess = span.count - count;
                best_idx = Some(i);
                if best_excess == 0 { break; }
            }
        }

        if let Some(idx) = best_idx {
            let mut span = self.free_list.swap_remove(idx);
            if span.count > count {
                // Split: return the tail to the free list.
                self.free_list.push(DiskSpan {
                    base: span.base + u32::from(count),
                    count: span.count - count,
                });
            }
            span.count = count;
            return span;
        }

        // Append to file.
        let base = self.file_slots;
        self.file_slots += u32::from(count);
        // Extend file to cover new slots.
        let new_len = u64::from(self.file_slots) * SLOT_SIZE;
        let _ = self.file.set_len(new_len);
        DiskSpan { base, count }
    }

    /// Return a span to the free list for reuse.
    pub fn free(&mut self, span: DiskSpan) {
        self.free_list.push(span);
    }

    /// Write a coin to a specific slot. Synchronous pwrite.
    pub fn write_coin(&self, slot: u32, coin: &CoinEntry, height: BlockHeight, coinbase: bool) -> io::Result<()> {
        let mut buf = [0u8; SLOT_SIZE_USIZE];
        encode_slot(&mut buf, coin, height, coinbase);
        pwrite_all(&self.file, &buf, u64::from(slot) * SLOT_SIZE)
    }

    /// Read a coin from a specific slot. Synchronous pread.
    pub fn read_coin(&self, slot: u32) -> io::Result<Option<Coin>> {
        let mut buf = [0u8; SLOT_SIZE_USIZE];
        pread_exact(&self.file, &mut buf, u64::from(slot) * SLOT_SIZE)?;
        Ok(decode_slot(&buf))
    }

    /// Batch-write coins for a new tx span using `io_uring`.
    pub fn write_span_uring(
        &self,
        span: DiskSpan,
        coins: &[(u32, &CoinEntry, bool)], // (vout, coin, coinbase)
        height: BlockHeight,
        ring: &mut ququmatz::IoUring,
        arena_buf: &mut Vec<u8>,
    ) -> io::Result<()> {
        let count = coins.len();
        let needed = count * SLOT_SIZE_USIZE;
        arena_buf.clear();
        arena_buf.resize(needed, 0u8);

        #[allow(clippy::cast_sign_loss)]
        let fd = ququmatz::types::RawFd::from_raw(self.file.as_raw_fd() as usize);
        let mut submitted = 0u32;

        for (i, (vout, coin, coinbase)) in coins.iter().enumerate() {
            let buf_start = i * SLOT_SIZE_USIZE;
            encode_slot(
                (&mut arena_buf[buf_start..buf_start + SLOT_SIZE_USIZE]).try_into().expect("slot-aligned slice"),
                coin,
                height,
                *coinbase,
            );
            let offset = (u64::from(span.base) + u64::from(*vout)) * SLOT_SIZE;
            let sqe = unsafe {
                ququmatz::Sqe::write_ptr(
                    fd,
                    arena_buf[buf_start..].as_ptr(),
                    SLOT_SIZE_U32,
                    offset,
                )
            }.user_data(u64::try_from(i).expect("index fits u64"));
            ring.push(sqe).map_err(|e| io::Error::other(format!("{e:?}")))?;
            submitted += 1;
        }

        if submitted > 0 {
            ring.submit_and_wait(submitted)
                .map_err(|e| io::Error::other(format!("{e:?}")))?;
            while ring.complete().is_some() {}
        }
        Ok(())
    }

    /// Batch-read coins for a set of vouts within a span using `io_uring`.
    pub fn read_coins_uring(
        &self,
        span: DiskSpan,
        vouts: &[u32],
        ring: &mut ququmatz::IoUring,
        arena_buf: &mut Vec<u8>,
    ) -> io::Result<Vec<Option<Coin>>> {
        let count = vouts.len();
        let needed = count * SLOT_SIZE_USIZE;
        arena_buf.clear();
        arena_buf.resize(needed, 0u8);

        #[allow(clippy::cast_sign_loss)]
        let fd = ququmatz::types::RawFd::from_raw(self.file.as_raw_fd() as usize);
        let mut submitted = 0u32;

        for (i, &vout) in vouts.iter().enumerate() {
            if vout >= u32::from(span.count) { continue; }
            let offset = (u64::from(span.base) + u64::from(vout)) * SLOT_SIZE;
            let buf_start = i * SLOT_SIZE_USIZE;
            let sqe = unsafe {
                ququmatz::Sqe::read_ptr(
                    fd,
                    arena_buf[buf_start..].as_mut_ptr(),
                    SLOT_SIZE_U32,
                    offset,
                )
            }.user_data(u64::try_from(i).expect("index fits u64"));
            ring.push(sqe).map_err(|e| io::Error::other(format!("{e:?}")))?;
            submitted += 1;
        }

        if submitted > 0 {
            ring.submit_and_wait(submitted)
                .map_err(|e| io::Error::other(format!("{e:?}")))?;
            while ring.complete().is_some() {}
        }

        let mut results = Vec::with_capacity(count);
        for i in 0..count {
            let buf_start = i * SLOT_SIZE_USIZE;
            let buf: &[u8; SLOT_SIZE_USIZE] =
                arena_buf[buf_start..buf_start + SLOT_SIZE_USIZE].try_into().expect("slot-aligned slice");
            results.push(decode_slot(buf));
        }
        Ok(results)
    }

    pub fn fd(&self) -> &File {
        &self.file
    }

    #[must_use]
    pub fn file_slots(&self) -> u32 {
        self.file_slots
    }

    #[must_use]
    pub fn free_list_len(&self) -> usize {
        self.free_list.len()
    }
}

// ── Slot encoding/decoding ───────────────────────────────────────────────────
// Layout (56 bytes):
//   [0..8]   value (u64 le)
//   [8..12]  height (u32 le)
//   [12]     spk_len (u8, 0 = empty/tombstone)
//   [13..47] spk (34 bytes, zero-padded)
//   [47]     coinbase (u8)
//   [48..56] padding (zeroed)

fn encode_slot(buf: &mut [u8; SLOT_SIZE_USIZE], coin: &CoinEntry, height: BlockHeight, coinbase: bool) {
    encode_coin_slot(buf, coin.value, height, coinbase, coin.script_pubkey.as_slice());
}

/// Encode a coin into a 56-byte slot buffer from raw fields.
pub fn encode_coin_slot(
    buf: &mut [u8; SLOT_SIZE_USIZE],
    value: Satoshi,
    height: BlockHeight,
    coinbase: bool,
    script_pubkey: &[u8],
) {
    buf[0..8].copy_from_slice(&value.to_le_bytes());
    buf[8..12].copy_from_slice(&height.to_u32().to_le_bytes());
    let spk_len = script_pubkey.len().min(MAX_INLINE_SPK);
    #[allow(clippy::cast_possible_truncation)]
    { buf[12] = spk_len as u8; }
    buf[13..13 + spk_len].copy_from_slice(&script_pubkey[..spk_len]);
    buf[13 + spk_len..47].fill(0);
    buf[47] = u8::from(coinbase);
    buf[48..56].fill(0);
}

fn decode_slot(buf: &[u8; SLOT_SIZE_USIZE]) -> Option<Coin> {
    let spk_len = buf[12] as usize;
    if spk_len == 0 && buf[0..8] == [0u8; 8] {
        return None; // tombstone / empty
    }
    let value = Satoshi::new(u64::from_le_bytes(buf[0..8].try_into().unwrap()));
    let height = BlockHeight::new(u32::from_le_bytes(buf[8..12].try_into().unwrap()));
    let script_pubkey = ScriptPubKey::from_slice(&buf[13..13 + spk_len]);
    let coinbase = buf[47] != 0;
    Some(Coin { value, script_pubkey, height, coinbase })
}

fn pwrite_all(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(buf, offset)
}

fn pread_exact(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new() -> Self {
            use std::time::{SystemTime, UNIX_EPOCH};
            let ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
            let path = std::env::temp_dir().join(format!("mantle-disk-arena-{}-{}", std::process::id(), ns));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path { &self.0 }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    fn coin(sats: u64) -> CoinEntry {
        CoinEntry {
            value: Satoshi::new(sats),
            script_pubkey: vec![0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14].into(),
        }
    }

    #[test]
    fn alloc_write_read() {
        let dir = TmpDir::new();
        let mut arena = DiskArena::open(&dir.path().join("coins.bin")).unwrap();
        let span = arena.alloc(2);
        assert_eq!(span.base, 0);
        assert_eq!(span.count, 2);

        arena.write_coin(0, &coin(5000), BlockHeight::new(100), false).unwrap();
        arena.write_coin(1, &coin(3000), BlockHeight::new(100), true).unwrap();

        let c0 = arena.read_coin(0).unwrap().unwrap();
        assert_eq!(c0.value, Satoshi::new(5000));
        assert!(!c0.coinbase);

        let c1 = arena.read_coin(1).unwrap().unwrap();
        assert_eq!(c1.value, Satoshi::new(3000));
        assert!(c1.coinbase);
    }

    #[test]
    fn free_list_reclamation() {
        let dir = TmpDir::new();
        let mut arena = DiskArena::open(&dir.path().join("coins.bin")).unwrap();

        let s1 = arena.alloc(3);
        let s2 = arena.alloc(2);
        assert_eq!(s1.base, 0);
        assert_eq!(s2.base, 3);
        assert_eq!(arena.file_slots(), 5);

        arena.free(s1);
        assert_eq!(arena.free_list_len(), 1);

        // Next alloc of size 2 should reuse part of s1.
        let s3 = arena.alloc(2);
        assert_eq!(s3.base, 0); // reused from s1
        assert_eq!(s3.count, 2);
        // Remainder of s1 (slot 2, count 1) stays in free list.
        assert_eq!(arena.free_list_len(), 1);

        // Alloc size 1 uses the remainder.
        let s4 = arena.alloc(1);
        assert_eq!(s4.base, 2);
        assert_eq!(arena.free_list_len(), 0);

        // File didn't grow.
        assert_eq!(arena.file_slots(), 5);
    }

    #[test]
    fn reopen_preserves_data() {
        let dir = TmpDir::new();
        let path = dir.path().join("coins.bin");
        {
            let mut arena = DiskArena::open(&path).unwrap();
            let span = arena.alloc(1);
            arena.write_coin(span.base, &coin(999), BlockHeight::new(42), false).unwrap();
        }
        let arena = DiskArena::open(&path).unwrap();
        let c = arena.read_coin(0).unwrap().unwrap();
        assert_eq!(c.value, Satoshi::new(999));
        assert_eq!(c.height, BlockHeight::new(42));
    }

    #[test]
    fn write_span_uring_then_read_coins_uring() {
        let dir = TmpDir::new();
        let mut arena = DiskArena::open(&dir.path().join("coins.bin")).unwrap();
        let mut ring = ququmatz::IoUring::new(64).unwrap();
        let mut arena_buf: Vec<u8> = Vec::new();

        let span = arena.alloc(3);
        let c0 = coin(1000);
        let c1 = coin(2000);
        let c2 = coin(3000);

        let coins_to_write: Vec<(u32, &CoinEntry, bool)> = vec![
            (0, &c0, false),
            (1, &c1, true),
            (2, &c2, false),
        ];

        arena
            .write_span_uring(span, &coins_to_write, BlockHeight::new(50), &mut ring, &mut arena_buf)
            .unwrap();

        // Read back all three vouts via io_uring.
        let mut read_buf = Vec::new();
        let results = arena
            .read_coins_uring(span, &[0, 1, 2], &mut ring, &mut read_buf)
            .unwrap();

        assert_eq!(results.len(), 3);
        let r0 = results[0].as_ref().unwrap();
        assert_eq!(r0.value, Satoshi::new(1000));
        assert!(!r0.coinbase);
        assert_eq!(r0.height, BlockHeight::new(50));

        let r1 = results[1].as_ref().unwrap();
        assert_eq!(r1.value, Satoshi::new(2000));
        assert!(r1.coinbase);

        let r2 = results[2].as_ref().unwrap();
        assert_eq!(r2.value, Satoshi::new(3000));
        assert!(!r2.coinbase);
    }

    #[test]
    fn read_coins_uring_skips_out_of_range_vout() {
        let dir = TmpDir::new();
        let mut arena = DiskArena::open(&dir.path().join("coins.bin")).unwrap();
        let mut ring = ququmatz::IoUring::new(64).unwrap();

        let span = arena.alloc(1);
        let c = coin(7777);
        arena.write_coin(span.base, &c, BlockHeight::new(10), false).unwrap();

        // vout 0 is valid, vout 5 is out-of-range (span.count == 1).
        let mut read_buf = Vec::new();
        let results = arena
            .read_coins_uring(span, &[0, 5], &mut ring, &mut read_buf)
            .unwrap();

        assert_eq!(results.len(), 2);
        assert!(results[0].is_some());
        assert_eq!(results[0].as_ref().unwrap().value, Satoshi::new(7777));
        // Out-of-range vout yields None (buffer is zeroed, decode_slot sees tombstone).
        assert!(results[1].is_none());
    }

    #[test]
    fn encode_decode_roundtrip() {
        let c = coin(123_456_789);
        let mut buf = [0u8; SLOT_SIZE_USIZE];
        encode_slot(&mut buf, &c, BlockHeight::new(800_000), true);
        let decoded = decode_slot(&buf).unwrap();
        assert_eq!(decoded.value, Satoshi::new(123_456_789));
        assert_eq!(decoded.height, BlockHeight::new(800_000));
        assert!(decoded.coinbase);
        assert_eq!(decoded.script_pubkey.as_slice(), c.script_pubkey.as_slice());
    }
}
