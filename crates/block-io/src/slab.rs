use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU32, Ordering};

const SLOT_SIZE: usize = 4 * 1024 * 1024;
const SLOT_COUNT: usize = 4;

#[derive(Clone, Copy)]
pub struct SlabToken {
    pub slot: u16,
    pub len: u32,
}

pub struct BufHandle<'a> {
    slice: &'a [u8],
    pub slot: u16,
}

impl<'a> BufHandle<'a> {
    #[must_use]
    pub fn as_slice(&self) -> &'a [u8] {
        self.slice
    }
}

impl AsRef<[u8]> for BufHandle<'_> {
    fn as_ref(&self) -> &[u8] {
        self.slice
    }
}

// ── Slot — the single unsafe boundary ──────────────────────────────────────
//
// All unsafe in the slab module is confined to this type (3 items):
//   1. `unsafe impl Sync` — required because UnsafeCell is !Sync
//   2. `write_buf()`       — &self → &mut [u8] for the writer
//   3. `read_buf()`        — &self → &[u8] for the reader
//
// Safety invariant: a slot is exclusively owned by either the writer
// (allocated, no token sent) or the reader (token received, not yet
// released), never both simultaneously.  The ring buffer's
// Release/Acquire ordering on token send/receive enforces this.

struct Slot {
    buf: UnsafeCell<Box<[u8; SLOT_SIZE]>>,
    used_len: AtomicU32,
}

unsafe impl Sync for Slot {}

impl Slot {
    fn new() -> Self {
        Self {
            buf: UnsafeCell::new(vec![0u8; SLOT_SIZE].into_boxed_slice().try_into().unwrap()),
            used_len: AtomicU32::new(0),
        }
    }

    #[allow(clippy::mut_from_ref)]
    fn write_buf(&self) -> &mut [u8; SLOT_SIZE] {
        // SAFETY: caller holds exclusive write access (slot allocated,
        // no token sent, not in free list).
        unsafe { &mut *self.buf.get() }
    }

    fn read_buf(&self) -> &[u8; SLOT_SIZE] {
        // SAFETY: caller holds read access (token received through ring
        // with Acquire ordering, writer will not touch until released).
        unsafe { &*self.buf.get() }
    }

    fn set_used_len(&self, len: u32) {
        self.used_len.store(len, Ordering::Release);
    }

    fn used_len(&self) -> u32 {
        self.used_len.load(Ordering::Acquire)
    }
}

// ── Slab (safe) ────────────────────────────────────────────────────────────

pub struct Slab {
    slots: Vec<Slot>,
}

impl Default for Slab {
    fn default() -> Self {
        Self::new()
    }
}

impl Slab {
    pub fn new() -> Self {
        let slots = (0..SLOT_COUNT).map(|_| Slot::new()).collect();
        Self { slots }
    }

    pub fn split(&self) -> (SlabWriter<'_>, SlabReader<'_>) {
        let free = (0..u16::try_from(SLOT_COUNT).expect("SLOT_COUNT fits u16"))
            .rev()
            .collect();
        (
            SlabWriter { slab: self, free },
            SlabReader { slab: self },
        )
    }
}

// ── SlabWriter (safe — delegates unsafe to Slot) ───────────────────────────

pub struct SlabWriter<'a> {
    slab: &'a Slab,
    free: Vec<u16>,
}

impl SlabWriter<'_> {
    pub fn alloc(&mut self) -> Option<u16> {
        self.free.pop()
    }

    pub fn release(&mut self, slot: u16) {
        let idx = slot as usize;
        if idx >= SLOT_COUNT {
            return;
        }
        let s = &self.slab.slots[idx];
        if s.used_len() == 0 {
            return;
        }
        s.set_used_len(0);
        self.free.push(slot);
    }

    #[allow(clippy::mut_from_ref)]
    pub fn slot_buf_mut(&self, slot: u16) -> &mut [u8] {
        self.slab.slots[slot as usize].write_buf()
    }

    pub fn fill(&self, slot: u16, len: u32) -> SlabToken {
        self.slab.slots[slot as usize].set_used_len(len);
        SlabToken { slot, len }
    }

    pub fn fill_from_disk(
        &self,
        slot: u16,
        store: &crate::store::FileStore,
        ring: &mut ququmatz::IoUring,
        offset: u64,
        len: u32,
    ) -> std::io::Result<SlabToken> {
        let len_usize = len as usize;
        if len_usize > SLOT_SIZE {
            return Err(std::io::Error::other(format!(
                "block {len} bytes exceeds slot size {SLOT_SIZE}"
            )));
        }
        let dst = &mut self.slot_buf_mut(slot)[..len_usize];
        // SAFETY: `SingleOp::run` blocks until this read completes, so `dst`
        // outlives it.
        let sqe = unsafe { ququmatz::Sqe::read(store.fd(), dst, offset) };
        crate::single_op::SingleOp::run(ring, sqe)?;
        Ok(self.fill(slot, len))
    }
}

// ── SlabReader (safe — delegates unsafe to Slot) ───────────────────────────

pub struct SlabReader<'a> {
    slab: &'a Slab,
}

impl<'a> SlabReader<'a> {
    pub fn handle(&self, token: SlabToken) -> BufHandle<'a> {
        let s = &self.slab.slots[token.slot as usize];
        let len = token.len as usize;
        let buf = s.read_buf();
        BufHandle {
            slice: &buf[..len],
            slot: token.slot,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_fill_read_release() {
        let slab = Slab::new();
        let (mut writer, reader) = slab.split();

        let slot = writer.alloc().expect("should allocate");
        let buf = writer.slot_buf_mut(slot);
        buf[0] = 0xAB;
        buf[1] = 0xCD;
        let token = writer.fill(slot, 2);

        let handle = reader.handle(token);
        assert_eq!(handle.as_slice(), &[0xAB, 0xCD]);
        assert_eq!(handle.slot, slot);

        drop(handle);
        writer.release(slot);
        assert!(writer.alloc().is_some());
    }

    #[test]
    fn exhaust_and_reclaim() {
        let slab = Slab::new();
        let (mut writer, _reader) = slab.split();

        let mut slots = Vec::new();
        for _ in 0..SLOT_COUNT {
            slots.push(writer.alloc().expect("should allocate"));
        }
        assert!(writer.alloc().is_none());

        writer.fill(slots[0], 1);
        writer.release(slots[0]);
        assert!(writer.alloc().is_some());
    }

    #[test]
    fn double_release_is_noop() {
        let slab = Slab::new();
        let (mut writer, _reader) = slab.split();

        let slot = writer.alloc().expect("should allocate");
        writer.fill(slot, 1);
        writer.release(slot);
        let before = writer.free.len();
        writer.release(slot);
        assert_eq!(writer.free.len(), before);
    }
}
