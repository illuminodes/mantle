use mantle::network::{Command, Magic};

const SEND_SLOT_SIZE: usize = 4 * 1024;
const SEND_SLOT_COUNT: u16 = 8_192;

pub struct SendSlab {
    slab: Box<[u8]>,
    used_len: Box<[u32]>,
}

pub struct SendAlloc {
    free: Vec<u16>,
    pub dbg_alloc: u64,
    pub dbg_release: u64,
}

pub struct BufHandle<'a> {
    slice: &'a [u8],
    seq: u16,
}

impl<'a> BufHandle<'a> {
    #[must_use]
    pub fn as_slice(&self) -> &'a [u8] {
        self.slice
    }

    #[must_use]
    pub fn seq(&self) -> u16 {
        self.seq
    }
}

impl SendSlab {
    #[must_use]
    pub fn new() -> Self {
        let slot_count_usize = SEND_SLOT_COUNT as usize;
        let slab = vec![0u8; slot_count_usize * SEND_SLOT_SIZE].into_boxed_slice();
        let used_len = vec![0u32; slot_count_usize].into_boxed_slice();
        Self { slab, used_len }
    }

    #[must_use]
    pub fn handle(&self, slot: u16) -> BufHandle<'_> {
        let off = (slot as usize) * SEND_SLOT_SIZE;
        let len = self.used_len[slot as usize] as usize;
        BufHandle {
            slice: &self.slab[off..off + len],
            seq: slot,
        }
    }

    pub fn frame_into(&mut self, slot: u16, magic: Magic, cmd: Command, payload: &[u8]) -> bool {
        let off = (slot as usize) * SEND_SLOT_SIZE;
        let dst = &mut self.slab[off..off + SEND_SLOT_SIZE];
        let mut cursor = std::io::Cursor::new(dst);
        if let Err(e) = magic.frame(cmd, payload, &mut cursor) {
            eprintln!(
                "  transport: frame_into({cmd:?}, {} bytes) failed: {e:?} \
                 (slot {slot} reclaimed)",
                payload.len()
            );
            return false;
        }
        let written = u32::try_from(cursor.position()).expect("frame fits u32");
        self.used_len[slot as usize] = written;
        true
    }
}

impl Default for SendSlab {
    fn default() -> Self {
        Self::new()
    }
}

impl SendAlloc {
    #[must_use]
    pub fn new() -> Self {
        let slot_count_usize = SEND_SLOT_COUNT as usize;
        let mut free = Vec::with_capacity(slot_count_usize);
        for i in (0..SEND_SLOT_COUNT).rev() {
            free.push(i);
        }
        Self {
            free,
            dbg_alloc: 0,
            dbg_release: 0,
        }
    }

    #[must_use]
    pub fn alloc(&mut self) -> Option<u16> {
        let slot = self.free.pop()?;
        self.dbg_alloc += 1;
        Some(slot)
    }

    pub fn release(&mut self, slot: u16) {
        self.free.push(slot);
        self.dbg_release += 1;
    }

    #[must_use]
    pub fn free_count(&self) -> usize {
        self.free.len()
    }

    #[must_use]
    pub fn slot_count() -> u16 {
        SEND_SLOT_COUNT
    }
}

impl Default for SendAlloc {
    fn default() -> Self {
        Self::new()
    }
}

/// Combined arena for backward compatibility and simpler call sites.
pub struct SendArena {
    pub slab: SendSlab,
    pub alloc: SendAlloc,
}

impl SendArena {
    #[must_use]
    pub fn new() -> Self {
        Self {
            slab: SendSlab::new(),
            alloc: SendAlloc::new(),
        }
    }

    pub fn frame_into(&mut self, magic: Magic, cmd: Command, payload: &[u8]) -> Option<u16> {
        let slot = self.alloc.alloc()?;
        if self.slab.frame_into(slot, magic, cmd, payload) {
            Some(slot)
        } else {
            self.alloc.release(slot);
            None
        }
    }

    #[must_use]
    pub fn handle(&self, slot: u16) -> BufHandle<'_> {
        self.slab.handle(slot)
    }

    #[must_use]
    pub fn slice(&self, slot: u16) -> &[u8] {
        self.slab.handle(slot).slice
    }

    pub fn release(&mut self, slot: u16) {
        if (slot as usize) >= SEND_SLOT_COUNT as usize {
            return;
        }
        if self.slab.used_len[slot as usize] == 0 {
            return;
        }
        self.slab.used_len[slot as usize] = 0;
        self.alloc.release(slot);
    }

    #[must_use]
    pub fn free_count(&self) -> usize {
        self.alloc.free_count()
    }

    #[must_use]
    pub fn slot_count() -> u16 {
        SEND_SLOT_COUNT
    }
}

impl Default for SendArena {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_and_release() {
        let mut arena = SendArena::new();
        assert_eq!(arena.free_count(), SendArena::slot_count() as usize);

        let seq = arena
            .frame_into(Magic::Mainnet, Command::Verack, &[])
            .expect("should allocate");
        assert_eq!(arena.free_count(), SendArena::slot_count() as usize - 1);
        assert!(!arena.slice(seq).is_empty());

        arena.release(seq);
        assert_eq!(arena.free_count(), SendArena::slot_count() as usize);
    }

    #[test]
    fn double_release_is_noop() {
        let mut arena = SendArena::new();
        let seq = arena
            .frame_into(Magic::Mainnet, Command::Verack, &[])
            .expect("should allocate");
        arena.release(seq);
        let before = arena.free_count();
        arena.release(seq);
        assert_eq!(arena.free_count(), before);
    }

    #[test]
    fn exhaust_slots() {
        let mut arena = SendArena::new();
        let mut seqs = Vec::new();
        for _ in 0..SendArena::slot_count() {
            let seq = arena
                .frame_into(Magic::Mainnet, Command::Verack, &[])
                .expect("should allocate");
            seqs.push(seq);
        }
        assert_eq!(arena.free_count(), 0);
        assert!(arena
            .frame_into(Magic::Mainnet, Command::Verack, &[])
            .is_none());

        arena.release(seqs[0]);
        assert_eq!(arena.free_count(), 1);
        assert!(arena
            .frame_into(Magic::Mainnet, Command::Verack, &[])
            .is_some());
    }

    #[test]
    fn release_out_of_bounds_is_noop() {
        let mut arena = SendArena::new();
        arena.release(u16::MAX);
        assert_eq!(arena.free_count(), SendArena::slot_count() as usize);
    }

    #[test]
    fn buf_handle_lifetime() {
        let mut arena = SendArena::new();
        let seq = arena
            .frame_into(Magic::Mainnet, Command::Verack, &[])
            .expect("should allocate");
        let handle = arena.handle(seq);
        assert!(!handle.as_slice().is_empty());
        assert_eq!(handle.seq(), seq);
    }
}
