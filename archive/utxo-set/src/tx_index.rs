//! On-disk Robin Hood hash table mapping txid → `DiskTxHandle`.
//!
//! 64-byte buckets, power-of-two slot count, keyed by `Hash256` (txid).
//! Probing uses the first 8 bytes of the txid as the hash (SHA-256d output
//! is uniformly distributed).

#![allow(clippy::cast_possible_truncation, clippy::missing_errors_doc)]

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use mantle::primitives::{BlockHeight, Hash256};

use crate::disk_arena::{DiskSpan, DiskTxHandle};

const BUCKET_SIZE: u64 = 64;
const BUCKET_SIZE_U32: u32 = BUCKET_SIZE as u32;
const BUCKET_SIZE_USIZE: usize = BUCKET_SIZE as usize;
const MAGIC: [u8; 8] = *b"MANTLTX\0";
const FORMAT_VERSION: u32 = 1;
const INITIAL_SLOT_COUNT: u64 = 1024;
const LOAD_FACTOR_NUM: u64 = 85;
const LOAD_FACTOR_DEN: u64 = 100;

// ── Bucket layout (64 bytes) ────────────────────────────────────────────────
// [0..32]   txid (Hash256)
// [32..36]  span.base (u32 le)
// [36..38]  span.count (u16 le)
// [38..42]  height (u32 le)
// [42..50]  live bitmap (u64 le)
// [50]      coinbase (u8, 0 or 1)
// [51]      probe_distance (u8, 0 = empty)
// [52..64]  padding (zeroed)

#[derive(Clone)]
struct Bucket {
    txid: [u8; 32],
    span_base: u32,
    span_count: u16,
    height: u32,
    live: u64,
    coinbase: bool,
    probe_distance: u8,
}

impl Bucket {
    #[inline]
    fn is_empty(&self) -> bool {
        self.probe_distance == 0
    }

    #[inline]
    fn matches(&self, txid: &Hash256) -> bool {
        self.txid == *txid.as_bytes()
    }

    fn to_handle(&self) -> DiskTxHandle {
        DiskTxHandle {
            span: DiskSpan {
                base: self.span_base,
                count: self.span_count,
            },
            height: BlockHeight::new(self.height),
            live: self.live,
            coinbase: self.coinbase,
        }
    }

    fn from_handle(txid: &Hash256, handle: &DiskTxHandle, probe_distance: u8) -> Self {
        Self {
            txid: *txid.as_bytes(),
            span_base: handle.span.base,
            span_count: handle.span.count,
            height: handle.height.to_u32(),
            live: handle.live,
            coinbase: handle.coinbase,
            probe_distance,
        }
    }

    fn encode(&self, buf: &mut [u8; BUCKET_SIZE as usize]) {
        buf[0..32].copy_from_slice(&self.txid);
        buf[32..36].copy_from_slice(&self.span_base.to_le_bytes());
        buf[36..38].copy_from_slice(&self.span_count.to_le_bytes());
        buf[38..42].copy_from_slice(&self.height.to_le_bytes());
        buf[42..50].copy_from_slice(&self.live.to_le_bytes());
        buf[50] = u8::from(self.coinbase);
        buf[51] = self.probe_distance;
        buf[52..64].fill(0);
    }

    fn decode(buf: &[u8; BUCKET_SIZE as usize]) -> Self {
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&buf[0..32]);
        Self {
            txid,
            span_base: u32::from_le_bytes(buf[32..36].try_into().unwrap()),
            span_count: u16::from_le_bytes(buf[36..38].try_into().unwrap()),
            height: u32::from_le_bytes(buf[38..42].try_into().unwrap()),
            live: u64::from_le_bytes(buf[42..50].try_into().unwrap()),
            coinbase: buf[50] != 0,
            probe_distance: buf[51],
        }
    }
}

// ── File header (stored in slot 0, same size as a bucket) ───────────────────

struct TableHeader {
    slot_count: u64,
    live_count: u64,
}

impl TableHeader {
    fn encode(&self, buf: &mut [u8; BUCKET_SIZE as usize]) {
        *buf = [0u8; BUCKET_SIZE as usize];
        buf[0..8].copy_from_slice(&MAGIC);
        buf[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        buf[12..20].copy_from_slice(&self.slot_count.to_le_bytes());
        buf[20..28].copy_from_slice(&self.live_count.to_le_bytes());
    }

    fn decode(buf: &[u8; BUCKET_SIZE as usize]) -> io::Result<Self> {
        if buf[0..8] != MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad tx index magic"));
        }
        let version = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        if version != FORMAT_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported tx index version {version}"),
            ));
        }
        Ok(Self {
            slot_count: u64::from_le_bytes(buf[12..20].try_into().unwrap()),
            live_count: u64::from_le_bytes(buf[20..28].try_into().unwrap()),
        })
    }
}

// ── Hash function ───────────────────────────────────────────────────────────

#[inline]
fn hash_txid(txid: &Hash256) -> u64 {
    u64::from_le_bytes(txid.as_bytes()[..8].try_into().unwrap())
}

// ── TxIndex ─────────────────────────────────────────────────────────────────

pub struct TxIndex {
    file: File,
    path: PathBuf,
    slot_count: u64,
    mask: u64,
    live_count: u64,
}

struct InsertState {
    bucket: Bucket,
    slot: u64,
    ideal: u64,
    resolved: bool,
}

impl TxIndex {
    pub fn open(path: &Path) -> io::Result<Self> {
        if path.exists() {
            Self::open_existing(path)
        } else {
            Self::create(path, INITIAL_SLOT_COUNT)
        }
    }

    pub fn open_with_capacity(path: &Path, min_slots: u64) -> io::Result<Self> {
        if path.exists() {
            Self::open_existing(path)
        } else {
            let slots = min_slots.next_power_of_two();
            Self::create(path, slots)
        }
    }

    fn create(path: &Path, slot_count: u64) -> io::Result<Self> {
        debug_assert!(slot_count.is_power_of_two());
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;

        let file_size = (slot_count + 1) * BUCKET_SIZE;
        file.set_len(file_size)?;

        let header = TableHeader { slot_count, live_count: 0 };
        let mut buf = [0u8; BUCKET_SIZE as usize];
        header.encode(&mut buf);
        pwrite_all(&file, &buf, 0)?;

        Ok(Self {
            file,
            path: path.to_owned(),
            slot_count,
            mask: slot_count - 1,
            live_count: 0,
        })
    }

    fn open_existing(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let mut buf = [0u8; BUCKET_SIZE as usize];
        pread_exact(&file, &mut buf, 0)?;
        let header = TableHeader::decode(&buf)?;
        Ok(Self {
            file,
            path: path.to_owned(),
            slot_count: header.slot_count,
            mask: header.slot_count - 1,
            live_count: header.live_count,
        })
    }

    #[inline]
    fn slot_offset(slot: u64) -> u64 {
        (slot + 1) * BUCKET_SIZE
    }

    fn read_bucket(&self, slot: u64) -> io::Result<Bucket> {
        let mut buf = [0u8; BUCKET_SIZE as usize];
        pread_exact(&self.file, &mut buf, Self::slot_offset(slot))?;
        Ok(Bucket::decode(&buf))
    }

    fn write_bucket(&self, slot: u64, bucket: &Bucket) -> io::Result<()> {
        let mut buf = [0u8; BUCKET_SIZE as usize];
        bucket.encode(&mut buf);
        pwrite_all(&self.file, &buf, Self::slot_offset(slot))
    }

    fn write_empty(&self, slot: u64) -> io::Result<()> {
        let buf = [0u8; BUCKET_SIZE as usize];
        pwrite_all(&self.file, &buf, Self::slot_offset(slot))
    }

    #[inline]
    fn ideal_slot(&self, txid: &Hash256) -> u64 {
        hash_txid(txid) & self.mask
    }

    fn needs_resize(&self) -> bool {
        self.live_count * LOAD_FACTOR_DEN > self.slot_count * LOAD_FACTOR_NUM
    }

    fn flush_header(&self) -> io::Result<()> {
        let header = TableHeader {
            slot_count: self.slot_count,
            live_count: self.live_count,
        };
        let mut buf = [0u8; BUCKET_SIZE as usize];
        header.encode(&mut buf);
        pwrite_all(&self.file, &buf, 0)
    }

    // ── Public API ──────────────────────────────────────────────────────────

    pub fn get(&self, txid: &Hash256) -> io::Result<Option<DiskTxHandle>> {
        let ideal = self.ideal_slot(txid);
        let mut dist: u8 = 1;
        let mut slot = ideal;
        loop {
            let bucket = self.read_bucket(slot)?;
            if bucket.is_empty() {
                return Ok(None);
            }
            if bucket.probe_distance < dist {
                return Ok(None);
            }
            if bucket.matches(txid) {
                return Ok(Some(bucket.to_handle()));
            }
            dist = dist.saturating_add(1);
            slot = (slot + 1) & self.mask;
            if slot == ideal {
                return Ok(None);
            }
        }
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn insert(&mut self, txid: &Hash256, handle: &DiskTxHandle) -> io::Result<()> {
        if self.needs_resize() {
            self.resize()?;
        }

        let ideal = self.ideal_slot(txid);
        let mut current = Bucket::from_handle(txid, handle, 1);
        let mut slot = ideal;

        loop {
            let existing = self.read_bucket(slot)?;

            if existing.is_empty() {
                self.write_bucket(slot, &current)?;
                self.live_count += 1;
                return Ok(());
            }

            if existing.matches(&Hash256::from_bytes(current.txid)) {
                current.probe_distance = existing.probe_distance;
                self.write_bucket(slot, &current)?;
                return Ok(());
            }

            if existing.probe_distance < current.probe_distance {
                self.write_bucket(slot, &current)?;
                current = existing;
            }

            current.probe_distance = current.probe_distance.saturating_add(1);
            slot = (slot + 1) & self.mask;
            assert!(
                slot != ideal,
                "TxIndex::insert: table full despite load-factor check"
            );
        }
    }

    /// Update an existing entry's handle in-place.
    pub fn update(&self, txid: &Hash256, handle: &DiskTxHandle) -> io::Result<bool> {
        let ideal = self.ideal_slot(txid);
        let mut dist: u8 = 1;
        let mut slot = ideal;
        loop {
            let bucket = self.read_bucket(slot)?;
            if bucket.is_empty() {
                return Ok(false);
            }
            if bucket.probe_distance < dist {
                return Ok(false);
            }
            if bucket.matches(txid) {
                let updated = Bucket::from_handle(txid, handle, bucket.probe_distance);
                self.write_bucket(slot, &updated)?;
                return Ok(true);
            }
            dist = dist.saturating_add(1);
            slot = (slot + 1) & self.mask;
            if slot == ideal {
                return Ok(false);
            }
        }
    }

    pub fn remove(&mut self, txid: &Hash256) -> io::Result<bool> {
        let ideal = self.ideal_slot(txid);
        let mut dist: u8 = 1;
        let mut slot = ideal;

        loop {
            let bucket = self.read_bucket(slot)?;
            if bucket.is_empty() {
                return Ok(false);
            }
            if bucket.probe_distance < dist {
                return Ok(false);
            }
            if bucket.matches(txid) {
                self.backshift(slot)?;
                self.live_count -= 1;
                return Ok(true);
            }
            dist = dist.saturating_add(1);
            slot = (slot + 1) & self.mask;
            if slot == ideal {
                return Ok(false);
            }
        }
    }

    fn backshift(&self, removed_slot: u64) -> io::Result<()> {
        crate::robin_hood::backshift(
            removed_slot,
            self.mask,
            |slot| self.read_bucket(slot),
            |slot, bucket| self.write_bucket(slot, bucket),
            |slot| self.write_empty(slot),
            |b| b.is_empty() || b.probe_distance == 1,
            |b| {
                let mut shifted = b.clone();
                shifted.probe_distance -= 1;
                shifted
            },
        )
    }

    fn resize(&mut self) -> io::Result<()> {
        let new_count = self.slot_count * 2;
        let new_path = self.path.with_extension("new");
        {
            let mut new_table = Self::create(&new_path, new_count)?;
            for slot in 0..self.slot_count {
                let bucket = self.read_bucket(slot)?;
                if !bucket.is_empty() {
                    let txid = Hash256::from_bytes(bucket.txid);
                    let handle = bucket.to_handle();
                    new_table.insert(&txid, &handle)?;
                }
            }
            new_table.flush_header()?;
        }
        std::fs::rename(&new_path, &self.path)?;
        self.file = OpenOptions::new().read(true).write(true).open(&self.path)?;
        self.slot_count = new_count;
        self.mask = new_count - 1;
        Ok(())
    }

    pub fn sync(&self) -> io::Result<()> {
        self.flush_header()?;
        self.file.sync_all()
    }

    #[must_use]
    pub fn len(&self) -> u64 {
        self.live_count
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.live_count == 0
    }

    #[must_use]
    pub fn slot_count(&self) -> u64 {
        self.slot_count
    }

    // ── io_uring batched operations ─────────────────────────────────────────

    #[allow(clippy::cast_sign_loss)]
    fn uring_fd(&self) -> ququmatz::types::RawFd {
        ququmatz::types::RawFd::from_raw(self.file.as_raw_fd() as usize)
    }

    /// Batch-get multiple txids via `io_uring` wave probing.
    /// Returns a Vec of `Option<DiskTxHandle>` in the same order as the input.
    #[allow(clippy::missing_panics_doc)]
    pub fn get_batch_uring(
        &self,
        txids: &[Hash256],
        ring: &mut ququmatz::IoUring,
        arena: &mut Vec<u8>,
    ) -> io::Result<Vec<Option<DiskTxHandle>>> {
        let n = txids.len();
        if n == 0 {
            return Ok(Vec::new());
        }

        let fd = self.uring_fd();
        let bs = BUCKET_SIZE_USIZE;
        let needed = n * bs;
        arena.clear();
        arena.resize(needed, 0u8);

        let mut slots: Vec<u64> = txids.iter().map(|t| self.ideal_slot(t)).collect();
        let mut dists: Vec<u8> = vec![1; n];
        let mut resolved: Vec<bool> = vec![false; n];
        let mut results: Vec<Option<DiskTxHandle>> = vec![None; n];

        loop {
            let mut submitted = 0u32;
            for i in 0..n {
                if resolved[i] {
                    continue;
                }
                let offset = Self::slot_offset(slots[i]);
                let buf_start = i * bs;
                let sqe = unsafe {
                    ququmatz::Sqe::read_ptr(
                        fd,
                        arena[buf_start..].as_mut_ptr(),
                        BUCKET_SIZE_U32,
                        offset,
                    )
                }.user_data(u64::try_from(i).expect("index fits u64"));
                flush_if_full(ring, sqe, &mut submitted)?;
            }

            if submitted == 0 {
                break;
            }

            ring.submit_and_wait(submitted)
                .map_err(|e| io::Error::other(format!("{e:?}")))?;

            while let Some(cqe) = ring.complete() {
                let i = usize::try_from(cqe.user_data()).expect("user_data index fits usize");
                if i >= n { continue; }
                if cqe.raw_result() < 0 {
                    return Err(io::Error::from_raw_os_error(-cqe.raw_result()));
                }

                let buf_start = i * bs;
                let buf: &[u8; 64] = arena[buf_start..buf_start + bs].try_into().expect("bucket-aligned slice");
                let bucket = Bucket::decode(buf);

                if bucket.is_empty() || bucket.probe_distance < dists[i] {
                    resolved[i] = true;
                    continue;
                }
                if bucket.matches(&txids[i]) {
                    results[i] = Some(bucket.to_handle());
                    resolved[i] = true;
                    continue;
                }
                dists[i] = dists[i].saturating_add(1);
                slots[i] = (slots[i] + 1) & self.mask;
            }
        }

        Ok(results)
    }

    /// Batch-insert multiple (txid, handle) pairs via `io_uring` wave probing.
    #[allow(clippy::missing_panics_doc, clippy::too_many_lines)]
    pub fn insert_batch_uring(
        &mut self,
        pairs: &[(Hash256, DiskTxHandle)],
        ring: &mut ququmatz::IoUring,
        arena: &mut Vec<u8>,
        write_arena: &mut Vec<u8>,
    ) -> io::Result<()> {
        if pairs.is_empty() {
            return Ok(());
        }

        let incoming = pairs.len() as u64;
        if (self.live_count + incoming) * LOAD_FACTOR_DEN > self.slot_count * LOAD_FACTOR_NUM {
            self.resize()?;
        }

        let fd = self.uring_fd();
        let bs = BUCKET_SIZE_USIZE;
        let n = pairs.len();
        let needed = n * bs;

        arena.clear();
        arena.resize(needed, 0u8);
        write_arena.clear();
        write_arena.resize(needed, 0u8);

        let mut states: Vec<InsertState> = pairs.iter().map(|(txid, handle)| {
            let ideal = self.ideal_slot(txid);
            InsertState {
                bucket: Bucket::from_handle(txid, handle, 1),
                slot: ideal,
                ideal,
                resolved: false,
            }
        }).collect();

        loop {
            let mut submitted = 0u32;
            for (i, state) in states.iter().enumerate() {
                if state.resolved { continue; }
                let offset = Self::slot_offset(state.slot);
                let buf_start = i * bs;
                let sqe = unsafe {
                    ququmatz::Sqe::read_ptr(
                        fd,
                        arena[buf_start..].as_mut_ptr(),
                        BUCKET_SIZE_U32,
                        offset,
                    )
                }.user_data(u64::try_from(i).expect("index fits u64"));
                flush_if_full(ring, sqe, &mut submitted)?;
            }

            if submitted == 0 { break; }

            ring.submit_and_wait(submitted)
                .map_err(|e| io::Error::other(format!("{e:?}")))?;

            let mut writes: Vec<u64> = Vec::new();
            let mut write_cursor: usize = 0;

            while let Some(cqe) = ring.complete() {
                let i = usize::try_from(cqe.user_data()).expect("user_data index fits usize");
                if i >= n { continue; }
                if cqe.raw_result() < 0 {
                    return Err(io::Error::from_raw_os_error(-cqe.raw_result()));
                }

                let buf_start = i * bs;
                let buf: &[u8; 64] = arena[buf_start..buf_start + bs].try_into().expect("bucket-aligned slice");
                let existing = Bucket::decode(buf);
                let state = &mut states[i];

                let write_to_slot = if existing.is_empty() {
                    self.live_count += 1;
                    state.resolved = true;
                    Some(state.slot)
                } else if existing.matches(&Hash256::from_bytes(state.bucket.txid)) {
                    state.bucket.probe_distance = existing.probe_distance;
                    state.resolved = true;
                    Some(state.slot)
                } else if existing.probe_distance < state.bucket.probe_distance {
                    let slot = state.slot;
                    let to_write = std::mem::replace(&mut state.bucket, existing);
                    state.bucket.probe_distance = state.bucket.probe_distance.saturating_add(1);
                    state.slot = (state.slot + 1) & self.mask;
                    state.ideal = state.slot;
                    let wb = write_cursor * bs;
                    if wb + bs > write_arena.len() {
                        write_arena.resize(wb + bs, 0);
                    }
                    to_write.encode((&mut write_arena[wb..wb + bs]).try_into().expect("bucket-aligned slice"));
                    writes.push(slot);
                    write_cursor += 1;
                    None
                } else {
                    state.bucket.probe_distance = state.bucket.probe_distance.saturating_add(1);
                    state.slot = (state.slot + 1) & self.mask;
                    assert!(
                        state.slot != state.ideal,
                        "TxIndex::insert_batch_uring: table full despite load-factor check"
                    );
                    None
                };

                if let Some(slot) = write_to_slot {
                    let wb = write_cursor * bs;
                    if wb + bs > write_arena.len() {
                        write_arena.resize(wb + bs, 0);
                    }
                    state.bucket.encode((&mut write_arena[wb..wb + bs]).try_into().expect("bucket-aligned slice"));
                    writes.push(slot);
                    write_cursor += 1;
                }
            }

            // Submit writes
            let mut write_count = 0u32;
            for (w_idx, slot) in writes.iter().enumerate() {
                let buf_start = w_idx * bs;
                let offset = Self::slot_offset(*slot);
                let sqe = unsafe {
                    ququmatz::Sqe::write_ptr(
                        fd,
                        write_arena[buf_start..].as_ptr(),
                        BUCKET_SIZE_U32,
                        offset,
                    )
                }.user_data(u64::MAX);
                flush_if_full(ring, sqe, &mut write_count)?;
            }

            if write_count > 0 {
                ring.submit_and_wait(write_count)
                    .map_err(|e| io::Error::other(format!("{e:?}")))?;
                while ring.complete().is_some() {}
            }
        }

        Ok(())
    }

    /// Batch-remove multiple txids via `io_uring`.
    #[allow(clippy::missing_panics_doc)]
    pub fn remove_batch_uring(
        &mut self,
        txids: &[Hash256],
        ring: &mut ququmatz::IoUring,
        arena: &mut Vec<u8>,
    ) -> io::Result<()> {
        if txids.is_empty() {
            return Ok(());
        }

        let n = txids.len();
        let fd = self.uring_fd();
        let bs = BUCKET_SIZE_USIZE;
        let needed = n * bs;
        arena.clear();
        arena.resize(needed, 0u8);

        let mut slots: Vec<u64> = txids.iter().map(|t| self.ideal_slot(t)).collect();
        let mut dists: Vec<u8> = vec![1; n];
        let mut resolved: Vec<bool> = vec![false; n];
        let mut found_slots: Vec<Option<u64>> = vec![None; n];

        // Phase 1: locate each entry
        loop {
            let mut submitted = 0u32;
            for i in 0..n {
                if resolved[i] { continue; }
                let offset = Self::slot_offset(slots[i]);
                let buf_start = i * bs;
                let sqe = unsafe {
                    ququmatz::Sqe::read_ptr(
                        fd,
                        arena[buf_start..].as_mut_ptr(),
                        BUCKET_SIZE_U32,
                        offset,
                    )
                }.user_data(u64::try_from(i).expect("index fits u64"));
                flush_if_full(ring, sqe, &mut submitted)?;
            }

            if submitted == 0 { break; }

            ring.submit_and_wait(submitted)
                .map_err(|e| io::Error::other(format!("{e:?}")))?;

            while let Some(cqe) = ring.complete() {
                let i = usize::try_from(cqe.user_data()).expect("user_data index fits usize");
                if i >= n { continue; }
                if cqe.raw_result() < 0 {
                    return Err(io::Error::from_raw_os_error(-cqe.raw_result()));
                }

                let buf_start = i * bs;
                let buf: &[u8; 64] = arena[buf_start..buf_start + bs].try_into().expect("bucket-aligned slice");
                let bucket = Bucket::decode(buf);

                if bucket.is_empty() || bucket.probe_distance < dists[i] {
                    resolved[i] = true;
                    continue;
                }
                if bucket.matches(&txids[i]) {
                    found_slots[i] = Some(slots[i]);
                    resolved[i] = true;
                    continue;
                }
                dists[i] = dists[i].saturating_add(1);
                slots[i] = (slots[i] + 1) & self.mask;
            }
        }

        // Phase 2: backshift each found entry (synchronous per-entry for correctness)
        for found_slot in found_slots.into_iter().flatten() {
            self.backshift(found_slot)?;
            self.live_count -= 1;
        }

        Ok(())
    }

    /// Iterate over all live entries, calling `f` for each.
    pub fn for_each<F>(&self, mut f: F) -> io::Result<()>
    where
        F: FnMut(Hash256, DiskTxHandle),
    {
        for slot in 0..self.slot_count {
            let bucket = self.read_bucket(slot)?;
            if !bucket.is_empty() {
                f(Hash256::from_bytes(bucket.txid), bucket.to_handle());
            }
        }
        Ok(())
    }
}

// ── I/O helpers ─────────────────────────────────────────────────────────────

fn flush_if_full(
    ring: &mut ququmatz::IoUring,
    sqe: ququmatz::Sqe,
    submitted: &mut u32,
) -> io::Result<()> {
    let copy = sqe;
    match ring.push(sqe) {
        Ok(()) => {
            *submitted += 1;
            Ok(())
        }
        Err(ququmatz::Error::Submit(ququmatz::SubmitError::QueueFull)) => {
            ring.submit_and_wait(*submitted)
                .map_err(|e| io::Error::other(format!("{e:?}")))?;
            while ring.complete().is_some() {}
            *submitted = 0;
            ring.push(copy).map_err(|e| io::Error::other(format!("{e:?}")))?;
            *submitted += 1;
            Ok(())
        }
        Err(e) => Err(io::Error::other(format!("{e:?}"))),
    }
}

fn pwrite_all(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(buf, offset)
}

fn pread_exact(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new() -> Self {
            use std::time::{SystemTime, UNIX_EPOCH};
            let ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
            let path = std::env::temp_dir().join(format!("mantle-tx-index-{}-{}", std::process::id(), ns));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path { &self.0 }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    fn fake_txid(n: u8) -> Hash256 {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        bytes[31] = n.wrapping_mul(7);
        Hash256::from_bytes(bytes)
    }

    fn fake_handle(base: u32, count: u16, height: u32) -> DiskTxHandle {
        DiskTxHandle {
            span: DiskSpan { base, count },
            height: BlockHeight::new(height),
            live: u64::MAX >> (64 - count as u64),
            coinbase: false,
        }
    }

    #[test]
    fn insert_get_remove() {
        let dir = TmpDir::new();
        let mut index = TxIndex::open(&dir.path().join("tx_index.bin")).unwrap();

        let txid = fake_txid(1);
        let handle = fake_handle(0, 3, 100);

        assert!(index.get(&txid).unwrap().is_none());

        index.insert(&txid, &handle).unwrap();
        assert_eq!(index.len(), 1);

        let got = index.get(&txid).unwrap().unwrap();
        assert_eq!(got.span.base, 0);
        assert_eq!(got.span.count, 3);
        assert_eq!(got.height, BlockHeight::new(100));

        assert!(index.remove(&txid).unwrap());
        assert_eq!(index.len(), 0);
        assert!(index.get(&txid).unwrap().is_none());
    }

    #[test]
    fn update_in_place() {
        let dir = TmpDir::new();
        let mut index = TxIndex::open(&dir.path().join("tx_index.bin")).unwrap();

        let txid = fake_txid(42);
        let handle = fake_handle(10, 5, 200);
        index.insert(&txid, &handle).unwrap();

        let mut updated = handle;
        updated.live = 0b1010;
        assert!(index.update(&txid, &updated).unwrap());

        let got = index.get(&txid).unwrap().unwrap();
        assert_eq!(got.live, 0b1010);
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn many_inserts_trigger_resize() {
        let dir = TmpDir::new();
        let mut index = TxIndex::open(&dir.path().join("tx_index.bin")).unwrap();
        assert_eq!(index.slot_count(), 1024);

        for i in 0u16..900 {
            let txid = fake_txid_u16(i);
            let handle = fake_handle(u32::from(i), 2, u32::from(i) + 100);
            index.insert(&txid, &handle).unwrap();
        }

        assert!(index.slot_count() > 1024);
        assert_eq!(index.len(), 900);

        for i in 0u16..900 {
            let txid = fake_txid_u16(i);
            let got = index.get(&txid).unwrap().unwrap();
            assert_eq!(got.span.base, u32::from(i));
        }
    }

    #[test]
    fn reopen_preserves_data() {
        let dir = TmpDir::new();
        let path = dir.path().join("tx_index.bin");
        {
            let mut index = TxIndex::open(&path).unwrap();
            let txid = fake_txid(99);
            let handle = fake_handle(7, 4, 500);
            index.insert(&txid, &handle).unwrap();
            index.sync().unwrap();
        }
        let index = TxIndex::open(&path).unwrap();
        assert_eq!(index.len(), 1);
        let got = index.get(&fake_txid(99)).unwrap().unwrap();
        assert_eq!(got.span.base, 7);
        assert_eq!(got.height, BlockHeight::new(500));
    }

    #[test]
    fn for_each_iterates_all() {
        let dir = TmpDir::new();
        let mut index = TxIndex::open(&dir.path().join("tx_index.bin")).unwrap();

        for i in 0u8..10 {
            index.insert(&fake_txid(i), &fake_handle(u32::from(i), 1, 0)).unwrap();
        }

        let mut count = 0u32;
        index.for_each(|_, _| count += 1).unwrap();
        assert_eq!(count, 10);
    }

    fn fake_txid_u16(n: u16) -> Hash256 {
        let mut bytes = [0u8; 32];
        bytes[0..2].copy_from_slice(&n.to_le_bytes());
        bytes[30..32].copy_from_slice(&n.wrapping_mul(13).to_le_bytes());
        Hash256::from_bytes(bytes)
    }

    #[test]
    fn insert_batch_uring() {
        let dir = TmpDir::new();
        let mut index = TxIndex::open_with_capacity(&dir.path().join("tx_index.bin"), 128).unwrap();
        let mut ring = ququmatz::IoUring::new(256).unwrap();
        let mut arena = Vec::new();
        let mut write_arena = Vec::new();

        let pairs: Vec<(Hash256, DiskTxHandle)> = (0..20u8)
            .map(|i| (fake_txid(i), fake_handle(u32::from(i) * 10, 3, u32::from(i) + 100)))
            .collect();

        index
            .insert_batch_uring(&pairs, &mut ring, &mut arena, &mut write_arena)
            .unwrap();

        assert_eq!(index.len(), 20);
        for (i, (txid, _)) in pairs.iter().enumerate() {
            let got = index.get(txid).unwrap().unwrap_or_else(|| {
                panic!("txid {i} should be present after batch insert")
            });
            assert_eq!(got.span.base, i as u32 * 10);
            assert_eq!(got.span.count, 3);
        }
    }

    #[test]
    fn get_batch_uring() {
        let dir = TmpDir::new();
        let mut index = TxIndex::open_with_capacity(&dir.path().join("tx_index.bin"), 128).unwrap();
        let mut ring = ququmatz::IoUring::new(256).unwrap();
        let mut arena = Vec::new();

        // Insert entries with the normal synchronous path.
        let count = 30u8;
        for i in 0..count {
            let txid = fake_txid(i);
            let handle = fake_handle(u32::from(i), 2, u32::from(i) + 200);
            index.insert(&txid, &handle).unwrap();
        }

        // Batch-lookup all of them via uring.
        let txids: Vec<Hash256> = (0..count).map(fake_txid).collect();
        let results = index.get_batch_uring(&txids, &mut ring, &mut arena).unwrap();

        assert_eq!(results.len(), count as usize);
        for (i, result) in results.iter().enumerate() {
            let handle = result.as_ref().unwrap_or_else(|| {
                panic!("txid {i} should be found in batch lookup")
            });
            assert_eq!(handle.span.base, i as u32);
            assert_eq!(handle.span.count, 2);
            assert_eq!(handle.height, BlockHeight::new(i as u32 + 200));
        }

        // Also test misses.
        let miss_txids: Vec<Hash256> = (200..210u8).map(fake_txid).collect();
        let miss_results = index.get_batch_uring(&miss_txids, &mut ring, &mut arena).unwrap();
        assert!(miss_results.iter().all(Option::is_none));
    }

    #[test]
    fn remove_batch_uring() {
        let dir = TmpDir::new();
        let mut index = TxIndex::open_with_capacity(&dir.path().join("tx_index.bin"), 128).unwrap();
        let mut ring = ququmatz::IoUring::new(256).unwrap();
        let mut arena = Vec::new();

        let count = 30u8;
        for i in 0..count {
            index.insert(&fake_txid(i), &fake_handle(u32::from(i), 2, u32::from(i) + 100)).unwrap();
        }
        assert_eq!(index.len(), 30);

        // Batch-remove txids 10..20.
        let remove_txids: Vec<Hash256> = (10..20u8).map(fake_txid).collect();
        index.remove_batch_uring(&remove_txids, &mut ring, &mut arena).unwrap();

        assert_eq!(index.len(), 20);

        // Removed entries should be gone.
        for i in 10..20u8 {
            assert!(
                index.get(&fake_txid(i)).unwrap().is_none(),
                "txid {i} should have been removed"
            );
        }

        // Remaining entries should still be present.
        for i in (0..10u8).chain(20..count) {
            let got = index.get(&fake_txid(i)).unwrap().unwrap_or_else(|| {
                panic!("txid {i} should still be present")
            });
            assert_eq!(got.span.base, u32::from(i));
        }
    }

    #[test]
    fn robin_hood_displacement_on_insert() {
        // Force Robin Hood displacement by inserting txids that hash to the
        // same slot. With mask=1023 (1024 slots), any txids whose first 8
        // bytes have the same low 10 bits will collide.
        let dir = TmpDir::new();
        let mut index = TxIndex::open(&dir.path().join("tx_index.bin")).unwrap();

        // Create txids that all hash to the same ideal slot.
        // hash_txid reads the first 8 bytes as u64 LE. We set the first 8
        // bytes to values that share the same low 10 bits (mask = 0x3FF).
        let base_slot = 42u64; // arbitrary slot
        let mut txids = Vec::new();
        for i in 0u64..5 {
            let mut bytes = [0u8; 32];
            let val = base_slot + i * 1024; // same low 10 bits
            bytes[0..8].copy_from_slice(&val.to_le_bytes());
            bytes[31] = i as u8; // make them distinguishable
            txids.push(Hash256::from_bytes(bytes));
        }

        // Insert all 5 — each one after the first will probe further.
        // The third+ inserts will find entries with lower probe_distance
        // and displace them (Robin Hood).
        for (i, txid) in txids.iter().enumerate() {
            let handle = fake_handle(i as u32 * 10, 2, i as u32 + 100);
            index.insert(txid, &handle).unwrap();
        }

        assert_eq!(index.len(), 5);

        // All entries must be retrievable.
        for (i, txid) in txids.iter().enumerate() {
            let got = index.get(txid).unwrap().unwrap_or_else(|| {
                panic!("txid {i} should be present after Robin Hood inserts")
            });
            assert_eq!(got.span.base, i as u32 * 10);
            assert_eq!(got.height, BlockHeight::new(i as u32 + 100));
        }

        // Remove all and verify cleanup.
        for txid in &txids {
            assert!(index.remove(txid).unwrap());
        }
        assert_eq!(index.len(), 0);
    }

    #[test]
    fn insert_resize_preserves_all_entries() {
        // Insert enough entries to trigger multiple resizes and verify all survive.
        let dir = TmpDir::new();
        let mut index = TxIndex::open(&dir.path().join("tx_index.bin")).unwrap();
        let initial_slots = index.slot_count();

        // Insert enough to trigger at least one resize.
        let count = (initial_slots * 9 / 10) as u16 + 10; // slightly over load factor
        for i in 0..count {
            let txid = fake_txid_u16(i);
            let handle = fake_handle(u32::from(i), 1, u32::from(i));
            index.insert(&txid, &handle).unwrap();
        }

        assert!(index.slot_count() > initial_slots, "should have resized");
        assert_eq!(index.len(), u64::from(count));

        // Every entry must survive the resize.
        for i in 0..count {
            let txid = fake_txid_u16(i);
            let got = index.get(&txid).unwrap().unwrap_or_else(|| {
                panic!("txid {i} should survive resize")
            });
            assert_eq!(got.span.base, u32::from(i));
        }
    }

    // ── Helper: create txids that all hash to the same ideal slot ───────────
    //
    // `hash_txid` reads the first 8 bytes as u64 LE, then masks with
    // `slot_count - 1`.  By keeping the low `log2(slot_count)` bits the
    // same and varying the higher bits we get distinct txids that all
    // map to the same bucket.

    fn colliding_txid(base_slot: u64, mask: u64, sequence: u64) -> Hash256 {
        // Every value `base_slot + (sequence+1) * (mask+1)` shares the same
        // low bits as `base_slot` under `& mask`.
        let val = base_slot + sequence * (mask + 1);
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&val.to_le_bytes());
        // Put something distinguishing in the tail so Hash256 values differ.
        bytes[24..32].copy_from_slice(&sequence.to_le_bytes());
        Hash256::from_bytes(bytes)
    }

    // ── Tests targeting uncovered branches in insert_batch_uring ────────────

    #[test]
    fn insert_batch_uring_resize_during_batch() {
        // Start with a small table (16 slots). Load factor threshold is
        // 85%, so 14 entries should trigger a resize when we batch-insert
        // 15 entries in one call (live_count + incoming > slot_count * 85/100).
        let dir = TmpDir::new();
        let mut index =
            TxIndex::open_with_capacity(&dir.path().join("tx_index.bin"), 16).unwrap();
        assert_eq!(index.slot_count(), 16);

        let mut ring = ququmatz::IoUring::new(64).unwrap();
        let mut arena = Vec::new();
        let mut write_arena = Vec::new();

        // 15 entries into a 16-slot table → resize path at the top of
        // insert_batch_uring fires before probing begins.
        let pairs: Vec<(Hash256, DiskTxHandle)> = (0..15u16)
            .map(|i| {
                (
                    fake_txid_u16(i),
                    fake_handle(u32::from(i) * 5, 2, u32::from(i) + 1000),
                )
            })
            .collect();

        index
            .insert_batch_uring(&pairs, &mut ring, &mut arena, &mut write_arena)
            .unwrap();

        // Table must have grown.
        assert!(
            index.slot_count() > 16,
            "table should have resized, got {}",
            index.slot_count()
        );
        assert_eq!(index.len(), 15);

        // Every entry must be retrievable.
        for (i, (txid, _)) in pairs.iter().enumerate() {
            let got = index.get(txid).unwrap().unwrap_or_else(|| {
                panic!("entry {i} missing after batch-insert with resize")
            });
            assert_eq!(got.span.base, i as u32 * 5);
            assert_eq!(got.height, BlockHeight::new(i as u32 + 1000));
        }
    }

    #[test]
    fn insert_batch_uring_collision_and_robin_hood() {
        // Use a 128-slot table (mask = 0x7F). Pre-populate 4 entries at
        // the same ideal slot so they occupy slots 50..53 with probe
        // distances 1..4.  Then batch-insert ONE new entry that also
        // collides at slot 50.  This single batch entry must:
        //   - probe past existing entries (multi-round, the `else` branch)
        //   - eventually find an empty slot at 54 and write there
        //
        // Then we repeat with a second batch entry that maps to a
        // DIFFERENT ideal slot (slot 54) so it collides with the entry
        // we just placed.  That entry's probe_distance is 1 (it's in its
        // ideal slot 54… no wait, it's NOT in its ideal slot).
        //
        // Simpler approach: pre-populate 3 at slot 50 (pd 1,2,3), then
        // batch-insert ONE that also collides at slot 50.  It probes past
        // the existing 3 and lands at slot 53 with pd 4.  All 4 entries
        // are retrievable.  This exercises multi-round probing and the
        // write-to-empty branch after multiple probe rounds.
        let dir = TmpDir::new();
        let mut index =
            TxIndex::open_with_capacity(&dir.path().join("tx_index.bin"), 128).unwrap();
        let mask = index.slot_count() - 1;
        assert_eq!(mask, 127);

        let mut ring = ququmatz::IoUring::new(64).unwrap();
        let mut arena = Vec::new();
        let mut write_arena = Vec::new();

        let target_slot: u64 = 50;

        // Synchronously insert 3 entries at the target slot.
        for seq in 0u64..3 {
            let txid = colliding_txid(target_slot, mask, seq);
            assert_eq!(index.ideal_slot(&txid), target_slot);
            let handle = fake_handle(seq as u32, 1, seq as u32);
            index.insert(&txid, &handle).unwrap();
        }
        assert_eq!(index.len(), 3);

        // Batch-insert one MORE entry that collides at the same slot.
        // It will probe past the 3 existing entries (multi-round reads)
        // and land in an empty slot.
        let new_txid = colliding_txid(target_slot, mask, 3);
        assert_eq!(index.ideal_slot(&new_txid), target_slot);
        let new_handle = fake_handle(300, 5, 999);
        let batch_pairs = vec![(new_txid, new_handle)];

        index
            .insert_batch_uring(&batch_pairs, &mut ring, &mut arena, &mut write_arena)
            .unwrap();

        assert_eq!(index.len(), 4);

        // All 4 entries must be retrievable.
        for seq in 0u64..3 {
            let txid = colliding_txid(target_slot, mask, seq);
            let got = index.get(&txid).unwrap().unwrap_or_else(|| {
                panic!("pre-existing entry seq={seq} missing")
            });
            assert_eq!(got.span.base, seq as u32);
        }
        let got = index.get(&new_txid).unwrap().expect("batch-inserted entry missing");
        assert_eq!(got.span.base, 300);
        assert_eq!(got.span.count, 5);
        assert_eq!(got.height, BlockHeight::new(999));

        // Now test Robin Hood displacement via batch insert.
        // Insert an entry at a DIFFERENT ideal slot that is one past the
        // last occupied slot.  Pre-populate slot 60 with pd=1, slot 61
        // with pd=1 (different ideal slot 61).  Then batch-insert an
        // entry whose ideal slot is 60 — it reads slot 60 (occupied,
        // pd 1 == its pd 1 → advance), reads slot 61 (occupied, pd 1
        // < its pd 2 → Robin Hood: displace the slot-61 entry and write
        // ours there, continue inserting the displaced entry).
        let slot_a: u64 = 60;
        let slot_b: u64 = 61;
        let txid_a = colliding_txid(slot_a, mask, 0);
        let txid_b = colliding_txid(slot_b, mask, 0);
        assert_eq!(index.ideal_slot(&txid_a), slot_a);
        assert_eq!(index.ideal_slot(&txid_b), slot_b);

        index.insert(&txid_a, &fake_handle(600, 1, 600)).unwrap();
        index.insert(&txid_b, &fake_handle(610, 1, 610)).unwrap();

        // Batch-insert a second entry at ideal slot 60.
        let txid_a2 = colliding_txid(slot_a, mask, 1);
        assert_eq!(index.ideal_slot(&txid_a2), slot_a);
        let batch2 = vec![(txid_a2, fake_handle(620, 2, 620))];
        index
            .insert_batch_uring(&batch2, &mut ring, &mut arena, &mut write_arena)
            .unwrap();

        // All three entries must be present.
        let ga = index.get(&txid_a).unwrap().expect("txid_a missing");
        assert_eq!(ga.span.base, 600);
        let gb = index.get(&txid_b).unwrap().expect("txid_b missing");
        assert_eq!(gb.span.base, 610);
        let ga2 = index.get(&txid_a2).unwrap().expect("txid_a2 missing");
        assert_eq!(ga2.span.base, 620);
    }

    #[test]
    fn insert_batch_uring_existing_key_update() {
        // Insert entries synchronously, then batch-insert the SAME txids
        // with different handles. The `existing.matches(...)` branch in
        // insert_batch_uring should fire and update in-place without
        // incrementing live_count.
        let dir = TmpDir::new();
        let mut index =
            TxIndex::open_with_capacity(&dir.path().join("tx_index.bin"), 128).unwrap();

        let mut ring = ququmatz::IoUring::new(64).unwrap();
        let mut arena = Vec::new();
        let mut write_arena = Vec::new();

        let count = 10u8;

        // Phase 1: synchronous insert of 10 entries.
        for i in 0..count {
            let txid = fake_txid(i);
            let handle = fake_handle(u32::from(i), 2, u32::from(i) + 100);
            index.insert(&txid, &handle).unwrap();
        }
        assert_eq!(index.len(), u64::from(count));

        // Phase 2: batch-insert the same 10 txids with different handles.
        let updated_pairs: Vec<(Hash256, DiskTxHandle)> = (0..count)
            .map(|i| {
                let txid = fake_txid(i);
                let handle = fake_handle(u32::from(i) + 9000, 4, u32::from(i) + 5000);
                (txid, handle)
            })
            .collect();

        index
            .insert_batch_uring(&updated_pairs, &mut ring, &mut arena, &mut write_arena)
            .unwrap();

        // live_count must NOT have grown — these were updates, not new inserts.
        assert_eq!(index.len(), u64::from(count));

        // Verify the handles were updated.
        for i in 0..count {
            let txid = fake_txid(i);
            let got = index.get(&txid).unwrap().unwrap_or_else(|| {
                panic!("txid {i} should still be present after update")
            });
            assert_eq!(got.span.base, u32::from(i) + 9000);
            assert_eq!(got.span.count, 4);
            assert_eq!(got.height, BlockHeight::new(u32::from(i) + 5000));
        }
    }
}
