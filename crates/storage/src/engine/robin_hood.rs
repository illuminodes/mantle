//! On-disk Robin Hood hash table for the UTXO set.
//!
//! Fixed 88-byte buckets stored in `utxo_table.bin`. Power-of-two slot count.
//! Standard scriptPubKeys (≤34 bytes) stored inline; nonstandard overflow to
//! a sidecar file. Phase 1 uses synchronous `pread`/`pwrite`; Phase 2 replaces
//! with `io_uring` batched I/O.

use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use mantle::collections::{BuildPrehashedHasher, PrehashedMap};
use mantle::primitives::{
    BlockHeader, BlockHeight, Hash256, OutPoint, Satoshi, ScriptPubKey,
};
use mantle_consensus::chain_view::{Coin, TipInfo};

use super::{Engine, EngineError};
use crate::types::{CommitBlockReq, Durability, LookupResult};

const BUCKET_SIZE: usize = 88;
const BUCKET_SIZE_U64: u64 = BUCKET_SIZE as u64;
const MAGIC: [u8; 8] = *b"MANTLEU\0";
const FORMAT_VERSION: u32 = 2;
const INITIAL_SLOT_COUNT: u64 = 1024;
const MAX_INLINE_SPK: usize = 34;
const OVERFLOW_MARKER: u16 = 0xFFFF;
const LOAD_FACTOR_NUM: u64 = 85;
const LOAD_FACTOR_DEN: u64 = 100;

// ── Bucket layout ────────────────────────────────────────────────────────────

#[derive(Clone)]
struct Bucket {
    probe_distance: u16,
    coinbase: bool,
    spk_len: u16,
    height: u32,
    value: u64,
    txid: [u8; 32],
    vout: u32,
    script_pubkey: [u8; MAX_INLINE_SPK],
}

impl Bucket {
    fn is_empty(&self) -> bool {
        self.probe_distance == 0
    }

    fn outpoint(&self) -> OutPoint {
        OutPoint {
            txid: Hash256::from_bytes(self.txid),
            vout: self.vout,
        }
    }

    fn matches(&self, op: &OutPoint) -> bool {
        self.txid == *op.txid.as_bytes() && self.vout == op.vout
    }

    fn to_coin(&self, overflow: &File) -> io::Result<Coin> {
        let script_pubkey = if self.spk_len == OVERFLOW_MARKER {
            let offset = u64::from_le_bytes(self.script_pubkey[..8].try_into().unwrap());
            let spk = read_overflow(overflow, offset)?;
            ScriptPubKey::from_slice(&spk)
        } else {
            ScriptPubKey::from_slice(&self.script_pubkey[..self.spk_len as usize])
        };
        Ok(Coin {
            value: Satoshi::new(self.value),
            script_pubkey,
            height: BlockHeight::new(self.height),
            coinbase: self.coinbase,
        })
    }

    fn from_outpoint_and_coin(
        op: &OutPoint,
        coin: &Coin,
        probe_distance: u16,
        overflow: &mut File,
    ) -> io::Result<Self> {
        let spk = coin.script_pubkey.as_slice();
        let spk_len = spk.len();
        let mut script_pubkey = [0u8; MAX_INLINE_SPK];
        if spk_len <= MAX_INLINE_SPK {
            script_pubkey[..spk_len].copy_from_slice(spk);
        } else {
            let offset = append_overflow(overflow, spk)?;
            script_pubkey[..8].copy_from_slice(&offset.to_le_bytes());
        }
        Ok(Self {
            probe_distance,
            coinbase: coin.coinbase,
            spk_len: if spk_len <= MAX_INLINE_SPK {
                u16::try_from(spk_len).expect("spk_len <= MAX_INLINE_SPK <= u16::MAX")
            } else {
                OVERFLOW_MARKER
            },
            height: coin.height.to_u32(),
            value: coin.value.to_u64(),
            txid: *op.txid.as_bytes(),
            vout: op.vout,
            script_pubkey,
        })
    }

    fn encode(&self, buf: &mut [u8; BUCKET_SIZE]) {
        // Layout (88 bytes total):
        //  [0]      probe_distance low byte
        //  [1]      coinbase
        //  [2..4]   spk_len (u16 le)
        //  [4..8]   height (u32 le)
        //  [8..16]  value (u64 le)
        //  [16..48] txid
        //  [48..52] vout (u32 le)
        //  [52..86] script_pubkey (34 bytes inline)
        //  [86]     probe_distance high byte
        //  [87]     padding
        let pd = self.probe_distance.to_le_bytes();
        buf[0] = pd[0];
        buf[1] = u8::from(self.coinbase);
        buf[2..4].copy_from_slice(&self.spk_len.to_le_bytes());
        buf[4..8].copy_from_slice(&self.height.to_le_bytes());
        buf[8..16].copy_from_slice(&self.value.to_le_bytes());
        buf[16..48].copy_from_slice(&self.txid);
        buf[48..52].copy_from_slice(&self.vout.to_le_bytes());
        buf[52..86].copy_from_slice(&self.script_pubkey);
        buf[86] = pd[1];
        buf[87] = 0;
    }

    fn decode(buf: &[u8; BUCKET_SIZE]) -> Self {
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&buf[16..48]);
        let mut script_pubkey = [0u8; MAX_INLINE_SPK];
        script_pubkey.copy_from_slice(&buf[52..86]);
        Self {
            probe_distance: u16::from_le_bytes([buf[0], buf[86]]),
            coinbase: buf[1] != 0,
            spk_len: u16::from_le_bytes([buf[2], buf[3]]),
            height: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            value: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            txid,
            vout: u32::from_le_bytes([buf[48], buf[49], buf[50], buf[51]]),
            script_pubkey,
        }
    }
}

// ── Insert state (used by insert_batch_uring) ────────────────────────────────

pub struct InsertState {
    bucket: Bucket,
    slot: u64,
    ideal: u64,
    resolved: bool,
}

// ── Hash function ────────────────────────────────────────────────────────────

fn hash_outpoint(op: &OutPoint) -> u64 {
    // OutPoint.txid is SHA-256d output — first 8 bytes are uniformly distributed.
    u64::from_le_bytes(op.txid.as_bytes()[..8].try_into().unwrap())
}

// ── File header ──────────────────────────────────────────────────────────────

struct TableHeader {
    slot_count: u64,
    live_count: u64,
}

impl TableHeader {
    fn encode(&self, buf: &mut [u8; BUCKET_SIZE]) {
        *buf = [0u8; BUCKET_SIZE];
        buf[0..8].copy_from_slice(&MAGIC);
        buf[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        buf[12..20].copy_from_slice(&self.slot_count.to_le_bytes());
        buf[20..28].copy_from_slice(&self.live_count.to_le_bytes());
    }

    fn decode(buf: &[u8; BUCKET_SIZE]) -> io::Result<Self> {
        if buf[0..8] != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad UTXO table magic",
            ));
        }
        let version = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        if version != FORMAT_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported UTXO table version {version}"),
            ));
        }
        Ok(Self {
            slot_count: u64::from_le_bytes(buf[12..20].try_into().unwrap()),
            live_count: u64::from_le_bytes(buf[20..28].try_into().unwrap()),
        })
    }
}

// ── RobinHoodTable ───────────────────────────────────────────────────────────

pub struct RobinHoodTable {
    file: File,
    path: PathBuf,
    overflow: File,
    slot_count: u64,
    mask: u64,
    live_count: u64,
    fixed_fd: Option<ququmatz::types::RawFd>,
}

impl RobinHoodTable {
    /// # Errors
    /// Returns an error if the file cannot be created or opened.
    pub fn open(path: &Path) -> io::Result<Self> {
        if path.exists() {
            Self::open_existing(path)
        } else {
            Self::create(path, INITIAL_SLOT_COUNT)
        }
    }

    /// # Errors
    /// Returns an error if the file cannot be created or opened.
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

        let file_size = (slot_count + 1) * BUCKET_SIZE_U64;
        file.set_len(file_size)?;

        let header = TableHeader {
            slot_count,
            live_count: 0,
        };
        let mut buf = [0u8; BUCKET_SIZE];
        header.encode(&mut buf);
        pwrite_all(&file, &buf, 0)?;

        let overflow = open_overflow_file(&overflow_path(path))?;

        Ok(Self {
            file,
            path: path.to_owned(),
            overflow,
            slot_count,
            mask: slot_count - 1,
            live_count: 0,
            fixed_fd: None,
        })
    }

    fn open_existing(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let mut buf = [0u8; BUCKET_SIZE];
        pread_exact(&file, &mut buf, 0)?;
        let header = TableHeader::decode(&buf)?;
        let overflow = open_overflow_file(&overflow_path(path))?;
        Ok(Self {
            file,
            path: path.to_owned(),
            overflow,
            slot_count: header.slot_count,
            mask: header.slot_count - 1,
            live_count: header.live_count,
            fixed_fd: None,
        })
    }

    fn slot_offset(slot: u64) -> u64 {
        (slot + 1) * BUCKET_SIZE_U64
    }

    fn read_bucket(&self, slot: u64) -> io::Result<Bucket> {
        let mut buf = [0u8; BUCKET_SIZE];
        pread_exact(&self.file, &mut buf, Self::slot_offset(slot))?;
        Ok(Bucket::decode(&buf))
    }

    fn write_bucket(&self, slot: u64, bucket: &Bucket) -> io::Result<()> {
        let mut buf = [0u8; BUCKET_SIZE];
        bucket.encode(&mut buf);
        pwrite_all(&self.file, &buf, Self::slot_offset(slot))
    }

    fn write_empty(&self, slot: u64) -> io::Result<()> {
        let buf = [0u8; BUCKET_SIZE];
        pwrite_all(&self.file, &buf, Self::slot_offset(slot))
    }

    fn ideal_slot(&self, op: &OutPoint) -> u64 {
        hash_outpoint(op) & self.mask
    }

    fn needs_resize(&self) -> bool {
        self.live_count * LOAD_FACTOR_DEN > self.slot_count * LOAD_FACTOR_NUM
    }

    fn flush_header(&self) -> io::Result<()> {
        let header = TableHeader {
            slot_count: self.slot_count,
            live_count: self.live_count,
        };
        let mut buf = [0u8; BUCKET_SIZE];
        header.encode(&mut buf);
        pwrite_all(&self.file, &buf, 0)
    }

    #[cfg(unix)]
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub fn fd(&self) -> ququmatz::types::RawFd {
        use std::os::unix::io::AsRawFd;
        ququmatz::types::RawFd::from_raw(self.file.as_raw_fd() as usize)
    }

    pub fn set_fixed_fd(&mut self, fd: ququmatz::types::RawFd) {
        self.fixed_fd = Some(fd);
    }

    fn uring_fd(&self) -> ququmatz::types::RawFd {
        self.fixed_fd.unwrap_or_else(|| self.fd())
    }

    fn apply_fd_flags(&self, sqe: ququmatz::Sqe) -> ququmatz::Sqe {
        if self.fixed_fd.is_some() {
            sqe.fixed_file()
        } else {
            sqe
        }
    }

    /// Queue a read whose completion the caller must see. Returns `false` when
    /// the submission queue is full; the caller leaves the entry for the next
    /// round instead of draining completions it still needs.
    fn try_push_read(&self, ring: &mut ququmatz::IoUring, sqe: ququmatz::Sqe) -> io::Result<bool> {
        match ring.push(self.apply_fd_flags(sqe)) {
            Ok(()) => Ok(true),
            Err(ququmatz::Error::Submit(ququmatz::SubmitError::QueueFull)) => Ok(false),
            Err(e) => Err(uring_err(e)),
        }
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /// # Errors
    /// Returns an error on I/O failure.
    pub fn get(&self, op: &OutPoint) -> io::Result<Option<Coin>> {
        let ideal = self.ideal_slot(op);
        let mut dist: u16 = 1;
        let mut slot = ideal;
        loop {
            let bucket = self.read_bucket(slot)?;
            if bucket.is_empty() {
                return Ok(None);
            }
            if bucket.probe_distance < dist {
                return Ok(None);
            }
            if bucket.matches(op) {
                return Ok(Some(bucket.to_coin(&self.overflow)?));
            }
            dist += 1;
            slot = (slot + 1) & self.mask;
            if slot == ideal {
                return Ok(None);
            }
        }
    }

    /// # Errors
    /// Returns an error on I/O failure.
    ///
    /// # Panics
    /// Panics if the table is full despite the load-factor resize check, which
    /// indicates a bug in the resize logic.
    pub fn insert(&mut self, op: &OutPoint, coin: &Coin) -> io::Result<()> {
        if self.needs_resize() {
            self.resize()?;
        }

        let ideal = self.ideal_slot(op);
        let mut current = Bucket::from_outpoint_and_coin(op, coin, 1, &mut self.overflow)?;
        let mut slot = ideal;

        loop {
            let existing = self.read_bucket(slot)?;

            if existing.is_empty() {
                self.write_bucket(slot, &current)?;
                self.live_count += 1;
                return Ok(());
            }

            if existing.matches(&current.outpoint()) {
                current.probe_distance = existing.probe_distance;
                self.write_bucket(slot, &current)?;
                return Ok(());
            }

            if existing.probe_distance < current.probe_distance {
                self.write_bucket(slot, &current)?;
                current = existing;
            }

            current.probe_distance += 1;
            slot = (slot + 1) & self.mask;
            assert!(
                slot != ideal,
                "RobinHoodTable::insert: table full despite load-factor check"
            );
        }
    }

    /// # Errors
    /// Returns an error on I/O failure.
    pub fn remove(&mut self, op: &OutPoint) -> io::Result<bool> {
        let ideal = self.ideal_slot(op);
        let mut dist: u16 = 1;
        let mut slot = ideal;

        loop {
            let bucket = self.read_bucket(slot)?;
            if bucket.is_empty() {
                return Ok(false);
            }
            if bucket.probe_distance < dist {
                return Ok(false);
            }
            if bucket.matches(op) {
                self.backshift(slot)?;
                self.live_count -= 1;
                return Ok(true);
            }
            dist += 1;
            slot = (slot + 1) & self.mask;
            if slot == ideal {
                return Ok(false);
            }
        }
    }

    fn backshift(&self, removed_slot: u64) -> io::Result<()> {
        let mut prev = removed_slot;
        let mut slot = (removed_slot + 1) & self.mask;
        loop {
            let bucket = self.read_bucket(slot)?;
            if bucket.is_empty() || bucket.probe_distance == 1 {
                return self.write_empty(prev);
            }
            let mut shifted = bucket.clone();
            shifted.probe_distance -= 1;
            self.write_bucket(prev, &shifted)?;
            prev = slot;
            slot = (slot + 1) & self.mask;
        }
    }

    fn resize(&mut self) -> io::Result<()> {
        let new_count = self.slot_count * 2;
        let new_path = self.path.with_extension("new");
        {
            let mut new_table = Self::create(&new_path, new_count)?;
            for slot in 0..self.slot_count {
                let bucket = self.read_bucket(slot)?;
                if !bucket.is_empty() {
                    let op = bucket.outpoint();
                    let coin = bucket.to_coin(&self.overflow)?;
                    new_table.insert(&op, &coin)?;
                }
            }
            new_table.flush_header()?;
        }
        std::fs::rename(&new_path, &self.path)?;
        let new_overflow_path = overflow_path(&new_path);
        let old_overflow_path = overflow_path(&self.path);
        std::fs::rename(&new_overflow_path, &old_overflow_path)?;
        self.file = OpenOptions::new().read(true).write(true).open(&self.path)?;
        self.overflow = open_overflow_file(&old_overflow_path)?;
        self.slot_count = new_count;
        self.mask = new_count - 1;
        self.fixed_fd = None;
        Ok(())
    }

    #[must_use]
    pub fn len(&self) -> u64 {
        self.live_count
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.live_count == 0
    }

    /// # Errors
    /// Returns an error on I/O failure.
    pub fn sync(&self) -> io::Result<()> {
        self.flush_header()?;
        self.overflow.sync_all()?;
        self.file.sync_all()
    }

    /// Batched insert using `io_uring`.
    ///
    /// Inserts all `(OutPoint, Coin)` pairs via wave-based Robin Hood probing.
    /// Each wave submits one `pread` per pending entry (its current probe slot),
    /// waits for all completions, then either writes the entry into an empty slot,
    /// displaces a weaker incumbent (Robin Hood steal), or advances to the next
    /// probe slot.  Typically completes in 2–4 waves for realistic load factors.
    ///
    /// Scratch vecs (`arena`, `states`) are passed in by the caller so they can
    /// be reused across calls without re-allocating.
    ///
    /// # Errors
    /// Returns an error on I/O failure.
    ///
    /// # Panics
    /// Panics if the table fills despite the load-factor check (bug in resize
    /// logic) or if the `live_count` would overflow.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)]
    pub fn insert_batch_uring(
        &mut self,
        pairs: &[(OutPoint, Coin)],
        ring: &mut ququmatz::IoUring,
        arena: &mut Vec<u8>,
        write_arena: &mut Vec<u8>,
        states: &mut Vec<InsertState>,
    ) -> io::Result<()> {
        if pairs.is_empty() {
            return Ok(());
        }

        let incoming = u64::try_from(pairs.len()).expect("batch fits u64");
        while (self.live_count + incoming) * LOAD_FACTOR_DEN > self.slot_count * LOAD_FACTOR_NUM {
            self.resize()?;
        }

        let fd = self.uring_fd();

        states.clear();
        for (op, coin) in pairs {
            let ideal = self.ideal_slot(op);
            states.push(InsertState {
                bucket: Bucket::from_outpoint_and_coin(op, coin, 1, &mut self.overflow)?,
                slot: ideal,
                ideal,
                resolved: false,
            });
        }

        let n = states.len();
        let needed = n * BUCKET_SIZE;
        arena.clear();
        arena.resize(needed, 0u8);
        write_arena.clear();
        write_arena.resize(needed, 0u8);

        let mut claimed: std::collections::HashSet<u64> = std::collections::HashSet::new();
        loop {
            let mut submitted = 0u32;
            claimed.clear();
            for (i, state) in states.iter().enumerate() {
                if state.resolved || claimed.contains(&state.slot) {
                    continue;
                }
                let offset = Self::slot_offset(state.slot);
                let buf_start = i * BUCKET_SIZE;
                let sqe = unsafe {
                    ququmatz::Sqe::read_ptr(
                        fd,
                        arena[buf_start..].as_mut_ptr(),
                        u32::try_from(BUCKET_SIZE).expect("BUCKET_SIZE fits u32"),
                        offset,
                    )
                }
                .user_data(u64::try_from(i).expect("index fits u64"));
                if !self.try_push_read(ring, sqe)? {
                    break;
                }
                claimed.insert(state.slot);
                submitted += 1;
            }

            if submitted == 0 {
                break;
            }

            ring.submit_and_wait(submitted).map_err(uring_err)?;

            let mut writes: Vec<u64> = Vec::new();
            let mut write_cursor: usize = 0;

            while let Some(cqe) = ring.complete() {
                let i = usize::try_from(cqe.user_data()).expect("user_data index fits usize");
                if i >= n {
                    continue;
                }
                let res = cqe.raw_result();
                if res < 0 {
                    return Err(io::Error::from_raw_os_error(-res));
                }

                let buf_start = i * BUCKET_SIZE;
                let buf: &[u8; BUCKET_SIZE] = arena[buf_start..buf_start + BUCKET_SIZE]
                    .try_into()
                    .expect("bucket-aligned slice");
                let existing = Bucket::decode(buf);

                let state = &mut states[i];

                let write_to_slot = if existing.is_empty() {
                    self.live_count += 1;
                    state.resolved = true;
                    Some(state.slot)
                } else if existing.matches(&state.bucket.outpoint()) {
                    state.bucket.probe_distance = existing.probe_distance;
                    state.resolved = true;
                    Some(state.slot)
                } else if existing.probe_distance < state.bucket.probe_distance {
                    let slot = state.slot;
                    let to_write = std::mem::replace(&mut state.bucket, existing);
                    state.bucket.probe_distance += 1;
                    state.slot = (state.slot + 1) & self.mask;
                    state.ideal = state.slot;
                    // Encode the entry we're placing (not the displaced one).
                    let wb = write_cursor * BUCKET_SIZE;
                    if wb + BUCKET_SIZE > write_arena.len() {
                        write_arena.resize(wb + BUCKET_SIZE, 0);
                    }
                    to_write.encode((&mut write_arena[wb..wb + BUCKET_SIZE]).try_into().expect("bucket-aligned slice"));
                    writes.push(slot);
                    write_cursor += 1;
                    None // already handled
                } else {
                    state.bucket.probe_distance += 1;
                    state.slot = (state.slot + 1) & self.mask;
                    assert!(
                        state.slot != state.ideal,
                        "insert_batch_uring: table full despite load-factor check"
                    );
                    None
                };

                if let Some(slot) = write_to_slot {
                    let wb = write_cursor * BUCKET_SIZE;
                    if wb + BUCKET_SIZE > write_arena.len() {
                        write_arena.resize(wb + BUCKET_SIZE, 0);
                    }
                    state
                        .bucket
                        .encode((&mut write_arena[wb..wb + BUCKET_SIZE]).try_into().expect("bucket-aligned slice"));
                    writes.push(slot);
                    write_cursor += 1;
                }
            }

            let mut write_count = 0u32;
            for (w_idx, slot) in writes.iter().enumerate() {
                let buf_start = w_idx * BUCKET_SIZE;
                let offset = Self::slot_offset(*slot);
                let sqe = unsafe {
                    ququmatz::Sqe::write_ptr(
                        fd,
                        write_arena[buf_start..].as_ptr(),
                        u32::try_from(BUCKET_SIZE).expect("BUCKET_SIZE fits u32"),
                        offset,
                    )
                }
                .user_data(u64::MAX);
                flush_if_full(ring, self.apply_fd_flags(sqe), &mut write_count)?;
            }

            if write_count > 0 {
                ring.submit_and_wait(write_count).map_err(uring_err)?;
                while ring.complete().is_some() {}
            }
        }

        Ok(())
    }

    /// Batched delete.
    ///
    /// Locates every target with batched `io_uring` reads, then removes the
    /// found entries one at a time. Each backshift reads the table as the
    /// previous one left it; running backshifts concurrently corrupts
    /// chains that overlap.
    ///
    /// Scratch vecs are passed in by the caller for reuse.
    ///
    /// # Errors
    /// Returns an error on I/O failure.
    ///
    /// # Panics
    /// Panics only on internal invariant violations that cannot occur in
    /// correct usage (infallible `u32`/`usize` casts on compile-time constants).
    #[allow(clippy::too_many_arguments)]
    pub fn remove_batch_uring(
        &mut self,
        ops: &[OutPoint],
        ring: &mut ququmatz::IoUring,
        arena: &mut Vec<u8>,
        slots: &mut Vec<u64>,
        dists: &mut Vec<u16>,
        resolved: &mut Vec<bool>,
    ) -> io::Result<()> {
        if ops.is_empty() {
            return Ok(());
        }

        let found_slots =
            self.remove_probe_phase(ops, ring, arena, slots, dists, resolved)?;

        for (op, found) in ops.iter().zip(&found_slots) {
            if found.is_some() {
                self.remove(op)?;
            }
        }
        Ok(())
    }

    /// Phase 1 of [`remove_batch_uring`]: probe the table to locate each
    /// target slot (mirrors `get_batch_uring`).
    ///
    /// Returns `found_slots` where `found_slots[i] == Some(slot)` once the
    /// entry for `ops[i]` has been located.
    #[allow(clippy::too_many_arguments)]
    fn remove_probe_phase(
        &self,
        ops: &[OutPoint],
        ring: &mut ququmatz::IoUring,
        arena: &mut Vec<u8>,
        slots: &mut Vec<u64>,
        dists: &mut Vec<u16>,
        resolved: &mut Vec<bool>,
    ) -> io::Result<Vec<Option<u64>>> {
        let n = ops.len();
        let fd = self.uring_fd();

        slots.clear();
        slots.extend(ops.iter().map(|op| self.ideal_slot(op)));
        dists.clear();
        dists.resize(n, 1);
        resolved.clear();
        resolved.resize(n, false);

        let mut found_slots: Vec<Option<u64>> = vec![None; n];

        let needed = n * BUCKET_SIZE;
        arena.clear();
        arena.resize(needed, 0u8);

        loop {
            let mut submitted = 0u32;
            for i in 0..n {
                if resolved[i] {
                    continue;
                }
                let offset = Self::slot_offset(slots[i]);
                let buf_start = i * BUCKET_SIZE;
                let sqe = unsafe {
                    ququmatz::Sqe::read_ptr(
                        fd,
                        arena[buf_start..].as_mut_ptr(),
                        u32::try_from(BUCKET_SIZE).expect("BUCKET_SIZE fits u32"),
                        offset,
                    )
                }
                .user_data(u64::try_from(i).expect("index fits u64"));
                if !self.try_push_read(ring, sqe)? {
                    break;
                }
                submitted += 1;
            }

            if submitted == 0 {
                break;
            }

            ring.submit_and_wait(submitted).map_err(uring_err)?;

            while let Some(cqe) = ring.complete() {
                let i = usize::try_from(cqe.user_data()).expect("user_data index fits usize");
                if i >= n {
                    continue;
                }
                let res = cqe.raw_result();
                if res < 0 {
                    return Err(io::Error::from_raw_os_error(-res));
                }

                let buf_start = i * BUCKET_SIZE;
                let buf: &[u8; BUCKET_SIZE] = arena[buf_start..buf_start + BUCKET_SIZE]
                    .try_into()
                    .expect("bucket-aligned slice");
                let bucket = Bucket::decode(buf);

                if bucket.is_empty() || bucket.probe_distance < dists[i] {
                    resolved[i] = true; // not found
                    continue;
                }
                if bucket.matches(&ops[i]) {
                    found_slots[i] = Some(slots[i]);
                    resolved[i] = true;
                    continue;
                }
                dists[i] += 1;
                slots[i] = (slots[i] + 1) & self.mask;
            }
        }

        Ok(found_slots)
    }

    /// Batched UTXO lookup using `io_uring`.
    ///
    /// Submits one `pread` per outpoint for the ideal bucket, waits for all
    /// completions, then submits follow-up reads for Robin Hood probe chains.
    /// Typically completes in 1–2 rounds.
    ///
    /// `arena` must be pre-sized to `ops.len() * BUCKET_SIZE`. Results are
    /// written into `results` in the same order as `ops`.
    ///
    /// # Errors
    /// Returns an error on I/O failure.
    ///
    /// # Panics
    /// Panics if `arena` is shorter than `ops.len() * BUCKET_SIZE`.
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::too_many_arguments)]
    pub fn get_batch_uring(
        &self,
        ops: &[OutPoint],
        results: &mut Vec<Option<Coin>>,
        ring: &mut ququmatz::IoUring,
        arena: &mut Vec<u8>,
        slots: &mut Vec<u64>,
        dists: &mut Vec<u16>,
        resolved: &mut Vec<bool>,
    ) -> io::Result<()> {
        let n = ops.len();
        if n == 0 {
            return Ok(());
        }

        results.clear();
        results.resize(n, None);

        let fd = self.uring_fd();

        // Per-outpoint state: current probe slot and distance.
        slots.clear();
        slots.extend(ops.iter().map(|op| self.ideal_slot(op)));
        dists.clear();
        dists.resize(n, 1);
        resolved.clear();
        resolved.resize(n, false);
        // Arena for bucket reads — reused across calls, capacity grows to max block size.
        let needed = n * BUCKET_SIZE;
        arena.clear();
        arena.resize(needed, 0);

        loop {
            let mut submitted = 0u32;
            for i in 0..n {
                if resolved[i] {
                    continue;
                }
                let offset = Self::slot_offset(slots[i]);
                let buf_start = i * BUCKET_SIZE;
                let sqe = unsafe {
                    ququmatz::Sqe::read_ptr(
                        fd,
                        arena[buf_start..].as_mut_ptr(),
                        u32::try_from(BUCKET_SIZE).expect("BUCKET_SIZE fits u32"),
                        offset,
                    )
                }
                .user_data(u64::try_from(i).expect("index fits u64"));
                if !self.try_push_read(ring, sqe)? {
                    break;
                }
                submitted += 1;
            }

            if submitted == 0 {
                break;
            }

            ring.submit_and_wait(submitted).map_err(uring_err)?;

            while let Some(cqe) = ring.complete() {
                let i = usize::try_from(cqe.user_data()).expect("user_data index fits usize");
                if i >= n {
                    continue;
                }

                let res = cqe.raw_result();
                if res < 0 {
                    return Err(io::Error::from_raw_os_error(-res));
                }

                let buf_start = i * BUCKET_SIZE;
                let buf: &[u8; BUCKET_SIZE] = arena[buf_start..buf_start + BUCKET_SIZE]
                    .try_into()
                    .expect("bucket-aligned slice");
                let bucket = Bucket::decode(buf);

                if bucket.is_empty() || bucket.probe_distance < dists[i] {
                    // Not found — empty slot or Robin Hood invariant says stop.
                    resolved[i] = true;
                    continue;
                }

                if bucket.matches(&ops[i]) {
                    // Found.
                    results[i] = Some(bucket.to_coin(&self.overflow)?);
                    resolved[i] = true;
                    continue;
                }

                dists[i] += 1;
                slots[i] = (slots[i] + 1) & self.mask;
            }
        }

        Ok(())
    }
}

// ── RobinHoodEngine — Engine trait impl ──────────────────────────────────────

use super::header_io::{
    parse_header_record, HeaderStore,
    HEADER_RECORD_SIZE, HEADER_RECORD_SIZE_U64,
};

const STORAGE_RING_ENTRIES: u32 = 32768;

/// Shallowest ring depth accepted when locked-memory pressure forces the
/// preferred depth down. Submission paths drain and retry on a full queue, so
/// a shallower ring costs throughput but never correctness.
const STORAGE_RING_ENTRIES_MIN: u32 = 256;

const WRITE_BUFFER_FLUSH_THRESHOLD: usize = 500_000;

// ── Write buffer ─────────────────────────────────────────────────────────────

enum BufferEntry {
    Live(Coin),
}

// SAFETY: RobinHoodEngine is only accessed from the single storage thread
// after being moved there via spawn(). The IoUring raw pointers inside are
// thread-local to that thread — no concurrent access.
unsafe impl Send for RobinHoodEngine {}

pub struct RobinHoodEngine {
    data_dir: PathBuf,
    table: RobinHoodTable,
    ring: ququmatz::IoUring,
    write_buffer: PrehashedMap<OutPoint, BufferEntry>,
    pending_disk_deletes: Vec<OutPoint>,
    read_arena: Vec<u8>,
    // Scratch buffers reused across read_coins / get_batch_uring calls.
    rc_results: Vec<Option<Coin>>,
    rc_disk_indices: Vec<usize>,
    rc_disk_outpoints: Vec<OutPoint>,
    rc_disk_coins: Vec<Option<Coin>>,
    uring_slots: Vec<u64>,
    uring_dists: Vec<u16>,
    uring_resolved: Vec<bool>,
    // Scratch buffers reused across flush_write_buffer calls.
    wb_pairs: Vec<(OutPoint, Coin)>,
    wb_insert_arena: Vec<u8>,
    wb_write_arena: Vec<u8>,
    wb_insert_states: Vec<InsertState>,
    wb_del_slots: Vec<u64>,
    wb_del_dists: Vec<u16>,
    wb_del_resolved: Vec<bool>,
    headers: HeaderStore,
}

impl RobinHoodEngine {
    #[allow(clippy::missing_errors_doc)]
    pub fn open(data_dir: &Path) -> Result<Self, EngineError> {
        std::fs::create_dir_all(data_dir)?;

        let table_path = data_dir.join("utxo_table.bin");

        let table = RobinHoodTable::open(&table_path)?;
        let headers = HeaderStore::open(data_dir)?;

        let mut ring = crate::engine::ring_budget::RingBudget::new(
            STORAGE_RING_ENTRIES,
            STORAGE_RING_ENTRIES_MIN,
        )
        .build()?;

        let table_fd = table.fd();
        ring.register_files(&[table_fd.as_i32()])
            .map_err(|e| EngineError::Io(uring_err(e)))?;

        let mut table = table;
        table.set_fixed_fd(ququmatz::types::RawFd::from_raw(0));

        let mut engine = Self {
            data_dir: data_dir.to_owned(),
            table,
            ring,
            write_buffer: PrehashedMap::with_capacity_and_hasher(
                WRITE_BUFFER_FLUSH_THRESHOLD,
                BuildPrehashedHasher,
            ),
            pending_disk_deletes: Vec::with_capacity(WRITE_BUFFER_FLUSH_THRESHOLD),
            read_arena: Vec::new(),
            rc_results: Vec::new(),
            rc_disk_indices: Vec::new(),
            rc_disk_outpoints: Vec::new(),
            rc_disk_coins: Vec::new(),
            uring_slots: Vec::new(),
            uring_dists: Vec::new(),
            uring_resolved: Vec::new(),
            wb_pairs: Vec::new(),
            wb_insert_arena: Vec::new(),
            wb_write_arena: Vec::new(),
            wb_insert_states: Vec::new(),
            wb_del_slots: Vec::new(),
            wb_del_dists: Vec::new(),
            wb_del_resolved: Vec::new(),
            headers,
        };
        engine.recover()?;
        Ok(engine)
    }

    fn refresh_registered_fd(&mut self) -> Result<(), EngineError> {
        let new_fd = self.table.fd();
        self.ring
            .update_registered_files(&[new_fd.as_i32()], 0)
            .map_err(|e| EngineError::Io(uring_err(e)))?;
        self.table
            .set_fixed_fd(ququmatz::types::RawFd::from_raw(0));
        Ok(())
    }

    fn flush_write_buffer(&mut self) -> Result<(), EngineError> {
        self.wb_pairs.clear();
        for (op, entry) in self.write_buffer.drain() {
            let BufferEntry::Live(coin) = entry;
            self.wb_pairs.push((op, coin));
        }

        if !self.wb_pairs.is_empty() {
            self.table
                .insert_batch_uring(
                    &self.wb_pairs,
                    &mut self.ring,
                    &mut self.wb_insert_arena,
                    &mut self.wb_write_arena,
                    &mut self.wb_insert_states,
                )
                ?;
            self.wb_pairs.clear();
            self.refresh_registered_fd()?;
        }

        let deletes = std::mem::take(&mut self.pending_disk_deletes);
        self.table
            .remove_batch_uring(
                &deletes,
                &mut self.ring,
                &mut self.read_arena,
                &mut self.wb_del_slots,
                &mut self.wb_del_dists,
                &mut self.wb_del_resolved,
            )?;
        self.pending_disk_deletes = deletes;

        Ok(())
    }
}

impl Engine for RobinHoodEngine {
    fn read_coin(&mut self, op: &OutPoint) -> Result<Option<Coin>, EngineError> {
        match self.write_buffer.get(op) {
            Some(BufferEntry::Live(coin)) => return Ok(Some(coin.clone())),
            None => {}
        }
        self.table.get(op).map_err(EngineError::from)
    }

    fn read_coins(
        &mut self,
        ops: &[OutPoint],
        out: &mut Vec<LookupResult>,
    ) -> Result<(), EngineError> {
        let results = &mut self.rc_results;
        let disk_indices = &mut self.rc_disk_indices;
        let disk_outpoints = &mut self.rc_disk_outpoints;
        let disk_coins = &mut self.rc_disk_coins;

        results.clear();
        disk_indices.clear();
        disk_outpoints.clear();

        out.reserve(ops.len());
        results.resize(ops.len(), None);

        for (i, &op) in ops.iter().enumerate() {
            match self.write_buffer.get(&op) {
                Some(BufferEntry::Live(coin)) => results[i] = Some(coin.clone()),
                None => {
                    disk_indices.push(i);
                    disk_outpoints.push(op);
                }
            }
        }

        if !disk_outpoints.is_empty() {
            self.table
                .get_batch_uring(
                    disk_outpoints,
                    disk_coins,
                    &mut self.ring,
                    &mut self.read_arena,
                    &mut self.uring_slots,
                    &mut self.uring_dists,
                    &mut self.uring_resolved,
                )?;
            for (j, &i) in disk_indices.iter().enumerate() {
                if let Some(coin) = disk_coins.get(j).and_then(|c| c.as_ref()) {
                    results[i] = Some(coin.clone());
                }
            }
        }

        for (i, &op) in ops.iter().enumerate() {
            out.push(LookupResult {
                outpoint: op,
                coin: results[i].take(),
            });
        }
        Ok(())
    }

    fn write_block(&mut self, req: &CommitBlockReq) -> Result<(), EngineError> {
        for nc in req.created {
            let coin = Coin {
                value: nc.value,
                script_pubkey: ScriptPubKey::from_slice(nc.script_pubkey),
                height: nc.height,
                coinbase: nc.coinbase,
            };
            self.write_buffer
                .insert(nc.outpoint, BufferEntry::Live(coin));
        }
        for op in req.spent {
            match self.write_buffer.remove(op) {
                Some(BufferEntry::Live(_)) => {
                    // Created and spent within the buffer window — elided.
                }
                None => {
                    // Coin is on disk — schedule deletion for next flush.
                    self.pending_disk_deletes.push(*op);
                }
            }
        }

        // Only flush when durability requires persistence. With Memory
        // durability (bench / test paths) the buffer is never written to disk,
        // so flushing here would be O(N) synchronous pread/pwrite for no
        // benefit — just let the buffer grow.
        if req.durability != Durability::Memory
            && self.write_buffer.len() + self.pending_disk_deletes.len()
                > WRITE_BUFFER_FLUSH_THRESHOLD
        {
            self.flush_write_buffer()?;
        }

        debug_assert_eq!(
            req.header.prev_block(),
            req.prev_hash,
            "CommitBlockReq.header.prev_block must match req.prev_hash"
        );
        self.headers
            .write_block_header(req.height, &req.header, req.hash)?;
        Ok(())
    }

    fn read_header(&self, hash: &Hash256) -> Result<Option<BlockHeader>, EngineError> {
        let Some(&height_u32) = self.headers.index.get(hash) else {
            return Ok(None);
        };
        self.read_header_at(BlockHeight::new(height_u32))
    }

    fn read_header_at(&self, h: BlockHeight) -> Result<Option<BlockHeader>, EngineError> {
        let offset = u64::from(h.to_u32()) * HEADER_RECORD_SIZE_U64;
        if offset + HEADER_RECORD_SIZE_U64 > self.headers.write_len {
            return Ok(None);
        }
        let mut buf = [0u8; HEADER_RECORD_SIZE];
        pread_exact(self.headers.file(), &mut buf, offset)?;
        Ok(Some(parse_header_record(&buf)))
    }

    fn write_header(&mut self, h: BlockHeight, header: &BlockHeader) -> Result<(), EngineError> {
        self.headers.write_header(h, header)
    }

    fn flush(&mut self, d: Durability) -> Result<(), EngineError> {
        if d == Durability::Synced {
            self.flush_write_buffer()?;
            self.table.sync()?;
            self.headers.sync_checkpoint()?;
        }
        Ok(())
    }

    fn recover(&mut self) -> Result<TipInfo, EngineError> {
        self.headers.recover()?;

        // If there's no checkpoint and no headers, the UTXO table is stale —
        // wipe it so a fresh start doesn't inherit data from a previous run.
        if self.headers.index.is_empty() && !self.table.is_empty() {
            let table_path = self.data_dir.join("utxo_table.bin");
            self.table = RobinHoodTable::create(&table_path, INITIAL_SLOT_COUNT)?;
        }

        Ok(self.headers.tip.clone())
    }

    fn tip(&self) -> TipInfo {
        self.headers.tip.clone()
    }
}

// ── Overflow sidecar helpers ────────────────────────────────────────────────
//
// Layout per record: u32_le(len) + script_bytes.  The offset stored in the
// bucket's inline script_pubkey[0..8] points to the start of the record.

fn overflow_path(table_path: &Path) -> PathBuf {
    table_path.with_extension("overflow")
}

fn open_overflow_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

fn append_overflow(file: &mut File, spk: &[u8]) -> io::Result<u64> {
    let offset = file.seek(SeekFrom::End(0))?;
    let len = u32::try_from(spk.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "script > 4 GiB"))?;
    file.write_all(&len.to_le_bytes())?;
    file.write_all(spk)?;
    Ok(offset)
}

fn read_overflow(file: &File, offset: u64) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    pread_exact(file, &mut len_buf, offset)?;
    let len = usize::try_from(u32::from_le_bytes(len_buf)).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "overflow script length exceeds usize",
        )
    })?;
    let mut buf = vec![0u8; len];
    pread_exact(file, &mut buf, offset + 4)?;
    Ok(buf)
}

fn uring_err(e: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{e:?}"))
}

// ── pread/pwrite helpers ─────────────────────────────────────────────────────

#[cfg(unix)]
fn pread_exact(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(unix)]
fn pwrite_all(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(buf, offset)
}

/// Push `sqe` onto the ring. If the SQ is full, submit and drain all in-flight
/// entries first, then retry. `submitted` tracks how many SQEs are pending
/// for the caller's final `submit_and_wait`.
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
            ring.submit_and_wait(*submitted).map_err(uring_err)?;
            while ring.complete().is_some() {}
            *submitted = 0;
            ring.push(copy).map_err(uring_err)?;
            *submitted += 1;
            Ok(())
        }
        Err(e) => Err(uring_err(e)),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use mantle::primitives::{BlockTime, BlockVersion, CompactBits, Nonce};

    struct TmpFile(PathBuf);
    impl TmpFile {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "mantle-rh-{}-{}-{}",
                name,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .subsec_nanos()
            ));
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TmpFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let new_path = self.0.with_extension("new");
            let _ = std::fs::remove_file(&new_path);
            let _ = std::fs::remove_file(overflow_path(&self.0));
            let _ = std::fs::remove_file(overflow_path(&new_path));
        }
    }

    fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }

    fn make_coin(value: u64, spk: &[u8]) -> Coin {
        Coin {
            value: Satoshi::new(value),
            script_pubkey: ScriptPubKey::from_slice(spk),
            height: BlockHeight::new(100),
            coinbase: false,
        }
    }

    fn make_op(i: u8) -> OutPoint {
        OutPoint {
            txid: Hash256::from_bytes([i; 32]),
            vout: 0,
        }
    }

    #[test]
    fn create_and_reopen() {
        let tmp = TmpFile::new("create");
        {
            let table = RobinHoodTable::open(tmp.path()).unwrap();
            assert_eq!(table.len(), 0);
            assert!(table.is_empty());
        }
        {
            let table = RobinHoodTable::open(tmp.path()).unwrap();
            assert_eq!(table.len(), 0);
        }
    }

    #[test]
    fn insert_get_remove() {
        let tmp = TmpFile::new("basic");
        let mut table = RobinHoodTable::open(tmp.path()).unwrap();

        let op = make_op(1);
        let coin = make_coin(5_000_000_000, &[0x51]);

        assert!(table.get(&op).unwrap().is_none());

        table.insert(&op, &coin).unwrap();
        assert_eq!(table.len(), 1);

        let got = table.get(&op).unwrap().unwrap();
        assert_eq!(got.value.to_u64(), 5_000_000_000);
        assert_eq!(got.script_pubkey.as_slice(), &[0x51]);

        assert!(table.remove(&op).unwrap());
        assert_eq!(table.len(), 0);
        assert!(table.get(&op).unwrap().is_none());
        assert!(!table.remove(&op).unwrap());
    }

    #[test]
    fn insert_many_triggers_resize() {
        let tmp = TmpFile::new("resize");
        let mut table = RobinHoodTable::open_with_capacity(tmp.path(), 16).unwrap();
        let initial_slots = table.slot_count;
        assert_eq!(initial_slots, 16);

        for i in 0..200u8 {
            let op = make_op(i);
            let coin = make_coin(u64::from(i) * 1000, &[0x51]);
            table.insert(&op, &coin).unwrap();
        }
        assert_eq!(table.len(), 200);
        assert!(table.slot_count > initial_slots);

        for i in 0..200u8 {
            let op = make_op(i);
            let got = table.get(&op).unwrap().unwrap();
            assert_eq!(got.value.to_u64(), u64::from(i) * 1000);
        }
    }

    #[test]
    fn persistence_across_reopen() {
        let tmp = TmpFile::new("persist");
        let op = make_op(42);
        let coin = make_coin(999, &[0x76, 0xa9]);
        {
            let mut table = RobinHoodTable::open(tmp.path()).unwrap();
            table.insert(&op, &coin).unwrap();
            table.sync().unwrap();
        }
        {
            let table = RobinHoodTable::open(tmp.path()).unwrap();
            assert_eq!(table.len(), 1);
            let got = table.get(&op).unwrap().unwrap();
            assert_eq!(got.value.to_u64(), 999);
            assert_eq!(got.script_pubkey.as_slice(), &[0x76, 0xa9]);
        }
    }

    #[test]
    fn remove_with_backshift() {
        let tmp = TmpFile::new("backshift");
        let mut table = RobinHoodTable::open_with_capacity(tmp.path(), 16).unwrap();

        let ops: Vec<OutPoint> = (0..10u8).map(make_op).collect();
        for (i, op) in ops.iter().enumerate() {
            let coin = make_coin(u64::try_from(i).unwrap(), &[0x51]);
            table.insert(op, &coin).unwrap();
        }

        table.remove(&ops[3]).unwrap();
        table.remove(&ops[7]).unwrap();
        assert_eq!(table.len(), 8);

        for (i, op) in ops.iter().enumerate() {
            if i == 3 || i == 7 {
                assert!(table.get(op).unwrap().is_none());
            } else {
                let got = table.get(op).unwrap().unwrap();
                assert_eq!(got.value.to_u64(), u64::try_from(i).unwrap());
            }
        }
    }

    #[test]
    fn update_existing_key() {
        let tmp = TmpFile::new("update");
        let mut table = RobinHoodTable::open(tmp.path()).unwrap();

        let op = make_op(5);
        table.insert(&op, &make_coin(100, &[0x51])).unwrap();
        table.insert(&op, &make_coin(200, &[0x51])).unwrap();

        assert_eq!(table.len(), 1);
        assert_eq!(table.get(&op).unwrap().unwrap().value.to_u64(), 200);
    }

    #[test]
    fn standard_script_lengths() {
        let tmp = TmpFile::new("scripts");
        let mut table = RobinHoodTable::open(tmp.path()).unwrap();

        let cases: &[(&str, &[u8])] = &[
            (
                "p2pkh",
                &[
                    0x76, 0xa9, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                    18, 19, 20, 0x88, 0xac,
                ],
            ),
            (
                "p2sh",
                &[
                    0xa9, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                    20, 0x87,
                ],
            ),
            (
                "p2wpkh",
                &[
                    0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                    20,
                ],
            ),
            ("p2wsh", &{
                let mut v = vec![0x00, 0x20];
                v.extend_from_slice(&[0xAB; 32]);
                v
            }),
            ("p2tr", &{
                let mut v = vec![0x51, 0x20];
                v.extend_from_slice(&[0xCD; 32]);
                v
            }),
        ];

        for (i, (name, spk)) in cases.iter().enumerate() {
            let op = make_op(u8::try_from(i).expect("test index fits u8"));
            let coin = make_coin(u64::try_from(i).unwrap(), spk);
            table.insert(&op, &coin).unwrap();
            let got = table.get(&op).unwrap().unwrap();
            assert_eq!(
                got.script_pubkey.as_slice(),
                *spk,
                "{name} script round-trip failed"
            );
        }
    }

    #[test]
    fn overflow_script_roundtrip() {
        let tmp = TmpFile::new("overflow");
        let mut table = RobinHoodTable::open(tmp.path()).unwrap();

        // 80-byte bare multisig — exceeds MAX_INLINE_SPK (34).
        let big_spk: Vec<u8> = (0..80).collect();
        let op = make_op(1);
        let coin = make_coin(42_000, &big_spk);
        table.insert(&op, &coin).unwrap();

        let got = table.get(&op).unwrap().unwrap();
        assert_eq!(got.script_pubkey.as_slice(), &big_spk[..]);
        assert_eq!(got.value.to_u64(), 42_000);
    }

    #[test]
    fn overflow_survives_resize() {
        let tmp = TmpFile::new("overflow-resize");
        let mut table = RobinHoodTable::open_with_capacity(tmp.path(), 16).unwrap();

        let big_spk: Vec<u8> = (0..64).collect();
        let overflow_op = make_op(200);
        table
            .insert(&overflow_op, &make_coin(999, &big_spk))
            .unwrap();

        // Fill until resize triggers.
        for i in 0..100u8 {
            table
                .insert(&make_op(i), &make_coin(u64::from(i), &[0x51]))
                .unwrap();
        }
        assert!(table.slot_count > 16);

        let got = table.get(&overflow_op).unwrap().unwrap();
        assert_eq!(got.script_pubkey.as_slice(), &big_spk[..]);
        assert_eq!(got.value.to_u64(), 999);
    }

    #[test]
    fn batched_uring_lookup() {
        let tmp = TmpFile::new("uring-batch");
        let mut table = RobinHoodTable::open_with_capacity(tmp.path(), 64).unwrap();
        let mut ring = crate::engine::ring_budget::RingBudget::new(256, 16).build().unwrap();
        let mut arena = Vec::new();

        let count = 50u8;
        for i in 0..count {
            let op = make_op(i);
            let coin = make_coin(u64::from(i) * 100, &[0x51]);
            table.insert(&op, &coin).unwrap();
        }

        let ops: Vec<OutPoint> = (0..count).map(make_op).collect();
        let mut results = Vec::new();
        let (mut slots, mut dists, mut resolved) = (Vec::new(), Vec::new(), Vec::new());
        table
            .get_batch_uring(
                &ops,
                &mut results,
                &mut ring,
                &mut arena,
                &mut slots,
                &mut dists,
                &mut resolved,
            )
            .unwrap();

        assert_eq!(results.len(), count as usize);
        for (i, result) in results.iter().enumerate() {
            let coin = result.as_ref().unwrap();
            assert_eq!(coin.value.to_u64(), i as u64 * 100);
        }

        // Also test miss: outpoints not in the table.
        let miss_ops: Vec<OutPoint> = (200..210u8).map(make_op).collect();
        let mut miss_results = Vec::new();
        table
            .get_batch_uring(
                &miss_ops,
                &mut miss_results,
                &mut ring,
                &mut arena,
                &mut slots,
                &mut dists,
                &mut resolved,
            )
            .unwrap();
        assert!(miss_results.iter().all(Option::is_none));
    }

    #[test]
    fn batched_uring_remove() {
        let tmp = TmpFile::new("uring-remove");
        let mut table = RobinHoodTable::open_with_capacity(tmp.path(), 128).unwrap();
        let mut ring = crate::engine::ring_budget::RingBudget::new(256, 16).build().unwrap();
        let mut arena = Vec::new();

        let count = 50u8;
        for i in 0..count {
            let op = make_op(i);
            let coin = make_coin(u64::from(i) * 100, &[0x51]);
            table.insert(&op, &coin).unwrap();
        }
        assert_eq!(table.len(), 50);

        // Remove outpoints 10..20 via uring batch.
        let remove_ops: Vec<OutPoint> = (10..20u8).map(make_op).collect();
        let (mut slots, mut dists, mut resolved) = (Vec::new(), Vec::new(), Vec::new());
        table
            .remove_batch_uring(
                &remove_ops,
                &mut ring,
                &mut arena,
                &mut slots,
                &mut dists,
                &mut resolved,
            )
            .unwrap();

        assert_eq!(table.len(), 40);

        // Verify removed entries are gone.
        for i in 10..20u8 {
            let op = make_op(i);
            assert!(
                table.get(&op).unwrap().is_none(),
                "outpoint {i} should have been removed"
            );
        }

        // Verify remaining entries are still present with correct values.
        for i in (0..10u8).chain(20..count) {
            let op = make_op(i);
            let coin = table.get(&op).unwrap().unwrap_or_else(|| {
                panic!("outpoint {i} should still be present")
            });
            assert_eq!(coin.value.to_u64(), u64::from(i) * 100);
        }
    }

    #[test]
    fn write_buffer_elides_create_then_spend() {
        let dir = TmpFile::new("wb-elide");
        std::fs::create_dir_all(dir.path()).unwrap();
        let mut eng = RobinHoodEngine::open(dir.path()).unwrap();

        let op = OutPoint {
            txid: Hash256::from_bytes([10u8; 32]),
            vout: 0,
        };

        // Create a coin — goes into write buffer, not disk.
        let req1 = CommitBlockReq {
            token: crate::types::ReqToken(1),
            height: BlockHeight::new(1),
            hash: Hash256::from_bytes([11u8; 32]),
            prev_hash: Hash256::ZERO,
            header: make_header(0),
            created: &[mantle_consensus::chain_view::NewCoin {
                outpoint: op,
                value: Satoshi::new(1000),
                script_pubkey: &[0x51],
                coinbase: false,
                height: BlockHeight::new(1),
            }],
            spent: &[],
            block_bytes: None,
            durability: Durability::Memory,
        };
        eng.write_block(&req1).unwrap();

        // Read from buffer — should find it.
        assert!(eng.read_coin(&op).unwrap().is_some());

        // Disk table should be empty (not flushed yet).
        assert_eq!(eng.table.len(), 0);

        // Spend the coin — should elide (never hits disk).
        let req2 = CommitBlockReq {
            token: crate::types::ReqToken(2),
            height: BlockHeight::new(2),
            hash: Hash256::from_bytes([12u8; 32]),
            prev_hash: Hash256::from_bytes([11u8; 32]),
            header: {
                let mut h = make_header(0);
                h.set_prev_block(Hash256::from_bytes([11u8; 32]));
                h
            },
            created: &[],
            spent: &[op],
            block_bytes: None,
            durability: Durability::Memory,
        };
        eng.write_block(&req2).unwrap();

        // Coin should be gone from buffer and disk.
        assert!(eng.read_coin(&op).unwrap().is_none());
        assert_eq!(eng.table.len(), 0);
        assert!(eng.pending_disk_deletes.is_empty());
    }

    #[test]
    fn write_buffer_flushes_on_sync() {
        let dir = TmpFile::new("wb-flush");
        std::fs::create_dir_all(dir.path()).unwrap();
        let mut eng = RobinHoodEngine::open(dir.path()).unwrap();

        let op = OutPoint {
            txid: Hash256::from_bytes([20u8; 32]),
            vout: 0,
        };
        let req = CommitBlockReq {
            token: crate::types::ReqToken(1),
            height: BlockHeight::new(1),
            hash: Hash256::from_bytes([21u8; 32]),
            prev_hash: Hash256::ZERO,
            header: make_header(0),
            created: &[mantle_consensus::chain_view::NewCoin {
                outpoint: op,
                value: Satoshi::new(2000),
                script_pubkey: &[0x51],
                coinbase: false,
                height: BlockHeight::new(1),
            }],
            spent: &[],
            block_bytes: None,
            durability: Durability::Memory,
        };
        eng.write_block(&req).unwrap();

        // Not on disk yet.
        assert_eq!(eng.table.len(), 0);

        // Flush with Synced durability.
        eng.flush(Durability::Synced).unwrap();

        // Now on disk.
        assert_eq!(eng.table.len(), 1);
        assert!(eng.write_buffer.is_empty());
    }

    // ── Engine integration tests ─────────────────────────────────────────

    fn make_header(time: u32) -> BlockHeader {
        BlockHeader::new(
            BlockVersion::new(1),
            Hash256::ZERO,
            Hash256::ZERO,
            BlockTime::new(time),
            CompactBits::new(0x1d00_ffff),
            Nonce::new(0),
        )
    }

    #[test]
    fn engine_write_and_read_coin() {
        let dir = TmpFile::new("eng-coin");
        std::fs::create_dir_all(dir.path()).unwrap();
        let mut eng = RobinHoodEngine::open(dir.path()).unwrap();

        let op = OutPoint {
            txid: Hash256::from_bytes([1u8; 32]),
            vout: 0,
        };
        let req = CommitBlockReq {
            token: crate::types::ReqToken(1),
            height: BlockHeight::new(1),
            hash: Hash256::from_bytes([2u8; 32]),
            prev_hash: Hash256::ZERO,
            header: make_header(0),
            created: &[mantle_consensus::chain_view::NewCoin {
                outpoint: op,
                value: Satoshi::new(5_000_000_000),
                script_pubkey: &[0x51],
                coinbase: true,
                height: BlockHeight::new(1),
            }],
            spent: &[],
            block_bytes: None,
            durability: Durability::Memory,
        };
        eng.write_block(&req).unwrap();
        let coin = eng.read_coin(&op).unwrap().unwrap();
        assert_eq!(coin.value.to_u64(), 5_000_000_000);
        assert!(coin.coinbase);
    }

    #[test]
    fn engine_spend_removes_coin() {
        let dir = TmpFile::new("eng-spend");
        std::fs::create_dir_all(dir.path()).unwrap();
        let mut eng = RobinHoodEngine::open(dir.path()).unwrap();

        let op = OutPoint {
            txid: Hash256::from_bytes([3u8; 32]),
            vout: 0,
        };
        let req1 = CommitBlockReq {
            token: crate::types::ReqToken(1),
            height: BlockHeight::new(10),
            hash: Hash256::from_bytes([4u8; 32]),
            prev_hash: Hash256::ZERO,
            header: make_header(0),
            created: &[mantle_consensus::chain_view::NewCoin {
                outpoint: op,
                value: Satoshi::new(1000),
                script_pubkey: &[],
                coinbase: false,
                height: BlockHeight::new(10),
            }],
            spent: &[],
            block_bytes: None,
            durability: Durability::Memory,
        };
        eng.write_block(&req1).unwrap();
        assert!(eng.read_coin(&op).unwrap().is_some());

        let req2 = CommitBlockReq {
            token: crate::types::ReqToken(2),
            height: BlockHeight::new(11),
            hash: Hash256::from_bytes([5u8; 32]),
            prev_hash: Hash256::from_bytes([4u8; 32]),
            header: {
                let mut h = make_header(0);
                h.set_prev_block(Hash256::from_bytes([4u8; 32]));
                h
            },
            created: &[],
            spent: &[op],
            block_bytes: None,
            durability: Durability::Memory,
        };
        eng.write_block(&req2).unwrap();
        assert!(eng.read_coin(&op).unwrap().is_none());
    }

    #[test]
    fn engine_header_roundtrip() {
        let dir = TmpFile::new("eng-hdr");
        std::fs::create_dir_all(dir.path()).unwrap();
        let mut eng = RobinHoodEngine::open(dir.path()).unwrap();

        let h = BlockHeader::new(
            BlockVersion::new(0x2000_0007_i32),
            Hash256::from_bytes([0x11; 32]),
            Hash256::from_bytes([0x22; 32]),
            BlockTime::new(12_345),
            CompactBits::new(0x1d00_ffff),
            Nonce::new(0xdead_beef),
        );
        eng.write_header(BlockHeight::new(0), &h).unwrap();
        let got = eng.read_header_at(BlockHeight::new(0)).unwrap().unwrap();
        assert_eq!(got.version(), h.version());
        assert_eq!(got.prev_block(), h.prev_block());
        assert_eq!(got.merkle_root(), h.merkle_root());
        assert_eq!(got.time(), h.time());
        assert_eq!(got.bits().to_u32(), h.bits().to_u32());
        assert_eq!(got.nonce(), h.nonce());
    }

    #[test]
    fn write_buffer_survives_2000_blocks() {
        let dir = TmpFile::new("wb-2k");
        std::fs::create_dir_all(dir.path()).unwrap();
        let mut eng = RobinHoodEngine::open(dir.path()).unwrap();

        let target_height = 1965u32;
        let mut prev_hash = Hash256::ZERO;

        for h in 1..=2000u32 {
            let mut txid_bytes = [0u8; 32];
            txid_bytes[..4].copy_from_slice(&h.to_le_bytes());
            let txid = Hash256::from_bytes(txid_bytes);
            let op = OutPoint { txid, vout: 0 };

            let mut hash_bytes = [0u8; 32];
            hash_bytes[..4].copy_from_slice(&(h + 10000).to_le_bytes());
            let block_hash = Hash256::from_bytes(hash_bytes);

            let req = CommitBlockReq {
                token: crate::types::ReqToken(u64::from(h)),
                height: BlockHeight::new(h),
                hash: block_hash,
                prev_hash,
                header: {
                    let mut h = make_header(h);
                    h.set_prev_block(prev_hash);
                    h
                },
                created: &[mantle_consensus::chain_view::NewCoin {
                    outpoint: op,
                    value: Satoshi::new(5_000_000_000),
                    script_pubkey: &[
                        0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
                    ],
                    coinbase: true,
                    height: BlockHeight::new(h),
                }],
                spent: &[],
                block_bytes: None,
                durability: Durability::Memory,
            };
            eng.write_block(&req).unwrap();
            prev_hash = block_hash;
        }

        // Look up the coin from block 1965 via read_coin (single).
        let mut target_txid = [0u8; 32];
        target_txid[..4].copy_from_slice(&target_height.to_le_bytes());
        let target_op = OutPoint {
            txid: Hash256::from_bytes(target_txid),
            vout: 0,
        };
        let coin = eng.read_coin(&target_op).unwrap();
        assert!(
            coin.is_some(),
            "read_coin should find block 1965 coinbase in write buffer"
        );
        assert_eq!(coin.unwrap().height.to_u32(), target_height);

        // Look up via read_coins (batch) — this is the path validate_and_commit uses.
        let mut out = Vec::new();
        eng.read_coins(&[target_op], &mut out).unwrap();
        assert_eq!(out.len(), 1);
        assert!(
            out[0].coin.is_some(),
            "read_coins should find block 1965 coinbase in write buffer"
        );
        assert_eq!(out[0].coin.as_ref().unwrap().height.to_u32(), target_height);
    }

    #[test]
    fn write_buffer_survives_2000_blocks_via_handle() {
        let dir = TmpFile::new("wb-2k-handle");
        std::fs::create_dir_all(dir.path()).unwrap();
        let eng = RobinHoodEngine::open(dir.path()).unwrap();

        crate::with_storage(eng, |handle| {
            let target_height = 1965u32;
            let mut prev_hash = Hash256::ZERO;

            for h in 1..=2000u32 {
                let mut txid_bytes = [0u8; 32];
                txid_bytes[..4].copy_from_slice(&h.to_le_bytes());
                let op = OutPoint {
                    txid: Hash256::from_bytes(txid_bytes),
                    vout: 0,
                };

                let mut hash_bytes = [0u8; 32];
                hash_bytes[..4].copy_from_slice(&(h + 10000).to_le_bytes());
                let block_hash = Hash256::from_bytes(hash_bytes);

                let spk = [
                    0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
                ];
                let created = [mantle_consensus::chain_view::NewCoin {
                    outpoint: op,
                    value: Satoshi::new(5_000_000_000),
                    script_pubkey: &spk,
                    coinbase: true,
                    height: BlockHeight::new(h),
                }];
                handle
                    .commit_block_borrowed(CommitBlockReq {
                        token: crate::types::ReqToken(u64::from(h)),
                        height: BlockHeight::new(h),
                        hash: block_hash,
                        prev_hash,
                        header: {
                            let mut h = make_header(h);
                            h.set_prev_block(prev_hash);
                            h
                        },
                        created: &created,
                        spent: &[],
                        block_bytes: None,
                        durability: Durability::Memory,
                    })
                    .expect("commit_block_borrowed");
                prev_hash = block_hash;
            }

            let mut target_txid = [0u8; 32];
            target_txid[..4].copy_from_slice(&target_height.to_le_bytes());
            let target_op = OutPoint {
                txid: Hash256::from_bytes(target_txid),
                vout: 0,
            };

            let mut out = Vec::new();
            handle
                .lookup_coins_borrowed(&[target_op], &mut out)
                .expect("lookup_coins_borrowed");
            assert_eq!(out.len(), 1, "should get exactly one result");
            assert!(
                out[0].coin.is_some(),
                "handle lookup should find block 1965 coinbase in write buffer"
            );
            assert_eq!(out[0].coin.as_ref().unwrap().height.to_u32(), target_height);
        })
        .expect("with_storage");
    }

    #[test]
    fn write_buffer_survives_2000_blocks_via_open_robin_hood() {
        let dir = TmpFile::new("wb-2k-rh");
        std::fs::create_dir_all(dir.path()).unwrap();

        let mut handle =
            crate::StorageHandle::open_robin_hood(dir.path()).expect("open_robin_hood");

        let target_height = 1965u32;
        let mut prev_hash = Hash256::ZERO;

        for h in 1..=2000u32 {
            let mut txid_bytes = [0u8; 32];
            txid_bytes[..4].copy_from_slice(&h.to_le_bytes());
            let op = OutPoint {
                txid: Hash256::from_bytes(txid_bytes),
                vout: 0,
            };

            let mut hash_bytes = [0u8; 32];
            hash_bytes[..4].copy_from_slice(&(h + 10000).to_le_bytes());
            let block_hash = Hash256::from_bytes(hash_bytes);

            let spk = [
                0x00u8, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
            ];
            let created = [mantle_consensus::chain_view::NewCoin {
                outpoint: op,
                value: Satoshi::new(5_000_000_000),
                script_pubkey: &spk,
                coinbase: true,
                height: BlockHeight::new(h),
            }];
            handle
                .commit_block_borrowed(CommitBlockReq {
                    token: crate::types::ReqToken(u64::from(h)),
                    height: BlockHeight::new(h),
                    hash: block_hash,
                    prev_hash,
                    header: {
                        let mut h = make_header(h);
                        h.set_prev_block(prev_hash);
                        h
                    },
                    created: &created,
                    spent: &[],
                    block_bytes: None,
                    durability: Durability::Memory,
                })
                .expect("commit_block_borrowed");
            prev_hash = block_hash;
        }

        let mut target_txid = [0u8; 32];
        target_txid[..4].copy_from_slice(&target_height.to_le_bytes());
        let target_op = OutPoint {
            txid: Hash256::from_bytes(target_txid),
            vout: 0,
        };

        let mut out = Vec::new();
        handle
            .lookup_coins_borrowed(&[target_op], &mut out)
            .expect("lookup_coins_borrowed");
        assert_eq!(out.len(), 1, "should get exactly one result");
        assert!(
            out[0].coin.is_some(),
            "open_robin_hood handle should find block 1965 coinbase in write buffer"
        );
        assert_eq!(out[0].coin.as_ref().unwrap().height.to_u32(), target_height);

        handle.shutdown().expect("shutdown");
    }

    #[test]
    fn replay_block_1965_then_lookup_for_2067() {
        use mantle::codec::Decode;
        use mantle::primitives::{Block, TxHash};
        use mantle_consensus::chain_view::NewCoin;

        let dir = TmpFile::new("replay-1965");
        std::fs::create_dir_all(dir.path()).unwrap();
        let mut eng = RobinHoodEngine::open(dir.path()).unwrap();

        let block_1965_hex = "000000205ede77c0cb37c34615b3b20a2a240dfb5ba9e4eb45ca84c91fbf263d0000000081f980c7703039a91a9a7c5365f9902975e2944209629fa58fc36dd1a25e183192433966ffff001d865e2a0001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402ad0700ffffffff0200f2052a01000000160014690912f95570260001bc668468269a82b382fd040000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000";
        let block_bytes = decode_hex(block_1965_hex).unwrap();
        let block = Block::decode(&mut std::io::Cursor::new(&block_bytes)).unwrap();

        let coinbase = &block.transactions[0];
        let txid = coinbase.txid().unwrap();
        eprintln!("coinbase txid (internal): {:?}", &txid.as_bytes()[..4]);

        let mut created = Vec::new();
        for (vout, output) in coinbase.outputs.iter().enumerate() {
            created.push(NewCoin {
                outpoint: OutPoint {
                    txid,
                    #[allow(clippy::cast_possible_truncation)]
                    vout: vout as u32,
                },
                value: output.value,
                script_pubkey: output.script_pubkey.as_slice(),
                coinbase: true,
                height: BlockHeight::new(1965),
            });
        }

        let hash = block.header.hash();
        eng.write_block(&CommitBlockReq {
            token: crate::types::ReqToken(1965),
            height: BlockHeight::new(1965),
            hash,
            prev_hash: block.header.prev_block(),
            header: block.header,
            created: &created,
            spent: &[],
            block_bytes: None,
            durability: Durability::Memory,
        })
        .unwrap();

        // Now look up the outpoint that block 2067 tries to spend
        let block_2067_hex = "00000020f009a7425a6b0962bc12d3a2d2497588182202b9b59d46d33835ad0300000000b2ed3db0e5f468e9faa29b50a2bbe9cb041c40c2ecd53156a3d51173719e8e6c6d4b3966c0ff3f1c65c7bf0102010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0a021308062f4077697a2fffffffff028df2052a01000000160014a54e2a1ec06389203887661535ed118b7d0538890000000000000000266a24aa21a9ed2b5052d89d429b990f78f48e0b0332e2caf6cea8c878168f9847e5b6b3daff8201200000000000000000000000000000000000000000000000000000000000000000000000000200000000010181f980c7703039a91a9a7c5365f9902975e2944209629fa58fc36dd1a25e18310000000000fdffffff022005000000000000160014a54e2a1ec06389203887661535ed118b7d05388953ec052a01000000160014505c4fa6dd11e0b3a0b0211cfa3ddf33958dd8bd02473044022032d0f97adef165f69da184332f68c91fc27782444aacc213088ac7c5ba6fe3a602206d7dbb42dcc78ba1661bb3106bb8ae1b424036592c0a16c9b51adcad46731eba012102476e8b9914532f15a42d34840b3b143746d1bb35d536055a276b41f1321479e111080000";
        let block_2067_bytes = decode_hex(block_2067_hex).unwrap();
        let block_2067 = Block::decode(&mut std::io::Cursor::new(&block_2067_bytes)).unwrap();

        let spend_input = &block_2067.transactions[1].inputs[0];
        let spend_op = spend_input.previous_output;
        eprintln!(
            "block 2067 tx[1] input[0] spends {:?}:{}",
            &spend_op.txid.as_bytes()[..4],
            spend_op.vout
        );
        eprintln!("txids match: {}", spend_op.txid == txid);

        let coin = eng.read_coin(&spend_op).unwrap();
        assert!(
            coin.is_some(),
            "engine should find block 1965 coinbase output 0"
        );
    }

    #[test]
    fn engine_keeps_every_unspent_coin_across_many_synced_flushes() {
        let dir = TmpFile::new("many-flushes");
        std::fs::create_dir_all(dir.path()).unwrap();
        let mut eng = RobinHoodEngine::open(dir.path()).unwrap();
        let mut live: Vec<OutPoint> = Vec::new();
        let mut spent_total = 0usize;
        let mut prev_hash = Hash256::ZERO;

        for h in 1..=6_000u32 {
            let created: Vec<mantle_consensus::chain_view::NewCoin<'_>> = (0..4u32)
                .map(|vout| mantle_consensus::chain_view::NewCoin {
                    outpoint: OutPoint {
                        txid: Hash256::hash(&h.to_le_bytes()),
                        vout,
                    },
                    value: Satoshi::new(u64::from(h)),
                    script_pubkey: &[0x51],
                    coinbase: vout == 0,
                    height: BlockHeight::new(h),
                })
                .collect();
            let spent: Vec<OutPoint> = if h % 3 == 0 && live.len() > 8 {
                let picks = [live.len() / 3, live.len() / 2, live.len() - 1];
                let mut out: Vec<OutPoint> = picks.iter().map(|&i| live[i]).collect();
                out.dedup();
                live.retain(|op| !out.contains(op));
                out
            } else {
                Vec::new()
            };
            spent_total += spent.len();
            live.extend(created.iter().map(|c| c.outpoint));

            let durability = if h % 500 == 0 {
                Durability::Synced
            } else {
                Durability::Memory
            };
            let mut hash_bytes = [0u8; 32];
            hash_bytes[..4].copy_from_slice(&(h + 1_000_000).to_le_bytes());
            let block_hash = Hash256::from_bytes(hash_bytes);
            let mut header = make_header(h);
            header.set_prev_block(prev_hash);
            eng.write_block(&CommitBlockReq {
                token: crate::types::ReqToken(u64::from(h)),
                height: BlockHeight::new(h),
                hash: block_hash,
                prev_hash,
                header,
                created: &created,
                spent: &spent,
                block_bytes: None,
                durability,
            })
            .unwrap();
            eng.flush(durability).unwrap();
            prev_hash = block_hash;
        }

        assert!(spent_total > 1_000);
        let mut out = Vec::new();
        eng.read_coins(&live, &mut out).unwrap();
        let missing: Vec<_> = out.iter().filter(|r| r.coin.is_none()).collect();
        assert!(missing.is_empty(), "{} of {} live coins lost", missing.len(), live.len());
        assert_eq!(eng.table.len(), u64::try_from(live.len()).unwrap());
    }

    #[test]
    fn flush_then_lookup_via_engine() {
        let dir = TmpFile::new("flush-lookup");
        std::fs::create_dir_all(dir.path()).unwrap();
        let mut eng = RobinHoodEngine::open(dir.path()).unwrap();

        let target_height = 1965u32;
        let mut prev_hash = Hash256::ZERO;

        for h in 1..=2016u32 {
            let mut txid_bytes = [0u8; 32];
            txid_bytes[..4].copy_from_slice(&h.to_le_bytes());
            let op = OutPoint {
                txid: Hash256::from_bytes(txid_bytes),
                vout: 0,
            };

            let mut hash_bytes = [0u8; 32];
            hash_bytes[..4].copy_from_slice(&(h + 10000).to_le_bytes());
            let block_hash = Hash256::from_bytes(hash_bytes);

            let durability = if h == 2016 {
                Durability::Synced
            } else {
                Durability::Memory
            };

            let spk = [
                0x00u8, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
            ];
            eng.write_block(&CommitBlockReq {
                token: crate::types::ReqToken(u64::from(h)),
                height: BlockHeight::new(h),
                hash: block_hash,
                prev_hash,
                header: {
                    let mut h = make_header(h);
                    h.set_prev_block(prev_hash);
                    h
                },
                created: &[mantle_consensus::chain_view::NewCoin {
                    outpoint: op,
                    value: Satoshi::new(5_000_000_000),
                    script_pubkey: &spk,
                    coinbase: true,
                    height: BlockHeight::new(h),
                }],
                spent: &[],
                block_bytes: None,
                durability,
            })
            .unwrap();
            eng.flush(durability).unwrap();
            prev_hash = block_hash;
        }

        // Write buffer should be empty after Synced flush at 2016.
        assert!(
            eng.write_buffer.is_empty(),
            "write buffer should be flushed"
        );
        assert!(!eng.table.is_empty(), "table should have entries");

        // Look up block 1965 coinbase via read_coin (synchronous pread).
        let mut target_txid = [0u8; 32];
        target_txid[..4].copy_from_slice(&target_height.to_le_bytes());
        let target_op = OutPoint {
            txid: Hash256::from_bytes(target_txid),
            vout: 0,
        };

        let coin_sync = eng.table.get(&target_op).unwrap();
        assert!(
            coin_sync.is_some(),
            "synchronous table.get should find the coin"
        );

        // Look up via read_coins (batch uring path).
        let mut out = Vec::new();
        eng.read_coins(&[target_op], &mut out).unwrap();
        assert_eq!(out.len(), 1);
        assert!(
            out[0].coin.is_some(),
            "batch uring read_coins should find the coin after flush"
        );
    }

    #[test]
    fn flush_then_lookup_via_handle() {
        let dir = TmpFile::new("flush-handle");
        std::fs::create_dir_all(dir.path()).unwrap();
        let eng = RobinHoodEngine::open(dir.path()).unwrap();

        crate::with_storage(eng, |handle| {
            let target_height = 1965u32;
            let mut prev_hash = Hash256::ZERO;

            for h in 1..=2016u32 {
                let mut txid_bytes = [0u8; 32];
                txid_bytes[..4].copy_from_slice(&h.to_le_bytes());
                let op = OutPoint {
                    txid: Hash256::from_bytes(txid_bytes),
                    vout: 0,
                };
                let mut hash_bytes = [0u8; 32];
                hash_bytes[..4].copy_from_slice(&(h + 10000).to_le_bytes());
                let block_hash = Hash256::from_bytes(hash_bytes);
                let durability = if h == 2016 {
                    Durability::Synced
                } else {
                    Durability::Memory
                };
                let spk = [
                    0x00u8, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
                ];
                let created = [mantle_consensus::chain_view::NewCoin {
                    outpoint: op,
                    value: Satoshi::new(5_000_000_000),
                    script_pubkey: &spk,
                    coinbase: true,
                    height: BlockHeight::new(h),
                }];
                handle
                    .commit_block_borrowed(CommitBlockReq {
                        token: crate::types::ReqToken(u64::from(h)),
                        height: BlockHeight::new(h),
                        hash: block_hash,
                        prev_hash,
                        header: {
                            let mut h = make_header(h);
                            h.set_prev_block(prev_hash);
                            h
                        },
                        created: &created,
                        spent: &[],
                        block_bytes: None,
                        durability,
                    })
                    .expect("commit_block_borrowed");
                prev_hash = block_hash;
            }

            let mut target_txid = [0u8; 32];
            target_txid[..4].copy_from_slice(&target_height.to_le_bytes());
            let target_op = OutPoint {
                txid: Hash256::from_bytes(target_txid),
                vout: 0,
            };

            let mut out = Vec::new();
            handle
                .lookup_coins_borrowed(&[target_op], &mut out)
                .expect("lookup");
            assert_eq!(out.len(), 1);
            assert!(
                out[0].coin.is_some(),
                "handle lookup should find coin after Synced flush at 2016"
            );
        })
        .unwrap();
    }

    #[test]
    fn recover_rebuilds_tip_from_checkpoint() {
        let dir = TmpFile::new("recover-tip");
        std::fs::create_dir_all(dir.path()).unwrap();

        let block_count = 5u32;
        let last_hash;

        // Phase 1: write blocks and flush with Synced to create a checkpoint.
        {
            let mut eng = RobinHoodEngine::open(dir.path()).unwrap();
            let mut prev_hash = Hash256::ZERO;

            for h in 1..=block_count {
                let mut hash_bytes = [0u8; 32];
                hash_bytes[..4].copy_from_slice(&h.to_le_bytes());
                let block_hash = Hash256::from_bytes(hash_bytes);

                let mut txid_bytes = [0u8; 32];
                txid_bytes[..4].copy_from_slice(&(h + 100).to_le_bytes());
                let op = OutPoint {
                    txid: Hash256::from_bytes(txid_bytes),
                    vout: 0,
                };

                eng.write_block(&CommitBlockReq {
                    token: crate::types::ReqToken(u64::from(h)),
                    height: BlockHeight::new(h),
                    hash: block_hash,
                    prev_hash,
                    header: {
                        let mut hdr = make_header(h * 1000);
                        hdr.set_prev_block(prev_hash);
                        hdr
                    },
                    created: &[mantle_consensus::chain_view::NewCoin {
                        outpoint: op,
                        value: Satoshi::new(5_000_000_000),
                        script_pubkey: &[0x51],
                        coinbase: true,
                        height: BlockHeight::new(h),
                    }],
                    spent: &[],
                    block_bytes: None,
                    durability: Durability::Memory,
                })
                .unwrap();
                prev_hash = block_hash;
            }

            // Flush with Synced to write checkpoint and persist headers.
            eng.flush(Durability::Synced).unwrap();
            last_hash = eng.tip().hash;
            assert_eq!(eng.tip().height, BlockHeight::new(block_count));
        }

        // Phase 2: reopen — recover() should rebuild the tip and header index.
        {
            let eng = RobinHoodEngine::open(dir.path()).unwrap();
            let tip = eng.tip();

            assert_eq!(tip.height, BlockHeight::new(block_count));
            assert_eq!(tip.hash, last_hash);

            // Verify headers are readable by height.
            for h in 1..=block_count {
                let hdr = eng.read_header_at(BlockHeight::new(h)).unwrap();
                assert!(
                    hdr.is_some(),
                    "header at height {h} should be recoverable"
                );
                assert_eq!(hdr.unwrap().time().to_u32(), h * 1000);
            }

            // Verify header index by hash.
            let hdr_by_hash = eng.read_header(&last_hash).unwrap();
            assert!(hdr_by_hash.is_some(), "last header should be findable by hash");
        }
    }

    #[test]
    fn recover_no_checkpoint_no_headers_wipes_table() {
        let dir = TmpFile::new("recover-wipe");
        std::fs::create_dir_all(dir.path()).unwrap();

        // Create a table with some data but no headers or checkpoint.
        let table_path = dir.path().join("utxo_table.bin");
        {
            let mut table = RobinHoodTable::open(&table_path).unwrap();
            table.insert(&make_op(1), &make_coin(100, &[0x51])).unwrap();
            table.sync().unwrap();
            assert_eq!(table.len(), 1);
        }

        // Opening the engine should detect stale table and wipe it.
        let eng = RobinHoodEngine::open(dir.path()).unwrap();
        assert_eq!(eng.tip().height, BlockHeight::ZERO);
        // The table should have been wiped during recover.
        assert!(eng.table.is_empty());
    }

    #[test]
    fn recover_headers_beyond_checkpoint_truncated() {
        // Write 10 headers but only checkpoint at height 5.
        // On recovery, only heights 0..=5 should be in the header index.
        let dir = TmpFile::new("recover-trunc");
        std::fs::create_dir_all(dir.path()).unwrap();

        {
            let mut eng = RobinHoodEngine::open(dir.path()).unwrap();
            let mut prev_hash = Hash256::ZERO;

            for h in 1..=10u32 {
                let mut hash_bytes = [0u8; 32];
                hash_bytes[..4].copy_from_slice(&h.to_le_bytes());
                let block_hash = Hash256::from_bytes(hash_bytes);

                let mut txid_bytes = [0u8; 32];
                txid_bytes[..4].copy_from_slice(&(h + 100).to_le_bytes());
                let op = OutPoint {
                    txid: Hash256::from_bytes(txid_bytes),
                    vout: 0,
                };

                eng.write_block(&CommitBlockReq {
                    token: crate::types::ReqToken(u64::from(h)),
                    height: BlockHeight::new(h),
                    hash: block_hash,
                    prev_hash,
                    header: {
                        let mut hdr = make_header(h * 1000);
                        hdr.set_prev_block(prev_hash);
                        hdr
                    },
                    created: &[mantle_consensus::chain_view::NewCoin {
                        outpoint: op,
                        value: Satoshi::new(1_000),
                        script_pubkey: &[0x51],
                        coinbase: true,
                        height: BlockHeight::new(h),
                    }],
                    spent: &[],
                    block_bytes: None,
                    durability: Durability::Memory,
                })
                .unwrap();
                prev_hash = block_hash;
            }

            // Flush at height 5 to create checkpoint at 5.
            // Then write blocks 6..10 without flushing.
            // We can't selectively checkpoint, so flush Synced at height 10
            // but manually overwrite the checkpoint to 5 afterwards.
            eng.flush(Durability::Synced).unwrap();

            // Manually overwrite checkpoint to height 5.
            use std::io::Write;
            let checkpoint_path = dir.path().join("checkpoint.bin");
            let mut cp = std::fs::OpenOptions::new()
                .write(true)
                .open(&checkpoint_path)
                .unwrap();
            cp.write_all(&5u32.to_le_bytes()).unwrap();
            cp.sync_all().unwrap();
        }

        // Reopen: recover should only include headers up to checkpoint=5.
        let eng = RobinHoodEngine::open(dir.path()).unwrap();
        assert_eq!(
            eng.tip().height,
            BlockHeight::new(5),
            "tip should be truncated to checkpoint height"
        );
        // Headers beyond checkpoint should not be indexed.
        let mut h6_bytes = [0u8; 32];
        h6_bytes[..4].copy_from_slice(&6u32.to_le_bytes());
        assert!(
            eng.read_header(&Hash256::from_bytes(h6_bytes)).unwrap().is_none(),
            "header at height 6 should not be in index after truncation"
        );
    }

    #[test]
    fn remove_backshift_multi_step_chain() {
        // Insert entries into a small table so they form long probe chains.
        // Remove one from the middle and verify the chain collapses correctly.
        let tmp = TmpFile::new("backshift-multi");
        let mut table = RobinHoodTable::open_with_capacity(tmp.path(), 16).unwrap();

        // Insert 12 entries into 16 slots — 75% load, lots of collisions.
        let ops: Vec<OutPoint> = (0..12u8).map(make_op).collect();
        for (i, op) in ops.iter().enumerate() {
            let coin = make_coin(u64::try_from(i).unwrap() * 100, &[0x51]);
            table.insert(op, &coin).unwrap();
        }
        assert_eq!(table.len(), 12);

        // Remove entries from the middle of the probe chains.
        table.remove(&ops[2]).unwrap();
        table.remove(&ops[5]).unwrap();
        table.remove(&ops[8]).unwrap();
        assert_eq!(table.len(), 9);

        // Verify removed entries are gone and remaining are intact.
        for (i, op) in ops.iter().enumerate() {
            if i == 2 || i == 5 || i == 8 {
                assert!(
                    table.get(op).unwrap().is_none(),
                    "outpoint {i} should have been removed"
                );
            } else {
                let coin = table
                    .get(op)
                    .unwrap()
                    .unwrap_or_else(|| panic!("outpoint {i} should still be present"));
                assert_eq!(coin.value.to_u64(), u64::try_from(i).unwrap() * 100);
            }
        }
    }

    #[test]
    fn uring_remove_backshift_multi_step_chain() {
        // Same as above but using the io_uring batch remove path, which
        // exercises remove_backshift_phase with multi-step shifts.
        let tmp = TmpFile::new("uring-backshift-multi");
        let mut table = RobinHoodTable::open_with_capacity(tmp.path(), 16).unwrap();
        let mut ring = crate::engine::ring_budget::RingBudget::new(256, 16).build().unwrap();
        let mut arena = Vec::new();

        let ops: Vec<OutPoint> = (0..12u8).map(make_op).collect();
        for (i, op) in ops.iter().enumerate() {
            let coin = make_coin(u64::try_from(i).unwrap() * 100, &[0x51]);
            table.insert(op, &coin).unwrap();
        }

        // Remove 4 entries from the middle to force multi-step backshifts.
        let remove_ops: Vec<OutPoint> = [2u8, 4, 7, 9].iter().map(|&i| make_op(i)).collect();
        let (mut slots, mut dists, mut resolved) = (Vec::new(), Vec::new(), Vec::new());
        table
            .remove_batch_uring(
                &remove_ops,
                &mut ring,
                &mut arena,
                &mut slots,
                &mut dists,
                &mut resolved,
            )
            .unwrap();

        assert_eq!(table.len(), 8);

        for (i, op) in ops.iter().enumerate() {
            if [2, 4, 7, 9].contains(&i) {
                assert!(
                    table.get(op).unwrap().is_none(),
                    "outpoint {i} should have been removed"
                );
            } else {
                let coin = table
                    .get(op)
                    .unwrap()
                    .unwrap_or_else(|| panic!("outpoint {i} should still be present"));
                assert_eq!(coin.value.to_u64(), u64::try_from(i).unwrap() * 100);
            }
        }
    }

    // ── Task 1: insert_batch_uring coverage tests ───────────────────────

    /// Helper: create an OutPoint whose ideal slot (in a table of given
    /// slot_count) is `target_slot`.  We use a txid where the first 8 bytes
    /// encode the desired hash directly.
    fn make_op_for_slot(target_slot: u64, disambig: u8) -> OutPoint {
        // hash_outpoint reads the first 8 bytes of txid as u64 LE.
        // ideal_slot = hash & mask.  We build hash = target_slot so
        // ideal_slot == target_slot for any power-of-two table where
        // slot_count > target_slot.  `disambig` goes into byte 8+ to
        // make txids unique when multiple ops target the same slot.
        let mut txid = [0u8; 32];
        txid[..8].copy_from_slice(&target_slot.to_le_bytes());
        txid[8] = disambig;
        OutPoint {
            txid: Hash256::from_bytes(txid),
            vout: 0,
        }
    }

    #[test]
    fn insert_batch_uring_triggers_resize() {
        // Start with a 16-slot table.  Pre-fill 10 entries synchronously
        // so the table is at 10/16 = 62.5% load.  Then batch-insert 4
        // more entries: (10+4)*100 = 1400 > 16*85 = 1360, which triggers
        // resize to 32 slots.  After resize, 14 entries in 32 slots is
        // 43.75% — well within capacity.
        let tmp = TmpFile::new("uring-insert-resize");
        let mut table = RobinHoodTable::open_with_capacity(tmp.path(), 16).unwrap();
        let initial_slots = table.slot_count;
        assert_eq!(initial_slots, 16);

        // Pre-fill 10 entries.
        for i in 0..10u8 {
            table
                .insert(&make_op(i), &make_coin(u64::from(i) * 10, &[0x51]))
                .unwrap();
        }
        assert_eq!(table.len(), 10);

        let mut ring = crate::engine::ring_budget::RingBudget::new(256, 16).build().unwrap();
        let mut arena = Vec::new();
        let mut write_arena = Vec::new();
        let mut states = Vec::new();

        // Batch-insert 4 entries to push past the 85% threshold.
        let pairs: Vec<(OutPoint, Coin)> = (10..14u8)
            .map(|i| (make_op(i), make_coin(u64::from(i) * 10, &[0x51])))
            .collect();

        table
            .insert_batch_uring(
                &pairs,
                &mut ring,
                &mut arena,
                &mut write_arena,
                &mut states,
            )
            .unwrap();

        assert_eq!(table.len(), 14);
        assert!(
            table.slot_count > initial_slots,
            "table should have resized from {} slots",
            initial_slots
        );

        // Verify every entry (pre-filled + batch) is retrievable.
        for i in 0..14u8 {
            let op = make_op(i);
            let coin = table
                .get(&op)
                .unwrap()
                .unwrap_or_else(|| panic!("entry {i} should be present after batch insert"));
            assert_eq!(coin.value.to_u64(), u64::from(i) * 10);
        }
    }

    fn colliding_op(i: u32) -> OutPoint {
        OutPoint {
            txid: Hash256::hash(&i.to_le_bytes()),
            vout: i % 3,
        }
    }

    #[test]
    fn batch_insert_and_remove_keep_every_entry_when_probes_collide() {
        let tmp = TmpFile::new("uring-batch-collide");
        let mut table = RobinHoodTable::open_with_capacity(tmp.path(), 64).unwrap();
        let mut ring = crate::engine::ring_budget::RingBudget::new(256, 16).build().unwrap();
        let mut arena = Vec::new();
        let mut write_arena = Vec::new();
        let mut states = Vec::new();

        let pairs: Vec<(OutPoint, Coin)> = (0..50u32)
            .map(|i| (colliding_op(i), make_coin(u64::from(i) + 1, &[0x51])))
            .collect();
        table
            .insert_batch_uring(&pairs, &mut ring, &mut arena, &mut write_arena, &mut states)
            .unwrap();
        for (op, coin) in &pairs {
            assert_eq!(
                table.get(op).unwrap().map(|c| c.value),
                Some(coin.value),
                "batch insert lost {op:?}"
            );
        }
        assert_eq!(table.len(), 50);

        let removed: Vec<OutPoint> = (0..50u32).step_by(2).map(colliding_op).collect();
        let (mut slots, mut dists, mut resolved) = (Vec::new(), Vec::new(), Vec::new());
        table
            .remove_batch_uring(
                &removed,
                &mut ring,
                &mut arena,
                &mut slots,
                &mut dists,
                &mut resolved,
            )
            .unwrap();
        for i in 0..50u32 {
            let found = table.get(&colliding_op(i)).unwrap();
            if i % 2 == 0 {
                assert!(found.is_none(), "batch remove left {i}");
            } else {
                assert_eq!(
                    found.map(|c| c.value.to_u64()),
                    Some(u64::from(i) + 1),
                    "batch remove lost {i}"
                );
            }
        }
        assert_eq!(table.len(), 25);
    }

    #[test]
    fn batch_insert_writes_through_a_registered_fd_without_a_resize() {
        let tmp = TmpFile::new("uring-batch-registered");
        let mut table = RobinHoodTable::open_with_capacity(tmp.path(), 1024).unwrap();
        let mut ring = crate::engine::ring_budget::RingBudget::new(256, 16).build().unwrap();
        ring.register_files(&[table.fd().as_i32()]).unwrap();
        table.set_fixed_fd(ququmatz::types::RawFd::from_raw(0));
        let mut arena = Vec::new();
        let mut write_arena = Vec::new();
        let mut states = Vec::new();

        let pairs: Vec<(OutPoint, Coin)> = (0..100u32)
            .map(|i| (colliding_op(i), make_coin(u64::from(i) + 1, &[0x51])))
            .collect();
        table
            .insert_batch_uring(&pairs, &mut ring, &mut arena, &mut write_arena, &mut states)
            .unwrap();

        for (op, coin) in &pairs {
            assert_eq!(
                table.get(op).unwrap().map(|c| c.value),
                Some(coin.value),
                "registered-fd batch insert lost {op:?}"
            );
        }
    }

    #[test]
    fn batches_larger_than_the_ring_lose_no_lookups_inserts_or_removes() {
        let tmp = TmpFile::new("uring-small-ring");
        let mut table = RobinHoodTable::open_with_capacity(tmp.path(), 1024).unwrap();
        let mut ring = crate::engine::ring_budget::RingBudget::new(16, 16).build().unwrap();
        let (mut arena, mut write_arena, mut states) = (Vec::new(), Vec::new(), Vec::new());
        let (mut slots, mut dists, mut resolved) = (Vec::new(), Vec::new(), Vec::new());

        let pairs: Vec<(OutPoint, Coin)> = (0..300u32)
            .map(|i| (colliding_op(i), make_coin(u64::from(i) + 1, &[0x51])))
            .collect();
        table
            .insert_batch_uring(&pairs, &mut ring, &mut arena, &mut write_arena, &mut states)
            .unwrap();
        assert_eq!(table.len(), 300);

        let ops: Vec<OutPoint> = pairs.iter().map(|(op, _)| *op).collect();
        let mut found = Vec::new();
        table
            .get_batch_uring(&ops, &mut found, &mut ring, &mut arena, &mut slots, &mut dists, &mut resolved)
            .unwrap();
        let missing = found.iter().filter(|c| c.is_none()).count();
        assert_eq!(missing, 0, "batched lookup lost {missing} of 300");

        let removed: Vec<OutPoint> = ops.iter().step_by(2).copied().collect();
        table
            .remove_batch_uring(&removed, &mut ring, &mut arena, &mut slots, &mut dists, &mut resolved)
            .unwrap();
        assert_eq!(table.len(), 150, "batched remove missed entries");
    }

    #[test]
    fn batch_insert_grows_the_table_enough_for_a_large_batch() {
        let tmp = TmpFile::new("uring-batch-large");
        let mut table = RobinHoodTable::open_with_capacity(tmp.path(), 64).unwrap();
        let mut ring = crate::engine::ring_budget::RingBudget::new(256, 16).build().unwrap();
        let mut arena = Vec::new();
        let mut write_arena = Vec::new();
        let mut states = Vec::new();

        let pairs: Vec<(OutPoint, Coin)> = (0..1_000u32)
            .map(|i| (colliding_op(i), make_coin(u64::from(i) + 1, &[0x51])))
            .collect();
        table
            .insert_batch_uring(&pairs, &mut ring, &mut arena, &mut write_arena, &mut states)
            .unwrap();

        assert!(table.len() * LOAD_FACTOR_DEN <= table.slot_count * LOAD_FACTOR_NUM);
        for (op, coin) in &pairs {
            assert_eq!(table.get(op).unwrap().map(|c| c.value), Some(coin.value));
        }
    }

    #[test]
    fn insert_batch_uring_multi_round_probing() {
        // Pre-populate a chain of entries at slots 5..10 so that a
        // batch-inserted entry targeting slot 5 must probe through the
        // entire chain before finding an empty slot.  Each batch entry
        // targets a different ideal slot to avoid intra-batch collisions.
        let tmp = TmpFile::new("uring-insert-multiround");
        let mut table = RobinHoodTable::open_with_capacity(tmp.path(), 64).unwrap();

        // Fill slots 5..10 with entries that each have ideal=their slot.
        for s in 5..10u64 {
            let op = make_op_for_slot(s, 0);
            table
                .insert(&op, &make_coin(s * 100, &[0x51]))
                .unwrap();
        }
        assert_eq!(table.len(), 5);

        let mut ring = crate::engine::ring_budget::RingBudget::new(256, 16).build().unwrap();
        let mut arena = Vec::new();
        let mut write_arena = Vec::new();
        let mut states = Vec::new();

        // Batch: one entry targeting slot 5 (must probe 5,6,7,8,9 before
        // finding slot 10 empty), one entry targeting slot 20 (resolves
        // immediately).  The first entry forces multiple uring rounds.
        let batch_pairs: Vec<(OutPoint, Coin)> = vec![
            (make_op_for_slot(5, 1), make_coin(5555, &[0x51])),
            (make_op_for_slot(20, 0), make_coin(2020, &[0x51])),
        ];

        table
            .insert_batch_uring(
                &batch_pairs,
                &mut ring,
                &mut arena,
                &mut write_arena,
                &mut states,
            )
            .unwrap();

        assert_eq!(table.len(), 7);

        // The probed entry should land at slot 10.
        let coin = table
            .get(&make_op_for_slot(5, 1))
            .unwrap()
            .expect("probed entry should be present");
        assert_eq!(coin.value.to_u64(), 5555);

        // Quick-resolve entry.
        let coin = table
            .get(&make_op_for_slot(20, 0))
            .unwrap()
            .expect("quick-resolve entry should be present");
        assert_eq!(coin.value.to_u64(), 2020);

        // Original entries should be untouched.
        for s in 5..10u64 {
            let c = table
                .get(&make_op_for_slot(s, 0))
                .unwrap()
                .expect("pre-existing entry should survive");
            assert_eq!(c.value.to_u64(), s * 100);
        }
    }

    #[test]
    fn insert_batch_uring_robin_hood_displacement() {
        // Pre-populate so that a batch-inserted entry has a longer probe
        // distance than an existing entry, triggering Robin Hood
        // displacement.  Each batch entry targets a unique ideal slot.
        let tmp = TmpFile::new("uring-insert-displace");
        let mut table = RobinHoodTable::open_with_capacity(tmp.path(), 64).unwrap();

        // Entry A: ideal=10, sits at slot 10 with pd=1.
        let op_a = make_op_for_slot(10, 0);
        table.insert(&op_a, &make_coin(100, &[0x51])).unwrap();
        // Entry B: ideal=11, sits at slot 11 with pd=1.
        let op_b = make_op_for_slot(11, 0);
        table.insert(&op_b, &make_coin(200, &[0x51])).unwrap();
        // Entry C: ideal=12, sits at slot 12 with pd=1.
        let op_c = make_op_for_slot(12, 0);
        table.insert(&op_c, &make_coin(300, &[0x51])).unwrap();

        let mut ring = crate::engine::ring_budget::RingBudget::new(256, 16).build().unwrap();
        let mut arena = Vec::new();
        let mut write_arena = Vec::new();
        let mut states = Vec::new();

        // Batch-insert one entry targeting slot 10 (different disambig).
        // Round 1: reads slot 10, finds A (pd=1 vs new pd=1, no steal),
        //   advances to slot 11.
        // Round 2: reads slot 11, finds B (pd=1 vs new pd=2 -> steal!),
        //   writes new entry at slot 11, displaces B to continue at slot 12.
        // Round 3 (internal): displaced B (pd=2) vs C at slot 12 (pd=1 ->
        //   steal again), B goes to slot 13.
        // This exercises the Robin Hood displacement cascade.
        let batch_pairs = vec![
            (make_op_for_slot(10, 1), make_coin(999, &[0x51])),
        ];

        table
            .insert_batch_uring(
                &batch_pairs,
                &mut ring,
                &mut arena,
                &mut write_arena,
                &mut states,
            )
            .unwrap();

        assert_eq!(table.len(), 4);

        // All entries should be retrievable.
        let got_a = table.get(&op_a).unwrap().unwrap();
        assert_eq!(got_a.value.to_u64(), 100);
        let got_b = table.get(&op_b).unwrap().unwrap();
        assert_eq!(got_b.value.to_u64(), 200);
        let got_c = table.get(&op_c).unwrap().unwrap();
        assert_eq!(got_c.value.to_u64(), 300);
        let got_new = table
            .get(&make_op_for_slot(10, 1))
            .unwrap()
            .expect("displaced batch entry should be present");
        assert_eq!(got_new.value.to_u64(), 999);
    }

    // ── Task 2: remove_backshift_phase coverage tests ───────────────────

    #[test]
    fn uring_remove_backshift_wraps_around_table() {
        // Place entries near the end of the table so that a backshift
        // chain wraps past slot_count-1 back to slot 0.
        let tmp = TmpFile::new("uring-backshift-wrap");
        let slot_count: u64 = 32;
        let mut table = RobinHoodTable::open_with_capacity(tmp.path(), slot_count).unwrap();
        assert_eq!(table.slot_count, slot_count);

        // Insert entries whose ideal slot is near the end: slots 30, 31.
        // They will occupy slots 30, 31, 0, 1, ... forming a chain that
        // wraps around.  We use make_op_for_slot to target slot 30.
        let wrap_ops: Vec<OutPoint> = (0..4u8)
            .map(|d| make_op_for_slot(30, d))
            .collect();
        for (i, op) in wrap_ops.iter().enumerate() {
            table
                .insert(op, &make_coin(u64::try_from(i).unwrap() * 77, &[0x51]))
                .unwrap();
        }
        // Also add a few unrelated entries so the table is not trivial.
        for i in 0..5u8 {
            table
                .insert(
                    &make_op_for_slot(10, i),
                    &make_coin(u64::from(i) * 11, &[0x51]),
                )
                .unwrap();
        }
        assert_eq!(table.len(), 9);

        // Remove the first entry (slot 30, ideal=30, pd=1).  The backshift
        // chain must pull entries from slots 31, 0, 1 backward — wrapping
        // around the table boundary.
        let mut ring = crate::engine::ring_budget::RingBudget::new(256, 16).build().unwrap();
        let mut arena = Vec::new();
        let (mut slots, mut dists, mut resolved) = (Vec::new(), Vec::new(), Vec::new());

        table
            .remove_batch_uring(
                &[wrap_ops[0]],
                &mut ring,
                &mut arena,
                &mut slots,
                &mut dists,
                &mut resolved,
            )
            .unwrap();

        assert_eq!(table.len(), 8);
        assert!(
            table.get(&wrap_ops[0]).unwrap().is_none(),
            "removed entry should be gone"
        );
        // The remaining wrap entries should still be retrievable.
        for d in 1..4u8 {
            let coin = table
                .get(&wrap_ops[d as usize])
                .unwrap()
                .unwrap_or_else(|| panic!("wrap entry d={d} should survive backshift"));
            assert_eq!(coin.value.to_u64(), u64::from(d) * 77);
        }
        // Unrelated entries should be untouched.
        for i in 0..5u8 {
            let op = make_op_for_slot(10, i);
            assert!(
                table.get(&op).unwrap().is_some(),
                "unrelated entry i={i} should be untouched"
            );
        }
    }

    #[test]
    fn uring_remove_batch_many_entries() {
        // Remove 5 entries in a single batch call to exercise
        // remove_backshift_phase with many concurrent backshift chains.
        let tmp = TmpFile::new("uring-remove-batch-many");
        let mut table = RobinHoodTable::open_with_capacity(tmp.path(), 64).unwrap();

        // Insert 30 entries spread across the table.
        let all_ops: Vec<OutPoint> = (0..30u8).map(make_op).collect();
        for (i, op) in all_ops.iter().enumerate() {
            table
                .insert(op, &make_coin(u64::try_from(i).unwrap() * 50, &[0x51]))
                .unwrap();
        }
        assert_eq!(table.len(), 30);

        // Remove 5 entries scattered across the table.
        let remove_indices: Vec<u8> = vec![3, 7, 12, 19, 25];
        let remove_ops: Vec<OutPoint> = remove_indices.iter().map(|&i| make_op(i)).collect();

        let mut ring = crate::engine::ring_budget::RingBudget::new(256, 16).build().unwrap();
        let mut arena = Vec::new();
        let (mut slots, mut dists, mut resolved) = (Vec::new(), Vec::new(), Vec::new());

        table
            .remove_batch_uring(
                &remove_ops,
                &mut ring,
                &mut arena,
                &mut slots,
                &mut dists,
                &mut resolved,
            )
            .unwrap();

        assert_eq!(table.len(), 25);

        for (i, op) in all_ops.iter().enumerate() {
            let i_u8 = u8::try_from(i).unwrap();
            if remove_indices.contains(&i_u8) {
                assert!(
                    table.get(op).unwrap().is_none(),
                    "entry {i} should have been removed"
                );
            } else {
                let coin = table
                    .get(op)
                    .unwrap()
                    .unwrap_or_else(|| panic!("entry {i} should still be present"));
                assert_eq!(coin.value.to_u64(), u64::try_from(i).unwrap() * 50);
            }
        }
    }

    #[test]
    fn uring_remove_backshift_wrapping_chain_with_batch() {
        // Combine wrapping backshift with multiple concurrent removals
        // from independent clusters (non-overlapping probe chains).
        let tmp = TmpFile::new("uring-remove-wrap-batch");
        let slot_count: u64 = 32;
        let mut table = RobinHoodTable::open_with_capacity(tmp.path(), slot_count).unwrap();
        assert_eq!(table.slot_count, slot_count);

        // Cluster A: 3 entries targeting slot 30 (near end, will wrap
        // to slots 30, 31, 0).
        let cluster_a: Vec<OutPoint> = (0..3u8)
            .map(|d| make_op_for_slot(30, d))
            .collect();
        for (i, op) in cluster_a.iter().enumerate() {
            table
                .insert(op, &make_coin(u64::try_from(i).unwrap() * 100 + 1000, &[0x51]))
                .unwrap();
        }
        // Cluster B: 3 entries targeting slot 10 (middle, independent).
        let cluster_b: Vec<OutPoint> = (0..3u8)
            .map(|d| make_op_for_slot(10, d + 100))
            .collect();
        for (i, op) in cluster_b.iter().enumerate() {
            table
                .insert(op, &make_coin(u64::try_from(i).unwrap() * 100 + 2000, &[0x51]))
                .unwrap();
        }
        // Cluster C: 3 entries targeting slot 20.
        let cluster_c: Vec<OutPoint> = (0..3u8)
            .map(|d| make_op_for_slot(20, d + 200))
            .collect();
        for (i, op) in cluster_c.iter().enumerate() {
            table
                .insert(op, &make_coin(u64::try_from(i).unwrap() * 100 + 3000, &[0x51]))
                .unwrap();
        }
        assert_eq!(table.len(), 9);

        // Remove the head of each cluster in a single batch.
        // cluster_a[0] at slot 30: backshift wraps around 31->30, 0->31.
        // cluster_b[0] at slot 10: standard backshift within the middle.
        // cluster_c[0] at slot 20: standard backshift.
        // All three chains are independent (non-overlapping slot ranges).
        let remove_ops = vec![cluster_a[0], cluster_b[0], cluster_c[0]];

        let mut ring = crate::engine::ring_budget::RingBudget::new(256, 16).build().unwrap();
        let mut arena = Vec::new();
        let (mut slots, mut dists, mut resolved) = (Vec::new(), Vec::new(), Vec::new());

        table
            .remove_batch_uring(
                &remove_ops,
                &mut ring,
                &mut arena,
                &mut slots,
                &mut dists,
                &mut resolved,
            )
            .unwrap();

        assert_eq!(table.len(), 6);

        // Removed entries should be gone.
        assert!(table.get(&cluster_a[0]).unwrap().is_none());
        assert!(table.get(&cluster_b[0]).unwrap().is_none());
        assert!(table.get(&cluster_c[0]).unwrap().is_none());

        // Surviving entries should still be present with correct values.
        let c = table.get(&cluster_a[1]).unwrap().unwrap();
        assert_eq!(c.value.to_u64(), 1100);
        let c = table.get(&cluster_a[2]).unwrap().unwrap();
        assert_eq!(c.value.to_u64(), 1200);
        let c = table.get(&cluster_b[1]).unwrap().unwrap();
        assert_eq!(c.value.to_u64(), 2100);
        let c = table.get(&cluster_b[2]).unwrap().unwrap();
        assert_eq!(c.value.to_u64(), 2200);
        let c = table.get(&cluster_c[1]).unwrap().unwrap();
        assert_eq!(c.value.to_u64(), 3100);
        let c = table.get(&cluster_c[2]).unwrap().unwrap();
        assert_eq!(c.value.to_u64(), 3200);
    }
}
