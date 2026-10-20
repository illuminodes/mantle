use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use mantle::primitives::{BlockHeight, Hash256, OutPoint, Satoshi, ScriptPubKey};
use mantle_consensus::chain_view::Coin;

use crate::background::Extent;

use super::super::chunk_cache::CHUNK_SLOTS;
use super::super::chunk_sink::{ChunkSink, DirectSink};
use super::super::extent_writer::ExtentWriter;
use super::super::{overflow_path, Bucket, RobinHoodTable};
use super::FlushPass;

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        Self(std::env::temp_dir().join(format!(
            "mantle-rh-flush-{name}-{}-{nanos}",
            std::process::id()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("new"));
        let _ = std::fs::remove_file(overflow_path(&self.0));
    }
}

struct Entry;

impl Entry {
    fn hashed(i: u32) -> OutPoint {
        OutPoint {
            txid: Hash256::hash(&i.to_le_bytes()),
            vout: i % 3,
        }
    }

    fn at_hash(hash: u64, disambig: u32) -> OutPoint {
        let mut txid = [0u8; 32];
        txid[..8].copy_from_slice(&hash.to_le_bytes());
        txid[8..12].copy_from_slice(&disambig.to_le_bytes());
        OutPoint {
            txid: Hash256::from_bytes(txid),
            vout: 0,
        }
    }

    fn coin(tag: u32) -> Coin {
        Coin {
            value: Satoshi::new(u64::from(tag) + 1),
            script_pubkey: ScriptPubKey::from_slice(&[0x51]),
            height: BlockHeight::new(tag),
            coinbase: false,
        }
    }
}

/// Writes each step like [`DirectSink`], then checks that every coin the
/// flush leaves alone is still found in the file, as a lookup between two
/// steps would see it.
struct CheckingSink<'m> {
    before: &'m HashMap<OutPoint, Coin>,
    after: &'m HashMap<OutPoint, Coin>,
    steps: usize,
}

impl CheckingSink<'_> {
    fn check(&self, table: &RobinHoodTable) {
        for (op, coin) in self.after {
            if self.before.get(op) == Some(coin) {
                assert_eq!(
                    table.get(op).unwrap().as_ref(),
                    Some(coin),
                    "step {} lost {op:?}",
                    self.steps
                );
            }
        }
    }
}

impl ChunkSink for CheckingSink<'_> {
    fn publish(
        &mut self,
        table: &RobinHoodTable,
        ring: &mut ququmatz::IoUring,
        extents: Vec<Extent>,
    ) -> io::Result<()> {
        ExtentWriter::write(table, ring, &extents)?;
        self.steps += 1;
        self.check(table);
        Ok(())
    }

    fn settle(&mut self, _ring: &mut ququmatz::IoUring) -> io::Result<()> {
        Ok(())
    }

    fn replaced(
        &mut self,
        _table: &RobinHoodTable,
        _ring: &mut ququmatz::IoUring,
    ) -> io::Result<()> {
        Ok(())
    }
}

/// A table plus the map of what it must contain, flushed through
/// [`FlushPass`] with a chosen read-ahead.
struct Harness {
    scratch: Scratch,
    table: RobinHoodTable,
    ring: ququmatz::IoUring,
    model: HashMap<OutPoint, Coin>,
}

impl Harness {
    fn new(name: &str, slots: u64) -> Self {
        let scratch = Scratch::new(name);
        let table = RobinHoodTable::open_with_capacity(scratch.path(), slots).unwrap();
        let ring = crate::engine::ring_budget::RingBudget::new(64, 16).build().unwrap();
        Self {
            scratch,
            table,
            ring,
            model: HashMap::new(),
        }
    }

    fn flush(&mut self, deletes: &[OutPoint], inserts: &[(OutPoint, Coin)], read_ahead: usize) {
        let before = self.model.clone();
        for op in deletes {
            self.model.remove(op);
        }
        for (op, coin) in inserts {
            self.model.insert(*op, coin.clone());
        }
        let buckets = self.buckets(inserts);
        let mut sink = CheckingSink {
            before: &before,
            after: &self.model,
            steps: 0,
        };
        FlushPass::with_read_ahead(&mut self.table, &mut self.ring, &mut sink, read_ahead)
            .apply(deletes, buckets)
            .unwrap();
    }

    fn flush_direct(&mut self, deletes: &[OutPoint], inserts: &[(OutPoint, Coin)], read_ahead: usize) {
        for op in deletes {
            self.model.remove(op);
        }
        for (op, coin) in inserts {
            self.model.insert(*op, coin.clone());
        }
        let buckets = self.buckets(inserts);
        FlushPass::with_read_ahead(&mut self.table, &mut self.ring, &mut DirectSink, read_ahead)
            .apply(deletes, buckets)
            .unwrap();
    }

    fn buckets(&mut self, inserts: &[(OutPoint, Coin)]) -> Vec<Bucket> {
        inserts
            .iter()
            .map(|(op, coin)| {
                Bucket::from_outpoint_and_coin(op, coin, 1, &mut self.table.overflow).unwrap()
            })
            .collect()
    }

    fn check(&self) {
        for (op, coin) in &self.model {
            assert_eq!(self.table.get(op).unwrap().as_ref(), Some(coin), "{op:?}");
        }
        let occupied: Vec<Bucket> = (0..self.table.slot_count)
            .map(|slot| self.table.read_bucket(slot).unwrap())
            .filter(|b| !b.is_empty())
            .collect();
        assert_eq!(occupied.len(), self.model.len(), "stray or lost buckets");
        assert_eq!(self.table.len(), u64::try_from(self.model.len()).unwrap());
        for slot in 0..self.table.slot_count {
            let bucket = self.table.read_bucket(slot).unwrap();
            if bucket.is_empty() {
                continue;
            }
            let ideal = self.table.ideal_slot(&bucket.outpoint());
            let distance = (slot + self.table.slot_count - ideal) & self.table.mask;
            assert_eq!(u64::from(bucket.probe_distance), distance + 1, "slot {slot}");
        }
    }
}

#[test]
fn a_flush_matches_the_model_for_every_read_ahead() {
    for read_ahead in [1, 3, 17, 1 << 16] {
        let mut harness = Harness::new("read-ahead", 1024);
        let first: Vec<_> = (0..600).map(|i| (Entry::hashed(i), Entry::coin(i))).collect();
        harness.flush(&[], &first, read_ahead);
        harness.check();

        let deletes: Vec<_> = (0..600).step_by(3).map(Entry::hashed).collect();
        let inserts: Vec<_> = (600..800).map(|i| (Entry::hashed(i), Entry::coin(i))).collect();
        harness.flush(&deletes, &inserts, read_ahead);
        harness.check();
    }
}

#[test]
fn chains_that_wrap_past_the_last_slot_survive_retiring_the_first_chunks() {
    let slots = 4 * CHUNK_SLOTS;
    let mut harness = Harness::new("wrap", slots);
    let tail = slots - 3;
    let wrapping: Vec<_> = (0..40)
        .map(|i| (Entry::at_hash(tail, i), Entry::coin(i)))
        .collect();
    let head: Vec<_> = (0..20)
        .map(|i| (Entry::at_hash(2, 100 + i), Entry::coin(100 + i)))
        .collect();
    let mut all = wrapping.clone();
    all.extend(head);
    harness.flush(&[], &all, 2);
    harness.check();

    let deletes: Vec<_> = wrapping.iter().step_by(2).map(|(op, _)| *op).collect();
    harness.flush(&deletes, &[], 2);
    harness.check();
}

#[test]
fn deleting_and_reinserting_one_outpoint_in_a_flush_keeps_it() {
    let mut harness = Harness::new("respend", 256);
    let op = Entry::hashed(7);
    harness.flush(&[], &[(op, Entry::coin(1))], 4);
    harness.flush(&[op], &[(op, Entry::coin(2))], 4);
    harness.check();
    assert_eq!(harness.table.get(&op).unwrap(), Some(Entry::coin(2)));
}

#[test]
fn deleting_an_absent_outpoint_changes_nothing() {
    let mut harness = Harness::new("absent", 256);
    let present: Vec<_> = (0..50).map(|i| (Entry::hashed(i), Entry::coin(i))).collect();
    harness.flush(&[], &present, 8);
    harness.flush(&[Entry::hashed(999)], &[], 8);
    harness.check();
}

#[test]
fn many_random_flushes_stay_consistent() {
    let mut harness = Harness::new("random", 4096);
    let mut next = 0u32;
    let mut live: Vec<OutPoint> = Vec::new();
    for round in 0..30u32 {
        let deletes: Vec<OutPoint> = live
            .iter()
            .enumerate()
            .filter(|(i, _)| (u32::try_from(*i).unwrap() + round) % 4 == 0)
            .map(|(_, op)| *op)
            .collect();
        live.retain(|op| !deletes.contains(op));
        let inserts: Vec<_> = (next..next + 90)
            .map(|i| (Entry::hashed(i), Entry::coin(i)))
            .collect();
        next += 90;
        live.extend(inserts.iter().map(|(op, _)| *op));
        harness.flush(&deletes, &inserts, 1 + (round as usize % 7) * 13);
        harness.check();
    }
}

#[test]
fn the_header_records_the_live_count_after_a_flush() {
    let mut harness = Harness::new("header", 512);
    let inserts: Vec<_> = (0..120).map(|i| (Entry::hashed(i), Entry::coin(i))).collect();
    harness.flush_direct(&[], &inserts, 16);
    let reopened = RobinHoodTable::open_existing(harness.scratch.path()).unwrap();
    assert_eq!(reopened.len(), 120);
}

#[test]
fn every_step_of_a_dense_flush_keeps_untouched_coins_findable() {
    let mut harness = Harness::new("dense-steps", 4 * CHUNK_SLOTS);
    let first: Vec<_> = (0..180).map(|i| (Entry::hashed(i), Entry::coin(i))).collect();
    harness.flush(&[], &first, 5);
    for round in 0..6u32 {
        let deletes: Vec<_> = (0..180)
            .filter(|i| (i + round) % 5 == 0)
            .map(Entry::hashed)
            .filter(|op| harness.model.contains_key(op))
            .collect();
        let inserts: Vec<_> = (1000 + round * 40..1040 + round * 40)
            .map(|i| (Entry::hashed(i), Entry::coin(i)))
            .collect();
        harness.flush(&deletes, &inserts, 3);
        harness.check();
    }
}
