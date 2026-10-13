use std::path::{Path, PathBuf};

use mantle::primitives::{BlockHeight, Hash256, OutPoint, Satoshi, ScriptPubKey};
use mantle_consensus::chain_view::Coin;

use super::super::{overflow_path, RobinHoodTable};

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        Self(std::env::temp_dir().join(format!(
            "mantle-rh-growth-{name}-{}-{nanos}",
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
            vout: i % 5,
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

    fn coin(i: u32) -> Coin {
        let script = if i.is_multiple_of(7) { vec![0x6a; 80] } else { vec![0x51, 0x52] };
        Coin {
            value: Satoshi::new(u64::from(i) + 1),
            script_pubkey: ScriptPubKey::from_slice(&script),
            height: BlockHeight::new(i),
            coinbase: i.is_multiple_of(3),
        }
    }
}

struct Check;

impl Check {
    fn all_present(table: &RobinHoodTable, ops: &[OutPoint]) {
        for (i, op) in (0u32..).zip(ops) {
            let coin = table.get(op).unwrap().unwrap_or_else(|| panic!("entry {i} lost"));
            assert_eq!(coin, Entry::coin(i), "entry {i} changed");
        }
    }

    fn table_len_matches(table: &RobinHoodTable, expected: usize) {
        let occupied = (0..table.slot_count)
            .filter(|slot| !table.read_bucket(*slot).unwrap().is_empty())
            .count();
        assert_eq!(occupied, expected);
        assert_eq!(table.len(), u64::try_from(expected).unwrap());
    }
}

#[test]
fn growth_keeps_every_entry_through_several_doublings() {
    let scratch = Scratch::new("doublings");
    let mut table = RobinHoodTable::open_with_capacity(scratch.path(), 16).unwrap();
    let ops: Vec<OutPoint> = (0..20_000).map(Entry::hashed).collect();
    for (i, op) in (0u32..).zip(&ops) {
        table.insert(op, &Entry::coin(i)).unwrap();
    }
    assert!(table.slot_count >= 16_384);
    Check::all_present(&table, &ops);
    Check::table_len_matches(&table, ops.len());
}

#[test]
fn growth_moves_entries_that_wrapped_past_the_last_slot() {
    let scratch = Scratch::new("wrap");
    let mut table = RobinHoodTable::open_with_capacity(scratch.path(), 16).unwrap();
    let ops: Vec<OutPoint> = (0..15).map(|i| Entry::at_hash(15, i)).collect();
    for (i, op) in (0u32..).zip(&ops) {
        table.insert(op, &Entry::coin(i)).unwrap();
    }
    assert_eq!(table.slot_count, 32);
    Check::all_present(&table, &ops);
    Check::table_len_matches(&table, ops.len());
}

#[test]
fn growth_keeps_a_long_run_that_wraps_from_mid_table() {
    let scratch = Scratch::new("mid-wrap");
    let mut table = RobinHoodTable::open_with_capacity(scratch.path(), 64).unwrap();
    let ops: Vec<OutPoint> = (0..56).map(|i| Entry::at_hash(40, i)).collect();
    for (i, op) in (0u32..).zip(&ops) {
        table.insert(op, &Entry::coin(i)).unwrap();
    }
    assert_eq!(table.slot_count, 128);
    Check::all_present(&table, &ops);
    Check::table_len_matches(&table, ops.len());
}

#[test]
fn outputs_of_one_transaction_do_not_share_a_probe_run() {
    let scratch = Scratch::new("one-tx");
    let mut table = RobinHoodTable::open_with_capacity(scratch.path(), 1 << 14).unwrap();
    let txid = Hash256::hash(b"fan-out");
    let ops: Vec<OutPoint> = (0..4_000).map(|vout| OutPoint { txid, vout }).collect();
    for (i, op) in (0u32..).zip(&ops) {
        table.insert(op, &Entry::coin(i)).unwrap();
    }
    let longest = (0..table.slot_count)
        .map(|slot| table.read_bucket(slot).unwrap().probe_distance)
        .max()
        .unwrap();
    assert!(longest < 32, "probe run of {longest} for one transaction's outputs");
    Check::all_present(&table, &ops);
}

#[test]
fn growth_survives_reopen() {
    let scratch = Scratch::new("reopen");
    let ops: Vec<OutPoint> = (0..5_000).map(Entry::hashed).collect();
    {
        let mut table = RobinHoodTable::open_with_capacity(scratch.path(), 16).unwrap();
        for (i, op) in (0u32..).zip(&ops) {
            table.insert(op, &Entry::coin(i)).unwrap();
        }
        table.sync().unwrap();
    }
    let table = RobinHoodTable::open(scratch.path()).unwrap();
    Check::all_present(&table, &ops);
    Check::table_len_matches(&table, ops.len());
}
