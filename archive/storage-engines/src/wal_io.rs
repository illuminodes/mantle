use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use mantle::hash::ByteSliceExt;
use mantle::primitives::{BlockHeight, Hash256, OutPoint, Satoshi};
use mantle_consensus::chain_view::NewCoin;

use mantle_storage::engine::EngineError;

// ── WAL record format ────────────────────────────────────────────────────────
//
// Create record:
//   outpoint (36) | tag=1 (1) | value (8) | height (4) | coinbase (1) | spk_len (4) | spk
// Spend record:
//   outpoint (36) | tag=0 (1)

pub(crate) enum WalEntry<'a> {
    Create(NewCoin<'a>, u64),
    Spend(OutPoint, u64),
}

pub(crate) fn write_wal_create<W: Write>(f: &mut W, nc: &NewCoin) -> Result<(), EngineError> {
    f.write_all(nc.outpoint.txid.as_bytes())?;
    f.write_all(&nc.outpoint.vout.to_le_bytes())?;
    f.write_all(&[1u8])?;
    f.write_all(&nc.value.to_le_bytes())?;
    f.write_all(&nc.height.to_u32().to_le_bytes())?;
    f.write_all(&[u8::from(nc.coinbase)])?;
    let spk_len =
        u32::try_from(nc.script_pubkey.len()).map_err(|_| EngineError::ScriptPubKeyTooLarge)?;
    f.write_all(&spk_len.to_le_bytes())?;
    f.write_all(nc.script_pubkey)?;
    Ok(())
}

pub(crate) fn write_wal_spend<W: Write>(f: &mut W, op: &OutPoint) -> Result<(), EngineError> {
    f.write_all(op.txid.as_bytes())?;
    f.write_all(&op.vout.to_le_bytes())?;
    f.write_all(&[0u8])?;
    Ok(())
}

pub(crate) fn read_wal_entry(
    f: &mut File,
    offset: u64,
) -> Result<Option<WalEntry<'static>>, EngineError> {
    f.seek(SeekFrom::Start(offset))?;
    let mut op_buf = [0u8; 36];
    if f.read_exact(&mut op_buf).is_err() {
        return Ok(None);
    }
    let txid = Hash256::from_bytes(op_buf.read_hash(0));
    let vout = op_buf.read_u32_le(32);
    let outpoint = OutPoint { txid, vout };

    let mut tag = [0u8; 1];
    f.read_exact(&mut tag)?;
    if tag[0] == 0 {
        return Ok(Some(WalEntry::Spend(outpoint, offset + 37)));
    }

    let mut buf8 = [0u8; 8];
    f.read_exact(&mut buf8)?;
    let value = u64::from_le_bytes(buf8);
    let mut buf4 = [0u8; 4];
    f.read_exact(&mut buf4)?;
    let height = u32::from_le_bytes(buf4);
    let mut tag1 = [0u8; 1];
    f.read_exact(&mut tag1)?;
    let coinbase = tag1[0] != 0;
    f.read_exact(&mut buf4)?;
    let spk_len =
        usize::try_from(u32::from_le_bytes(buf4)).map_err(|_| EngineError::ScriptLenOverflow)?;

    // Leak the script bytes so they live as 'static for the NewCoin.
    // This only runs during recovery (once at startup).
    let mut spk = vec![0u8; spk_len];
    f.read_exact(&mut spk)?;
    let spk_static: &'static [u8] = Vec::leak(spk);

    let record_end = offset + 36 + 1 + 8 + 4 + 1 + 4
        + u64::try_from(spk_len).map_err(|_| EngineError::ScriptLenOverflow)?;

    Ok(Some(WalEntry::Create(
        NewCoin {
            outpoint,
            value: Satoshi::new(value),
            script_pubkey: spk_static,
            coinbase,
            height: BlockHeight::new(height),
        },
        record_end,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufWriter;

    fn make_outpoint(i: u32) -> OutPoint {
        let mut txid_bytes = [0u8; 32];
        txid_bytes[..4].copy_from_slice(&i.to_le_bytes());
        OutPoint {
            txid: Hash256::from_bytes(txid_bytes),
            vout: i,
        }
    }

    fn make_new_coin(i: u32, spk: &[u8]) -> NewCoin<'_> {
        NewCoin {
            outpoint: make_outpoint(i),
            value: Satoshi::new(u64::from(i) * 1_000_000),
            script_pubkey: spk,
            coinbase: i == 0,
            height: BlockHeight::new(100 + i),
        }
    }

    /// Write several WAL entries (mix of Create and Spend), then read them
    /// back with `read_wal_entry` and verify all fields match.
    #[test]
    fn round_trip_mixed_entries() {
        let dir = std::env::temp_dir().join(format!(
            "mantle-wal-io-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let wal_path = dir.join("test_wal.bin");

        // --- write phase ---
        let spk0: &[u8] = &[0xac, 0x51];
        let spk1: &[u8] = &[0x76, 0xa9, 0x14];
        let spk3: &[u8] = &[0x00, 0x20, 0xab, 0xcd];

        let nc0 = make_new_coin(0, spk0);
        let nc1 = make_new_coin(1, spk1);
        let op_spend = make_outpoint(0);
        let nc3 = make_new_coin(3, spk3);

        {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&wal_path)
                .unwrap();
            let mut w = BufWriter::new(f);
            write_wal_create(&mut w, &nc0).unwrap();
            write_wal_create(&mut w, &nc1).unwrap();
            write_wal_spend(&mut w, &op_spend).unwrap();
            write_wal_create(&mut w, &nc3).unwrap();
            w.flush().unwrap();
        }

        // --- read phase ---
        let mut rf = File::open(&wal_path).unwrap();
        let mut offset: u64 = 0;

        // Entry 0: Create nc0
        match read_wal_entry(&mut rf, offset).unwrap().unwrap() {
            WalEntry::Create(nc, next) => {
                assert_eq!(nc.outpoint, nc0.outpoint);
                assert_eq!(nc.value.to_u64(), nc0.value.to_u64());
                assert_eq!(nc.script_pubkey, spk0);
                assert!(nc.coinbase);
                assert_eq!(nc.height.to_u32(), 100);
                offset = next;
            }
            WalEntry::Spend(..) => panic!("expected Create"),
        }

        // Entry 1: Create nc1
        match read_wal_entry(&mut rf, offset).unwrap().unwrap() {
            WalEntry::Create(nc, next) => {
                assert_eq!(nc.outpoint, nc1.outpoint);
                assert_eq!(nc.value.to_u64(), 1_000_000);
                assert_eq!(nc.script_pubkey, spk1);
                assert!(!nc.coinbase);
                assert_eq!(nc.height.to_u32(), 101);
                offset = next;
            }
            WalEntry::Spend(..) => panic!("expected Create"),
        }

        // Entry 2: Spend op_spend
        match read_wal_entry(&mut rf, offset).unwrap().unwrap() {
            WalEntry::Spend(op, next) => {
                assert_eq!(op, op_spend);
                offset = next;
            }
            WalEntry::Create(..) => panic!("expected Spend"),
        }

        // Entry 3: Create nc3
        match read_wal_entry(&mut rf, offset).unwrap().unwrap() {
            WalEntry::Create(nc, next) => {
                assert_eq!(nc.outpoint, nc3.outpoint);
                assert_eq!(nc.value.to_u64(), 3_000_000);
                assert_eq!(nc.script_pubkey, spk3);
                assert!(!nc.coinbase);
                assert_eq!(nc.height.to_u32(), 103);
                offset = next;
            }
            WalEntry::Spend(..) => panic!("expected Create"),
        }

        // Past EOF -> None
        assert!(read_wal_entry(&mut rf, offset).unwrap().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Reading from an offset past the end of the file returns `None`.
    #[test]
    fn read_past_eof_returns_none() {
        let dir = std::env::temp_dir().join(format!(
            "mantle-wal-io-eof-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let wal_path = dir.join("empty_wal.bin");

        // Create an empty file
        std::fs::write(&wal_path, &[]).unwrap();
        let mut f = File::open(&wal_path).unwrap();

        // Reading at offset 0 of an empty file -> None
        assert!(read_wal_entry(&mut f, 0).unwrap().is_none());

        // Reading at a large offset -> None
        assert!(read_wal_entry(&mut f, 9999).unwrap().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Write a spend record and read it back, verifying outpoint fields.
    #[test]
    fn write_wal_spend_round_trip() {
        let dir = std::env::temp_dir().join(format!(
            "mantle-wal-io-spend-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let wal_path = dir.join("spend_wal.bin");

        let op = OutPoint {
            txid: Hash256::from_bytes([0xaa; 32]),
            vout: 42,
        };

        {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&wal_path)
                .unwrap();
            let mut w = BufWriter::new(f);
            write_wal_spend(&mut w, &op).unwrap();
            w.flush().unwrap();
        }

        let mut rf = File::open(&wal_path).unwrap();
        match read_wal_entry(&mut rf, 0).unwrap().unwrap() {
            WalEntry::Spend(got, next) => {
                assert_eq!(got.txid, op.txid);
                assert_eq!(got.vout, 42);
                assert_eq!(next, 37);
            }
            WalEntry::Create(..) => panic!("expected Spend"),
        }

        // Nothing after the single spend record
        assert!(read_wal_entry(&mut rf, 37).unwrap().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
