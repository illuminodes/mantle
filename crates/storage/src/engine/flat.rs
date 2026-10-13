use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use mantle::collections::{BuildPrehashedHasher, PrehashedMap};
use mantle::hash::ByteSliceExt;
use mantle::primitives::{BlockHeader, BlockHeight, Hash256, OutPoint, Satoshi, ScriptPubKey};
use mantle_consensus::chain_view::{Coin, NewCoin, TipInfo};

use super::header_io::HeaderStore;
use super::{Engine, EngineError};
use crate::types::{CommitBlockReq, Durability, LookupResult};

/// User-space buffer in front of the append-only logs. Sized to absorb several
/// blocks' worth of UTXO and header writes so the kernel only sees a handful
/// of large `write()` syscalls instead of thousands of tiny ones.
const WRITE_BUF_BYTES: usize = 256 * 1024;

/// Phase-1 flat-file storage engine.
///
/// - `utxo.bin`: append-only log of `(OutPoint, Option<Coin>)` records.
///   In-memory `HashMap<OutPoint, file_offset>` is rebuilt on startup.
/// - `headers.bin`: fixed-width 116-byte records keyed by height.
/// - `checkpoint.bin`: last height for which `Durability::Synced` completed.
pub struct FlatEngine {
    data_dir: PathBuf,

    utxo_file: BufWriter<File>,
    utxo_read: File,
    utxo_write_pos: u64,
    utxo_flushed_pos: u64,
    utxo_index: PrehashedMap<OutPoint, u64>,

    headers: HeaderStore,
}

impl FlatEngine {
    /// Open (or create) the engine at `data_dir`. Rebuilds the in-memory index
    /// from the log on startup, stopping at the last synced checkpoint.
    ///
    /// # Errors
    ///
    /// Returns `EngineError` if any file I/O fails during open or recovery.
    pub fn open(data_dir: &Path) -> Result<Self, EngineError> {
        std::fs::create_dir_all(data_dir)?;

        let utxo_path = data_dir.join("utxo.bin");

        let utxo_file = BufWriter::with_capacity(WRITE_BUF_BYTES, open_append(&utxo_path)?);
        let utxo_read = open_read(&utxo_path)?;
        let headers = HeaderStore::open(data_dir)?;

        let mut engine = Self {
            data_dir: data_dir.to_owned(),
            utxo_file,
            utxo_read,
            utxo_write_pos: 0,
            utxo_flushed_pos: 0,
            utxo_index: PrehashedMap::with_hasher(BuildPrehashedHasher),
            headers,
        };
        engine.recover()?;
        Ok(engine)
    }

    /// Drain the UTXO write buffer to the kernel so subsequent reads via
    /// `utxo_read` see all newly written records. Cheap when nothing is
    /// buffered.
    fn flush_utxo_writer(&mut self) -> Result<(), EngineError> {
        if self.utxo_flushed_pos != self.utxo_write_pos {
            self.utxo_file.flush()?;
            self.utxo_flushed_pos = self.utxo_write_pos;
        }
        Ok(())
    }

    fn utxo_path(&self) -> PathBuf {
        self.data_dir.join("utxo.bin")
    }
}

impl Engine for FlatEngine {
    fn read_coin(&mut self, op: &OutPoint) -> Result<Option<Coin>, EngineError> {
        let Some(&offset) = self.utxo_index.get(op) else {
            return Ok(None);
        };
        // The index can point into the still-buffered tail of the writer; drain
        // it so the read handle observes the bytes.
        if offset >= self.utxo_flushed_pos {
            self.flush_utxo_writer()?;
        }
        self.utxo_read
            .seek(SeekFrom::Start(offset))
            ?;
        read_coin_record(&mut self.utxo_read)
    }

    fn read_coins(
        &mut self,
        ops: &[OutPoint],
        out: &mut Vec<LookupResult>,
    ) -> Result<(), EngineError> {
        // If any requested outpoint maps into the still-buffered tail, flush
        // once up-front instead of branching per-record.
        let needs_flush = ops
            .iter()
            .filter_map(|op| self.utxo_index.get(op).copied())
            .any(|off| off >= self.utxo_flushed_pos);
        if needs_flush {
            self.flush_utxo_writer()?;
        }
        for &op in ops {
            let coin = if let Some(&offset) = self.utxo_index.get(&op) {
                self.utxo_read
                    .seek(SeekFrom::Start(offset))
                    ?;
                read_coin_record(&mut self.utxo_read)?
            } else {
                None
            };
            out.push(LookupResult { outpoint: op, coin });
        }
        Ok(())
    }

    fn write_block(&mut self, req: &CommitBlockReq) -> Result<(), EngineError> {
        for nc in req.created {
            let record_start = self.utxo_write_pos;
            write_coin_record(&mut self.utxo_file, nc)?;
            let spk_len = u64::try_from(nc.script_pubkey.len())
                .map_err(|_| EngineError::ScriptPubKeyTooLarge)?;
            // 36 (outpoint) + 1 (tag) + 8 (value) + 4 (height) + 1 (coinbase) + 4 (spk_len) + spk
            self.utxo_write_pos += 36 + 1 + 8 + 4 + 1 + 4 + spk_len;
            // Index points past the 36-byte outpoint to where read_coin_record starts (tag byte).
            self.utxo_index.insert(nc.outpoint, record_start + 36);
        }
        for op in req.spent {
            write_spend_record(&mut self.utxo_file, op)?;
            // 36 (outpoint) + 1 (tag)
            self.utxo_write_pos += 37;
            self.utxo_index.remove(op);
        }

        // Persist the full header so `read_header*` round-trips. MTP and
        // retarget lookups during incremental replay need every field.
        debug_assert_eq!(
            req.header.prev_block(),
            req.prev_hash,
            "CommitBlockReq.header.prev_block must match req.prev_hash"
        );
        self.headers.write_block_header(req.height, &req.header, req.hash)?;
        Ok(())
    }

    fn read_header(&self, hash: &Hash256) -> Result<Option<BlockHeader>, EngineError> {
        self.headers.read_header(hash)
    }

    fn read_header_at(&self, h: BlockHeight) -> Result<Option<BlockHeader>, EngineError> {
        self.headers.read_header_at(h)
    }

    fn write_header(&mut self, h: BlockHeight, header: &BlockHeader) -> Result<(), EngineError> {
        self.headers.write_header(h, header)
    }

    fn flush(&mut self, d: Durability) -> Result<(), EngineError> {
        if d == Durability::Synced {
            self.utxo_file.flush()?;
            self.utxo_file.get_ref().sync_all()?;
            self.utxo_flushed_pos = self.utxo_write_pos;
            self.headers.sync_checkpoint()?;
        }
        Ok(())
    }

    fn recover(&mut self) -> Result<TipInfo, EngineError> {
        self.headers.recover()?;

        // Rebuild UTXO index.
        self.utxo_index.clear();
        self.utxo_write_pos = 0;
        let utxo_path = self.utxo_path();
        if let Ok(mut uf) = File::open(&utxo_path) {
            let mut offset: u64 = 0;
            loop {
                match read_utxo_log_entry(&mut uf, offset) {
                    Ok(Some((op, Some(_), record_end))) => {
                        self.utxo_index.insert(op, offset + 36);
                        offset = record_end;
                    }
                    Ok(Some((op, None, record_end))) => {
                        self.utxo_index.remove(&op);
                        offset = record_end;
                    }
                    Ok(None) | Err(_) => {
                        self.utxo_write_pos = offset;
                        break;
                    }
                }
            }
        }

        Ok(self.headers.tip.clone())
    }

    fn tip(&self) -> TipInfo {
        self.headers.tip.clone()
    }
}

// ── UTXO log serialization ────────────────────────────────────────────────────
//
// Each record:
//   OutPoint (32 + 4 = 36 bytes)
//   tag: u8  (1 = create, 0 = spend)
//   if create:
//     value: u64 (8)
//     height: u32 (4)
//     coinbase: u8 (1)
//     script_pubkey_len: u32 (4)
//     script_pubkey: [u8; len]

fn write_coin_record<W: Write>(f: &mut W, nc: &NewCoin) -> Result<(), EngineError> {
    write_outpoint(f, &nc.outpoint)?;
    f.write_all(&[1u8])?;
    f.write_all(&nc.value.to_le_bytes())?;
    f.write_all(&nc.height.to_u32().to_le_bytes())
        ?;
    f.write_all(&[u8::from(nc.coinbase)])?;
    let spk = nc.script_pubkey;
    let spk_len = u32::try_from(spk.len()).map_err(|_| EngineError::ScriptPubKeyTooLarge)?;
    f.write_all(&spk_len.to_le_bytes())?;
    f.write_all(spk)?;
    Ok(())
}

fn write_spend_record<W: Write>(f: &mut W, op: &OutPoint) -> Result<(), EngineError> {
    write_outpoint(f, op)?;
    f.write_all(&[0u8])?;
    Ok(())
}

fn write_outpoint<W: Write>(f: &mut W, op: &OutPoint) -> Result<(), EngineError> {
    f.write_all(op.txid.as_bytes())?;
    f.write_all(&op.vout.to_le_bytes())?;
    Ok(())
}

fn read_coin_record(f: &mut File) -> Result<Option<Coin>, EngineError> {
    let mut tag = [0u8; 1];
    if f.read_exact(&mut tag).is_err() {
        return Ok(None);
    }
    if tag[0] == 0 {
        return Ok(None);
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
    let mut spk = vec![0u8; spk_len];
    f.read_exact(&mut spk)?;
    Ok(Some(Coin {
        value: Satoshi::new(value),
        script_pubkey: ScriptPubKey::from(spk),
        height: BlockHeight::new(height),
        coinbase,
    }))
}

fn read_utxo_log_entry(
    f: &mut File,
    offset: u64,
) -> Result<Option<(OutPoint, Option<Coin>, u64)>, EngineError> {
    f.seek(SeekFrom::Start(offset))?;
    let mut op_buf = [0u8; 36];
    if f.read_exact(&mut op_buf).is_err() {
        return Ok(None);
    }
    let txid = Hash256::from_bytes(op_buf.read_hash(0));
    let vout = op_buf.read_u32_le(32);
    let op = OutPoint { txid, vout };

    let mut tag = [0u8; 1];
    f.read_exact(&mut tag)?;
    if tag[0] == 0 {
        return Ok(Some((op, None, offset + 37)));
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
    let mut spk = vec![0u8; spk_len];
    f.read_exact(&mut spk)?;
    let coin = Coin {
        value: Satoshi::new(value),
        script_pubkey: ScriptPubKey::from(spk),
        height: BlockHeight::new(height),
        coinbase,
    };
    // 36 (outpoint) + 1 (tag) + 8 + 4 + 1 + 4 + spk_len
    let record_end = offset
        + 36
        + 1
        + 8
        + 4
        + 1
        + 4
        + u64::try_from(spk_len).map_err(|_| EngineError::ScriptLenOverflow)?;
    Ok(Some((op, Some(coin), record_end)))
}

fn open_append(path: &Path) -> Result<File, EngineError> {
    Ok(OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)?)
}

fn open_read(path: &Path) -> Result<File, EngineError> {
    Ok(OpenOptions::new().read(true).open(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantle::primitives::{BlockTime, BlockVersion, CompactBits, Hash256, Nonce};

    struct TmpDir(std::path::PathBuf);
    impl TmpDir {
        fn new() -> Self {
            use std::time::{SystemTime, UNIX_EPOCH};
            let ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .subsec_nanos();
            let path =
                std::env::temp_dir().join(format!("mantle-test-{}-{}", std::process::id(), ns));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tmp() -> TmpDir {
        TmpDir::new()
    }

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
    fn write_and_read_header_roundtrips_every_field() {
        let dir = tmp();
        let mut eng = FlatEngine::open(dir.path()).unwrap();
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
    fn write_and_read_coin() {
        let dir = tmp();
        let mut eng = FlatEngine::open(dir.path()).unwrap();
        let op = OutPoint {
            txid: Hash256::from_bytes([1u8; 32]),
            vout: 0,
        };
        let nc = NewCoin {
            outpoint: op,
            value: Satoshi::new(5_000_000_000),
            script_pubkey: &[0xac],
            coinbase: true,
            height: BlockHeight::new(1),
        };
        let req = crate::types::CommitBlockReq {
            token: crate::types::ReqToken(1),
            height: BlockHeight::new(1),
            hash: Hash256::from_bytes([2u8; 32]),
            prev_hash: Hash256::ZERO,
            header: make_header(0),
            created: &[nc],
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
    fn spend_removes_coin() {
        let dir = tmp();
        let mut eng = FlatEngine::open(dir.path()).unwrap();
        let op = OutPoint {
            txid: Hash256::from_bytes([3u8; 32]),
            vout: 0,
        };
        let nc = NewCoin {
            outpoint: op,
            value: Satoshi::new(1000),
            script_pubkey: &[],
            coinbase: false,
            height: BlockHeight::new(10),
        };
        let req1 = crate::types::CommitBlockReq {
            token: crate::types::ReqToken(1),
            height: BlockHeight::new(10),
            hash: Hash256::from_bytes([4u8; 32]),
            prev_hash: Hash256::ZERO,
            header: make_header(0),
            created: &[nc],
            spent: &[],
            block_bytes: None,
            durability: Durability::Memory,
        };
        eng.write_block(&req1).unwrap();
        assert!(eng.read_coin(&op).unwrap().is_some());

        let req2 = crate::types::CommitBlockReq {
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
    fn flush_synced_survives_reopen() {
        let dir = tmp();
        let op = OutPoint {
            txid: Hash256::from_bytes([0xAA; 32]),
            vout: 0,
        };
        {
            let mut eng = FlatEngine::open(dir.path()).unwrap();
            let nc = NewCoin {
                outpoint: op,
                value: Satoshi::new(42_000),
                script_pubkey: &[0x51],
                coinbase: false,
                height: BlockHeight::new(1),
            };
            let req = crate::types::CommitBlockReq {
                token: crate::types::ReqToken(0),
                height: BlockHeight::new(1),
                hash: Hash256::from_bytes([0xBB; 32]),
                prev_hash: Hash256::ZERO,
                header: make_header(100),
                created: &[nc],
                spent: &[],
                block_bytes: None,
                durability: Durability::Memory,
            };
            eng.write_block(&req).unwrap();
            eng.flush(Durability::Synced).unwrap();
        }
        // Reopen from the same directory.
        let mut eng2 = FlatEngine::open(dir.path()).unwrap();
        // Coin must survive recovery.
        let coin = eng2.read_coin(&op).unwrap().unwrap();
        assert_eq!(coin.value.to_u64(), 42_000);
        assert!(!coin.coinbase);
        assert_eq!(coin.height, BlockHeight::new(1));
        // Tip must match the flushed block.
        let tip = eng2.tip();
        assert_eq!(tip.height, BlockHeight::new(1));
        assert_eq!(tip.hash, Hash256::from_bytes([0xBB; 32]));
    }

    #[test]
    fn recover_rebuilds_index() {
        let dir = tmp();
        let op = OutPoint {
            txid: Hash256::from_bytes([7u8; 32]),
            vout: 1,
        };
        {
            let mut eng = FlatEngine::open(dir.path()).unwrap();
            let nc = NewCoin {
                outpoint: op,
                value: Satoshi::new(999),
                script_pubkey: &[0x51],
                coinbase: false,
                height: BlockHeight::new(5),
            };
            let req = crate::types::CommitBlockReq {
                token: crate::types::ReqToken(1),
                height: BlockHeight::new(5),
                hash: Hash256::from_bytes([8u8; 32]),
                prev_hash: Hash256::ZERO,
                header: make_header(0),
                created: &[nc],
                spent: &[],
                block_bytes: None,
                durability: Durability::Memory,
            };
            eng.write_block(&req).unwrap();
        }
        let mut eng2 = FlatEngine::open(dir.path()).unwrap();
        let coin = eng2.read_coin(&op).unwrap().unwrap();
        assert_eq!(coin.value.to_u64(), 999);
    }

    #[test]
    fn read_coins_batch() {
        let dir = tmp();
        let mut eng = FlatEngine::open(dir.path()).unwrap();
        let op1 = OutPoint { txid: Hash256::from_bytes([10u8; 32]), vout: 0 };
        let op2 = OutPoint { txid: Hash256::from_bytes([11u8; 32]), vout: 0 };
        let op_missing = OutPoint { txid: Hash256::from_bytes([99u8; 32]), vout: 0 };
        let nc1 = NewCoin {
            outpoint: op1,
            value: Satoshi::new(1000),
            script_pubkey: &[0x51],
            coinbase: false,
            height: BlockHeight::new(1),
        };
        let nc2 = NewCoin {
            outpoint: op2,
            value: Satoshi::new(2000),
            script_pubkey: &[0x51],
            coinbase: false,
            height: BlockHeight::new(1),
        };
        let req = crate::types::CommitBlockReq {
            token: crate::types::ReqToken(0),
            height: BlockHeight::new(1),
            hash: Hash256::from_bytes([12u8; 32]),
            prev_hash: Hash256::ZERO,
            header: make_header(1000),
            created: &[nc1, nc2],
            spent: &[],
            block_bytes: None,
            durability: Durability::Memory,
        };
        eng.write_block(&req).unwrap();
        let mut results = Vec::new();
        eng.read_coins(&[op1, op2, op_missing], &mut results).unwrap();
        assert_eq!(results.len(), 3);
        assert!(results[0].coin.is_some());
        assert_eq!(results[0].coin.as_ref().unwrap().value, Satoshi::new(1000));
        assert!(results[1].coin.is_some());
        assert_eq!(results[1].coin.as_ref().unwrap().value, Satoshi::new(2000));
        assert!(results[2].coin.is_none());
    }

    #[test]
    fn recover_with_utxo_log_spends() {
        // Write two blocks: one creates two coins, another spends one.
        // Flush synced, reopen. Recovery must replay both creates and the spend
        // in the UTXO log, covering the (op, None, record_end) branch.
        let dir = tmp();
        let op1 = OutPoint { txid: Hash256::from_bytes([0xA0; 32]), vout: 0 };
        let op2 = OutPoint { txid: Hash256::from_bytes([0xA1; 32]), vout: 0 };
        {
            let mut eng = FlatEngine::open(dir.path()).unwrap();
            let nc1 = NewCoin {
                outpoint: op1,
                value: Satoshi::new(1000),
                script_pubkey: &[0x51],
                coinbase: false,
                height: BlockHeight::new(1),
            };
            let nc2 = NewCoin {
                outpoint: op2,
                value: Satoshi::new(2000),
                script_pubkey: &[0x51],
                coinbase: false,
                height: BlockHeight::new(1),
            };
            let req1 = crate::types::CommitBlockReq {
                token: crate::types::ReqToken(0),
                height: BlockHeight::new(1),
                hash: Hash256::from_bytes([0xB0; 32]),
                prev_hash: Hash256::ZERO,
                header: make_header(100),
                created: &[nc1, nc2],
                spent: &[],
                block_bytes: None,
                durability: Durability::Synced,
            };
            eng.write_block(&req1).unwrap();

            // Block 2: spend op1.
            let req2 = crate::types::CommitBlockReq {
                token: crate::types::ReqToken(1),
                height: BlockHeight::new(2),
                hash: Hash256::from_bytes([0xB1; 32]),
                prev_hash: Hash256::from_bytes([0xB0; 32]),
                header: {
                    let mut h = make_header(200);
                    h.set_prev_block(Hash256::from_bytes([0xB0; 32]));
                    h
                },
                created: &[],
                spent: &[op1],
                block_bytes: None,
                durability: Durability::Synced,
            };
            eng.write_block(&req2).unwrap();
            eng.flush(Durability::Synced).unwrap();
        }
        // Reopen — recovery replays the UTXO log with both creates and the spend.
        let mut eng2 = FlatEngine::open(dir.path()).unwrap();
        // op1 was spent — should be gone.
        assert!(eng2.read_coin(&op1).unwrap().is_none());
        // op2 was not spent — should survive.
        let coin2 = eng2.read_coin(&op2).unwrap().unwrap();
        assert_eq!(coin2.value.to_u64(), 2000);
    }
}
