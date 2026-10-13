use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use mantle::primitives::{
    BlockHeader, BlockHeight, Hash256, OutPoint,
};
use mantle_consensus::chain_view::{Coin, TipInfo};
use mantle_storage::engine::header_io::HeaderStore;
use mantle_storage::engine::{Engine, EngineError};
use mantle_storage::types::{CommitBlockReq, Durability};
use mantle_utxo_set::{ArenaUtxoSet, ConnectScratch};

use crate::wal_io::{read_wal_entry, write_wal_create, write_wal_spend, WalEntry};

const WRITE_BUF_BYTES: usize = 256 * 1024;

pub struct ArenaEngine {
    data_dir: PathBuf,
    utxo_set: ArenaUtxoSet,
    scratch: ConnectScratch,

    wal_file: BufWriter<File>,
    wal_write_pos: u64,

    headers: HeaderStore,
}

impl ArenaEngine {
    /// # Errors
    /// Returns `EngineError` if any file I/O fails during open or recovery.
    pub fn open(data_dir: &Path) -> Result<Self, EngineError> {
        std::fs::create_dir_all(data_dir)?;

        let wal_path = data_dir.join("utxo_wal.bin");
        let wal_file = BufWriter::with_capacity(WRITE_BUF_BYTES, open_append(&wal_path)?);
        let headers = HeaderStore::open(data_dir)?;

        let mut engine = Self {
            data_dir: data_dir.to_owned(),
            utxo_set: ArenaUtxoSet::new(),
            scratch: ConnectScratch::new(),
            wal_file,
            wal_write_pos: 0,
            headers,
        };
        engine.recover()?;
        Ok(engine)
    }

    fn wal_path(&self) -> PathBuf {
        self.data_dir.join("utxo_wal.bin")
    }
}

impl Engine for ArenaEngine {
    fn read_coin(&mut self, op: &OutPoint) -> Result<Option<Coin>, EngineError> {
        Ok(self.utxo_set.get(op))
    }

    fn write_block(&mut self, req: &CommitBlockReq) -> Result<(), EngineError> {
        for nc in req.created {
            write_wal_create(&mut self.wal_file, nc)?;
            let spk_len = u64::try_from(nc.script_pubkey.len())
                .map_err(|_| EngineError::ScriptPubKeyTooLarge)?;
            self.wal_write_pos += 36 + 1 + 8 + 4 + 1 + 4 + spk_len;
        }
        for op in req.spent {
            write_wal_spend(&mut self.wal_file, op)?;
            self.wal_write_pos += 37;
        }

        let undo = self
            .utxo_set
            .connect_block_best_effort(&mut self.scratch, req.height, req.created, req.spent);
        self.scratch.reclaim(undo);

        debug_assert_eq!(req.header.prev_block(), req.prev_hash);
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
            self.wal_file.flush()?;
            self.wal_file.get_ref().sync_all()?;
            self.headers.sync_checkpoint()?;
        }
        Ok(())
    }

    fn recover(&mut self) -> Result<TipInfo, EngineError> {
        self.headers.recover()?;

        self.utxo_set = ArenaUtxoSet::new();
        self.wal_write_pos = 0;
        let wal_path = self.wal_path();
        if let Ok(mut wf) = File::open(&wal_path) {
            let mut offset: u64 = 0;
            loop {
                match read_wal_entry(&mut wf, offset) {
                    Ok(Some(WalEntry::Create(nc, record_end))) => {
                        let _ = self.utxo_set.connect_block(nc.height, &[nc], &[]);
                        offset = record_end;
                    }
                    Ok(Some(WalEntry::Spend(op, record_end))) => {
                        let _ = self.utxo_set.connect_block(
                            self.headers.tip.height,
                            &[],
                            &[op],
                        );
                        offset = record_end;
                    }
                    Ok(None) | Err(_) => {
                        self.wal_write_pos = offset;
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

fn open_append(path: &Path) -> Result<File, EngineError> {
    Ok(OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantle::primitives::{BlockTime, BlockVersion, CompactBits, Nonce, Satoshi};
    use mantle_consensus::chain_view::NewCoin;
    use mantle_storage::types::ReqToken;

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new() -> Self {
            use std::time::{SystemTime, UNIX_EPOCH};
            let ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
            let path = std::env::temp_dir()
                .join(format!("mantle-arena-eng-{}-{}", std::process::id(), ns));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path { &self.0 }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    fn make_header(prev: Hash256, time: u32) -> BlockHeader {
        BlockHeader::new(
            BlockVersion::new(1), prev, Hash256::ZERO,
            BlockTime::new(time), CompactBits::new(0x1d00_ffff), Nonce::new(0),
        )
    }

    fn make_outpoint(i: u32) -> OutPoint {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&i.to_le_bytes());
        OutPoint { txid: Hash256::from_bytes(b), vout: 0 }
    }

    #[test]
    fn open_empty_dir_succeeds() {
        let dir = TmpDir::new();
        let eng = ArenaEngine::open(dir.path()).unwrap();
        assert_eq!(eng.tip().height, BlockHeight::ZERO);
    }

    #[test]
    fn write_block_and_read_coin() {
        let dir = TmpDir::new();
        let mut eng = ArenaEngine::open(dir.path()).unwrap();
        let op = make_outpoint(1);
        let spk: &[u8] = &[0x51];
        let header = make_header(Hash256::ZERO, 1000);
        let hash = header.hash();
        let nc = NewCoin {
            outpoint: op, value: Satoshi::new(5000), script_pubkey: spk,
            coinbase: false, height: BlockHeight::new(1),
        };
        let req = CommitBlockReq {
            token: ReqToken(0), height: BlockHeight::new(1), hash,
            prev_hash: Hash256::ZERO, header, created: &[nc], spent: &[],
            block_bytes: None, durability: Durability::Memory,
        };
        eng.write_block(&req).unwrap();
        let coin = eng.read_coin(&op).unwrap();
        assert!(coin.is_some());
        assert_eq!(coin.unwrap().value, Satoshi::new(5000));
    }

    #[test]
    fn write_and_spend_coin() {
        let dir = TmpDir::new();
        let mut eng = ArenaEngine::open(dir.path()).unwrap();
        let op = make_outpoint(2);
        let spk: &[u8] = &[0x51];
        let header1 = make_header(Hash256::ZERO, 1000);
        let hash1 = header1.hash();
        let nc = NewCoin {
            outpoint: op, value: Satoshi::new(3000), script_pubkey: spk,
            coinbase: false, height: BlockHeight::new(1),
        };
        let req1 = CommitBlockReq {
            token: ReqToken(0), height: BlockHeight::new(1), hash: hash1,
            prev_hash: Hash256::ZERO, header: header1, created: &[nc], spent: &[],
            block_bytes: None, durability: Durability::Memory,
        };
        eng.write_block(&req1).unwrap();
        assert!(eng.read_coin(&op).unwrap().is_some());

        let header2 = make_header(hash1, 2000);
        let hash2 = header2.hash();
        let req2 = CommitBlockReq {
            token: ReqToken(1), height: BlockHeight::new(2), hash: hash2,
            prev_hash: hash1, header: header2, created: &[], spent: &[op],
            block_bytes: None, durability: Durability::Memory,
        };
        eng.write_block(&req2).unwrap();
        assert!(eng.read_coin(&op).unwrap().is_none());
    }

    #[test]
    fn flush_and_recover() {
        let dir = TmpDir::new();
        let op = make_outpoint(3);
        let spk: &[u8] = &[0x51];
        let header = make_header(Hash256::ZERO, 1000);
        let hash = header.hash();
        {
            let mut eng = ArenaEngine::open(dir.path()).unwrap();
            let nc = NewCoin {
                outpoint: op, value: Satoshi::new(7000), script_pubkey: spk,
                coinbase: false, height: BlockHeight::new(1),
            };
            let req = CommitBlockReq {
                token: ReqToken(0), height: BlockHeight::new(1), hash,
                prev_hash: Hash256::ZERO, header, created: &[nc], spent: &[],
                block_bytes: None, durability: Durability::Synced,
            };
            eng.write_block(&req).unwrap();
            eng.flush(Durability::Synced).unwrap();
        }
        let mut eng = ArenaEngine::open(dir.path()).unwrap();
        assert_eq!(eng.tip().height, BlockHeight::new(1));
        let coin = eng.read_coin(&op).unwrap();
        assert!(coin.is_some());
        assert_eq!(coin.unwrap().value, Satoshi::new(7000));
    }

    #[test]
    fn header_write_and_read() {
        let dir = TmpDir::new();
        let mut eng = ArenaEngine::open(dir.path()).unwrap();
        let header = make_header(Hash256::ZERO, 12345);
        eng.write_header(BlockHeight::new(0), &header).unwrap();
        let got = eng.read_header_at(BlockHeight::new(0)).unwrap().unwrap();
        assert_eq!(got.time().to_u32(), 12345);
    }

    #[test]
    fn read_header_out_of_range_returns_none() {
        let dir = TmpDir::new();
        let eng = ArenaEngine::open(dir.path()).unwrap();
        let got = eng.read_header_at(BlockHeight::new(999)).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn read_coins_batch() {
        let dir = TmpDir::new();
        let mut eng = ArenaEngine::open(dir.path()).unwrap();
        let op1 = make_outpoint(10);
        let op2 = make_outpoint(11);
        let op_missing = make_outpoint(99);
        let spk: &[u8] = &[0x51];
        let header = make_header(Hash256::ZERO, 1000);
        let hash = header.hash();
        let nc1 = NewCoin {
            outpoint: op1, value: Satoshi::new(1000), script_pubkey: spk,
            coinbase: false, height: BlockHeight::new(1),
        };
        let nc2 = NewCoin {
            outpoint: op2, value: Satoshi::new(2000), script_pubkey: spk,
            coinbase: false, height: BlockHeight::new(1),
        };
        let req = CommitBlockReq {
            token: ReqToken(0), height: BlockHeight::new(1), hash,
            prev_hash: Hash256::ZERO, header,
            created: &[nc1, nc2], spent: &[],
            block_bytes: None, durability: Durability::Memory,
        };
        eng.write_block(&req).unwrap();
        let mut results = Vec::new();
        eng.read_coins(&[op1, op2, op_missing], &mut results).unwrap();
        assert_eq!(results.len(), 3);
        assert!(results[0].coin.is_some());
        assert!(results[1].coin.is_some());
        assert!(results[2].coin.is_none());
    }

    #[test]
    fn recover_with_wal_spends() {
        let dir = TmpDir::new();
        let op1 = make_outpoint(50);
        let op2 = make_outpoint(51);
        let spk: &[u8] = &[0x51];
        let header1 = make_header(Hash256::ZERO, 1000);
        let hash1 = header1.hash();
        {
            let mut eng = ArenaEngine::open(dir.path()).unwrap();
            let nc1 = NewCoin {
                outpoint: op1, value: Satoshi::new(1000), script_pubkey: spk,
                coinbase: false, height: BlockHeight::new(1),
            };
            let nc2 = NewCoin {
                outpoint: op2, value: Satoshi::new(2000), script_pubkey: spk,
                coinbase: false, height: BlockHeight::new(1),
            };
            let req1 = CommitBlockReq {
                token: ReqToken(0), height: BlockHeight::new(1), hash: hash1,
                prev_hash: Hash256::ZERO, header: header1,
                created: &[nc1, nc2], spent: &[],
                block_bytes: None, durability: Durability::Synced,
            };
            eng.write_block(&req1).unwrap();

            let header2 = make_header(hash1, 2000);
            let hash2 = header2.hash();
            let req2 = CommitBlockReq {
                token: ReqToken(1), height: BlockHeight::new(2), hash: hash2,
                prev_hash: hash1, header: header2,
                created: &[], spent: &[op1],
                block_bytes: None, durability: Durability::Synced,
            };
            eng.write_block(&req2).unwrap();
            eng.flush(Durability::Synced).unwrap();
        }
        let mut eng2 = ArenaEngine::open(dir.path()).unwrap();
        assert!(eng2.read_coin(&op1).unwrap().is_none());
        let coin2 = eng2.read_coin(&op2).unwrap().unwrap();
        assert_eq!(coin2.value, Satoshi::new(2000));
    }

    #[test]
    fn recover_checkpoint_height_zero() {
        let dir = TmpDir::new();
        {
            let _eng = ArenaEngine::open(dir.path()).unwrap();
        }
        let eng2 = ArenaEngine::open(dir.path()).unwrap();
        assert_eq!(eng2.tip().height, BlockHeight::ZERO);
    }
}
