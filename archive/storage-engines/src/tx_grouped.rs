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
use mantle_utxo_set::{ConnectScratch, UtxoSet};

use crate::wal_io::{read_wal_entry, write_wal_create, write_wal_spend, WalEntry};

const WRITE_BUF_BYTES: usize = 256 * 1024;

pub struct TxGroupedEngine {
    data_dir: PathBuf,
    utxo_set: UtxoSet,
    scratch: ConnectScratch,

    wal_file: BufWriter<File>,
    wal_write_pos: u64,

    headers: HeaderStore,
}

impl TxGroupedEngine {
    /// # Errors
    /// Returns `EngineError` if any file I/O fails during open or recovery.
    pub fn open(data_dir: &Path) -> Result<Self, EngineError> {
        std::fs::create_dir_all(data_dir)?;

        let wal_path = data_dir.join("utxo_wal.bin");
        let wal_file = BufWriter::with_capacity(WRITE_BUF_BYTES, open_append(&wal_path)?);
        let headers = HeaderStore::open(data_dir)?;

        let mut engine = Self {
            data_dir: data_dir.to_owned(),
            utxo_set: UtxoSet::new(),
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

impl Engine for TxGroupedEngine {
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

        self.utxo_set = UtxoSet::new();
        self.wal_write_pos = 0;
        let wal_path = self.wal_path();
        if let Ok(mut wf) = File::open(&wal_path) {
            let mut offset: u64 = 0;
            loop {
                match read_wal_entry(&mut wf, offset) {
                    Ok(Some(WalEntry::Create(nc, record_end))) => {
                        let _ = self.utxo_set.connect_block(
                            nc.height,
                            &[nc],
                            &[],
                        );
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

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new() -> Self {
            use std::time::{SystemTime, UNIX_EPOCH};
            let ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .subsec_nanos();
            let path = std::env::temp_dir()
                .join(format!("mantle-txg-test-{}-{}", std::process::id(), ns));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
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

    fn make_outpoint(i: u32) -> OutPoint {
        let mut txid_bytes = [0u8; 32];
        txid_bytes[..4].copy_from_slice(&i.to_le_bytes());
        OutPoint {
            txid: Hash256::from_bytes(txid_bytes),
            vout: 0,
        }
    }

    fn make_block_hash(i: u32) -> Hash256 {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&(i + 10_000).to_le_bytes());
        Hash256::from_bytes(bytes)
    }

    #[test]
    fn write_and_read_coin() {
        let dir = TmpDir::new();
        let mut eng = TxGroupedEngine::open(dir.path()).unwrap();
        let op = make_outpoint(1);
        let nc = NewCoin {
            outpoint: op,
            value: Satoshi::new(5_000_000_000),
            script_pubkey: &[0xac],
            coinbase: true,
            height: BlockHeight::new(1),
        };
        let req = CommitBlockReq {
            token: mantle_storage::types::ReqToken(1),
            height: BlockHeight::new(1),
            hash: make_block_hash(1),
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
        let dir = TmpDir::new();
        let mut eng = TxGroupedEngine::open(dir.path()).unwrap();
        let op = make_outpoint(1);
        let nc = NewCoin {
            outpoint: op,
            value: Satoshi::new(1000),
            script_pubkey: &[],
            coinbase: false,
            height: BlockHeight::new(10),
        };
        let req1 = CommitBlockReq {
            token: mantle_storage::types::ReqToken(1),
            height: BlockHeight::new(10),
            hash: make_block_hash(10),
            prev_hash: Hash256::ZERO,
            header: make_header(0),
            created: &[nc],
            spent: &[],
            block_bytes: None,
            durability: Durability::Memory,
        };
        eng.write_block(&req1).unwrap();
        assert!(eng.read_coin(&op).unwrap().is_some());

        let mut h2 = make_header(1);
        h2.set_prev_block(make_block_hash(10));
        let req2 = CommitBlockReq {
            token: mantle_storage::types::ReqToken(2),
            height: BlockHeight::new(11),
            hash: make_block_hash(11),
            prev_hash: make_block_hash(10),
            header: h2,
            created: &[],
            spent: &[op],
            block_bytes: None,
            durability: Durability::Memory,
        };
        eng.write_block(&req2).unwrap();
        assert!(eng.read_coin(&op).unwrap().is_none());
    }

    #[test]
    fn write_and_read_header() {
        let dir = TmpDir::new();
        let mut eng = TxGroupedEngine::open(dir.path()).unwrap();
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
    fn recover_rebuilds_utxo_set() {
        let dir = TmpDir::new();
        let op = make_outpoint(1);
        {
            let mut eng = TxGroupedEngine::open(dir.path()).unwrap();
            let nc = NewCoin {
                outpoint: op,
                value: Satoshi::new(999),
                script_pubkey: &[0x51],
                coinbase: false,
                height: BlockHeight::new(5),
            };
            let req = CommitBlockReq {
                token: mantle_storage::types::ReqToken(1),
                height: BlockHeight::new(5),
                hash: make_block_hash(5),
                prev_hash: Hash256::ZERO,
                header: make_header(0),
                created: &[nc],
                spent: &[],
                block_bytes: None,
                durability: Durability::Memory,
            };
            eng.write_block(&req).unwrap();
            eng.flush(Durability::Synced).unwrap();
        }
        let mut eng2 = TxGroupedEngine::open(dir.path()).unwrap();
        let coin = eng2.read_coin(&op).unwrap().unwrap();
        assert_eq!(coin.value.to_u64(), 999);
    }

    #[test]
    fn recover_with_wal_spends() {
        // Write two blocks: one creates two coins, another spends one.
        // Flush synced, reopen. Recovery must replay both creates and the spend.
        let dir = TmpDir::new();
        let op1 = make_outpoint(50);
        let op2 = make_outpoint(51);
        {
            let mut eng = TxGroupedEngine::open(dir.path()).unwrap();
            let nc1 = NewCoin {
                outpoint: op1, value: Satoshi::new(1000), script_pubkey: &[0x51],
                coinbase: false, height: BlockHeight::new(1),
            };
            let nc2 = NewCoin {
                outpoint: op2, value: Satoshi::new(2000), script_pubkey: &[0x51],
                coinbase: false, height: BlockHeight::new(1),
            };
            let req1 = CommitBlockReq {
                token: mantle_storage::types::ReqToken(1),
                height: BlockHeight::new(1),
                hash: make_block_hash(1),
                prev_hash: Hash256::ZERO,
                header: make_header(0),
                created: &[nc1, nc2], spent: &[],
                block_bytes: None, durability: Durability::Synced,
            };
            eng.write_block(&req1).unwrap();

            let mut h2 = make_header(1);
            h2.set_prev_block(make_block_hash(1));
            let req2 = CommitBlockReq {
                token: mantle_storage::types::ReqToken(2),
                height: BlockHeight::new(2),
                hash: make_block_hash(2),
                prev_hash: make_block_hash(1),
                header: h2,
                created: &[], spent: &[op1],
                block_bytes: None, durability: Durability::Synced,
            };
            eng.write_block(&req2).unwrap();
            eng.flush(Durability::Synced).unwrap();
        }
        let mut eng2 = TxGroupedEngine::open(dir.path()).unwrap();
        // op1 was spent — should be gone.
        assert!(eng2.read_coin(&op1).unwrap().is_none());
        // op2 was not spent — should survive.
        let coin2 = eng2.read_coin(&op2).unwrap().unwrap();
        assert_eq!(coin2.value.to_u64(), 2000);
    }
}
