pub mod flat;
pub mod header_io;
pub mod ring_budget;
pub mod robin_hood;

use mantle::primitives::{BlockHeader, BlockHeight, Hash256, OutPoint};
use mantle_consensus::chain_view::{Coin, TipInfo};

use crate::background::{BackgroundEvent, BackgroundTask};
use crate::types::{CommitBlockReq, Durability, LookupResult};

/// All failure modes from the storage engine.
#[derive(Debug)]
pub enum EngineError {
    /// An underlying I/O failure.
    Io(std::io::Error),
    /// A script pubkey exceeded the maximum encodable length (`u32::MAX` bytes).
    ScriptPubKeyTooLarge,
    /// A stored script pubkey length field would overflow `usize` on this platform.
    ScriptLenOverflow,
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "engine I/O error: {e}"),
            Self::ScriptPubKeyTooLarge => f.write_str("script_pubkey exceeds 4 GiB"),
            Self::ScriptLenOverflow => f.write_str("script_pubkey length overflows usize"),
        }
    }
}

impl std::error::Error for EngineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for EngineError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub trait Engine {
    /// # Errors
    /// Returns `EngineError` on I/O failure.
    fn read_coin(&mut self, op: &OutPoint) -> Result<Option<Coin>, EngineError>;

    /// # Errors
    /// Returns `EngineError` on I/O failure.
    fn read_coins(
        &mut self,
        ops: &[OutPoint],
        out: &mut Vec<LookupResult>,
    ) -> Result<(), EngineError> {
        for &op in ops {
            let coin = self.read_coin(&op)?;
            out.push(LookupResult { outpoint: op, coin });
        }
        Ok(())
    }

    /// # Errors
    /// Returns `EngineError` on I/O failure.
    fn write_block(&mut self, b: &CommitBlockReq) -> Result<(), EngineError>;

    /// # Errors
    /// Returns `EngineError` on I/O failure.
    fn read_header(&self, hash: &Hash256) -> Result<Option<BlockHeader>, EngineError>;

    /// # Errors
    /// Returns `EngineError` on I/O failure.
    fn read_header_at(&self, h: BlockHeight) -> Result<Option<BlockHeader>, EngineError>;

    /// # Errors
    /// Returns `EngineError` on I/O failure.
    fn write_header(&mut self, h: BlockHeight, header: &BlockHeader) -> Result<(), EngineError>;

    /// # Errors
    /// Returns `EngineError` on I/O failure.
    fn flush(&mut self, d: Durability) -> Result<(), EngineError>;

    /// Rebuild in-memory state from on-disk files. Called once at startup.
    ///
    /// # Errors
    /// Returns `EngineError` on I/O failure.
    fn recover(&mut self) -> Result<TipInfo, EngineError>;

    fn tip(&self) -> TipInfo;

    /// Thread bodies to run beside the storage thread. Called once, before
    /// the storage thread starts; their events arrive through
    /// [`on_background`](Self::on_background).
    ///
    /// # Errors
    /// Returns `EngineError` if the threads' resources cannot be set up.
    fn background_tasks(&mut self) -> Result<Vec<BackgroundTask>, EngineError> {
        Ok(Vec::new())
    }

    fn on_background(&mut self, _event: BackgroundEvent) {}

    /// Whether the last commit must wait for background work before it can
    /// be answered.
    fn awaits_background(&self) -> bool {
        false
    }

    /// Whether no background work is running or waiting to run.
    fn background_idle(&self) -> bool {
        true
    }

    /// # Errors
    /// Returns the reason background work failed, if it did.
    fn background_health(&self) -> Result<(), EngineError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::EngineError;

    #[test]
    fn engine_error_display_all_variants() {
        let io = EngineError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"));
        assert!(format!("{io}").contains("engine I/O error"));

        let spk = EngineError::ScriptPubKeyTooLarge;
        assert!(format!("{spk}").contains("script_pubkey exceeds"));

        let overflow = EngineError::ScriptLenOverflow;
        assert!(format!("{overflow}").contains("overflows"));
    }

    #[test]
    fn engine_error_source() {
        use std::error::Error;
        let io = EngineError::Io(std::io::Error::new(std::io::ErrorKind::Other, "x"));
        assert!(io.source().is_some());
        assert!(EngineError::ScriptPubKeyTooLarge.source().is_none());
    }
}
