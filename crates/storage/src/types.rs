use std::io;

use mantle::primitives::{BlockHeader, BlockHeight, Hash256, OutPoint};
use mantle_consensus::chain_view::{Coin, NewCoin, TipInfo};

use crate::engine::EngineError;

// ── Tokens ────────────────────────────────────────────────────────────────────

/// Opaque request token. Each `StorageHandle` call stamps its request with a
/// monotonically-increasing token and matches the response on the same token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReqToken(pub u64);

// ── Durability ────────────────────────────────────────────────────────────────

/// How durable a committed block must be before the handle call returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    /// Write to the engine's in-memory state only. Fast; survives restart only
    /// if the engine itself persists (it does for `FlatEngine`, which flushes
    /// at `Synced` boundaries).
    Memory,
    /// Write buffered state to the data files without `fsync`. Bounds memory
    /// like `Synced` but survives only a process exit, not a crash or power
    /// loss; for runs whose data is thrown away afterwards.
    Flushed,
    /// `fsync` to disk before returning. Used every 2016 blocks (difficulty
    /// epoch boundary) by the replay loop.
    Synced,
}

// ── LookupResult ─────────────────────────────────────────────────────────────

/// Result for a single outpoint in a batched UTXO lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupResult {
    pub outpoint: OutPoint,
    pub coin: Option<Coin>,
}

// ── Request subtypes ──────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct LookupCoinsReq<'a> {
    pub token: ReqToken,
    pub outpoints: &'a [OutPoint],
    pub out: &'a mut Vec<LookupResult>,
}

#[derive(Debug)]
pub struct CommitBlockReq<'a> {
    pub token: ReqToken,
    pub height: BlockHeight,
    pub hash: Hash256,
    pub prev_hash: Hash256,
    /// Full block header. Persisted by the engine so that `read_header` /
    /// `read_header_at` round-trip (BIP113 MTP and retarget lookups need
    /// `merkle_root`, `time`, `bits`, `nonce`, and `version`, none of
    /// which can be derived from `hash` + `prev_hash` alone).
    pub header: BlockHeader,
    pub created: &'a [NewCoin<'a>],
    pub spent: &'a [OutPoint],
    pub block_bytes: Option<Vec<u8>>,
    pub durability: Durability,
}

#[derive(Debug)]
pub struct ReadHeaderReq {
    pub token: ReqToken,
    pub key: HeaderKey,
}

#[derive(Debug)]
pub enum HeaderKey {
    ByHash(Hash256),
    ByHeight(BlockHeight),
}

// ── StorageReq / StorageResp ──────────────────────────────────────────────────

#[derive(Debug)]
pub enum StorageReq<'a> {
    LookupCoins(LookupCoinsReq<'a>),
    CommitBlock(CommitBlockReq<'a>),
    ReadHeader(ReadHeaderReq),
    Shutdown,
}

// ── Response subtypes ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LookupCoinsResp {
    pub token: ReqToken,
}

#[derive(Debug, Clone)]
pub struct CommittedResp {
    pub token: ReqToken,
    pub tip: TipInfo,
}

#[derive(Debug, Clone)]
pub struct ReadHeaderResp {
    pub token: ReqToken,
    pub header: Option<BlockHeader>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    /// Underlying I/O failure; carries the `ErrorKind` so the type stays `Clone + Copy`.
    Io(io::ErrorKind),
    /// A script pubkey exceeded the maximum encodable length.
    ScriptPubKeyTooLarge,
    /// A stored script pubkey length field overflows `usize` on this platform.
    ScriptLenOverflow,
    /// The storage thread exited unexpectedly.
    ThreadGone,
    /// A response arrived for a different request variant than expected.
    UnexpectedResponse,
}

impl From<EngineError> for StorageError {
    fn from(e: EngineError) -> Self {
        match e {
            EngineError::Io(e) => Self::Io(e.kind()),
            EngineError::ScriptPubKeyTooLarge => Self::ScriptPubKeyTooLarge,
            EngineError::ScriptLenOverflow => Self::ScriptLenOverflow,
        }
    }
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(k) => write!(f, "storage I/O error: {k}"),
            Self::ScriptPubKeyTooLarge => f.write_str("script_pubkey exceeds 4 GiB"),
            Self::ScriptLenOverflow => f.write_str("script_pubkey length overflows usize"),
            Self::ThreadGone => f.write_str("storage thread exited unexpectedly"),
            Self::UnexpectedResponse => f.write_str("unexpected response from storage thread"),
        }
    }
}

impl std::error::Error for StorageError {}

#[derive(Debug, Clone)]
pub enum StorageResp {
    LookupCoins(Result<LookupCoinsResp, StorageError>),
    CommitBlock(Result<CommittedResp, StorageError>),
    ReadHeader(Result<ReadHeaderResp, StorageError>),
    Shutdown,
}

impl StorageResp {
    #[must_use]
    pub fn token(&self) -> Option<ReqToken> {
        match self {
            Self::LookupCoins(Ok(r)) => Some(r.token),
            Self::CommitBlock(Ok(r)) => Some(r.token),
            Self::ReadHeader(Ok(r)) => Some(r.token),
            Self::LookupCoins(Err(_))
            | Self::CommitBlock(Err(_))
            | Self::ReadHeader(Err(_))
            | Self::Shutdown => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantle::primitives::BlockHeight;
    use mantle_consensus::chain_view::TipInfo;

    #[test]
    fn token_returns_some_for_ok_variants() {
        let tok = ReqToken(42);

        let resp = StorageResp::LookupCoins(Ok(LookupCoinsResp { token: tok }));
        assert_eq!(resp.token(), Some(tok));

        let resp = StorageResp::CommitBlock(Ok(CommittedResp {
            token: tok,
            tip: TipInfo {
                hash: Hash256::ZERO,
                height: BlockHeight::ZERO,
            },
        }));
        assert_eq!(resp.token(), Some(tok));

        let resp = StorageResp::ReadHeader(Ok(ReadHeaderResp {
            token: tok,
            header: None,
        }));
        assert_eq!(resp.token(), Some(tok));
    }

    #[test]
    fn token_returns_none_for_err_and_shutdown() {
        let err = StorageError::ThreadGone;

        assert!(StorageResp::LookupCoins(Err(err)).token().is_none());
        assert!(StorageResp::CommitBlock(Err(err)).token().is_none());
        assert!(StorageResp::ReadHeader(Err(err)).token().is_none());
        assert!(StorageResp::Shutdown.token().is_none());
    }

    #[test]
    fn storage_error_display_all_variants_non_empty() {
        let cases: Vec<StorageError> = vec![
            StorageError::Io(std::io::ErrorKind::NotFound),
            StorageError::ScriptPubKeyTooLarge,
            StorageError::ScriptLenOverflow,
            StorageError::ThreadGone,
            StorageError::UnexpectedResponse,
        ];
        for e in &cases {
            assert!(!format!("{e}").is_empty(), "variant {e:?} must format");
        }
    }

    #[test]
    fn storage_error_display_io_includes_kind() {
        let err = StorageError::Io(std::io::ErrorKind::PermissionDenied);
        let msg = format!("{err}");
        assert!(
            msg.contains("storage I/O error"),
            "Io variant should mention 'storage I/O error', got: {msg}"
        );
    }

    #[test]
    fn storage_error_display_specific_messages() {
        assert_eq!(
            format!("{}", StorageError::ScriptPubKeyTooLarge),
            "script_pubkey exceeds 4 GiB"
        );
        assert_eq!(
            format!("{}", StorageError::ScriptLenOverflow),
            "script_pubkey length overflows usize"
        );
        assert_eq!(
            format!("{}", StorageError::ThreadGone),
            "storage thread exited unexpectedly"
        );
        assert_eq!(
            format!("{}", StorageError::UnexpectedResponse),
            "unexpected response from storage thread"
        );
    }
}
