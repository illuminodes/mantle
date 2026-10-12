use mantle::primitives::BlockVersion;

use crate::script::ScriptError;

/// All consensus validation failure modes.
///
/// Variants are structured by validation stage so callers can distinguish
/// stateless failures (Stage 1) from contextual ones (Stage 2) without
/// inspecting error strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    // ── Stage 1: structural ───────────────────────────────────────────────────
    /// Block contains no transactions.
    EmptyBlock,
    /// First transaction is not a coinbase (no inputs spending the null outpoint).
    FirstTxNotCoinbase,
    /// A non-coinbase transaction has a coinbase-style input.
    UnexpectedCoinbaseInput { tx_index: usize },
    /// A transaction has no inputs.
    EmptyInputs { tx_index: usize },
    /// A transaction has no outputs.
    EmptyOutputs { tx_index: usize },
    /// An output value is out of range (> 21M BTC in satoshis).
    OutputValueOutOfRange {
        tx_index: usize,
        output_index: usize,
    },
    /// Sum of output values overflows or exceeds `MAX_MONEY`.
    TotalOutputValueOverflow { tx_index: usize },
    /// A transaction contains duplicate inputs (same outpoint appears twice).
    DuplicateInput { tx_index: usize },
    /// Two or more transactions in the block share the same txid (CVE-2012-2459).
    DuplicateTransaction,
    /// Coinbase scriptSig length is outside [2, 100].
    CoinbaseScriptSigLength { len: usize },
    /// Block weight exceeds the 4,000,000 weight-unit limit (BIP141).
    BlockWeightExceeded { weight: u64 },
    /// Block contains more transactions than the practical consensus limit.
    TooManyTransactions { count: usize },
    /// A transaction's wire encoding is truncated or otherwise malformed.
    MalformedTransaction { tx_index: usize },
    /// Merkle root in the header does not match the computed root of the tx list.
    MerkleRootMismatch,
    /// Header proof-of-work does not satisfy the claimed nBits target.
    InsufficientProofOfWork,
    /// nBits field encodes a target of zero or has invalid format.
    InvalidBits,

    // ── Stage 3: connect (UTXO) ──────────────────────────────────────────────
    /// BIP30: a transaction in this block has the same txid as an unspent
    /// coinbase already in the UTXO set.
    Bip30Violation { tx_index: usize },
    /// An input's BIP68 relative lock-time has not elapsed.
    SequenceLockNotSatisfied { tx_index: usize },
    /// A non-coinbase input spends an outpoint that does not exist in the UTXO set.
    MissingInput { tx_index: usize, input_index: usize },
    /// A coinbase input is spent before it has 100 confirmations.
    CoinbaseMaturityViolation { tx_index: usize, input_index: usize },
    /// Sum of input values overflows `u64` or exceeds `MAX_MONEY`.
    InputValueOverflow { tx_index: usize },
    /// A transaction's outputs exceed its inputs (negative fee).
    NegativeFee { tx_index: usize },
    /// The coinbase output value exceeds the block subsidy plus collected fees.
    CoinbaseRewardExceedsSubsidy,
    /// Weighted sigop cost across the block exceeds 80,000 (BIP141; equal to
    /// 20,000 legacy sigops before segwit).
    SigopsLimitExceeded { cost: u64 },
    /// Script verification rejected this input — `kind` carries the
    /// structured `ScriptError` from the interpreter.
    ScriptVerifyFailed {
        tx_index: usize,
        input_index: usize,
        kind: ScriptError,
    },

    // ── Stage 2: contextual ───────────────────────────────────────────────────
    /// nBits does not match the expected difficulty for this block's height.
    UnexpectedDifficulty,
    /// Block timestamp is not greater than the median of the past 11 blocks (BIP113).
    TimestampTooEarly,
    /// Block timestamp is more than 2 hours in the future.
    TimestampTooFarFuture,
    /// BIP34: coinbase scriptSig does not begin with the encoded block height
    /// (required after BIP34 activation height 227,931).
    Bip34HeightMissing,
    /// Block version is below the minimum required for the current deployment state.
    BlockVersionTooLow {
        version: BlockVersion,
        required: BlockVersion,
    },
    /// The requested block's parent is not in the chain view.
    UnknownParent,
    /// A transaction's lock-time is not yet satisfied (`IsFinalTx`, BIP113).
    NonFinalTransaction { tx_index: usize },
    /// The coinbase witness is not a single 32-byte reserved value (BIP141).
    BadWitnessNonceSize,
    /// The coinbase witness commitment does not match the block's wtxids (BIP141).
    BadWitnessMerkleMatch,
    /// A transaction carries witness data in a block without a witness commitment.
    UnexpectedWitness { tx_index: usize },
    /// `ChainView` returned an error.
    ChainView(ChainViewError),
    /// An I/O error during serialisation (e.g. computing a txid).
    Io(std::io::ErrorKind),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ValidationError {}

impl From<ChainViewError> for ValidationError {
    fn from(e: ChainViewError) -> Self {
        Self::ChainView(e)
    }
}

impl From<std::io::Error> for ValidationError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind())
    }
}

impl From<mantle::codec::Error> for ValidationError {
    fn from(e: mantle::codec::Error) -> Self {
        Self::from(std::io::Error::from(e))
    }
}

/// Errors returned by a `ChainView` implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainViewError {
    /// The requested item was not found (distinct from a storage failure).
    NotFound,
}

impl std::fmt::Display for ChainViewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("not found"),
        }
    }
}

impl std::error::Error for ChainViewError {}
