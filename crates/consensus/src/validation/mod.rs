mod bip30;
pub(crate) mod block_coins;
mod clock;
mod connect;
mod pow;
mod script_checks;
mod sequence_locks;
mod sigop_cost;
mod structure;
mod tx_finality;
mod tx_script_context;
mod witness_commitment;

// ── Re-exports (preserve the public API of the old validation.rs) ─────────────

pub use bip30::Bip30;
pub use clock::{Clock, FixedClock, SystemClock};
pub use connect::{BlockHeightExt, connect_block};
pub use sigop_cost::SigopCost;
pub use script_checks::{InlineScripts, ScriptChecks, SkippedScripts};
pub use tx_script_context::{Prevout, TxScriptContext};
pub use pow::{HeaderValidationExt, RetargetExt};
pub use structure::{
    BIP34_HEIGHT, MAX_BLOCK_TRANSACTIONS, MAX_BLOCK_WEIGHT, MAX_COINBASE_SCRIPTSIG_LEN, MAX_MONEY,
    MIN_COINBASE_SCRIPTSIG_LEN, WITNESS_SCALE_FACTOR, validate_block_structure,
    validate_block_structure_reusing, validate_block_wire,
};

// ── Shared constant ───────────────────────────────────────────────────────────

/// Clock drift allowance: blocks may not be more than 2 hours in the future.
pub const MAX_FUTURE_BLOCK_TIME: u64 = 2 * 60 * 60;

// ── Stage 2 imports ───────────────────────────────────────────────────────────

use crate::chain_view::ChainView;
use crate::error::ValidationError;
use clock::SystemClock as _SystemClock;
use pow::expected_nbits;
use structure::BIP34_HEIGHT as _BIP34_HEIGHT;
use tx_finality::TxFinality;
use witness_commitment::WitnessCommitment;

// ── Stage 2: contextual validation ───────────────────────────────────────────

/// Stage 2: contextual validation, using the wall clock for the
/// "≤ now + 2h" timestamp rule.
///
/// Requires the header chain (via `ChainView`). Does not touch the UTXO set.
///
/// # Errors
/// Returns the first `ValidationError` encountered.
pub fn validate_block_context(
    block: &mantle::primitives::Block,
    view: &impl ChainView,
    allow_min_difficulty: bool,
) -> Result<(), ValidationError> {
    validate_block_context_with_clock(block, view, &_SystemClock, allow_min_difficulty)
}

/// Stage 2: contextual validation with an injected clock.
///
/// Same checks as `validate_block_context`, but the caller supplies the
/// "current time" used by the future-timestamp rule. Useful for tests
/// (deterministic clocks) and for historical replay (clock pinned to the
/// block being replayed).
///
/// `allow_min_difficulty` enables the testnet 20-minute difficulty reset
/// rule (testnet3/testnet4). Must be false for mainnet/signet.
///
/// # Errors
/// Returns the first `ValidationError` encountered.
pub fn validate_block_context_with_clock(
    block: &mantle::primitives::Block,
    view: &impl ChainView,
    clock: &impl Clock,
    allow_min_difficulty: bool,
) -> Result<(), ValidationError> {
    let header = &block.header;

    // Parent must exist on the canonical chain.
    let parent = view
        .get_header(&header.prev_block())?
        .ok_or(ValidationError::UnknownParent)?;
    let parent_height = view
        .height_of(&header.prev_block())?
        .ok_or(ValidationError::UnknownParent)?;
    let this_height = parent_height + 1;

    // nBits must match expected difficulty.
    let expected_bits = expected_nbits(
        parent_height,
        parent,
        view,
        header.time(),
        allow_min_difficulty,
    )?;
    if header.bits() != expected_bits {
        return Err(ValidationError::UnexpectedDifficulty);
    }

    // Timestamp > MTP (BIP113).
    let mtp = view.median_time_past(header)?;
    if header.time() <= mtp {
        return Err(ValidationError::TimestampTooEarly);
    }

    // Timestamp ≤ now + 2h.
    if u64::from(header.time()) > clock.now_secs() + MAX_FUTURE_BLOCK_TIME {
        return Err(ValidationError::TimestampTooFarFuture);
    }

    // BIP34: coinbase scriptSig must begin with encoded block height.
    if this_height >= _BIP34_HEIGHT && !block.transactions[0].validate_bip34(this_height) {
        return Err(ValidationError::Bip34HeightMissing);
    }

    // Block version lower bound per BIP9/BIP8 deployment state.
    // For v1: enforce the historical minimums only.
    header.check_version(this_height)?;

    TxFinality::new(this_height, header.time(), mtp).check(block)?;
    WitnessCommitment::check(block, this_height)?;

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_bip30;
#[cfg(test)]
mod tests_lax_der;
#[cfg(test)]
mod tests_block_rules;
#[cfg(test)]
mod tests_script_cache;
#[cfg(test)]
mod tests_script_flag_history;
