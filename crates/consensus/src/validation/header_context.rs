use mantle::primitives::{BlockHeader, BlockHeight, BlockTime};

use crate::chain_view::ChainView;
use crate::error::ValidationError;

use super::MAX_FUTURE_BLOCK_TIME;
use super::clock::Clock;
use super::pow::{HeaderValidationExt, expected_nbits};

/// Where a header sits once its contextual rules pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderContext {
    pub height: BlockHeight,
    pub median_time_past: BlockTime,
}

/// The contextual rules a header must satisfy against the chain it extends:
/// expected difficulty, BIP113 median time past, the two-hour future limit,
/// and the historical version floors. Proof of work is checked separately by
/// [`HeaderValidationExt::check_pow`].
pub trait HeaderContextExt {
    /// # Errors
    /// `UnknownParent`, `UnexpectedDifficulty`, `TimestampTooEarly`,
    /// `TimestampTooFarFuture`, `BlockVersionTooLow`, or a `ChainView` error.
    fn check_context(
        &self,
        view: &impl ChainView,
        clock: &impl Clock,
        allow_min_difficulty: bool,
    ) -> Result<HeaderContext, ValidationError>;
}

impl HeaderContextExt for BlockHeader {
    fn check_context(
        &self,
        view: &impl ChainView,
        clock: &impl Clock,
        allow_min_difficulty: bool,
    ) -> Result<HeaderContext, ValidationError> {
        let parent = view
            .get_header(&self.prev_block())?
            .ok_or(ValidationError::UnknownParent)?;
        let parent_height = view
            .height_of(&self.prev_block())?
            .ok_or(ValidationError::UnknownParent)?;
        let height = parent_height + 1;

        let expected_bits = expected_nbits(
            parent_height,
            parent,
            view,
            self.time(),
            allow_min_difficulty,
        )?;
        if self.bits() != expected_bits {
            return Err(ValidationError::UnexpectedDifficulty);
        }

        let median_time_past = view.median_time_past(self)?;
        if self.time() <= median_time_past {
            return Err(ValidationError::TimestampTooEarly);
        }
        if u64::from(self.time()) > clock.now_secs() + MAX_FUTURE_BLOCK_TIME {
            return Err(ValidationError::TimestampTooFarFuture);
        }

        self.check_version(height)?;
        Ok(HeaderContext {
            height,
            median_time_past,
        })
    }
}
