use crate::error::ValidationError;
use crate::script::{ScriptExecutionCache, ScriptFlags};
use crate::tx_view::{InputView, TxView};

use super::tx_script_context::{Prevout, TxScriptContext};

/// Where `connect_block` sends each transaction's script verification.
///
/// `connect_block` calls [`check_tx`](Self::check_tx) once per non-coinbase
/// transaction, after that transaction's input, maturity, sigop and fee
/// checks pass, and [`finish`](Self::finish) once after every other block
/// rule has passed. An implementation may verify immediately or defer the
/// work and report the outcome from `finish`, as Bitcoin Core's check queue
/// does. `'s` is how long the block and its spent outputs stay borrowable,
/// which bounds how long a deferred check may hold them.
pub trait ScriptChecks<'s> {
    /// `false` when scripts are not verified at all, so the caller can skip
    /// building per-transaction prevouts.
    fn enabled(&self) -> bool {
        true
    }

    /// Verify, or queue verification of, every input of transaction
    /// `tx_index`. `prevouts` holds one entry per input, in input order.
    ///
    /// # Errors
    /// Returns [`ValidationError::ScriptVerifyFailed`] when an input is
    /// verified immediately and fails.
    fn check_tx<T: TxView + Sync + 's>(
        &mut self,
        tx_index: usize,
        tx: &'s T,
        prevouts: &[Prevout<'s>],
        flags: ScriptFlags,
        scratch: &mut Vec<u8>,
    ) -> Result<(), ValidationError>;

    /// Wait for every queued check.
    ///
    /// # Errors
    /// Returns the failure with the lowest `(tx_index, input_index)` among
    /// the deferred checks.
    fn finish(&mut self) -> Result<(), ValidationError>;
}

/// Verifies every input on the calling thread as soon as it is submitted.
pub struct InlineScripts<'c> {
    cache: Option<&'c mut ScriptExecutionCache>,
}

impl<'c> InlineScripts<'c> {
    #[must_use]
    pub fn new(cache: Option<&'c mut ScriptExecutionCache>) -> Self {
        Self { cache }
    }
}

impl<'s> ScriptChecks<'s> for InlineScripts<'_> {
    fn check_tx<T: TxView + Sync + 's>(
        &mut self,
        tx_index: usize,
        tx: &'s T,
        prevouts: &[Prevout<'s>],
        flags: ScriptFlags,
        scratch: &mut Vec<u8>,
    ) -> Result<(), ValidationError> {
        let ctx = TxScriptContext::new(tx, prevouts, flags, self.cache.is_some(), scratch)?;
        for (input_index, (input, prevout)) in tx.inputs().zip(prevouts).enumerate() {
            ctx.verify_input(
                tx,
                input_index,
                input.script_sig(),
                prevout,
                self.cache.as_deref_mut(),
            )
            .map_err(|kind| ValidationError::ScriptVerifyFailed {
                tx_index,
                input_index,
                kind,
            })?;
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ValidationError> {
        Ok(())
    }
}

/// Skips script verification, for blocks covered by `assumevalid`.
pub struct SkippedScripts;

impl<'s> ScriptChecks<'s> for SkippedScripts {
    fn enabled(&self) -> bool {
        false
    }

    fn check_tx<T: TxView + Sync + 's>(
        &mut self,
        _tx_index: usize,
        _tx: &'s T,
        _prevouts: &[Prevout<'s>],
        _flags: ScriptFlags,
        _scratch: &mut Vec<u8>,
    ) -> Result<(), ValidationError> {
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ValidationError> {
        Ok(())
    }
}
