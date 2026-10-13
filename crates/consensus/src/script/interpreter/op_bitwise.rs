//! Bitwise opcodes — `OP_EQUAL` and `OP_EQUALVERIFY`.
//!
//! These are the only consensus-active members of the bitwise group. The
//! disabled members (`OP_INVERT`, `OP_AND`, `OP_OR`, `OP_XOR`) are rejected
//! by the legacy pre-scan and never reach a handler.

use crate::script::checker::SignatureChecker;
use crate::script::error::ScriptError;

use super::Interpreter;

impl<C: SignatureChecker> Interpreter<'_, C> {
    /// `OP_EQUAL`. Byte-wise compare top two; push 1 if equal, else 0.
    pub(super) fn op_equal(&mut self) -> Result<(), ScriptError> {
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        self.stack.push_bool(a == b, self.altstack.len())
    }

    /// `OP_EQUALVERIFY`. Compare; fail if unequal.
    pub(super) fn op_equal_verify(&mut self) -> Result<(), ScriptError> {
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        if a == b {
            Ok(())
        } else {
            Err(ScriptError::Verify)
        }
    }
}
