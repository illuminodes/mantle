//! Arithmetic and comparison opcodes.
//!
//! All operands are decoded as `ScriptNum` with the 4-byte arithmetic limit
//! and (under `MINIMALDATA`) the minimal-encoding check. Results are pushed
//! using `Stack::push_num` which encodes minimally.

use crate::script::checker::SignatureChecker;
use crate::script::error::ScriptError;
use crate::script::flags::ScriptFlags;
use crate::script::num::MAX_NUM_SIZE_ARITHMETIC;

use super::Interpreter;

impl<C: SignatureChecker> Interpreter<'_, C> {
    /// Pop one arithmetic operand under the current minimality flag.
    fn pop_arith_num(&mut self) -> Result<i64, ScriptError> {
        let minimal = self.flags.contains(ScriptFlags::MINIMALDATA);
        self.stack.pop_num(MAX_NUM_SIZE_ARITHMETIC, minimal)
    }

    /// Push a signed result.
    fn push_num(&mut self, value: i64) -> Result<(), ScriptError> {
        self.stack.push_num(value, self.altstack.len())
    }

    /// Push a boolean as either `[]` (false) or `[0x01]` (true).
    fn push_bool(&mut self, value: bool) -> Result<(), ScriptError> {
        self.stack.push_bool(value, self.altstack.len())
    }

    // ── Unary ───────────────────────────────────────────────────────────────

    pub(super) fn op_1add(&mut self) -> Result<(), ScriptError> {
        let a = self.pop_arith_num()?;
        self.push_num(a.wrapping_add(1))
    }

    pub(super) fn op_1sub(&mut self) -> Result<(), ScriptError> {
        let a = self.pop_arith_num()?;
        self.push_num(a.wrapping_sub(1))
    }

    pub(super) fn op_negate(&mut self) -> Result<(), ScriptError> {
        let a = self.pop_arith_num()?;
        self.push_num(a.wrapping_neg())
    }

    pub(super) fn op_abs(&mut self) -> Result<(), ScriptError> {
        let a = self.pop_arith_num()?;
        self.push_num(a.wrapping_abs())
    }

    /// `OP_NOT`. Logical not: pushes 1 if `a == 0`, else 0.
    pub(super) fn op_not(&mut self) -> Result<(), ScriptError> {
        let a = self.pop_arith_num()?;
        self.push_bool(a == 0)
    }

    /// `OP_0NOTEQUAL`. Pushes 1 if `a != 0`, else 0.
    pub(super) fn op_0not_equal(&mut self) -> Result<(), ScriptError> {
        let a = self.pop_arith_num()?;
        self.push_bool(a != 0)
    }

    // ── Binary arithmetic ──────────────────────────────────────────────────

    pub(super) fn op_add(&mut self) -> Result<(), ScriptError> {
        let b = self.pop_arith_num()?;
        let a = self.pop_arith_num()?;
        self.push_num(a.wrapping_add(b))
    }

    pub(super) fn op_sub(&mut self) -> Result<(), ScriptError> {
        let b = self.pop_arith_num()?;
        let a = self.pop_arith_num()?;
        self.push_num(a.wrapping_sub(b))
    }

    pub(super) fn op_min(&mut self) -> Result<(), ScriptError> {
        let b = self.pop_arith_num()?;
        let a = self.pop_arith_num()?;
        self.push_num(a.min(b))
    }

    pub(super) fn op_max(&mut self) -> Result<(), ScriptError> {
        let b = self.pop_arith_num()?;
        let a = self.pop_arith_num()?;
        self.push_num(a.max(b))
    }

    // ── Boolean combinators ─────────────────────────────────────────────────

    pub(super) fn op_bool_and(&mut self) -> Result<(), ScriptError> {
        let b = self.pop_arith_num()?;
        let a = self.pop_arith_num()?;
        self.push_bool(a != 0 && b != 0)
    }

    pub(super) fn op_bool_or(&mut self) -> Result<(), ScriptError> {
        let b = self.pop_arith_num()?;
        let a = self.pop_arith_num()?;
        self.push_bool(a != 0 || b != 0)
    }

    // ── Comparison ─────────────────────────────────────────────────────────

    pub(super) fn op_num_equal(&mut self) -> Result<(), ScriptError> {
        let b = self.pop_arith_num()?;
        let a = self.pop_arith_num()?;
        self.push_bool(a == b)
    }

    /// `OP_NUMEQUALVERIFY`. Compare; fail if unequal, else consume both.
    pub(super) fn op_num_equal_verify(&mut self) -> Result<(), ScriptError> {
        let b = self.pop_arith_num()?;
        let a = self.pop_arith_num()?;
        if a == b {
            Ok(())
        } else {
            Err(ScriptError::Verify)
        }
    }

    pub(super) fn op_num_not_equal(&mut self) -> Result<(), ScriptError> {
        let b = self.pop_arith_num()?;
        let a = self.pop_arith_num()?;
        self.push_bool(a != b)
    }

    pub(super) fn op_less_than(&mut self) -> Result<(), ScriptError> {
        let b = self.pop_arith_num()?;
        let a = self.pop_arith_num()?;
        self.push_bool(a < b)
    }

    pub(super) fn op_greater_than(&mut self) -> Result<(), ScriptError> {
        let b = self.pop_arith_num()?;
        let a = self.pop_arith_num()?;
        self.push_bool(a > b)
    }

    pub(super) fn op_less_than_or_equal(&mut self) -> Result<(), ScriptError> {
        let b = self.pop_arith_num()?;
        let a = self.pop_arith_num()?;
        self.push_bool(a <= b)
    }

    pub(super) fn op_greater_than_or_equal(&mut self) -> Result<(), ScriptError> {
        let b = self.pop_arith_num()?;
        let a = self.pop_arith_num()?;
        self.push_bool(a >= b)
    }

    // ── Ternary ─────────────────────────────────────────────────────────────

    /// `OP_WITHIN`. `x min max → 1 iff min <= x < max else 0`.
    pub(super) fn op_within(&mut self) -> Result<(), ScriptError> {
        let max = self.pop_arith_num()?;
        let min = self.pop_arith_num()?;
        let x = self.pop_arith_num()?;
        self.push_bool(min <= x && x < max)
    }
}
