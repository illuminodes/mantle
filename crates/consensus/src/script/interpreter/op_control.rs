//! Control-flow opcodes: `OP_IF`, `OP_NOTIF`, `OP_ELSE`, `OP_ENDIF`,
//! `OP_VERIFY`, `OP_RETURN`, the `OP_NOP` family.
//!
//! `OP_IF` / `OP_NOTIF` consult the top of stack for the branch decision
//! when executing, and skip the read when not (a no-op push-and-skip).
//! Conditional state lives in `Interpreter::conditions` (`ConditionStack`).

use crate::script::checker::SignatureChecker;
use crate::script::error::ScriptError;
use crate::script::flags::ScriptFlags;

use super::Interpreter;

impl<C: SignatureChecker> Interpreter<'_, C> {
    /// `OP_IF` / `OP_NOTIF`. Consumes one stack item if executing; pushes
    /// the resulting branch decision onto the condition stack.
    pub(super) fn op_if(&mut self, negated: bool) -> Result<(), ScriptError> {
        let executing_branch = if self.conditions.executing() {
            let top = self.stack.peek(0)?;
            if self.flags.contains(ScriptFlags::MINIMALIF) {
                // MINIMALIF: the operand must be exactly the empty push or [0x01].
                let ok = top.is_empty() || (top.len() == 1 && top[0] == 0x01);
                if !ok {
                    return Err(ScriptError::MinimalIf);
                }
            }
            let cond = top.is_truthy();
            self.stack.pop()?; // discard the operand
            if negated { !cond } else { cond }
        } else {
            // Not executing: don't consume anything; record a "false" branch
            // so the body remains skipped regardless.
            false
        };
        if !self.conditions.push(executing_branch) {
            return Err(ScriptError::UnbalancedConditional);
        }
        Ok(())
    }

    /// `OP_ELSE`. Flips the topmost condition.
    pub(super) fn op_else(&mut self) -> Result<(), ScriptError> {
        self.conditions
            .toggle_top()
            .ok_or(ScriptError::UnbalancedConditional)
    }

    /// `OP_ENDIF`. Pops the topmost condition.
    pub(super) fn op_endif(&mut self) -> Result<(), ScriptError> {
        self.conditions
            .pop()
            .map(|_| ())
            .ok_or(ScriptError::UnbalancedConditional)
    }

    /// `OP_VERIFY`. Pops the top; if falsey, fails the script.
    pub(super) fn op_verify(&mut self) -> Result<(), ScriptError> {
        if self.stack.pop_bool()? {
            Ok(())
        } else {
            Err(ScriptError::Verify)
        }
    }

    /// `OP_RETURN`. Always fails the script.
    #[allow(clippy::unused_self)] // method shape required for uniform dispatch
    pub(super) fn op_return(&mut self) -> Result<(), ScriptError> {
        Err(ScriptError::OpReturn)
    }

    /// `OP_NOP`. Does nothing.
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)] // dispatch shape
    pub(super) fn op_nop(&self) -> Result<(), ScriptError> {
        Ok(())
    }

    /// `OP_NOP1`, `OP_NOP4`..`OP_NOP10`. Reserved for soft forks. Under
    /// `DISCOURAGE_UPGRADABLE_NOPS` they fail; otherwise they no-op.
    pub(super) fn op_nop_upgradable(&self) -> Result<(), ScriptError> {
        if self.flags.contains(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS) {
            Err(ScriptError::DiscourageUpgradableNops)
        } else {
            Ok(())
        }
    }
}
