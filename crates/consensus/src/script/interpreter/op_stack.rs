//! Stack-manipulation opcodes: `OP_DUP`, `OP_DROP`, `OP_SWAP`, `OP_PICK`,
//! `OP_ROLL`, the multi-element variants, and the alt-stack transfer ops.
//!
//! Every method assumes the interpreter is currently in an executing branch;
//! the dispatch loop checks `conditions.executing()` before calling any
//! handler in this file.
//!
//! Allocation discipline: `pop()` returns an owned `StackElement<N>`; pushing
//! it back uses `push_element` which transfers the slot without copying.
//! Duplication uses `dup_at` which clones the slot in place — for inline
//! elements that's a `memcpy` of `N+1` bytes with no heap touch. The old
//! `peek(n).to_vec(); push(...)` pattern (two allocations) is gone.

use crate::script::checker::SignatureChecker;
use crate::script::error::ScriptError;
use crate::script::num::MAX_NUM_SIZE_ARITHMETIC;

use super::Interpreter;

impl<C: SignatureChecker> Interpreter<'_, C> {
    /// `OP_TOALTSTACK`. Move top of main stack to alt stack.
    pub(super) fn op_to_alt_stack(&mut self) -> Result<(), ScriptError> {
        let item = self.stack.pop()?;
        // Pushing onto altstack: combined cap counts main stack length.
        self.altstack.push_element(item, self.stack.len())
    }

    /// `OP_FROMALTSTACK`. Move top of alt stack to main stack.
    pub(super) fn op_from_alt_stack(&mut self) -> Result<(), ScriptError> {
        let item = self.altstack.pop()?;
        self.stack.push_element(item, self.altstack.len())
    }

    /// `OP_DROP`. Pop the top.
    pub(super) fn op_drop(&mut self) -> Result<(), ScriptError> {
        self.stack.pop()?;
        Ok(())
    }

    /// `OP_2DROP`. Pop two.
    pub(super) fn op_2drop(&mut self) -> Result<(), ScriptError> {
        self.stack.pop()?;
        self.stack.pop()?;
        Ok(())
    }

    /// `OP_DUP`. Duplicate the top.
    pub(super) fn op_dup(&mut self) -> Result<(), ScriptError> {
        self.stack.dup_at(0, self.altstack.len())
    }

    /// `OP_2DUP`. Duplicate the top two items: `a b → a b a b`.
    pub(super) fn op_2dup(&mut self) -> Result<(), ScriptError> {
        self.stack.dup_at(1, self.altstack.len())?; // a
        self.stack.dup_at(1, self.altstack.len()) // b is now at depth 1
    }

    /// `OP_3DUP`. `a b c → a b c a b c`.
    pub(super) fn op_3dup(&mut self) -> Result<(), ScriptError> {
        self.stack.dup_at(2, self.altstack.len())?;
        self.stack.dup_at(2, self.altstack.len())?;
        self.stack.dup_at(2, self.altstack.len())
    }

    /// `OP_OVER`. Copy second-from-top to top: `a b → a b a`.
    pub(super) fn op_over(&mut self) -> Result<(), ScriptError> {
        self.stack.dup_at(1, self.altstack.len())
    }

    /// `OP_2OVER`. `a b c d → a b c d a b`.
    pub(super) fn op_2over(&mut self) -> Result<(), ScriptError> {
        self.stack.dup_at(3, self.altstack.len())?;
        self.stack.dup_at(3, self.altstack.len())
    }

    /// `OP_SWAP`. Swap the top two.
    pub(super) fn op_swap(&mut self) -> Result<(), ScriptError> {
        let top = self.stack.pop()?;
        let second = self.stack.pop()?;
        self.stack.push_element(top, self.altstack.len())?;
        self.stack.push_element(second, self.altstack.len())
    }

    /// `OP_2SWAP`. `a b c d → c d a b`.
    pub(super) fn op_2swap(&mut self) -> Result<(), ScriptError> {
        let d = self.stack.pop()?;
        let c = self.stack.pop()?;
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        self.stack.push_element(c, self.altstack.len())?;
        self.stack.push_element(d, self.altstack.len())?;
        self.stack.push_element(a, self.altstack.len())?;
        self.stack.push_element(b, self.altstack.len())
    }

    /// `OP_ROT`. `a b c → b c a`.
    pub(super) fn op_rot(&mut self) -> Result<(), ScriptError> {
        let c = self.stack.pop()?;
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        self.stack.push_element(b, self.altstack.len())?;
        self.stack.push_element(c, self.altstack.len())?;
        self.stack.push_element(a, self.altstack.len())
    }

    /// `OP_2ROT`. `a b c d e f → c d e f a b`.
    #[allow(clippy::many_single_char_names)] // mirrors the spec's rotation
    pub(super) fn op_2rot(&mut self) -> Result<(), ScriptError> {
        let f = self.stack.pop()?;
        let e = self.stack.pop()?;
        let d = self.stack.pop()?;
        let c = self.stack.pop()?;
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        self.stack.push_element(c, self.altstack.len())?;
        self.stack.push_element(d, self.altstack.len())?;
        self.stack.push_element(e, self.altstack.len())?;
        self.stack.push_element(f, self.altstack.len())?;
        self.stack.push_element(a, self.altstack.len())?;
        self.stack.push_element(b, self.altstack.len())
    }

    /// `OP_NIP`. Remove the second-from-top: `a b → b`.
    pub(super) fn op_nip(&mut self) -> Result<(), ScriptError> {
        self.stack.remove_at(1)?;
        Ok(())
    }

    /// `OP_TUCK`. Insert a copy of the top below the second-from-top:
    /// `a b → b a b`.
    pub(super) fn op_tuck(&mut self) -> Result<(), ScriptError> {
        // Need at least two items.
        let _ = self.stack.peek(1)?;
        let b = self.stack.pop()?;
        let a = self.stack.pop()?;
        // Cloning b once is unavoidable for OP_TUCK — but with inline storage
        // it's a stack-only memcpy.
        let b_copy = b.clone();
        self.stack.push_element(b, self.altstack.len())?;
        self.stack.push_element(a, self.altstack.len())?;
        self.stack.push_element(b_copy, self.altstack.len())
    }

    /// `OP_PICK`. Top is depth `n`; copy item at depth `n+1` to top.
    pub(super) fn op_pick(&mut self) -> Result<(), ScriptError> {
        let n = self.stack.pop_num(MAX_NUM_SIZE_ARITHMETIC, false)?;
        let depth = usize::try_from(n).map_err(|_| ScriptError::InvalidStackOperation)?;
        self.stack.dup_at(depth, self.altstack.len())
    }

    /// `OP_ROLL`. Top is depth `n`; move item at depth `n+1` to top.
    pub(super) fn op_roll(&mut self) -> Result<(), ScriptError> {
        let n = self.stack.pop_num(MAX_NUM_SIZE_ARITHMETIC, false)?;
        let depth = usize::try_from(n).map_err(|_| ScriptError::InvalidStackOperation)?;
        let item = self.stack.remove_at(depth)?;
        self.stack.push_element(item, self.altstack.len())
    }

    /// `OP_DEPTH`. Push the current main-stack depth as a `ScriptNum`.
    pub(super) fn op_depth(&mut self) -> Result<(), ScriptError> {
        let depth =
            i64::try_from(self.stack.len()).map_err(|_| ScriptError::InvalidStackOperation)?;
        self.stack.push_num(depth, self.altstack.len())
    }

    /// `OP_IFDUP`. Duplicate the top iff it's truthy.
    pub(super) fn op_if_dup(&mut self) -> Result<(), ScriptError> {
        if self.stack.peek(0)?.is_truthy() {
            self.stack.dup_at(0, self.altstack.len())?;
        }
        Ok(())
    }

    /// `OP_SIZE`. Push the byte length of the top (without consuming it).
    pub(super) fn op_size(&mut self) -> Result<(), ScriptError> {
        let len = self.stack.peek(0)?.len();
        let n = i64::try_from(len).map_err(|_| ScriptError::InvalidStackOperation)?;
        self.stack.push_num(n, self.altstack.len())
    }
}
