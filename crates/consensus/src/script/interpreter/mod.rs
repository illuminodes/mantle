//! Bitcoin script dispatch loop.
//!
//! The `Interpreter` owns a main stack, alt stack, condition stack
//! (`OP_IF`/`OP_NOTIF` nesting), opcode counter, last-`OP_CODESEPARATOR`
//! offset, the script flags, the sighash regime, and a borrowed
//! `SignatureChecker`. Each opcode handler is a method on `Interpreter`
//! living in one of the `op_*.rs` files in this directory.
//!
//! The `eval` entry point runs the pre-scan (`pre_scan.rs`), then iterates
//! through `ScriptReader::next_step` (`reader.rs`) calling `step` for each
//! decoded opcode. The match in `step` is the dispatch; the methods are
//! the logic.

pub mod op_arith;
pub mod op_bitwise;
pub mod op_control;
pub mod op_crypto;
pub mod op_stack;
pub mod pre_scan;
pub mod reader;

use crate::script::checker::SignatureChecker;
use crate::script::condition_stack::ConditionStack;
use crate::script::error::ScriptError;
use crate::script::flags::ScriptFlags;
use crate::script::opcodes::Opcode;
use crate::script::sig_version::SigVersion;
use crate::script::sighash::Bip341Cache;
use crate::script::stack::{Stack, StackElement};

/// Convenience alias for the element type used by the interpreter's stacks.
pub type InterpStackElement = StackElement<{ crate::script::stack::DEFAULT_INLINE_CAP }>;

use reader::{ScriptReader, Step};

/// Maximum non-push opcodes per script (`MAX_OPS_PER_SCRIPT`). `OP_0`,
/// `OP_PUSHBYTES_*`, `OP_PUSHDATA*`, `OP_1NEGATE`, and `OP_1`..`OP_16` are
/// not counted.
pub const MAX_OPS_PER_SCRIPT: u32 = 201;

/// Tapscript execution context — fields only populated when `sig_version ==
/// Tapscript`. Grouped to keep the `Interpreter` struct tidy.
pub(super) struct TapscriptCtx {
    /// `TapLeaf` hash for the leaf being executed.
    pub leaf_hash: [u8; 32],
    /// Value of the UTXO being spent (for BIP341 sighash).
    pub spent_amount: mantle::primitives::Satoshi,
    /// scriptPubKey of the UTXO being spent (for BIP341 sighash).
    pub spent_spk: Vec<u8>,
    /// Per-transaction BIP341 cache (shared across inputs).
    pub bip341_cache: Bip341Cache,
}

/// Dispatch loop and execution state for a single script invocation.
pub struct Interpreter<'a, C: SignatureChecker> {
    pub(super) stack: Stack,
    pub(super) altstack: Stack,
    pub(super) conditions: ConditionStack,
    pub(super) op_count: u32,
    /// Byte offset within the current script of the last `OP_CODESEPARATOR`,
    /// or 0 if none has been seen.
    pub(super) last_codeseparator: usize,
    pub(super) flags: ScriptFlags,
    pub(super) sig_version: SigVersion,
    pub(super) checker: &'a C,
    /// Set when `sig_version == Tapscript`.
    pub(super) tapscript: Option<TapscriptCtx>,
}

impl<'a, C: SignatureChecker> Interpreter<'a, C> {
    /// Construct an interpreter, allocating fresh stack buffers.
    #[must_use]
    pub fn new(checker: &'a C, flags: ScriptFlags, sig_version: SigVersion) -> Self {
        Self {
            stack: Stack::new(),
            altstack: Stack::new(),
            conditions: ConditionStack::new(),
            op_count: 0,
            last_codeseparator: usize::MAX, // sentinel: no OP_CODESEPARATOR seen (→ 0xFFFF_FFFF)
            flags,
            sig_version,
            checker,
            tapscript: None,
        }
    }

    /// Construct an interpreter using caller-provided, pre-allocated stack
    /// buffers. Both vecs must be empty (asserted in debug builds); their
    /// capacity is reused so that repeated calls across many inputs incur no
    /// heap allocation once the buffers have grown to their working-set size.
    ///
    /// Pair with [`Interpreter::into_bufs`] to recover the buffers after use.
    #[must_use]
    pub fn new_with_bufs(
        checker: &'a C,
        flags: ScriptFlags,
        sig_version: SigVersion,
        stack_buf: Vec<InterpStackElement>,
        altstack_buf: Vec<InterpStackElement>,
    ) -> Self {
        Self {
            stack: Stack::from_buf(stack_buf),
            altstack: Stack::from_buf(altstack_buf),
            conditions: ConditionStack::new(),
            op_count: 0,
            last_codeseparator: usize::MAX, // sentinel: no OP_CODESEPARATOR seen (→ 0xFFFF_FFFF)
            flags,
            sig_version,
            checker,
            tapscript: None,
        }
    }

    /// Consume the interpreter and return the two stack buffers (both cleared,
    /// capacity preserved) so the caller can reuse them for the next input.
    #[must_use]
    pub fn into_bufs(self) -> (Vec<InterpStackElement>, Vec<InterpStackElement>) {
        (self.stack.into_buf(), self.altstack.into_buf())
    }

    /// Borrow the main stack — for tests and for the upcoming
    /// `verify_script` final-stack-truthy check.
    #[must_use]
    pub fn stack(&self) -> &Stack {
        &self.stack
    }

    /// Mutable access to the main stack — for tests that need to seed
    /// initial state without going through a script.
    pub fn stack_mut(&mut self) -> &mut Stack {
        &mut self.stack
    }

    /// Evaluate `script` to completion.
    ///
    /// On success, the final stack is left in `self.stack` for the caller
    /// to inspect (e.g. for the `verify_script` truthy-top check).
    ///
    /// # Errors
    /// Any `ScriptError` produced by the pre-scan or by an opcode handler.
    pub fn eval(&mut self, script: &[u8]) -> Result<(), ScriptError> {
        pre_scan::pre_scan(script, self.sig_version)?;

        // Reset per-script state — `verify_script` invokes `eval` up to three
        // times on the same Interpreter (scriptSig, scriptPubKey, P2SH redeem)
        // and the stack persists across them, but condition stack, op count,
        // and `last_codeseparator` reset for each new script.
        //
        // Sentinel `usize::MAX`: no `OP_CODESEPARATOR` seen yet. Legacy/segwit-v0
        // CHECKSIG treats that as "scriptCode is the whole script" (offset 0);
        // tapscript CHECKSIG signs `code_sep_pos = 0xFFFF_FFFF`. Both paths read
        // `last_codeseparator` and apply their own conversion.
        self.last_codeseparator = usize::MAX;
        self.op_count = 0;
        self.conditions.clear();

        let mut reader = ScriptReader::new(script);
        while let Some(step) = reader.next_step()? {
            // Snapshot the cursor *after* the opcode body has been consumed.
            // For OP_CODESEPARATOR this is the offset of the next byte —
            // exactly what BIP / Core record. For CHECKSIG it's the offset
            // immediately after the CHECKSIG opcode, which is fine because
            // sighash-relevant slicing only uses `last_codeseparator`.
            let pos_after_step = reader.position();
            self.step(script, pos_after_step, step)?;
        }

        if !self.conditions.is_empty() {
            return Err(ScriptError::UnbalancedConditional);
        }

        Ok(())
    }

    /// Dispatch one decoded step. Public to the parent module so individual
    /// opcodes can be tested in isolation by feeding hand-built `Step`s.
    ///
    /// `script` is the full script being evaluated (so signature opcodes can
    /// slice from `last_codeseparator`). `pos_after_step` is the byte offset
    /// in `script` of the byte immediately following the just-decoded opcode
    /// — used by `OP_CODESEPARATOR` to record itself.
    pub(super) fn step(
        &mut self,
        script: &[u8],
        pos_after_step: usize,
        step: Step<'_>,
    ) -> Result<(), ScriptError> {
        // Always-fail opcodes: rejected even when reached only inside an
        // unexecuted `OP_IF` branch. Inlined here so we don't pay for a
        // separate pre-scan walk of the script.
        // - VERIF / VERNOTIF: rejected in every script version.
        // - The legacy disabled set (CAT/SUBSTR/LEFT/RIGHT/INVERT/AND/OR/XOR/
        //   2MUL/2DIV/MUL/DIV/MOD/LSHIFT/RSHIFT): rejected unconditionally
        //   under SigVersion::Base. Under Tapscript they only fail when
        //   executed (not in unexecuted branches) — handled in dispatch.
        // - OP_SUCCESSx (BIP342): if any such opcode appears *anywhere* in a
        //   tapscript (even in an unexecuted branch), the whole script
        //   succeeds immediately.
        if step.flags.is_verif_class() {
            return Err(ScriptError::BadOpcodeReserved);
        }

        if self.sig_version == SigVersion::Tapscript {
            if step.opcode.is_tapscript_success() {
                return Ok(());
            }
        } else {
            if step.opcode.is_disabled() {
                return Err(ScriptError::DisabledOpcode);
            }
            if step.flags.counts_toward_op_limit() {
                self.op_count += 1;
                if self.op_count > MAX_OPS_PER_SCRIPT {
                    return Err(ScriptError::OpCount);
                }
            }
        }

        let executing = self.conditions.executing();

        // Conditional opcodes are *always* dispatched — they manipulate the
        // condition stack regardless of the executing flag. Everything else
        // is skipped when not executing.
        let is_conditional = matches!(
            step.opcode,
            Opcode::If | Opcode::NotIf | Opcode::Else | Opcode::EndIf
        );
        if !executing && !is_conditional {
            return Ok(());
        }

        self.dispatch(script, pos_after_step, step)
    }

    /// The big match. Each arm calls the corresponding `op_*` method.
    #[allow(
        clippy::too_many_lines,    // dispatch table; methods do the work
        clippy::match_same_arms,   // arms grouped by category for readability
    )]
    fn dispatch(
        &mut self,
        script: &[u8],
        pos_after_step: usize,
        step: Step<'_>,
    ) -> Result<(), ScriptError> {
        match step.opcode {
            // ── Push opcodes ────────────────────────────────────────────────
            Opcode::Op0 => self.stack.push_checked(&[], self.altstack.len()),
            Opcode::PushBytes(_) | Opcode::PushData1 | Opcode::PushData2 | Opcode::PushData4 => {
                self.stack.push_checked(step.data, self.altstack.len())
            }
            Opcode::Op1Negate => self.stack.push_num(-1, self.altstack.len()),
            Opcode::OpN(n) => self.stack.push_num(i64::from(n), self.altstack.len()),

            // ── Control flow ────────────────────────────────────────────────
            Opcode::If => self.op_if(false),
            Opcode::NotIf => self.op_if(true),
            Opcode::Else => self.op_else(),
            Opcode::EndIf => self.op_endif(),
            Opcode::Verify => self.op_verify(),
            Opcode::Return => self.op_return(),
            Opcode::Nop => self.op_nop(),
            Opcode::Nop1
            | Opcode::Nop4
            | Opcode::Nop5
            | Opcode::Nop6
            | Opcode::Nop7
            | Opcode::Nop8
            | Opcode::Nop9
            | Opcode::Nop10 => self.op_nop_upgradable(),

            // ── Stack manipulation ──────────────────────────────────────────
            Opcode::ToAltStack => self.op_to_alt_stack(),
            Opcode::FromAltStack => self.op_from_alt_stack(),
            Opcode::Drop => self.op_drop(),
            Opcode::TwoDrop => self.op_2drop(),
            Opcode::Dup => self.op_dup(),
            Opcode::TwoDup => self.op_2dup(),
            Opcode::ThreeDup => self.op_3dup(),
            Opcode::Over => self.op_over(),
            Opcode::TwoOver => self.op_2over(),
            Opcode::Swap => self.op_swap(),
            Opcode::TwoSwap => self.op_2swap(),
            Opcode::Rot => self.op_rot(),
            Opcode::TwoRot => self.op_2rot(),
            Opcode::Nip => self.op_nip(),
            Opcode::Tuck => self.op_tuck(),
            Opcode::Pick => self.op_pick(),
            Opcode::Roll => self.op_roll(),
            Opcode::Depth => self.op_depth(),
            Opcode::IfDup => self.op_if_dup(),
            Opcode::Size => self.op_size(),

            // ── Bitwise ─────────────────────────────────────────────────────
            Opcode::Equal => self.op_equal(),
            Opcode::EqualVerify => self.op_equal_verify(),

            // ── Arithmetic ──────────────────────────────────────────────────
            Opcode::OneAdd => self.op_1add(),
            Opcode::OneSub => self.op_1sub(),
            Opcode::Negate => self.op_negate(),
            Opcode::Abs => self.op_abs(),
            Opcode::Not => self.op_not(),
            Opcode::ZeroNotEqual => self.op_0not_equal(),
            Opcode::Add => self.op_add(),
            Opcode::Sub => self.op_sub(),
            Opcode::BoolAnd => self.op_bool_and(),
            Opcode::BoolOr => self.op_bool_or(),
            Opcode::NumEqual => self.op_num_equal(),
            Opcode::NumEqualVerify => self.op_num_equal_verify(),
            Opcode::NumNotEqual => self.op_num_not_equal(),
            Opcode::LessThan => self.op_less_than(),
            Opcode::GreaterThan => self.op_greater_than(),
            Opcode::LessThanOrEqual => self.op_less_than_or_equal(),
            Opcode::GreaterThanOrEqual => self.op_greater_than_or_equal(),
            Opcode::Min => self.op_min(),
            Opcode::Max => self.op_max(),
            Opcode::Within => self.op_within(),

            // ── Crypto ──────────────────────────────────────────────────────
            Opcode::Ripemd160 => self.op_ripemd160(),
            Opcode::Sha1 => self.op_sha1(),
            Opcode::Sha256 => self.op_sha256(),
            Opcode::Hash160 => self.op_hash160(),
            Opcode::Hash256 => self.op_hash256(),

            // ── Signatures ──────────────────────────────────────────────────
            Opcode::CodeSeparator => self.op_code_separator(pos_after_step),
            Opcode::CheckSig => self.op_check_sig(script, false),
            Opcode::CheckSigVerify => self.op_check_sig(script, true),
            Opcode::CheckMultiSig => self.op_check_multi_sig(script, false),
            Opcode::CheckMultiSigVerify => self.op_check_multi_sig(script, true),

            // ── Locktime opcodes ────────────────────────────────────────────
            // Pre-activation, both are NOPs: BIP65/112 redefined OP_NOP2/OP_NOP3,
            // so when their respective flags are unset they behave as upgradable
            // NOPs (no-op unless DISCOURAGE_UPGRADABLE_NOPS).
            Opcode::CheckLockTimeVerify => {
                if self.flags.contains(ScriptFlags::CHECKLOCKTIMEVERIFY) {
                    self.op_check_lock_time_verify()
                } else {
                    self.op_nop_upgradable()
                }
            }
            Opcode::CheckSequenceVerify => {
                if self.flags.contains(ScriptFlags::CHECKSEQUENCEVERIFY) {
                    self.op_check_sequence_verify()
                } else {
                    self.op_nop_upgradable()
                }
            }

            // ── Always-fail-when-executed ──────────────────────────────────
            // OP_RESERVED, OP_VER, OP_RESERVED1/2 fail when reached during
            // execution. (Note OP_VERIF/OP_VERNOTIF are pre-scanned out.)
            Opcode::OpReserved | Opcode::Ver | Opcode::Reserved1 | Opcode::Reserved2 => {
                Err(ScriptError::BadOpcodeReserved)
            }

            // ── Disabled even-when-unexecuted in legacy ────────────────────
            // pre_scan rejects these in SigVersion::Base before we get here;
            // under tapscript they fail when executed.
            Opcode::Cat
            | Opcode::SubStr
            | Opcode::Left
            | Opcode::Right
            | Opcode::Invert
            | Opcode::And
            | Opcode::Or
            | Opcode::Xor
            | Opcode::TwoMul
            | Opcode::TwoDiv
            | Opcode::Mul
            | Opcode::Div
            | Opcode::Mod
            | Opcode::LShift
            | Opcode::RShift => Err(ScriptError::DisabledOpcode),

            // ── Tapscript (M3) ───────────────────────────────────────────────
            Opcode::CheckSigAdd => {
                if self.sig_version == SigVersion::Tapscript {
                    self.op_check_sig_add(script)
                } else {
                    // Outside tapscript this byte is OP_INVALIDOPCODE.
                    Err(ScriptError::BadOpcode)
                }
            }

            // ── Pre-scanned out (defensive) ─────────────────────────────────
            Opcode::VerIf | Opcode::VerNotIf => Err(ScriptError::BadOpcodeReserved),

            // ── Anything else ──────────────────────────────────────────────
            Opcode::Invalid(_) => Err(ScriptError::BadOpcode),
        }
    }
}

#[cfg(test)]
mod tests;
