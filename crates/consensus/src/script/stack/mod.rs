//! Script execution stack with consensus-mandated size caps.
//!
//! Two caps:
//! - **Per-element**: 520 bytes. Pushes that would exceed this fail with
//!   `ScriptError::PushSize`.
//! - **Combined**: 1000 elements across stack + altstack. Operations that
//!   would push the combined depth past 1000 fail with `ScriptError::StackSize`.
//!
//! Stack elements are stored as `StackElement<N>` — inline up to `N` bytes,
//! heap above. `N` is a const generic on `Stack` so we can tune the inline
//! cap without rewriting the type or its call sites; the interpreter uses
//! `Stack<32>` (covers numbers, hashes, x-only pubkeys; compressed pubkeys
//! and DER signatures spill once per CHECKSIG, which is fine).

use std::mem::MaybeUninit;
use std::ops::Deref;

use super::error::ScriptError;
use super::num::ScriptNum;

/// Maximum size of any single stack element, in bytes (`MAX_SCRIPT_ELEMENT_SIZE`).
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Maximum combined stack + altstack depth (`MAX_STACK_SIZE`).
pub const MAX_STACK_SIZE: usize = 1000;

/// Default inline capacity for the interpreter's stacks. Covers `ScriptNum`
/// (≤ 5 bytes), HASH160 / RIPEMD-160 / SHA-1 (20 bytes), SHA-256 / HASH256
/// (32 bytes), x-only pubkeys (32 bytes). Compressed pubkeys (33 bytes) and
/// DER signatures (~71-72 bytes) spill to heap.
pub const DEFAULT_INLINE_CAP: usize = 32;

/// One stack slot — inline up to `N` bytes, heap above. Same shape as
/// `mantle::primitives::ScriptBuf<N>` from the core crate.
///
/// **Safety invariant**: when `Inline { len, data }`, the first `len` bytes
/// of `data` are initialized; bytes at positions `len..N` are uninitialized
/// and must never be read. `as_slice` and `Deref<Target=[u8]>` only ever
/// expose the initialized prefix. Skipping the zero-fill on construction
/// removes ~17% from `OP_ADD`-class hot paths where most operands are
/// 1-2 bytes long.
#[derive(Clone)]
pub enum StackElement<const N: usize> {
    /// Stored inline. `len <= N`. The first `len` bytes of `data` are
    /// initialized; the rest are uninitialized.
    Inline { len: u8, data: [MaybeUninit<u8>; N] },
    /// Stored on the heap. `len > N`.
    Heap(Box<[u8]>),
}

impl<const N: usize> StackElement<N> {
    /// The empty element — used for `OP_0`, false-bool pushes, and as the
    /// neutral fill for unused slots. The `data` array is uninitialized but
    /// safe because `len = 0` means `as_slice` returns `&[]`.
    pub const EMPTY: Self = Self::Inline {
        len: 0,
        data: [const { MaybeUninit::uninit() }; N],
    };

    /// Construct from a byte slice. Picks inline vs. heap by length.
    ///
    /// `#[inline]` because callers in the dispatch hot path (every push,
    /// every `push_num`, every `push_bool`) want this body in their frame
    /// so LLVM can fold the small-`s.len()` case into a couple of `mov`s.
    ///
    /// # Panics
    /// Never in practice — `N` is always small enough that `s.len() <= N`
    /// implies `s.len()` fits in `u8`. (Asserted in debug builds.)
    #[inline]
    #[must_use]
    pub fn from_slice(s: &[u8]) -> Self {
        if s.len() <= N {
            debug_assert!(u8::try_from(s.len()).is_ok(), "N must be <= 255");
            // Skip zero-fill: only the first `s.len()` bytes are read by
            // `as_slice`; the rest of `data` stays uninitialized but
            // unobservable.
            let mut data: [MaybeUninit<u8>; N] = [const { MaybeUninit::uninit() }; N];
            // SAFETY: `MaybeUninit<u8>` and `u8` have the same layout, so we
            // can write `s` directly into the initial prefix. We only access
            // `data[..s.len()]` from `as_slice`, so leaving the tail
            // uninitialized is sound.
            unsafe {
                let dst = data.as_mut_ptr().cast::<u8>();
                std::ptr::copy_nonoverlapping(s.as_ptr(), dst, s.len());
            }
            #[allow(clippy::cast_possible_truncation)]
            Self::Inline {
                len: s.len() as u8,
                data,
            }
        } else {
            Self::Heap(s.to_vec().into_boxed_slice())
        }
    }

    /// Borrow as a byte slice.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Inline { len, data } => {
                let len = *len as usize;
                // SAFETY: by the type invariant, `data[..len]` is initialized.
                // `MaybeUninit<u8>` and `u8` are layout-compatible.
                unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), len) }
            }
            Self::Heap(b) => b,
        }
    }

    /// Length in bytes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Inline { len, .. } => *len as usize,
            Self::Heap(b) => b.len(),
        }
    }

    /// `true` if zero bytes.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bitcoin's "is this byte string truthy?" rule.
    ///
    /// A value is truthy iff any byte is non-zero, *except* a sole high bit
    /// on the last byte (i.e. `0x80`) is treated as zero — that encodes
    /// negative-zero in `ScriptNum`.
    #[inline]
    #[must_use]
    pub fn is_truthy(&self) -> bool {
        let bytes = self.as_slice();
        let Some((&last, rest)) = bytes.split_last() else {
            return false;
        };
        if rest.iter().any(|&b| b != 0) {
            return true;
        }
        last != 0 && last != 0x80
    }
}

impl<const N: usize> Deref for StackElement<N> {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> Default for StackElement<N> {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl<const N: usize> std::fmt::Debug for StackElement<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StackElement({:?})", self.as_slice())
    }
}

impl<const N: usize> PartialEq for StackElement<N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<const N: usize> Eq for StackElement<N> {}

impl<const N: usize> PartialEq<[u8]> for StackElement<N> {
    fn eq(&self, other: &[u8]) -> bool {
        self.as_slice() == other
    }
}

impl<const N: usize, const M: usize> PartialEq<[u8; M]> for StackElement<N> {
    fn eq(&self, other: &[u8; M]) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<const N: usize> PartialEq<&[u8]> for StackElement<N> {
    fn eq(&self, other: &&[u8]) -> bool {
        self.as_slice() == *other
    }
}

impl<const N: usize> PartialEq<Vec<u8>> for StackElement<N> {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

/// Mutable stack of byte-string elements. Used for both the main stack and
/// the alt stack — the type is shared because the cap is on their *combined*
/// size and methods that grow either need to see both.
///
/// `N` is the per-slot inline byte capacity. The interpreter uses
/// [`DEFAULT_INLINE_CAP`].
#[derive(Debug, Clone)]
pub struct Stack<const N: usize = DEFAULT_INLINE_CAP> {
    items: Vec<StackElement<N>>,
}

impl<const N: usize> Default for Stack<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Initial `Vec` capacity for a new stack. Real scripts rarely exceed a handful
/// of items; we grow on demand up to `MAX_STACK_SIZE`. Pre-allocating 1000
/// slots (~33 KB each for `Stack<32>`) was the dominant allocation site in the
/// dhat profile — two stacks per `Interpreter::new` × every input.
const INITIAL_STACK_CAP: usize = 16;

impl<const N: usize> Stack<N> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: Vec::with_capacity(INITIAL_STACK_CAP),
        }
    }

    /// Wrap a caller-provided, already-empty `Vec` as the backing store.
    ///
    /// The vec must be empty (debug-asserted). Its capacity is preserved, so
    /// the caller can pre-allocate once and pass the same buffer across many
    /// inputs — truly zero per-input allocation once the buffer has grown to
    /// the working set size.
    #[inline]
    #[must_use]
    pub fn from_buf(buf: Vec<StackElement<N>>) -> Self {
        debug_assert!(
            buf.is_empty(),
            "buf passed to Stack::from_buf must be empty"
        );
        Self { items: buf }
    }

    /// Consume the stack, returning the backing `Vec` (cleared, capacity kept).
    ///
    /// Pair with [`Stack::from_buf`] to reuse the allocation across inputs.
    #[inline]
    #[must_use]
    pub fn into_buf(mut self) -> Vec<StackElement<N>> {
        self.items.clear();
        self.items
    }

    /// Number of items.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// `true` if no items.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Borrow the element at depth `n` (0 = top).
    ///
    /// Callers wanting a `&[u8]` deref the result; callers wanting the
    /// truthy semantics call `.is_truthy()`.
    ///
    /// # Errors
    /// `InvalidStackOperation` if `n` is at or beyond the current depth.
    #[inline]
    pub fn peek(&self, n: usize) -> Result<&StackElement<N>, ScriptError> {
        let idx = self
            .items
            .len()
            .checked_sub(n + 1)
            .ok_or(ScriptError::InvalidStackOperation)?;
        Ok(&self.items[idx])
    }

    /// Pop the top element.
    ///
    /// # Errors
    /// `InvalidStackOperation` if empty.
    #[inline]
    pub fn pop(&mut self) -> Result<StackElement<N>, ScriptError> {
        self.items.pop().ok_or(ScriptError::InvalidStackOperation)
    }

    /// Push without bounds checking. Used by tests and internal helpers that
    /// have already validated the size — production opcode handlers go
    /// through `push_checked`.
    pub fn push_unchecked(&mut self, item: StackElement<N>) {
        self.items.push(item);
    }

    /// Push from a byte slice, with both caps enforced. The slice is copied
    /// into the slot (inline if it fits in `N`, heap otherwise).
    ///
    /// `altstack_len` is the current depth of the *other* stack so the
    /// combined-size check is exact.
    ///
    /// # Errors
    /// - `PushSize` if `bytes.len() > MAX_SCRIPT_ELEMENT_SIZE`.
    /// - `StackSize` if the push would take the combined depth past
    ///   `MAX_STACK_SIZE`.
    #[inline]
    pub fn push_checked(&mut self, bytes: &[u8], altstack_len: usize) -> Result<(), ScriptError> {
        if bytes.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ScriptError::PushSize);
        }
        if self.items.len() + altstack_len >= MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
        self.items.push(StackElement::from_slice(bytes));
        Ok(())
    }

    /// Push an already-constructed element with caps enforced. Used when the
    /// caller owns a `StackElement` (e.g. from `pop()` returning to the
    /// stack after a peek-style operation).
    ///
    /// # Errors
    /// As `push_checked`.
    #[inline]
    pub fn push_element(
        &mut self,
        elem: StackElement<N>,
        altstack_len: usize,
    ) -> Result<(), ScriptError> {
        if elem.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ScriptError::PushSize);
        }
        if self.items.len() + altstack_len >= MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
        self.items.push(elem);
        Ok(())
    }

    /// Duplicate the element at depth `n` and push it. Avoids the
    /// `peek().to_vec(); push()` allocation pattern by cloning the slot
    /// directly — for inline slots this is a `memcpy` of `N+1` bytes with
    /// no heap touch.
    ///
    /// # Errors
    /// - `InvalidStackOperation` if depth `n` does not exist.
    /// - `StackSize` if the push would take combined depth past the cap.
    #[inline]
    pub fn dup_at(&mut self, n: usize, altstack_len: usize) -> Result<(), ScriptError> {
        if self.items.len() + altstack_len >= MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
        let idx = self
            .items
            .len()
            .checked_sub(n + 1)
            .ok_or(ScriptError::InvalidStackOperation)?;
        let copy = self.items[idx].clone();
        self.items.push(copy);
        Ok(())
    }

    /// Borrow the underlying slice — for read-only iteration in tests and
    /// the eventual `OP_DEPTH` handler.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[StackElement<N>] {
        &self.items
    }

    /// Remove the item at depth `n` (0 = top), shifting later items down.
    /// Used by `OP_ROLL` and similar.
    ///
    /// # Errors
    /// `InvalidStackOperation` if depth `n` does not exist.
    pub fn remove_at(&mut self, n: usize) -> Result<StackElement<N>, ScriptError> {
        let idx = self
            .items
            .len()
            .checked_sub(n + 1)
            .ok_or(ScriptError::InvalidStackOperation)?;
        Ok(self.items.remove(idx))
    }

    /// Truncate to `new_len` items.
    ///
    /// # Errors
    /// `InvalidStackOperation` if `new_len > self.len()`.
    pub fn truncate(&mut self, new_len: usize) -> Result<(), ScriptError> {
        if new_len > self.items.len() {
            return Err(ScriptError::InvalidStackOperation);
        }
        self.items.truncate(new_len);
        Ok(())
    }

    // ── High-level helpers used by opcode handlers ──────────────────────────

    /// Pop the top element and decode it as a `ScriptNum` operand.
    ///
    /// `max_len` is the per-opcode size limit (4 for arithmetic, 5 for
    /// `OP_CHECKLOCKTIMEVERIFY`); `require_minimal` is the `MINIMALDATA`
    /// gate.
    ///
    /// # Errors
    /// - `InvalidStackOperation` if the stack is empty.
    /// - `NumOverflow` / `NumNotMinimal` per `ScriptNum::from_bytes`.
    #[inline]
    pub fn pop_num(&mut self, max_len: usize, require_minimal: bool) -> Result<i64, ScriptError> {
        let bytes = self.pop()?;
        Ok(ScriptNum::from_bytes(&bytes, max_len, require_minimal)?.to_i64())
    }

    /// Pop the top element and interpret it as a Bitcoin-script boolean.
    ///
    /// See [`StackElement::is_truthy`] for the rule.
    ///
    /// # Errors
    /// `InvalidStackOperation` if the stack is empty.
    #[inline]
    pub fn pop_bool(&mut self) -> Result<bool, ScriptError> {
        Ok(self.pop()?.is_truthy())
    }

    /// Push a `ScriptNum`, encoded minimally, with both stack caps enforced.
    /// Encodes directly into the slot — never allocates for values whose
    /// minimal encoding fits in `N` bytes (which is every `i64` value once
    /// `N >= 5`).
    ///
    /// # Errors
    /// `StackSize` if the combined depth would exceed `MAX_STACK_SIZE`.
    #[inline]
    pub fn push_num(&mut self, value: i64, altstack_len: usize) -> Result<(), ScriptError> {
        let n = ScriptNum::from_i64(value);
        self.push_checked(n.as_bytes(), altstack_len)
    }

    /// Push a boolean as either the empty byte string (false) or `[0x01]` (true).
    ///
    /// # Errors
    /// `StackSize` if the combined depth would exceed `MAX_STACK_SIZE`.
    #[inline]
    pub fn push_bool(&mut self, value: bool, altstack_len: usize) -> Result<(), ScriptError> {
        let bytes: &[u8] = if value { &[0x01] } else { &[] };
        self.push_checked(bytes, altstack_len)
    }
}

#[cfg(test)]
mod tests;
