//! `ConditionStack` — O(1) "are we currently executing?" tracker for
//! `OP_IF`/`OP_NOTIF` nesting, with no depth limit.
//!
//! Only two numbers are kept: the nesting depth and the position of the
//! lowest `false` entry. Entries above that position cannot change whether
//! the script is executing, and `OP_ELSE` only flips the top entry, so their
//! values never need to be stored. Tapscript has no opcode limit, so nesting
//! depth is bounded only by script size.

/// Tracks `OP_IF`/`OP_NOTIF` nesting with O(1) push, pop, toggle and query.
#[derive(Debug, Clone, Default)]
pub struct ConditionStack {
    len: u32,
    first_false: Option<u32>,
}

impl ConditionStack {
    /// Empty — no `OP_IF` is currently open.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            len: 0,
            first_false: None,
        }
    }

    /// Open `IF`/`NOTIF` depth.
    #[inline]
    #[must_use]
    pub fn depth(&self) -> u32 {
        self.len
    }

    /// `true` if every open branch is taking the executing side.
    #[inline]
    #[must_use]
    pub fn executing(&self) -> bool {
        self.first_false.is_none()
    }

    /// `true` if no `IF`/`NOTIF` is currently open.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Push the result of an `OP_IF`/`OP_NOTIF` condition.
    pub fn push(&mut self, executing: bool) {
        if self.first_false.is_none() && !executing {
            self.first_false = Some(self.len);
        }
        self.len += 1;
    }

    /// Pop the topmost branch (`OP_ENDIF`). `None` if the stack is empty.
    pub fn pop(&mut self) -> Option<()> {
        self.len = self.len.checked_sub(1)?;
        if self.first_false == Some(self.len) {
            self.first_false = None;
        }
        Some(())
    }

    /// Drop all open branches.
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    /// Flip the topmost branch (`OP_ELSE`). `None` if the stack is empty.
    pub fn toggle_top(&mut self) -> Option<()> {
        let top = self.len.checked_sub(1)?;
        match self.first_false {
            None => self.first_false = Some(top),
            Some(pos) if pos == top => self.first_false = None,
            Some(_) => {}
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ModelStack(Vec<bool>);

    impl ModelStack {
        fn executing(&self) -> bool {
            self.0.iter().all(|b| *b)
        }
    }

    #[test]
    fn empty_is_executing() {
        let cs = ConditionStack::new();
        assert!(cs.executing());
        assert!(cs.is_empty());
        assert_eq!(cs.depth(), 0);
    }

    #[test]
    fn pop_and_toggle_on_empty_return_none() {
        let mut cs = ConditionStack::new();
        assert!(cs.pop().is_none());
        assert!(cs.toggle_top().is_none());
    }

    #[test]
    fn nesting_is_not_limited() {
        let mut cs = ConditionStack::new();
        for _ in 0..100_000 {
            cs.push(true);
        }
        cs.push(false);
        assert!(!cs.executing());
        assert!(cs.pop().is_some());
        assert!(cs.executing());
        assert_eq!(cs.depth(), 100_000);
    }

    #[test]
    fn matches_a_vector_of_bools_on_every_operation_sequence() {
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..2000 {
            let mut cs = ConditionStack::new();
            let mut model = ModelStack(Vec::new());
            for _ in 0..64 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                match seed % 4 {
                    0 => {
                        cs.push(true);
                        model.0.push(true);
                    }
                    1 => {
                        cs.push(false);
                        model.0.push(false);
                    }
                    2 => {
                        let model_top = model.0.last_mut().map(|b| *b = !*b);
                        assert_eq!(cs.toggle_top(), model_top);
                    }
                    _ => assert_eq!(cs.pop(), model.0.pop().map(|_| ())),
                }
                assert_eq!(cs.executing(), model.executing());
                assert_eq!(cs.depth() as usize, model.0.len());
            }
        }
    }
}
