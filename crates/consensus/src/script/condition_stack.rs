//! `ConditionStack` — O(1) "are we currently executing?" tracker.
//!
//! Bitcoin Core's interpreter scans a `vector<bool>` on every opcode to decide
//! whether the current `OP_IF`/`OP_NOTIF` branch is being executed. That scan
//! is O(N) in nesting depth and was a known DoS-able surface (bitslog 2017,
//! Core PR review club #16902). We track the same information in O(1) by
//! caching:
//!
//! - `len`             — how many `IF`/`NOTIF` are currently open.
//! - `depth_executing` — how many of those have `true` (executing) on top.
//!
//! "Are we executing?" is `len == depth_executing`. Push, pop, and
//! `OP_ELSE`'s toggle each update both counters in O(1).
//!
//! For the toggle we also track the bool that was last pushed at the current
//! top, in a fixed-size inline array. `MAX_OPS_PER_SCRIPT = 201` limits nesting
//! to at most 100 levels (each open `IF` costs at minimum one `OP_IF` + one
//! `OP_ENDIF`), so a `[bool; 100]` covers every valid script with zero heap
//! allocation.

/// Maximum `OP_IF`/`OP_NOTIF` nesting depth for any valid script.
///
/// `MAX_OPS_PER_SCRIPT = 201` non-push opcodes. Each open IF consumes at least
/// one `OP_IF` and one `OP_ENDIF`, so depth ≤ 201 / 2 = 100.
pub const MAX_CONDITION_DEPTH: usize = 100;

/// Tracks `OP_IF`/`OP_NOTIF` nesting with an O(1) "are we executing?" query
/// and zero heap allocation.
#[derive(Debug, Clone)]
pub struct ConditionStack {
    /// Fixed-size inline store. Used only by `toggle_top` (`OP_ELSE`) and
    /// `pop` (`OP_ENDIF`); never scanned for the hot-path `executing()` query.
    branches: [bool; MAX_CONDITION_DEPTH],
    /// Number of currently open `IF`/`NOTIF` levels.
    len: u8,
    /// Number of `true` entries in `branches[..len]`. Maintained incrementally.
    depth_executing: u8,
}

impl Default for ConditionStack {
    fn default() -> Self {
        Self::new()
    }
}

impl ConditionStack {
    /// Empty — no `OP_IF` is currently open.
    #[must_use]
    pub fn new() -> Self {
        Self {
            branches: [false; MAX_CONDITION_DEPTH],
            len: 0,
            depth_executing: 0,
        }
    }

    /// Total open `IF`/`NOTIF` depth.
    #[inline]
    #[must_use]
    pub fn depth(&self) -> u32 {
        u32::from(self.len)
    }

    /// `true` if every open branch is taking the executing side.
    /// O(1).
    #[inline]
    #[must_use]
    pub fn executing(&self) -> bool {
        self.len == self.depth_executing
    }

    /// `true` if no `IF`/`NOTIF` is currently open.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Push the result of an `OP_IF`/`OP_NOTIF` condition.
    ///
    /// Returns `false` if the nesting depth would exceed `MAX_CONDITION_DEPTH`.
    /// The pre-scan's op-count limit enforces this for legacy scripts, but
    /// tapscript removes the per-script op limit, so the bound must be checked
    /// here too.
    #[must_use]
    pub fn push(&mut self, executing: bool) -> bool {
        let idx = usize::from(self.len);
        if idx >= MAX_CONDITION_DEPTH {
            return false;
        }
        self.branches[idx] = executing;
        self.len += 1;
        if executing {
            self.depth_executing += 1;
        }
        true
    }

    /// Pop the topmost branch (`OP_ENDIF`). `None` if the stack is empty —
    /// callers detect that and return `UnbalancedConditional`.
    pub fn pop(&mut self) -> Option<bool> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        let top = self.branches[usize::from(self.len)];
        if top {
            self.depth_executing -= 1;
        }
        Some(top)
    }

    /// Drop all open branches. Used at the start of each script invocation
    /// when an `Interpreter` is reused across `verify_script`'s scriptSig /
    /// scriptPubKey / P2SH-redeem evals — the stack persists, but `IF`
    /// nesting must not leak between scripts.
    pub fn clear(&mut self) {
        self.len = 0;
        self.depth_executing = 0;
    }

    /// Flip the topmost branch (`OP_ELSE`). `None` if the stack is empty.
    pub fn toggle_top(&mut self) -> Option<()> {
        if self.len == 0 {
            return None;
        }
        let top = &mut self.branches[usize::from(self.len - 1)];
        if *top {
            self.depth_executing -= 1;
        } else {
            self.depth_executing += 1;
        }
        *top = !*top;
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_executing() {
        let cs = ConditionStack::new();
        assert!(cs.executing());
        assert!(cs.is_empty());
        assert_eq!(cs.depth(), 0);
    }

    #[test]
    fn push_true_keeps_executing() {
        let mut cs = ConditionStack::new();
        assert!(cs.push(true));
        assert!(cs.executing());
        assert_eq!(cs.depth(), 1);
    }

    #[test]
    fn push_false_stops_executing() {
        let mut cs = ConditionStack::new();
        assert!(cs.push(false));
        assert!(!cs.executing());
    }

    #[test]
    fn nested_true_then_false_not_executing() {
        let mut cs = ConditionStack::new();
        assert!(cs.push(true));
        assert!(cs.push(false));
        assert!(!cs.executing());
        assert_eq!(cs.depth(), 2);
    }

    #[test]
    fn pop_restores_outer() {
        let mut cs = ConditionStack::new();
        assert!(cs.push(true));
        assert!(cs.push(false));
        assert!(!cs.executing());
        cs.pop();
        assert!(cs.executing());
    }

    #[test]
    fn toggle_flips_top() {
        let mut cs = ConditionStack::new();
        assert!(cs.push(false));
        assert!(!cs.executing());
        cs.toggle_top();
        assert!(cs.executing());
        cs.toggle_top();
        assert!(!cs.executing());
    }

    #[test]
    fn toggle_inner_under_outer_false_stays_not_executing() {
        let mut cs = ConditionStack::new();
        assert!(cs.push(false));
        assert!(cs.push(true));
        assert!(!cs.executing());
        cs.toggle_top();
        assert!(!cs.executing());
    }

    #[test]
    fn toggle_inner_under_outer_true_can_execute() {
        let mut cs = ConditionStack::new();
        assert!(cs.push(true));
        assert!(cs.push(false));
        assert!(!cs.executing());
        cs.toggle_top();
        assert!(cs.executing());
    }

    #[test]
    fn deeply_nested_o1() {
        let mut cs = ConditionStack::new();
        for _ in 0..MAX_CONDITION_DEPTH - 1 {
            assert!(cs.push(true));
        }
        assert!(cs.executing());
        assert_eq!(cs.depth(), u32::try_from(MAX_CONDITION_DEPTH - 1).unwrap());
        assert!(cs.push(false));
        assert!(!cs.executing());
    }

    #[test]
    fn push_at_max_depth_fails() {
        let mut cs = ConditionStack::new();
        for _ in 0..MAX_CONDITION_DEPTH {
            assert!(cs.push(true));
        }
        assert!(
            !cs.push(true),
            "push beyond MAX_CONDITION_DEPTH must return false"
        );
    }

    #[test]
    fn pop_empty_returns_none() {
        let mut cs = ConditionStack::new();
        assert!(cs.pop().is_none());
    }

    #[test]
    fn toggle_empty_returns_none() {
        let mut cs = ConditionStack::new();
        assert!(cs.toggle_top().is_none());
    }

    #[test]
    fn depth_executing_invariant_after_mix() {
        let mut cs = ConditionStack::new();
        assert!(cs.push(true));
        assert!(cs.push(false));
        assert!(cs.push(true));
        cs.toggle_top(); // top is now false
        assert!(cs.push(false));
        cs.toggle_top(); // top is now true
        // branches: [true, false, false, true]; executing count = 2.
        assert_eq!(cs.depth_executing, 2);
        assert!(!cs.executing()); // depth=4, executing=2
    }
}
