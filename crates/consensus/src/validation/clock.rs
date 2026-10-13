use std::time::{SystemTime, UNIX_EPOCH};

/// Source of the current Unix timestamp for the "block time within 2h of now"
/// rule (BIP113-adjacent; see `MAX_FUTURE_BLOCK_TIME`).
///
/// Production wires `SystemClock` and the validator behaves as if it called
/// `SystemTime::now()` directly. Tests inject a `FixedClock` for determinism.
/// Historical replay passes a clock that returns the timestamp of the block
/// currently being replayed, so genesis-era blocks are not rejected as
/// "too far in the future" relative to wall-clock 2009.
pub trait Clock {
    /// Current Unix timestamp in seconds.
    fn now_secs(&self) -> u64;
}

/// Reads the wall clock via `SystemTime::now()`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// A clock that always returns a fixed timestamp. Used for tests and replay.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_secs(&self) -> u64 {
        self.0
    }
}
