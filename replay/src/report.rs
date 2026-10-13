//! Progress reporter for the replay loop.
//!
//! Throttled stderr printer that emits one line at most every `INTERVAL`
//! showing height, % done, blocks/sec running average, and ETA. The replay
//! loop calls `tick(height)` on every block; the reporter decides when to
//! actually print.

use std::time::{Duration, Instant};

use mantle::primitives::BlockHeight;

pub struct Reporter {
    interval: Duration,
    start: Instant,
    last_print: Instant,
    start_height: BlockHeight,
    target_height: BlockHeight,
    total_committed: u64,
    committed_since_last: u64,
}

impl Reporter {
    pub fn new(start_height: BlockHeight, target_height: BlockHeight, interval: Duration) -> Self {
        let now = Instant::now();
        Self {
            interval,
            start: now,
            last_print: now,
            start_height,
            target_height,
            total_committed: 0,
            committed_since_last: 0,
        }
    }

    pub fn tick(&mut self, height: BlockHeight) {
        self.total_committed += 1;
        self.committed_since_last += 1;
        let now = Instant::now();
        let since_print = now.duration_since(self.last_print);
        if since_print < self.interval {
            return;
        }

        #[allow(clippy::cast_precision_loss)]
        let bps_window = self.committed_since_last as f64 / since_print.as_secs_f64().max(1e-9);
        let elapsed = now.duration_since(self.start).as_secs_f64().max(1e-9);
        #[allow(clippy::cast_precision_loss)]
        let bps_overall = self.total_committed as f64 / elapsed;
        let remaining =
            u64::from(self.target_height.to_u32()).saturating_sub(u64::from(height.to_u32()));
        let eta_secs = if bps_window > 0.0 {
            #[allow(
                clippy::cast_precision_loss,
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss
            )]
            Some((remaining as f64 / bps_window) as u64)
        } else {
            None
        };
        let pct = 100.0 * f64::from(height.to_u32() - self.start_height.to_u32())
            / f64::from((self.target_height.to_u32() - self.start_height.to_u32()).max(1));

        eprintln!(
            "  [{:>7}/{:>7}]  {:>5.1}%  {:>7.1} bps (now) / {:>7.1} bps (avg)  ETA {}",
            height.to_u32(),
            self.target_height.to_u32(),
            pct,
            bps_window,
            bps_overall,
            format_eta(eta_secs),
        );
        self.last_print = now;
        self.committed_since_last = 0;
    }

    /// Called once after the final commit. Prints a summary line.
    pub fn done(&self, final_height: BlockHeight) {
        let elapsed = self.start.elapsed().as_secs_f64();
        let bps = f64::from(final_height.to_u32()) / elapsed.max(1e-9);
        eprintln!(
            "Replay complete: {} blocks in {elapsed:.1}s ({bps:.1} blocks/s)",
            final_height.to_u32(),
        );
    }
}

fn format_eta(secs: Option<u64>) -> String {
    let Some(secs) = secs else {
        return "—".to_string();
    };
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h{m:02}m")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}
