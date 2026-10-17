use std::time::{Duration, Instant};

use mantle_validator::{ConnectPipeline, PoolBusy};

/// Splits one window's wall time between the script workers, script checks
/// the replay thread ran itself, and waits for storage lookups.
pub struct WindowMeter {
    started: Instant,
    busy: PoolBusy,
    lookups: Duration,
}

impl WindowMeter {
    #[must_use]
    pub fn start(pipeline: &ConnectPipeline) -> Self {
        Self {
            started: Instant::now(),
            busy: pipeline.script_busy(),
            lookups: pipeline.lookup_time(),
        }
    }

    /// The line for the window since the last call, then start the next.
    pub fn take_line(&mut self, pipeline: &ConnectPipeline) -> String {
        let next = Self::start(pipeline);
        let wall = next.started.duration_since(self.started);
        let busy = next.busy - self.busy;
        let lookups = next.lookups.saturating_sub(self.lookups);
        let line = WindowReading {
            wall,
            busy,
            lookups,
            workers: pipeline.workers(),
        }
        .render();
        *self = next;
        line
    }
}

struct WindowReading {
    wall: Duration,
    busy: PoolBusy,
    lookups: Duration,
    workers: usize,
}

impl WindowReading {
    fn worker_utilisation(&self) -> f64 {
        let workers = f64::from(u32::try_from(self.workers).unwrap_or(u32::MAX));
        let capacity = self.wall.as_secs_f64() * workers;
        if capacity == 0.0 {
            return 0.0;
        }
        100.0 * self.busy.workers.as_secs_f64() / capacity
    }

    fn render(&self) -> String {
        format!(
            "wall {:.1}s, workers {:.0}% busy, replay thread ran scripts {:.1}s, lookup wait {:.1}s",
            self.wall.as_secs_f64(),
            self.worker_utilisation(),
            self.busy.owner.as_secs_f64(),
            self.lookups.as_secs_f64(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::WindowReading;
    use mantle_validator::PoolBusy;
    use std::time::Duration;

    #[test]
    fn utilisation_is_worker_time_over_worker_capacity() {
        let reading = WindowReading {
            wall: Duration::from_secs(10),
            busy: PoolBusy {
                workers: Duration::from_secs(40),
                owner: Duration::from_secs(3),
            },
            lookups: Duration::from_millis(500),
            workers: 8,
        };
        assert!((reading.worker_utilisation() - 50.0).abs() < 1e-9);
        let line = reading.render();
        assert!(line.contains("workers 50% busy"), "{line}");
        assert!(line.contains("ran scripts 3.0s"), "{line}");
        assert!(line.contains("lookup wait 0.5s"), "{line}");
    }

    #[test]
    fn zero_workers_reports_zero_utilisation() {
        let reading = WindowReading {
            wall: Duration::from_secs(5),
            busy: PoolBusy::default(),
            lookups: Duration::ZERO,
            workers: 0,
        };
        assert!(reading.worker_utilisation().abs() < 1e-9);
    }
}
