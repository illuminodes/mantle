use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Download,
    Read,
    Validate,
    Discard,
}

impl Stage {
    const ALL: [Self; 4] = [Self::Download, Self::Read, Self::Validate, Self::Discard];

    const fn index(self) -> usize {
        match self {
            Self::Download => 0,
            Self::Read => 1,
            Self::Validate => 2,
            Self::Discard => 3,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Download => "download",
            Self::Read => "read",
            Self::Validate => "validate",
            Self::Discard => "discard",
        }
    }
}

#[derive(Default)]
pub struct StageClock {
    spent: [Duration; 4],
}

impl StageClock {
    pub fn time<T>(&mut self, stage: Stage, work: impl FnOnce() -> T) -> T {
        let started = Instant::now();
        let out = work();
        self.add(stage, started);
        out
    }

    pub fn add(&mut self, stage: Stage, started: Instant) {
        self.spent[stage.index()] += started.elapsed();
    }

    pub fn take_line(&mut self) -> String {
        let line = Stage::ALL
            .iter()
            .map(|s| format!("{} {:.1}s", s.label(), self.spent[s.index()].as_secs_f64()))
            .collect::<Vec<_>>()
            .join(", ");
        self.spent = [Duration::ZERO; 4];
        line
    }
}

#[cfg(test)]
mod tests {
    use super::{Stage, StageClock};
    use std::time::Duration;

    #[test]
    fn time_accumulates_per_stage_and_take_line_resets() {
        let mut clock = StageClock::default();
        let value = clock.time(Stage::Read, || {
            std::thread::sleep(Duration::from_millis(20));
            7
        });
        assert_eq!(value, 7);
        assert!(clock.spent[Stage::Read.index()] >= Duration::from_millis(20));
        assert_eq!(clock.spent[Stage::Download.index()], Duration::ZERO);

        let line = clock.take_line();
        assert!(line.starts_with("download 0.0s, read 0.0"), "{line}");
        assert!(clock.spent.iter().all(Duration::is_zero));
    }
}
