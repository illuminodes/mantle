use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub(crate) struct EwmaLatency {
    ms: u64,
}

impl EwmaLatency {
    const INITIAL_MS: u64 = 1_000;
    const WEIGHT: u64 = 8;
    const CEILING_MS: u64 = 10_000;

    pub(crate) const fn new() -> Self {
        Self {
            ms: Self::INITIAL_MS,
        }
    }

    pub(crate) fn observe(&mut self, sample: Duration) {
        let sample_ms = u64::try_from(sample.as_millis()).unwrap_or(u64::MAX);
        self.ms = if sample_ms >= self.ms {
            self.ms.saturating_add((sample_ms - self.ms) / Self::WEIGHT)
        } else {
            self.ms - (self.ms - sample_ms) / Self::WEIGHT
        }
        .min(Self::CEILING_MS);
    }

    pub(crate) const fn as_millis(self) -> u64 {
        self.ms
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::EwmaLatency;

    #[test]
    fn moves_an_eighth_of_the_way_toward_each_sample() {
        let mut ewma = EwmaLatency::new();
        ewma.observe(Duration::from_millis(1_800));
        assert_eq!(ewma.as_millis(), 1_100);
        ewma.observe(Duration::from_millis(300));
        assert_eq!(ewma.as_millis(), 1_000);
    }

    #[test]
    fn is_capped() {
        let mut ewma = EwmaLatency::new();
        for _ in 0..200 {
            ewma.observe(Duration::from_mins(5));
        }
        assert_eq!(ewma.as_millis(), EwmaLatency::CEILING_MS);
    }
}
