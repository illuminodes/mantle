/// Sampling CPU profile of the whole process, printed per thread on
/// [`finish`](Self::finish). Real only with the `cpu-profile` feature.
pub struct CpuProfile {
    #[cfg(feature = "cpu-profile")]
    guard: Option<pprof::ProfilerGuard<'static>>,
}

#[cfg(feature = "cpu-profile")]
impl CpuProfile {
    const HZ: i32 = 499;
    const TOP: usize = 30;

    #[must_use]
    pub fn start(enabled: bool) -> Self {
        let guard = enabled.then(|| {
            pprof::ProfilerGuardBuilder::default()
                .frequency(Self::HZ)
                .blocklist(&["libc", "libgcc", "pthread", "vdso"])
                .build()
                .expect("start CPU profiler")
        });
        Self { guard }
    }

    pub fn finish(self) {
        let Some(guard) = self.guard else { return };
        match guard.report().build() {
            Ok(report) => ThreadReport::from_report(&report).print(Self::TOP),
            Err(e) => eprintln!("  warning: CPU profile report failed: {e}"),
        }
    }
}

#[cfg(not(feature = "cpu-profile"))]
impl CpuProfile {
    #[must_use]
    pub fn start(enabled: bool) -> Self {
        if enabled {
            eprintln!("  note: --cpu-profile needs a build with `--features cpu-profile`");
        }
        Self {}
    }

    pub fn finish(self) {
        let Self {} = self;
    }
}

#[cfg(feature = "cpu-profile")]
struct ThreadProfile {
    name: String,
    samples: isize,
    functions: Vec<(String, isize)>,
}

#[cfg(feature = "cpu-profile")]
struct ThreadReport {
    threads: Vec<ThreadProfile>,
}

#[cfg(feature = "cpu-profile")]
impl ThreadReport {
    fn from_report(report: &pprof::Report) -> Self {
        use std::collections::{HashMap, HashSet};
        let mut by_thread: HashMap<String, (isize, HashMap<String, isize>)> = HashMap::new();
        for (frames, &count) in &report.data {
            let group = Self::group(&frames.thread_name);
            let entry = by_thread.entry(group).or_default();
            entry.0 += count;
            let mut seen = HashSet::new();
            for symbols in &frames.frames {
                for symbol in symbols {
                    let name = symbol.name();
                    if seen.insert(name.clone()) {
                        *entry.1.entry(name).or_default() += count;
                    }
                }
            }
        }
        let mut threads: Vec<_> = by_thread
            .into_iter()
            .map(|(name, (samples, funcs))| {
                let mut functions: Vec<_> = funcs.into_iter().collect();
                functions.sort_by_key(|f| std::cmp::Reverse(f.1));
                ThreadProfile {
                    name,
                    samples,
                    functions,
                }
            })
            .collect();
        threads.sort_by_key(|t| std::cmp::Reverse(t.samples));
        Self { threads }
    }

    fn group(thread: &str) -> String {
        let trimmed = thread.trim_end_matches(|c: char| c.is_ascii_digit());
        if trimmed.len() < thread.len() && trimmed.ends_with('-') {
            format!("{trimmed}*")
        } else {
            thread.to_string()
        }
    }

    #[allow(clippy::cast_precision_loss)]
    fn print(&self, top: usize) {
        for thread in &self.threads {
            eprintln!(
                "── CPU profile: thread {} ({} samples) ──",
                thread.name, thread.samples
            );
            for (func, count) in thread.functions.iter().take(top) {
                let pct = *count as f64 / thread.samples as f64 * 100.0;
                eprintln!("  {pct:>5.1}%  {func}");
            }
        }
    }
}

#[cfg(all(test, feature = "cpu-profile"))]
mod tests {
    use super::ThreadReport;

    #[test]
    fn numbered_threads_share_a_group() {
        assert_eq!(ThreadReport::group("script-12"), "script-*");
        assert_eq!(ThreadReport::group("mantle-replay"), "mantle-replay");
        assert_eq!(ThreadReport::group("storage"), "storage");
    }
}
