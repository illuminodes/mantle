use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// CPU time used by each group of this process's threads, grouped by
/// thread name with trailing digits removed (`script-3` counts as `script-`).
pub struct CpuMeter {
    started: Instant,
    start: BTreeMap<String, (u64, usize)>,
    clock_ticks: u64,
}

pub struct CpuReport {
    pub wall: Duration,
    pub groups: Vec<CpuGroup>,
}

pub struct CpuGroup {
    pub name: String,
    pub threads: usize,
    pub busy: Duration,
}

impl CpuMeter {
    const CLOCK_TICKS_PER_SECOND: u64 = 100;

    pub fn start() -> Self {
        Self {
            started: Instant::now(),
            start: Self::sample(),
            clock_ticks: Self::CLOCK_TICKS_PER_SECOND,
        }
    }

    pub fn finish(&self) -> CpuReport {
        let wall = self.started.elapsed();
        let groups = Self::sample()
            .into_iter()
            .map(|(name, (ticks, threads))| {
                let before = self.start.get(&name).map_or(0, |(t, _)| *t);
                CpuGroup {
                    name,
                    threads,
                    busy: Duration::from_millis(ticks.saturating_sub(before) * 1000 / self.clock_ticks),
                }
            })
            .filter(|g| !g.busy.is_zero())
            .collect();
        CpuReport { wall, groups }
    }

    fn sample() -> BTreeMap<String, (u64, usize)> {
        let mut groups: BTreeMap<String, (u64, usize)> = BTreeMap::new();
        let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
            return groups;
        };
        for task in tasks.flatten() {
            let Ok(stat) = std::fs::read_to_string(task.path().join("stat")) else {
                continue;
            };
            let Some((name, ticks)) = Self::parse(&stat) else {
                continue;
            };
            let entry = groups.entry(name).or_default();
            entry.0 += ticks;
            entry.1 += 1;
        }
        groups
    }

    fn parse(stat: &str) -> Option<(String, u64)> {
        let open = stat.find('(')?;
        let close = stat.rfind(')')?;
        let name = stat[open + 1..close].trim_end_matches(|c: char| c.is_ascii_digit());
        let fields: Vec<&str> = stat[close + 2..].split(' ').collect();
        let utime: u64 = fields.get(11)?.parse().ok()?;
        let stime: u64 = fields.get(12)?.parse().ok()?;
        Some((name.to_string(), utime + stime))
    }
}

impl CpuReport {
    pub fn print(&self) {
        let wall = self.wall.as_secs_f64();
        println!("cpu by thread group (wall {wall:.2}s):");
        for group in &self.groups {
            let busy = group.busy.as_secs_f64();
            println!(
                "  {:<16} {:>3} thread(s)  {:>8.2}s cpu  {:>6.1}% of one core per thread",
                group.name,
                group.threads,
                busy,
                100.0 * busy / wall / group.threads as f64,
            );
        }
        let total: f64 = self.groups.iter().map(|g| g.busy.as_secs_f64()).sum();
        println!("  total {total:.2}s cpu = {:.2} cores busy on average", total / wall);
    }
}
