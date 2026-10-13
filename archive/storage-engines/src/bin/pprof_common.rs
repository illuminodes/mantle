//! Shared pprof helpers for per-component CPU profilers.
//!
//! Included via `#[path = "../pprof_common.rs"] mod pprof_common;`.
#![allow(dead_code)]
#![allow(clippy::cast_precision_loss)]

use std::time::{Duration, Instant};

pub fn print_top(report: &pprof::Report, name: &str, iters: u64, duration_secs: u64) {
    println!("── {name} ({iters} iters, {duration_secs}s) ──");

    let total_samples: isize = report.data.values().sum();
    if total_samples == 0 {
        println!("  (no samples captured)");
        println!();
        return;
    }

    let mut flat: std::collections::HashMap<String, isize> = std::collections::HashMap::new();
    for (frames, &count) in &report.data {
        let mut seen = std::collections::HashSet::new();
        for sym_list in &frames.frames {
            for sym in sym_list {
                let fname = sym.name();
                if seen.insert(fname.clone()) {
                    *flat.entry(fname).or_default() += count;
                }
            }
        }
    }

    let mut entries: Vec<_> = flat.into_iter().collect();
    entries.sort_by_key(|e| std::cmp::Reverse(e.1));

    println!("  {:<70} {:>8} {:>7}", "FUNCTION", "SAMPLES", "%");
    for (fname, count) in entries.iter().take(25) {
        let pct = *count as f64 / total_samples as f64 * 100.0;
        println!("  {fname:<70} {count:>8} {pct:>6.1}%");
    }
    println!();
}

pub fn profile<F: FnMut()>(name: &str, duration_secs: u64, mut workload: F) {
    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(997)
        .build()
        .expect("pprof profiler must initialize");

    let deadline = Instant::now() + Duration::from_secs(duration_secs);
    let mut iters = 0u64;
    while Instant::now() < deadline {
        workload();
        iters += 1;
    }

    let report = guard.report().build().expect("pprof report must build");
    print_top(&report, name, iters, duration_secs);
}
