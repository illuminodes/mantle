//! Regression tests for every script-interpreter divergence the
//! differential fuzzer has ever found.
//!
//! When the fuzzer hits a panic on a new input, the policy is:
//! 1. Drop the raw `crash-*` file from `fuzz/artifacts/` into
//!    `fuzz/tests/regression/`.
//! 2. Fix the underlying bug in `mantle-consensus`.
//! 3. This test file picks the new fixture up automatically.
//!
//! Future regressions on a fixed bug fail this test — the fuzzer might
//! not rediscover the same input, but the fixture is permanent.

use std::fs;
use std::path::Path;

use mantle_fuzz::{FuzzInput, run_differential};

/// Decode an `Arbitrary`-encoded crash file into a `FuzzInput` and run it
/// through the same differential as the live fuzz target.
fn replay(name: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/regression")
        .join(name);
    let bytes = fs::read(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()));

    // Some `Arbitrary` decodes fail on truncated bytes — those aren't
    // useful regressions. Real crashes always decode (libFuzzer wrote
    // them after the harness consumed them).
    let input = FuzzInput::from_corpus_bytes(&bytes)
        .unwrap_or_else(|e| panic!("fixture {name} did not decode as FuzzInput: {e:?}"));

    run_differential(&input);
}

/// Iterate every fixture in `tests/regression/` and replay it.
///
/// One `#[test]` per fixture would give better failure granularity, but
/// the file list is dynamic — adding a fixture should *not* require
/// editing this file. The loop reports the offending name in its panic
/// message instead.
#[test]
fn all_known_crashes() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/regression");
    let mut count = 0;
    for entry in fs::read_dir(&dir).expect("regression dir exists") {
        let entry = entry.expect("readable entry");
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("crash-") {
            continue;
        }
        replay(&name);
        count += 1;
    }
    assert!(
        count > 0,
        "no regression fixtures found in {}",
        dir.display()
    );
    eprintln!("replayed {count} crash fixtures");
}
