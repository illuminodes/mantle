#![no_main]

use libfuzzer_sys::fuzz_target;
use mantle_fuzz::{FuzzInput, run_differential};

fuzz_target!(|input: FuzzInput| {
    run_differential(&input);
});
