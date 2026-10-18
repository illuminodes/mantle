//! Differential test against Bitcoin Core's `script_assets_test.json`
//! (bitcoin-core/qa-assets, `unit_test_data/`). Each case is a spend that
//! Core accepts (`success`) and/or rejects (`failure`) under every
//! consensus flag combination the case permits. This runs the same
//! verdicts through Mantle.
//!
//! The file is not vendored. Set `SCRIPT_ASSETS_JSON` to its path; the test
//! is skipped with a message when the variable is unset.

mod asset_case;
mod consensus_flag_sets;
mod mismatch_report;

use asset_case::AssetCase;
use consensus_flag_sets::ConsensusFlagSets;
use mismatch_report::MismatchReport;

#[test]
fn mantle_agrees_with_core_on_every_script_asset() {
    let Some(path) = std::env::var_os("SCRIPT_ASSETS_JSON") else {
        eprintln!("SCRIPT_ASSETS_JSON unset; skipping the script assets differential test");
        return;
    };
    let text = std::fs::read_to_string(&path).expect("read script_assets_test.json");
    let cases: Vec<serde_json::Value> = serde_json::from_str(&text).expect("parse JSON");
    assert!(!cases.is_empty(), "no cases in {}", path.to_string_lossy());

    let flag_sets = ConsensusFlagSets::all();
    let mut report = MismatchReport::default();
    for value in &cases {
        let case = AssetCase::parse(value);
        case.check(&flag_sets, &mut report);
    }
    report.finish(cases.len());
}
