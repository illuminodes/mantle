//! Collects disagreements with Core and fails the test with a summary.

use std::collections::BTreeMap;

use mantle_consensus::script::ScriptFlags;

/// Disagreements grouped by the case's comment (its category in Core's
/// generator), keeping one example of each.
#[derive(Default)]
pub struct MismatchReport {
    by_comment: BTreeMap<String, (usize, String)>,
    checks: usize,
}

impl MismatchReport {
    pub fn record_check(&mut self) {
        self.checks += 1;
    }

    pub fn record_mismatch(
        &mut self,
        comment: &str,
        expected_ok: bool,
        flags: ScriptFlags,
        got: &str,
    ) {
        let entry = self
            .by_comment
            .entry(comment.to_string())
            .or_insert_with(|| {
                (
                    0,
                    format!(
                        "expected {}, flags 0x{:x}, got {got}",
                        if expected_ok { "accept" } else { "reject" },
                        flags.bits()
                    ),
                )
            });
        entry.0 += 1;
    }

    pub fn finish(self, cases: usize) {
        eprintln!(
            "script assets: {cases} cases, {} verdicts checked",
            self.checks
        );
        if self.by_comment.is_empty() {
            return;
        }
        let total: usize = self.by_comment.values().map(|(n, _)| n).sum();
        let mut lines = vec![format!(
            "{total} disagreements with Core in {} categories:",
            self.by_comment.len()
        )];
        for (comment, (count, example)) in &self.by_comment {
            lines.push(format!("  {comment}: {count} ({example})"));
        }
        panic!("{}", lines.join("\n"));
    }
}
