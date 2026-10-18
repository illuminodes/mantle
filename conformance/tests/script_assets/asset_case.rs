//! One entry of `script_assets_test.json` and the checks Core runs on it.

use std::io::Cursor;

use mantle::codec::Decode;
use mantle::primitives::{Satoshi, Transaction, TxOut, Witness};
use mantle_consensus::script::{ScriptFlags, SpentOutputs, verify_script_with_spent_outputs};
use mantle_consensus::test_helpers::decode_hex;

use crate::consensus_flag_sets::ConsensusFlagSets;
use crate::mismatch_report::MismatchReport;

/// The scriptSig and witness to place in the spending input.
pub struct Spend {
    script_sig: Vec<u8>,
    witness: Vec<Vec<u8>>,
}

impl Spend {
    fn parse(value: &serde_json::Value) -> Self {
        Self {
            script_sig: decode_hex(value["scriptSig"].as_str().expect("scriptSig")),
            witness: value["witness"]
                .as_array()
                .expect("witness array")
                .iter()
                .map(|w| decode_hex(w.as_str().expect("witness hex")))
                .collect(),
        }
    }
}

pub struct AssetCase {
    tx: Transaction,
    prevouts: Vec<TxOut>,
    index: usize,
    flags: ScriptFlags,
    is_final: bool,
    success: Option<Spend>,
    failure: Option<Spend>,
    comment: String,
}

impl AssetCase {
    pub fn parse(value: &serde_json::Value) -> Self {
        let tx_bytes = decode_hex(value["tx"].as_str().expect("tx"));
        let tx = Transaction::decode(&mut Cursor::new(tx_bytes)).expect("tx decodes");
        let prevouts = value["prevouts"]
            .as_array()
            .expect("prevouts")
            .iter()
            .map(|p| {
                let bytes = decode_hex(p.as_str().expect("prevout hex"));
                TxOut::decode(&mut Cursor::new(bytes)).expect("prevout decodes")
            })
            .collect();
        Self {
            tx,
            prevouts,
            index: usize::try_from(value["index"].as_u64().expect("index")).expect("fits"),
            flags: ConsensusFlagSets::parse(value["flags"].as_str().expect("flags")),
            is_final: value["final"].as_bool().unwrap_or(false),
            success: value.get("success").map(Spend::parse),
            failure: value.get("failure").map(Spend::parse),
            comment: value["comment"].as_str().unwrap_or("").to_string(),
        }
    }

    /// Core's rules: a success must pass under every flag set that is a
    /// subset of the case's flags (every flag set if `final`); a failure
    /// must fail under every superset of the case's flags.
    pub fn check(&self, flag_sets: &ConsensusFlagSets, report: &mut MismatchReport) {
        if let Some(spend) = &self.success {
            for flags in flag_sets.iter() {
                if self.is_final || (flags & self.flags) == flags {
                    self.expect(spend, flags, true, report);
                }
            }
        }
        if let Some(spend) = &self.failure {
            for flags in flag_sets.iter() {
                if (flags & self.flags) == self.flags {
                    self.expect(spend, flags, false, report);
                }
            }
        }
    }

    fn expect(
        &self,
        spend: &Spend,
        flags: ScriptFlags,
        expected_ok: bool,
        report: &mut MismatchReport,
    ) {
        let mut tx = self.tx.clone();
        let input = &mut tx.inputs[self.index];
        input.script_sig = spend.script_sig.clone().into();
        input.witness =
            Witness::from_slice(&spend.witness.iter().map(Vec::as_slice).collect::<Vec<_>>());
        let amounts: Vec<Satoshi> = self.prevouts.iter().map(|p| p.value).collect();
        let spks: Vec<&[u8]> = self
            .prevouts
            .iter()
            .map(|p| p.script_pubkey.as_slice())
            .collect();
        let spent_outputs = SpentOutputs::new(&amounts, &spks).expect("parallel slices");
        let prevout = &self.prevouts[self.index];
        let result = verify_script_with_spent_outputs(
            &spend.script_sig,
            prevout.script_pubkey.as_slice(),
            &tx,
            self.index,
            prevout.value,
            flags,
            spent_outputs,
        );
        report.record_check();
        if result.is_ok() != expected_ok {
            report.record_mismatch(&self.comment, expected_ok, flags, &format!("{result:?}"));
        }
    }
}
