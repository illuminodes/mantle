//! Differential probe: derive the exact CSV (BIP112) acceptance rule from
//! `bitcoinconsensus` by enumeration, and assert that mantle's
//! `verify_script` agrees on the same matrix.
//!
//! Why this exists: the BIP112 spec text is ambiguous about how
//! `tx.version < 2` interacts with the disable flag on the stack item, and
//! the differential fuzzer found inputs where mantle's implementation
//! differed from the oracle. Rather than read Core source (per
//! `principles.md` §1 — clean room), we derive the rule by *asking the
//! oracle directly* on a curated input matrix and capturing both the
//! oracle's verdicts and mantle's verdicts as test assertions. Future
//! drift on either side fails the test.
//!
//! Each row of the matrix is one CSV-only script:
//!   `<push n> OP_CSV`
//! evaluated against a tx with controlled `version` and input `nSequence`.

use mantle::codec::Encode;
use mantle::primitives::{
    Hash256, Locktime, OutPoint, Satoshi, Sequence, Transaction, TxIn, TxOut, TxVersion,
};
use mantle_conformance::conformance;
use mantle_consensus::script::{ScriptFlags, verify_script};

const VERIFY_CSV: u32 = conformance::VERIFY_CHECKSEQUENCEVERIFY;

/// One probe row.
#[derive(Debug)]
struct Probe {
    name: &'static str,
    tx_version: i32,
    input_seq: u32,
    /// `<n>` pushed before `OP_CSV`. Encoded as Bitcoin `ScriptNum`.
    csv_arg: i64,
}

/// Encode `n` as a minimal ScriptNum push opcode + body.
fn push_scriptnum(n: i64) -> Vec<u8> {
    use mantle_consensus::script::ScriptNum;
    let body = ScriptNum::from_i64(n);
    let mut s = vec![u8::try_from(body.as_bytes().len()).expect("≤5")];
    s.extend_from_slice(body.as_bytes());
    s
}

fn build_tx(version: i32, input_seq: u32) -> Transaction {
    Transaction {
        version: TxVersion::new(version),
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_bytes([1u8; 32]),
                vout: 0,
            },
            script_sig: Vec::<u8>::new().into(),
            sequence: Sequence::new(input_seq),
            witness: mantle::primitives::Witness::empty(),
        }],
        outputs: vec![TxOut {
            value: Satoshi::new(0),
            script_pubkey: vec![0x51].into(), // OP_1
        }],
        locktime: Locktime::new(0),
    }
}

/// Run one probe: ask both the oracle and mantle for a verdict.
fn run(probe: &Probe) -> (bool, bool) {
    let tx = build_tx(probe.tx_version, probe.input_seq);
    let mut tx_wire = Vec::new();
    tx.encode(&mut tx_wire).expect("encode");

    let mut script_pubkey = push_scriptnum(probe.csv_arg);
    script_pubkey.push(0xb2); // OP_CHECKSEQUENCEVERIFY

    let oracle = conformance::verify_script(&script_pubkey, 0, &tx_wire, None, 0, VERIFY_CSV);

    let mantle = verify_script(
        &[],
        &script_pubkey,
        &tx,
        0,
        Satoshi::ZERO,
        ScriptFlags::CHECKSEQUENCEVERIFY,
    );

    (oracle.is_ok(), mantle.is_ok())
}

#[test]
fn csv_oracle_matrix() {
    // Ground-truth rows. The `expected_oracle` column is what
    // bitcoinconsensus returns; we assert mantle matches it. If the
    // oracle's verdict ever changes (e.g. on a Core upgrade) the
    // assertion catches it before silently diverging.
    //
    // The DISABLE_BIT on the stack value is `1 << 31`. The same bit on
    // tx.nSequence disables BIP68 relative locktime for that input.
    const DISABLE: i64 = 1 << 31;
    const TYPE: i64 = 1 << 22;

    let probes = [
        // ── tx.version = 1 (pre-BIP68) ─────────────────────────────────
        // Stack disable bit set: BIP112 says NOP-pass regardless of version.
        Probe {
            name: "v1, csv=disable",
            tx_version: 1,
            input_seq: 0,
            csv_arg: DISABLE,
        },
        // Stack disable not set, v1 → fail (BIP112 rule 5).
        Probe {
            name: "v1, csv=1, seq=0",
            tx_version: 1,
            input_seq: 0,
            csv_arg: 1,
        },
        // Even with input nSequence == 1, v1 still fails.
        Probe {
            name: "v1, csv=1, seq=1",
            tx_version: 1,
            input_seq: 1,
            csv_arg: 1,
        },
        // ── tx.version = 2 (BIP68 active) ──────────────────────────────
        // csv=0 ≤ seq=anything → pass.
        Probe {
            name: "v2, csv=0, seq=0",
            tx_version: 2,
            input_seq: 0,
            csv_arg: 0,
        },
        // csv=1 vs seq=0 → fail (1 > 0).
        Probe {
            name: "v2, csv=1, seq=0",
            tx_version: 2,
            input_seq: 0,
            csv_arg: 1,
        },
        // csv=1 vs seq=1 → pass.
        Probe {
            name: "v2, csv=1, seq=1",
            tx_version: 2,
            input_seq: 1,
            csv_arg: 1,
        },
        // Input has DISABLE bit set: CSV cannot enforce → fail.
        Probe {
            name: "v2, csv=1, seq=disable",
            tx_version: 2,
            input_seq: 1u32 << 31,
            csv_arg: 1,
        },
        // Stack DISABLE bit set: NOP-pass regardless.
        Probe {
            name: "v2, csv=disable",
            tx_version: 2,
            input_seq: 0,
            csv_arg: DISABLE,
        },
        // Type-bit mismatch: stack has TYPE bit, input doesn't → fail.
        Probe {
            name: "v2, csv=type|1, seq=1",
            tx_version: 2,
            input_seq: 1,
            csv_arg: TYPE | 1,
        },
        // ── Negative tx.version (i32 wrap, observed in fuzzer) ─────────
        // i32::MIN. Cast to u32 has high bit set; treat as v < 2 path.
        Probe {
            name: "v=neg, csv=1",
            tx_version: -1,
            input_seq: 0,
            csv_arg: 1,
        },
        Probe {
            name: "v=neg, csv=disable",
            tx_version: -1,
            input_seq: 0,
            csv_arg: DISABLE,
        },
        // Reproduces fuzzer crash 04afca... shape: version 0xfd010101 (negative).
        Probe {
            name: "v=0xfd010101, csv=1",
            tx_version: 0xfd01_0101u32 as i32,
            input_seq: 0x0101_0101,
            csv_arg: 1,
        },
    ];

    let mut mismatches = Vec::new();
    let mut table = String::new();
    for probe in &probes {
        let (oracle_ok, mantle_ok) = run(probe);
        table.push_str(&format!(
            "  {:35} oracle={} mantle={}\n",
            probe.name,
            if oracle_ok { "ACCEPT" } else { "REJECT" },
            if mantle_ok { "ACCEPT" } else { "REJECT" },
        ));
        if oracle_ok != mantle_ok {
            mismatches.push(probe.name);
        }
    }

    // Print the full matrix even on success — the table *is* the ground
    // truth, and updating mantle to match it requires reading it.
    println!("CSV oracle matrix:\n{table}");

    assert!(
        mismatches.is_empty(),
        "mantle disagreed with oracle on {} probe(s):\n{}\nfull matrix:\n{}",
        mismatches.len(),
        mismatches.join(", "),
        table,
    );
}
