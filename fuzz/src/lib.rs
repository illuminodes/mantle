//! Shared logic between `fuzz_script_differential` and its regression tests.
//!
//! The fuzz target loops on random inputs; the regression test replays
//! known crash bytes. Both reduce to the same per-input differential
//! between mantle and bitcoinconsensus, so it lives here.

use arbitrary::{Arbitrary, Unstructured};
use mantle::codec::{Decode, Encode};
use mantle::primitives::{Hash256, Satoshi, Transaction, TxOut};
use mantle_conformance::conformance;
use mantle_consensus::script::{ScriptFlags, ScriptVerifier, SpentOutputs};
use std::io::Cursor;

/// Mask to the flag bits we currently assert parity on.
///
/// **M4**: all consensus flags — P2SH, BIP66 (DERSIG), NULLDUMMY, CLTV, CSV,
/// WITNESS, and TAPROOT. Every flag bitcoinconsensus accepts is now compared.
pub const FLAGS_MASK: u32 = conformance::VERIFY_P2SH
    | conformance::VERIFY_DERSIG
    | conformance::VERIFY_NULLDUMMY
    | conformance::VERIFY_CHECKLOCKTIMEVERIFY
    | conformance::VERIFY_CHECKSEQUENCEVERIFY
    | conformance::VERIFY_WITNESS
    | conformance::VERIFY_TAPROOT;

/// One entry in the spent-outputs table: the script_pubkey and amount for a
/// single input's corresponding UTXO.
#[derive(Arbitrary, Debug)]
pub struct SpentOutput {
    pub script_pubkey: Vec<u8>,
    pub amount: u64,
}

/// Full differential fuzz input.
#[derive(Arbitrary, Debug)]
pub struct FuzzInput {
    pub tx_bytes: Vec<u8>,
    pub spent_outputs: Vec<SpentOutput>,
    pub flags: u32,
}

impl FuzzInput {
    /// Decode an `Arbitrary`-encoded `FuzzInput` from raw bytes — what
    /// libFuzzer hands us, what cargo-fuzz writes to crash files, and
    /// what regression-test fixtures store.
    ///
    /// # Errors
    /// `arbitrary::Error` if the bytes don't satisfy `Arbitrary`'s
    /// derivation (rare — `Vec<u8>` and `u32` are very permissive).
    pub fn from_corpus_bytes(bytes: &[u8]) -> Result<Self, arbitrary::Error> {
        let u = Unstructured::new(bytes);
        Self::arbitrary_take_rest(u)
    }
}

/// Run one differential round on a `FuzzInput`. Used by the fuzz target
/// and by `tests/regression.rs`.
///
/// On any divergence, panics with the same message format the fuzz
/// target produces — so a regression test failure reads exactly like
/// the crash that caused it.
pub fn run_differential(input: &FuzzInput) {
    let mut flags = input.flags & FLAGS_MASK;
    // Bitcoin Core asserts P2SH must be set whenever WITNESS is set.
    if flags & conformance::VERIFY_WITNESS != 0 {
        flags |= conformance::VERIFY_P2SH;
    }
    let tx = match Transaction::decode(&mut Cursor::new(&input.tx_bytes)) {
        Ok(tx) => tx,
        Err(_) => return,
    };

    // Coinbase inputs are never script-verified.
    if tx
        .inputs
        .iter()
        .any(|i| i.previous_output.txid == Hash256::ZERO && i.previous_output.vout == u32::MAX)
    {
        return;
    }

    let mut tx_wire = Vec::new();
    tx.encode(&mut tx_wire)
        .expect("encode must not fail on a decoded Transaction");

    // Build the spent-outputs table for the oracle (required for taproot).
    //
    // Core's C++ requires `spent_outputs.len() == tx.inputs.len()` whenever
    // TAPROOT is set and spent_outputs is Some — a count mismatch returns
    // ERR_SPENT_OUTPUTS_MISMATCH regardless of the script being verified.
    // When the fuzz input doesn't cover all inputs, we can't meaningfully
    // compare taproot verdicts, so strip TAPROOT and pass None.
    let have_full_spent_outputs = input.spent_outputs.len() >= tx.inputs.len();
    if flags & conformance::VERIFY_TAPROOT != 0 && !have_full_spent_outputs {
        flags &= !conformance::VERIFY_TAPROOT;
    }
    let mantle_flags = ScriptFlags::from_bits(flags);

    // `Utxo` holds a raw pointer into the script_pubkey bytes, so the Vec
    // data must outlive the Utxo slice. We borrow from `input.spent_outputs`
    // directly — their Vecs don't move while `utxos` is alive.
    let utxos: Vec<conformance::Utxo> = input
        .spent_outputs
        .iter()
        .take(tx.inputs.len())
        .map(|s| conformance::Utxo {
            script_pubkey: s.script_pubkey.as_ptr(),
            script_pubkey_len: s.script_pubkey.len() as u32,
            value: s.amount as i64,
        })
        .collect();
    let spent_outputs_arg = if flags & conformance::VERIFY_TAPROOT != 0 {
        Some(utxos.as_slice())
    } else {
        None
    };

    let mantle_amounts: Vec<Satoshi> = input
        .spent_outputs
        .iter()
        .take(tx.inputs.len())
        .map(|s| Satoshi::new(s.amount))
        .collect();
    let mantle_spks: Vec<&[u8]> = input
        .spent_outputs
        .iter()
        .take(tx.inputs.len())
        .map(|s| s.script_pubkey.as_slice())
        .collect();
    let mantle_spent = spent_outputs_arg
        .and_then(|_| SpentOutputs::new(&mantle_amounts, &mantle_spks));

    for (i, spent) in input.spent_outputs.iter().enumerate().take(tx.inputs.len()) {
        // Exercise TxOut codec on each spent output.
        let txout = TxOut {
            value: Satoshi::new(spent.amount),
            script_pubkey: spent.script_pubkey.clone().into(),
        };
        let mut txout_wire = Vec::new();
        txout
            .encode(&mut txout_wire)
            .expect("TxOut encode must not fail");
        let txout_rt = TxOut::decode(&mut Cursor::new(&txout_wire))
            .expect("TxOut decode must not fail on freshly encoded bytes");
        assert_eq!(txout.value, txout_rt.value);
        assert_eq!(txout.script_pubkey, txout_rt.script_pubkey);

        let oracle = conformance::verify_script(
            &spent.script_pubkey,
            spent.amount,
            &tx_wire,
            spent_outputs_arg,
            i,
            flags,
        );

        let mut verifier =
            ScriptVerifier::new(&tx, i, Satoshi::new(spent.amount), mantle_flags);
        if let Some(table) = mantle_spent {
            verifier = verifier.with_spent_outputs(table);
        }
        let mantle = verifier.verify(tx.inputs[i].script_sig.as_slice(), &spent.script_pubkey);

        assert_eq!(
            oracle.is_ok(),
            mantle.is_ok(),
            "M4 divergence at input {}: oracle={:?} mantle={:?}\n\
             tx_wire={:02x?}\n\
             script_pubkey={:02x?}\n\
             flags={:#010x}",
            i,
            oracle,
            mantle,
            tx_wire,
            spent.script_pubkey,
            flags,
        );
    }
}
