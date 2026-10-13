use mantle::primitives::{Hash256, Satoshi};

use crate::script::sighash::Bip143Cache;
use crate::script::{ScriptError, ScriptExecutionCache, ScriptFlags, ScriptVerifier, SpentOutputs};
use crate::tx_view::TxView;

/// The output an input spends, reduced to what script verification reads.
#[derive(Debug, Clone, Copy)]
pub struct Prevout<'a> {
    pub value: Satoshi,
    pub script_pubkey: &'a [u8],
}

/// Per-transaction state shared by every input's script verification:
/// the BIP143 midstate, the BIP341 spent-output table, and the wtxid that
/// keys the execution cache.
pub struct TxScriptContext<'v> {
    flags: ScriptFlags,
    bip143: Option<Bip143Cache>,
    spent: Option<SpentTable<'v>>,
    wtxid: Option<Hash256>,
}

struct SpentTable<'v> {
    amounts: Vec<Satoshi>,
    script_pubkeys: Vec<&'v [u8]>,
}

impl<'v> SpentTable<'v> {
    const TAPROOT_PROGRAM_PREFIX: [u8; 2] = [0x51, 0x20];

    fn is_taproot_output(spk: &[u8]) -> bool {
        spk.len() == 34 && spk.starts_with(&Self::TAPROOT_PROGRAM_PREFIX)
    }

    fn build(prevouts: &[Prevout<'v>]) -> Option<Self> {
        if prevouts.len() < 2
            || !prevouts
                .iter()
                .any(|p| Self::is_taproot_output(p.script_pubkey))
        {
            return None;
        }
        Some(Self {
            amounts: prevouts.iter().map(|p| p.value).collect(),
            script_pubkeys: prevouts.iter().map(|p| p.script_pubkey).collect(),
        })
    }

    fn view(&self) -> SpentOutputs<'_> {
        SpentOutputs::new(&self.amounts, &self.script_pubkeys)
            .expect("amounts and script_pubkeys are built from the same prevouts")
    }
}

impl<'v> TxScriptContext<'v> {
    /// Build the shared state for verifying every input of `tx`.
    ///
    /// `prevouts` holds one entry per input, in input order. `cached` selects
    /// the execution-cache path, which needs the wtxid instead of the BIP143
    /// midstate.
    ///
    /// # Errors
    /// Propagates wtxid encoding errors (none in practice).
    pub fn new<T: TxView>(
        tx: &T,
        prevouts: &[Prevout<'v>],
        flags: ScriptFlags,
        cached: bool,
        scratch: &mut Vec<u8>,
    ) -> std::io::Result<Self> {
        if !cached {
            return Ok(Self::uncached(tx, prevouts, flags));
        }
        Ok(Self {
            flags,
            bip143: None,
            spent: SpentTable::build(prevouts),
            wtxid: Some(tx.compute_wtxid(scratch)?),
        })
    }

    /// Build the shared state for verifying every input of `tx` without an
    /// execution cache.
    pub fn uncached<T: TxView>(tx: &T, prevouts: &[Prevout<'v>], flags: ScriptFlags) -> Self {
        Self {
            flags,
            bip143: Some(Bip143Cache::new(tx)),
            spent: SpentTable::build(prevouts),
            wtxid: None,
        }
    }

    /// Verify input `n_in` of `tx` against the output it spends.
    ///
    /// # Errors
    /// Returns the interpreter's [`ScriptError`] when the input does not
    /// authorise the spend.
    pub fn verify_input<T: TxView>(
        &self,
        tx: &T,
        n_in: usize,
        script_sig: &[u8],
        prevout: &Prevout<'_>,
        exec_cache: Option<&mut ScriptExecutionCache>,
    ) -> Result<(), ScriptError> {
        let mut verifier = match &self.bip143 {
            Some(midstate) => {
                ScriptVerifier::with_cache(tx, n_in, prevout.value, self.flags, midstate.clone())
            }
            None => ScriptVerifier::new(tx, n_in, prevout.value, self.flags),
        };
        if let Some(table) = &self.spent {
            verifier = verifier.with_spent_outputs(table.view());
        }
        match (exec_cache, &self.wtxid) {
            (Some(cache), Some(wtxid)) => {
                verifier.verify_cached(script_sig, prevout.script_pubkey, wtxid, cache)
            }
            _ => verifier.verify(script_sig, prevout.script_pubkey),
        }
    }
}
