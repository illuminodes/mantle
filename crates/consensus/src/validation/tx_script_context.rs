use mantle::primitives::{Hash256, Satoshi};

use crate::chain_view::Coin;
use crate::script::sighash::Bip143Cache;
use crate::script::{ScriptError, ScriptExecutionCache, ScriptFlags, ScriptVerifier, SpentOutputs};
use crate::tx_view::TxView;

/// Per-transaction state shared by every input's script verification:
/// the BIP143 midstate, the BIP341 spent-output table, and the wtxid that
/// keys the execution cache.
pub(super) struct TxScriptContext<'v> {
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

    fn build(coins: &[Option<&'v Coin>]) -> Option<Self> {
        if coins.len() < 2 {
            return None;
        }
        let mut amounts = Vec::with_capacity(coins.len());
        let mut script_pubkeys = Vec::with_capacity(coins.len());
        let mut any_taproot = false;
        for coin in coins {
            let coin = (*coin)?;
            let spk = coin.script_pubkey.as_slice();
            any_taproot |= Self::is_taproot_output(spk);
            amounts.push(coin.value);
            script_pubkeys.push(spk);
        }
        any_taproot.then_some(Self {
            amounts,
            script_pubkeys,
        })
    }

    fn view(&self) -> SpentOutputs<'_> {
        SpentOutputs::new(&self.amounts, &self.script_pubkeys)
            .expect("amounts and script_pubkeys are pushed in lockstep")
    }
}

impl<'v> TxScriptContext<'v> {
    pub(super) fn new<T: TxView>(
        tx: &T,
        coins: &[Option<&'v Coin>],
        flags: ScriptFlags,
        cached: bool,
        scratch: &mut Vec<u8>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            flags,
            bip143: (!cached).then(|| Bip143Cache::new(tx)),
            spent: SpentTable::build(coins),
            wtxid: if cached {
                Some(tx.compute_wtxid(scratch)?)
            } else {
                None
            },
        })
    }

    pub(super) fn verify_input<T: TxView>(
        &self,
        tx: &T,
        n_in: usize,
        script_sig: &[u8],
        coin: &Coin,
        exec_cache: Option<&mut ScriptExecutionCache>,
    ) -> Result<(), ScriptError> {
        let mut verifier = match &self.bip143 {
            Some(midstate) => {
                ScriptVerifier::with_cache(tx, n_in, coin.value, self.flags, midstate.clone())
            }
            None => ScriptVerifier::new(tx, n_in, coin.value, self.flags),
        };
        if let Some(table) = &self.spent {
            verifier = verifier.with_spent_outputs(table.view());
        }
        let spk = coin.script_pubkey.as_slice();
        match (exec_cache, &self.wtxid) {
            (Some(cache), Some(wtxid)) => verifier.verify_cached(script_sig, spk, wtxid, cache),
            _ => verifier.verify(script_sig, spk),
        }
    }
}
