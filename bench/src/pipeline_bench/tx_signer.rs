use mantle::primitives::{Transaction, Witness};
use mantle_consensus::script::sighash::{Bip143Cache, SigHashType, TxSighash};

use crate::keyring::Keyring;
use crate::spendable_coin::{CoinKind, SpendableCoin};

/// Fills in the scriptSigs and witnesses of a transaction whose inputs
/// spend `coins`, one coin per input in order.
pub struct TxSigner<'k> {
    keys: &'k Keyring,
}

impl<'k> TxSigner<'k> {
    pub fn new(keys: &'k Keyring) -> Self {
        Self { keys }
    }

    pub fn sign(&self, tx: &mut Transaction, coins: &[SpendableCoin]) {
        let bip143 = coins
            .iter()
            .any(|c| c.kind == CoinKind::P2wpkh)
            .then(|| Bip143Cache::new(&*tx));
        let signatures: Vec<Vec<u8>> = coins
            .iter()
            .enumerate()
            .map(|(n_in, coin)| {
                let script_code = self.keys.p2pkh_script(coin.key);
                let digest = match (coin.kind, &bip143) {
                    (CoinKind::P2wpkh, Some(cache)) => tx.bip143_sighash(
                        n_in,
                        &script_code,
                        coin.value,
                        SigHashType::ALL,
                        cache,
                    ),
                    _ => tx.legacy_sighash(n_in, &script_code, SigHashType::ALL),
                };
                self.keys.sign_all(coin.key, digest.as_bytes())
            })
            .collect();
        for ((input, coin), signature) in tx.inputs.iter_mut().zip(coins).zip(signatures) {
            let pubkey = self.keys.pubkey(coin.key);
            match coin.kind {
                CoinKind::P2pkh => {
                    let mut script_sig = Vec::with_capacity(signature.len() + pubkey.len() + 2);
                    script_sig.push(u8::try_from(signature.len()).expect("DER signature < 76"));
                    script_sig.extend_from_slice(&signature);
                    script_sig.push(u8::try_from(pubkey.len()).expect("compressed pubkey"));
                    script_sig.extend_from_slice(pubkey);
                    input.script_sig = script_sig.into();
                }
                CoinKind::P2wpkh => {
                    input.witness = Witness::from_slice(&[signature.as_slice(), pubkey]);
                }
            }
        }
    }
}
