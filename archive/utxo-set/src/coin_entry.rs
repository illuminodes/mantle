use mantle::primitives::{Satoshi, ScriptPubKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinEntry {
    pub value: Satoshi,
    pub script_pubkey: ScriptPubKey,
}
