//! UTXO set commitments compatible with Bitcoin Core.
//!
//! [`MuHash3072`] reproduces Core's `crypto/muhash.cpp`. [`UtxoSetHash`]
//! applies it to the UTXO set the way Core's coinstats index does, giving the
//! value of `gettxoutsetinfo muhash`.

pub mod chacha20;
pub mod muhash;
pub mod num3072;
pub mod utxo_set_hash;

#[cfg(test)]
mod test_hex;

pub use muhash::MuHash3072;
pub use num3072::Num3072;
pub use utxo_set_hash::{UtxoCoin, UtxoSetHash};
