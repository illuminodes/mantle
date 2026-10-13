use mantle::codec::{Encode, VarInt};
use mantle::primitives::{BlockHeight, Hash256, OutPoint, Satoshi};

use crate::muhash::MuHash3072;
use crate::num3072::Num3072;

/// One unspent output, as the UTXO set hash sees it.
#[derive(Debug, Clone, Copy)]
pub struct UtxoCoin<'a> {
    pub outpoint: OutPoint,
    pub value: Satoshi,
    pub script_pubkey: &'a [u8],
    pub height: BlockHeight,
    pub coinbase: bool,
}

impl UtxoCoin<'_> {
    const MAX_SCRIPT_SIZE: usize = 10_000;
    const OP_RETURN: u8 = 0x6a;

    /// Core's `CScript::IsUnspendable`. Such outputs never enter Core's UTXO set.
    #[must_use]
    pub fn is_unspendable(&self) -> bool {
        self.script_pubkey.first() == Some(&Self::OP_RETURN)
            || self.script_pubkey.len() > Self::MAX_SCRIPT_SIZE
    }

    /// Core's `TxOutSer`: outpoint, `height << 1 | coinbase`, then the `CTxOut`.
    fn serialize_into(&self, out: &mut Vec<u8>) {
        out.clear();
        out.extend_from_slice(self.outpoint.txid.as_bytes());
        out.extend_from_slice(&self.outpoint.vout.to_le_bytes());
        let code = (self.height.to_u32() << 1) | u32::from(self.coinbase);
        out.extend_from_slice(&code.to_le_bytes());
        out.extend_from_slice(&self.value.to_le_bytes());
        VarInt::from(self.script_pubkey.len())
            .encode(out)
            .expect("writing to a Vec cannot fail");
        out.extend_from_slice(self.script_pubkey);
    }
}

/// The `MuHash3072` of the UTXO set, maintained block by block the way Core's
/// coinstats index maintains it. [`finalize`](Self::finalize) gives the value
/// of `bitcoin-cli gettxoutsetinfo muhash <height>`.
#[derive(Clone, Debug, Default)]
pub struct UtxoSetHash {
    muhash: MuHash3072,
    scratch: Vec<u8>,
}

impl UtxoSetHash {
    pub const STATE_LEN: usize = 2 * Num3072::BYTE_SIZE;

    /// Coinbases that a later duplicate overwrote before they were spent. Core's
    /// `IsBIP30Unspendable` leaves them out of the hash.
    const OVERWRITTEN_COINBASES: [(BlockHeight, Hash256); 2] = [
        (
            BlockHeight::new(91_722),
            Hash256::from_display_hex_const(
                "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e",
            ),
        ),
        (
            BlockHeight::new(91_812),
            Hash256::from_display_hex_const(
                "00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f",
            ),
        ),
    ];

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the coinbase outputs of this block are left out of the hash.
    #[must_use]
    pub fn skips_coinbase_of(height: BlockHeight, block_hash: Hash256) -> bool {
        Self::OVERWRITTEN_COINBASES
            .iter()
            .any(|&(h, hash)| h == height && hash == block_hash)
    }

    pub fn insert(&mut self, coin: &UtxoCoin<'_>) {
        if coin.is_unspendable() {
            return;
        }
        coin.serialize_into(&mut self.scratch);
        self.muhash.insert(&self.scratch);
    }

    pub fn remove(&mut self, coin: &UtxoCoin<'_>) {
        if coin.is_unspendable() {
            return;
        }
        coin.serialize_into(&mut self.scratch);
        self.muhash.remove(&self.scratch);
    }

    #[must_use]
    pub fn finalize(&self) -> Hash256 {
        self.muhash.finalize()
    }

    #[must_use]
    pub fn to_state_bytes(&self) -> [u8; Self::STATE_LEN] {
        self.muhash.to_state_bytes()
    }

    #[must_use]
    pub fn from_state_bytes(bytes: &[u8; Self::STATE_LEN]) -> Self {
        Self {
            muhash: MuHash3072::from_state_bytes(bytes),
            scratch: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{UtxoCoin, UtxoSetHash};
    use crate::muhash::MuHash3072;
    use crate::test_hex::TestHex;
    use mantle::primitives::{BlockHeight, Hash256, OutPoint, Satoshi};

    fn coin(script: &[u8]) -> UtxoCoin<'_> {
        UtxoCoin {
            outpoint: OutPoint {
                txid: Hash256::from_bytes([0xab; 32]),
                vout: 0x0102_0304,
            },
            value: Satoshi::new(5_000_000_000),
            script_pubkey: script,
            height: BlockHeight::new(100),
            coinbase: true,
        }
    }

    #[test]
    fn serializes_like_core_txoutser() {
        let mut out = Vec::new();
        coin(&[0x51, 0x52]).serialize_into(&mut out);
        let expected = format!(
            "{}{}{}{}{}",
            "ab".repeat(32),
            "04030201",
            "c9000000",
            "00f2052a01000000",
            "025152",
        );
        assert_eq!(TestHex::encode(&out), expected);
    }

    #[test]
    fn unspendable_outputs_are_not_hashed() {
        let mut set = UtxoSetHash::new();
        set.insert(&coin(&[0x6a, 0x01, 0x00]));
        set.insert(&coin(&vec![0x51; 10_001]));
        assert_eq!(set.finalize(), MuHash3072::new().finalize());

        set.insert(&coin(&vec![0x51; 10_000]));
        assert_ne!(set.finalize(), MuHash3072::new().finalize());
    }

    #[test]
    fn insert_then_remove_is_empty() {
        let mut set = UtxoSetHash::new();
        set.insert(&coin(&[0x51]));
        set.remove(&coin(&[0x51]));
        assert_eq!(set.finalize(), UtxoSetHash::new().finalize());
    }

    #[test]
    fn height_and_coinbase_flag_are_part_of_the_coin() {
        let mut a = UtxoSetHash::new();
        a.insert(&coin(&[0x51]));
        let mut b = UtxoSetHash::new();
        b.insert(&UtxoCoin {
            coinbase: false,
            ..coin(&[0x51])
        });
        let mut c = UtxoSetHash::new();
        c.insert(&UtxoCoin {
            height: BlockHeight::new(101),
            ..coin(&[0x51])
        });
        assert_ne!(a.finalize(), b.finalize());
        assert_ne!(a.finalize(), c.finalize());
    }

    #[test]
    fn only_the_two_overwritten_coinbases_are_skipped() {
        let hash_91722 = Hash256::from_display_hex_const(
            "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e",
        );
        assert!(UtxoSetHash::skips_coinbase_of(BlockHeight::new(91_722), hash_91722));
        assert!(!UtxoSetHash::skips_coinbase_of(BlockHeight::new(91_723), hash_91722));
        assert!(!UtxoSetHash::skips_coinbase_of(
            BlockHeight::new(91_722),
            Hash256::ZERO
        ));
    }

    #[test]
    fn state_bytes_round_trip() {
        let mut set = UtxoSetHash::new();
        set.insert(&coin(&[0x51]));
        set.remove(&coin(&[0x52]));
        let restored = UtxoSetHash::from_state_bytes(&set.to_state_bytes());
        assert_eq!(restored.finalize(), set.finalize());
    }
}
