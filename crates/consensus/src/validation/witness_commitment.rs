use mantle::primitives::{Block, BlockHeight, Hash256, Transaction};

use crate::error::ValidationError;
use crate::merkle::compute_merkle_root;
use crate::tx_view::TxView;

/// BIP141 witness commitment carried in a coinbase output.
///
/// The commitment is the last coinbase output whose scriptPubKey starts
/// `OP_RETURN 0x24 0xaa21a9ed`. It holds `SHA256d(witness_root || reserved)`,
/// where `witness_root` is the merkle root of every wtxid with the coinbase
/// wtxid replaced by zero, and `reserved` is the single 32-byte item of the
/// coinbase input's witness.
pub(super) struct WitnessCommitment<'a> {
    script: &'a [u8],
}

impl<'a> WitnessCommitment<'a> {
    /// Mainnet height at which BIP141 (segwit) became active.
    pub(super) const SEGWIT_HEIGHT: BlockHeight = BlockHeight::new(481_824);

    const PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    const MIN_SCRIPT_LEN: usize = 38;
    const RESERVED_VALUE_LEN: usize = 32;

    fn find(coinbase: &'a Transaction) -> Option<Self> {
        coinbase
            .outputs
            .iter()
            .rev()
            .map(|output| output.script_pubkey.as_slice())
            .find(|spk| spk.len() >= Self::MIN_SCRIPT_LEN && spk.starts_with(&Self::PREFIX))
            .map(|script| Self { script })
    }

    fn committed_hash(&self) -> &[u8] {
        &self.script[Self::PREFIX.len()..Self::MIN_SCRIPT_LEN]
    }

    /// Enforce the commitment rules for a block at `height`.
    ///
    /// Blocks without an active commitment (before segwit, or without the
    /// commitment output) may not carry witness data at all.
    ///
    /// # Errors
    /// `BadWitnessNonceSize`, `BadWitnessMerkleMatch` or `UnexpectedWitness`.
    pub(super) fn check(block: &'a Block, height: BlockHeight) -> Result<(), ValidationError> {
        let coinbase = &block.transactions[0];
        let commitment = if height >= Self::SEGWIT_HEIGHT {
            Self::find(coinbase)
        } else {
            None
        };
        match commitment {
            Some(commitment) => commitment.verify(block),
            None => Self::reject_witness_data(block),
        }
    }

    fn verify(&self, block: &Block) -> Result<(), ValidationError> {
        let coinbase_witness = block.transactions[0].inputs[0].witness.to_vec();
        let [reserved] = coinbase_witness.as_slice() else {
            return Err(ValidationError::BadWitnessNonceSize);
        };
        if reserved.len() != Self::RESERVED_VALUE_LEN {
            return Err(ValidationError::BadWitnessNonceSize);
        }

        let mut scratch = Vec::new();
        let mut wtxids = Vec::with_capacity(block.transactions.len());
        wtxids.push(Hash256::ZERO);
        for tx in &block.transactions[1..] {
            wtxids.push(tx.compute_wtxid(&mut scratch)?);
        }
        let root = compute_merkle_root(&wtxids).expect("wtxid list holds at least the coinbase");

        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(root.as_bytes());
        preimage[32..].copy_from_slice(reserved);
        if Hash256::hash(&preimage).as_bytes()[..] != *self.committed_hash() {
            return Err(ValidationError::BadWitnessMerkleMatch);
        }
        Ok(())
    }

    fn reject_witness_data(block: &Block) -> Result<(), ValidationError> {
        match block.transactions.iter().position(Transaction::is_segwit) {
            Some(tx_index) => Err(ValidationError::UnexpectedWitness { tx_index }),
            None => Ok(()),
        }
    }
}
