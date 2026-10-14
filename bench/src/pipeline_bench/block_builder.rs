use mantle::primitives::{
    Block, BlockHeader, BlockHeight, BlockTime, BlockVersion, Hash256, Locktime, Nonce, OutPoint,
    Satoshi, Sequence, Transaction, TxHash, TxIn, TxOut, TxVersion, Witness,
};
use mantle_consensus::merkle::compute_merkle_root;
use mantle_consensus::tx_view::TxView;
use mantle_consensus::validation::BlockHeightExt;

use crate::chain_spec::ChainSpec;

/// Assembles a valid block around already-signed spending transactions:
/// the coinbase with its BIP34 height and BIP141 witness commitment, the
/// merkle root, and a nonce that meets the easy target.
pub struct BlockBuilder {
    height: BlockHeight,
    prev_hash: Hash256,
}

impl BlockBuilder {
    const RESERVED_VALUE: [u8; 32] = [0; 32];
    const COMMITMENT_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    const BLOCK_VERSION: i32 = 0x2000_0000;

    pub fn new(height: BlockHeight, prev_hash: Hash256) -> Self {
        Self { height, prev_hash }
    }

    pub fn build(&self, spends: Vec<Transaction>, fees: Satoshi) -> Block {
        let mut transactions = Vec::with_capacity(spends.len() + 1);
        transactions.push(Transaction {
            version: TxVersion::new(1),
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime: Locktime::new(0),
        });
        transactions.extend(spends);
        let commitment = Self::witness_commitment(&transactions);
        transactions[0] = self.coinbase(fees, commitment);

        let txids: Vec<Hash256> = transactions
            .iter()
            .map(|tx| tx.txid().expect("txid encoding"))
            .collect();
        let merkle_root = compute_merkle_root(&txids).expect("coinbase present");
        let header = BlockHeader::new(
            BlockVersion::new(Self::BLOCK_VERSION),
            self.prev_hash,
            merkle_root,
            BlockTime::new(ChainSpec::time_at(self.height.to_u32())),
            ChainSpec::BITS,
            Nonce::new(0),
        );
        Block {
            header: Self::mine(header),
            transactions,
        }
    }

    fn coinbase(&self, fees: Satoshi, commitment: Hash256) -> Transaction {
        let mut script_sig = Transaction::bip34_height_script(self.height);
        script_sig.extend_from_slice(b"mantle-synthetic");
        let mut commitment_script = Self::COMMITMENT_PREFIX.to_vec();
        commitment_script.extend_from_slice(commitment.as_bytes());
        let reward = self
            .height
            .subsidy()
            .checked_add(fees)
            .expect("reward fits");
        Transaction {
            version: TxVersion::new(1),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: u32::MAX,
                },
                script_sig: script_sig.into(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[&Self::RESERVED_VALUE]),
            }],
            outputs: vec![
                TxOut {
                    value: reward,
                    script_pubkey: vec![0x51].into(),
                },
                TxOut {
                    value: Satoshi::ZERO,
                    script_pubkey: commitment_script.into(),
                },
            ],
            locktime: Locktime::new(0),
        }
    }

    fn witness_commitment(transactions: &[Transaction]) -> Hash256 {
        let mut scratch = Vec::new();
        let mut wtxids = Vec::with_capacity(transactions.len());
        wtxids.push(Hash256::ZERO);
        for tx in &transactions[1..] {
            wtxids.push(tx.compute_wtxid(&mut scratch).expect("wtxid encoding"));
        }
        let root = compute_merkle_root(&wtxids).expect("coinbase slot present");
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(root.as_bytes());
        preimage[32..].copy_from_slice(&Self::RESERVED_VALUE);
        Hash256::hash(&preimage)
    }

    fn mine(mut header: BlockHeader) -> BlockHeader {
        let target = ChainSpec::BITS.to_target().expect("easy target decodes");
        for nonce in 0..=u32::MAX {
            header.set_nonce(Nonce::new(nonce));
            let mut hash = *header.hash().as_bytes();
            hash.reverse();
            if hash <= target {
                return header;
            }
        }
        unreachable!("the easy target accepts about half of all hashes")
    }
}
