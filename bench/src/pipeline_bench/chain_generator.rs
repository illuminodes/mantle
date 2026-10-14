use mantle::codec::Encode;
use mantle::primitives::{
    BlockHeight, Hash256, Locktime, OutPoint, Satoshi, Sequence, Transaction, TxHash, TxIn, TxOut,
    TxVersion, Witness,
};

use crate::block_builder::BlockBuilder;
use crate::chain_spec::ChainSpec;
use crate::coin_pool::CoinPool;
use crate::keyring::Keyring;
use crate::spendable_coin::{CoinKind, SpendableCoin};
use crate::tx_signer::TxSigner;

/// One spending transaction before signing, with the coins it spends and
/// the coins it will create once its txid is known.
struct PlannedTx {
    tx: Transaction,
    spends: Vec<SpendableCoin>,
    creates: Vec<SpendableCoin>,
}

/// Builds the blocks of a synthetic chain one after another.
pub struct ChainGenerator {
    spec: ChainSpec,
    keys: Keyring,
    pool: CoinPool,
    outputs_made: u64,
    prev_hash: Hash256,
}

impl ChainGenerator {
    const FEE: u64 = 1_000;

    pub fn new(spec: ChainSpec, prev_hash: Hash256) -> Self {
        Self {
            spec,
            keys: Keyring::new(),
            pool: CoinPool::new(spec.seed(), spec.recent_spend_percent),
            outputs_made: 0,
            prev_hash,
        }
    }

    pub fn block_bytes(&mut self, height: u32) -> Vec<u8> {
        let mut planned: Vec<PlannedTx> = (0..self.spec.txs_per_block)
            .map(|_| self.plan())
            .collect();
        self.sign(&mut planned);
        let fees = Satoshi::new(Self::FEE * planned.len() as u64);
        let mut spends = Vec::with_capacity(planned.len());
        for PlannedTx { tx, creates, .. } in planned {
            let txid = tx.txid().expect("txid encoding");
            for (vout, mut coin) in creates.into_iter().enumerate() {
                coin.outpoint = OutPoint {
                    txid,
                    vout: u32::try_from(vout).expect("vout fits u32"),
                };
                self.pool.add(coin);
            }
            spends.push(tx);
        }
        self.pool.end_block();
        let block = BlockBuilder::new(BlockHeight::new(height), self.prev_hash).build(spends, fees);
        self.prev_hash = block.header.hash();
        let mut bytes = Vec::new();
        block.encode(&mut bytes).expect("encode into a Vec");
        bytes
    }

    fn plan(&mut self) -> PlannedTx {
        let spends = self.pool.take(self.spec.inputs_per_tx);
        let total: u64 = spends.iter().map(|c| c.value.to_u64()).sum();
        let spendable = total.checked_sub(Self::FEE).expect("inputs cover the fee");
        let count = self.spec.outputs_per_tx as u64;
        let creates: Vec<SpendableCoin> = (0..count)
            .map(|i| {
                self.outputs_made += 1;
                SpendableCoin {
                    outpoint: OutPoint {
                        txid: Hash256::ZERO,
                        vout: 0,
                    },
                    value: Satoshi::new(spendable / count + if i == 0 { spendable % count } else { 0 }),
                    key: usize::try_from(self.outputs_made).expect("fits usize") % Keyring::SIZE,
                    kind: CoinKind::pick(self.outputs_made, self.spec.segwit_percent),
                }
            })
            .collect();
        let tx = Transaction {
            version: TxVersion::new(2),
            inputs: spends
                .iter()
                .map(|c| TxIn {
                    previous_output: c.outpoint,
                    script_sig: Vec::<u8>::new().into(),
                    sequence: Sequence::MAX,
                    witness: Witness::empty(),
                })
                .collect(),
            outputs: creates
                .iter()
                .map(|c| TxOut {
                    value: c.value,
                    script_pubkey: c.script_pubkey(&self.keys).into(),
                })
                .collect(),
            locktime: Locktime::new(0),
        };
        PlannedTx {
            tx,
            spends,
            creates,
        }
    }

    fn sign(&self, planned: &mut [PlannedTx]) {
        let signer = TxSigner::new(&self.keys);
        let threads = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        let chunk = planned.len().div_ceil(threads).max(1);
        std::thread::scope(|scope| {
            for part in planned.chunks_mut(chunk) {
                let signer = &signer;
                scope.spawn(move || {
                    for p in part {
                        signer.sign(&mut p.tx, &p.spends);
                    }
                });
            }
        });
    }
}
