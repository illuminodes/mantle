use mantle::collections::{BuildPrehashedHasher, PrehashedSet};
use mantle::primitives::{Block, BlockHeight, Hash256, OutPoint, TxHash};
use mantle_consensus::chain_view::NewCoin;
use mantle_consensus::error::ValidationError;
use mantle_consensus::validation::Bip30;

/// What a block needs from the UTXO set, worked out from the block alone:
/// its txids, the outpoints it spends from earlier blocks, the outpoints it
/// creates and spends itself, and the BIP30 probes. None of it depends on
/// chain state, so it can be computed for many blocks ahead of connecting.
#[derive(Default)]
pub struct BlockInputs {
    pub txids: Vec<Hash256>,
    pub external: Vec<OutPoint>,
    pub internal: Vec<OutPoint>,
    pub bip30: Vec<OutPoint>,
    spent_set: PrehashedSet<OutPoint>,
    hash_scratch: Vec<u8>,
}

impl BlockInputs {
    #[must_use]
    pub fn new() -> Self {
        Self {
            spent_set: PrehashedSet::with_hasher(BuildPrehashedHasher),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn of(block: &Block, height: BlockHeight) -> Self {
        let mut inputs = Self::new();
        inputs.collect(block, height);
        inputs
    }

    pub fn collect(&mut self, block: &Block, height: BlockHeight) {
        self.txids.clear();
        self.external.clear();
        self.internal.clear();
        self.bip30.clear();
        self.spent_set.clear();

        for tx in block.transactions.iter().skip(1) {
            self.spent_set
                .extend(tx.inputs.iter().map(|input| input.previous_output));
        }
        let mut created: PrehashedSet<OutPoint> = PrehashedSet::with_hasher(BuildPrehashedHasher);
        for tx in &block.transactions {
            let Ok(txid) = tx.txid_into(&mut self.hash_scratch) else {
                continue;
            };
            self.txids.push(txid);
            for vout in 0..tx.outputs.len() {
                let Ok(vout) = u32::try_from(vout) else {
                    continue;
                };
                let op = OutPoint { txid, vout };
                if self.spent_set.contains(&op) {
                    created.insert(op);
                }
            }
        }
        for tx in block.transactions.iter().skip(1) {
            for input in &tx.inputs {
                if created.contains(&input.previous_output) {
                    self.internal.push(input.previous_output);
                } else {
                    self.external.push(input.previous_output);
                }
            }
        }

        self.spent_set.clear();
        self.spent_set.extend(self.external.iter().copied());
        if self.txids.len() == block.transactions.len() {
            let bip30 = Bip30::new(height, &block.header);
            for op in bip30.probes(block, &self.txids) {
                if !created.contains(&op) && !self.spent_set.contains(&op) {
                    self.bip30.push(op);
                }
            }
        }
    }

    /// Every outpoint whose coin has to come from the UTXO set: the external
    /// spends followed by the BIP30 probes.
    pub fn lookups(&self) -> impl Iterator<Item = &OutPoint> {
        self.external.iter().chain(&self.bip30)
    }

    #[must_use]
    pub fn txids_for(&self, block: &Block) -> Option<&[Hash256]> {
        (self.txids.len() == block.transactions.len()).then_some(self.txids.as_slice())
    }

    /// The block's UTXO delta as storage takes it: every output created and
    /// every non-coinbase input spent, the same lists `connect_block` returns.
    ///
    /// # Errors
    /// `MalformedTransaction` when a txid could not be computed or a vout
    /// does not fit 32 bits.
    pub fn delta<'b>(
        &self,
        block: &'b Block,
        height: BlockHeight,
    ) -> Result<(Vec<NewCoin<'b>>, Vec<OutPoint>), ValidationError> {
        let txids = self
            .txids_for(block)
            .ok_or(ValidationError::MalformedTransaction { tx_index: self.txids.len() })?;
        let mut created = Vec::new();
        let mut spent = Vec::new();
        for (tx_index, (tx, &txid)) in block.transactions.iter().zip(txids).enumerate() {
            if tx_index > 0 {
                spent.extend(tx.inputs.iter().map(|input| input.previous_output));
            }
            for (vout, output) in tx.outputs.iter().enumerate() {
                let vout = u32::try_from(vout)
                    .map_err(|_| ValidationError::MalformedTransaction { tx_index })?;
                created.push(NewCoin {
                    outpoint: OutPoint { txid, vout },
                    value: output.value,
                    script_pubkey: output.script_pubkey.as_slice(),
                    coinbase: tx_index == 0,
                    height,
                });
            }
        }
        Ok((created, spent))
    }

    #[must_use]
    pub fn input_count(&self) -> usize {
        self.external.len() + self.internal.len()
    }
}
