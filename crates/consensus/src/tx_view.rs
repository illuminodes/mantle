//! Abstraction over `Transaction` (owned) and `TransactionRef<'_>` (borrowed).
//!
//! The validation and script subsystems were originally written against
//! `&Transaction`. To let the replay path drive validation directly from a
//! wire-buffer-backed `BlockRef` without materialising owned txs, every
//! caller below `connect_block` works through this trait instead.
//!
//! Two trait objects model the access shapes:
//! - [`TxView`] — whole transaction: header fields + iteration over inputs and
//!   outputs + per-input witness lookup.
//! - [`InputView`] / [`OutputView`] — per-element field access. These return
//!   borrowed slices for scripts so callers never copy on read.
//!
//! `WitnessView` covers the witness stack with a pair of methods (`is_empty`
//! and `iter`) that match what the BIP141/142 verifier actually uses; the
//! `to_vec` shim keeps existing call sites compiling unchanged.

use mantle::primitives::{
    Block, BlockHeader, BlockRef, Hash256, Locktime, OutPoint, Satoshi, Sequence, Transaction,
    TransactionRef, TxVersion, Witness, WitnessRef,
};

/// Whole-block view. Implemented by both [`Block`] (owned) and
/// [`BlockRef`] (borrowed). Lets `connect_block` iterate transactions
/// without caring whether the block came off the wire as owned or zero-copy.
///
/// The associated `Tx` type is the per-transaction view: `Transaction` for
/// owned blocks, `TransactionRef<'a>` for borrowed.
pub trait BlockView {
    type Tx<'a>: TxView + Sync
    where
        Self: 'a;
    type TxIter<'a>: Iterator<Item = &'a Self::Tx<'a>>
    where
        Self: 'a;

    /// The block header.
    fn header(&self) -> &BlockHeader;
    /// Number of transactions (≥ 1 for any non-empty block).
    fn tx_count(&self) -> usize;
    /// Borrow transaction at index `i`. Panics if `i >= tx_count()`.
    fn tx(&self, i: usize) -> &Self::Tx<'_>;
    /// Iterate transactions in order.
    fn txs(&self) -> Self::TxIter<'_>;
}

impl BlockView for Block {
    type Tx<'a> = Transaction;
    type TxIter<'a> = std::slice::Iter<'a, Transaction>;

    fn header(&self) -> &BlockHeader {
        &self.header
    }
    fn tx_count(&self) -> usize {
        self.transactions.len()
    }
    fn tx(&self, i: usize) -> &Self::Tx<'_> {
        &self.transactions[i]
    }
    fn txs(&self) -> Self::TxIter<'_> {
        self.transactions.iter()
    }
}

impl<'wire, 'arena> BlockView for BlockRef<'wire, 'arena>
where
    'wire: 'arena,
{
    type Tx<'a>
        = TransactionRef<'wire, 'arena>
    where
        Self: 'a;
    type TxIter<'a>
        = std::slice::Iter<'a, TransactionRef<'wire, 'arena>>
    where
        Self: 'a;

    fn header(&self) -> &BlockHeader {
        &self.header
    }
    fn tx_count(&self) -> usize {
        self.txs.len()
    }
    fn tx(&self, i: usize) -> &Self::Tx<'_> {
        &self.txs[i]
    }
    fn txs(&self) -> Self::TxIter<'_> {
        self.txs.iter()
    }
}

/// Whole-transaction view. Implemented by both [`Transaction`] (owned) and
/// [`TransactionRef`] (borrowed into a wire buffer).
pub trait TxView {
    /// Iterator type yielded by [`Self::inputs`].
    type InputIter<'a>: Iterator<Item = Self::Input<'a>>
    where
        Self: 'a;
    /// Iterator type yielded by [`Self::outputs`].
    type OutputIter<'a>: Iterator<Item = Self::Output<'a>>
    where
        Self: 'a;
    /// Per-input view returned by [`Self::input`] / [`Self::inputs`].
    type Input<'a>: InputView
    where
        Self: 'a;
    /// Per-output view returned by [`Self::output`] / [`Self::outputs`].
    type Output<'a>: OutputView<'a>
    where
        Self: 'a;

    /// `nVersion` (4 LE bytes on the wire).
    fn version(&self) -> TxVersion;
    /// `nLockTime` (4 LE bytes on the wire).
    fn locktime(&self) -> Locktime;
    /// Number of inputs.
    fn input_count(&self) -> usize;
    /// Number of outputs.
    fn output_count(&self) -> usize;

    /// Borrow input `n_in`. Panics if `n_in >= input_count()`.
    fn input(&self, n_in: usize) -> Self::Input<'_>;
    /// Borrow output `n_out`. Panics if `n_out >= output_count()`.
    fn output(&self, n_out: usize) -> Self::Output<'_>;

    /// Iterate all inputs in order.
    fn inputs(&self) -> Self::InputIter<'_>;
    /// Iterate all outputs in order.
    fn outputs(&self) -> Self::OutputIter<'_>;

    /// Compute the txid (`SHA256d` of non-witness serialisation). Provided
    /// because the trait needs it for sighash computation; implementations
    /// dispatch to the existing `TxHash::txid_into` once the buffer is set up.
    ///
    /// # Errors
    /// Propagates encoding errors (none in practice — encoding into Vec<u8>
    /// cannot fail).
    fn compute_txid(&self, scratch: &mut Vec<u8>) -> std::io::Result<Hash256>;

    /// Compute the wtxid (`SHA256d` of the full BIP144 serialisation,
    /// including witness data). Equals the txid for non-segwit transactions.
    ///
    /// # Errors
    /// Propagates encoding errors (none in practice).
    fn compute_wtxid(&self, scratch: &mut Vec<u8>) -> std::io::Result<Hash256>;

    /// Materialise into an owned `Transaction`.
    ///
    /// Required by the legacy sighash path, which builds a *modified* tx
    /// (rewrites scriptSigs, masks outputs, etc.) and then re-encodes it.
    /// For owned txs this is just `Clone`; for refs it round-trips through
    /// the wire buffer.
    ///
    /// # Errors
    /// Propagates decode errors from the borrowed-tx path.
    fn to_owned_tx(&self) -> std::io::Result<Transaction>;
}

/// Per-input view: outpoint + scriptSig + sequence + witness.
pub trait InputView {
    type Witness: WitnessView;

    fn previous_output(&self) -> OutPoint;
    fn script_sig(&self) -> &[u8];
    fn sequence(&self) -> Sequence;
    fn witness(&self) -> Self::Witness;
}

/// Per-output view: value + scriptPubKey.
///
/// The lifetime `'data` is the lifetime of the backing data (wire buffer or
/// owned transaction), not the lifetime of the view itself. This lets
/// `script_pubkey()` return a borrow that outlives the transient output-view
/// iterator item — critical for zero-copy `NewCoin` construction.
pub trait OutputView<'data> {
    fn value(&self) -> Satoshi;
    fn script_pubkey(&self) -> &'data [u8];
}

/// Witness-stack view. Borrowed and owned witnesses alike expose the same
/// minimal surface used by the BIP141/142/143 verifier paths.
pub trait WitnessView {
    /// `true` if the witness has no items (legacy / non-segwit input).
    fn is_empty(&self) -> bool;
    /// Materialise items as `Vec<Vec<u8>>` — the shape every existing call
    /// site already uses for the segwit dispatch.
    fn to_vec(&self) -> Vec<Vec<u8>>;
}

// ── Owned: Transaction ───────────────────────────────────────────────────────

/// Per-input borrow over an owned [`Transaction`].
pub struct OwnedInputView<'a> {
    inner: &'a mantle::primitives::TxIn,
}

impl<'a> InputView for OwnedInputView<'a> {
    type Witness = OwnedWitnessView<'a>;

    fn previous_output(&self) -> OutPoint {
        self.inner.previous_output
    }
    fn script_sig(&self) -> &[u8] {
        self.inner.script_sig.as_slice()
    }
    fn sequence(&self) -> Sequence {
        self.inner.sequence
    }
    fn witness(&self) -> Self::Witness {
        OwnedWitnessView {
            inner: &self.inner.witness,
        }
    }
}

/// Per-output borrow over an owned [`Transaction`].
pub struct OwnedOutputView<'a> {
    inner: &'a mantle::primitives::TxOut,
}

impl<'a> OutputView<'a> for OwnedOutputView<'a> {
    fn value(&self) -> Satoshi {
        self.inner.value
    }
    fn script_pubkey(&self) -> &'a [u8] {
        self.inner.script_pubkey.as_slice()
    }
}

/// Witness borrow over an owned [`Witness`].
pub struct OwnedWitnessView<'a> {
    inner: &'a Witness,
}

impl WitnessView for OwnedWitnessView<'_> {
    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    fn to_vec(&self) -> Vec<Vec<u8>> {
        self.inner.to_vec()
    }
}

impl TxView for Transaction {
    type Input<'a> = OwnedInputView<'a>;
    type Output<'a> = OwnedOutputView<'a>;
    type InputIter<'a> = OwnedInputIter<'a>;
    type OutputIter<'a> = OwnedOutputIter<'a>;

    fn version(&self) -> TxVersion {
        self.version
    }
    fn locktime(&self) -> Locktime {
        self.locktime
    }
    fn input_count(&self) -> usize {
        self.inputs.len()
    }
    fn output_count(&self) -> usize {
        self.outputs.len()
    }
    fn input(&self, n_in: usize) -> Self::Input<'_> {
        OwnedInputView {
            inner: &self.inputs[n_in],
        }
    }
    fn output(&self, n_out: usize) -> Self::Output<'_> {
        OwnedOutputView {
            inner: &self.outputs[n_out],
        }
    }
    fn inputs(&self) -> Self::InputIter<'_> {
        OwnedInputIter {
            iter: self.inputs.iter(),
        }
    }
    fn outputs(&self) -> Self::OutputIter<'_> {
        OwnedOutputIter {
            iter: self.outputs.iter(),
        }
    }

    fn compute_txid(&self, scratch: &mut Vec<u8>) -> std::io::Result<Hash256> {
        use mantle::primitives::TxHash;
        Ok(TxHash::txid_into(self, scratch)?)
    }

    fn compute_wtxid(&self, scratch: &mut Vec<u8>) -> std::io::Result<Hash256> {
        use mantle::codec::Encode;
        use mantle::hash::ByteSliceExt;
        scratch.clear();
        self.encode(scratch)?;
        Ok(scratch.sha256d())
    }

    fn to_owned_tx(&self) -> std::io::Result<Transaction> {
        Ok(self.clone())
    }
}

pub struct OwnedInputIter<'a> {
    iter: std::slice::Iter<'a, mantle::primitives::TxIn>,
}
impl<'a> Iterator for OwnedInputIter<'a> {
    type Item = OwnedInputView<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|inner| OwnedInputView { inner })
    }
}

pub struct OwnedOutputIter<'a> {
    iter: std::slice::Iter<'a, mantle::primitives::TxOut>,
}
impl<'a> Iterator for OwnedOutputIter<'a> {
    type Item = OwnedOutputView<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|inner| OwnedOutputView { inner })
    }
}

// ── Borrowed: TransactionRef ─────────────────────────────────────────────────

/// Per-input borrow over a [`TransactionRef`].
pub struct RefInputView<'a> {
    inner: mantle::primitives::TxInRef<'a>,
    witness: WitnessRef<'a>,
}

impl<'a> InputView for RefInputView<'a> {
    type Witness = RefWitnessView<'a>;

    fn previous_output(&self) -> OutPoint {
        self.inner.previous_output
    }
    fn script_sig(&self) -> &[u8] {
        self.inner.script_sig
    }
    fn sequence(&self) -> Sequence {
        self.inner.sequence
    }
    fn witness(&self) -> Self::Witness {
        RefWitnessView {
            inner: self.witness,
        }
    }
}

/// Per-output borrow over a [`TransactionRef`].
pub struct RefOutputView<'a> {
    inner: mantle::primitives::TxOutRef<'a>,
}

impl<'a, 'tx: 'a> OutputView<'a> for RefOutputView<'tx> {
    fn value(&self) -> Satoshi {
        self.inner.value
    }
    fn script_pubkey(&self) -> &'a [u8] {
        self.inner.script_pubkey
    }
}

/// Witness borrow over a [`WitnessRef`].
#[derive(Clone, Copy)]
pub struct RefWitnessView<'a> {
    inner: WitnessRef<'a>,
}

impl WitnessView for RefWitnessView<'_> {
    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    fn to_vec(&self) -> Vec<Vec<u8>> {
        self.inner.to_vec()
    }
}

impl<'wire, 'arena> TxView for TransactionRef<'wire, 'arena>
where
    'wire: 'arena,
{
    type Input<'a>
        = RefInputView<'wire>
    where
        Self: 'a;
    type Output<'a>
        = RefOutputView<'wire>
    where
        Self: 'a;
    type InputIter<'a>
        = RefInputIter<'wire>
    where
        Self: 'a;
    type OutputIter<'a>
        = RefOutputIter<'wire>
    where
        Self: 'a;

    fn version(&self) -> TxVersion {
        self.version
    }
    fn locktime(&self) -> Locktime {
        self.locktime
    }
    fn input_count(&self) -> usize {
        TransactionRef::input_count(self)
    }
    fn output_count(&self) -> usize {
        TransactionRef::output_count(self)
    }
    fn input(&self, n_in: usize) -> Self::Input<'_> {
        // Walk the inputs iterator to position `n_in`. O(n_in) per call but
        // this method is only used by the script verifier on the input
        // currently being verified, so the cost is amortised across the
        // sigops/script work.
        let mut iter = TransactionRef::inputs(self);
        for _ in 0..n_in {
            let _ = iter.next().expect("n_in < input_count");
        }
        let inner = iter
            .next()
            .expect("n_in < input_count")
            .expect("input decode must succeed for a validated block");
        RefInputView {
            inner,
            witness: self.witness(n_in),
        }
    }
    fn output(&self, n_out: usize) -> Self::Output<'_> {
        let mut iter = TransactionRef::outputs(self);
        for _ in 0..n_out {
            let _ = iter.next().expect("n_out < output_count");
        }
        let inner = iter
            .next()
            .expect("n_out < output_count")
            .expect("output decode must succeed for a validated block");
        RefOutputView { inner }
    }
    fn inputs(&self) -> Self::InputIter<'_> {
        RefInputIter {
            inner: self.inputs(),
            // Cursor walks the per-input witness layout one step per next(),
            // so total witness work is O(n) instead of O(n²).
            witnesses_cursor: if self.is_segwit {
                Some(self.witnesses_buf)
            } else {
                None
            },
        }
    }
    fn outputs(&self) -> Self::OutputIter<'_> {
        RefOutputIter {
            inner: self.outputs(),
        }
    }

    fn compute_txid(&self, scratch: &mut Vec<u8>) -> std::io::Result<Hash256> {
        // TransactionRef::txid_into ignores the scratch and hashes
        // non_witness_raw directly; we still take it for trait uniformity.
        use mantle::primitives::TxHash;
        Ok(TxHash::txid_into(self, scratch)?)
    }

    fn compute_wtxid(&self, _scratch: &mut Vec<u8>) -> std::io::Result<Hash256> {
        use mantle::hash::ByteSliceExt;
        Ok(self.raw.sha256d())
    }

    fn to_owned_tx(&self) -> std::io::Result<Transaction> {
        // Materialise structurally via the existing helper, then patch in
        // the per-input witnesses (TransactionRef::to_owned discards them).
        let mut owned = TransactionRef::to_owned(*self)?;
        if self.is_segwit {
            for (i, input) in owned.inputs.iter_mut().enumerate() {
                let w = self.witness(i);
                if !w.is_empty() {
                    let items: Vec<Vec<u8>> = w.to_vec();
                    let slices: Vec<&[u8]> = items.iter().map(Vec::as_slice).collect();
                    input.witness = Witness::from_slice(&slices);
                }
            }
        }
        Ok(owned)
    }
}

pub struct RefInputIter<'a> {
    inner: mantle::primitives::TxInRefIter<'a>,
    /// `Some` carries the remaining per-input witness bytes for a segwit tx.
    /// Each `next()` pops one witness off the front in O(1) amortised, so a
    /// full input pass is O(n) instead of the O(n²) cost of indexing each
    /// input's witness independently.
    witnesses_cursor: Option<&'a [u8]>,
}

impl<'a> Iterator for RefInputIter<'a> {
    type Item = RefInputView<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let inner = self.inner.next()?.ok()?;
        let witness = match self.witnesses_cursor {
            Some(buf) => {
                if let Ok((w, rest)) = WitnessRef::pop_from(buf) {
                    self.witnesses_cursor = Some(rest);
                    w
                } else {
                    self.witnesses_cursor = None;
                    WitnessRef::EMPTY
                }
            }
            None => WitnessRef::EMPTY,
        };
        Some(RefInputView { inner, witness })
    }
}

pub struct RefOutputIter<'a> {
    inner: mantle::primitives::TxOutRefIter<'a>,
}
impl<'a> Iterator for RefOutputIter<'a> {
    type Item = RefOutputView<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let inner = self.inner.next()?.ok()?;
        Some(RefOutputView { inner })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantle::codec::Encode;
    use mantle::primitives::{Hash256, Locktime, Sequence, TxIn, TxOut, TxVersion, Witness};

    fn make_segwit_tx() -> Transaction {
        Transaction {
            version: TxVersion::new(2),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([0x42; 32]),
                    vout: 7,
                },
                script_sig: Vec::<u8>::new().into(),
                sequence: Sequence::new(0xffff_fffe),
                witness: Witness::from_slice(&[
                    &[0xab, 0xcd][..],
                    &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66][..],
                ]),
            }],
            outputs: vec![TxOut {
                value: Satoshi::new(123_456),
                script_pubkey: vec![0x76, 0xa9, 0x14, 0xff].into(),
            }],
            locktime: Locktime::new(100_000),
        }
    }

    fn encode_tx(tx: &Transaction) -> Vec<u8> {
        let mut buf = Vec::new();
        tx.encode(&mut buf).expect("encode");
        buf
    }

    #[test]
    fn owned_and_ref_views_agree_on_segwit_tx() {
        let tx = make_segwit_tx();
        let bytes = encode_tx(&tx);
        let mut arena = Vec::new();
        let (tx_ref, _) = mantle::primitives::transaction_ref_with_arena(&bytes, &mut arena)
            .expect("arena decode");

        // Header fields.
        assert_eq!(TxView::version(&tx), TxView::version(&tx_ref));
        assert_eq!(TxView::locktime(&tx), TxView::locktime(&tx_ref));
        assert_eq!(TxView::input_count(&tx), TxView::input_count(&tx_ref));
        assert_eq!(TxView::output_count(&tx), TxView::output_count(&tx_ref));

        // Per-input fields incl. witness.
        let owned_in = TxView::input(&tx, 0);
        let ref_in = TxView::input(&tx_ref, 0);
        assert_eq!(owned_in.previous_output(), ref_in.previous_output());
        assert_eq!(owned_in.script_sig(), ref_in.script_sig());
        assert_eq!(owned_in.sequence(), ref_in.sequence());
        assert_eq!(owned_in.witness().is_empty(), ref_in.witness().is_empty());
        assert_eq!(owned_in.witness().to_vec(), ref_in.witness().to_vec());

        // Per-output fields.
        let owned_out = TxView::output(&tx, 0);
        let ref_out = TxView::output(&tx_ref, 0);
        assert_eq!(owned_out.value(), ref_out.value());
        assert_eq!(owned_out.script_pubkey(), ref_out.script_pubkey());

        // txid agrees through the trait.
        let mut s1 = Vec::new();
        let mut s2 = Vec::new();
        let owned_txid = TxView::compute_txid(&tx, &mut s1).expect("owned txid");
        let ref_txid = TxView::compute_txid(&tx_ref, &mut s2).expect("ref txid");
        assert_eq!(owned_txid, ref_txid);

        // to_owned_tx round-trips and preserves witnesses (which the bare
        // TransactionRef::to_owned drops).
        let materialised = TxView::to_owned_tx(&tx_ref).expect("to_owned_tx");
        assert_eq!(materialised, tx);
    }

    #[test]
    fn ref_input_iter_iterates_segwit_inputs() {
        // Exercise RefInputIter::next by iterating all inputs through the
        // TxView::inputs() method on a TransactionRef.
        let tx = make_segwit_tx();
        let bytes = encode_tx(&tx);
        let mut arena = Vec::new();
        let (tx_ref, _) = mantle::primitives::transaction_ref_with_arena(&bytes, &mut arena)
            .expect("arena decode");

        let mut count = 0;
        for input in TxView::inputs(&tx_ref) {
            assert_eq!(
                input.previous_output().txid,
                Hash256::from_bytes([0x42; 32])
            );
            assert_eq!(input.previous_output().vout, 7);
            assert_eq!(input.sequence(), Sequence::new(0xffff_fffe));
            // Witness should be populated from the cursor.
            assert!(!input.witness().is_empty());
            let wit_items = input.witness().to_vec();
            assert_eq!(wit_items.len(), 2);
            assert_eq!(wit_items[0], &[0xab, 0xcd]);
            assert_eq!(wit_items[1], &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
            count += 1;
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn ref_input_iter_multi_input_segwit() {
        // Multi-input segwit tx: exercises the witnesses_cursor advancing
        // through multiple inputs.
        let tx = Transaction {
            version: TxVersion::new(2),
            inputs: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: Hash256::from_bytes([0x11; 32]),
                        vout: 0,
                    },
                    script_sig: Vec::<u8>::new().into(),
                    sequence: Sequence::new(0xffff_ffff),
                    witness: Witness::from_slice(&[&[0xaa][..], &[0xbb, 0xcc][..]]),
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: Hash256::from_bytes([0x22; 32]),
                        vout: 1,
                    },
                    script_sig: Vec::<u8>::new().into(),
                    sequence: Sequence::new(0xffff_fffe),
                    witness: Witness::from_slice(&[&[0xdd, 0xee, 0xff][..]]),
                },
            ],
            outputs: vec![TxOut {
                value: Satoshi::new(50_000),
                script_pubkey: vec![0x6a].into(),
            }],
            locktime: Locktime::new(0),
        };

        let bytes = encode_tx(&tx);
        let mut arena = Vec::new();
        let (tx_ref, _) = mantle::primitives::transaction_ref_with_arena(&bytes, &mut arena)
            .expect("arena decode");

        let inputs: Vec<_> = TxView::inputs(&tx_ref).collect();
        assert_eq!(inputs.len(), 2);

        // First input's witness.
        let w0 = inputs[0].witness().to_vec();
        assert_eq!(w0.len(), 2);
        assert_eq!(w0[0], &[0xaa]);
        assert_eq!(w0[1], &[0xbb, 0xcc]);

        // Second input's witness.
        let w1 = inputs[1].witness().to_vec();
        assert_eq!(w1.len(), 1);
        assert_eq!(w1[0], &[0xdd, 0xee, 0xff]);
    }

    #[test]
    fn ref_input_iter_non_segwit_has_empty_witness() {
        // Non-segwit tx: RefInputIter should produce empty witnesses.
        let tx = Transaction {
            version: TxVersion::new(1),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([0x33; 32]),
                    vout: 0,
                },
                script_sig: vec![0x51u8].into(), // OP_1
                sequence: Sequence::new(0xffff_ffff),
                witness: Witness::empty(),
            }],
            outputs: vec![TxOut {
                value: Satoshi::new(10_000),
                script_pubkey: vec![0x6a].into(),
            }],
            locktime: Locktime::new(0),
        };

        let bytes = encode_tx(&tx);
        let mut arena = Vec::new();
        let (tx_ref, _) = mantle::primitives::transaction_ref_with_arena(&bytes, &mut arena)
            .expect("arena decode");

        let inputs: Vec<_> = TxView::inputs(&tx_ref).collect();
        assert_eq!(inputs.len(), 1);
        assert!(inputs[0].witness().is_empty());
    }
}
