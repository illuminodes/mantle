use crate::codec::{DecodeRef, Encode, Error, VarInt};
use crate::difficulty::{Locktime, TxVersion};
use crate::hash::{ByteSliceExt, Hash256};
use crate::script::Witness;

use super::hash::TxHash;
use super::input::{TxIn, TxInRef};
use super::output::{TxOut, TxOutRef};
use super::owned::Transaction;

// ── TxInRefIter ──────────────────────────────────────────────────────────────

/// Lazy iterator over zero-copy `TxInRef` views.
#[derive(Debug, Clone)]
pub struct TxInRefIter<'a> {
    buf: &'a [u8],
    remaining: usize,
}

impl<'a> Iterator for TxInRefIter<'a> {
    type Item = Result<TxInRef<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        match TxInRef::decode_ref(self.buf) {
            Ok((item, rest)) => {
                self.buf = rest;
                self.remaining -= 1;
                Some(Ok(item))
            }
            Err(e) => {
                self.remaining = 0;
                Some(Err(e))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

// ── TxOutRefIter ─────────────────────────────────────────────────────────────

/// Lazy iterator over zero-copy `TxOutRef` views.
#[derive(Debug, Clone)]
pub struct TxOutRefIter<'a> {
    buf: &'a [u8],
    remaining: usize,
}

impl<'a> Iterator for TxOutRefIter<'a> {
    type Item = Result<TxOutRef<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        match TxOutRef::decode_ref(self.buf) {
            Ok((item, rest)) => {
                self.buf = rest;
                self.remaining -= 1;
                Some(Ok(item))
            }
            Err(e) => {
                self.remaining = 0;
                Some(Err(e))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

// ── TransactionRef ───────────────────────────────────────────────────────────

/// Zero-copy borrowed view of a `Transaction`.
///
/// Inputs and outputs are not materialised into `Vec`s — they are decoded
/// lazily from slices of the original buffer. Use [`inputs`](Self::inputs) and
/// [`outputs`](Self::outputs) to iterate; use [`to_owned`](Self::to_owned) to
/// materialise a full `Transaction` when needed.
///
/// `raw` holds the complete wire bytes (BIP144 form for segwit transactions).
/// `non_witness_raw` holds the non-witness serialisation used for txid. For
/// legacy transactions it is the same slice as `raw`. For segwit transactions
/// produced via [`Self::decode_into_arena`] it points at a contiguous span in
/// the caller-supplied arena. The bare [`Self::decode_ref`] entrypoint sets
/// `non_witness_raw == raw` for segwit, which is **not** a valid txid preimage
/// — those callers must either go via `decode_into_arena` or fall back to
/// [`Self::to_owned`]+`Transaction::txid_into`.
#[derive(Debug, Clone, Copy)]
pub struct TransactionRef<'wire, 'arena>
where
    'wire: 'arena,
{
    pub version: TxVersion,
    pub locktime: Locktime,
    pub raw: &'wire [u8],
    pub non_witness_raw: &'arena [u8],
    pub is_segwit: bool,
    input_count: usize,
    inputs_buf: &'wire [u8],
    output_count: usize,
    outputs_buf: &'wire [u8],
    pub witnesses_buf: &'wire [u8],
}

impl<'wire, 'arena> TransactionRef<'wire, 'arena>
where
    'wire: 'arena,
{
    /// Lazily iterate over inputs. Each call returns a fresh iterator.
    #[must_use]
    pub fn inputs(&self) -> TxInRefIter<'wire> {
        TxInRefIter {
            buf: self.inputs_buf,
            remaining: self.input_count,
        }
    }

    /// Lazily iterate over outputs. Each call returns a fresh iterator.
    #[must_use]
    pub fn outputs(&self) -> TxOutRefIter<'wire> {
        TxOutRefIter {
            buf: self.outputs_buf,
            remaining: self.output_count,
        }
    }

    /// Number of inputs.
    #[must_use]
    pub fn input_count(&self) -> usize {
        self.input_count
    }

    /// Number of outputs.
    #[must_use]
    pub fn output_count(&self) -> usize {
        self.output_count
    }

    /// Serialised byte length — O(1), reads directly from the raw wire span.
    #[inline]
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.raw.len()
    }

    /// Materialise into an owned `Transaction`, allocating.
    ///
    /// # Errors
    /// Returns an error if any input or output is malformed.
    pub fn to_owned(self) -> Result<Transaction, Error> {
        let inputs = self
            .inputs()
            .map(|r| {
                r.map(|i| TxIn {
                    previous_output: i.previous_output,
                    script_sig: i.script_sig.to_vec().into(),
                    sequence: i.sequence,
                    witness: Witness::empty(),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let outputs = self
            .outputs()
            .map(|r| {
                r.map(|o| TxOut {
                    value: o.value,
                    script_pubkey: o.script_pubkey.to_vec().into(),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(Transaction {
            version: self.version,
            inputs,
            outputs,
            locktime: self.locktime,
        })
    }

    /// Borrow the witness stack for input `n_in` without allocating.
    ///
    /// Returns an empty [`WitnessRef`] for legacy transactions or for an
    /// out-of-range index. The returned ref borrows from the wire buffer; no
    /// witness items are decoded until iterated.
    #[must_use]
    pub fn witness(&self, n_in: usize) -> WitnessRef<'wire> {
        if !self.is_segwit || n_in >= self.input_count {
            return WitnessRef::EMPTY;
        }
        // Re-walk witnesses_buf to the requested input. Witnesses are
        // variable-length so the per-input boundary is computed lazily.
        let mut buf = self.witnesses_buf;
        for _ in 0..n_in {
            buf = match WitnessRef::skip_one(buf) {
                Ok(r) => r,
                Err(_) => return WitnessRef::EMPTY,
            };
        }
        WitnessRef::decode_at(buf).unwrap_or(WitnessRef::EMPTY)
    }
}

/// Decode `TransactionRef` from `wire`, materialising a correct
/// `non_witness_raw` slice for segwit transactions into the caller-supplied
/// arena.
///
/// For legacy transactions this is identical to [`TransactionRef::decode_ref`]
/// — `non_witness_raw` aliases the wire bytes and the arena is left untouched.
/// For segwit transactions the function appends `version || inputs_region ||
/// outputs_region || locktime` to `arena` and points `non_witness_raw` at
/// that fresh span. The arena lifetime drives `'a`, so the returned ref
/// remains valid as long as the arena (and the wire buffer) live.
///
/// `arena` may be reused across calls — capacity is preserved between blocks
/// so amortised allocation cost is minimal.
///
/// # Errors
/// Same as [`TransactionRef::decode_ref`].
pub fn transaction_ref_with_arena<'a>(
    wire: &'a [u8],
    arena: &'a mut Vec<u8>,
) -> Result<(TransactionRef<'a, 'a>, &'a [u8]), Error> {
    let (mut tx, rest) = TransactionRef::decode_ref(wire)?;
    if !tx.is_segwit {
        // Already correct — `non_witness_raw == raw` aliases the wire bytes.
        return Ok((tx, rest));
    }

    // Layout in `wire`: version(4) | 0x00 0x01 | inputs_count VarInt | inputs |
    // outputs_count VarInt | outputs | witnesses | locktime(4).
    //
    // The non-witness preimage is: version(4) | inputs_count VarInt | inputs |
    // outputs_count VarInt | outputs | locktime(4).
    let raw = tx.raw;
    let raw_start = raw.as_ptr() as usize;
    let inputs_buf_start = tx.inputs_buf.as_ptr() as usize;
    let outputs_buf_start = tx.outputs_buf.as_ptr() as usize;

    // Boundaries inside `raw`, relative to its start.
    // Inputs region begins at the inputs_count VarInt; we recover that by
    // walking back from inputs_buf_start through the VarInt bytes. Easier:
    // the inputs_count VarInt is right after the marker+flag, which sits
    // right after the version (4 bytes).
    // version | marker(1) | flag(1) | inputs_count VarInt | inputs ...
    let inputs_region_start = 4 + 2; // skip version + marker + flag
    debug_assert!(inputs_region_start <= raw.len());

    // The end of the outputs region equals where the witnesses begin.
    let witnesses_start_offset = if tx.witnesses_buf.is_empty() {
        // Edge case: segwit flagged but no witnesses (malformed-but-decoded
        // path). Treat as ending right before locktime.
        raw.len() - 4
    } else {
        tx.witnesses_buf.as_ptr() as usize - raw_start
    };

    let arena_start = arena.len();
    arena.reserve(4 + (witnesses_start_offset - inputs_region_start) + 4);
    // version (4 bytes)
    arena.extend_from_slice(&raw[..4]);
    // inputs_count VarInt + inputs + outputs_count VarInt + outputs
    arena.extend_from_slice(&raw[inputs_region_start..witnesses_start_offset]);
    // locktime (4 bytes) — the last 4 bytes of `raw`.
    arena.extend_from_slice(&raw[raw.len() - 4..]);

    debug_assert!(inputs_buf_start >= raw_start);
    debug_assert!(outputs_buf_start >= raw_start);

    tx.non_witness_raw = &arena[arena_start..];
    Ok((tx, rest))
}

// ── WitnessRef ───────────────────────────────────────────────────────────────

/// Borrowed witness stack for one transaction input. Wraps a slice of the
/// BIP144 witness wire bytes (`VarInt(count) || VarInt(len)+bytes…`) and
/// decodes items lazily.
#[derive(Debug, Clone, Copy)]
pub struct WitnessRef<'a> {
    item_count: usize,
    /// Slice covering only the items (after the leading count `VarInt`).
    items_buf: &'a [u8],
}

impl<'a> WitnessRef<'a> {
    /// An empty witness stack.
    pub const EMPTY: WitnessRef<'static> = WitnessRef {
        item_count: 0,
        items_buf: &[],
    };

    /// Decode the witness at the start of `buf`.
    ///
    /// # Errors
    /// Returns an error if the count or any item length is truncated.
    pub fn decode_at(buf: &'a [u8]) -> Result<Self, Error> {
        let (vi, mut rest) = VarInt::decode_ref(buf)?;
        let count = vi.to_usize()?;
        let items_start = rest;
        for _ in 0..count {
            let (vi, r2) = VarInt::decode_ref(rest)?;
            let len = vi.to_usize()?;
            if r2.len() < len {
                return Err(Error::UnexpectedEof);
            }
            rest = &r2[len..];
        }
        let items_buf = &items_start[..items_start.len() - rest.len()];
        Ok(Self {
            item_count: count,
            items_buf,
        })
    }

    /// Decode one witness at the start of `buf` and return both the decoded
    /// `WitnessRef` and the trailing slice — i.e. `(this_witness, rest)`.
    ///
    /// Designed for streaming the per-input witness layout of a segwit tx:
    /// after each call, pass `rest` back in to read the next input's witness.
    /// One pass is O(n) total work across n inputs, vs the O(n²) cost of
    /// computing each input's witness independently from the tx start.
    ///
    /// # Errors
    /// Returns an error if the count or any item length is truncated.
    pub fn pop_from(buf: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        let (vi, mut rest) = VarInt::decode_ref(buf)?;
        let count = vi.to_usize()?;
        let items_start = rest;
        for _ in 0..count {
            let (vi, r2) = VarInt::decode_ref(rest)?;
            let len = vi.to_usize()?;
            if r2.len() < len {
                return Err(Error::UnexpectedEof);
            }
            rest = &r2[len..];
        }
        let items_buf = &items_start[..items_start.len() - rest.len()];
        Ok((
            Self {
                item_count: count,
                items_buf,
            },
            rest,
        ))
    }

    /// Skip one full witness (count + items) and return the trailing slice.
    fn skip_one(buf: &'a [u8]) -> Result<&'a [u8], Error> {
        let (vi, mut rest) = VarInt::decode_ref(buf)?;
        let count = vi.to_usize()?;
        for _ in 0..count {
            let (vi, r2) = VarInt::decode_ref(rest)?;
            let len = vi.to_usize()?;
            if r2.len() < len {
                return Err(Error::UnexpectedEof);
            }
            rest = &r2[len..];
        }
        Ok(rest)
    }

    /// Number of items on this witness stack.
    #[must_use]
    pub fn len(&self) -> usize {
        self.item_count
    }

    /// `true` if the witness stack is empty (legacy input).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.item_count == 0
    }

    /// Iterate items as borrowed `&'a [u8]` slices without allocating.
    #[must_use]
    pub fn iter(&self) -> WitnessRefIter<'a> {
        WitnessRefIter {
            buf: self.items_buf,
            remaining: self.item_count,
        }
    }

    /// Materialise the witness stack as a `Vec<Vec<u8>>`. Matches the shape
    /// produced by [`Witness::to_vec`] for compatibility with consumers that
    /// still take owned items.
    #[must_use]
    pub fn to_vec(&self) -> Vec<Vec<u8>> {
        self.iter().map(<[u8]>::to_vec).collect()
    }
}

impl<'a> IntoIterator for &WitnessRef<'a> {
    type Item = &'a [u8];
    type IntoIter = WitnessRefIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

// ── WitnessRefIter ───────────────────────────────────────────────────────────

/// Iterator over the items of a [`WitnessRef`]. Yields each item as a slice
/// into the underlying wire buffer; truncated items end iteration early.
pub struct WitnessRefIter<'a> {
    buf: &'a [u8],
    remaining: usize,
}

impl<'a> Iterator for WitnessRefIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.remaining == 0 {
            return None;
        }
        let (vi, rest) = VarInt::decode_ref(self.buf).ok()?;
        let len = vi.to_usize().ok()?;
        if rest.len() < len {
            self.remaining = 0;
            return None;
        }
        let (item, after) = rest.split_at(len);
        self.buf = after;
        self.remaining -= 1;
        Some(item)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl Encode for TransactionRef<'_, '_> {
    #[inline]
    fn encode(&self, w: &mut impl std::io::Write) -> Result<(), Error> {
        w.write_all(self.raw)?;
        Ok(())
    }
}

impl TxHash for TransactionRef<'_, '_> {
    #[inline]
    fn txid_into(&self, _buf: &mut Vec<u8>) -> Result<Hash256, Error> {
        Ok(self.non_witness_raw.sha256d())
    }
}

impl<'a> DecodeRef<'a> for TransactionRef<'a, 'a> {
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        let tx_start = buf;
        let (version, buf) = TxVersion::decode_ref(buf)?;

        // BIP144: if the byte after version is 0x00 and the one after that is
        // 0x01, this is a segwit transaction. Otherwise 0x00 means 0 inputs
        // (legacy) and the second byte is the output-count VarInt start.
        let (first, buf) = u8::decode_ref(buf)?;
        let (segwit, input_count, buf, legacy_output_first) = if first == 0x00 {
            let (flag, buf) = u8::decode_ref(buf)?;
            if flag == 0x01 {
                let (vi, buf) = VarInt::decode_ref(buf)?;
                let count = vi.to_usize()?;
                (true, count, buf, None)
            } else {
                // Legacy 0-input tx; `flag` is first byte of output-count VarInt.
                (false, 0usize, buf, Some(flag))
            }
        } else {
            // Re-decode the VarInt with `first` as its initial byte using a cursor.
            let mut cursor = std::io::Cursor::new(buf);
            let vi = VarInt::decode_from_first_byte(first, &mut cursor)?;
            let consumed = usize::try_from(cursor.position()).map_err(|_| Error::UnexpectedEof)?;
            let count = vi.to_usize()?;
            (false, count, &buf[consumed..], None)
        };

        let inputs_buf = buf;
        let mut rest = buf;
        for _ in 0..input_count {
            let (_, r) = TxInRef::decode_ref(rest)?;
            rest = r;
        }

        let (output_count, rest) = if let Some(b) = legacy_output_first {
            let mut cursor = std::io::Cursor::new(rest);
            let vi = VarInt::decode_from_first_byte(b, &mut cursor)?;
            let consumed = usize::try_from(cursor.position()).map_err(|_| Error::UnexpectedEof)?;
            let count = vi.to_usize()?;
            (count, &rest[consumed..])
        } else {
            let (vi, rest) = VarInt::decode_ref(rest)?;
            let count = vi.to_usize()?;
            (count, rest)
        };
        let outputs_buf = rest;
        let mut rest = rest;
        for _ in 0..output_count {
            let (_, r) = TxOutRef::decode_ref(rest)?;
            rest = r;
        }

        // For segwit: skip past the per-input witness stacks.
        let witnesses_start = rest;
        if segwit {
            for _ in 0..input_count {
                // Each witness: VarInt(item_count) then VarInt(len)+bytes per item.
                let (vi, mut r) = VarInt::decode_ref(rest)?;
                let item_count = vi.to_u64();
                for _ in 0..item_count {
                    let (vi, r2) = VarInt::decode_ref(r)?;
                    let len = vi.to_usize()?;
                    if r2.len() < len {
                        return Err(Error::UnexpectedEof);
                    }
                    r = &r2[len..];
                }
                rest = r;
            }
        }
        let witnesses_end = rest;
        // Span covering all input witnesses concatenated (BIP144). Empty for legacy.
        let witnesses_buf = &witnesses_start[..witnesses_start.len() - witnesses_end.len()];

        let (locktime, rest) = Locktime::decode_ref(rest)?;
        let raw = &tx_start[..tx_start.len() - rest.len()];

        // For legacy transactions `raw` is already the non-witness form, so
        // `non_witness_raw == raw` is the correct txid preimage. For segwit
        // transactions the txid is `SHA256d(version || inputs || outputs ||
        // locktime)` — produced without re-encoding by [`Self::decode_into_arena`].
        // The bare `decode_ref` path here cannot allocate, so it stores
        // `raw` as a placeholder; callers that need a correct segwit txid
        // must use `decode_into_arena` or fall back to `to_owned`.
        let non_witness_raw = raw;

        Ok((
            Self {
                version,
                locktime,
                raw,
                non_witness_raw,
                is_segwit: segwit,
                input_count,
                inputs_buf,
                output_count,
                outputs_buf,
                witnesses_buf,
            },
            rest,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::amount::Satoshi;
    use crate::codec::{DecodeRef, Encode, Error};
    use crate::difficulty::{Locktime, Sequence, TxVersion};
    use crate::hash::Hash256;
    use crate::script::Witness;
    use crate::tx::{
        OutPoint, Transaction, TransactionRef, TxHash, TxIn, TxOut, transaction_ref_with_arena,
    };

    fn encode<T: Encode>(val: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        val.encode(&mut buf).expect("Vec<u8> write cannot fail");
        buf
    }

    fn decode_ref<'a, T: DecodeRef<'a>>(buf: &'a [u8]) -> (T, &'a [u8]) {
        T::decode_ref(buf).expect("test data must decode")
    }

    fn make_tx() -> Transaction {
        Transaction {
            version: TxVersion::new(2),
            inputs: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: Hash256::from_bytes([0xab; 32]),
                        vout: 1,
                    },
                    script_sig: vec![0x01, 0x02, 0x03].into(),
                    sequence: Sequence::new(0xffff_fffe),
                    witness: Witness::empty(),
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: Hash256::from_bytes([0xcd; 32]),
                        vout: 0,
                    },
                    script_sig: vec![].into(),
                    sequence: Sequence::new(0),
                    witness: Witness::empty(),
                },
            ],
            outputs: vec![
                TxOut {
                    value: Satoshi::new(50_000),
                    script_pubkey: vec![0x76, 0xa9].into(),
                },
                TxOut {
                    value: Satoshi::ZERO,
                    script_pubkey: vec![].into(),
                },
            ],
            locktime: Locktime::new(800_000),
        }
    }

    /// Build a small segwit transaction with two witness items on the only input.
    fn make_segwit_tx() -> Transaction {
        Transaction {
            version: TxVersion::new(2),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([0x11u8; 32]),
                    vout: 0,
                },
                script_sig: Vec::<u8>::new().into(), // P2WPKH has empty scriptSig
                sequence: Sequence::new(0xffff_fffe),
                witness: Witness::from_slice(&[
                    &[0xde, 0xad, 0xbe, 0xef][..],
                    &[0x01, 0x02, 0x03, 0x04, 0x05][..],
                ]),
            }],
            outputs: vec![TxOut {
                value: Satoshi::new(99_000),
                script_pubkey: vec![0x00, 0x14, 0xaa, 0xbb, 0xcc].into(),
            }],
            locktime: Locktime::new(0),
        }
    }

    #[test]
    fn transaction_ref_decode_ref_roundtrip() {
        let tx = make_tx();
        let bytes = encode(&tx);
        let (tx_ref, tail) = decode_ref::<TransactionRef>(&bytes);
        assert!(tail.is_empty());
        assert_eq!(tx_ref.version, tx.version);
        assert_eq!(tx_ref.locktime, tx.locktime);
        assert_eq!(tx_ref.input_count(), tx.inputs.len());
        assert_eq!(tx_ref.output_count(), tx.outputs.len());

        for (r, expected) in tx_ref.inputs().zip(&tx.inputs) {
            let i = r.expect("input decode must succeed");
            assert_eq!(i.previous_output, expected.previous_output);
            assert_eq!(i.script_sig, expected.script_sig.as_slice());
            assert_eq!(i.sequence, expected.sequence);
        }
        for (r, expected) in tx_ref.outputs().zip(&tx.outputs) {
            let o = r.expect("output decode must succeed");
            assert_eq!(o.value, expected.value);
            assert_eq!(o.script_pubkey, expected.script_pubkey.as_slice());
        }
    }

    #[test]
    fn transaction_ref_script_sig_zero_copy() {
        let tx = make_tx();
        let bytes = encode(&tx);
        let (tx_ref, _) = decode_ref::<TransactionRef>(&bytes);
        let first = tx_ref
            .inputs()
            .next()
            .expect("tx has inputs")
            .expect("input decode must succeed");
        // script_sig must point directly into `bytes`, not a new allocation.
        let script_start = first.script_sig.as_ptr() as usize;
        let buf_start = bytes.as_ptr() as usize;
        let buf_end = buf_start + bytes.len();
        assert!(script_start >= buf_start && script_start < buf_end);
    }

    #[test]
    fn transaction_ref_to_owned_matches_original() {
        let tx = make_tx();
        let bytes = encode(&tx);
        let (tx_ref, _) = decode_ref::<TransactionRef>(&bytes);
        assert_eq!(tx_ref.to_owned().expect("to_owned must succeed"), tx);
    }

    #[test]
    fn transaction_ref_encode_matches_original() {
        let tx = make_tx();
        let bytes = encode(&tx);
        let (tx_ref, _) = decode_ref::<TransactionRef>(&bytes);
        let re_encoded = encode(&tx_ref);
        assert_eq!(re_encoded, bytes);
    }

    #[test]
    fn transaction_ref_encoded_len_matches_transaction() {
        let tx = make_tx();
        let bytes = encode(&tx);
        let (tx_ref, _) = decode_ref::<TransactionRef>(&bytes);
        assert_eq!(tx_ref.encoded_len(), tx.encoded_len());
        assert_eq!(tx_ref.encoded_len(), bytes.len());
    }

    #[test]
    fn transaction_ref_tail_is_remaining_bytes() {
        let tx = make_tx();
        let mut bytes = encode(&tx);
        bytes.extend_from_slice(&[0xde, 0xad]);
        let (_, tail) = decode_ref::<TransactionRef>(&bytes);
        assert_eq!(tail, &[0xde, 0xad]);
    }

    #[test]
    fn transaction_ref_truncated_returns_error() {
        let tx = make_tx();
        let bytes = encode(&tx);
        // Cut the buffer in half — must not panic, must return an error.
        let e = TransactionRef::decode_ref(&bytes[..bytes.len() / 2]).unwrap_err();
        assert!(matches!(e, Error::UnexpectedEof | Error::Io(_)));
    }

    #[test]
    fn transaction_ref_empty_inputs_outputs() {
        let tx = Transaction {
            version: TxVersion::new(1),
            inputs: vec![],
            outputs: vec![],
            locktime: Locktime::new(0),
        };
        let bytes = encode(&tx);
        let (tx_ref, tail) = decode_ref::<TransactionRef>(&bytes);
        assert!(tail.is_empty());
        assert_eq!(tx_ref.input_count(), 0);
        assert_eq!(tx_ref.output_count(), 0);
        assert!(tx_ref.inputs().next().is_none());
        assert!(tx_ref.outputs().next().is_none());
        assert_eq!(tx_ref.to_owned().expect("to_owned must succeed"), tx);
    }

    #[test]
    fn transaction_ref_segwit_decode_marks_segwit() {
        let tx = make_segwit_tx();
        let bytes = encode(&tx);
        let (tx_ref, tail) = decode_ref::<TransactionRef>(&bytes);
        assert!(tail.is_empty());
        assert!(tx_ref.is_segwit, "BIP144 marker+flag must set is_segwit");
        assert_eq!(tx_ref.input_count(), 1);
        // Bare decode_ref leaves non_witness_raw == raw for segwit; the txid is
        // therefore wrong on this path. Confirm the documented mismatch.
        let bare_txid = tx_ref.txid_into(&mut Vec::new()).expect("hash never fails");
        let owned_txid = tx.txid().expect("owned txid");
        assert_ne!(bare_txid, owned_txid);
    }

    #[test]
    fn transaction_ref_arena_txid_matches_owned() {
        let tx = make_segwit_tx();
        let bytes = encode(&tx);
        let mut arena = Vec::new();
        let (tx_ref, tail) =
            transaction_ref_with_arena(&bytes, &mut arena).expect("arena decode must succeed");
        assert!(tail.is_empty());
        assert!(tx_ref.is_segwit);

        let arena_txid = tx_ref.txid_into(&mut Vec::new()).expect("hash never fails");
        let owned_txid = tx.txid().expect("owned txid");
        assert_eq!(arena_txid, owned_txid, "arena segwit txid must match owned");
    }

    #[test]
    fn transaction_ref_arena_legacy_does_not_grow_arena() {
        let tx = make_tx(); // legacy
        let bytes = encode(&tx);
        let mut arena = Vec::new();
        {
            let (tx_ref, _) = transaction_ref_with_arena(&bytes, &mut arena)
                .expect("legacy arena decode must succeed");
            assert!(!tx_ref.is_segwit);
            assert_eq!(
                tx_ref.txid_into(&mut Vec::new()).expect("hash"),
                tx.txid().expect("owned txid"),
            );
        }
        assert_eq!(arena.len(), 0, "legacy txs do not touch the arena");
    }

    #[test]
    fn transaction_ref_witness_round_trips() {
        let tx = make_segwit_tx();
        let bytes = encode(&tx);
        let (tx_ref, _) = decode_ref::<TransactionRef>(&bytes);
        let w = tx_ref.witness(0);
        assert!(!w.is_empty());
        assert_eq!(w.len(), 2);
        let items: Vec<&[u8]> = w.iter().collect();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], &[0xde, 0xad, 0xbe, 0xef][..]);
        assert_eq!(items[1], &[0x01, 0x02, 0x03, 0x04, 0x05][..]);

        // Out-of-range and legacy paths return EMPTY.
        assert!(tx_ref.witness(99).is_empty());
        let legacy = make_tx();
        let lb = encode(&legacy);
        let (legacy_ref, _) = decode_ref::<TransactionRef>(&lb);
        assert!(legacy_ref.witness(0).is_empty());
    }

    /// Multi-input segwit tx: exercises `WitnessRef::skip_one` via
    /// `TransactionRef::witness(n_in)` when n_in > 0.
    #[test]
    fn transaction_ref_witness_skip_one_multi_input() {
        // Two-input segwit tx, each with different witness stacks.
        let tx = Transaction {
            version: TxVersion::new(2),
            inputs: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: Hash256::from_bytes([0x11u8; 32]),
                        vout: 0,
                    },
                    script_sig: Vec::<u8>::new().into(),
                    sequence: Sequence::new(0xffff_fffe),
                    witness: Witness::from_slice(&[
                        &[0xaa, 0xbb][..],
                        &[0xcc][..],
                    ]),
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: Hash256::from_bytes([0x22u8; 32]),
                        vout: 1,
                    },
                    script_sig: Vec::<u8>::new().into(),
                    sequence: Sequence::new(0xffff_ffff),
                    witness: Witness::from_slice(&[
                        &[0xdd, 0xee, 0xff][..],
                    ]),
                },
            ],
            outputs: vec![TxOut {
                value: Satoshi::new(50_000),
                script_pubkey: vec![0x00, 0x14, 0x01, 0x02, 0x03].into(),
            }],
            locktime: Locktime::new(0),
        };
        let bytes = encode(&tx);
        let (tx_ref, tail) = decode_ref::<TransactionRef>(&bytes);
        assert!(tail.is_empty());
        assert!(tx_ref.is_segwit);
        assert_eq!(tx_ref.input_count(), 2);

        // witness(0) should work without skip_one.
        let w0 = tx_ref.witness(0);
        assert_eq!(w0.len(), 2);
        let items0: Vec<&[u8]> = w0.iter().collect();
        assert_eq!(items0[0], &[0xaa, 0xbb]);
        assert_eq!(items0[1], &[0xcc]);

        // witness(1) must call skip_one to skip past input 0's witness.
        let w1 = tx_ref.witness(1);
        assert_eq!(w1.len(), 1);
        let items1: Vec<&[u8]> = w1.iter().collect();
        assert_eq!(items1[0], &[0xdd, 0xee, 0xff]);

        // Out-of-range still returns EMPTY.
        assert!(tx_ref.witness(2).is_empty());
    }

    // ── WitnessRef::pop_from ──────────────────────────────────────────

    use super::WitnessRef;

    #[test]
    fn witness_ref_pop_from_empty_witness() {
        // VarInt(0) = single byte 0x00
        let buf = [0x00, 0xaa, 0xbb];
        let (w, rest) = WitnessRef::pop_from(&buf).unwrap();
        assert_eq!(w.len(), 0);
        assert!(w.is_empty());
        assert_eq!(rest, &[0xaa, 0xbb]);
    }

    #[test]
    fn witness_ref_pop_from_two_items() {
        // count=2, item1=2 bytes [0xde, 0xad], item2=1 byte [0xff]
        let buf = [
            0x02, // count
            0x02, 0xde, 0xad, // item 1
            0x01, 0xff, // item 2
            0xcc, // trailing
        ];
        let (w, rest) = WitnessRef::pop_from(&buf).unwrap();
        assert_eq!(w.len(), 2);
        assert!(!w.is_empty());
        let items: Vec<&[u8]> = w.iter().collect();
        assert_eq!(items[0], &[0xde, 0xad]);
        assert_eq!(items[1], &[0xff]);
        assert_eq!(rest, &[0xcc]);
    }

    #[test]
    fn witness_ref_pop_from_streaming() {
        // Two witnesses back-to-back
        let buf = [
            0x01, 0x03, 0xaa, 0xbb, 0xcc, // witness 0: 1 item, 3 bytes
            0x01, 0x01, 0xdd, // witness 1: 1 item, 1 byte
        ];
        let (w0, rest) = WitnessRef::pop_from(&buf).unwrap();
        assert_eq!(w0.len(), 1);
        let (w1, rest) = WitnessRef::pop_from(rest).unwrap();
        assert_eq!(w1.len(), 1);
        assert!(rest.is_empty());
        let items0: Vec<&[u8]> = w0.iter().collect();
        let items1: Vec<&[u8]> = w1.iter().collect();
        assert_eq!(items0[0], &[0xaa, 0xbb, 0xcc]);
        assert_eq!(items1[0], &[0xdd]);
    }

    #[test]
    fn witness_ref_pop_from_truncated_fails() {
        // count=1 but no item data
        let buf = [0x01];
        assert!(WitnessRef::pop_from(&buf).is_err());
    }
}
