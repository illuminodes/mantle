use std::collections::HashSet;

use mantle::codec::{DecodeRef, VarInt};
use mantle::collections::PrehashedSet;
use mantle::hash::ByteSliceExt;
use mantle::primitives::{
    Block, BlockHeader, BlockHeight, Hash256, OutPoint, Satoshi, Transaction, TransactionRef,
    TxHash, TxInRef, TxOutRef,
};

use crate::error::ValidationError;
use crate::merkle::compute_merkle_root_reusing;

use super::pow::HeaderValidationExt;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum money supply in satoshis (21 million BTC).
pub const MAX_MONEY: Satoshi = Satoshi::MAX_MONEY;

/// Maximum block weight in weight units (BIP141).
pub const MAX_BLOCK_WEIGHT: u64 = 4_000_000;

/// Base size (non-witness) weight multiplier.
pub const WITNESS_SCALE_FACTOR: u64 = 4;

/// Maximum coinbase scriptSig length in bytes.
pub const MAX_COINBASE_SCRIPTSIG_LEN: usize = 100;
/// Minimum coinbase scriptSig length in bytes.
pub const MIN_COINBASE_SCRIPTSIG_LEN: usize = 2;

/// BIP34 activation height on mainnet.
pub const BIP34_HEIGHT: BlockHeight = BlockHeight::new(227_931);

/// Maximum number of transactions per block (practical consensus limit).
pub const MAX_BLOCK_TRANSACTIONS: usize = 1_000_000;

// ── Null outpoint (coinbase marker) ──────────────────────────────────────────

/// The null outpoint used in coinbase inputs.
pub(super) const NULL_OUTPOINT: OutPoint = OutPoint {
    txid: Hash256::ZERO,
    vout: u32::MAX,
};

// ── Stage 1 public functions ──────────────────────────────────────────────────

/// Stage 1: stateless structural validation.
///
/// Validates the block in isolation — no chain state required. This is the
/// first line of defence against malformed blocks from peers. All checks here
/// are pure functions of the block bytes.
///
/// Allocates fresh scratch buffers each call. For bulk processing use
/// [`validate_block_structure_reusing`] to amortise those allocations across
/// many blocks.
///
/// # Errors
/// Returns the first `ValidationError` encountered.
///
/// # Panics
/// Never — the internal `expect` is guarded by the non-empty check above it.
pub fn validate_block_structure(block: &Block) -> Result<(), ValidationError> {
    validate_block_structure_reusing(
        block,
        &mut Vec::new(),
        &mut Vec::new(),
        &mut Vec::new(),
        &mut PrehashedSet::default(),
        &mut PrehashedSet::default(),
    )
}

/// Stage 1 with caller-supplied scratch buffers.
///
/// All five scratch containers are cleared before use; the caller just needs to
/// keep them alive across calls to amortise allocations. Capacity is retained
/// between calls so the buffers grow to the high-water mark and stay there.
///
/// - `serial_scratch` — byte buffer reused for tx serialisation (txid hashing).
/// - `txids` — accumulator for per-block txid list fed into the merkle check.
/// - `merkle_buf` — working buffer for the in-place merkle reduction.
/// - `seen_inputs` — dedup set for inputs within a single transaction.
/// - `seen_txids` — dedup set for CVE-2012-2459 check across all txids.
///
/// # Errors
/// Returns the first `ValidationError` encountered.
///
/// # Panics
/// Never.
pub fn validate_block_structure_reusing<S1, S2>(
    block: &Block,
    serial_scratch: &mut Vec<u8>,
    txids: &mut Vec<Hash256>,
    merkle_buf: &mut Vec<Hash256>,
    seen_inputs: &mut HashSet<OutPoint, S1>,
    seen_txids: &mut HashSet<Hash256, S2>,
) -> Result<(), ValidationError>
where
    S1: std::hash::BuildHasher,
    S2: std::hash::BuildHasher,
{
    // Non-empty tx list.
    if block.transactions.is_empty() {
        return Err(ValidationError::EmptyBlock);
    }

    if block.transactions.len() > MAX_BLOCK_TRANSACTIONS {
        return Err(ValidationError::TooManyTransactions {
            count: block.transactions.len(),
        });
    }

    // First tx must be coinbase; no subsequent tx may be coinbase.
    seen_inputs.clear();
    for (i, tx) in block.transactions.iter().enumerate() {
        check_tx_structure(tx, i, i == 0, seen_inputs)?;
    }

    // Block weight.
    let weight = block.weight();
    if weight > MAX_BLOCK_WEIGHT {
        return Err(ValidationError::BlockWeightExceeded { weight });
    }

    // Merkle root — all txids hashed with a single reused serialisation buffer.
    txids.clear();
    txids.reserve(block.transactions.len());
    for tx in &block.transactions {
        tx.txid_into(serial_scratch)?;
        txids.push(serial_scratch.sha256d());
    }

    // CVE-2012-2459: reject any block whose txid set contains duplicates.
    seen_txids.clear();
    seen_txids.reserve(txids.len());
    for &id in txids.iter() {
        if !seen_txids.insert(id) {
            return Err(ValidationError::DuplicateTransaction);
        }
    }

    let computed_root =
        compute_merkle_root_reusing(txids, merkle_buf).expect("non-empty; checked above");
    if computed_root != block.header.merkle_root() {
        return Err(ValidationError::MerkleRootMismatch);
    }

    // PoW: header hash must be ≤ target encoded in nBits.
    block.header.check_pow()?;

    Ok(())
}

/// Stage 1 from raw wire bytes — zero heap allocations for the validation
/// path itself.
///
/// Parses the 80-byte header and iterates transactions as [`TransactionRef`]
/// views directly into `wire`. No `Transaction` structs are materialised and
/// txids are computed by hashing the raw wire span directly — no re-encoding.
///
/// - `txids` — accumulator for the merkle check; cleared and filled per call.
/// - `merkle_buf` — working buffer for the in-place merkle reduction.
/// - `seen_inputs` — dedup set for inputs within a single transaction.
/// - `seen_txids` — dedup set for the CVE-2012-2459 check.
///
/// # Errors
/// Returns the first `ValidationError` encountered, or
/// `ValidationError::MalformedTransaction` if the wire bytes are truncated
/// or corrupt.
///
/// # Panics
/// Never — the `.expect` on the merkle root is guarded by the non-empty check
/// at the top of the function.
pub fn validate_block_wire<S1, S2>(
    wire: &[u8],
    txids: &mut Vec<Hash256>,
    merkle_buf: &mut Vec<Hash256>,
    seen_inputs: &mut HashSet<OutPoint, S1>,
    seen_txids: &mut HashSet<Hash256, S2>,
) -> Result<(), ValidationError>
where
    S1: std::hash::BuildHasher,
    S2: std::hash::BuildHasher,
{
    let malformed_block = |_| ValidationError::MalformedTransaction {
        tx_index: usize::MAX,
    };

    let (header, rest) = BlockHeader::decode_ref(wire).map_err(malformed_block)?;

    let (tx_count_vi, mut rest) =
        mantle::codec::VarInt::decode_ref(rest).map_err(malformed_block)?;
    let tx_count = tx_count_vi
        .to_usize()
        .map_err(|_| ValidationError::TooManyTransactions { count: usize::MAX })?;

    if tx_count == 0 {
        return Err(ValidationError::EmptyBlock);
    }
    if tx_count > MAX_BLOCK_TRANSACTIONS {
        return Err(ValidationError::TooManyTransactions { count: tx_count });
    }

    // Single-pass per-transaction scan: parse + validate in one walk.
    let mut base_size = BlockHeader::ENCODED_LEN + VarInt::from(tx_count).encoded_len();
    seen_inputs.clear();
    txids.clear();
    txids.reserve(tx_count);

    for tx_index in 0..tx_count {
        let (tx_raw_len, txid) = scan_tx_wire(rest, tx_index, seen_inputs)?;
        rest = &rest[tx_raw_len..];
        base_size += tx_raw_len;
        txids.push(txid);
    }

    let weight = base_size as u64 * WITNESS_SCALE_FACTOR;
    if weight > MAX_BLOCK_WEIGHT {
        return Err(ValidationError::BlockWeightExceeded { weight });
    }

    // CVE-2012-2459.
    seen_txids.clear();
    seen_txids.reserve(txids.len());
    for &id in txids.iter() {
        if !seen_txids.insert(id) {
            return Err(ValidationError::DuplicateTransaction);
        }
    }

    let computed_root =
        compute_merkle_root_reusing(txids, merkle_buf).expect("non-empty; checked above");
    if computed_root != header.merkle_root() {
        return Err(ValidationError::MerkleRootMismatch);
    }

    header.check_pow()?;

    Ok(())
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Parse and validate one transaction from raw wire bytes in a single pass.
///
/// Returns `(tx_raw_len, txid)` on success. `tx_raw_len` is the number of
/// bytes consumed from `wire`; the caller advances its cursor by that amount.
///
/// Combines what `TransactionRef::decode_ref` + `check_tx_structure` would do
/// in two passes into one: inputs are decoded once and simultaneously checked
/// for coinbase rules and duplicates; outputs are decoded once and checked for
/// value bounds.
fn scan_tx_wire<S>(
    wire: &[u8],
    tx_index: usize,
    seen_inputs: &mut HashSet<OutPoint, S>,
) -> Result<(usize, Hash256), ValidationError>
where
    S: std::hash::BuildHasher,
{
    let malformed = |_: mantle::codec::Error| ValidationError::MalformedTransaction { tx_index };

    let (_, buf) = i32::decode_ref(wire).map_err(malformed)?; // version

    let (vi, mut buf) = VarInt::decode_ref(buf).map_err(malformed)?;
    let input_count = vi
        .to_usize()
        .map_err(|_| ValidationError::MalformedTransaction { tx_index })?;
    if input_count == 0 {
        return Err(ValidationError::EmptyInputs { tx_index });
    }

    let expect_coinbase = tx_index == 0;
    let (first_in, buf_after_first) = TxInRef::decode_ref(buf).map_err(malformed)?;
    let first_is_coinbase = first_in.previous_output == NULL_OUTPOINT;

    if expect_coinbase && !first_is_coinbase {
        return Err(ValidationError::FirstTxNotCoinbase);
    }
    if !expect_coinbase && first_is_coinbase {
        return Err(ValidationError::UnexpectedCoinbaseInput { tx_index });
    }
    if expect_coinbase
        && !(MIN_COINBASE_SCRIPTSIG_LEN..=MAX_COINBASE_SCRIPTSIG_LEN)
            .contains(&first_in.script_sig.len())
    {
        return Err(ValidationError::CoinbaseScriptSigLength {
            len: first_in.script_sig.len(),
        });
    }

    buf = buf_after_first;
    if expect_coinbase {
        for _ in 1..input_count {
            let (_, next) = TxInRef::decode_ref(buf).map_err(malformed)?;
            buf = next;
        }
    } else {
        seen_inputs.clear();
        seen_inputs.reserve(input_count);
        seen_inputs.insert(first_in.previous_output);
        for _ in 1..input_count {
            let (inp, next) = TxInRef::decode_ref(buf).map_err(malformed)?;
            buf = next;
            if !seen_inputs.insert(inp.previous_output) {
                return Err(ValidationError::DuplicateInput { tx_index });
            }
        }
    }

    let (vi, mut buf) = VarInt::decode_ref(buf).map_err(malformed)?;
    let output_count = vi
        .to_usize()
        .map_err(|_| ValidationError::MalformedTransaction { tx_index })?;
    if output_count == 0 {
        return Err(ValidationError::EmptyOutputs { tx_index });
    }

    let mut total = Satoshi::ZERO;
    for output_index in 0..output_count {
        let (out, next) = TxOutRef::decode_ref(buf).map_err(malformed)?;
        buf = next;
        if out.value > MAX_MONEY {
            return Err(ValidationError::OutputValueOutOfRange {
                tx_index,
                output_index,
            });
        }
        total = total
            .checked_add(out.value)
            .filter(|&s| s <= MAX_MONEY)
            .ok_or(ValidationError::TotalOutputValueOverflow { tx_index })?;
    }

    let (_, rest) = u32::decode_ref(buf).map_err(malformed)?; // locktime
    let tx_raw_len = wire.len() - rest.len();
    Ok((tx_raw_len, wire[..tx_raw_len].sha256d()))
}

/// Minimal view a transaction must expose to be structurally validated.
///
/// Implemented for both owned `Transaction` and zero-copy `TransactionRef<'_>`
/// so the check is written once and reused on either path. Iterators yield
/// `Result<_, codec::Error>` to handle truncated wire bytes uniformly; owned
/// txs simply produce `Ok` items unconditionally.
trait TxStructureView {
    fn input_count(&self) -> usize;
    fn output_count(&self) -> usize;
    fn first_input(&self) -> Result<(OutPoint, usize), mantle::codec::Error>;
    fn for_each_output<E>(&self, f: impl FnMut(usize, Satoshi) -> Result<(), E>) -> Result<(), E>
    where
        E: From<mantle::codec::Error>;
    fn for_each_input_outpoint<E>(&self, f: impl FnMut(OutPoint) -> Result<(), E>) -> Result<(), E>
    where
        E: From<mantle::codec::Error>;
}

impl TxStructureView for Transaction {
    fn input_count(&self) -> usize {
        self.inputs.len()
    }

    fn output_count(&self) -> usize {
        self.outputs.len()
    }

    fn first_input(&self) -> Result<(OutPoint, usize), mantle::codec::Error> {
        let i = &self.inputs[0];
        Ok((i.previous_output, i.script_sig.len()))
    }

    fn for_each_output<E>(
        &self,
        mut f: impl FnMut(usize, Satoshi) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<mantle::codec::Error>,
    {
        for (i, o) in self.outputs.iter().enumerate() {
            f(i, o.value)?;
        }
        Ok(())
    }

    fn for_each_input_outpoint<E>(
        &self,
        mut f: impl FnMut(OutPoint) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<mantle::codec::Error>,
    {
        for input in &self.inputs {
            f(input.previous_output)?;
        }
        Ok(())
    }
}

impl TxStructureView for TransactionRef<'_, '_> {
    fn input_count(&self) -> usize {
        TransactionRef::input_count(self)
    }

    fn output_count(&self) -> usize {
        TransactionRef::output_count(self)
    }

    fn first_input(&self) -> Result<(OutPoint, usize), mantle::codec::Error> {
        let r = self
            .inputs()
            .next()
            .ok_or(mantle::codec::Error::UnexpectedEof)??;
        Ok((r.previous_output, r.script_sig.len()))
    }

    fn for_each_output<E>(
        &self,
        mut f: impl FnMut(usize, Satoshi) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<mantle::codec::Error>,
    {
        for (i, r) in self.outputs().enumerate() {
            let o = r.map_err(E::from)?;
            f(i, o.value)?;
        }
        Ok(())
    }

    fn for_each_input_outpoint<E>(
        &self,
        mut f: impl FnMut(OutPoint) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<mantle::codec::Error>,
    {
        for r in self.inputs() {
            let input = r.map_err(E::from)?;
            f(input.previous_output)?;
        }
        Ok(())
    }
}

fn check_tx_structure<T, S>(
    tx: &T,
    tx_index: usize,
    expect_coinbase: bool,
    seen_inputs: &mut HashSet<OutPoint, S>,
) -> Result<(), ValidationError>
where
    T: TxStructureView,
    S: std::hash::BuildHasher,
{
    let malformed = |_| ValidationError::MalformedTransaction { tx_index };

    if tx.input_count() == 0 {
        return Err(ValidationError::EmptyInputs { tx_index });
    }
    if tx.output_count() == 0 {
        return Err(ValidationError::EmptyOutputs { tx_index });
    }

    let (first_outpoint, first_script_len) = tx.first_input().map_err(malformed)?;
    let first_is_coinbase = first_outpoint == NULL_OUTPOINT;

    if expect_coinbase && !first_is_coinbase {
        return Err(ValidationError::FirstTxNotCoinbase);
    }
    if !expect_coinbase && first_is_coinbase {
        return Err(ValidationError::UnexpectedCoinbaseInput { tx_index });
    }

    if expect_coinbase
        && !(MIN_COINBASE_SCRIPTSIG_LEN..=MAX_COINBASE_SCRIPTSIG_LEN).contains(&first_script_len)
    {
        return Err(ValidationError::CoinbaseScriptSigLength {
            len: first_script_len,
        });
    }

    // Output value bounds.
    let mut total = Satoshi::ZERO;
    tx.for_each_output(|i, value| -> Result<(), ValidationError> {
        if value > MAX_MONEY {
            return Err(ValidationError::OutputValueOutOfRange {
                tx_index,
                output_index: i,
            });
        }
        total = total
            .checked_add(value)
            .filter(|&s| s <= MAX_MONEY)
            .ok_or(ValidationError::TotalOutputValueOverflow { tx_index })?;
        Ok(())
    })?;

    // Duplicate inputs within a single transaction.
    if !expect_coinbase {
        seen_inputs.clear();
        seen_inputs.reserve(tx.input_count());
        tx.for_each_input_outpoint(|outpoint| -> Result<(), ValidationError> {
            if !seen_inputs.insert(outpoint) {
                return Err(ValidationError::DuplicateInput { tx_index });
            }
            Ok(())
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mantle::codec::Encode;

    /// Helper: encode a coinbase input (null outpoint) with the given scriptSig bytes.
    fn encode_coinbase_input(script_sig: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        // txid = 32 zero bytes (null)
        buf.extend_from_slice(&[0u8; 32]);
        // vout = 0xFFFFFFFF
        buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        // VarInt(scriptSig.len())
        VarInt::from(script_sig.len()).encode(&mut buf).unwrap();
        buf.extend_from_slice(script_sig);
        // sequence
        buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        buf
    }

    /// Helper: encode a normal (non-coinbase) input spending a given outpoint.
    fn encode_input(txid: &[u8; 32], vout: u32, script_sig: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(txid);
        buf.extend_from_slice(&vout.to_le_bytes());
        VarInt::from(script_sig.len()).encode(&mut buf).unwrap();
        buf.extend_from_slice(script_sig);
        buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        buf
    }

    /// Helper: encode a single output with the given value and scriptPubKey.
    fn encode_output(value: u64, script_pubkey: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&value.to_le_bytes());
        VarInt::from(script_pubkey.len()).encode(&mut buf).unwrap();
        buf.extend_from_slice(script_pubkey);
        buf
    }

    /// Build a raw coinbase transaction with the given scriptSig, outputs, and
    /// return its wire bytes.
    fn build_coinbase_tx(script_sig: &[u8], outputs: &[(u64, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        // version
        buf.extend_from_slice(&1i32.to_le_bytes());
        // input count = 1
        buf.push(0x01);
        buf.extend_from_slice(&encode_coinbase_input(script_sig));
        // output count
        VarInt::from(outputs.len()).encode(&mut buf).unwrap();
        for &(value, spk) in outputs {
            buf.extend_from_slice(&encode_output(value, spk));
        }
        // locktime
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf
    }

    /// Build a raw non-coinbase transaction with one normal input and the
    /// given outputs.
    fn build_normal_tx(outputs: &[(u64, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.push(0x01);
        buf.extend_from_slice(&encode_input(&[0x11; 32], 0, &[0x51]));
        VarInt::from(outputs.len()).encode(&mut buf).unwrap();
        for &(value, spk) in outputs {
            buf.extend_from_slice(&encode_output(value, spk));
        }
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf
    }

    // ── Coinbase scriptSig too short ─────────────────────────────────────

    #[test]
    fn coinbase_scriptsig_too_short() {
        // MIN_COINBASE_SCRIPTSIG_LEN = 2; use a 1-byte scriptSig.
        let wire = build_coinbase_tx(&[0x04], &[(50_0000_0000, &[0xac])]);
        let mut seen = HashSet::new();
        let r = scan_tx_wire(&wire, 0, &mut seen);
        assert!(
            matches!(r, Err(ValidationError::CoinbaseScriptSigLength { len: 1 })),
            "1-byte coinbase scriptSig must fail, got: {r:?}"
        );
    }

    #[test]
    fn coinbase_scriptsig_empty() {
        // 0-byte scriptSig (even shorter).
        let wire = build_coinbase_tx(&[], &[(50_0000_0000, &[0xac])]);
        let mut seen = HashSet::new();
        let r = scan_tx_wire(&wire, 0, &mut seen);
        assert!(
            matches!(r, Err(ValidationError::CoinbaseScriptSigLength { len: 0 })),
            "0-byte coinbase scriptSig must fail, got: {r:?}"
        );
    }

    // ── Coinbase scriptSig too long ──────────────────────────────────────

    #[test]
    fn coinbase_scriptsig_too_long() {
        // MAX_COINBASE_SCRIPTSIG_LEN = 100; use 101 bytes.
        let script_sig = vec![0x04; 101];
        let wire = build_coinbase_tx(&script_sig, &[(50_0000_0000, &[0xac])]);
        let mut seen = HashSet::new();
        let r = scan_tx_wire(&wire, 0, &mut seen);
        assert!(
            matches!(
                r,
                Err(ValidationError::CoinbaseScriptSigLength { len: 101 })
            ),
            "101-byte coinbase scriptSig must fail, got: {r:?}"
        );
    }

    #[test]
    fn coinbase_scriptsig_at_max_succeeds() {
        // Exactly 100 bytes is valid.
        let script_sig = vec![0x04; 100];
        let wire = build_coinbase_tx(&script_sig, &[(50_0000_0000, &[0xac])]);
        let mut seen = HashSet::new();
        let r = scan_tx_wire(&wire, 0, &mut seen);
        assert!(
            r.is_ok(),
            "100-byte coinbase scriptSig must pass, got: {r:?}"
        );
    }

    #[test]
    fn coinbase_scriptsig_at_min_succeeds() {
        // Exactly 2 bytes is valid.
        let wire = build_coinbase_tx(&[0x04, 0x01], &[(50_0000_0000, &[0xac])]);
        let mut seen = HashSet::new();
        let r = scan_tx_wire(&wire, 0, &mut seen);
        assert!(r.is_ok(), "2-byte coinbase scriptSig must pass, got: {r:?}");
    }

    // ── Output value exceeding MAX_MONEY ─────────────────────────────────

    #[test]
    fn output_value_exceeds_max_money() {
        let over_max = Satoshi::MAX_MONEY.to_u64() + 1;
        let wire = build_normal_tx(&[(over_max, &[0xac])]);
        let mut seen = HashSet::new();
        let r = scan_tx_wire(&wire, 1, &mut seen);
        assert!(
            matches!(
                r,
                Err(ValidationError::OutputValueOutOfRange {
                    tx_index: 1,
                    output_index: 0,
                })
            ),
            "output value > MAX_MONEY must fail, got: {r:?}"
        );
    }

    #[test]
    fn output_value_at_max_money_succeeds() {
        let at_max = Satoshi::MAX_MONEY.to_u64();
        let wire = build_normal_tx(&[(at_max, &[0xac])]);
        let mut seen = HashSet::new();
        let r = scan_tx_wire(&wire, 1, &mut seen);
        assert!(r.is_ok(), "output value == MAX_MONEY must pass, got: {r:?}");
    }

    // ── Total output value overflow ──────────────────────────────────────

    #[test]
    fn total_output_value_overflow() {
        // Two outputs each at MAX_MONEY — the sum exceeds MAX_MONEY.
        let at_max = Satoshi::MAX_MONEY.to_u64();
        let wire = build_normal_tx(&[(at_max, &[0xac]), (at_max, &[0xac])]);
        let mut seen = HashSet::new();
        let r = scan_tx_wire(&wire, 1, &mut seen);
        assert!(
            matches!(
                r,
                Err(ValidationError::TotalOutputValueOverflow { tx_index: 1 })
            ),
            "total output value > MAX_MONEY must fail, got: {r:?}"
        );
    }

    #[test]
    fn total_output_value_just_over() {
        // Two outputs whose sum is MAX_MONEY + 1.
        let half = Satoshi::MAX_MONEY.to_u64() / 2;
        let other_half = Satoshi::MAX_MONEY.to_u64() - half + 1;
        let wire = build_normal_tx(&[(half, &[0xac]), (other_half, &[0xac])]);
        let mut seen = HashSet::new();
        let r = scan_tx_wire(&wire, 1, &mut seen);
        assert!(
            matches!(
                r,
                Err(ValidationError::TotalOutputValueOverflow { tx_index: 1 })
            ),
            "total output value == MAX_MONEY + 1 must fail, got: {r:?}"
        );
    }

    // ── Empty outputs ────────────────────────────────────────────────────

    #[test]
    fn empty_outputs_rejected() {
        // A transaction with 0 outputs must be rejected.
        let wire = build_normal_tx(&[]);
        let mut seen = HashSet::new();
        let r = scan_tx_wire(&wire, 1, &mut seen);
        assert!(
            matches!(r, Err(ValidationError::EmptyOutputs { tx_index: 1 })),
            "zero outputs must fail, got: {r:?}"
        );
    }

    #[test]
    fn empty_outputs_coinbase_rejected() {
        // Coinbase with 0 outputs must also be rejected.
        let wire = build_coinbase_tx(&[0x04, 0x01], &[]);
        let mut seen = HashSet::new();
        let r = scan_tx_wire(&wire, 0, &mut seen);
        assert!(
            matches!(r, Err(ValidationError::EmptyOutputs { tx_index: 0 })),
            "coinbase with zero outputs must fail, got: {r:?}"
        );
    }

    // ── Malformed / truncated transactions ──────────────────────────────

    #[test]
    fn truncated_tx_version_rejected() {
        // Only 2 bytes of the 4-byte version field — decode_ref fails
        // immediately, returning MalformedTransaction.
        let wire = [0x01, 0x00]; // truncated i32
        let mut seen = HashSet::new();
        let r = scan_tx_wire(&wire, 0, &mut seen);
        assert!(
            matches!(
                r,
                Err(ValidationError::MalformedTransaction { tx_index: 0 })
            ),
            "truncated version must fail with MalformedTransaction, got: {r:?}"
        );
    }

    #[test]
    fn truncated_after_version_rejected() {
        // Full 4-byte version but nothing after — VarInt for input_count
        // is missing.
        let wire = 1i32.to_le_bytes();
        let mut seen = HashSet::new();
        let r = scan_tx_wire(&wire, 3, &mut seen);
        assert!(
            matches!(
                r,
                Err(ValidationError::MalformedTransaction { tx_index: 3 })
            ),
            "truncated after version must fail with MalformedTransaction, got: {r:?}"
        );
    }

    #[test]
    fn truncated_input_rejected() {
        // Version + input_count=1 + partial input (only 10 bytes of
        // the 36-byte outpoint). The TxInRef::decode_ref call fails.
        let mut wire = Vec::new();
        wire.extend_from_slice(&1i32.to_le_bytes()); // version
        wire.push(0x01); // input_count = 1
        wire.extend_from_slice(&[0xaa; 10]); // partial outpoint
        let mut seen = HashSet::new();
        let r = scan_tx_wire(&wire, 2, &mut seen);
        assert!(
            matches!(
                r,
                Err(ValidationError::MalformedTransaction { tx_index: 2 })
            ),
            "truncated input must fail with MalformedTransaction, got: {r:?}"
        );
    }

    #[test]
    fn truncated_output_rejected() {
        // A valid coinbase input followed by output_count=1 but only
        // 3 bytes of the 8-byte value field — TxOutRef::decode_ref fails.
        let mut wire = Vec::new();
        wire.extend_from_slice(&1i32.to_le_bytes()); // version
        wire.push(0x01); // input_count = 1
        wire.extend_from_slice(&encode_coinbase_input(&[0x04, 0x01]));
        wire.push(0x01); // output_count = 1
        wire.extend_from_slice(&[0x00; 3]); // partial value (need 8 bytes)
        let mut seen = HashSet::new();
        let r = scan_tx_wire(&wire, 0, &mut seen);
        assert!(
            matches!(
                r,
                Err(ValidationError::MalformedTransaction { tx_index: 0 })
            ),
            "truncated output must fail with MalformedTransaction, got: {r:?}"
        );
    }

    #[test]
    fn empty_inputs_non_coinbase_rejected() {
        // A non-coinbase transaction (tx_index > 0) with input_count = 0
        // must be rejected as EmptyInputs.
        let mut wire = Vec::new();
        wire.extend_from_slice(&1i32.to_le_bytes()); // version
        wire.push(0x00); // input_count = 0
        let mut seen = HashSet::new();
        let r = scan_tx_wire(&wire, 1, &mut seen);
        assert!(
            matches!(r, Err(ValidationError::EmptyInputs { tx_index: 1 })),
            "zero inputs must fail with EmptyInputs, got: {r:?}"
        );
    }

    #[test]
    fn first_tx_not_coinbase_rejected_in_scan() {
        // tx_index == 0 but the first input is not a coinbase (non-null
        // outpoint). Must return FirstTxNotCoinbase.
        let wire = build_normal_tx(&[(1_000, &[0xac])]);
        let mut seen = HashSet::new();
        let r = scan_tx_wire(&wire, 0, &mut seen);
        assert!(
            matches!(r, Err(ValidationError::FirstTxNotCoinbase)),
            "non-coinbase at tx_index 0 must fail with FirstTxNotCoinbase, got: {r:?}"
        );
    }

    #[test]
    fn unexpected_coinbase_input_rejected_in_scan() {
        // tx_index > 0 but the first input IS a coinbase (null outpoint).
        // Must return UnexpectedCoinbaseInput.
        let wire = build_coinbase_tx(&[0x04, 0x01], &[(1_000, &[0xac])]);
        let mut seen = HashSet::new();
        let r = scan_tx_wire(&wire, 1, &mut seen);
        assert!(
            matches!(
                r,
                Err(ValidationError::UnexpectedCoinbaseInput { tx_index: 1 })
            ),
            "coinbase at tx_index 1 must fail with UnexpectedCoinbaseInput, got: {r:?}"
        );
    }

    #[test]
    fn duplicate_input_rejected_in_scan() {
        // A non-coinbase transaction with two inputs spending the same
        // outpoint. Must return DuplicateInput.
        let mut wire = Vec::new();
        wire.extend_from_slice(&1i32.to_le_bytes()); // version
        wire.push(0x02); // input_count = 2
        let inp = encode_input(&[0x11; 32], 0, &[0x51]);
        wire.extend_from_slice(&inp); // first input
        wire.extend_from_slice(&inp); // duplicate input
        VarInt::from(1usize).encode(&mut wire).unwrap(); // output_count = 1
        wire.extend_from_slice(&encode_output(1_000, &[0xac]));
        wire.extend_from_slice(&0u32.to_le_bytes()); // locktime
        let mut seen = HashSet::new();
        let r = scan_tx_wire(&wire, 1, &mut seen);
        assert!(
            matches!(r, Err(ValidationError::DuplicateInput { tx_index: 1 })),
            "duplicate inputs must fail with DuplicateInput, got: {r:?}"
        );
    }

    // ── Coinbase with multiple inputs ────────────────────────────────

    /// A coinbase transaction (tx_index=0) with input_count > 1.
    /// The code at lines 294-298 iterates over additional inputs after
    /// the first coinbase input without duplicate checking. This test
    /// exercises that loop body (the `for _ in 1..input_count` path for
    /// coinbase transactions).
    #[test]
    fn coinbase_with_multiple_inputs_parsed() {
        // Build a coinbase tx with 3 inputs: the first is the null
        // outpoint (coinbase), the second and third are arbitrary.
        let script_sig = &[0x04, 0x01]; // 2-byte scriptSig (valid length)
        let mut wire = Vec::new();
        wire.extend_from_slice(&1i32.to_le_bytes()); // version
        wire.push(0x03); // input_count = 3
        // First input: coinbase (null outpoint)
        wire.extend_from_slice(&encode_coinbase_input(script_sig));
        // Second input: arbitrary (not checked for coinbase-ness or duplicates)
        wire.extend_from_slice(&encode_input(&[0x22; 32], 0, &[0x51]));
        // Third input: another arbitrary input
        wire.extend_from_slice(&encode_input(&[0x33; 32], 1, &[0x51]));
        // One output
        VarInt::from(1usize).encode(&mut wire).unwrap();
        wire.extend_from_slice(&encode_output(50_0000_0000, &[0xac]));
        wire.extend_from_slice(&0u32.to_le_bytes()); // locktime
        let mut seen = HashSet::new();
        let r = scan_tx_wire(&wire, 0, &mut seen);
        assert!(
            r.is_ok(),
            "coinbase with multiple inputs must be parsed without error, got: {r:?}"
        );
        let (raw_len, _txid) = r.unwrap();
        assert_eq!(raw_len, wire.len(), "raw_len must consume entire wire");
    }

    /// Non-coinbase tx with multiple distinct inputs must succeed
    /// (exercises the non-coinbase dedup loop for > 1 inputs that are
    /// all unique).
    #[test]
    fn non_coinbase_multiple_distinct_inputs_accepted() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&1i32.to_le_bytes()); // version
        wire.push(0x03); // input_count = 3
        wire.extend_from_slice(&encode_input(&[0x11; 32], 0, &[0x51]));
        wire.extend_from_slice(&encode_input(&[0x22; 32], 0, &[0x51]));
        wire.extend_from_slice(&encode_input(&[0x33; 32], 0, &[0x51]));
        VarInt::from(1usize).encode(&mut wire).unwrap();
        wire.extend_from_slice(&encode_output(1_000, &[0xac]));
        wire.extend_from_slice(&0u32.to_le_bytes()); // locktime
        let mut seen = HashSet::new();
        let r = scan_tx_wire(&wire, 1, &mut seen);
        assert!(
            r.is_ok(),
            "non-coinbase with 3 distinct inputs must pass, got: {r:?}"
        );
    }
}
