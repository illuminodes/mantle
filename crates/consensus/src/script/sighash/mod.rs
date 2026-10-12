//! Signature hash computation for the three regimes Mantle supports —
//! legacy (pre-segwit), BIP143 (segwit v0), and BIP341 (taproot).
//!
//! All three are exposed as methods on [`Transaction`] via the
//! [`TxSighash`] extension trait — call sites read
//! `tx.legacy_sighash(...)`, `tx.bip143_sighash(...)`,
//! `tx.bip341_sighash(...)`. The trait lives here because `Transaction`
//! is foreign (defined in `mantle::primitives`).
//!
//! ## Legacy ([`TxSighash::legacy_sighash`])
//!
//! Produces the 32-byte digest that an ECDSA signature in the legacy
//! regime is computed over. The algorithm:
//!
//! 1. Build a *modified* transaction:
//!    - Replace every input's `script_sig` with the empty script.
//!    - Replace input `n_in`'s `script_sig` with `script_code` (after
//!      `FindAndDelete` of the signature being checked — see
//!      `find_and_delete_sig`).
//!    - Apply the `hash_type` modifications:
//!      - `SIGHASH_NONE`: clear all outputs and zero every other input's sequence.
//!      - `SIGHASH_SINGLE`: keep only output `n_in`; if `n_in >= n_outputs`,
//!        return the constant digest `0x0000…0001` (the **"1" bug**).
//!      - `SIGHASH_ANYONECANPAY`: keep only input `n_in`.
//! 2. Serialise the modified tx in legacy form, append the 4-byte
//!    little-endian `hash_type`, and SHA-256d.
//!
//! All four base modes plus `ANYONECANPAY` are reproduced exactly,
//! including the `SIGHASH_SINGLE` "1" bug — fixing it would be a hard
//! fork.
//!
//! ## BIP143 ([`TxSighash::bip143_sighash`])
//!
//! Segwit v0 sighash. Commits to amounts and removes quadratic hashing
//! by pre-hashing shared fields (`hashPrevouts`, `hashSequence`,
//! `hashOutputs`) once per transaction via [`Bip143Cache`], then
//! per-input serialises:
//!
//! ```text
//! nVersion || hashPrevouts || hashSequence || outpoint || scriptCode ||
//! amount || nSequence || hashOutputs || nLocktime || nHashType
//! ```
//!
//! `scriptCode` for P2WPKH is a synthetic P2PKH script; for P2WSH it is
//! the witness script with a `VarInt` length prefix (both supplied by
//! the caller from the segwit dispatch logic in `verify_script`).
//!
//! ## BIP341 ([`TxSighash::bip341_sighash`])
//!
//! Taproot sighash. Like BIP143, shared fields are pre-hashed via
//! [`Bip341Cache`]. Adds an epoch byte, an `out_mode` per
//! `TaprootSigHashType`, an `annex` commitment, and — for script-path
//! spends — a `(leaf_hash, code_sep_pos)` extension. See
//! [`TxSighash::bip341_sighash`] for the argument shape.

use std::cell::RefCell;

use mantle::codec::{Encode, VarInt};
use mantle::hash::ByteSliceExt;
use mantle::primitives::{Hash256, Satoshi, Sequence};

#[cfg(test)]
use mantle::primitives::{Transaction, TxIn, TxOut, Witness};

use super::consensus_crypto::Schnorr;
use crate::tx_view::{InputView, OutputView, TxView};

thread_local! {
    /// Reusable scratch buffer for the legacy preimage. Cleared and refilled per
    /// call instead of allocating a fresh `Vec<u8>` (and a fresh modified
    /// `Transaction`) every sighash. ~1 GB of allocations per 100k mainnet blocks
    /// collapses to a single per-thread buffer that grows once.
    static LEGACY_PREIMAGE_SCRATCH: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// `hash_type` mode (low 5 bits, masking off `ANYONECANPAY`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigHashMode {
    /// Default — sign every input and every output.
    All,
    /// Sign no outputs (anyone can change them).
    None,
    /// Sign only the output at the same index as the input being signed.
    Single,
}

/// The signature hash type byte (the trailing byte of a DER+sighash sig).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigHashType(pub u32);

impl SigHashType {
    /// `SIGHASH_ALL`.
    pub const ALL: Self = Self(0x01);
    /// `SIGHASH_NONE`.
    pub const NONE: Self = Self(0x02);
    /// `SIGHASH_SINGLE`.
    pub const SINGLE: Self = Self(0x03);
    /// `SIGHASH_ANYONECANPAY` flag bit, OR-able with the mode.
    pub const ANYONECANPAY: u32 = 0x80;

    /// Decode the mode from the low 5 bits. `ALL`, `NONE`, `SINGLE` are
    /// recognised; everything else maps to `ALL` (consensus behaviour —
    /// Core treats unknown modes as ALL in the legacy preimage; STRICTENC
    /// rejects them at the encoding layer separately).
    #[must_use]
    pub fn mode(self) -> SigHashMode {
        match self.0 & 0x1f {
            2 => SigHashMode::None,
            3 => SigHashMode::Single,
            _ => SigHashMode::All,
        }
    }

    /// `true` if the `ANYONECANPAY` bit is set.
    #[must_use]
    pub fn is_anyonecanpay(self) -> bool {
        self.0 & Self::ANYONECANPAY != 0
    }
}

/// Extension trait on [`Transaction`] grouping the three sighash regimes.
///
/// Methods over free functions per `docs/architecture/script.md` §9: the
/// transaction is the primary `&self`-shaped argument for every signature
/// hash, so the call sites read `tx.legacy_sighash(...)` instead of
/// `signature_hash(tx, ...)`. The trait lives in this module because the
/// `Transaction` type is foreign (it lives in `mantle::primitives`).
pub trait TxSighash {
    /// Legacy (pre-segwit) signature hash. See [`TxSighash::legacy_sighash`]
    /// implementation for the exact preimage construction.
    fn legacy_sighash(&self, n_in: usize, script_code: &[u8], hash_type: SigHashType) -> Hash256;

    /// BIP143 (segwit v0) signature hash. `cache` must have been built from
    /// `self`.
    fn bip143_sighash(
        &self,
        n_in: usize,
        script_code: &[u8],
        amount: Satoshi,
        hash_type: SigHashType,
        cache: &Bip143Cache,
    ) -> Hash256;

    /// BIP341 (taproot) signature hash. `spent_spk` is the scriptPubKey of
    /// the UTXO being spent; `spent_amount` is its value. `annex` is the
    /// optional annex item with the leading `0x50` byte already stripped;
    /// `leaf_hash_code_sep` is `Some` for script-path (tapscript) and `None`
    /// for key-path.
    #[allow(clippy::too_many_arguments)]
    fn bip341_sighash(
        &self,
        n_in: usize,
        spent_amount: Satoshi,
        spent_spk: &[u8],
        hash_type: TaprootSigHashType,
        cache: &Bip341Cache,
        annex: Option<&[u8]>,
        leaf_hash_code_sep: Option<([u8; 32], u32)>,
    ) -> [u8; 32];
}

impl<T: TxView> TxSighash for T {
    /// Legacy signature hash — see module docs §"Legacy" for the algorithm.
    ///
    /// `script_code` is the script being signed — the caller has already
    /// applied `OP_CODESEPARATOR` slicing and `FindAndDelete` of the
    /// signature. Returns the canonical "1" digest if `SIGHASH_SINGLE` is
    /// used with `n_in` past the last output.
    ///
    /// # Panics
    /// Panics if `n_in >= self.input_count()`. Calling code (the interpreter)
    /// only reaches this with a valid input index.
    fn legacy_sighash(&self, n_in: usize, script_code: &[u8], hash_type: SigHashType) -> Hash256 {
        let mode = hash_type.mode();

        // The SIGHASH_SINGLE "1" bug: if `n_in` is at or past the last output,
        // the digest is the canonical 1, not a hash of anything.
        if mode == SigHashMode::Single && n_in >= self.output_count() {
            let mut h = [0u8; 32];
            h[0] = 0x01;
            return Hash256::from_bytes(h);
        }

        // Write the preimage directly into a thread-local scratch buffer,
        // skipping the intermediate modified `Transaction` (which would heap-
        // allocate one `ScriptSig` per input plus a `Vec<TxIn>` per call).
        LEGACY_PREIMAGE_SCRATCH.with(|cell| {
            let mut buf = cell.borrow_mut();
            buf.clear();
            encode_legacy_preimage(self, n_in, script_code, hash_type, &mut buf);
            buf.sha256d()
        })
    }

    /// BIP143 (segwit v0) signature hash — see module docs §"BIP143" for
    /// the per-input layout. `script_code` is the scriptCode for this input
    /// (P2WPKH synthetic or P2WSH witness script); this method prepends the
    /// required `VarInt(len)` length prefix. `cache` must have been built
    /// from the same transaction.
    ///
    /// # Panics
    /// Panics if `n_in >= self.input_count()`.
    fn bip143_sighash(
        &self,
        n_in: usize,
        script_code: &[u8],
        amount: Satoshi,
        hash_type: SigHashType,
        cache: &Bip143Cache,
    ) -> Hash256 {
        let mode = hash_type.mode();
        let anyonecanpay = hash_type.is_anyonecanpay();

        let hash_prevouts = if anyonecanpay {
            Hash256::ZERO
        } else {
            cache.prevouts
        };

        let hash_sequence =
            if anyonecanpay || mode == SigHashMode::Single || mode == SigHashMode::None {
                Hash256::ZERO
            } else {
                cache.sequence
            };

        let hash_outputs = match mode {
            SigHashMode::All => cache.outputs,
            SigHashMode::None => Hash256::ZERO,
            SigHashMode::Single => {
                if n_in < self.output_count() {
                    let out = self.output(n_in);
                    let mut buf: Vec<u8> = Vec::new();
                    buf.extend_from_slice(&out.value().to_le_bytes());
                    let spk = out.script_pubkey();
                    let _ = VarInt::from(spk.len()).encode(&mut buf);
                    buf.extend_from_slice(spk);
                    buf.sha256d()
                } else {
                    Hash256::ZERO
                }
            }
        };

        let input = self.input(n_in);

        let mut buf: Vec<u8> = Vec::with_capacity(200);
        buf.extend_from_slice(&self.version().to_le_bytes());
        buf.extend_from_slice(hash_prevouts.as_bytes());
        buf.extend_from_slice(hash_sequence.as_bytes());
        let _ = input.previous_output().encode(&mut buf);
        let _ = VarInt::from(script_code.len()).encode(&mut buf);
        buf.extend_from_slice(script_code);
        buf.extend_from_slice(&amount.to_le_bytes());
        buf.extend_from_slice(&input.sequence().to_le_bytes());
        buf.extend_from_slice(hash_outputs.as_bytes());
        buf.extend_from_slice(&self.locktime().to_le_bytes());
        buf.extend_from_slice(&hash_type.0.to_le_bytes());

        buf.sha256d()
    }

    /// BIP341 (taproot) signature hash — see [`TxSighash::bip341_sighash`]
    /// trait doc for argument shape. The implementation lives in the
    /// free-standing `compute_bip341_sighash` so the BIP341 preimage
    /// construction reads top-down without trait-method indentation.
    fn bip341_sighash(
        &self,
        n_in: usize,
        spent_amount: Satoshi,
        spent_spk: &[u8],
        hash_type: TaprootSigHashType,
        cache: &Bip341Cache,
        annex: Option<&[u8]>,
        leaf_hash_code_sep: Option<([u8; 32], u32)>,
    ) -> [u8; 32] {
        compute_bip341_sighash(
            self,
            n_in,
            spent_amount,
            spent_spk,
            hash_type,
            cache,
            annex,
            leaf_hash_code_sep,
        )
    }
}

/// Per-transaction cache of the three BIP143 hash fields that are shared
/// across all inputs of a single transaction verification.
///
/// Computing these once up front eliminates the quadratic hashing that
/// plagued legacy sighash when many inputs sign the same tx.
///
/// Create with [`Bip143Cache::new`] before calling [`signature_hash_bip143`]
/// for each input; drop it when the transaction is fully verified.
#[derive(Debug, Clone)]
pub struct Bip143Cache {
    /// `SHA256d` of the concatenation of all input outpoints (36 bytes each).
    /// Zeroed when `ANYONECANPAY` is set.
    prevouts: Hash256,
    /// `SHA256d` of the concatenation of all input `nSequence` values (4 LE each).
    /// Zeroed when `ANYONECANPAY`, `SIGHASH_SINGLE`, or `SIGHASH_NONE` is set.
    sequence: Hash256,
    /// `SHA256d` of the concatenation of all outputs serialised as
    /// `value(8 LE) || scriptPubKey(VarInt len + bytes)`.
    /// Zeroed for `SIGHASH_NONE`; per-input for `SIGHASH_SINGLE`.
    outputs: Hash256,
}

impl Bip143Cache {
    /// Compute the shared hash fields from `tx`. Call once per transaction.
    ///
    /// Accepts any [`TxView`] so both owned [`Transaction`] and borrowed
    /// `TransactionRef` work without materialisation.
    #[must_use]
    pub fn new<T: TxView>(tx: &T) -> Self {
        let n_inputs = tx.input_count();
        let mut prevouts_buf = Vec::with_capacity(n_inputs * 36);
        let mut seq_buf = Vec::with_capacity(n_inputs * 4);
        for input in tx.inputs() {
            let _ = input.previous_output().encode(&mut prevouts_buf);
            seq_buf.extend_from_slice(&input.sequence().to_le_bytes());
        }

        let mut outputs_buf: Vec<u8> = Vec::new();
        for output in tx.outputs() {
            // Output wire form: value(8 LE) || VarInt(spk_len) || spk.
            outputs_buf.extend_from_slice(&output.value().to_le_bytes());
            let spk = output.script_pubkey();
            let _ = VarInt::from(spk.len()).encode(&mut outputs_buf);
            outputs_buf.extend_from_slice(spk);
        }

        Self {
            prevouts: prevouts_buf.sha256d(),
            sequence: seq_buf.sha256d(),
            outputs: outputs_buf.sha256d(),
        }
    }
}

/// Encode the legacy sighash preimage directly into `buf` (which the caller
/// has cleared). The preimage is the wire-form serialisation of the modified
/// transaction described in the module docs §"Legacy", with the 4-byte little-
/// endian `hash_type` appended. SHA-256d of the resulting bytes is the digest.
///
/// Walks `tx` once via the [`TxView`] trait; never materialises the modified
/// transaction. Avoids per-input `script_sig` allocations and the per-call
/// `Vec<TxIn>`/`Vec<TxOut>` allocations the previous `build_modified_tx`
/// construction incurred.
fn encode_legacy_preimage<T: TxView>(
    tx: &T,
    n_in: usize,
    script_code: &[u8],
    hash_type: SigHashType,
    buf: &mut Vec<u8>,
) {
    let mode = hash_type.mode();
    let anyonecanpay = hash_type.is_anyonecanpay();

    // version (4 LE)
    buf.extend_from_slice(&tx.version().to_le_bytes());

    // ── Inputs ──────────────────────────────────────────────────────────────
    if anyonecanpay {
        // Keep only the input being signed.
        let _ = VarInt::new(1).encode(buf);
        let input = tx.input(n_in);
        let _ = input.previous_output().encode(buf);
        let _ = VarInt::from(script_code.len()).encode(buf);
        buf.extend_from_slice(script_code);
        buf.extend_from_slice(&input.sequence().to_le_bytes());
    } else {
        let n_inputs = tx.input_count();
        let _ = VarInt::from(n_inputs).encode(buf);
        for (i, input) in tx.inputs().enumerate() {
            let _ = input.previous_output().encode(buf);
            if i == n_in {
                let _ = VarInt::from(script_code.len()).encode(buf);
                buf.extend_from_slice(script_code);
            } else {
                // Empty scriptSig.
                buf.push(0x00);
            }
            // Under SIGHASH_NONE / SIGHASH_SINGLE, every *other* input's
            // sequence is zeroed so those inputs cannot block re-signing.
            let sequence = match mode {
                SigHashMode::None | SigHashMode::Single if i != n_in => Sequence::new(0),
                _ => input.sequence(),
            };
            buf.extend_from_slice(&sequence.to_le_bytes());
        }
    }

    // ── Outputs ─────────────────────────────────────────────────────────────
    match mode {
        SigHashMode::All => {
            let n_out = tx.output_count();
            let _ = VarInt::from(n_out).encode(buf);
            for output in tx.outputs() {
                buf.extend_from_slice(&output.value().to_le_bytes());
                let spk = output.script_pubkey();
                let _ = VarInt::from(spk.len()).encode(buf);
                buf.extend_from_slice(spk);
            }
        }
        SigHashMode::None => {
            // Zero outputs.
            buf.push(0x00);
        }
        SigHashMode::Single => {
            // Keep outputs up to and including `n_in`; everything before
            // `n_in` is replaced with the "null" output (-1 value, empty
            // scriptPubKey). `n_in >= n_outputs` is short-circuited above.
            let _ = VarInt::from(n_in + 1).encode(buf);
            let null_value: u64 = u64::MAX; // -1 as i64 / u64
            for _ in 0..n_in {
                buf.extend_from_slice(&null_value.to_le_bytes());
                buf.push(0x00); // empty scriptPubKey
            }
            let output = tx.output(n_in);
            buf.extend_from_slice(&output.value().to_le_bytes());
            let spk = output.script_pubkey();
            let _ = VarInt::from(spk.len()).encode(buf);
            buf.extend_from_slice(spk);
        }
    }

    // locktime (4 LE) || hash_type (4 LE)
    buf.extend_from_slice(&tx.locktime().to_le_bytes());
    buf.extend_from_slice(&hash_type.0.to_le_bytes());
}

/// Test-only helper: materialise the modified `Transaction` the legacy
/// preimage represents. Production code uses [`encode_legacy_preimage`]
/// directly into a buffer; this exists only so the existing tests can keep
/// asserting on struct fields rather than serialised bytes.
#[cfg(test)]
fn build_modified_tx(
    tx: &Transaction,
    n_in: usize,
    script_code: &[u8],
    hash_type: SigHashType,
) -> Transaction {
    let mode = hash_type.mode();
    let anyonecanpay = hash_type.is_anyonecanpay();

    let inputs: Vec<TxIn> = if anyonecanpay {
        vec![TxIn {
            previous_output: tx.inputs[n_in].previous_output,
            script_sig: script_code.to_vec().into(),
            sequence: tx.inputs[n_in].sequence,
            witness: Witness::empty(),
        }]
    } else {
        tx.inputs
            .iter()
            .enumerate()
            .map(|(i, txin)| {
                let script_sig = if i == n_in {
                    script_code.to_vec().into()
                } else {
                    Vec::<u8>::new().into()
                };
                let sequence = match mode {
                    SigHashMode::None | SigHashMode::Single if i != n_in => Sequence::new(0),
                    _ => txin.sequence,
                };
                TxIn {
                    previous_output: txin.previous_output,
                    script_sig,
                    sequence,
                    witness: Witness::empty(),
                }
            })
            .collect()
    };

    let outputs: Vec<TxOut> = match mode {
        SigHashMode::All => tx.outputs.clone(),
        SigHashMode::None => Vec::new(),
        SigHashMode::Single => {
            let mut out = Vec::with_capacity(n_in + 1);
            for _ in 0..n_in {
                out.push(TxOut {
                    value: Satoshi::new(u64::MAX),
                    script_pubkey: Vec::<u8>::new().into(),
                });
            }
            out.push(tx.outputs[n_in].clone());
            out
        }
    };

    Transaction {
        version: tx.version,
        inputs,
        outputs,
        locktime: tx.locktime,
    }
}

/// Apply BIP-style `FindAndDelete` of `sig` from `script`.
///
/// The legacy sighash subroutine removes every push of the signature being
/// checked from the `scriptCode` before hashing. The match is a *pushdata*
/// match: a push opcode whose payload exactly equals `sig`, found at a
/// script-program boundary. Bytes that happen to contain `sig`'s pattern
/// inside another push body are not removed.
///
/// This matches Core's `FindAndDelete`: walk the script, copy every push or
/// opcode unchanged unless the entire pushed payload byte-for-byte matches
/// `sig`. Non-push opcodes are copied as-is.
///
/// Returns the script with all matching pushes removed.
#[must_use]
pub fn find_and_delete_sig(script: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(script.len());
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        // Determine the (data_start, data_end) span pushed by this opcode, if any.
        let span = pushed_span(script, i);
        if let Some((data_start, data_end, op_end)) = span {
            if &script[data_start..data_end] == sig {
                // Skip this push entirely.
                i = op_end;
                continue;
            }
            // Copy the whole opcode + payload.
            out.extend_from_slice(&script[i..op_end]);
            i = op_end;
        } else {
            // Non-push opcode: copy one byte.
            out.push(op);
            i += 1;
        }
    }
    out
}

/// If `script[i]` is a push opcode, return `(data_start, data_end, op_end)`
/// — the absolute byte indices of the pushed payload and one past the
/// last consumed byte. Returns `None` for non-push opcodes or truncated
/// pushes (truncated pushes are passed through as a single byte in
/// `find_and_delete_sig`, mirroring Core's tolerant parser there).
fn pushed_span(script: &[u8], i: usize) -> Option<(usize, usize, usize)> {
    let op = script[i];
    // OP_0 (0x00) falls through to the wildcard `None` — `FindAndDelete` only
    // matches non-empty data pushes, so OP_0 is treated as a regular opcode.
    match op {
        // 0x01..=0x4b: direct push of N bytes.
        n @ 0x01..=0x4b => {
            let len = usize::from(n);
            let data_start = i + 1;
            let data_end = data_start + len;
            if data_end > script.len() {
                None
            } else {
                Some((data_start, data_end, data_end))
            }
        }
        // OP_PUSHDATA1
        0x4c => {
            if i + 1 >= script.len() {
                return None;
            }
            let len = usize::from(script[i + 1]);
            let data_start = i + 2;
            let data_end = data_start + len;
            if data_end > script.len() {
                None
            } else {
                Some((data_start, data_end, data_end))
            }
        }
        // OP_PUSHDATA2
        0x4d => {
            if i + 2 >= script.len() {
                return None;
            }
            let len = usize::from(u16::from_le_bytes([script[i + 1], script[i + 2]]));
            let data_start = i + 3;
            let data_end = data_start + len;
            if data_end > script.len() {
                None
            } else {
                Some((data_start, data_end, data_end))
            }
        }
        // OP_PUSHDATA4
        0x4e => {
            if i + 4 >= script.len() {
                return None;
            }
            let len =
                u32::from_le_bytes([script[i + 1], script[i + 2], script[i + 3], script[i + 4]])
                    as usize;
            let data_start = i + 5;
            let data_end = data_start + len;
            if data_end > script.len() {
                None
            } else {
                Some((data_start, data_end, data_end))
            }
        }
        _ => None,
    }
}

/// Slice a script at the byte offset of the last `OP_CODESEPARATOR`.
///
/// `code_separator_pos` is the byte index of the *next* byte after the
/// `OP_CODESEPARATOR` (or 0 if none has executed yet — the whole script is
/// the scriptCode). Returns the suffix of `script` from that position.
#[must_use]
pub fn script_code_after_codeseparator(script: &[u8], code_separator_pos: usize) -> &[u8] {
    if code_separator_pos > script.len() {
        return &[];
    }
    &script[code_separator_pos..]
}

// ── codec helpers ──────────────────────────────────────────────────────────
// `encoded_len` is on `Transaction` already; we route through it to avoid
// a second size pass. `Vec<u8>` conversion of script_sig/script_pubkey is
// needed because `ScriptSig` / `ScriptPubKey` round-trip via `Vec<u8>`.

// ── BIP341 sighash ─────────────────────────────────────────────────────────

/// BIP341 `hash_type` for taproot/tapscript.
///
/// - `0x00` → `SIGHASH_DEFAULT` (same as ALL but only valid in 64-byte form)
/// - `0x01` → `SIGHASH_ALL`
/// - `0x02` → `SIGHASH_NONE`
/// - `0x03` → `SIGHASH_SINGLE`
/// - `0x81` → `SIGHASH_ALL | ANYONECANPAY`
/// - `0x82` → `SIGHASH_NONE | ANYONECANPAY`
/// - `0x83` → `SIGHASH_SINGLE | ANYONECANPAY`
///
/// All other values are invalid under BIP341.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaprootSigHashType(pub u8);

impl TaprootSigHashType {
    pub const DEFAULT: Self = Self(0x00);
    pub const ALL: Self = Self(0x01);
    pub const NONE: Self = Self(0x02);
    pub const SINGLE: Self = Self(0x03);
    pub const ALL_ANYONECANPAY: Self = Self(0x81);
    pub const NONE_ANYONECANPAY: Self = Self(0x82);
    pub const SINGLE_ANYONECANPAY: Self = Self(0x83);

    /// `true` if `ANYONECANPAY` bit is set (bit 7).
    #[must_use]
    pub const fn is_anyonecanpay(self) -> bool {
        self.0 & 0x80 != 0
    }

    /// Output coverage mode (low 2 bits, after stripping ANYONECANPAY).
    #[must_use]
    pub const fn output_mode(self) -> SigHashMode {
        match self.0 & 0x03 {
            0x02 => SigHashMode::None,
            0x03 => SigHashMode::Single,
            _ => SigHashMode::All, // 0x00 (DEFAULT) and 0x01 (ALL) both → All
        }
    }

    /// `true` iff this is a valid BIP341 hash type.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        matches!(self.0, 0x00 | 0x01 | 0x02 | 0x03 | 0x81 | 0x82 | 0x83)
    }
}

/// Per-transaction cache for the five BIP341 shared hash fields.
///
/// BIP341 sighash commits to *all* input outpoints, amounts, scriptPubKeys,
/// sequences, and (for non-ANYONECANPAY) all outputs. Pre-hashing them once
/// per transaction eliminates the quadratic work of legacy sighash.
#[derive(Debug, Clone)]
pub struct Bip341Cache {
    /// `SHA256(outpoint_0 || … || outpoint_{n-1})`
    prevouts: [u8; 32],
    /// `SHA256(amount_0 || … || amount_{n-1})`
    amounts: [u8; 32],
    /// `SHA256(spk_0 || … || spk_{n-1})`  (each prefixed with `VarInt` len)
    scriptpubkeys: [u8; 32],
    /// `SHA256(seq_0 || … || seq_{n-1})`
    sequences: [u8; 32],
    /// `SHA256(out_0 || … || out_{m-1})`
    outputs: [u8; 32],
}

impl Bip341Cache {
    /// Build the cache from the transaction and the scriptPubKeys of every
    /// input's spent output. `spent_spks[i]` is the scriptPubKey of the
    /// output that input `i` spends.
    ///
    /// Accepts any [`TxView`].
    ///
    /// # Panics
    /// Panics if `spent_spks.len() != tx.input_count()`.
    #[must_use]
    pub fn new<T: TxView>(tx: &T, spent_amounts: &[Satoshi], spent_spks: &[&[u8]]) -> Self {
        assert_eq!(spent_amounts.len(), tx.input_count());
        assert_eq!(spent_spks.len(), tx.input_count());

        let hash_prevouts: [u8; 32] = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            for inp in tx.inputs() {
                let mut buf = Vec::with_capacity(36);
                let _ = inp.previous_output().encode(&mut buf);
                h.update(&buf);
            }
            h.finalize().into()
        };

        let hash_amounts: [u8; 32] = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            for &amt in spent_amounts {
                h.update(amt.to_le_bytes());
            }
            h.finalize().into()
        };

        let hash_scriptpubkeys: [u8; 32] = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            for spk in spent_spks {
                let mut buf = Vec::new();
                let _ = VarInt::from(spk.len()).encode(&mut buf);
                h.update(&buf);
                h.update(spk);
            }
            h.finalize().into()
        };

        let hash_sequences: [u8; 32] = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            for inp in tx.inputs() {
                h.update(inp.sequence().to_le_bytes());
            }
            h.finalize().into()
        };

        let hash_outputs: [u8; 32] = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            for out in tx.outputs() {
                let mut buf = Vec::new();
                buf.extend_from_slice(&out.value().to_le_bytes());
                let spk = out.script_pubkey();
                let _ = VarInt::from(spk.len()).encode(&mut buf);
                buf.extend_from_slice(spk);
                h.update(&buf);
            }
            h.finalize().into()
        };

        Self {
            prevouts: hash_prevouts,
            amounts: hash_amounts,
            scriptpubkeys: hash_scriptpubkeys,
            sequences: hash_sequences,
            outputs: hash_outputs,
        }
    }
}

/// Compute the BIP341 sighash for a taproot input. Backing impl for
/// [`TxSighash::bip341_sighash`]; not exposed publicly because the trait
/// method is the supported entry point.
///
/// `spent_spk` is the scriptPubKey of the output being spent by
/// `tx.inputs[n_in]`. `spent_amount` is its value.
///
/// `annex` is the optional annex item (the witness item starting with
/// `0x50`), already stripped of its leading byte — pass `None` if no annex
/// is present.
///
/// For key-path spends, `leaf_hash_code_sep` is `None`. For script-path
/// (tapscript) spends, `leaf_hash_code_sep` is `Some((leaf_hash, code_sep_pos))`
/// where `leaf_hash` is `tagged_hash("TapLeaf", version || compact_size(script) || script)`
/// and `code_sep_pos` is `0xFFFF_FFFF` if no `OP_CODESEPARATOR` has been seen.
///
/// # Panics
/// Panics if `n_in >= tx.inputs.len()`.
#[must_use]
#[allow(clippy::too_many_arguments)]
fn compute_bip341_sighash<T: TxView>(
    tx: &T,
    n_in: usize,
    spent_amount: Satoshi,
    spent_spk: &[u8],
    hash_type: TaprootSigHashType,
    cache: &Bip341Cache,
    annex: Option<&[u8]>,
    leaf_hash_code_sep: Option<([u8; 32], u32)>,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let anyonecanpay = hash_type.is_anyonecanpay();
    let out_mode = hash_type.output_mode();

    // Epoch byte (BIP341 §Common signature message): always 0x00.
    let epoch: u8 = 0x00;

    let mut preimage: Vec<u8> = Vec::with_capacity(256);

    // epoch
    preimage.push(epoch);
    // hash_type
    preimage.push(hash_type.0);
    // nVersion (4 LE)
    preimage.extend_from_slice(&tx.version().to_le_bytes());
    // nLocktime (4 LE)
    preimage.extend_from_slice(&tx.locktime().to_le_bytes());

    // Shared input hashes — omitted under ANYONECANPAY.
    if !anyonecanpay {
        preimage.extend_from_slice(&cache.prevouts);
        preimage.extend_from_slice(&cache.amounts);
        preimage.extend_from_slice(&cache.scriptpubkeys);
        preimage.extend_from_slice(&cache.sequences);
    }

    // Shared outputs hash — only emitted for ALL/DEFAULT. SINGLE has its own
    // sha_single_output appended *after* the per-input data and annex (below);
    // NONE has no output commitment at all.
    if out_mode == SigHashMode::All {
        preimage.extend_from_slice(&cache.outputs);
    }

    // Spend type byte: bit 0 = has annex, bit 1 = script-path.
    let has_annex = annex.is_some();
    let is_script_path = leaf_hash_code_sep.is_some();
    let spend_type: u8 = (u8::from(has_annex)) | (u8::from(is_script_path) << 1);
    preimage.push(spend_type);

    // Per-input data.
    if anyonecanpay {
        let inp = tx.input(n_in);
        let mut ob = Vec::with_capacity(36);
        let _ = inp.previous_output().encode(&mut ob);
        preimage.extend_from_slice(&ob);
        preimage.extend_from_slice(&spent_amount.to_le_bytes());
        let mut spk_buf = Vec::new();
        let _ = VarInt::from(spent_spk.len()).encode(&mut spk_buf);
        preimage.extend_from_slice(&spk_buf);
        preimage.extend_from_slice(spent_spk);
        preimage.extend_from_slice(&inp.sequence().to_le_bytes());
    } else {
        // Input index (4 LE).
        preimage.extend_from_slice(&u32::try_from(n_in).unwrap_or(u32::MAX).to_le_bytes());
    }

    // Annex hash: SHA256(compact_size(len) || annex_bytes).
    if let Some(annex_bytes) = annex {
        let mut buf = Vec::new();
        let _ = VarInt::new((annex_bytes.len() as u64) + 1).encode(&mut buf); // +1 for the 0x50 prefix byte
        buf.push(0x50);
        buf.extend_from_slice(annex_bytes);
        let h: [u8; 32] = Sha256::digest(&buf).into();
        preimage.extend_from_slice(&h);
    }

    // sha_single_output: emitted *after* annex hash for SIGHASH_SINGLE only.
    // BIP341 §"Common signature message extension". When `n_in >= n_outputs`,
    // nothing is appended (this is not the legacy "SIGHASH_SINGLE 1 bug" —
    // BIP341 simply omits the field).
    if out_mode == SigHashMode::Single && n_in < tx.output_count() {
        let out = tx.output(n_in);
        let mut buf = Vec::new();
        buf.extend_from_slice(&out.value().to_le_bytes());
        let spk = out.script_pubkey();
        let _ = VarInt::from(spk.len()).encode(&mut buf);
        buf.extend_from_slice(spk);
        let h: [u8; 32] = Sha256::digest(&buf).into();
        preimage.extend_from_slice(&h);
    }

    // Script-path extension.
    if let Some((leaf_hash, code_sep_pos)) = leaf_hash_code_sep {
        preimage.extend_from_slice(&leaf_hash);
        preimage.extend_from_slice(&code_sep_pos.to_le_bytes());
    }

    Schnorr::tagged_hash(b"TapSighash", &preimage)
}

/// BIP341 taproot hash helpers — leaf, branch, and output-key tweak.
///
/// All methods are associated (no `self`) because they operate on raw byte
/// slices rather than any persistent state. Grouped as a struct to satisfy
/// the project guideline against free functions.
pub struct TapHasher;

impl TapHasher {
    /// `tagged_hash("TapLeaf", leaf_version || compact_size(len) || script)`.
    ///
    /// `leaf_version` is typically `0xC0`.
    #[must_use]
    pub fn leaf(leaf_version: u8, script: &[u8]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(1 + 9 + script.len());
        buf.push(leaf_version);
        let mut vint = Vec::new();
        let _ = VarInt::from(script.len()).encode(&mut vint);
        buf.extend_from_slice(&vint);
        buf.extend_from_slice(script);
        Schnorr::tagged_hash(b"TapLeaf", &buf)
    }

    /// `tagged_hash("TapBranch", left || right)`.
    ///
    /// BIP341 uses caller-ordered (non-auto-sorted) branch hashing.
    #[must_use]
    pub fn branch(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(left);
        buf[32..].copy_from_slice(right);
        Schnorr::tagged_hash(b"TapBranch", &buf)
    }

    /// Compute the BIP341 tweaked output key.
    ///
    /// `tweak = tagged_hash("TapTweak", internal_key || merkle_root)`
    /// `output_key = internal_key_point + tweak * G`  (x-only result).
    ///
    /// For key-path-only outputs pass an empty `merkle_root`.
    /// Returns `None` if `internal_key` is not a valid secp256k1 x-only point.
    #[must_use]
    pub fn tweak_output_key(internal_key: &[u8; 32], merkle_root: &[u8]) -> Option<[u8; 32]> {
        use k256::elliptic_curve::bigint::Encoding;
        use k256::elliptic_curve::ops::Reduce;
        use k256::elliptic_curve::point::AffineCoordinates;
        use k256::schnorr::VerifyingKey as SchnorrVK;
        use k256::{ProjectivePoint, Scalar, U256};

        let internal_vk = SchnorrVK::from_bytes(internal_key.into()).ok()?;
        let internal_point: ProjectivePoint = (*internal_vk.as_affine()).into();

        let mut tweak_input = Vec::with_capacity(64);
        tweak_input.extend_from_slice(internal_key);
        tweak_input.extend_from_slice(merkle_root);
        let tweak_hash = Schnorr::tagged_hash(b"TapTweak", &tweak_input);

        let tweak_scalar =
            <Scalar as Reduce<U256>>::reduce(&U256::from_be_bytes(tweak_hash.into()));
        let output_point = internal_point + ProjectivePoint::mul_by_generator(&tweak_scalar);
        let x: [u8; 32] = output_point.to_affine().x().into();
        Some(x)
    }
}

#[cfg(test)]
mod tests;
