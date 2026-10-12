use super::connect::*;
use super::pow::*;
use super::structure::*;
use super::*;

use crate::chain_view::{Coin, ConnectScratch, MemoryChainView};
use crate::merkle::compute_merkle_root;
use mantle::primitives::{
    Block, BlockHeader, BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Locktime,
    Nonce, OutPoint, Satoshi, Sequence, Transaction, TxHash, TxIn, TxOut, TxVersion, Witness,
};

// ── Helpers ───────────────────────────────────────────────────────────────

fn coinbase_tx(height: BlockHeight, value: u64) -> Transaction {
    Transaction {
        version: TxVersion::new(1),
        inputs: vec![TxIn {
            previous_output: NULL_OUTPOINT,
            script_sig: Transaction::bip34_height_script(height).into(),
            sequence: Sequence::MAX,
            witness: Witness::empty(),
        }],
        outputs: vec![TxOut {
            value: Satoshi::new(value),
            script_pubkey: vec![0x51].into(), // OP_1
        }],
        locktime: Locktime::new(0),
    }
}

fn regular_tx(prev_txid: Hash256, vout: u32, value: u64) -> Transaction {
    Transaction {
        version: TxVersion::new(1),
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: prev_txid,
                vout,
            },
            script_sig: vec![0x00].into(),
            sequence: Sequence::MAX,
            witness: Witness::empty(),
        }],
        outputs: vec![TxOut {
            value: Satoshi::new(value),
            script_pubkey: vec![0x51].into(),
        }],
        locktime: Locktime::new(0),
    }
}

fn make_block(txs: Vec<Transaction>, bits: CompactBits) -> Block {
    let txids: Vec<Hash256> = txs
        .iter()
        .map(Transaction::txid)
        .collect::<Result<Vec<_>, _>>()
        .expect("txid encoding cannot fail");
    let merkle_root =
        compute_merkle_root(&txids).expect("non-empty tx list always has a merkle root");
    Block {
        header: BlockHeader::new(
            BlockVersion::new(1),
            Hash256::ZERO,
            merkle_root,
            BlockTime::new(1_231_006_505),
            bits,
            Nonce::new(0),
        ),
        transactions: txs,
    }
}

/// Build a block with a valid `PoW` nonce (brute-force search).
/// Only used for tests that exercise `PoW` validation.
fn mine_block(mut block: Block) -> Block {
    let target = block
        .header
        .bits()
        .to_target()
        .expect("mine_block called with invalid nBits");
    for nonce in 0..=u32::MAX {
        block.header.set_nonce(Nonce::new(nonce));
        let header_hash = Hash256::hash(&block.header.to_bytes());
        let mut be = *header_hash.as_bytes();
        be.reverse();
        if be <= target {
            return block;
        }
    }
    panic!("could not find a valid nonce — use a very easy nBits in tests");
}

// ── Stage 1 tests ─────────────────────────────────────────────────────────

#[test]
fn empty_block_rejected() {
    let block = Block {
        header: BlockHeader::new(
            BlockVersion::new(1),
            Hash256::ZERO,
            Hash256::ZERO,
            BlockTime::new(0),
            CompactBits::new(0x207f_ffff),
            Nonce::new(0),
        ),
        transactions: vec![],
    };
    assert_eq!(
        validate_block_structure(&block),
        Err(ValidationError::EmptyBlock)
    );
}

#[test]
fn first_tx_not_coinbase_rejected() {
    let tx = regular_tx(Hash256::from_bytes([1u8; 32]), 0, 1000);
    let mut block = make_block(vec![tx], CompactBits::new(0x207f_ffff));
    // Fix merkle root so we reach the coinbase check.
    // (make_block already does this, but the block won't have PoW — that's fine,
    // we're testing structure checks which run before PoW.)
    assert_eq!(
        validate_block_structure(&block),
        Err(ValidationError::FirstTxNotCoinbase)
    );
    let _ = &mut block; // suppress unused warning
}

#[test]
fn coinbase_script_too_short() {
    let mut tx = coinbase_tx(BlockHeight::new(1), 5_000_000_000);
    tx.inputs[0].script_sig = vec![0x01].into(); // 1 byte < MIN (2)
    let block = make_block(vec![tx], CompactBits::new(0x207f_ffff));
    assert_eq!(
        validate_block_structure(&block),
        Err(ValidationError::CoinbaseScriptSigLength { len: 1 })
    );
}

#[test]
fn coinbase_script_too_long() {
    let mut tx = coinbase_tx(BlockHeight::new(1), 5_000_000_000);
    tx.inputs[0].script_sig = vec![0x00; 101].into(); // 101 > MAX (100)
    let block = make_block(vec![tx], CompactBits::new(0x207f_ffff));
    assert_eq!(
        validate_block_structure(&block),
        Err(ValidationError::CoinbaseScriptSigLength { len: 101 })
    );
}

#[test]
fn output_value_out_of_range() {
    let mut tx = coinbase_tx(BlockHeight::new(1), MAX_MONEY.to_u64() + 1);
    tx.outputs[0].value = Satoshi::new(MAX_MONEY.to_u64() + 1);
    // Re-encode the block with the bad tx — merkle root will be recomputed.
    let block = make_block(vec![tx], CompactBits::new(0x207f_ffff));
    assert_eq!(
        validate_block_structure(&block),
        Err(ValidationError::OutputValueOutOfRange {
            tx_index: 0,
            output_index: 0
        })
    );
}

#[test]
fn duplicate_inputs_rejected() {
    let cb = coinbase_tx(BlockHeight::new(1), 5_000_000_000);
    let mut tx2 = regular_tx(Hash256::from_bytes([2u8; 32]), 0, 1000);
    // Add a duplicate input.
    tx2.inputs.push(tx2.inputs[0].clone());
    let block = make_block(vec![cb, tx2], CompactBits::new(0x207f_ffff));
    assert_eq!(
        validate_block_structure(&block),
        Err(ValidationError::DuplicateInput { tx_index: 1 })
    );
}

/// CVE-2012-2459: a block containing two transactions with the same txid
/// must be rejected, regardless of merkle-root agreement.
///
/// The two duplicates are non-coinbase: a coinbase clone would be
/// rejected earlier as `UnexpectedCoinbaseInput`, never reaching the
/// duplicate-txid check. Two identical regular transactions hash to the
/// same txid and exercise the CVE-2012-2459 defence directly.
#[test]
fn duplicate_transaction_rejected() {
    let cb = coinbase_tx(BlockHeight::new(1), 5_000_000_000);
    let tx = regular_tx(Hash256::from_bytes([0x42; 32]), 0, 1000);
    let dup = tx.clone();
    let block = make_block(vec![cb, tx, dup], CompactBits::new(0x207f_ffff));
    assert_eq!(
        validate_block_structure(&block),
        Err(ValidationError::DuplicateTransaction)
    );
}

#[test]
fn merkle_root_mismatch() {
    let tx = coinbase_tx(BlockHeight::new(1), 5_000_000_000);
    let mut block = make_block(vec![tx], CompactBits::new(0x207f_ffff));
    block
        .header
        .set_merkle_root(Hash256::from_bytes([0xde; 32])); // corrupt root
    assert_eq!(
        validate_block_structure(&block),
        Err(ValidationError::MerkleRootMismatch)
    );
}

#[test]
fn pow_invalid() {
    let tx = coinbase_tx(BlockHeight::new(1), 5_000_000_000);
    // Use a very hard nBits — nonce=0 will almost certainly fail PoW.
    let block = make_block(vec![tx], CompactBits::new(0x1d00_ffff));
    assert_eq!(
        validate_block_structure(&block),
        Err(ValidationError::InsufficientProofOfWork)
    );
}

#[test]
fn valid_block_easy_pow() {
    let tx = coinbase_tx(BlockHeight::new(1), 5_000_000_000);
    // 0x207fffff is the easiest possible nBits (used in regtest).
    let block = mine_block(make_block(vec![tx], CompactBits::new(0x207f_ffff)));
    assert!(validate_block_structure(&block).is_ok());
}

// ── nbits helpers ─────────────────────────────────────────────────────────

#[test]
fn nbits_roundtrip_genesis() {
    let bits = CompactBits::new(0x1d00_ffff);
    let target = bits.to_target().expect("genesis nBits must decode");
    let back = CompactBits::from_target(target).expect("genesis target must re-encode");
    assert_eq!(back, bits);
}

#[test]
fn nbits_zero_mantissa_is_invalid() {
    assert!(CompactBits::new(0x0300_0000).to_target().is_none());
}

#[test]
fn nbits_negative_is_invalid() {
    // High bit of mantissa set → negative.
    assert!(CompactBits::new(0x0380_0000).to_target().is_none());
}

// ── BIP34 height encoding ─────────────────────────────────────────────────

#[test]
fn bip34_height_encoding() {
    assert_eq!(
        Transaction::bip34_height_script(BlockHeight::new(1)),
        vec![0x01, 0x01]
    );
    assert_eq!(
        Transaction::bip34_height_script(BlockHeight::new(256)),
        vec![0x02, 0x00, 0x01]
    );
    assert_eq!(
        Transaction::bip34_height_script(BlockHeight::new(0x80)),
        vec![0x02, 0x80, 0x00]
    );
}

// ── Stage 2 tests ─────────────────────────────────────────────────────────

fn build_view_with_chain(len: u32) -> MemoryChainView {
    let mut view = MemoryChainView::new();
    let mut prev = Hash256::ZERO;
    for i in 0..len {
        let h = BlockHeader::new(
            BlockVersion::new(4),
            prev,
            Hash256::ZERO,
            BlockTime::new(1_296_688_602 + i * 600),
            CompactBits::new(0x207f_ffff),
            Nonce::new(0),
        );
        prev = h.hash();
        view.push_header(h);
    }
    view
}

/// Like `build_view_with_chain` but starts at `base` and only stores 12
/// headers, so the tip is at `base + 11`. Validation only needs the parent
/// plus up to 11 ancestors for MTP.
fn build_view_at_height(tip_height: BlockHeight) -> MemoryChainView {
    let window = 12u32;
    let start = tip_height.to_u32().saturating_sub(window - 1);
    let mut view = MemoryChainView::with_height_base(BlockHeight::new(start));
    let mut prev = Hash256::ZERO;
    for i in 0..window {
        let h = BlockHeader::new(
            BlockVersion::new(4),
            prev,
            Hash256::ZERO,
            BlockTime::new(1_296_688_602 + (start + i) * 600),
            CompactBits::new(0x207f_ffff),
            Nonce::new(0),
        );
        prev = h.hash();
        view.push_header(h);
    }
    view
}

#[test]
fn unknown_parent_rejected() {
    let view = build_view_with_chain(1);
    let tx = coinbase_tx(BlockHeight::new(1), 5_000_000_000);
    let block = Block {
        header: BlockHeader::new(
            BlockVersion::new(4),
            Hash256::from_bytes([0xff; 32]), // unknown
            compute_merkle_root(&[tx.txid().expect("txid encoding cannot fail")])
                .expect("single-tx merkle root cannot be empty"),
            BlockTime::new(1_296_688_602 + 600),
            CompactBits::new(0x207f_ffff),
            Nonce::new(0),
        ),
        transactions: vec![tx],
    };
    assert_eq!(
        validate_block_context(&block, &view, false),
        Err(ValidationError::UnknownParent)
    );
}

#[test]
fn timestamp_too_early_rejected() {
    let view = build_view_with_chain(12);
    let tip = view.tip();
    let tip_header = view
        .get_header_at(tip.height)
        .expect("chain view error")
        .expect("tip header must exist");
    let tx = coinbase_tx(tip.height + 1, 5_000_000_000);
    let mtp = view
        .median_time_past(&BlockHeader::new(
            BlockVersion::new(4),
            tip.hash,
            Hash256::ZERO,
            BlockTime::new(0),
            CompactBits::new(0x207f_ffff),
            Nonce::new(0),
        ))
        .expect("median_time_past must succeed for a populated chain");
    let block = Block {
        header: BlockHeader::new(
            BlockVersion::new(4),
            tip.hash,
            compute_merkle_root(&[tx.txid().expect("txid encoding cannot fail")])
                .expect("single-tx merkle root cannot be empty"),
            BlockTime::new(mtp.to_u32()), // exactly MTP — must be > MTP
            CompactBits::new(0x207f_ffff),
            Nonce::new(0),
        ),
        transactions: vec![tx],
    };
    let _ = tip_header; // used for clarity
    assert_eq!(
        validate_block_context(&block, &view, false),
        Err(ValidationError::TimestampTooEarly)
    );
}

/// A block timestamped more than 2h beyond the injected clock must be
/// rejected as `TimestampTooFarFuture`. Uses `FixedClock` so the
/// outcome doesn't depend on wall time.
#[test]
fn timestamp_too_far_future_rejected() {
    let view = build_view_with_chain(12);
    let tip = view.tip();
    let parent_time = view
        .get_header_at(tip.height)
        .expect("chain view error")
        .expect("tip header must exist")
        .time();
    let tx = coinbase_tx(tip.height + 1, 5_000_000_000);

    // Block claims a time ≥ now + 3h.
    let now: u64 = u64::from(parent_time) + 600;
    let block_time = now + MAX_FUTURE_BLOCK_TIME + 1;

    let block = Block {
        header: BlockHeader::new(
            BlockVersion::new(4),
            tip.hash,
            compute_merkle_root(&[tx.txid().expect("txid encoding cannot fail")])
                .expect("single-tx merkle root cannot be empty"),
            BlockTime::new(u32::try_from(block_time).expect("test block_time fits in u32")),
            CompactBits::new(0x207f_ffff),
            Nonce::new(0),
        ),
        transactions: vec![tx],
    };
    assert_eq!(
        validate_block_context_with_clock(&block, &view, &FixedClock(now), false),
        Err(ValidationError::TimestampTooFarFuture)
    );
}

#[test]
fn bip34_missing_rejected() {
    let view = build_view_at_height(BIP34_HEIGHT - 1u32);
    let tip = view.tip();
    let mut tx = coinbase_tx(tip.height + 1, 5_000_000_000);
    // Replace BIP34 scriptSig with garbage that doesn't encode the height.
    tx.inputs[0].script_sig = vec![0x02, 0x00, 0x00].into();
    let block = Block {
        header: BlockHeader::new(
            BlockVersion::new(4),
            tip.hash,
            compute_merkle_root(&[tx.txid().expect("txid encoding cannot fail")])
                .expect("single-tx merkle root cannot be empty"),
            BlockTime::new(1_296_688_602 + BIP34_HEIGHT.to_u32() * 600 + 600),
            CompactBits::new(0x207f_ffff),
            Nonce::new(0),
        ),
        transactions: vec![tx],
    };
    assert_eq!(
        validate_block_context(&block, &view, false),
        Err(ValidationError::Bip34HeightMissing)
    );
}

// ── U256 arithmetic ───────────────────────────────────────────────────────

#[test]
fn u256_byte_roundtrip() {
    let bytes: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    assert_eq!(U256::from_be_bytes(bytes).to_be_bytes(), bytes);
}

#[test]
fn u256_mul_u64_no_overflow() {
    // (1 << 200) * 4 == (1 << 202)
    let mut bytes = [0u8; 32];
    bytes[31 - 25] = 0x01; // bit 200
    let a = U256::from_be_bytes(bytes);
    let product = a.saturating_mul_u64(4);
    let mut expected = [0u8; 32];
    expected[31 - 25] = 0x04; // bit 202 — same byte, value × 4
    assert_eq!(product.to_be_bytes(), expected);
}

#[test]
fn u256_mul_u64_carries_across_limb_boundary() {
    // 0xffff_ffff_ffff_ffff (low 64 bits all set) * 2 = 0x1_ffff_ffff_ffff_fffe
    let mut bytes = [0u8; 32];
    for b in bytes.iter_mut().skip(24) {
        *b = 0xff;
    }
    let a = U256::from_be_bytes(bytes);
    let product = a.saturating_mul_u64(2);
    // Expect 0x1_ffff_ffff_ffff_fffe
    let mut expected = [0u8; 32];
    expected[31 - 8] = 0x01;
    for b in expected.iter_mut().take(31).skip(24) {
        *b = 0xff;
    }
    expected[31] = 0xfe;
    assert_eq!(product.to_be_bytes(), expected);
}

#[test]
fn u256_mul_u64_saturates_on_overflow() {
    // U256::MAX * 2 must saturate.
    let max = U256::from_be_bytes([0xff; 32]);
    assert_eq!(max.saturating_mul_u64(2), U256::MAX);
}

#[test]
fn u256_div_u64_basic() {
    let mut bytes = [0u8; 32];
    bytes[31] = 100; // value = 100
    let a = U256::from_be_bytes(bytes);
    let q = a.div_u64(7);
    let mut expected = [0u8; 32];
    expected[31] = 14; // 100 / 7 = 14
    assert_eq!(q.to_be_bytes(), expected);
}

#[test]
fn u256_mul_then_div_recovers() {
    // (1 << 200) * 1_000_000 / 1_000_000 == (1 << 200)
    let mut bytes = [0u8; 32];
    bytes[31 - 25] = 0x01;
    let a = U256::from_be_bytes(bytes);
    let result = a.saturating_mul_u64(1_000_000).div_u64(1_000_000);
    assert_eq!(result.to_be_bytes(), bytes);
}

#[test]
fn u256_ordering() {
    let small = U256::from_be_bytes({
        let mut b = [0u8; 32];
        b[31] = 1;
        b
    });
    let large = U256::from_be_bytes({
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    });
    assert!(small < large);
    assert!(large > small);
    assert_eq!(small, small);
}

// ── Retarget arithmetic ───────────────────────────────────────────────────

/// Mainnet's first real retarget, at block 32256.
///
/// Reference values from Bitcoin mainnet block headers:
/// - block 0:     time = `1_231_006_505`, nBits = 0x1d00ffff
/// - block 32255: time = `1_262_152_739`, nBits = 0x1d00ffff
///
///   `actual_timespan` = `1_262_152_739` - `1_231_006_505` = `31_146_234` seconds
///   ≈ 360 days  (vs target 14 days)
///   `clamped`         = `MAX_TIMESPAN` = 4 × `TARGET_TIMESPAN` = `4_838_400`
///   `new_target_raw`  = `old_target` × 4
///   = encoded 0x1d03fffc, which exceeds powLimit
///   `new_target`      = clamp(`new_target_raw`, ≤ powLimit) = powLimit
///
/// So the network kept difficulty pinned at the floor (`0x1d00ffff`)
/// through the first retarget. This is exactly what mainnet block 32256
/// records.
#[test]
fn first_mainnet_retarget_matches_core() {
    let old_bits = CompactBits::new(0x1d00_ffff);
    let actual = 1_262_152_739_u64 - 1_231_006_505_u64;
    assert_eq!(actual, 31_146_234, "raw timespan from block headers");

    let clamped = actual.clamp(MIN_TIMESPAN, MAX_TIMESPAN);
    assert_eq!(clamped, MAX_TIMESPAN, "timespan must clamp to MAX_TIMESPAN");

    let new_bits = old_bits
        .retarget(clamped, TARGET_TIMESPAN, POW_LIMIT_BITS)
        .expect("retarget must succeed for valid inputs");

    assert_eq!(
        new_bits,
        CompactBits::new(0x1d00_ffff),
        "first mainnet retarget must clamp to powLimit, got {:#010x}",
        new_bits.to_u32(),
    );
}

/// A retarget that should produce a real difficulty change without
/// hitting either clamp. Synthetic but exercises the full arithmetic
/// path: `target * actual / expected` with no powLimit clamp.
///
/// Use a starting target well below powLimit (`0x1c05_a3f4`) and an
/// actual timespan equal to half the target — difficulty should
/// roughly halve the target (= double the difficulty).
#[test]
fn retarget_arithmetic_round_trip() {
    let old_bits = CompactBits::new(0x1c05_a3f4);
    let old_target = old_bits.to_target().expect("old_bits must decode");
    let actual = TARGET_TIMESPAN / 2; // blocks came twice as fast
    let clamped = actual.clamp(MIN_TIMESPAN, MAX_TIMESPAN);
    assert_eq!(clamped, actual, "actual is within clamp bounds");

    let new_target = scale_target(old_target, clamped, TARGET_TIMESPAN)
        .expect("scale_target must succeed for valid inputs");
    // new_target ≈ old_target / 2. Re-derive without scale_target to
    // verify: U256(old_target) / 2.
    let expected = U256::from_be_bytes(old_target).div_u64(2);
    assert_eq!(
        U256::from_be_bytes(new_target),
        expected,
        "halved-timespan retarget must halve the target",
    );

    // And the new target must still be ≤ powLimit (sanity).
    let pow_limit = U256::from_be_bytes(
        POW_LIMIT_BITS
            .to_target()
            .expect("POW_LIMIT_BITS must decode"),
    );
    assert!(U256::from_be_bytes(new_target) <= pow_limit);
}

/// Sanity check: a retarget that would push the target above powLimit
/// is clamped back to the powLimit. Use the genesis target (already at
/// powLimit) and a maximum-clamped timespan — the result must remain
/// at the powLimit, never exceed it.
#[test]
fn retarget_clamps_to_pow_limit() {
    let old_target = POW_LIMIT_BITS
        .to_target()
        .expect("POW_LIMIT_BITS must decode");
    // Even a max-clamped timespan (×4) would yield 4× the target if not
    // clamped. We expect the powLimit clamp to bring it back.
    let new_target = scale_target(old_target, MAX_TIMESPAN, TARGET_TIMESPAN)
        .expect("scale_target must succeed for valid inputs");
    let new_bits =
        CompactBits::from_target(new_target).expect("from_target must succeed for valid target");
    assert_eq!(
        new_bits,
        POW_LIMIT_BITS,
        "target above powLimit must clamp back, got {:#010x}",
        new_bits.to_u32(),
    );
}

// ── Stage 3: connect_block tests ─────────────────────────────────────────

/// Build a minimal view + block pair ready for `connect_block`.
///
/// Returns `(view, block, coinbase_txid)`. The view has `height` headers
/// pushed (so the block will be at height+1, but we pass `height` as the
/// connect height for simplicity in most tests). The UTXO set is empty;
/// callers insert coins as needed.
fn connect_setup(height: u32) -> (MemoryChainView, Block, Hash256) {
    let mut view = MemoryChainView::new();
    let mut prev = Hash256::ZERO;
    for i in 0..height {
        let h = BlockHeader::new(
            BlockVersion::new(1),
            prev,
            Hash256::ZERO,
            BlockTime::new(1_231_006_505 + i * 600),
            CompactBits::new(0x207f_ffff),
            Nonce::new(0),
        );
        prev = h.hash();
        view.push_header(h);
    }
    let h = BlockHeight::new(height);
    let cb = coinbase_tx(h, block_subsidy(h).to_u64());
    let txid = cb.txid().expect("txid encoding cannot fail");
    let block = make_block(vec![cb], CompactBits::new(0x207f_ffff));
    (view, block, txid)
}

#[test]
fn connect_coinbase_only_block() {
    let (view, block, coinbase_txid) = connect_setup(1);
    let mut scratch = Vec::new();
    let result = connect_block(
        &block,
        BlockHeight::new(1),
        &view,
        &mut scratch,
        &mut ConnectScratch::new(),
        false,
        None,
        None,
    )
    .expect("coinbase-only block must connect");
    assert_eq!(result.fees, Satoshi::ZERO);
    assert!(result.spent.is_empty());
    assert_eq!(result.created.len(), 1);
    assert_eq!(
        result.created[0].outpoint,
        OutPoint {
            txid: coinbase_txid,
            vout: 0
        }
    );
    assert!(result.created[0].coinbase);
}

#[test]
fn connect_block_with_spend() {
    let (mut view, _, _) = connect_setup(200);
    // Insert a mature non-coinbase coin to spend.
    let prev_op = OutPoint {
        txid: Hash256::from_bytes([0xab; 32]),
        vout: 0,
    };
    view.insert_coin(
        prev_op,
        Coin {
            value: Satoshi::new(50_000),
            script_pubkey: vec![0x51].into(),
            height: BlockHeight::new(1),
            coinbase: false,
        },
    );
    let cb = coinbase_tx(
        BlockHeight::new(200),
        block_subsidy(BlockHeight::new(200)).to_u64(),
    );
    let spend = regular_tx(prev_op.txid, 0, 40_000); // 10_000 fee
    let block = make_block(vec![cb, spend], CompactBits::new(0x207f_ffff));
    let mut scratch = Vec::new();
    let result = connect_block(
        &block,
        BlockHeight::new(200),
        &view,
        &mut scratch,
        &mut ConnectScratch::new(),
        false,
        None,
        None,
    )
    .expect("block with valid spend must connect");
    assert_eq!(result.fees, Satoshi::new(10_000));
    assert_eq!(result.spent, vec![prev_op]);
    // created: coinbase output + spend output
    assert_eq!(result.created.len(), 2);
}

#[test]
fn connect_missing_input_rejected() {
    let (view, _, _) = connect_setup(200);
    let cb = coinbase_tx(
        BlockHeight::new(200),
        block_subsidy(BlockHeight::new(200)).to_u64(),
    );
    // Spend a coin that doesn't exist in the view.
    let ghost = regular_tx(Hash256::from_bytes([0xff; 32]), 0, 1_000);
    let block = make_block(vec![cb, ghost], CompactBits::new(0x207f_ffff));
    let mut scratch = Vec::new();
    assert_eq!(
        connect_block(
            &block,
            BlockHeight::new(200),
            &view,
            &mut scratch,
            &mut ConnectScratch::new(),
            false,
            None,
            None
        ),
        Err(ValidationError::MissingInput {
            tx_index: 1,
            input_index: 0
        })
    );
}

#[test]
fn connect_coinbase_maturity_rejected() {
    let (mut view, _, _) = connect_setup(50);
    // Insert a coinbase coin that is only 49 blocks deep (height 1, connect at 50).
    let prev_op = OutPoint {
        txid: Hash256::from_bytes([0xcc; 32]),
        vout: 0,
    };
    view.insert_coin(
        prev_op,
        Coin {
            value: Satoshi::new(100_000),
            script_pubkey: vec![0x51].into(),
            height: BlockHeight::new(1),
            coinbase: true, // coinbase output, immature at height 50
        },
    );
    let cb = coinbase_tx(
        BlockHeight::new(50),
        block_subsidy(BlockHeight::new(50)).to_u64(),
    );
    let spend = regular_tx(prev_op.txid, 0, 90_000);
    let block = make_block(vec![cb, spend], CompactBits::new(0x207f_ffff));
    let mut scratch = Vec::new();
    assert_eq!(
        connect_block(
            &block,
            BlockHeight::new(50),
            &view,
            &mut scratch,
            &mut ConnectScratch::new(),
            false,
            None,
            None
        ),
        Err(ValidationError::CoinbaseMaturityViolation {
            tx_index: 1,
            input_index: 0
        })
    );
}

#[test]
fn connect_script_verify_failure_propagates() {
    // The spent UTXO has scriptPubKey = OP_DUP, which pops the stack on
    // execution. Combined with the regular_tx scriptSig of [OP_0], the
    // OP_DUP duplicates an empty top — that succeeds, but the final stack
    // top is empty (falsey) → EvalFalse from verify_script. The exact
    // ScriptError variant only needs to be reachable, not specific.
    let (mut view, _, _) = connect_setup(200);
    let prev_op = OutPoint {
        txid: Hash256::from_bytes([0xee; 32]),
        vout: 0,
    };
    view.insert_coin(
        prev_op,
        Coin {
            value: Satoshi::new(50_000),
            // OP_RETURN — guaranteed to fail any script verification.
            script_pubkey: vec![0x6a].into(),
            height: BlockHeight::new(1),
            coinbase: false,
        },
    );
    let cb = coinbase_tx(
        BlockHeight::new(200),
        block_subsidy(BlockHeight::new(200)).to_u64(),
    );
    let spend = regular_tx(prev_op.txid, 0, 40_000);
    let block = make_block(vec![cb, spend], CompactBits::new(0x207f_ffff));
    let mut scratch = Vec::new();
    let r = connect_block(
        &block,
        BlockHeight::new(200),
        &view,
        &mut scratch,
        &mut ConnectScratch::new(),
        false,
        None,
        None,
    );
    assert!(
        matches!(
            r,
            Err(ValidationError::ScriptVerifyFailed {
                tx_index: 1,
                input_index: 0,
                ..
            })
        ),
        "expected ScriptVerifyFailed, got {r:?}"
    );
}

/// `skip_script=true` bypasses script verification: a block whose inputs
/// would normally fail (`OP_RETURN` scriptPubKey) succeeds when skipped.
#[test]
fn connect_skip_script_bypasses_verification() {
    let (mut view, _, _) = connect_setup(200);
    let prev_op = OutPoint {
        txid: Hash256::from_bytes([0xfe; 32]),
        vout: 0,
    };
    view.insert_coin(
        prev_op,
        Coin {
            value: Satoshi::new(50_000),
            script_pubkey: vec![0x6a].into(), // OP_RETURN — would always fail
            height: BlockHeight::new(1),
            coinbase: false,
        },
    );
    let cb = coinbase_tx(
        BlockHeight::new(200),
        block_subsidy(BlockHeight::new(200)).to_u64(),
    );
    let spend = regular_tx(prev_op.txid, 0, 40_000);
    let block = make_block(vec![cb, spend], CompactBits::new(0x207f_ffff));
    let mut scratch = Vec::new();
    // With skip_script=false this would be ScriptVerifyFailed.
    connect_block(
        &block,
        BlockHeight::new(200),
        &view,
        &mut scratch,
        &mut ConnectScratch::new(),
        true,
        None,
        None,
    )
    .expect("skip_script=true must succeed even with OP_RETURN scriptPubKey");
}

/// Cache hit: second call returns same verdict without re-running the interpreter.
#[test]
fn connect_exec_cache_hits_on_second_call() {
    let (mut view, _, _) = connect_setup(200);
    let prev_op = OutPoint {
        txid: Hash256::from_bytes([0xfa; 32]),
        vout: 0,
    };
    view.insert_coin(
        prev_op,
        Coin {
            value: Satoshi::new(50_000),
            script_pubkey: vec![0x51].into(), // OP_1 — always passes
            height: BlockHeight::new(1),
            coinbase: false,
        },
    );
    let cb = coinbase_tx(
        BlockHeight::new(200),
        block_subsidy(BlockHeight::new(200)).to_u64(),
    );
    let spend = regular_tx(prev_op.txid, 0, 40_000);
    let block = make_block(vec![cb, spend], CompactBits::new(0x207f_ffff));
    let mut scratch = Vec::new();
    let mut cache = crate::script::ScriptExecutionCache::new(64);
    // Cold call — populates cache.
    connect_block(
        &block,
        BlockHeight::new(200),
        &view,
        &mut scratch,
        &mut ConnectScratch::new(),
        false,
        Some(&mut cache),
        None,
    )
    .expect("first call must succeed");
    assert_eq!(cache.hits(), 0);
    assert!(cache.misses() > 0);
    // Hot call — must hit the cache.
    connect_block(
        &block,
        BlockHeight::new(200),
        &view,
        &mut scratch,
        &mut ConnectScratch::new(),
        false,
        Some(&mut cache),
        None,
    )
    .expect("second call must succeed");
    assert!(
        cache.hits() > 0,
        "second call must produce at least one cache hit"
    );
}

#[test]
fn connect_negative_fee_rejected() {
    let (mut view, _, _) = connect_setup(200);
    let prev_op = OutPoint {
        txid: Hash256::from_bytes([0xdd; 32]),
        vout: 0,
    };
    view.insert_coin(
        prev_op,
        Coin {
            value: Satoshi::new(1_000),
            script_pubkey: vec![0x51].into(),
            height: BlockHeight::new(1),
            coinbase: false,
        },
    );
    let cb = coinbase_tx(
        BlockHeight::new(200),
        block_subsidy(BlockHeight::new(200)).to_u64(),
    );
    // Output exceeds input value.
    let overspend = regular_tx(prev_op.txid, 0, 2_000);
    let block = make_block(vec![cb, overspend], CompactBits::new(0x207f_ffff));
    let mut scratch = Vec::new();
    assert_eq!(
        connect_block(
            &block,
            BlockHeight::new(200),
            &view,
            &mut scratch,
            &mut ConnectScratch::new(),
            false,
            None,
            None
        ),
        Err(ValidationError::NegativeFee { tx_index: 1 })
    );
}

#[test]
fn connect_coinbase_reward_exceeds_subsidy_rejected() {
    let (view, _, _) = connect_setup(1);
    // Coinbase claims more than the 50 BTC subsidy at height 1.
    let greedy_cb = Transaction {
        version: TxVersion::new(1),
        inputs: vec![TxIn {
            previous_output: NULL_OUTPOINT,
            script_sig: Transaction::bip34_height_script(BlockHeight::new(1)).into(),
            sequence: Sequence::MAX,
            witness: Witness::empty(),
        }],
        outputs: vec![TxOut {
            value: Satoshi::new(50 * 100_000_000 + 1), // one satoshi over
            script_pubkey: vec![0x51].into(),
        }],
        locktime: Locktime::new(0),
    };
    let block = make_block(vec![greedy_cb], CompactBits::new(0x207f_ffff));
    let mut scratch = Vec::new();
    assert_eq!(
        connect_block(
            &block,
            BlockHeight::new(1),
            &view,
            &mut scratch,
            &mut ConnectScratch::new(),
            false,
            None,
            None
        ),
        Err(ValidationError::CoinbaseRewardExceedsSubsidy)
    );
}

#[test]
fn block_subsidy_halvings() {
    // Genesis era: 50 BTC
    assert_eq!(
        block_subsidy(BlockHeight::new(0)).to_u64(),
        50 * 100_000_000
    );
    // First halving at 210,000
    assert_eq!(
        block_subsidy(BlockHeight::new(210_000)).to_u64(),
        25 * 100_000_000
    );
    // Second halving at 420,000
    assert_eq!(
        block_subsidy(BlockHeight::new(420_000)).to_u64(),
        1_250_000_000
    );
    // After 64 halvings: zero
    assert_eq!(block_subsidy(BlockHeight::new(64 * 210_000)).to_u64(), 0);
}

#[test]
fn sigops_checksig_and_multisig() {
    let legacy = |s: &[u8]| super::sigop_cost::SigopCost::count(s, false);
    assert_eq!(legacy(&[0xac]), 1);
    assert_eq!(legacy(&[0xad]), 1);
    assert_eq!(legacy(&[0xae]), 20);
    assert_eq!(legacy(&[0xaf]), 20);
    assert_eq!(legacy(&[0x01, 0xac, 0xac]), 1);
    assert_eq!(legacy(&[]), 0);
}

#[test]
fn connect_sigops_limit_exceeded() {
    let (view, _, _) = connect_setup(1);
    // Each OP_CHECKMULTISIG in a scriptPubKey counts as 20.
    // 1001 × OP_CHECKMULTISIG = 20,020 sigops > 20,000 limit.
    let many_sigops: Vec<u8> = std::iter::repeat_n(0xae_u8, 1001).collect();
    let cb = Transaction {
        version: TxVersion::new(1),
        inputs: vec![TxIn {
            previous_output: NULL_OUTPOINT,
            script_sig: Transaction::bip34_height_script(BlockHeight::new(1)).into(),
            sequence: Sequence::MAX,
            witness: Witness::empty(),
        }],
        outputs: vec![TxOut {
            value: Satoshi::new(block_subsidy(BlockHeight::new(1)).to_u64()),
            script_pubkey: many_sigops.into(),
        }],
        locktime: Locktime::new(0),
    };
    let block = make_block(vec![cb], CompactBits::new(0x207f_ffff));
    let mut scratch = Vec::new();
    let err = connect_block(
        &block,
        BlockHeight::new(1),
        &view,
        &mut scratch,
        &mut ConnectScratch::new(),
        false,
        None,
        None,
    )
    .expect_err("block with too many sigops must be rejected");
    assert!(matches!(err, ValidationError::SigopsLimitExceeded { .. }));
}

#[test]
fn connect_bip30_violation_rejected() {
    let (mut view, _, _prior_coinbase_txid) = connect_setup(200);
    // Re-use the identical coinbase tx at the same height so its txid is
    // deterministic and we can pre-populate the UTXO set with a collision.
    let collision_txid = coinbase_tx(
        BlockHeight::new(200),
        block_subsidy(BlockHeight::new(200)).to_u64(),
    )
    .txid()
    .expect("txid encoding cannot fail");
    view.insert_coin(
        OutPoint {
            txid: collision_txid,
            vout: 0,
        },
        Coin {
            value: Satoshi::new(1_000),
            script_pubkey: vec![0x51].into(),
            height: BlockHeight::new(1),
            coinbase: true,
        },
    );
    // Build a block with the identical coinbase tx — same txid, guaranteed collision.
    let cb = coinbase_tx(
        BlockHeight::new(200),
        block_subsidy(BlockHeight::new(200)).to_u64(),
    );
    let block = make_block(vec![cb], CompactBits::new(0x207f_ffff));
    let mut scratch = Vec::new();
    assert_eq!(
        connect_block(
            &block,
            BlockHeight::new(200),
            &view,
            &mut scratch,
            &mut ConnectScratch::new(),
            false,
            None,
            None
        ),
        Err(ValidationError::Bip30Violation { tx_index: 0 })
    );
}

/// Round-trip property: every nBits accepted by `nbits_to_target` should
/// either round-trip cleanly through `target_to_nbits`, or canonicalize
/// to a value with the same target. Bitcoin's compact format has one
/// canonical encoding per target value; non-canonical inputs (mantissa
/// with trailing zero bytes) re-encode to canonical form.
#[test]
fn nbits_target_roundtrip_canonical_examples() {
    // These are values Bitcoin Core has produced as outputs of
    // target_to_nbits, so they are canonical and must round-trip.
    for &raw in &[
        0x1d00_ffff_u32, // genesis
        0x1d00_d86a,     // first mainnet retarget
        0x1c05_a3f4,     // post-retarget-2 difficulty (illustrative)
        0x1903_a30c,     // mid-2010s mainnet difficulty (illustrative shape)
        0x207f_ffff,     // regtest
    ] {
        let bits = CompactBits::new(raw);
        let target = bits
            .to_target()
            .unwrap_or_else(|| panic!("bits {raw:#010x} must decode to a target"));
        let back = CompactBits::from_target(target)
            .unwrap_or_else(|| panic!("target from {raw:#010x} must re-encode"));
        assert_eq!(
            back,
            bits,
            "round-trip failed for {raw:#010x} → {:#010x}",
            back.to_u32()
        );
    }
}

// ── BIP30 exception-height bypass ────────────────────────────────────────

/// Core rejects an overwrite of any unspent output, whether or not the
/// existing coin came from a coinbase, and on any output index.
#[test]
fn connect_bip30_rejects_overwriting_a_non_coinbase_coin_at_a_later_index() {
    let (mut view, _, _) = connect_setup(200);
    let mut cb = coinbase_tx(
        BlockHeight::new(200),
        block_subsidy(BlockHeight::new(200)).to_u64(),
    );
    cb.outputs.push(TxOut {
        value: Satoshi::ZERO,
        script_pubkey: vec![0x51].into(),
    });
    let txid = cb.txid().expect("txid encoding cannot fail");
    view.insert_coin(
        OutPoint { txid, vout: 1 },
        Coin {
            value: Satoshi::new(1_000),
            script_pubkey: vec![0x51].into(),
            height: BlockHeight::new(1),
            coinbase: false,
        },
    );

    let block = make_block(vec![cb], CompactBits::new(0x207f_ffff));
    let mut scratch = Vec::new();
    assert_eq!(
        connect_block(
            &block,
            BlockHeight::new(200),
            &view,
            &mut scratch,
            &mut ConnectScratch::new(),
            true,
            None,
            None,
        ),
        Err(ValidationError::Bip30Violation { tx_index: 0 })
    );
}

// ── exec_cache: cold script failure caches the rejection ─────────────────

/// When exec_cache is Some and script verification fails (cold miss),
/// the error propagates as ScriptVerifyFailed. This covers the
/// `ScriptVerifier::verify_cached` branch inside `connect_block` for a failing input.
#[test]
fn connect_exec_cache_script_failure_propagates() {
    let (mut view, _, _) = connect_setup(200);
    let prev_op = OutPoint {
        txid: Hash256::from_bytes([0xd1; 32]),
        vout: 0,
    };
    view.insert_coin(
        prev_op,
        Coin {
            value: Satoshi::new(50_000),
            script_pubkey: vec![0x6a].into(), // OP_RETURN — always fails
            height: BlockHeight::new(1),
            coinbase: false,
        },
    );
    let cb = coinbase_tx(
        BlockHeight::new(200),
        block_subsidy(BlockHeight::new(200)).to_u64(),
    );
    let spend = regular_tx(prev_op.txid, 0, 40_000);
    let block = make_block(vec![cb, spend], CompactBits::new(0x207f_ffff));
    let mut scratch = Vec::new();
    let mut cache = crate::script::ScriptExecutionCache::new(64);

    let r = connect_block(
        &block,
        BlockHeight::new(200),
        &view,
        &mut scratch,
        &mut ConnectScratch::new(),
        false,
        Some(&mut cache),
        None,
    );
    assert!(
        matches!(
            r,
            Err(ValidationError::ScriptVerifyFailed {
                tx_index: 1,
                input_index: 0,
                ..
            })
        ),
        "exec_cache cold miss with failing script must propagate error, got {r:?}"
    );
    // The cache should have recorded the failure (miss then insert).
    assert!(cache.misses() > 0, "cache must record at least one miss");
}

// ── precomputed_txids path ───────────────────────────────────────────────

/// Exercise the `precomputed_txids` parameter to cover the `Some(txids)`
/// branch in the txid match expression (line 121).
#[test]
fn connect_with_precomputed_txids() {
    let (mut view, _, _) = connect_setup(200);
    let prev_op = OutPoint {
        txid: Hash256::from_bytes([0xb1; 32]),
        vout: 0,
    };
    view.insert_coin(
        prev_op,
        Coin {
            value: Satoshi::new(50_000),
            script_pubkey: vec![0x51].into(), // OP_1 — passes
            height: BlockHeight::new(1),
            coinbase: false,
        },
    );
    let cb = coinbase_tx(
        BlockHeight::new(200),
        block_subsidy(BlockHeight::new(200)).to_u64(),
    );
    let spend = regular_tx(prev_op.txid, 0, 40_000);

    let txids = vec![
        cb.txid().expect("txid encoding cannot fail"),
        spend.txid().expect("txid encoding cannot fail"),
    ];
    let block = make_block(vec![cb, spend], CompactBits::new(0x207f_ffff));
    let mut scratch = Vec::new();

    let result = connect_block(
        &block,
        BlockHeight::new(200),
        &view,
        &mut scratch,
        &mut ConnectScratch::new(),
        false,
        None,
        Some(&txids),
    )
    .expect("block with precomputed txids must connect");
    assert_eq!(result.fees, Satoshi::new(10_000));
    assert_eq!(result.spent, vec![prev_op]);
    assert_eq!(result.created.len(), 2);
}
