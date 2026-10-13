use super::*;
use mantle_consensus::validation::validate_block_wire;
use std::collections::HashSet;

// ── Known transaction fixtures ────────────────────────────────────────────────
//
// These are hand-encoded from Bitcoin Core's tx_valid / tx_invalid test data.
// Only a curated subset is included to keep the file self-contained and fast.

/// The genesis coinbase transaction (raw hex), confirmed in block 0.
const GENESIS_COINBASE_RAW: &str = concat!(
    "01000000", // version = 1
    "01",       // input count = 1
    // prevout hash (null, 32 bytes)
    "0000000000000000000000000000000000000000000000000000000000000000",
    "ffffffff", // prevout index = 0xffffffff (coinbase)
    // scriptSig length + bytes: "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
    "4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73",
    "ffffffff",         // sequence
    "01",               // output count = 1
    "00f2052a01000000", // value = 5_000_000_000 (50 BTC)
    // scriptPubKey (65-byte uncompressed pubkey + OP_CHECKSIG)
    "434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
    "00000000" // locktime = 0
);

/// Known txid of the genesis coinbase (display / reversed byte order).
const GENESIS_COINBASE_TXID_DISPLAY: &str =
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

#[test]
fn genesis_coinbase_decode_roundtrip() {
    let bytes = decode_hex(GENESIS_COINBASE_RAW);
    let tx = Transaction::decode(&mut Cursor::new(&bytes)).expect("genesis coinbase must decode");

    // Basic structure checks.
    assert_eq!(tx.version, TxVersion::new(1));
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 1);
    assert_eq!(
        tx.outputs[0].value,
        mantle::primitives::Satoshi::new(50_0000_0000)
    );
    assert_eq!(tx.locktime, Locktime::new(0));

    // Re-encode must produce identical bytes.
    let mut reencoded = Vec::new();
    tx.encode(&mut reencoded)
        .expect("Vec<u8> write cannot fail");
    assert_eq!(
        reencoded, bytes,
        "encode(decode(x)) != x for genesis coinbase"
    );
}

#[test]
fn genesis_coinbase_txid_matches() {
    let bytes = decode_hex(GENESIS_COINBASE_RAW);
    let tx = Transaction::decode(&mut Cursor::new(&bytes)).expect("genesis coinbase must decode");
    let computed = tx.txid().expect("txid encoding cannot fail");
    assert_eq!(
        hash_to_hex_display(computed),
        GENESIS_COINBASE_TXID_DISPLAY,
        "genesis coinbase txid mismatch",
    );
}

#[test]
fn genesis_coinbase_is_valid_null_outpoint() {
    let bytes = decode_hex(GENESIS_COINBASE_RAW);
    let tx = Transaction::decode(&mut Cursor::new(&bytes)).expect("genesis coinbase must decode");
    // Input must reference the null outpoint (coinbase marker).
    assert_eq!(tx.inputs[0].previous_output.txid, Hash256::ZERO);
    assert_eq!(tx.inputs[0].previous_output.vout, u32::MAX);
}

// ── BIP68 / sequence numbers (fixture regression) ────────────────────────────
//
// Sequence number 0xffffffff means "final" (no relative lock-time). We verify
// the codec preserves arbitrary sequence values.

#[test]
fn sequence_field_roundtrip() {
    for &seq in &[0u32, 1, 0xffff_fffe, 0xffff_ffff] {
        let tx = Transaction {
            version: TxVersion::new(1),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([0xab; 32]),
                    vout: 0,
                },
                script_sig: vec![].into(),
                sequence: Sequence::new(seq),
                witness: Witness::empty(),
            }],
            outputs: vec![make_output(1000)],
            locktime: Locktime::new(0),
        };
        let mut buf = Vec::new();
        tx.encode(&mut buf).expect("Vec<u8> write cannot fail");
        let decoded =
            Transaction::decode(&mut Cursor::new(&buf)).expect("transaction roundtrip must decode");
        assert_eq!(
            decoded.inputs[0].sequence,
            Sequence::new(seq),
            "sequence {seq:#010x} not preserved"
        );
    }
}

// ── ChainView UTXO fixtures ───────────────────────────────────────────────────

#[test]
fn memory_chain_view_utxo_insert_lookup_spend() {
    let mut view = MemoryChainView::new();
    let op = OutPoint {
        txid: Hash256::from_bytes([0x12; 32]),
        vout: 3,
    };
    let coin = Coin {
        value: mantle::primitives::Satoshi::new(100_000),
        script_pubkey: vec![0x76, 0xa9, 0x14].into(), // OP_DUP OP_HASH160 OP_DATA14
        height: BlockHeight::new(500_000),
        coinbase: false,
    };

    assert!(
        view.get_coin(&op).expect("storage error").is_none(),
        "UTXO must not exist before insert"
    );
    view.insert_coin(op, coin.clone());
    assert_eq!(
        view.get_coin(&op).expect("storage error"),
        Some(&coin),
        "UTXO must be retrievable after insert"
    );

    view.spend_coin(&op);
    assert!(
        view.get_coin(&op).expect("storage error").is_none(),
        "UTXO must be gone after spend"
    );
}

#[test]
fn memory_chain_view_coinbase_flag_preserved() {
    let mut view = MemoryChainView::new();
    let op = OutPoint {
        txid: Hash256::from_bytes([0x99; 32]),
        vout: 0,
    };
    let coin = Coin {
        value: mantle::primitives::Satoshi::new(50_0000_0000),
        script_pubkey: vec![0x51].into(),
        height: BlockHeight::ZERO,
        coinbase: true,
    };
    view.insert_coin(op, coin.clone());
    let retrieved = view
        .get_coin(&op)
        .expect("storage error")
        .expect("coin must exist after insert");
    assert!(
        retrieved.coinbase,
        "coinbase flag must survive round-trip through MemoryChainView"
    );
    assert_eq!(retrieved.height, BlockHeight::ZERO);
    assert_eq!(
        retrieved.value,
        mantle::primitives::Satoshi::new(50_0000_0000)
    );
}

// ── validate_block_wire ───────────────────────────────────────────────────────

fn wire_scratch() -> (
    Vec<mantle::primitives::Hash256>,
    Vec<mantle::primitives::Hash256>,
    HashSet<OutPoint>,
    HashSet<mantle::primitives::Hash256>,
) {
    (Vec::new(), Vec::new(), HashSet::new(), HashSet::new())
}

#[test]
fn wire_genesis_passes_stage1() {
    let bytes = decode_hex(GENESIS_BLOCK_HEX);
    let (mut t, mut mb, mut si, mut st) = wire_scratch();
    validate_block_wire(&bytes, &mut t, &mut mb, &mut si, &mut st)
        .expect("genesis wire must pass Stage 1");
}

#[test]
fn wire_agrees_with_owned_on_valid_block() {
    let block = minimal_block(vec![0x03, 0x01, 0x00, 0x00], vec![]);
    let mut bytes = Vec::new();
    block.encode(&mut bytes).expect("Vec<u8> write cannot fail");

    let owned_result = validate_block_structure(&block);
    let (mut t, mut mb, mut si, mut st) = wire_scratch();
    let wire_result = validate_block_wire(&bytes, &mut t, &mut mb, &mut si, &mut st);
    assert_eq!(owned_result.is_ok(), wire_result.is_ok());
}

#[test]
fn wire_empty_block_rejected() {
    // Header + VarInt(0) — no transactions.
    let block = Block {
        header: BlockHeader::new(
            BlockVersion::new(1),
            Hash256::ZERO,
            Hash256::ZERO,
            BlockTime::new(0),
            mantle::primitives::CompactBits::new(0x207f_ffff),
            Nonce::new(0),
        ),
        transactions: vec![],
    };
    let mut bytes = Vec::new();
    block.encode(&mut bytes).expect("Vec<u8> write cannot fail");
    let (mut t, mut mb, mut si, mut st) = wire_scratch();
    assert_eq!(
        validate_block_wire(&bytes, &mut t, &mut mb, &mut si, &mut st),
        Err(ValidationError::EmptyBlock),
    );
}

#[test]
fn wire_merkle_mismatch_rejected() {
    let mut block = minimal_block(vec![0x03, 0x01, 0x00, 0x00], vec![]);
    block
        .header
        .set_merkle_root(Hash256::from_bytes([0xff; 32])); // corrupt the root
    let mut bytes = Vec::new();
    block.encode(&mut bytes).expect("Vec<u8> write cannot fail");
    let (mut t, mut mb, mut si, mut st) = wire_scratch();
    assert_eq!(
        validate_block_wire(&bytes, &mut t, &mut mb, &mut si, &mut st),
        Err(ValidationError::MerkleRootMismatch),
    );
}

#[test]
fn wire_truncated_returns_malformed() {
    let block = minimal_block(vec![0x03, 0x01, 0x00, 0x00], vec![]);
    let mut bytes = Vec::new();
    block.encode(&mut bytes).expect("Vec<u8> write cannot fail");
    let truncated = &bytes[..bytes.len() / 2];
    let (mut t, mut mb, mut si, mut st) = wire_scratch();
    let err = validate_block_wire(truncated, &mut t, &mut mb, &mut si, &mut st)
        .expect_err("truncated block must fail validation");
    assert!(
        matches!(err, ValidationError::MalformedTransaction { .. }),
        "expected MalformedTransaction, got {err:?}",
    );
}

#[test]
fn wire_agrees_with_owned_on_all_stage1_errors() {
    // Run a matrix of blocks that owned validation rejects and verify
    // wire validation returns the same error variant.
    use mantle::primitives::TxIn;

    let cases: &[(&str, Block)] = &[
        ("first_tx_not_coinbase", {
            let non_cb = Transaction {
                version: TxVersion::new(1),
                inputs: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Hash256::from_bytes([0xab; 32]),
                        vout: 0,
                    },
                    script_sig: vec![0x51].into(),
                    sequence: Sequence::MAX,
                    witness: Witness::empty(),
                }],
                outputs: vec![make_output(1000)],
                locktime: Locktime::new(0),
            };
            let txids = vec![non_cb.txid().expect("txid encoding cannot fail")];
            let merkle_root =
                compute_merkle_root(&txids).expect("single-tx merkle root must exist");
            Block {
                header: BlockHeader::new(
                    BlockVersion::new(4),
                    Hash256::ZERO,
                    merkle_root,
                    BlockTime::new(1_231_006_505),
                    mantle::primitives::CompactBits::new(0x207f_ffff),
                    Nonce::new(0),
                ),
                transactions: vec![non_cb],
            }
        }),
        (
            "coinbase_script_too_short",
            minimal_block(vec![0x51], vec![]),
        ),
        ("output_value_overflow", {
            let coinbase = Transaction {
                version: TxVersion::new(1),
                inputs: vec![coinbase_input(vec![0x03, 0x01, 0x00, 0x00])],
                outputs: vec![TxOut {
                    value: mantle::primitives::Satoshi::new(u64::MAX),
                    script_pubkey: vec![0x51].into(),
                }],
                locktime: Locktime::new(0),
            };
            let txids = vec![coinbase.txid().expect("txid encoding cannot fail")];
            let merkle_root =
                compute_merkle_root(&txids).expect("single-tx merkle root must exist");
            Block {
                header: BlockHeader::new(
                    BlockVersion::new(4),
                    Hash256::ZERO,
                    merkle_root,
                    BlockTime::new(1_231_006_505),
                    mantle::primitives::CompactBits::new(0x207f_ffff),
                    Nonce::new(0),
                ),
                transactions: vec![coinbase],
            }
        }),
    ];

    for (name, block) in cases {
        let mut bytes = Vec::new();
        block.encode(&mut bytes).expect("Vec<u8> write cannot fail");
        let owned_err =
            validate_block_structure(block).expect_err("case must fail owned validation");
        let (mut t, mut mb, mut si, mut st) = wire_scratch();
        let wire_err = validate_block_wire(&bytes, &mut t, &mut mb, &mut si, &mut st)
            .expect_err("case must fail wire validation");
        assert_eq!(
            std::mem::discriminant(&owned_err),
            std::mem::discriminant(&wire_err),
            "case {name}: owned={owned_err:?} wire={wire_err:?}",
        );
    }
}
