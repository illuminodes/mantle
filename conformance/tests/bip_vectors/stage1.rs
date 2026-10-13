use super::*;

// ── Stage 1: structural validation vectors ────────────────────────────────────

#[test]
fn stage1_empty_block_rejected() {
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
    assert_eq!(
        validate_block_structure(&block),
        Err(ValidationError::EmptyBlock)
    );
}

#[test]
fn stage1_first_tx_not_coinbase_rejected() {
    let non_cb = Transaction {
        version: TxVersion::new(1),
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_bytes([0xab; 32]),
                vout: 0,
            },
            script_sig: vec![].into(),
            sequence: Sequence::MAX,
            witness: Witness::empty(),
        }],
        outputs: vec![make_output(1000)],
        locktime: Locktime::new(0),
    };
    let txids = vec![non_cb.txid().expect("txid encoding cannot fail")];
    let merkle_root = compute_merkle_root(&txids).expect("single-tx merkle root must exist");
    let block = Block {
        header: BlockHeader::new(
            BlockVersion::new(1),
            Hash256::ZERO,
            merkle_root,
            BlockTime::new(0),
            mantle::primitives::CompactBits::new(0x207f_ffff),
            Nonce::new(0),
        ),
        transactions: vec![non_cb],
    };
    assert_eq!(
        validate_block_structure(&block),
        Err(ValidationError::FirstTxNotCoinbase)
    );
}

#[test]
fn stage1_non_coinbase_with_null_outpoint_rejected() {
    // Second tx uses the coinbase null outpoint — must be rejected.
    let cb_script = {
        let mut s = Transaction::bip34_height_script(BlockHeight::ZERO);
        s.extend_from_slice(&[0x00]); // pad to meet min length
        s
    };
    let fake_cb = Transaction {
        version: TxVersion::new(1),
        inputs: vec![coinbase_input(vec![0x51, 0x52])], // valid coinbase
        outputs: vec![make_output(50_0000_0000)],
        locktime: Locktime::new(0),
    };
    let imposter = Transaction {
        version: TxVersion::new(1),
        inputs: vec![coinbase_input(vec![0x00, 0x00])], // null outpoint in tx[1]
        outputs: vec![make_output(1000)],
        locktime: Locktime::new(0),
    };
    let _ = cb_script;
    let txids = vec![
        fake_cb.txid().expect("txid encoding cannot fail"),
        imposter.txid().expect("txid encoding cannot fail"),
    ];
    let merkle_root = compute_merkle_root(&txids).expect("two-tx merkle root must exist");
    let block = Block {
        header: BlockHeader::new(
            BlockVersion::new(1),
            Hash256::ZERO,
            merkle_root,
            BlockTime::new(0),
            mantle::primitives::CompactBits::new(0x207f_ffff),
            Nonce::new(0),
        ),
        transactions: vec![fake_cb, imposter],
    };
    assert_eq!(
        validate_block_structure(&block),
        Err(ValidationError::UnexpectedCoinbaseInput { tx_index: 1 }),
    );
}

#[test]
fn stage1_coinbase_script_too_short() {
    let block = minimal_block(vec![0x00], vec![]); // 1 byte — below minimum of 2
    assert_eq!(
        validate_block_structure(&block),
        Err(ValidationError::CoinbaseScriptSigLength { len: 1 }),
    );
}

#[test]
fn stage1_coinbase_script_too_long() {
    let long_script = vec![0x00; MAX_COINBASE_SCRIPTSIG_LEN + 1];
    let block = minimal_block(long_script, vec![]);
    assert_eq!(
        validate_block_structure(&block),
        Err(ValidationError::CoinbaseScriptSigLength {
            len: MAX_COINBASE_SCRIPTSIG_LEN + 1
        }),
    );
}

#[test]
fn stage1_coinbase_script_boundary_values_accepted() {
    // We only care that the coinbase script-length check doesn't reject these.
    // PoW with nonce=0 may or may not pass (hash is ~uniform), so we accept
    // any error that is NOT CoinbaseScriptSigLength.
    for &len in &[MIN_COINBASE_SCRIPTSIG_LEN, MAX_COINBASE_SCRIPTSIG_LEN] {
        let script = vec![0x51; len];
        match validate_block_structure(&minimal_block(script, vec![])) {
            Ok(()) => {}
            Err(ValidationError::CoinbaseScriptSigLength { len: actual }) => {
                panic!("coinbase script of {len} bytes was rejected as bad length (got {actual})");
            }
            Err(_other) => {} // PoW or other structural error — script length was accepted
        }
    }
}

#[test]
fn stage1_output_value_over_max_money_rejected() {
    let too_much = mantle::primitives::Satoshi::new(MAX_MONEY.to_u64() + 1);
    let coinbase = Transaction {
        version: TxVersion::new(1),
        inputs: vec![coinbase_input(vec![0x51, 0x52])],
        outputs: vec![TxOut {
            value: too_much,
            script_pubkey: vec![0x51].into(),
        }],
        locktime: Locktime::new(0),
    };
    let txids = vec![coinbase.txid().expect("txid encoding cannot fail")];
    let merkle_root = compute_merkle_root(&txids).expect("single-tx merkle root must exist");
    let block = Block {
        header: BlockHeader::new(
            BlockVersion::new(1),
            Hash256::ZERO,
            merkle_root,
            BlockTime::new(0),
            mantle::primitives::CompactBits::new(0x207f_ffff),
            Nonce::new(0),
        ),
        transactions: vec![coinbase],
    };
    assert_eq!(
        validate_block_structure(&block),
        Err(ValidationError::OutputValueOutOfRange {
            tx_index: 0,
            output_index: 0
        }),
    );
}

#[test]
fn stage1_duplicate_inputs_rejected() {
    let outpoint = OutPoint {
        txid: Hash256::from_bytes([0xab; 32]),
        vout: 1,
    };
    let tx = Transaction {
        version: TxVersion::new(1),
        inputs: vec![
            TxIn {
                previous_output: outpoint,
                script_sig: vec![].into(),
                sequence: Sequence::MAX,
                witness: Witness::empty(),
            },
            TxIn {
                previous_output: outpoint,
                script_sig: vec![].into(),
                sequence: Sequence::MAX,
                witness: Witness::empty(),
            }, // dup
        ],
        outputs: vec![make_output(1000)],
        locktime: Locktime::new(0),
    };
    let coinbase = Transaction {
        version: TxVersion::new(1),
        inputs: vec![coinbase_input(vec![0x51, 0x52])],
        outputs: vec![make_output(50_0000_0000)],
        locktime: Locktime::new(0),
    };
    let txids = vec![
        coinbase.txid().expect("txid encoding cannot fail"),
        tx.txid().expect("txid encoding cannot fail"),
    ];
    let merkle_root = compute_merkle_root(&txids).expect("two-tx merkle root must exist");
    let block = Block {
        header: BlockHeader::new(
            BlockVersion::new(1),
            Hash256::ZERO,
            merkle_root,
            BlockTime::new(0),
            mantle::primitives::CompactBits::new(0x207f_ffff),
            Nonce::new(0),
        ),
        transactions: vec![coinbase, tx],
    };
    assert_eq!(
        validate_block_structure(&block),
        Err(ValidationError::DuplicateInput { tx_index: 1 }),
    );
}

#[test]
fn stage1_merkle_mismatch_rejected() {
    let mut block = minimal_block(vec![0x51, 0x52], vec![]);
    // Corrupt the merkle root.
    block
        .header
        .set_merkle_root(Hash256::from_bytes([0xff; 32]));
    assert_eq!(
        validate_block_structure(&block),
        Err(ValidationError::MerkleRootMismatch)
    );
}

#[test]
fn stage1_invalid_bits_rejected() {
    let mut block = minimal_block(vec![0x51, 0x52], vec![]);
    block
        .header
        .set_bits(mantle::primitives::CompactBits::new(0)); // zero nBits is always invalid
    // Also recompute merkle (header bits don't affect merkle root — this is fine).
    assert_eq!(
        validate_block_structure(&block),
        Err(ValidationError::InvalidBits)
    );
}

#[test]
fn stage1_insufficient_pow_rejected() {
    // Use a very hard target (0x03000001 ≈ 0x000001 × 2^(3-3)*8 — basically
    // requires the hash to be almost zero). The block header nonce is 0 so
    // the hash is effectively random and almost certainly fails this target.
    let mut block = minimal_block(vec![0x51, 0x52], vec![]);
    block
        .header
        .set_bits(mantle::primitives::CompactBits::new(0x1900_0001)); // very hard target
    // Recompute the hash check — the actual hash won't satisfy target 0x0001…
    // Note: we don't update merkle root for the bits field (it only appears in
    // the header, not in tx data). So we need to rebuild:
    let txids: Vec<Hash256> = block
        .transactions
        .iter()
        .map(Transaction::txid)
        .collect::<Result<Vec<_>, _>>()
        .expect("txid encoding cannot fail");
    let merkle_root = compute_merkle_root(&txids).expect("non-empty tx list must have merkle root");
    block.header.set_merkle_root(merkle_root);
    assert_eq!(
        validate_block_structure(&block),
        Err(ValidationError::InsufficientProofOfWork),
    );
}
