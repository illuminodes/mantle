use super::*;

// ── Stage 2: contextual validation vectors ────────────────────────────────────

/// Build a structurally valid block whose coinbase scriptSig starts with the
/// BIP34 height encoding for `this_height`.
fn stage2_block_for_height(
    view: &MemoryChainView,
    this_height: BlockHeight,
    version: i32,
) -> Block {
    let tip = view.tip();
    let parent_bits = view
        .get_header_at(tip.height)
        .expect("storage error")
        .expect("tip header must exist")
        .bits();
    let script_sig = {
        let mut s = Transaction::bip34_height_script(this_height);
        // Ensure minimum length of 2 even if bip34_script produced 1 byte.
        if s.len() < MIN_COINBASE_SCRIPTSIG_LEN {
            s.push(0x00);
        }
        s
    };
    let coinbase = Transaction {
        version: TxVersion::new(1),
        inputs: vec![coinbase_input(script_sig)],
        outputs: vec![make_output(50_0000_0000)],
        locktime: Locktime::new(0),
    };
    let txids = vec![coinbase.txid().expect("txid encoding cannot fail")];
    let merkle_root = compute_merkle_root(&txids).expect("single-tx merkle root must exist");

    // MTP = median of up to 11 preceding blocks. We need time > MTP.
    // We pick a timestamp 600 seconds after the tip's timestamp.
    let parent_time = view
        .get_header_at(tip.height)
        .expect("storage error")
        .expect("tip header must exist")
        .time();
    let time = parent_time + 600;

    Block {
        header: BlockHeader::new(
            BlockVersion::new(version),
            tip.hash,
            merkle_root,
            time,
            parent_bits, // same difficulty (non-retarget height)
            Nonce::new(0),
        ),
        transactions: vec![coinbase],
    }
}

#[test]
fn stage2_unknown_parent_rejected() {
    let view = build_chain(
        10,
        mantle::primitives::CompactBits::new(0x207f_ffff),
        1_000_000,
    );
    let mut block = stage2_block_for_height(&view, BlockHeight::new(10), 4);
    // Point to an unknown parent.
    block.header.set_prev_block(Hash256::from_bytes([0xde; 32]));
    assert_eq!(
        validate_block_context(&block, &view, false),
        Err(ValidationError::UnknownParent),
    );
}

#[test]
fn stage2_unexpected_difficulty_rejected() {
    let view = build_chain(
        10,
        mantle::primitives::CompactBits::new(0x207f_ffff),
        1_000_000,
    );
    let mut block = stage2_block_for_height(&view, BlockHeight::new(10), 4);
    // Change the nBits to something different from the parent (non-retarget block).
    block
        .header
        .set_bits(mantle::primitives::CompactBits::new(0x1d00_ffff));
    assert_eq!(
        validate_block_context(&block, &view, false),
        Err(ValidationError::UnexpectedDifficulty),
    );
}

#[test]
fn stage2_timestamp_not_greater_than_mtp_rejected() {
    let view = build_chain(
        12,
        mantle::primitives::CompactBits::new(0x207f_ffff),
        1_000_000,
    );
    let tip = view.tip();
    let parent_bits = view
        .get_header_at(tip.height)
        .expect("storage error")
        .expect("tip header must exist")
        .bits();
    let this_height = tip.height + 1;
    let script_sig = {
        let mut s = Transaction::bip34_height_script(this_height);
        if s.len() < MIN_COINBASE_SCRIPTSIG_LEN {
            s.push(0x00);
        }
        s
    };
    let coinbase = Transaction {
        version: TxVersion::new(1),
        inputs: vec![coinbase_input(script_sig)],
        outputs: vec![make_output(50_0000_0000)],
        locktime: Locktime::new(0),
    };
    let txids = vec![coinbase.txid().expect("txid encoding cannot fail")];
    let merkle_root = compute_merkle_root(&txids).expect("single-tx merkle root must exist");

    // MTP for 12 blocks at times [1_000_000, 1_000_600, …, 1_006_600].
    // The 11 preceding blocks span heights 1..=11 (times 1_000_600..1_006_600).
    // Median of 11 = the 6th = 1_003_600. We set time = 1_003_600 (not strictly greater).
    let mtp = 1_003_600_u32; // median of heights 1..=11
    let _ = Block {
        header: BlockHeader::new(
            BlockVersion::new(4),
            tip.hash,
            merkle_root,
            BlockTime::new(mtp), // equal to MTP — must be *greater*
            parent_bits,
            Nonce::new(0),
        ),
        transactions: vec![coinbase],
    };

    // Build a block with time == MTP (not strictly greater).
    let bad_block = {
        let script_sig2 = {
            let mut s = Transaction::bip34_height_script(this_height);
            if s.len() < MIN_COINBASE_SCRIPTSIG_LEN {
                s.push(0x00);
            }
            s
        };
        let coinbase2 = Transaction {
            version: TxVersion::new(1),
            inputs: vec![coinbase_input(script_sig2)],
            outputs: vec![make_output(50_0000_0000)],
            locktime: Locktime::new(0),
        };
        let txids2 = vec![coinbase2.txid().expect("txid encoding cannot fail")];
        let mr2 = compute_merkle_root(&txids2).expect("single-tx merkle root must exist");
        Block {
            header: BlockHeader::new(
                BlockVersion::new(4),
                tip.hash,
                mr2,
                BlockTime::new(mtp),
                parent_bits,
                Nonce::new(0),
            ),
            transactions: vec![coinbase2],
        }
    };
    assert_eq!(
        validate_block_context(&bad_block, &view, false),
        Err(ValidationError::TimestampTooEarly),
    );
}

#[test]
fn stage2_bip34_height_missing_rejected() {
    let view = build_chain_at(
        BIP34_HEIGHT - 1u32,
        mantle::primitives::CompactBits::new(0x207f_ffff),
        1_000_000,
    );
    let tip = view.tip();
    assert_eq!(tip.height, BIP34_HEIGHT - 1u32);

    let parent_bits = view
        .get_header_at(tip.height)
        .expect("storage error")
        .expect("tip header must exist")
        .bits();
    let parent_time = view
        .get_header_at(tip.height)
        .expect("storage error")
        .expect("tip header must exist")
        .time();

    // coinbase with NO height encoding — just padding bytes.
    let bad_script = vec![0x51, 0x52]; // does not start with encoded height
    let coinbase = Transaction {
        version: TxVersion::new(1),
        inputs: vec![coinbase_input(bad_script)],
        outputs: vec![make_output(50_0000_0000)],
        locktime: Locktime::new(0),
    };
    let txids = vec![coinbase.txid().expect("txid encoding cannot fail")];
    let merkle_root = compute_merkle_root(&txids).expect("single-tx merkle root must exist");
    let block = Block {
        header: BlockHeader::new(
            BlockVersion::new(4),
            tip.hash,
            merkle_root,
            parent_time + 600,
            parent_bits,
            Nonce::new(0),
        ),
        transactions: vec![coinbase],
    };
    assert_eq!(
        validate_block_context(&block, &view, false),
        Err(ValidationError::Bip34HeightMissing),
    );
}

#[test]
fn stage2_bip34_correct_encoding_accepted() {
    let view = build_chain_at(
        BIP34_HEIGHT - 1u32,
        mantle::primitives::CompactBits::new(0x207f_ffff),
        1_000_000,
    );
    let block = stage2_block_for_height(&view, BIP34_HEIGHT, 4);
    // Stage 1 uses easiest PoW so it passes; Stage 2 should also pass.
    validate_block_context(&block, &view, false)
        .expect("block with correct BIP34 height encoding must pass Stage 2");
}

#[test]
fn stage2_block_version_too_low_rejected() {
    let view = build_chain_at(
        BlockHeight::new(388_381 - 1),
        mantle::primitives::CompactBits::new(0x207f_ffff),
        1_000_000,
    );
    let block = stage2_block_for_height(&view, BlockHeight::new(388_381), 3); // version 3 < required 4
    assert_eq!(
        validate_block_context(&block, &view, false),
        Err(ValidationError::BlockVersionTooLow {
            version: BlockVersion::new(3),
            required: BlockVersion::new(4),
        }),
    );
}

#[test]
fn stage2_valid_block_accepted() {
    // Small chain, pre-BIP34: no height encoding required, version 1 is fine.
    let view = build_chain(
        5,
        mantle::primitives::CompactBits::new(0x207f_ffff),
        1_000_000,
    );
    let tip = view.tip();
    let parent_bits = view
        .get_header_at(tip.height)
        .expect("storage error")
        .expect("tip header must exist")
        .bits();
    let parent_time = view
        .get_header_at(tip.height)
        .expect("storage error")
        .expect("tip header must exist")
        .time();
    let coinbase = Transaction {
        version: TxVersion::new(1),
        inputs: vec![coinbase_input(vec![0x51, 0x52])],
        outputs: vec![make_output(50_0000_0000)],
        locktime: Locktime::new(0),
    };
    let txids = vec![coinbase.txid().expect("txid encoding cannot fail")];
    let merkle_root = compute_merkle_root(&txids).expect("single-tx merkle root must exist");
    let block = Block {
        header: BlockHeader::new(
            BlockVersion::new(1),
            tip.hash,
            merkle_root,
            parent_time + 600,
            parent_bits,
            Nonce::new(0),
        ),
        transactions: vec![coinbase],
    };
    validate_block_context(&block, &view, false).expect("minimal valid block must pass Stage 2");
}
