use super::*;

// ── Genesis block BIP vectors ─────────────────────────────────────────────────

#[test]
fn genesis_decode_and_stage1_pass() {
    let bytes = decode_hex(GENESIS_BLOCK_HEX);
    let block = Block::decode(&mut Cursor::new(&bytes)).expect("genesis block must decode");

    // The genesis block predates BIP34, so validate_block_structure should pass.
    // The nBits is 0x1d00ffff; genesis hash is known to satisfy that target.
    validate_block_structure(&block).expect("genesis block must pass Stage 1");
}

#[test]
fn genesis_hash_matches_known_constant() {
    let bytes = decode_hex(GENESIS_BLOCK_HEX);
    let raw = *Hash256::hash(&bytes[..BlockHeader::ENCODED_LEN]).as_bytes();
    assert_eq!(
        hash_to_hex_display(Hash256::from_bytes(raw)),
        GENESIS_BLOCK_HASH
    );
}

#[test]
fn genesis_txid_matches_merkle_root() {
    let bytes = decode_hex(GENESIS_BLOCK_HEX);
    let block = Block::decode(&mut Cursor::new(&bytes)).expect("genesis block must decode");

    let mut tx_bytes = Vec::new();
    block.transactions[0]
        .encode(&mut tx_bytes)
        .expect("Vec<u8> write cannot fail");
    let computed_txid = Hash256::hash(&tx_bytes);

    // Genesis has one tx — merkle root equals the txid (no pair hashing).
    assert_eq!(block.header.merkle_root(), computed_txid);
}
