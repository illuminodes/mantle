/// Layer 4: BIP test vectors and static regression fixtures.
///
/// These are static, hand-encoded constants derived from known-good Bitcoin
/// data. No runtime file I/O; everything compiles into the test binary.
use mantle::codec::{Decode, Encode};
use mantle::primitives::{
    Block, BlockHeader, BlockHeight, BlockTime, BlockVersion, Hash256, Locktime, Nonce, OutPoint,
    Sequence, Transaction, TxHash, TxIn, TxOut, TxVersion, Witness,
};
use std::io::Cursor;

use mantle_consensus::chain_view::{ChainView, Coin, MemoryChainView};
use mantle_consensus::error::ValidationError;
use mantle_consensus::genesis::{GENESIS_BLOCK_HASH, GENESIS_BLOCK_HEX};
use mantle_consensus::merkle::compute_merkle_root;
use mantle_consensus::test_helpers::{decode_hex, hash_to_hex};
use mantle_consensus::validation::{
    BIP34_HEIGHT, MAX_COINBASE_SCRIPTSIG_LEN, MAX_MONEY, MIN_COINBASE_SCRIPTSIG_LEN,
    validate_block_context, validate_block_structure,
};

mod bip112;
mod bip143;
mod bip65;
mod bip66;
mod fixtures;
mod genesis;
mod stage1;
mod stage2;
mod taproot;

fn hash_to_hex_display(hash: Hash256) -> String {
    hash_to_hex(*hash.as_bytes())
}

/// Build the minimal null-outpoint input (coinbase marker).
fn coinbase_input(script_sig: Vec<u8>) -> TxIn {
    TxIn {
        previous_output: OutPoint {
            txid: Hash256::ZERO,
            vout: u32::MAX,
        },
        script_sig: script_sig.into(),
        sequence: Sequence::MAX,
        witness: Witness::empty(),
    }
}

fn make_output(value: u64) -> TxOut {
    TxOut {
        value: mantle::primitives::Satoshi::new(value),
        script_pubkey: vec![0x51].into(),
    } // OP_1 (trivial P2PK stand-in)
}

/// Build a minimal valid block whose Stage 1 checks pass.
///
/// The caller supplies the coinbase scriptSig. nBits is set to the easiest
/// possible target (0x207fffff) so proof-of-work is trivially satisfied.
fn minimal_block(coinbase_script_sig: Vec<u8>, transactions: Vec<Transaction>) -> Block {
    let coinbase = Transaction {
        version: TxVersion::new(1),
        inputs: vec![coinbase_input(coinbase_script_sig)],
        outputs: vec![make_output(50_0000_0000)],
        locktime: Locktime::new(0),
    };

    let mut txs = vec![coinbase];
    txs.extend(transactions);

    let txids: Vec<Hash256> = txs
        .iter()
        .map(Transaction::txid)
        .collect::<Result<Vec<_>, _>>()
        .expect("txid encoding cannot fail");
    let merkle_root = compute_merkle_root(&txids).expect("non-empty tx list must have merkle root");

    Block {
        header: BlockHeader::new(
            BlockVersion::new(4),
            Hash256::ZERO,
            merkle_root,
            BlockTime::new(1_231_006_505),
            mantle::primitives::CompactBits::new(0x207f_ffff), // regtest easiest target
            Nonce::new(0),
        ),
        transactions: txs,
    }
}

// ── Build a MemoryChainView with N sequential headers ─────────────────────────

fn build_chain(n: u32, bits: mantle::primitives::CompactBits, base_time: u32) -> MemoryChainView {
    let mut view = MemoryChainView::new();
    let mut prev = Hash256::ZERO;
    for i in 0..n {
        let h = BlockHeader::new(
            BlockVersion::new(4),
            prev,
            Hash256::ZERO,
            BlockTime::new(base_time + i * 600),
            bits,
            Nonce::new(0),
        );
        prev = h.hash();
        view.push_header(h);
    }
    view
}

/// Build a chain whose tip is at `tip_height` by only storing the last 12
/// headers. Validation only needs the parent + 11 ancestors for MTP.
fn build_chain_at(
    tip_height: BlockHeight,
    bits: mantle::primitives::CompactBits,
    base_time: u32,
) -> MemoryChainView {
    let window = 12u32;
    let start = tip_height.to_u32().saturating_sub(window - 1);
    let mut view = MemoryChainView::with_height_base(BlockHeight::new(start));
    let mut prev = Hash256::ZERO;
    for i in 0..window {
        let h = BlockHeader::new(
            BlockVersion::new(4),
            prev,
            Hash256::ZERO,
            BlockTime::new(base_time + (start + i) * 600),
            bits,
            Nonce::new(0),
        );
        prev = h.hash();
        view.push_header(h);
    }
    view
}
