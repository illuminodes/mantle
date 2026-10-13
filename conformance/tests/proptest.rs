/// Layer 3: property-based tests using proptest.
///
/// These verify algebraic invariants that hold for all inputs, not just
/// hand-crafted examples. They run on every `cargo test` invocation.
use proptest::prelude::*;

use mantle::codec::{Decode, Encode, VarInt};
use mantle::primitives::{
    Block, BlockHeader, BlockTime, BlockVersion, CompactBits, Hash256, Locktime, Nonce, OutPoint,
    Sequence, Transaction, TxIn, TxOut, TxVersion, Witness,
};
use std::io::Cursor;

use mantle_consensus::merkle::compute_merkle_root;

// ── Codec roundtrip strategies ────────────────────────────────────────────────

fn arb_hash256() -> impl Strategy<Value = Hash256> {
    any::<[u8; 32]>().prop_map(Hash256::from_bytes)
}

fn arb_varint() -> impl Strategy<Value = VarInt> {
    // Cover all four encoding lengths: 1-byte, 3-byte, 5-byte, 9-byte.
    prop_oneof![
        (0u64..=0xfc_u64).prop_map(VarInt::from),
        (0xfd_u64..=0xffff_u64).prop_map(VarInt::from),
        (0x1_0000_u64..=0xffff_ffff_u64).prop_map(VarInt::from),
        (0x1_0000_0000_u64..=u64::MAX).prop_map(VarInt::from),
    ]
}

fn arb_block_header() -> impl Strategy<Value = BlockHeader> {
    (
        any::<i32>(),
        arb_hash256(),
        arb_hash256(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
    )
        .prop_map(|(version, prev_block, merkle_root, time, bits, nonce)| {
            BlockHeader::new(
                BlockVersion::new(version),
                prev_block,
                merkle_root,
                BlockTime::new(time),
                CompactBits::new(bits),
                Nonce::new(nonce),
            )
        })
}

fn arb_txout() -> impl Strategy<Value = TxOut> {
    (
        any::<u64>(),
        prop::collection::vec(any::<u8>(), 0..=256_usize),
    )
        .prop_map(|(value, script_pubkey)| TxOut {
            value: mantle::primitives::Satoshi::new(value),
            script_pubkey: script_pubkey.into(),
        })
}

fn arb_txin() -> impl Strategy<Value = TxIn> {
    (
        arb_hash256(),
        any::<u32>(),
        prop::collection::vec(any::<u8>(), 0..=256_usize),
        any::<u32>(),
    )
        .prop_map(|(txid, vout, script_sig, sequence)| TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: script_sig.into(),
            sequence: Sequence::new(sequence),
            witness: Witness::empty(),
        })
}

fn arb_transaction() -> impl Strategy<Value = Transaction> {
    (
        any::<i32>(),
        prop::collection::vec(arb_txin(), 1..=8_usize),
        prop::collection::vec(arb_txout(), 0..=8_usize),
        any::<u32>(),
    )
        .prop_map(|(version, inputs, outputs, locktime)| Transaction {
            version: TxVersion::new(version),
            inputs,
            outputs,
            locktime: Locktime::new(locktime),
        })
}

fn arb_block() -> impl Strategy<Value = Block> {
    (
        arb_block_header(),
        prop::collection::vec(arb_transaction(), 0..=4_usize),
    )
        .prop_map(|(header, transactions)| Block {
            header,
            transactions,
        })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn encode_to_vec<T: Encode>(val: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    val.encode(&mut buf).expect("Vec<u8> write cannot fail");
    buf
}

// ── VarInt properties ─────────────────────────────────────────────────────────

proptest! {
    /// VarInt encode→decode roundtrip is lossless for all values.
    #[test]
    fn varint_roundtrip(v in arb_varint()) {
        let encoded = encode_to_vec(&v);
        let decoded = VarInt::decode(&mut Cursor::new(&encoded))
            .expect("VarInt roundtrip must decode");
        prop_assert_eq!(decoded, v);
    }

    /// VarInt encoded_len matches the actual byte count.
    #[test]
    fn varint_encoded_len_matches(v in arb_varint()) {
        let encoded = encode_to_vec(&v);
        prop_assert_eq!(v.encoded_len(), encoded.len());
    }

    /// VarInt canonicality: re-encoding a decoded value produces identical bytes.
    /// This catches non-canonical encodings that decode and re-encode differently.
    #[test]
    fn varint_canonical(v in arb_varint()) {
        let first = encode_to_vec(&v);
        let decoded = VarInt::decode(&mut Cursor::new(&first))
            .expect("VarInt canonical decode must succeed");
        let second = encode_to_vec(&decoded);
        prop_assert_eq!(first, second, "VarInt({}) re-encoded differently", v.to_u64());
    }
}

// ── BlockHeader codec properties ──────────────────────────────────────────────

proptest! {
    /// BlockHeader encode→decode roundtrip is lossless.
    #[test]
    fn block_header_roundtrip(h in arb_block_header()) {
        let encoded = encode_to_vec(&h);
        prop_assert_eq!(encoded.len(), BlockHeader::ENCODED_LEN);
        let decoded = BlockHeader::decode(&mut Cursor::new(&encoded))
            .expect("BlockHeader roundtrip must decode");
        prop_assert_eq!(decoded, h);
    }

    /// to_bytes / from_bytes agree with encode / decode.
    #[test]
    fn block_header_to_from_bytes_agrees(h in arb_block_header()) {
        let via_encode = encode_to_vec(&h);
        let via_to_bytes = h.to_bytes();
        prop_assert_eq!(&via_encode[..], &via_to_bytes[..]);

        let from_encode = BlockHeader::decode(&mut Cursor::new(&via_encode))
            .expect("BlockHeader from_encode must decode");
        let from_bytes = BlockHeader::from_bytes(via_to_bytes);
        prop_assert_eq!(from_encode, from_bytes);
    }
}

// ── Transaction codec properties ──────────────────────────────────────────────

proptest! {
    /// Transaction encode→decode roundtrip is lossless.
    #[test]
    fn transaction_roundtrip(tx in arb_transaction()) {
        let encoded = encode_to_vec(&tx);
        let decoded = Transaction::decode(&mut Cursor::new(&encoded))
            .expect("Transaction roundtrip must decode");
        prop_assert_eq!(decoded, tx);
    }
}

// ── Block codec properties ────────────────────────────────────────────────────

proptest! {
    /// Block encode→decode roundtrip is lossless.
    #[test]
    fn block_roundtrip(b in arb_block()) {
        let encoded = encode_to_vec(&b);
        let decoded = Block::decode(&mut Cursor::new(&encoded))
            .expect("Block roundtrip must decode");
        prop_assert_eq!(decoded, b);
    }
}

// ── ScriptFlags::for_height parity ───────────────────────────────────────────

proptest! {
    /// `ScriptFlags::for_height` must match `bitcoinconsensus::height_to_flags`
    /// at every mainnet height. This is the M4 gate: all flag bits are active.
    #[test]
    fn flags_for_height_matches_bitcoinconsensus(h in 0u32..=900_000u32) {
        use mantle::primitives::BlockHeight;
        use mantle_conformance::conformance;
        use mantle_consensus::script::ScriptFlags;

        let oracle = conformance::flags_for_height(h);
        let ours   = ScriptFlags::for_height(BlockHeight::new(h)).bits();
        prop_assert_eq!(
            oracle, ours,
            "flags_for_height({}) diverged: oracle={:#010x} ours={:#010x}",
            h, oracle, ours
        );
    }
}

// ── ScriptExecutionCache: cached == uncached verdict ─────────────────────────

proptest! {
    /// The cached verifier must agree with the uncached one on every call,
    /// cold or warm, and a warm success must come from the cache.
    #[test]
    fn exec_cache_same_verdict_cold_vs_hot(
        script_sig  in prop::collection::vec(any::<u8>(), 0..=32_usize),
        script_pubkey in prop::collection::vec(any::<u8>(), 0..=32_usize),
        amount      in any::<u64>(),
    ) {
        use mantle::primitives::{Hash256, OutPoint, Satoshi, TxIn, TxOut, Witness};
        use mantle_consensus::script::{ScriptExecutionCache, ScriptFlags, ScriptVerifier, verify_script};
        use mantle_consensus::tx_view::TxView;

        let flags = ScriptFlags::NONE;
        let amount = Satoshi::new(amount);
        let tx = Transaction {
            version: TxVersion::new(1),
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Hash256::ZERO, vout: 0 },
                script_sig: script_sig.clone().into(),
                sequence: Sequence::new(0xffff_ffff),
                witness: Witness::empty(),
            }],
            outputs: vec![TxOut {
                value: amount,
                script_pubkey: vec![0x51].into(),
            }],
            locktime: Locktime::new(0),
        };

        let wtxid = tx.compute_wtxid(&mut Vec::new()).expect("wtxid");
        let verifier = ScriptVerifier::new(&tx, 0, amount, flags);
        let reference = verify_script(&script_sig, &script_pubkey, &tx, 0, amount, flags);

        let mut cache = ScriptExecutionCache::new(64);
        let cold = verifier.verify_cached(&script_sig, &script_pubkey, &wtxid, &mut cache);
        let hot  = verifier.verify_cached(&script_sig, &script_pubkey, &wtxid, &mut cache);
        prop_assert_eq!(&cold, &reference);
        prop_assert_eq!(&hot, &reference);
        prop_assert_eq!(cache.hits(), u64::from(reference.is_ok()));
    }
}

// ── Merkle tree properties ────────────────────────────────────────────────────

proptest! {
    /// Merkle root is deterministic: same input always produces same output.
    #[test]
    fn merkle_deterministic(txids in prop::collection::vec(arb_hash256(), 1..=16_usize)) {
        let r1 = compute_merkle_root(&txids);
        let r2 = compute_merkle_root(&txids);
        prop_assert_eq!(r1, r2);
    }

    /// Single-tx merkle root equals the txid itself (no hashing).
    #[test]
    fn merkle_single_tx_is_txid(txid in arb_hash256()) {
        let root = compute_merkle_root(&[txid])
            .expect("single-element merkle root must exist");
        prop_assert_eq!(root, txid);
    }

    /// Empty slice returns None.
    #[test]
    fn merkle_empty_is_none(_x in any::<u8>()) {
        prop_assert!(compute_merkle_root(&[]).is_none());
    }

    /// Appending a duplicate of the last element to an odd-length list does not
    /// change the root (that's exactly what the algorithm does internally).
    #[test]
    fn merkle_odd_duplicate_invariant(
        txids in prop::collection::vec(arb_hash256(), 3..=15_usize).prop_filter(
            "must be odd length >= 3",
            |v| v.len() % 2 == 1,
        )
    ) {
        let root_odd = compute_merkle_root(&txids)
            .expect("odd-length merkle root must exist");
        let mut padded = txids.clone();
        padded.push(txids[txids.len() - 1]);
        let root_padded = compute_merkle_root(&padded)
            .expect("padded merkle root must exist");
        prop_assert_eq!(root_odd, root_padded,
            "odd-length duplicate invariant broken for {} txids", txids.len());
    }
}
