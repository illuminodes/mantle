use mantle::codec::Encode;
use mantle::primitives::{
    Block, BlockHeader, BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Locktime,
    Nonce, OutPoint, Satoshi, Sequence, Transaction, TxHash, TxIn, TxOut, TxVersion, Witness,
};
use mantle_consensus::chain_view::{ChainView, Coin, MemoryChainView};
use mantle_consensus::merkle::{compute_merkle_root, compute_merkle_root_reusing};
use mantle_consensus::validation::{
    FixedClock, validate_block_context_with_clock, validate_block_structure, validate_block_wire,
};
use std::hint::black_box;

fn main() {
    divan::main();
}

// ── Shared helpers ──────────────────────────────────────────────────────────

const EASY_BITS: CompactBits = CompactBits::new(0x207f_ffff);

fn coinbase_tx(value: u64) -> Transaction {
    Transaction {
        version: TxVersion::new(1),
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::ZERO,
                vout: u32::MAX,
            },
            script_sig: vec![0x03, 0x01, 0x00, 0x00].into(), // BIP34 height=1
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

fn regular_tx(prev: Hash256, vout: u32, value: u64) -> Transaction {
    Transaction {
        version: TxVersion::new(1),
        inputs: vec![TxIn {
            previous_output: OutPoint { txid: prev, vout },
            script_sig: vec![0x51].into(),
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

fn mine_block(mut block: Block) -> Block {
    let target = block
        .header
        .bits()
        .to_target()
        .expect("EASY_BITS must produce a valid target");
    for nonce in 0..=u32::MAX {
        block.header.set_nonce(Nonce::new(nonce));
        let raw = *Hash256::hash(&block.header.to_bytes()).as_bytes();
        let mut be = raw;
        be.reverse();
        if be <= target {
            return block;
        }
    }
    panic!("no valid nonce found");
}

fn make_valid_block(txs: Vec<Transaction>) -> Block {
    let txids: Vec<Hash256> = txs
        .iter()
        .map(|tx| tx.txid().expect("txid encoding cannot fail"))
        .collect();
    let merkle_root =
        compute_merkle_root(&txids).expect("non-empty tx list must have a merkle root");
    let block = Block {
        header: BlockHeader::new(
            BlockVersion::new(1),
            Hash256::ZERO,
            merkle_root,
            BlockTime::new(1_231_006_505),
            EASY_BITS,
            Nonce::new(0),
        ),
        transactions: txs,
    };
    mine_block(block)
}

fn build_chain(len: u32) -> MemoryChainView {
    let mut view = MemoryChainView::new();
    let mut prev = Hash256::ZERO;
    for i in 0..len {
        let h = BlockHeader::new(
            BlockVersion::new(4),
            prev,
            Hash256::ZERO,
            BlockTime::new(1_296_688_602 + i * 600),
            EASY_BITS,
            Nonce::new(0),
        );
        prev = h.hash();
        view.push_header(h);
    }
    view
}

fn make_n_tx_block(n: usize) -> Block {
    let mut txs = vec![coinbase_tx(5_000_000_000)];
    for i in 1..n {
        txs.push(regular_tx(
            Hash256::from_bytes([u8::try_from(i & 0xff).unwrap(); 32]),
            0,
            1000,
        ));
    }
    make_valid_block(txs)
}

// ── txid ────────────────────────────────────────────────────────────────────

mod txid {
    use super::{
        Hash256, OutPoint, Sequence, Transaction, TxHash, TxIn, Witness, black_box, coinbase_tx,
        regular_tx,
    };

    #[divan::bench]
    fn coinbase() {
        black_box(
            coinbase_tx(5_000_000_000)
                .txid()
                .expect("txid encoding cannot fail"),
        );
    }

    #[divan::bench(args = [1usize, 4, 16])]
    fn regular(bencher: divan::Bencher, n_inputs: usize) {
        let tx = regular_tx(Hash256::from_bytes([0xabu8; 32]), 0, 1000);
        let big_tx = Transaction {
            inputs: (0..n_inputs)
                .map(|i| TxIn {
                    previous_output: OutPoint {
                        txid: Hash256::from_bytes(
                            [u8::try_from(i).expect("bench index fits u8"); 32],
                        ),
                        vout: u32::try_from(i).expect("bench index fits u32"),
                    },
                    script_sig: vec![0x51; 20].into(),
                    sequence: Sequence::MAX,
                    witness: Witness::empty(),
                })
                .collect(),
            ..tx
        };
        bencher.bench(|| black_box(big_tx.txid()));
    }
}

// ── merkle_root ─────────────────────────────────────────────────────────────

mod merkle_root {
    use super::{Hash256, black_box, compute_merkle_root, compute_merkle_root_reusing};

    fn make_txids(n: usize) -> Vec<Hash256> {
        (0..n)
            .map(|i| Hash256::from_bytes([u8::try_from(i & 0xff).unwrap(); 32]))
            .collect()
    }

    #[divan::bench(args = [1usize, 2, 3, 7, 8, 100, 2000])]
    fn fresh(bencher: divan::Bencher, n: usize) {
        let txids = make_txids(n);
        bencher.bench(|| compute_merkle_root(black_box(&txids)));
    }

    #[divan::bench(args = [1usize, 2, 3, 7, 8, 100, 2000])]
    fn reusing(bencher: divan::Bencher, n: usize) {
        let txids = make_txids(n);
        let mut buf: Vec<Hash256> = Vec::with_capacity(n);
        bencher.bench_local(|| compute_merkle_root_reusing(black_box(&txids), &mut buf));
    }

    /// 9,001 leaves — matches Bitcoin Core's `MerkleRoot` bench
    /// (`src/bench/merkle_root.cpp`).
    #[divan::bench]
    fn core_parity_9001(bencher: divan::Bencher) {
        let txids: Vec<Hash256> = (0..9_001usize)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = u8::try_from(i & 0xff).unwrap();
                h[1] = u8::try_from((i >> 8) & 0xff).unwrap();
                Hash256::from_bytes(h)
            })
            .collect();
        bencher.bench(|| compute_merkle_root(black_box(&txids)));
    }

    /// Same workload with the reusing variant — measures allocation savings
    /// vs Core's single-allocation path.
    #[divan::bench]
    fn core_parity_9001_reusing(bencher: divan::Bencher) {
        let txids: Vec<Hash256> = (0..9_001usize)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = u8::try_from(i & 0xff).unwrap();
                h[1] = u8::try_from((i >> 8) & 0xff).unwrap();
                Hash256::from_bytes(h)
            })
            .collect();
        let mut buf: Vec<Hash256> = Vec::with_capacity(9_001);
        bencher.bench_local(|| compute_merkle_root_reusing(black_box(&txids), &mut buf));
    }
}

// ── validate_block_structure (Stage 1) ──────────────────────────────────────

mod stage1_structure {
    use super::{
        black_box, coinbase_tx, make_n_tx_block, make_valid_block, validate_block_structure,
    };

    #[divan::bench]
    fn single_coinbase(bencher: divan::Bencher) {
        let block = make_valid_block(vec![coinbase_tx(5_000_000_000)]);
        bencher.bench(|| {
            validate_block_structure(black_box(&block))
                .expect("valid block must pass structure validation");
        });
    }

    #[divan::bench(args = [2usize, 10, 100])]
    fn n_txs(bencher: divan::Bencher, n: usize) {
        let block = make_n_tx_block(n);
        bencher.bench(|| {
            validate_block_structure(black_box(&block))
                .expect("valid block must pass structure validation");
        });
    }
}

// ── validate_block_wire (Stage 1, zero-copy) ────────────────────────────────

mod stage1_wire {
    use super::{
        Encode, black_box, coinbase_tx, make_n_tx_block, make_valid_block, validate_block_wire,
    };

    #[divan::bench]
    fn single_coinbase(bencher: divan::Bencher) {
        let block = make_valid_block(vec![coinbase_tx(5_000_000_000)]);
        let mut wire = Vec::new();
        block.encode(&mut wire).expect("Vec<u8> write cannot fail");
        let mut t = Vec::new();
        let mut mb = Vec::new();
        let mut si = std::collections::HashSet::new();
        let mut st = std::collections::HashSet::new();
        bencher.bench_local(|| {
            validate_block_wire(black_box(&wire), &mut t, &mut mb, &mut si, &mut st)
                .expect("valid block wire must pass validation");
        });
    }

    #[divan::bench(args = [2usize, 10, 100])]
    fn n_txs(bencher: divan::Bencher, n: usize) {
        let block = make_n_tx_block(n);
        let mut wire = Vec::new();
        block.encode(&mut wire).expect("Vec<u8> write cannot fail");
        let mut t = Vec::new();
        let mut mb = Vec::new();
        let mut si = std::collections::HashSet::new();
        let mut st = std::collections::HashSet::new();
        bencher.bench_local(|| {
            validate_block_wire(black_box(&wire), &mut t, &mut mb, &mut si, &mut st)
                .expect("valid block wire must pass validation");
        });
    }
}

// ── validate_block_context (Stage 2) ────────────────────────────────────────

mod stage2_context {
    use super::{
        Block, BlockHeader, BlockTime, BlockVersion, ChainView, EASY_BITS, FixedClock, Hash256,
        Locktime, Nonce, OutPoint, Satoshi, Sequence, Transaction, TxHash, TxIn, TxOut, TxVersion,
        Witness, black_box, build_chain, compute_merkle_root, validate_block_context_with_clock,
    };

    #[divan::bench]
    fn chain_12(bencher: divan::Bencher) {
        let view = build_chain(12);
        let tip = view.tip();
        let parent_time = view
            .get_header_at(tip.height)
            .expect("storage error")
            .expect("tip header must exist")
            .time();
        let clock_now = u64::from(parent_time) + 600;

        let tx = Transaction {
            version: TxVersion::new(4),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::ZERO,
                    vout: u32::MAX,
                },
                script_sig: vec![0x03, 0x0d, 0x00, 0x00].into(), // height=13
                sequence: Sequence::MAX,
                witness: Witness::empty(),
            }],
            outputs: vec![TxOut {
                value: Satoshi::new(5_000_000_000),
                script_pubkey: vec![0x51].into(),
            }],
            locktime: Locktime::new(0),
        };
        let merkle_root = compute_merkle_root(&[tx.txid().expect("txid encoding cannot fail")])
            .expect("single-tx merkle root must exist");
        let mtp = view
            .median_time_past(&BlockHeader::new(
                BlockVersion::new(4),
                tip.hash,
                Hash256::ZERO,
                BlockTime::new(0),
                EASY_BITS,
                Nonce::new(0),
            ))
            .expect("median_time_past must succeed on valid chain");
        let block = Block {
            header: BlockHeader::new(
                BlockVersion::new(4),
                tip.hash,
                merkle_root,
                BlockTime::new((mtp + 1).to_u32()),
                EASY_BITS,
                Nonce::new(0),
            ),
            transactions: vec![tx],
        };
        let clock = FixedClock(clock_now + 3600);
        bencher.bench(|| {
            validate_block_context_with_clock(black_box(&block), &view, &clock, false)
                .expect("valid block must pass context validation");
        });
    }
}

// ── MemoryChainView lookups ─────────────────────────────────────────────────

mod chain_view {
    use super::{
        BlockHeader, BlockHeight, BlockTime, BlockVersion, ChainView, Coin, EASY_BITS, Hash256,
        MemoryChainView, Nonce, OutPoint, Satoshi, black_box, build_chain,
    };

    #[divan::bench]
    fn get_header_by_hash(bencher: divan::Bencher) {
        let view = build_chain(100);
        let tip = view.tip();
        bencher.bench(|| {
            view.get_header(black_box(&tip.hash))
                .expect("storage error")
        });
    }

    #[divan::bench]
    fn get_header_at(bencher: divan::Bencher) {
        let view = build_chain(100);
        bencher.bench(|| {
            view.get_header_at(black_box(BlockHeight::new(50)))
                .expect("storage error")
        });
    }

    #[divan::bench]
    fn height_of(bencher: divan::Bencher) {
        let view = build_chain(100);
        let tip = view.tip();
        bencher.bench(|| view.height_of(black_box(&tip.hash)).expect("storage error"));
    }

    #[divan::bench]
    fn tip(bencher: divan::Bencher) {
        let view = build_chain(100);
        bencher.bench(|| black_box(view.tip()));
    }

    #[divan::bench]
    fn get_coin_hit(bencher: divan::Bencher) {
        let mut view = MemoryChainView::new();
        let op = OutPoint {
            txid: Hash256::from_bytes([1u8; 32]),
            vout: 0,
        };
        view.insert_coin(
            op,
            Coin {
                value: Satoshi::new(5_000_000_000),
                script_pubkey: vec![0x51].into(),
                height: BlockHeight::new(1),
                coinbase: false,
            },
        );
        bencher.bench(|| view.get_coin(black_box(&op)).expect("storage error"));
    }

    #[divan::bench]
    fn get_coin_miss(bencher: divan::Bencher) {
        let view = MemoryChainView::new();
        let op = OutPoint {
            txid: Hash256::from_bytes([0xffu8; 32]),
            vout: 0,
        };
        bencher.bench(|| view.get_coin(black_box(&op)).expect("storage error"));
    }

    #[divan::bench(args = [1usize, 10, 100])]
    fn get_coins_batch(bencher: divan::Bencher, n: usize) {
        let mut view = MemoryChainView::new();
        let ops: Vec<OutPoint> = (0..n)
            .map(|i| OutPoint {
                txid: Hash256::from_bytes([u8::try_from(i).expect("bench index fits u8"); 32]),
                vout: 0,
            })
            .collect();
        for &op in &ops {
            view.insert_coin(
                op,
                Coin {
                    value: Satoshi::new(1000),
                    script_pubkey: vec![].into(),
                    height: BlockHeight::new(1),
                    coinbase: false,
                },
            );
        }
        let mut out = Vec::new();
        bencher.bench_local(|| {
            view.get_coins_into(black_box(&ops), &mut out)
                .expect("storage error");
        });
    }

    #[divan::bench]
    fn median_time_past(bencher: divan::Bencher) {
        let view = build_chain(12);
        let tip = view.tip();
        let next_header = BlockHeader::new(
            BlockVersion::new(4),
            tip.hash,
            Hash256::ZERO,
            BlockTime::new(0),
            EASY_BITS,
            Nonce::new(0),
        );
        bencher.bench(|| {
            view.median_time_past(black_box(&next_header))
                .expect("median_time_past must succeed on valid chain")
        });
    }
}
