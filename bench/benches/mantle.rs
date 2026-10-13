use mantle::block::BlockRef;
use mantle::codec::{Decode, DecodeRef, Encode, VarInt};
use mantle::difficulty::BlockHeight;
use mantle::network::{
    AddrEntry, AddrMsg, Command, CommandName, GetHeadersMsg, HeadersMsg, InvEntry, InvMsg, InvType,
    Magic, MessageHeader, NetworkAddr, PeerNonce, PingMsg, Port, ProtocolVersion, Services,
    Timestamp, VersionMsg, VersionMsgRef, encode_message,
};
use mantle::primitives::{
    Block, BlockHeader, BlockTime, BlockVersion, CompactBits, Hash256, Locktime, Nonce, OutPoint,
    Satoshi, Sequence, Transaction, TransactionRef, TxHash, TxIn, TxInRef, TxOut, TxOutRef,
    TxVersion, Witness,
};
use mantle::tx::transaction_ref_with_arena;
use std::hint::black_box;
use std::io::Cursor;

fn main() {
    divan::main();
}

fn encode_bytes<T: Encode>(val: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    val.encode(&mut buf).expect("Vec<u8> write cannot fail");
    buf
}

// ── Newtype codec ────────────────────────────────────────────────────────────

mod newtypes {
    use super::{BlockTime, DecodeRef, PeerNonce, ProtocolVersion, Satoshi, Services, Timestamp};

    #[divan::bench]
    fn satoshi_decode_ref() -> (Satoshi, &'static [u8]) {
        Satoshi::decode_ref(&[0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00])
            .expect("Satoshi decode_ref cannot fail on 8 bytes")
    }

    #[divan::bench]
    fn block_time_decode_ref() -> (BlockTime, &'static [u8]) {
        BlockTime::decode_ref(&[0x29, 0xab, 0x5f, 0x49])
            .expect("BlockTime decode_ref cannot fail on 4 bytes")
    }

    #[divan::bench]
    fn services_decode_ref() -> (Services, &'static [u8]) {
        Services::decode_ref(&[0x0d, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            .expect("Services decode_ref cannot fail on 8 bytes")
    }

    #[divan::bench]
    fn protocol_version_decode_ref() -> (ProtocolVersion, &'static [u8]) {
        ProtocolVersion::decode_ref(&[0x7f, 0x11, 0x01, 0x00])
            .expect("ProtocolVersion decode_ref cannot fail on 4 bytes")
    }

    #[divan::bench]
    fn peer_nonce_decode_ref() -> (PeerNonce, &'static [u8]) {
        PeerNonce::decode_ref(&[0xef, 0xbe, 0xad, 0xde, 0xfe, 0xca, 0x00, 0x00])
            .expect("PeerNonce decode_ref cannot fail on 8 bytes")
    }

    #[divan::bench]
    fn timestamp_decode_ref() -> (Timestamp, &'static [u8]) {
        Timestamp::decode_ref(&[0x00, 0x94, 0x35, 0x77, 0x00, 0x00, 0x00, 0x00])
            .expect("Timestamp decode_ref cannot fail on 8 bytes")
    }
}

// ── Hash256 ──────────────────────────────────────────────────────────────────

mod hash256 {
    use super::{Cursor, Decode, DecodeRef, Hash256, encode_bytes};

    #[divan::bench]
    fn encode() -> Vec<u8> {
        encode_bytes(&Hash256::from_bytes([0xabu8; 32]))
    }

    #[divan::bench]
    fn decode() -> Hash256 {
        Hash256::decode(&mut Cursor::new([0xabu8; 32].as_slice()))
            .expect("Hash256 decode cannot fail on 32 bytes")
    }

    #[divan::bench]
    fn decode_ref() -> (Hash256, &'static [u8]) {
        Hash256::decode_ref(&[0xabu8; 32]).expect("Hash256 decode_ref cannot fail on 32 bytes")
    }
}

// ── BlockHeader ──────────────────────────────────────────────────────────────

fn make_header(i: usize) -> BlockHeader {
    BlockHeader::new(
        BlockVersion::new(1),
        Hash256::from_bytes([u8::try_from(i & 0xff).unwrap(); 32]),
        Hash256::ZERO,
        BlockTime::new(u32::try_from(i).unwrap_or(0)),
        CompactBits::new(0x1d00_ffff),
        Nonce::new(u32::try_from(i).unwrap_or(0)),
    )
}

mod block_header {
    use super::{BlockHeader, Cursor, Decode, DecodeRef, encode_bytes, make_header};

    #[divan::bench]
    fn to_bytes() -> [u8; 80] {
        make_header(42).to_bytes()
    }

    #[divan::bench]
    fn from_bytes(bencher: divan::Bencher) {
        let bytes = make_header(42).to_bytes();
        bencher.bench(|| BlockHeader::from_bytes(bytes));
    }

    #[divan::bench]
    fn encode() -> Vec<u8> {
        encode_bytes(&make_header(42))
    }

    #[divan::bench]
    fn decode(bencher: divan::Bencher) {
        let bytes = encode_bytes(&make_header(42));
        bencher.bench(|| {
            BlockHeader::decode(&mut Cursor::new(bytes.as_slice()))
                .expect("BlockHeader decode cannot fail on valid bytes")
        });
    }

    #[divan::bench]
    fn decode_ref(bencher: divan::Bencher) {
        let bytes = encode_bytes(&make_header(42));
        bencher.bench(|| {
            BlockHeader::decode_ref(bytes.as_slice())
                .expect("BlockHeader decode_ref cannot fail on valid bytes")
        });
    }
}

// ── OutPoint ─────────────────────────────────────────────────────────────────

mod outpoint {
    use super::{Cursor, Decode, DecodeRef, Hash256, OutPoint, encode_bytes};

    #[divan::bench]
    fn encode() -> Vec<u8> {
        encode_bytes(&OutPoint {
            txid: Hash256::from_bytes([0xabu8; 32]),
            vout: 0,
        })
    }

    #[divan::bench]
    fn decode(bencher: divan::Bencher) {
        let bytes = encode_bytes(&OutPoint {
            txid: Hash256::from_bytes([0xabu8; 32]),
            vout: 0,
        });
        bencher.bench(|| {
            OutPoint::decode(&mut Cursor::new(bytes.as_slice()))
                .expect("OutPoint decode cannot fail on valid bytes")
        });
    }

    #[divan::bench]
    fn decode_ref(bencher: divan::Bencher) {
        let bytes = encode_bytes(&OutPoint {
            txid: Hash256::from_bytes([0xabu8; 32]),
            vout: 0,
        });
        bencher.bench(|| {
            OutPoint::decode_ref(bytes.as_slice())
                .expect("OutPoint decode_ref cannot fail on valid bytes")
        });
    }
}

// ── TxIn / TxInRef ───────────────────────────────────────────────────────────

mod txin {
    use super::{
        Cursor, Decode, DecodeRef, Hash256, OutPoint, Sequence, TxIn, TxInRef, Witness, black_box,
        encode_bytes,
    };

    fn sample() -> TxIn {
        TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_bytes([0xabu8; 32]),
                vout: 0,
            },
            script_sig: vec![0x76; 25].into(),
            sequence: Sequence::MAX,
            witness: Witness::empty(),
        }
    }

    #[divan::bench]
    fn encode() -> Vec<u8> {
        encode_bytes(&sample())
    }

    #[divan::bench]
    fn decode(bencher: divan::Bencher) {
        let bytes = encode_bytes(&sample());
        bencher.bench(|| {
            TxIn::decode(&mut Cursor::new(bytes.as_slice()))
                .expect("TxIn decode cannot fail on valid bytes")
        });
    }

    #[divan::bench]
    fn decode_ref(bencher: divan::Bencher) {
        let bytes = encode_bytes(&sample());
        bencher.bench(|| {
            let (r, _) = TxInRef::decode_ref(bytes.as_slice())
                .expect("TxInRef decode_ref cannot fail on valid bytes");
            black_box(r.sequence)
        });
    }
}

// ── TxOut / TxOutRef ─────────────────────────────────────────────────────────

mod txout {
    use super::{Cursor, Decode, DecodeRef, Satoshi, TxOut, TxOutRef, black_box, encode_bytes};

    fn sample() -> TxOut {
        TxOut {
            value: Satoshi::new(5_000_000_000),
            script_pubkey: vec![0x76, 0xa9, 0x14].into(),
        }
    }

    #[divan::bench]
    fn encode() -> Vec<u8> {
        encode_bytes(&sample())
    }

    #[divan::bench]
    fn decode(bencher: divan::Bencher) {
        let bytes = encode_bytes(&sample());
        bencher.bench(|| {
            TxOut::decode(&mut Cursor::new(bytes.as_slice()))
                .expect("TxOut decode cannot fail on valid bytes")
        });
    }

    #[divan::bench]
    fn decode_ref(bencher: divan::Bencher) {
        let bytes = encode_bytes(&sample());
        bencher.bench(|| {
            let (r, _) = TxOutRef::decode_ref(bytes.as_slice())
                .expect("TxOutRef decode_ref cannot fail on valid bytes");
            black_box(r.value)
        });
    }
}

// ── Transaction / TransactionRef ─────────────────────────────────────────────

fn make_tx(n_inputs: usize, n_outputs: usize) -> Transaction {
    Transaction {
        version: TxVersion::new(1),
        inputs: (0..n_inputs)
            .map(|i| TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([u8::try_from(i & 0xff).unwrap(); 32]),
                    vout: u32::try_from(i).unwrap_or(0),
                },
                script_sig: vec![0x51; 20].into(),
                sequence: Sequence::MAX,
                witness: Witness::empty(),
            })
            .collect(),
        outputs: (0..n_outputs)
            .map(|i| TxOut {
                value: Satoshi::new((i as u64 + 1) * 1000),
                script_pubkey: vec![0x76, 0xa9, 0x14].into(),
            })
            .collect(),
        locktime: Locktime::new(0),
    }
}

fn make_segwit_tx() -> Transaction {
    Transaction {
        version: TxVersion::new(2),
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Hash256::from_bytes([0x11u8; 32]),
                vout: 0,
            },
            script_sig: Vec::<u8>::new().into(),
            sequence: Sequence::new(0xffff_fffe),
            witness: Witness::from_slice(&[&[0xde, 0xad, 0xbe, 0xef][..], &[0x01; 33][..]]),
        }],
        outputs: vec![TxOut {
            value: Satoshi::new(99_000),
            script_pubkey: vec![0x00, 0x14, 0xaa, 0xbb, 0xcc].into(),
        }],
        locktime: Locktime::new(0),
    }
}

mod transaction {
    use super::{
        Cursor, Decode, DecodeRef, Transaction, TransactionRef, TxHash, black_box, encode_bytes,
        make_segwit_tx, make_tx, transaction_ref_with_arena,
    };

    #[divan::bench(args = [1usize, 4, 16])]
    fn encode(bencher: divan::Bencher, n: usize) {
        let tx = make_tx(n, n);
        bencher.bench(|| encode_bytes(&tx));
    }

    #[divan::bench(args = [1usize, 4, 16])]
    fn decode(bencher: divan::Bencher, n: usize) {
        let bytes = encode_bytes(&make_tx(n, n));
        bencher.bench(|| {
            Transaction::decode(&mut Cursor::new(bytes.as_slice()))
                .expect("Transaction decode cannot fail on valid bytes")
        });
    }

    #[divan::bench(args = [1usize, 4, 16])]
    fn decode_ref(bencher: divan::Bencher, n: usize) {
        let bytes = encode_bytes(&make_tx(n, n));
        bencher.bench(|| {
            let (tx, _) = TransactionRef::decode_ref(bytes.as_slice())
                .expect("TransactionRef decode_ref cannot fail on valid bytes");
            black_box(tx.version)
        });
    }

    #[divan::bench(args = [1usize, 4, 16])]
    fn ref_iter(bencher: divan::Bencher, n: usize) {
        let bytes = encode_bytes(&make_tx(n, n));
        let (tx_ref, _) = TransactionRef::decode_ref(bytes.as_slice())
            .expect("TransactionRef decode_ref cannot fail on valid bytes");
        bencher.bench(|| {
            let mut sum = 0u64;
            for r in tx_ref.inputs() {
                sum += u64::from(
                    r.expect("input decode cannot fail on valid bytes")
                        .sequence
                        .to_u32(),
                );
            }
            for r in tx_ref.outputs() {
                sum += r
                    .expect("output decode cannot fail on valid bytes")
                    .value
                    .to_u64();
            }
            black_box(sum)
        });
    }

    #[divan::bench(args = [1usize, 4, 16])]
    fn ref_to_owned(bencher: divan::Bencher, n: usize) {
        let bytes = encode_bytes(&make_tx(n, n));
        let (tx_ref, _) = TransactionRef::decode_ref(bytes.as_slice())
            .expect("TransactionRef decode_ref cannot fail on valid bytes");
        bencher.bench(|| {
            tx_ref
                .to_owned()
                .expect("to_owned cannot fail on valid bytes")
        });
    }

    #[divan::bench(args = [1usize, 4, 16])]
    fn ref_encode(bencher: divan::Bencher, n: usize) {
        let bytes = encode_bytes(&make_tx(n, n));
        let (tx_ref, _) = TransactionRef::decode_ref(bytes.as_slice())
            .expect("TransactionRef decode_ref cannot fail on valid bytes");
        bencher.bench(|| encode_bytes(&tx_ref));
    }

    #[divan::bench(args = [1usize, 4, 16])]
    fn ref_txid(bencher: divan::Bencher, n: usize) {
        let bytes = encode_bytes(&make_tx(n, n));
        let (tx_ref, _) = TransactionRef::decode_ref(bytes.as_slice())
            .expect("TransactionRef decode_ref cannot fail on valid bytes");
        bencher.bench(|| tx_ref.txid().expect("txid encoding cannot fail"));
    }

    #[divan::bench(args = [1usize, 4, 16])]
    fn txid(bencher: divan::Bencher, n: usize) {
        let tx = make_tx(n, n);
        bencher.bench(|| tx.txid().expect("txid encoding cannot fail"));
    }

    #[divan::bench]
    fn arena_segwit_txid(bencher: divan::Bencher) {
        let bytes = encode_bytes(&make_segwit_tx());
        let mut arena = Vec::new();
        bencher.bench_local(|| {
            arena.clear();
            let (tx_ref, _) = transaction_ref_with_arena(&bytes, &mut arena)
                .expect("arena decode cannot fail on valid bytes");
            tx_ref.txid_into(&mut Vec::new()).expect("txid never fails")
        });
    }
}

// ── Block / BlockRef ─────────────────────────────────────────────────────────

mod block {
    use super::{
        Block, BlockRef, Cursor, Decode, Hash256, Locktime, OutPoint, Satoshi, Sequence,
        Transaction, TxIn, TxOut, TxVersion, Witness, black_box, encode_bytes, make_header,
        make_tx,
    };

    #[divan::bench(args = [1usize, 10, 100])]
    fn encode(bencher: divan::Bencher, n: usize) {
        let blk = Block {
            header: make_header(0),
            transactions: (0..n).map(|_| make_tx(2, 2)).collect(),
        };
        bencher.bench(|| encode_bytes(&blk));
    }

    #[divan::bench(args = [1usize, 10, 100])]
    fn decode(bencher: divan::Bencher, n: usize) {
        let blk = Block {
            header: make_header(0),
            transactions: (0..n).map(|_| make_tx(2, 2)).collect(),
        };
        let bytes = encode_bytes(&blk);
        bencher.bench(|| {
            Block::decode(&mut Cursor::new(bytes.as_slice()))
                .expect("Block decode cannot fail on valid bytes")
        });
    }

    #[divan::bench(args = [1usize, 10, 100])]
    fn decode_ref_with_arena(bencher: divan::Bencher, n: usize) {
        let blk = Block {
            header: make_header(0),
            transactions: (0..n).map(|_| make_tx(2, 2)).collect(),
        };
        let bytes = encode_bytes(&blk);
        bencher.bench_local(|| {
            let mut arena = Vec::new();
            let mut txs_buf = Vec::new();
            let br = BlockRef::decode_with_arena(&bytes, &mut arena, &mut txs_buf)
                .expect("BlockRef decode cannot fail on valid bytes");
            black_box(br.tx_count())
        });
    }

    #[divan::bench]
    fn decode_1000_txs(bencher: divan::Bencher) {
        let blk = Block {
            header: make_header(0),
            transactions: (0..1_000).map(|_| make_tx(1, 1)).collect(),
        };
        let bytes = encode_bytes(&blk);
        bencher.bench(|| {
            Block::decode(&mut Cursor::new(bytes.as_slice()))
                .expect("Block decode cannot fail on valid bytes")
        });
    }

    #[divan::bench]
    fn decode_ref_1000_txs(bencher: divan::Bencher) {
        let blk = Block {
            header: make_header(0),
            transactions: (0..1_000).map(|_| make_tx(1, 1)).collect(),
        };
        let bytes = encode_bytes(&blk);
        bencher.bench_local(|| {
            let mut arena = Vec::new();
            let mut txs_buf = Vec::new();
            let br = BlockRef::decode_with_arena(&bytes, &mut arena, &mut txs_buf)
                .expect("BlockRef decode cannot fail on valid bytes");
            black_box(br.tx_count())
        });
    }

    #[divan::bench]
    fn decode_p2pkh_btccore(bencher: divan::Bencher) {
        let tx = Transaction {
            version: TxVersion::new(1),
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Hash256::from_bytes([0xabu8; 32]),
                    vout: 0,
                },
                script_sig: vec![
                    0x76, 0xa9, 0x14, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
                    0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x88, 0xac,
                ]
                .into(),
                sequence: Sequence::MAX,
                witness: Witness::empty(),
            }],
            outputs: vec![TxOut {
                value: Satoshi::new(100_000),
                script_pubkey: vec![0x76, 0xa9, 0x14].into(),
            }],
            locktime: Locktime::new(0),
        };
        let bytes = encode_bytes(&tx);
        bencher.bench(|| {
            Transaction::decode(&mut Cursor::new(bytes.as_slice()))
                .expect("Transaction decode cannot fail on valid bytes")
        });
    }
}

// ── MessageHeader ────────────────────────────────────────────────────────────

mod message_header {
    use super::{
        Command, CommandName, Cursor, Decode, DecodeRef, Hash256, Magic, MessageHeader,
        encode_bytes, encode_message,
    };

    #[divan::bench]
    fn to_bytes() -> [u8; 24] {
        MessageHeader::new(
            Magic::Mainnet,
            CommandName::new("ping"),
            8,
            Hash256::checksum(&[0u8; 8]),
        )
        .to_bytes()
    }

    #[divan::bench]
    fn from_bytes(bencher: divan::Bencher) {
        let bytes = MessageHeader::new(
            Magic::Mainnet,
            CommandName::new("ping"),
            8,
            Hash256::checksum(&[0u8; 8]),
        )
        .to_bytes();
        bencher.bench(|| MessageHeader::from_bytes(&bytes));
    }

    #[divan::bench]
    fn decode(bencher: divan::Bencher) {
        let payload = b"nonce_8_bytes___";
        let bytes = encode_bytes(&MessageHeader::new(
            Magic::Mainnet,
            CommandName::new("ping"),
            u32::try_from(payload.len()).expect("payload fits u32"),
            Hash256::checksum(payload),
        ));
        bencher.bench(|| {
            MessageHeader::decode(&mut Cursor::new(bytes.as_slice()))
                .expect("MessageHeader decode cannot fail on valid bytes")
        });
    }

    #[divan::bench]
    fn decode_ref(bencher: divan::Bencher) {
        let payload = b"nonce_8_bytes___";
        let bytes = encode_bytes(&MessageHeader::new(
            Magic::Mainnet,
            CommandName::new("ping"),
            u32::try_from(payload.len()).expect("payload fits u32"),
            Hash256::checksum(payload),
        ));
        bencher.bench(|| {
            MessageHeader::decode_ref(bytes.as_slice())
                .expect("MessageHeader decode_ref cannot fail on valid bytes")
        });
    }

    #[divan::bench]
    fn encode_message_ping() -> Vec<u8> {
        let nonce = 0xdead_beef_cafe_babe_u64.to_le_bytes();
        let mut buf = Vec::with_capacity(32);
        encode_message(Magic::Mainnet, Command::Ping, &nonce, &mut buf)
            .expect("encode_message cannot fail on Vec<u8>");
        buf
    }
}

// ── VersionMsg / VersionMsgRef ───────────────────────────────────────────────

fn make_addr() -> NetworkAddr {
    NetworkAddr {
        services: Services::NODE_NETWORK,
        ip: [0u8; 16],
        port: Port::MAINNET,
    }
}

fn make_version_msg() -> VersionMsg {
    let addr = make_addr();
    VersionMsg {
        version: ProtocolVersion::CURRENT,
        services: Services::NODE_NETWORK,
        timestamp: Timestamp::new(1_700_000_000),
        receiver: addr,
        sender: addr,
        nonce: PeerNonce::new(0xdead_beef),
        user_agent: "/mantle:0.1.0/".to_string(),
        start_height: BlockHeight::new(800_000),
        relay: true,
    }
}

mod version_msg {
    use super::{
        Cursor, Decode, DecodeRef, VersionMsg, VersionMsgRef, encode_bytes, make_version_msg,
    };

    #[divan::bench]
    fn encode(bencher: divan::Bencher) {
        let msg = make_version_msg();
        bencher.bench(|| encode_bytes(&msg));
    }

    #[divan::bench]
    fn decode(bencher: divan::Bencher) {
        let bytes = encode_bytes(&make_version_msg());
        bencher.bench(|| {
            VersionMsg::decode(&mut Cursor::new(bytes.as_slice()))
                .expect("VersionMsg decode cannot fail on valid bytes")
        });
    }

    #[divan::bench]
    fn decode_ref(bencher: divan::Bencher) {
        let bytes = encode_bytes(&make_version_msg());
        bencher.bench(|| {
            VersionMsgRef::decode_ref(bytes.as_slice())
                .expect("VersionMsgRef decode_ref cannot fail on valid bytes")
        });
    }
}

// ── PingMsg ──────────────────────────────────────────────────────────────────

mod ping_msg {
    use super::{Cursor, Decode, PeerNonce, PingMsg, encode_bytes};

    #[divan::bench]
    fn encode() -> Vec<u8> {
        encode_bytes(&PingMsg {
            nonce: PeerNonce::new(0xdead_beef),
        })
    }

    #[divan::bench]
    fn decode(bencher: divan::Bencher) {
        let bytes = encode_bytes(&PingMsg {
            nonce: PeerNonce::new(0xdead_beef),
        });
        bencher.bench(|| {
            PingMsg::decode(&mut Cursor::new(bytes.as_slice()))
                .expect("PingMsg decode cannot fail on valid bytes")
        });
    }
}

// ── InvMsg ───────────────────────────────────────────────────────────────────

mod inv_msg {
    use super::{
        Cursor, Decode, DecodeRef, Hash256, InvEntry, InvMsg, InvType, black_box, encode_bytes,
    };

    fn make(n: usize) -> InvMsg {
        InvMsg(
            (0..n)
                .map(|i| {
                    InvEntry::new(
                        InvType::Block,
                        Hash256::from_bytes([u8::try_from(i & 0xff).unwrap(); 32]),
                    )
                })
                .collect(),
        )
    }

    #[divan::bench(args = [1usize, 16, 256, 2000])]
    fn encode(bencher: divan::Bencher, n: usize) {
        let msg = make(n);
        bencher.bench(|| encode_bytes(&msg));
    }

    #[divan::bench(args = [1usize, 16, 256, 2000])]
    fn decode(bencher: divan::Bencher, n: usize) {
        let bytes = encode_bytes(&make(n));
        bencher.bench(|| {
            InvMsg::decode(&mut Cursor::new(bytes.as_slice()))
                .expect("InvMsg decode cannot fail on valid bytes")
        });
    }

    #[divan::bench(args = [1usize, 16, 256, 2000])]
    fn iter(bencher: divan::Bencher, n: usize) {
        let bytes = encode_bytes(&make(n));
        bencher.bench(|| {
            let mut count = 0usize;
            for entry in InvMsg::iter_entries::<50_000>(&bytes)
                .expect("iter_entries cannot fail on valid bytes")
            {
                black_box(entry.expect("inv entry decode cannot fail on valid bytes"));
                count += 1;
            }
            count
        });
    }

    #[divan::bench(args = [1usize, 16, 256, 2000])]
    fn decode_into(bencher: divan::Bencher, n: usize) {
        let bytes = encode_bytes(&make(n));
        let mut buf = Vec::new();
        bencher.bench_local(|| {
            InvMsg::decode_into_limited::<50_000>(&mut Cursor::new(bytes.as_slice()), &mut buf)
                .expect("decode_into_limited cannot fail on valid bytes");
            black_box(buf.len())
        });
    }

    #[divan::bench]
    fn entry_to_bytes() -> [u8; 36] {
        InvEntry::new(InvType::Block, Hash256::ZERO).to_bytes()
    }

    #[divan::bench]
    fn entry_decode_ref(bencher: divan::Bencher) {
        let bytes = InvEntry::new(InvType::Block, Hash256::ZERO).to_bytes();
        bencher.bench(|| {
            InvEntry::decode_ref(&bytes).expect("InvEntry decode_ref cannot fail on valid bytes")
        });
    }
}

// ── AddrMsg ──────────────────────────────────────────────────────────────────

mod addr_msg {
    use super::{AddrEntry, AddrMsg, Cursor, Decode, DecodeRef, Encode, VarInt, black_box};

    fn make_payload(n: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        VarInt::from(n)
            .encode(&mut buf)
            .expect("Vec write cannot fail");
        for i in 0..n {
            buf.extend_from_slice(&u32::try_from(i).unwrap().to_le_bytes()); // time
            buf.extend_from_slice(&1u64.to_le_bytes()); // services
            buf.extend_from_slice(&[0u8; 16]); // ip
            buf.extend_from_slice(&8333u16.to_be_bytes()); // port
        }
        buf
    }

    #[divan::bench(args = [1usize, 100, 1000])]
    fn decode(bencher: divan::Bencher, n: usize) {
        let bytes = make_payload(n);
        bencher.bench(|| {
            AddrMsg::decode(&mut Cursor::new(bytes.as_slice()))
                .expect("AddrMsg decode cannot fail on valid bytes")
        });
    }

    #[divan::bench(args = [1usize, 100, 1000])]
    fn iter(bencher: divan::Bencher, n: usize) {
        let bytes = make_payload(n);
        bencher.bench(|| {
            let mut count = 0usize;
            for entry in AddrMsg::iter_entries::<1000>(&bytes)
                .expect("iter_entries cannot fail on valid bytes")
            {
                black_box(entry.expect("addr entry decode cannot fail on valid bytes"));
                count += 1;
            }
            count
        });
    }

    #[divan::bench(args = [1usize, 100, 1000])]
    fn decode_into(bencher: divan::Bencher, n: usize) {
        let bytes = make_payload(n);
        let mut buf = Vec::new();
        bencher.bench_local(|| {
            AddrMsg::decode_into_limited::<1000>(&mut Cursor::new(bytes.as_slice()), &mut buf)
                .expect("decode_into_limited cannot fail on valid bytes");
            black_box(buf.len())
        });
    }

    #[divan::bench]
    fn entry_to_bytes() -> [u8; 30] {
        let payload = make_payload(1);
        let entry = AddrMsg::decode(&mut Cursor::new(payload.as_slice()))
            .expect("decode cannot fail")
            .0
            .into_iter()
            .next()
            .expect("one entry");
        entry.to_bytes()
    }

    #[divan::bench]
    fn entry_decode_ref(bencher: divan::Bencher) {
        let payload = make_payload(1);
        let entry = AddrMsg::decode(&mut Cursor::new(payload.as_slice()))
            .expect("decode cannot fail")
            .0
            .into_iter()
            .next()
            .expect("one entry");
        let bytes = entry.to_bytes();
        bencher.bench(|| {
            AddrEntry::decode_ref(&bytes).expect("AddrEntry decode_ref cannot fail on valid bytes")
        });
    }
}

// ── HeadersMsg ───────────────────────────────────────────────────────────────

mod headers_msg {
    use super::{Cursor, Decode, HeadersMsg, black_box, encode_bytes, make_header};

    #[divan::bench(args = [1usize, 100, 2000])]
    fn encode(bencher: divan::Bencher, n: usize) {
        let msg = HeadersMsg((0..n).map(make_header).collect());
        bencher.bench(|| encode_bytes(&msg));
    }

    #[divan::bench(args = [1usize, 100, 2000])]
    fn decode(bencher: divan::Bencher, n: usize) {
        let bytes = encode_bytes(&HeadersMsg((0..n).map(make_header).collect()));
        bencher.bench(|| {
            HeadersMsg::decode(&mut Cursor::new(bytes.as_slice()))
                .expect("HeadersMsg decode cannot fail on valid bytes")
        });
    }

    #[divan::bench(args = [1usize, 100, 2000])]
    fn iter(bencher: divan::Bencher, n: usize) {
        let bytes = encode_bytes(&HeadersMsg((0..n).map(make_header).collect()));
        bencher.bench(|| {
            let mut count = 0usize;
            for header in HeadersMsg::iter_entries::<2_000>(&bytes)
                .expect("iter_entries cannot fail on valid bytes")
            {
                black_box(header.expect("header decode cannot fail on valid bytes"));
                count += 1;
            }
            count
        });
    }

    #[divan::bench(args = [1usize, 100, 2000])]
    fn decode_into(bencher: divan::Bencher, n: usize) {
        let bytes = encode_bytes(&HeadersMsg((0..n).map(make_header).collect()));
        let mut buf = Vec::new();
        bencher.bench_local(|| {
            HeadersMsg::decode_into_limited::<2_000>(&mut Cursor::new(bytes.as_slice()), &mut buf)
                .expect("decode_into_limited cannot fail on valid bytes");
            black_box(buf.len())
        });
    }
}

// ── GetHeadersMsg ────────────────────────────────────────────────────────────

mod getheaders_msg {
    use super::{Cursor, Decode, GetHeadersMsg, Hash256, ProtocolVersion, encode_bytes};

    fn sample() -> GetHeadersMsg {
        GetHeadersMsg {
            version: ProtocolVersion::CURRENT,
            locator_hashes: (0..10u8).map(|i| Hash256::from_bytes([i; 32])).collect(),
            stop_hash: Hash256::ZERO,
        }
    }

    #[divan::bench]
    fn encode(bencher: divan::Bencher) {
        let msg = sample();
        bencher.bench(|| encode_bytes(&msg));
    }

    #[divan::bench]
    fn decode(bencher: divan::Bencher) {
        let bytes = encode_bytes(&sample());
        bencher.bench(|| {
            GetHeadersMsg::decode(&mut Cursor::new(bytes.as_slice()))
                .expect("GetHeadersMsg decode cannot fail on valid bytes")
        });
    }
}
