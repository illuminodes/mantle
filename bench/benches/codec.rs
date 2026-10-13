use mantle::codec::{
    Decode, DecodeRef, Encode, VarInt, decode_bytes_limited, decode_string_limited,
};
use std::io::Cursor;

fn main() {
    divan::main();
}

// ── VarInt ────────────────────────────────────────────────────────────────────

#[divan::bench(args = [0xfcu64, 0xfdu64, 0x1_0000u64, u64::MAX])]
fn varint_encode(n: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(9);
    VarInt::from(n)
        .encode(&mut buf)
        .expect("Vec<u8> write cannot fail");
    buf
}

#[divan::bench(args = [0xfcu64, 0xfdu64, 0x1_0000u64, u64::MAX])]
fn varint_decode(bencher: divan::Bencher, n: u64) {
    let mut buf = Vec::new();
    VarInt::from(n)
        .encode(&mut buf)
        .expect("Vec<u8> write cannot fail");
    bencher.bench(|| {
        VarInt::decode(&mut Cursor::new(buf.as_slice()))
            .expect("varint decode cannot fail on valid bytes")
    });
}

#[divan::bench(args = [0xfcu64, 0xfdu64, 0x1_0000u64, u64::MAX])]
fn varint_decode_ref(bencher: divan::Bencher, n: u64) {
    let mut buf = Vec::new();
    VarInt::from(n)
        .encode(&mut buf)
        .expect("Vec<u8> write cannot fail");
    bencher.bench(|| {
        VarInt::decode_ref(buf.as_slice()).expect("varint decode_ref cannot fail on valid bytes")
    });
}

// ── Primitives ────────────────────────────────────────────────────────────────

#[divan::bench]
fn u32_decode_ref() -> (u32, &'static [u8]) {
    u32::decode_ref(&[0x01, 0x00, 0x00, 0x00]).expect("u32 decode_ref cannot fail on 4 bytes")
}

#[divan::bench]
fn u64_decode_ref() -> (u64, &'static [u8]) {
    u64::decode_ref(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe])
        .expect("u64 decode_ref cannot fail on 8 bytes")
}

// ── Integer primitives ────────────────────────────────────────────────────────

#[divan::bench]
fn u8_encode() -> Vec<u8> {
    let mut buf = Vec::with_capacity(1);
    0xabu8.encode(&mut buf).expect("Vec<u8> write cannot fail");
    buf
}

#[divan::bench]
fn u16_encode() -> Vec<u8> {
    let mut buf = Vec::with_capacity(2);
    0xabcdu16
        .encode(&mut buf)
        .expect("Vec<u8> write cannot fail");
    buf
}

#[divan::bench]
fn u32_encode() -> Vec<u8> {
    let mut buf = Vec::with_capacity(4);
    0xdead_beef_u32
        .encode(&mut buf)
        .expect("Vec<u8> write cannot fail");
    buf
}

#[divan::bench]
fn u64_encode() -> Vec<u8> {
    let mut buf = Vec::with_capacity(8);
    0xdead_beef_cafe_babe_u64
        .encode(&mut buf)
        .expect("Vec<u8> write cannot fail");
    buf
}

#[divan::bench]
fn i32_encode() -> Vec<u8> {
    let mut buf = Vec::with_capacity(4);
    (-1i32).encode(&mut buf).expect("Vec<u8> write cannot fail");
    buf
}

#[divan::bench]
fn i64_encode() -> Vec<u8> {
    let mut buf = Vec::with_capacity(8);
    i64::MIN
        .encode(&mut buf)
        .expect("Vec<u8> write cannot fail");
    buf
}

#[divan::bench]
fn u8_decode_ref() -> (u8, &'static [u8]) {
    u8::decode_ref(&[0xab]).expect("u8 decode_ref cannot fail on 1 byte")
}

#[divan::bench]
fn u16_decode_ref() -> (u16, &'static [u8]) {
    u16::decode_ref(&[0xcd, 0xab]).expect("u16 decode_ref cannot fail on 2 bytes")
}

#[divan::bench]
fn i32_decode_ref() -> (i32, &'static [u8]) {
    i32::decode_ref(&[0xff, 0xff, 0xff, 0xff]).expect("i32 decode_ref cannot fail on 4 bytes")
}

#[divan::bench]
fn i64_decode_ref() -> (i64, &'static [u8]) {
    i64::decode_ref(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80])
        .expect("i64 decode_ref cannot fail on 8 bytes")
}

// ── decode_bytes_limited / decode_string_limited ──────────────────────────────

#[divan::bench(args = [0usize, 16, 256])]
fn decode_bytes_limited_bench(bencher: divan::Bencher, len: usize) {
    let payload = vec![0xabu8; len];
    let mut buf = Vec::new();
    VarInt::from(len)
        .encode(&mut buf)
        .expect("Vec<u8> write cannot fail");
    buf.extend_from_slice(&payload);
    bencher.bench(|| {
        decode_bytes_limited::<{ 1 << 20 }>(&mut Cursor::new(buf.as_slice()))
            .expect("decode_bytes_limited cannot fail on valid bytes")
    });
}

#[divan::bench(args = [0usize, 16, 256])]
fn decode_string_limited_bench(bencher: divan::Bencher, len: usize) {
    let s = "a".repeat(len);
    let mut buf = Vec::new();
    s.as_str()
        .encode(&mut buf)
        .expect("Vec<u8> write cannot fail");
    bencher.bench(|| {
        decode_string_limited::<{ 1 << 20 }>(&mut Cursor::new(buf.as_slice()))
            .expect("decode_string_limited cannot fail on valid bytes")
    });
}

// ── VarStr ────────────────────────────────────────────────────────────────────

mod varstr {
    use super::{Cursor, Decode, DecodeRef, Encode};

    fn encode_str(s: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        s.encode(&mut buf).expect("Vec<u8> write cannot fail");
        buf
    }

    #[divan::bench]
    fn encode_short() -> Vec<u8> {
        encode_str("ping")
    }

    #[divan::bench]
    fn encode_long_256(bencher: divan::Bencher) {
        let s = "a".repeat(256);
        bencher.bench(|| encode_str(&s));
    }

    #[divan::bench]
    fn decode_short(bencher: divan::Bencher) {
        let buf = encode_str("ping");
        bencher.bench(|| {
            String::decode(&mut Cursor::new(buf.as_slice()))
                .expect("String decode cannot fail on valid bytes")
        });
    }

    #[divan::bench]
    fn decode_long_256(bencher: divan::Bencher) {
        let buf = encode_str(&"a".repeat(256));
        bencher.bench(|| {
            String::decode(&mut Cursor::new(buf.as_slice()))
                .expect("String decode cannot fail on valid bytes")
        });
    }

    #[divan::bench]
    fn decode_ref_short(bencher: divan::Bencher) {
        let buf = encode_str("ping");
        bencher.bench(|| {
            <&str>::decode_ref(buf.as_slice()).expect("str decode_ref cannot fail on valid bytes")
        });
    }

    #[divan::bench]
    fn decode_ref_long_256(bencher: divan::Bencher) {
        let buf = encode_str(&"a".repeat(256));
        bencher.bench(|| {
            <&str>::decode_ref(buf.as_slice()).expect("str decode_ref cannot fail on valid bytes")
        });
    }
}
