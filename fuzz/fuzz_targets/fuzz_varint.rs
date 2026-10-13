#![no_main]
use libfuzzer_sys::fuzz_target;
use mantle::codec::{Decode, DecodeRef, Encode, VarInt};
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = VarInt::decode(&mut Cursor::new(data)) {
        let mut buf = Vec::new();
        v.encode(&mut buf).unwrap();
        let v2 = VarInt::decode(&mut Cursor::new(buf.as_slice())).unwrap();
        assert_eq!(v, v2);
    }

    if let Ok((v, _tail)) = VarInt::decode_ref(data) {
        let mut buf = Vec::new();
        v.encode(&mut buf).unwrap();
        let (v2, _) = VarInt::decode_ref(&buf).unwrap();
        assert_eq!(v, v2);
    }
});
