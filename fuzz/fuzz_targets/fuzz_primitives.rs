#![no_main]
use libfuzzer_sys::fuzz_target;
use mantle::codec::{Decode, Encode};
use mantle::primitives::{Block, BlockHeader, Hash256, OutPoint, Transaction, TxIn, TxOut};
use std::io::Cursor;

macro_rules! fuzz_roundtrip {
    ($T:ty, $data:expr) => {
        if let Ok(v) = <$T>::decode(&mut Cursor::new($data)) {
            let mut buf = Vec::new();
            v.encode(&mut buf).unwrap();
            let v2 = <$T>::decode(&mut Cursor::new(buf.as_slice())).unwrap();
            assert_eq!(v, v2, "round-trip mismatch for {}", stringify!($T));
        }
    };
}

fuzz_target!(|data: &[u8]| {
    fuzz_roundtrip!(Hash256, data);
    fuzz_roundtrip!(BlockHeader, data);
    fuzz_roundtrip!(OutPoint, data);
    fuzz_roundtrip!(TxIn, data);
    fuzz_roundtrip!(TxOut, data);
    fuzz_roundtrip!(Transaction, data);
    fuzz_roundtrip!(Block, data);
});
