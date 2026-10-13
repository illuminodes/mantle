#![no_main]
use libfuzzer_sys::fuzz_target;
use mantle::codec::{Decode, Encode};
use mantle::network::{
    GetHeadersMsg, HeadersMsg, InvMsg, MessageHeader, NetworkAddr, PingMsg, VersionMsg,
};
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
    // MessageHeader doesn't derive PartialEq; check field-by-field.
    if let Ok(h) = MessageHeader::decode(&mut Cursor::new(data)) {
        let mut buf = Vec::new();
        h.encode(&mut buf).unwrap();
        let h2 = MessageHeader::decode(&mut Cursor::new(buf.as_slice())).unwrap();
        assert_eq!(h.magic(), h2.magic());
        assert_eq!(h.command(), h2.command());
        assert_eq!(h.length(), h2.length());
        assert_eq!(h.checksum(), h2.checksum());
    }
    fuzz_roundtrip!(NetworkAddr, data);
    fuzz_roundtrip!(PingMsg, data);
    fuzz_roundtrip!(VersionMsg, data);
    fuzz_roundtrip!(InvMsg, data);
    fuzz_roundtrip!(GetHeadersMsg, data);
    fuzz_roundtrip!(HeadersMsg, data);

    // iter_entries: must agree with the owned decode on every input that parses.
    if let Ok(owned) = InvMsg::decode(&mut Cursor::new(data)) {
        let iter_entries: Vec<_> = InvMsg::iter_entries::<50_000>(data)
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(iter_entries, owned.0, "InvMsg iter_entries mismatch");

        // decode_into must also agree.
        let mut reuse_buf = Vec::new();
        InvMsg::decode_into_limited::<50_000>(&mut Cursor::new(data), &mut reuse_buf).unwrap();
        assert_eq!(reuse_buf, owned.0, "InvMsg decode_into mismatch");
    }

    if let Ok(owned) = HeadersMsg::decode(&mut Cursor::new(data)) {
        let iter_entries: Vec<_> = HeadersMsg::iter_entries::<2_000>(data)
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(iter_entries, owned.0, "HeadersMsg iter_entries mismatch");

        // decode_into must also agree.
        let mut reuse_buf = Vec::new();
        HeadersMsg::decode_into_limited::<2_000>(&mut Cursor::new(data), &mut reuse_buf).unwrap();
        assert_eq!(reuse_buf, owned.0, "HeadersMsg decode_into mismatch");
    }
});
