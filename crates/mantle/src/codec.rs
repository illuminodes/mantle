use std::io::{self, Read, Write};
use std::str::Utf8Error;

// ── Error ─────────────────────────────────────────────────────────────────────

/// All failure modes that can occur during Bitcoin wire-format encoding or decoding.
#[derive(Debug)]
pub enum Error {
    /// The input ended before all required bytes were read.
    UnexpectedEof,
    /// A `VarInt` length field claimed a size that exceeds `usize::MAX` on this
    /// platform and therefore cannot be used to allocate a buffer.
    LengthOverflow(u64),
    /// A byte sequence that was required to be valid UTF-8 was not.
    InvalidUtf8(Utf8Error),
    /// An underlying I/O operation failed for a reason unrelated to the data
    /// format (e.g. a real write error on a `Vec<u8>` is impossible, but a
    /// network stream could return one).
    Io(io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEof => f.write_str("unexpected end of input"),
            Self::LengthOverflow(n) => {
                write!(f, "VarInt length {n} overflows usize on this platform")
            }
            Self::InvalidUtf8(e) => write!(f, "invalid UTF-8: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidUtf8(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::UnexpectedEof | Self::LengthOverflow(_) => None,
        }
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::UnexpectedEof => io::Error::new(io::ErrorKind::UnexpectedEof, e.to_string()),
            Error::LengthOverflow(_) | Error::InvalidUtf8(_) => {
                io::Error::new(io::ErrorKind::InvalidData, e.to_string())
            }
            Error::Io(inner) => inner,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::UnexpectedEof => Self::UnexpectedEof,
            _ => Self::Io(e),
        }
    }
}

impl From<Utf8Error> for Error {
    fn from(e: Utf8Error) -> Self {
        Self::InvalidUtf8(e)
    }
}

// ── Traits ────────────────────────────────────────────────────────────────────

pub trait Encode {
    /// # Errors
    /// Returns an error if writing to `w` fails.
    fn encode(&self, w: &mut impl Write) -> Result<(), Error>;
}

pub trait Decode: Sized {
    /// # Errors
    /// Returns an error if reading from `r` fails or the data is malformed.
    fn decode(r: &mut impl Read) -> Result<Self, Error>;
}

/// Zero-copy decoding from a borrowed byte slice.
/// Returns the decoded value and the remaining unconsumed bytes.
pub trait DecodeRef<'a>: Sized {
    /// # Errors
    /// Returns an error if `buf` is too short or the data is malformed.
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), Error>;
}

// ── Primitives ────────────────────────────────────────────────────────────────

macro_rules! impl_codec_int {
    ($t:ty) => {
        impl Encode for $t {
            #[inline]
            fn encode(&self, w: &mut impl Write) -> Result<(), Error> {
                w.write_all(&self.to_le_bytes()).map_err(Error::Io)
            }
        }

        impl Decode for $t {
            #[inline]
            fn decode(r: &mut impl Read) -> Result<Self, Error> {
                let mut buf = [0u8; size_of::<$t>()];
                r.read_exact(&mut buf)?;
                Ok(<$t>::from_le_bytes(buf))
            }
        }

        impl<'a> DecodeRef<'a> for $t {
            #[inline]
            fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
                const N: usize = size_of::<$t>();
                if buf.len() < N {
                    return Err(Error::UnexpectedEof);
                }
                let (head, tail) = buf.split_at(N);
                let arr: [u8; N] = head.try_into().map_err(|_| Error::UnexpectedEof)?;
                Ok((<$t>::from_le_bytes(arr), tail))
            }
        }
    };
}

impl_codec_int!(u8);
impl_codec_int!(u16);
impl_codec_int!(u32);
impl_codec_int!(u64);
impl_codec_int!(i32);
impl_codec_int!(i64);

// ── VarInt ────────────────────────────────────────────────────────────────────

/// Bitcoin variable-length integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct VarInt(u64);

impl VarInt {
    #[inline]
    #[must_use]
    pub const fn new(n: u64) -> Self {
        Self(n)
    }

    #[inline]
    #[must_use]
    pub const fn to_u64(self) -> u64 {
        self.0
    }

    /// # Errors
    /// Returns [`Error::LengthOverflow`] if the value exceeds `usize::MAX`.
    #[inline]
    pub fn to_usize(self) -> Result<usize, Error> {
        usize::try_from(self.0).map_err(|_| Error::LengthOverflow(self.0))
    }

    #[inline]
    #[must_use]
    pub fn encoded_len(self) -> usize {
        match self.0 {
            0..=0xfc => 1,
            0xfd..=0xffff => 3,
            0x10000..=0xffff_ffff => 5,
            _ => 9,
        }
    }
}

impl From<u64> for VarInt {
    #[inline]
    fn from(n: u64) -> Self {
        Self(n)
    }
}

impl From<usize> for VarInt {
    #[inline]
    fn from(n: usize) -> Self {
        Self(n as u64)
    }
}

impl From<VarInt> for u64 {
    #[inline]
    fn from(v: VarInt) -> Self {
        v.0
    }
}

impl Encode for VarInt {
    #[inline]
    #[allow(clippy::cast_possible_truncation)] // match arms prove range
    fn encode(&self, w: &mut impl Write) -> Result<(), Error> {
        // Build into a stack buffer and emit in one write_all to avoid
        // paying two virtual-dispatch calls for multi-byte forms.
        let mut buf = [0u8; 9];
        let slice = match self.0 {
            n @ 0..=0xfc => {
                buf[0] = n as u8;
                &buf[..1]
            }
            n @ 0xfd..=0xffff => {
                buf[0] = 0xfd;
                buf[1..3].copy_from_slice(&(n as u16).to_le_bytes());
                &buf[..3]
            }
            n @ 0x10000..=0xffff_ffff => {
                buf[0] = 0xfe;
                buf[1..5].copy_from_slice(&(n as u32).to_le_bytes());
                &buf[..5]
            }
            n => {
                buf[0] = 0xff;
                buf[1..9].copy_from_slice(&n.to_le_bytes());
                &buf[..9]
            }
        };
        w.write_all(slice).map_err(Error::Io)
    }
}

impl VarInt {
    /// Decode a `VarInt` when the first byte has already been consumed.
    ///
    /// # Errors
    /// Propagates any I/O error from reading remaining bytes.
    #[inline]
    pub fn decode_from_first_byte(first: u8, r: &mut impl Read) -> Result<Self, Error> {
        let mut buf = [0u8; 8];
        let value = match first {
            0xff => {
                r.read_exact(&mut buf)?;
                u64::from_le_bytes(buf)
            }
            0xfe => {
                r.read_exact(&mut buf[..4])?;
                u64::from(u32::from_le_bytes(
                    buf[..4].try_into().map_err(|_| Error::UnexpectedEof)?,
                ))
            }
            0xfd => {
                r.read_exact(&mut buf[..2])?;
                u64::from(u16::from_le_bytes(
                    buf[..2].try_into().map_err(|_| Error::UnexpectedEof)?,
                ))
            }
            n => u64::from(n),
        };
        Ok(VarInt(value))
    }
}

impl Decode for VarInt {
    #[inline]
    fn decode(r: &mut impl Read) -> Result<Self, Error> {
        // Read up to 9 bytes in one shot: tag byte + up to 8 body bytes.
        // We only consume as many bytes as the tag demands.
        let mut buf = [0u8; 9];
        r.read_exact(&mut buf[..1])?;
        let value = match buf[0] {
            0xff => {
                r.read_exact(&mut buf[1..9])?;
                u64::from_le_bytes(buf[1..9].try_into().map_err(|_| Error::UnexpectedEof)?)
            }
            0xfe => {
                r.read_exact(&mut buf[1..5])?;
                u64::from(u32::from_le_bytes(
                    buf[1..5].try_into().map_err(|_| Error::UnexpectedEof)?,
                ))
            }
            0xfd => {
                r.read_exact(&mut buf[1..3])?;
                u64::from(u16::from_le_bytes(
                    buf[1..3].try_into().map_err(|_| Error::UnexpectedEof)?,
                ))
            }
            n => u64::from(n),
        };
        Ok(VarInt(value))
    }
}

impl<'a> DecodeRef<'a> for VarInt {
    #[inline]
    #[allow(clippy::cast_possible_truncation)] // match arms prove range
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        let (&tag, rest) = buf.split_first().ok_or(Error::UnexpectedEof)?;
        let (value, tail) = match tag {
            0xff if rest.len() >= 8 => (
                u64::from_le_bytes(rest[..8].try_into().map_err(|_| Error::UnexpectedEof)?),
                &rest[8..],
            ),
            0xfe if rest.len() >= 4 => (
                u64::from(u32::from_le_bytes(
                    rest[..4].try_into().map_err(|_| Error::UnexpectedEof)?,
                )),
                &rest[4..],
            ),
            0xfd if rest.len() >= 2 => (
                u64::from(u16::from_le_bytes(
                    rest[..2].try_into().map_err(|_| Error::UnexpectedEof)?,
                )),
                &rest[2..],
            ),
            0xfd..=0xff => return Err(Error::UnexpectedEof),
            n => (u64::from(n), rest),
        };
        Ok((VarInt(value), tail))
    }
}

// ── Fixed-size byte arrays ────────────────────────────────────────────────────

impl<const N: usize> Encode for [u8; N] {
    #[inline]
    fn encode(&self, w: &mut impl Write) -> Result<(), Error> {
        w.write_all(self).map_err(Error::Io)
    }
}

impl<const N: usize> Decode for [u8; N] {
    #[inline]
    fn decode(r: &mut impl Read) -> Result<Self, Error> {
        let mut buf = [0u8; N];
        r.read_exact(&mut buf)?;
        Ok(buf)
    }
}

impl<'a, const N: usize> DecodeRef<'a> for [u8; N] {
    #[inline]
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        if buf.len() < N {
            return Err(Error::UnexpectedEof);
        }
        let (head, tail) = buf.split_at(N);
        Ok((head.try_into().map_err(|_| Error::UnexpectedEof)?, tail))
    }
}

// ── Borrowed byte slice (zero-copy) ──────────────────────────────────────────

/// Zero-copy view into a `VarInt`-prefixed byte field.
impl<'a> DecodeRef<'a> for &'a [u8] {
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        let (VarInt(len), rest) = VarInt::decode_ref(buf)?;
        let len = usize::try_from(len).map_err(|_| Error::LengthOverflow(len))?;
        if rest.len() < len {
            return Err(Error::UnexpectedEof);
        }
        let (data, tail) = rest.split_at(len);
        Ok((data, tail))
    }
}

/// Zero-copy view into a `VarInt`-prefixed UTF-8 string field.
impl<'a> DecodeRef<'a> for &'a str {
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        let (bytes, tail) = <&'a [u8]>::decode_ref(buf)?;
        let s = std::str::from_utf8(bytes).map_err(Error::InvalidUtf8)?;
        Ok((s, tail))
    }
}

// ── Owned VarStr / VarBytes (stream path) ────────────────────────────────────

impl Encode for str {
    fn encode(&self, w: &mut impl Write) -> Result<(), Error> {
        VarInt(self.len() as u64).encode(w)?;
        w.write_all(self.as_bytes()).map_err(Error::Io)
    }
}

impl Encode for String {
    fn encode(&self, w: &mut impl Write) -> Result<(), Error> {
        self.as_str().encode(w)
    }
}

impl Decode for String {
    fn decode(r: &mut impl Read) -> Result<Self, Error> {
        VarInt::decode_string_limited::<{ 4 * 1024 * 1024 }>(r)
    }
}

impl Encode for Vec<u8> {
    fn encode(&self, w: &mut impl Write) -> Result<(), Error> {
        VarInt(self.len() as u64).encode(w)?;
        w.write_all(self).map_err(Error::Io)
    }
}

impl Decode for Vec<u8> {
    fn decode(r: &mut impl Read) -> Result<Self, Error> {
        VarInt::decode_bytes_limited::<{ 4 * 1024 * 1024 }>(r)
    }
}

// ── Length-limited byte/string helpers ───────────────────────────────────────

impl VarInt {
    /// Decode a `VarInt`-prefixed byte blob, rejecting lengths above `MAX_BYTES`.
    ///
    /// # Errors
    /// Returns `LengthOverflow` if the length field exceeds `MAX_BYTES`, or on any I/O error.
    pub fn decode_bytes_limited<const MAX_BYTES: usize>(
        r: &mut impl Read,
    ) -> Result<Vec<u8>, Error> {
        let VarInt(len) = VarInt::decode(r)?;
        let len = usize::try_from(len).map_err(|_| Error::LengthOverflow(len))?;
        if len > MAX_BYTES {
            return Err(Error::LengthOverflow(len as u64));
        }
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Decode a `VarInt`-prefixed UTF-8 string, rejecting lengths above `MAX_BYTES`.
    ///
    /// # Errors
    /// Returns `LengthOverflow` if the length field exceeds `MAX_BYTES`, or on any I/O error.
    pub fn decode_string_limited<const MAX_BYTES: usize>(
        r: &mut impl Read,
    ) -> Result<String, Error> {
        let buf = Self::decode_bytes_limited::<MAX_BYTES>(r)?;
        String::from_utf8(buf).map_err(|e| Error::InvalidUtf8(e.utf8_error()))
    }
}

/// See [`VarInt::decode_bytes_limited`].
#[allow(clippy::missing_errors_doc)]
#[inline]
pub fn decode_bytes_limited<const MAX_BYTES: usize>(r: &mut impl Read) -> Result<Vec<u8>, Error> {
    VarInt::decode_bytes_limited::<MAX_BYTES>(r)
}

/// See [`VarInt::decode_string_limited`].
#[allow(clippy::missing_errors_doc)]
#[inline]
pub fn decode_string_limited<const MAX_BYTES: usize>(r: &mut impl Read) -> Result<String, Error> {
    VarInt::decode_string_limited::<MAX_BYTES>(r)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn roundtrip_encode<T: Encode>(val: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        val.encode(&mut buf).expect("Vec<u8> write cannot fail");
        buf
    }

    fn roundtrip_decode<T: Decode>(bytes: &[u8]) -> T {
        T::decode(&mut Cursor::new(bytes)).expect("test data must decode")
    }

    fn decode_ref<'a, T: DecodeRef<'a>>(buf: &'a [u8]) -> (T, &'a [u8]) {
        T::decode_ref(buf).expect("test data must decode")
    }

    fn decode_err<T: Decode + std::fmt::Debug>(bytes: &[u8]) -> Error {
        T::decode(&mut Cursor::new(bytes)).unwrap_err()
    }

    fn decode_ref_err<'a, T: DecodeRef<'a> + std::fmt::Debug>(buf: &'a [u8]) -> Error {
        T::decode_ref(buf).unwrap_err()
    }

    #[test]
    fn u32_le() {
        let bytes = roundtrip_encode(&0x0102_0304_u32);
        assert_eq!(bytes, [0x04, 0x03, 0x02, 0x01]);
        assert_eq!(roundtrip_decode::<u32>(&bytes), 0x0102_0304_u32);
    }

    #[test]
    fn u32_decode_ref() {
        let buf = [0x04u8, 0x03, 0x02, 0x01, 0xff];
        let (val, tail) = decode_ref::<u32>(&buf);
        assert_eq!(val, 0x0102_0304_u32);
        assert_eq!(tail, &[0xff]);
    }

    #[test]
    fn varint_1byte() {
        let bytes = roundtrip_encode(&VarInt(0xfc));
        assert_eq!(bytes, [0xfc]);
        assert_eq!(roundtrip_decode::<VarInt>(&bytes), VarInt(0xfc));
    }

    #[test]
    fn varint_3byte() {
        let bytes = roundtrip_encode(&VarInt(0xfd));
        assert_eq!(bytes, [0xfd, 0xfd, 0x00]);
        assert_eq!(roundtrip_decode::<VarInt>(&bytes), VarInt(0xfd));
    }

    #[test]
    fn varint_5byte() {
        let bytes = roundtrip_encode(&VarInt(0x10000));
        assert_eq!(bytes, [0xfe, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(roundtrip_decode::<VarInt>(&bytes), VarInt(0x10000));
    }

    #[test]
    fn varint_9byte() {
        let val = VarInt(u64::MAX);
        let bytes = roundtrip_encode(&val);
        assert_eq!(bytes[0], 0xff);
        assert_eq!(roundtrip_decode::<VarInt>(&bytes), val);
    }

    #[test]
    fn varint_decode_ref() {
        let buf = [0xfd, 0x00, 0x01, 0xab];
        let (val, tail) = decode_ref::<VarInt>(&buf);
        assert_eq!(val, VarInt(0x0100));
        assert_eq!(tail, &[0xab]);
    }

    #[test]
    fn fixed_array() {
        let arr: [u8; 4] = [1, 2, 3, 4];
        let bytes = roundtrip_encode(&arr);
        assert_eq!(bytes, [1, 2, 3, 4]);
        assert_eq!(roundtrip_decode::<[u8; 4]>(&bytes), arr);
    }

    #[test]
    fn fixed_array_decode_ref() {
        let buf = [1u8, 2, 3, 4, 5, 6];
        let (arr, tail) = decode_ref::<[u8; 4]>(&buf);
        assert_eq!(arr, [1, 2, 3, 4]);
        assert_eq!(tail, &[5, 6]);
    }

    #[test]
    fn varstr() {
        let s = "hello".to_string();
        let bytes = roundtrip_encode(&s);
        assert_eq!(bytes[0], 5);
        assert_eq!(&bytes[1..], b"hello");
        assert_eq!(roundtrip_decode::<String>(&bytes), s);
    }

    #[test]
    fn str_decode_ref_zero_copy() {
        let buf = b"\x05helloworld";
        let (s, tail) = decode_ref::<&str>(buf);
        assert_eq!(s, "hello");
        assert_eq!(tail, b"world");
        // s borrows directly from buf — no allocation
        assert!(std::ptr::eq(s.as_bytes().as_ptr(), &raw const buf[1]));
    }

    #[test]
    fn slice_decode_ref_zero_copy() {
        let buf = b"\x04\xde\xad\xbe\xefXX";
        let (data, tail) = decode_ref::<&[u8]>(buf);
        assert_eq!(data, &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(tail, b"XX");
        assert!(std::ptr::eq(data.as_ptr(), &raw const buf[1]));
    }

    #[test]
    fn vec_u8() {
        let v: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef];
        let bytes = roundtrip_encode(&v);
        assert_eq!(bytes[0], 4);
        assert_eq!(roundtrip_decode::<Vec<u8>>(&bytes), v);
    }

    // ── Adversarial / edge-case tests ─────────────────────────────────────────

    // VarInt: truncated body after 0xfd tag must fail, not panic.
    #[test]
    fn varint_truncated_3byte_body() {
        let e = decode_err::<VarInt>(&[0xfd, 0x01]); // needs 2 more bytes, only 1
        assert!(matches!(e, Error::UnexpectedEof | Error::Io(_)));
    }

    // VarInt: only the tag byte present for a 9-byte encoding.
    #[test]
    fn varint_truncated_9byte_body() {
        let e = decode_err::<VarInt>(&[0xff, 0x00, 0x00, 0x00]); // needs 8, has 3
        assert!(matches!(e, Error::UnexpectedEof | Error::Io(_)));
    }

    // VarInt: completely empty input.
    #[test]
    fn varint_empty_input() {
        let e = decode_err::<VarInt>(&[]);
        assert!(matches!(e, Error::UnexpectedEof | Error::Io(_)));
    }

    // VarInt decode_ref: same truncation cases via the zero-copy path.
    #[test]
    fn varint_decode_ref_truncated() {
        let e = decode_ref_err::<VarInt>(&[0xfe, 0x00]); // needs 4 body bytes, has 1
        assert!(matches!(e, Error::UnexpectedEof | Error::Io(_)));
    }

    // VarInt: boundary values round-trip correctly.
    #[test]
    fn varint_boundary_values() {
        for val in [
            0u64,
            0xfc,
            0xfd,
            0xffff,
            0x10000,
            0xffff_ffff,
            0x1_0000_0000,
            u64::MAX,
        ] {
            let v = VarInt(val);
            let encoded = roundtrip_encode(&v);
            assert_eq!(roundtrip_decode::<VarInt>(&encoded), v, "VarInt({val})");
        }
    }

    // VarInt encoded_len matches the actual encoded byte count.
    #[test]
    fn varint_encoded_len_matches_actual() {
        for val in [0u64, 0xfc, 0xfd, 0xffff, 0x10000, 0xffff_ffff, u64::MAX] {
            let v = VarInt(val);
            assert_eq!(v.encoded_len(), roundtrip_encode(&v).len(), "VarInt({val})");
        }
    }

    // Primitive int: truncated input must fail.
    #[test]
    fn primitive_truncated_u32() {
        let e = decode_err::<u32>(&[0x01, 0x02]); // needs 4, has 2
        assert!(matches!(e, Error::UnexpectedEof | Error::Io(_)));
    }

    #[test]
    fn primitive_truncated_u64() {
        let e = decode_err::<u64>(&[0xff; 7]); // needs 8, has 7
        assert!(matches!(e, Error::UnexpectedEof | Error::Io(_)));
    }

    // decode_ref on an empty slice for fixed arrays.
    #[test]
    fn fixed_array_decode_ref_empty() {
        let e = decode_ref_err::<[u8; 4]>(&[]);
        assert!(matches!(e, Error::UnexpectedEof));
    }

    // &[u8] DecodeRef: length prefix claims more bytes than available.
    #[test]
    fn slice_decode_ref_claims_too_many_bytes() {
        // VarInt(10) followed by only 3 bytes.
        let buf = [0x0a, 0x01, 0x02, 0x03];
        let e = decode_ref_err::<&[u8]>(&buf);
        assert!(matches!(e, Error::UnexpectedEof));
    }

    // &str DecodeRef: invalid UTF-8 must return InvalidData, not panic.
    #[test]
    fn str_decode_ref_invalid_utf8() {
        let buf = [0x02, 0xff, 0xfe]; // 2-byte "string" with invalid UTF-8
        let e = decode_ref_err::<&str>(&buf);
        assert!(matches!(e, Error::InvalidUtf8(_)));
    }

    // String Decode (stream): invalid UTF-8 must return InvalidData.
    #[test]
    fn string_decode_invalid_utf8() {
        let buf = [0x02, 0xff, 0xfe];
        let e = decode_err::<String>(&buf);
        assert!(matches!(e, Error::InvalidUtf8(_)));
    }

    // String Decode: empty string round-trips correctly.
    #[test]
    fn string_empty_roundtrip() {
        let s = String::new();
        let bytes = roundtrip_encode(&s);
        assert_eq!(bytes, [0x00]);
        assert_eq!(roundtrip_decode::<String>(&bytes), s);
    }

    // Vec<u8> Decode: length of zero is valid.
    #[test]
    fn vec_u8_empty() {
        let bytes = roundtrip_encode(&Vec::<u8>::new());
        assert_eq!(bytes, [0x00]);
        assert_eq!(roundtrip_decode::<Vec<u8>>(&bytes), Vec::<u8>::new());
    }

    // Vec<u8> Decode: VarInt length exceeding MAX_BYTES must fail gracefully.
    #[test]
    fn vec_u8_length_exceeds_available_data() {
        // VarInt(0xfd, 0x00, 0x04) = length 1024, followed by no data.
        let buf = [0xfd, 0x00, 0x04];
        let e = decode_err::<Vec<u8>>(&buf);
        assert!(matches!(
            e,
            Error::LengthOverflow(_) | Error::UnexpectedEof | Error::Io(_)
        ));
    }

    // decode_ref on a primitive with exactly the right number of bytes leaves an
    // empty tail (no off-by-one).
    #[test]
    fn primitive_decode_ref_exact_fit() {
        let buf = [0x01, 0x00, 0x00, 0x00];
        let (val, tail) = decode_ref::<u32>(&buf);
        assert_eq!(val, 1u32);
        assert!(tail.is_empty());
    }

    // Encoding extreme integer values must not panic.
    #[test]
    fn encode_extreme_integers() {
        for v in [i32::MIN, i32::MAX, 0i32] {
            roundtrip_encode(&v);
        }
        for v in [i64::MIN, i64::MAX, 0i64] {
            roundtrip_encode(&v);
        }
        for v in [u64::MIN, u64::MAX] {
            roundtrip_encode(&v);
        }
    }

    // ── decode_from_first_byte tests ─────────────────────────────────────────

    #[test]
    fn decode_from_first_byte_single_byte() {
        // Single-byte values: 0x00 through 0xfc are returned directly.
        for b in [0x00, 0x01, 0x7f, 0xfc] {
            let mut cursor = Cursor::new(&[] as &[u8]);
            let vi = VarInt::decode_from_first_byte(b, &mut cursor).unwrap();
            assert_eq!(vi, VarInt(u64::from(b)));
        }
    }

    #[test]
    fn decode_from_first_byte_fd_prefix() {
        // 0xfd prefix: next 2 bytes are little-endian u16.
        let body = 0x0100u16.to_le_bytes();
        let mut cursor = Cursor::new(body.as_slice());
        let vi = VarInt::decode_from_first_byte(0xfd, &mut cursor).unwrap();
        assert_eq!(vi, VarInt(0x0100));
    }

    #[test]
    fn decode_from_first_byte_fe_prefix() {
        // 0xfe prefix: next 4 bytes are little-endian u32.
        let body = 0x0001_0000u32.to_le_bytes();
        let mut cursor = Cursor::new(body.as_slice());
        let vi = VarInt::decode_from_first_byte(0xfe, &mut cursor).unwrap();
        assert_eq!(vi, VarInt(0x0001_0000));
    }

    #[test]
    fn decode_from_first_byte_ff_prefix() {
        // 0xff prefix: next 8 bytes are little-endian u64.
        let body = u64::MAX.to_le_bytes();
        let mut cursor = Cursor::new(body.as_slice());
        let vi = VarInt::decode_from_first_byte(0xff, &mut cursor).unwrap();
        assert_eq!(vi, VarInt(u64::MAX));
    }

    // ── VarInt DecodeRef tests ────────────────────────────────────────────────

    #[test]
    fn varint_decode_ref_single_byte() {
        let buf = [0x42, 0xaa];
        let (vi, rest) = VarInt::decode_ref(&buf).unwrap();
        assert_eq!(vi, VarInt(0x42));
        assert_eq!(rest, &[0xaa]);
    }

    #[test]
    fn varint_decode_ref_fd_prefix() {
        let mut buf = vec![0xfd];
        buf.extend_from_slice(&300u16.to_le_bytes());
        buf.push(0xbb);
        let (vi, rest) = VarInt::decode_ref(&buf).unwrap();
        assert_eq!(vi, VarInt(300));
        assert_eq!(rest, &[0xbb]);
    }

    #[test]
    fn varint_decode_ref_fe_prefix() {
        let mut buf = vec![0xfe];
        buf.extend_from_slice(&70_000u32.to_le_bytes());
        let (vi, rest) = VarInt::decode_ref(&buf).unwrap();
        assert_eq!(vi, VarInt(70_000));
        assert!(rest.is_empty());
    }

    #[test]
    fn varint_decode_ref_ff_prefix() {
        let mut buf = vec![0xff];
        buf.extend_from_slice(&0x1_0000_0000u64.to_le_bytes());
        let (vi, rest) = VarInt::decode_ref(&buf).unwrap();
        assert_eq!(vi, VarInt(0x1_0000_0000));
        assert!(rest.is_empty());
    }

    #[test]
    fn varint_decode_ref_truncated_fd() {
        let buf = [0xfd, 0x01]; // needs 2 bytes after 0xfd, only 1
        assert!(VarInt::decode_ref(&buf).is_err());
    }

    #[test]
    fn varint_decode_ref_truncated_fe() {
        let buf = [0xfe, 0x01, 0x02]; // needs 4 bytes after 0xfe, only 2
        assert!(VarInt::decode_ref(&buf).is_err());
    }

    #[test]
    fn varint_decode_ref_empty() {
        let buf: &[u8] = &[];
        assert!(VarInt::decode_ref(buf).is_err());
    }

    #[test]
    fn codec_error_to_io_error_conversion() {
        // UnexpectedEof -> ErrorKind::UnexpectedEof
        let e = io::Error::from(Error::UnexpectedEof);
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);

        // LengthOverflow -> ErrorKind::InvalidData
        let e = io::Error::from(Error::LengthOverflow(999));
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);

        // InvalidUtf8 -> ErrorKind::InvalidData
        let utf8_err = std::str::from_utf8(&[0xff]).unwrap_err();
        let e = io::Error::from(Error::InvalidUtf8(utf8_err));
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);

        // Io(inner) -> returns the inner io::Error unchanged
        let inner = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let e = io::Error::from(Error::Io(inner));
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(e.to_string(), "access denied");
    }

    #[test]
    fn codec_error_display_all_variants() {
        let eof = Error::UnexpectedEof;
        assert!(format!("{eof}").contains("unexpected"));

        let overflow = Error::LengthOverflow(u64::MAX);
        assert!(format!("{overflow}").contains("overflows"));

        let utf8 = Error::InvalidUtf8(std::str::from_utf8(&[0xff]).unwrap_err());
        assert!(format!("{utf8}").contains("UTF-8"));

        let io = Error::Io(io::Error::new(io::ErrorKind::Other, "test"));
        assert!(format!("{io}").contains("I/O"));
    }

    #[test]
    fn error_source_unexpected_eof_is_none() {
        use std::error::Error as StdError;
        let e = Error::UnexpectedEof;
        assert!(e.source().is_none());
    }

    #[test]
    fn error_source_length_overflow_is_none() {
        use std::error::Error as StdError;
        let e = Error::LengthOverflow(42);
        assert!(e.source().is_none());
    }

    #[test]
    fn error_source_invalid_utf8_is_some() {
        use std::error::Error as StdError;
        let utf8_err = std::str::from_utf8(&[0xff]).unwrap_err();
        let e = Error::InvalidUtf8(utf8_err);
        let src = e.source().expect("InvalidUtf8 must have a source");
        // The source should be the inner Utf8Error — verify by Display.
        assert!(format!("{src}").contains("invalid"));
    }

    #[test]
    fn error_source_io_is_some() {
        use std::error::Error as StdError;
        let io_err = io::Error::new(io::ErrorKind::Other, "disk on fire");
        let e = Error::Io(io_err);
        let src = e.source().expect("Io must have a source");
        assert!(format!("{src}").contains("disk on fire"));
    }
}
