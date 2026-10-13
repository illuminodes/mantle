use std::io::{self, Read};

use crate::codec::{Decode, DecodeRef, Encode, Error as CodecError, VarInt};
use crate::difficulty::BlockTime;

use super::envelope::{Port, Services};

// ── Addr / AddrV2 ─────────────────────────────────────────────────────────────

/// One legacy `addr` entry: `time(4) || services(8) || ip(16) || port(2 BE)`.
///
/// `#[repr(C)]` guarantees the field layout matches the wire format exactly —
/// no padding, no reordering. `size_of::<AddrEntry>() == 30`.
///
/// `services` is stored as `[u8; 8]` (LE) rather than `u64` to avoid 8-byte
/// alignment that would insert padding after `time`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AddrEntry {
    time_le: [u8; 4],
    services_le: [u8; 8],
    /// IPv6 address (IPv4 mapped as `::ffff:0:0/96`).
    ip: [u8; 16],
    port_be: [u8; 2],
}

impl AddrEntry {
    pub const ENCODED_LEN: usize = 4 + 8 + 16 + 2;

    #[inline]
    #[must_use]
    pub fn time(&self) -> BlockTime {
        BlockTime::new(u32::from_le_bytes(self.time_le))
    }

    #[inline]
    #[must_use]
    pub fn services(&self) -> Services {
        Services::new(u64::from_le_bytes(self.services_le))
    }

    #[inline]
    #[must_use]
    pub fn ip(&self) -> [u8; 16] {
        self.ip
    }

    #[inline]
    #[must_use]
    pub fn ip_v4(&self) -> Option<[u8; 4]> {
        if self.ip[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
            Some([self.ip[12], self.ip[13], self.ip[14], self.ip[15]])
        } else {
            None
        }
    }

    #[inline]
    #[must_use]
    pub fn port(&self) -> Port {
        Port::from_be_bytes(self.port_be)
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let mut buf = [0u8; Self::ENCODED_LEN];
        buf[0..4].copy_from_slice(&self.time_le);
        buf[4..12].copy_from_slice(&self.services_le);
        buf[12..28].copy_from_slice(&self.ip);
        buf[28..30].copy_from_slice(&self.port_be);
        buf
    }

    #[must_use]
    pub fn from_bytes(b: &[u8; Self::ENCODED_LEN]) -> Self {
        let mut time_le = [0u8; 4];
        time_le.copy_from_slice(&b[0..4]);
        let mut services_le = [0u8; 8];
        services_le.copy_from_slice(&b[4..12]);
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&b[12..28]);
        let mut port_be = [0u8; 2];
        port_be.copy_from_slice(&b[28..30]);
        Self {
            time_le,
            services_le,
            ip,
            port_be,
        }
    }
}

#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for AddrEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddrEntry")
            .field("time", &self.time())
            .field("services", &self.services())
            .field("ip", &self.ip)
            .field("port", &self.port())
            .finish()
    }
}

impl Encode for AddrEntry {
    #[inline]
    fn encode(&self, w: &mut impl std::io::Write) -> Result<(), CodecError> {
        w.write_all(&self.to_bytes()).map_err(CodecError::Io)
    }
}

impl Decode for AddrEntry {
    #[inline]
    fn decode(r: &mut impl Read) -> Result<Self, CodecError> {
        let mut buf = [0u8; Self::ENCODED_LEN];
        r.read_exact(&mut buf).map_err(CodecError::Io)?;
        Ok(Self::from_bytes(&buf))
    }
}

impl<'a> DecodeRef<'a> for AddrEntry {
    #[inline]
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), CodecError> {
        if buf.len() < Self::ENCODED_LEN {
            return Err(CodecError::UnexpectedEof);
        }
        let (head, tail) = buf.split_at(Self::ENCODED_LEN);
        let arr: &[u8; Self::ENCODED_LEN] =
            head.try_into().map_err(|_| CodecError::UnexpectedEof)?;
        Ok((Self::from_bytes(arr), tail))
    }
}

/// `addr` — list of peer addresses (BIP31 / pre-BIP155 form).
///
/// Capped at 1000 entries (Bitcoin Core's `MAX_ADDR_TO_SEND`). Decode-only
/// for now — we only consume `addr` from peers, never originate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrMsg(pub Vec<AddrEntry>);

/// Zero-alloc lazy iterator over `AddrEntry` values parsed from a raw byte slice.
///
/// Created by [`AddrMsg::iter_entries`]. Yields `Result<AddrEntry, CodecError>` so
/// the caller can handle truncation errors entry-by-entry.
#[derive(Debug)]
pub struct AddrEntryIter<'a> {
    remaining: &'a [u8],
    left: usize,
}

impl Iterator for AddrEntryIter<'_> {
    type Item = Result<AddrEntry, CodecError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        if self.remaining.len() < AddrEntry::ENCODED_LEN {
            self.left = 0;
            return Some(Err(CodecError::UnexpectedEof));
        }
        let (head, tail) = self.remaining.split_at(AddrEntry::ENCODED_LEN);
        self.remaining = tail;
        self.left -= 1;
        Some(
            head.try_into()
                .map(AddrEntry::from_bytes)
                .map_err(|_| CodecError::UnexpectedEof),
        )
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl ExactSizeIterator for AddrEntryIter<'_> {}

impl AddrMsg {
    /// Bitcoin Core's `MAX_ADDR_TO_SEND`. Any incoming `addr` larger than
    /// this is rejected as malformed.
    pub const MAX_ENTRIES: usize = 1000;

    /// Return a zero-allocation iterator over entries in a raw `addr` payload.
    ///
    /// `buf` must start immediately after the message framing (i.e. be the raw payload).
    /// The `VarInt` count is read from the front of `buf`; no heap allocation occurs.
    ///
    /// # Errors
    /// Returns `InvalidData` if the entry count exceeds `MAX_ENTRIES` or if the `VarInt`
    /// cannot be decoded. Individual entries surface truncation errors as `Err` items.
    pub fn iter_entries<const MAX_ENTRIES: usize>(
        buf: &[u8],
    ) -> Result<AddrEntryIter<'_>, CodecError> {
        let (varint, rest) = VarInt::decode_ref(buf)?;
        let count = varint.to_usize()?;
        if count > MAX_ENTRIES {
            return Err(CodecError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "addr entry count exceeds limit",
            )));
        }
        Ok(AddrEntryIter {
            remaining: rest,
            left: count,
        })
    }

    /// # Errors
    /// `InvalidData` if the entry count exceeds `MAX_ENTRIES`, or on I/O error.
    #[allow(clippy::missing_panics_doc)]
    pub fn decode_limited(r: &mut impl Read) -> Result<Self, CodecError> {
        let count = VarInt::decode(r)?.to_usize()?;
        if count > Self::MAX_ENTRIES {
            return Err(CodecError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "addr entry count exceeds MAX_ADDR_TO_SEND",
            )));
        }
        let byte_len = count * AddrEntry::ENCODED_LEN;
        let mut buf = vec![0u8; byte_len];
        r.read_exact(&mut buf).map_err(CodecError::Io)?;
        let entries = buf
            .chunks_exact(AddrEntry::ENCODED_LEN)
            .map(|chunk| {
                chunk
                    .try_into()
                    .map(AddrEntry::from_bytes)
                    .map_err(|_| CodecError::UnexpectedEof)
            })
            .collect::<Result<Vec<_>, CodecError>>()?;
        Ok(Self(entries))
    }

    /// Decode into a caller-supplied buffer, clearing it first.
    ///
    /// On the second and subsequent calls the `Vec` already has capacity, so no
    /// heap allocation occurs. Equivalent to `decode_limited` but reuses storage.
    ///
    /// # Errors
    /// Returns `InvalidData` if the entry count exceeds `MAX_ENTRIES`, or on any I/O error.
    #[allow(clippy::missing_panics_doc)]
    pub fn decode_into_limited<const MAX_ENTRIES: usize>(
        r: &mut impl Read,
        out: &mut Vec<AddrEntry>,
    ) -> Result<(), CodecError> {
        let count = VarInt::decode(r)?.to_usize()?;
        if count > MAX_ENTRIES {
            return Err(CodecError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "addr entry count exceeds limit",
            )));
        }
        let byte_len = count * AddrEntry::ENCODED_LEN;
        let mut buf = vec![0u8; byte_len];
        r.read_exact(&mut buf).map_err(CodecError::Io)?;
        out.clear();
        out.extend(buf.chunks_exact(AddrEntry::ENCODED_LEN).map(|chunk| {
            let arr: &[u8; AddrEntry::ENCODED_LEN] = chunk.try_into().unwrap();
            AddrEntry::from_bytes(arr)
        }));
        Ok(())
    }
}

impl Decode for AddrMsg {
    fn decode(r: &mut impl Read) -> Result<Self, CodecError> {
        Self::decode_limited(r)
    }
}

/// One BIP155 address. Each defined network has a fixed-size payload, so we
/// store them as fixed arrays — no heap allocation. The `Unknown(network_id,
/// bytes)` variant catches future BIP-allocated network IDs whose width we
/// don't know at compile time; only the unknown case heap-allocates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddrV2Addr {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    /// Deprecated. BIP155 lists 10 bytes for compatibility with the legacy
    /// `.onion` v2 hidden-service addressing scheme.
    TorV2([u8; 10]),
    TorV3([u8; 32]),
    I2p([u8; 32]),
    Cjdns([u8; 16]),
    /// Forward-compat: a network-id byte we don't recognise. Address bytes
    /// preserved verbatim so the entry round-trips through serialisation if
    /// we ever re-encode. Bounded by [`AddrV2Addr::MAX_UNKNOWN_LEN`] on decode.
    Unknown {
        network_id: u8,
        addr: Vec<u8>,
    },
}

impl AddrV2Addr {
    /// Hard cap on the length of an `Unknown` network's address bytes —
    /// defensive against a malicious peer claiming a 16 MB address. Bitcoin
    /// Core uses 512 bytes for its `MAX_ADDRV2_SIZE`.
    pub const MAX_UNKNOWN_LEN: usize = 512;

    /// Expected wire length for a defined network ID. Returns `None` for
    /// unrecognised IDs so the caller knows to fall through to `Unknown`.
    ///
    /// Arms kept distinct by network kind so that a future BIP change to
    /// any single network's address width is a one-line edit and doesn't
    /// silently capture neighbours.
    #[allow(clippy::match_same_arms)]
    fn expected_len(network_id: u8) -> Option<usize> {
        match network_id {
            0x01 => Some(4),  // Ipv4
            0x02 => Some(16), // Ipv6
            0x03 => Some(10), // TorV2 (deprecated)
            0x04 => Some(32), // TorV3
            0x05 => Some(32), // I2p
            0x06 => Some(16), // Cjdns
            _ => None,
        }
    }

    /// Decode the per-entry address: `network_id(1) || addr(VarInt-len + bytes)`.
    ///
    /// # Errors
    /// `InvalidData` if a defined network ID arrives with an address length
    /// other than the BIP155-mandated size, or if an `Unknown` entry exceeds
    /// [`Self::MAX_UNKNOWN_LEN`], or on I/O error.
    pub fn decode(r: &mut impl Read) -> Result<Self, CodecError> {
        let mut nid = [0u8; 1];
        r.read_exact(&mut nid).map_err(CodecError::Io)?;
        let addr_len = VarInt::decode(r)?.to_usize()?;
        if let Some(expected) = Self::expected_len(nid[0]) {
            if addr_len != expected {
                return Err(CodecError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "addrv2 addr length does not match network_id",
                )));
            }
        } else if addr_len > Self::MAX_UNKNOWN_LEN {
            return Err(CodecError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "addrv2 addr length exceeds MAX_UNKNOWN_LEN",
            )));
        }

        // Defined networks decode into stack-resident fixed arrays; only the
        // `Unknown` arm heap-allocates.
        match nid[0] {
            0x01 => {
                let mut a = [0u8; 4];
                r.read_exact(&mut a).map_err(CodecError::Io)?;
                Ok(Self::Ipv4(a))
            }
            0x02 => {
                let mut a = [0u8; 16];
                r.read_exact(&mut a).map_err(CodecError::Io)?;
                Ok(Self::Ipv6(a))
            }
            0x03 => {
                let mut a = [0u8; 10];
                r.read_exact(&mut a).map_err(CodecError::Io)?;
                Ok(Self::TorV2(a))
            }
            0x04 => {
                let mut a = [0u8; 32];
                r.read_exact(&mut a).map_err(CodecError::Io)?;
                Ok(Self::TorV3(a))
            }
            0x05 => {
                let mut a = [0u8; 32];
                r.read_exact(&mut a).map_err(CodecError::Io)?;
                Ok(Self::I2p(a))
            }
            0x06 => {
                let mut a = [0u8; 16];
                r.read_exact(&mut a).map_err(CodecError::Io)?;
                Ok(Self::Cjdns(a))
            }
            n => {
                let mut buf = vec![0u8; addr_len];
                r.read_exact(&mut buf).map_err(CodecError::Io)?;
                Ok(Self::Unknown {
                    network_id: n,
                    addr: buf,
                })
            }
        }
    }
}

/// One BIP155 `addrv2` entry: `time(4) || services(VarInt) || network_id(1) ||
/// addr(VarInt-len + bytes) || port(2 BE)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrV2Entry {
    pub time: BlockTime,
    pub services: Services,
    pub addr: AddrV2Addr,
    pub port: Port,
}

impl AddrV2Entry {
    /// If this entry is an IPv4 address, return it as a [`std::net::SocketAddrV4`].
    /// Returns `None` for IPv6/Tor/I2P/etc. entries.
    #[must_use]
    pub fn ip_v4(&self) -> Option<std::net::SocketAddrV4> {
        match self.addr {
            AddrV2Addr::Ipv4(octets) => {
                let ip = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
                Some(std::net::SocketAddrV4::new(ip, self.port.to_u16()))
            }
            _ => None,
        }
    }
}

impl Decode for AddrV2Entry {
    fn decode(r: &mut impl Read) -> Result<Self, CodecError> {
        let time = BlockTime::new(u32::decode(r)?);
        let services = Services::new(VarInt::decode(r)?.to_u64());
        let addr = AddrV2Addr::decode(r)?;
        let mut port_bytes = [0u8; 2];
        r.read_exact(&mut port_bytes).map_err(CodecError::Io)?;
        Ok(Self {
            time,
            services,
            addr,
            port: Port::from_be_bytes(port_bytes),
        })
    }
}

/// `addrv2` — BIP155 list of peer addresses with extensible network types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrV2Msg(pub Vec<AddrV2Entry>);

impl AddrV2Msg {
    /// Same per-message cap as legacy `addr` — Bitcoin Core enforces both.
    pub const MAX_ENTRIES: usize = AddrMsg::MAX_ENTRIES;

    /// # Errors
    /// `InvalidData` if the entry count exceeds [`Self::MAX_ENTRIES`], or on I/O error.
    pub fn decode_limited(r: &mut impl Read) -> Result<Self, CodecError> {
        let count = VarInt::decode(r)?.to_usize()?;
        if count > Self::MAX_ENTRIES {
            return Err(CodecError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "addrv2 entry count exceeds MAX_ADDR_TO_SEND",
            )));
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(AddrV2Entry::decode(r)?);
        }
        Ok(Self(entries))
    }
}

impl Decode for AddrV2Msg {
    fn decode(r: &mut impl Read) -> Result<Self, CodecError> {
        Self::decode_limited(r)
    }
}

#[cfg(test)]
mod tests {
    use super::super::envelope::Services;
    use super::*;
    use std::io::Cursor;

    fn decode<T: Decode>(bytes: &[u8]) -> T {
        T::decode(&mut Cursor::new(bytes)).expect("test data must decode")
    }

    #[test]
    fn addr_msg_decodes_two_entries() {
        // VarInt count (2) || 2 × (4 time | 8 services | 16 ip | 2 port-BE)
        let mut bytes = vec![0x02];
        // entry 0: time=1, services=NODE_NETWORK, ip=::ffff:1.2.3.4, port=18333
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&Services::NODE_NETWORK.to_le_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4]);
        bytes.extend_from_slice(&18_333u16.to_be_bytes());
        // entry 1: same shape, different ip/port
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&Services::NODE_NETWORK.to_le_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 5, 6, 7, 8]);
        bytes.extend_from_slice(&8333u16.to_be_bytes());

        let msg = decode::<AddrMsg>(&bytes);
        assert_eq!(msg.0.len(), 2);
        assert_eq!(msg.0[0].port(), Port::new(18_333));
        assert_eq!(msg.0[0].ip()[12..], [1, 2, 3, 4]);
        assert_eq!(msg.0[1].port(), Port::new(8333));
    }

    #[test]
    fn addr_msg_rejects_oversize_count() {
        // Count = 1001 (one over MAX_ADDR_TO_SEND), no entry bytes (they'd
        // never be read — the cap check should fire first).
        let mut bytes = vec![0xfd]; // VarInt prefix for u16
        bytes.extend_from_slice(&1001u16.to_le_bytes());
        let mut cur = std::io::Cursor::new(&bytes);
        assert!(AddrMsg::decode_limited(&mut cur).is_err());
    }

    #[test]
    fn addrv2_decodes_ipv4_entry() {
        // VarInt count (1) || time(4) | services(VarInt) | netid(1)
        // | addr-len(VarInt) | addr(N) | port(2 BE)
        let mut bytes = vec![0x01]; // count = 1
        bytes.extend_from_slice(&100u32.to_le_bytes()); // time
        bytes.push(0x01); // services VarInt = 1 (NODE_NETWORK)
        bytes.push(0x01); // network = Ipv4
        bytes.push(0x04); // addr-len VarInt = 4
        bytes.extend_from_slice(&[10, 20, 30, 40]);
        bytes.extend_from_slice(&48_333u16.to_be_bytes());

        let msg = decode::<AddrV2Msg>(&bytes);
        assert_eq!(msg.0.len(), 1);
        let entry = &msg.0[0];
        assert!(matches!(entry.addr, AddrV2Addr::Ipv4([10, 20, 30, 40])));
        let v4 = entry.ip_v4().expect("ipv4 entry must produce SocketAddrV4");
        assert_eq!(v4.ip().octets(), [10, 20, 30, 40]);
        assert_eq!(v4.port(), 48_333);
    }

    #[test]
    fn addrv2_decodes_torv3_then_ipv4() {
        // count = 2: a torv3 entry (32-byte addr) followed by an ipv4 entry.
        // The torv3 entry must decode without error and yield ip_v4() == None.
        let mut bytes = vec![0x02];
        // entry 0: torv3
        bytes.extend_from_slice(&500u32.to_le_bytes());
        bytes.push(0x00); // services VarInt = 0
        bytes.push(0x04); // network = TorV3
        bytes.push(0x20); // addr-len VarInt = 32
        bytes.extend_from_slice(&[0xab; 32]);
        bytes.extend_from_slice(&48_333u16.to_be_bytes());
        // entry 1: ipv4
        bytes.extend_from_slice(&501u32.to_le_bytes());
        bytes.push(0x01);
        bytes.push(0x01);
        bytes.push(0x04);
        bytes.extend_from_slice(&[7, 7, 7, 7]);
        bytes.extend_from_slice(&48_333u16.to_be_bytes());

        let msg = decode::<AddrV2Msg>(&bytes);
        assert_eq!(msg.0.len(), 2);
        assert!(msg.0[0].ip_v4().is_none(), "torv3 has no v4 representation");
        assert_eq!(msg.0[1].ip_v4().unwrap().ip().octets(), [7, 7, 7, 7]);
    }

    #[test]
    fn addrv2_rejects_addr_len_mismatch_for_known_network() {
        // network = Ipv4 (expects 4 bytes) but addr-len = 6 → InvalidData.
        let mut bytes = vec![0x01]; // count = 1
        bytes.extend_from_slice(&100u32.to_le_bytes());
        bytes.push(0x00);
        bytes.push(0x01); // Ipv4
        bytes.push(0x06); // addr-len = 6 (wrong; spec says 4)
        bytes.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        bytes.extend_from_slice(&48_333u16.to_be_bytes());
        let mut cur = std::io::Cursor::new(&bytes);
        assert!(AddrV2Msg::decode_limited(&mut cur).is_err());
    }

    #[test]
    fn addr_entry_size_eq_encoded_len() {
        assert_eq!(std::mem::size_of::<AddrEntry>(), AddrEntry::ENCODED_LEN,);
    }

    // ── AddrMsg iter_entries / decode_into ────────────────────────────────────

    fn make_addr_payload(n: usize) -> Vec<u8> {
        use crate::codec::Encode as _;
        let mut payload = Vec::new();
        crate::codec::VarInt::from(n).encode(&mut payload).unwrap();
        for i in 0..n {
            payload.extend_from_slice(&u32::try_from(i).unwrap().to_le_bytes());
            payload.extend_from_slice(&Services::NODE_NETWORK.to_le_bytes());
            payload.extend_from_slice(&[0u8; 16]);
            payload.extend_from_slice(&8333u16.to_be_bytes());
        }
        payload
    }

    #[test]
    fn addr_iter_empty() {
        let payload = make_addr_payload(0);
        let mut iter =
            AddrMsg::iter_entries::<1000>(&payload).expect("must succeed on valid bytes");
        assert_eq!(iter.len(), 0);
        assert!(iter.next().is_none());
    }

    #[test]
    fn addr_iter_matches_owned_decode() {
        let payload = make_addr_payload(3);
        let owned = decode::<AddrMsg>(&payload);
        let iter_entries: Vec<AddrEntry> = AddrMsg::iter_entries::<1000>(&payload)
            .expect("must succeed")
            .map(|r| r.expect("entry must decode"))
            .collect();
        assert_eq!(iter_entries.len(), owned.0.len());
        for (a, b) in iter_entries.iter().zip(&owned.0) {
            assert_eq!(a.port(), b.port());
            assert_eq!(a.time(), b.time());
        }
    }

    #[test]
    fn addr_iter_limit_exceeded() {
        let payload = make_addr_payload(5);
        let err = AddrMsg::iter_entries::<3>(&payload).unwrap_err();
        assert!(matches!(
            err,
            CodecError::Io(_) | CodecError::LengthOverflow(_)
        ));
    }

    #[test]
    fn addr_iter_truncated_entry() {
        let mut payload = make_addr_payload(2);
        payload.truncate(1 + AddrEntry::ENCODED_LEN + 10);
        let mut iter = AddrMsg::iter_entries::<1000>(&payload).expect("header parses");
        assert!(iter.next().unwrap().is_ok());
        assert!(iter.next().unwrap().is_err());
        assert!(iter.next().is_none());
    }

    #[test]
    fn addr_decode_into_reuses_capacity() {
        let payload = make_addr_payload(5);
        let mut buf: Vec<AddrEntry> = Vec::new();
        AddrMsg::decode_into_limited::<1000>(&mut std::io::Cursor::new(&payload), &mut buf)
            .expect("must succeed");
        assert_eq!(buf.len(), 5);
        let cap = buf.capacity();

        AddrMsg::decode_into_limited::<1000>(&mut std::io::Cursor::new(&payload), &mut buf)
            .expect("must succeed");
        assert_eq!(buf.len(), 5);
        assert!(buf.capacity() >= cap);
    }

    #[test]
    fn addr_entry_to_bytes_from_bytes_roundtrip() {
        let payload = make_addr_payload(1);
        let entry = decode::<AddrMsg>(&payload).0.into_iter().next().unwrap();
        let bytes = entry.to_bytes();
        let entry2 = AddrEntry::from_bytes(&bytes);
        assert_eq!(entry.time(), entry2.time());
        assert_eq!(entry.services(), entry2.services());
        assert_eq!(entry.ip(), entry2.ip());
        assert_eq!(entry.port(), entry2.port());
    }

    #[test]
    fn addr_entry_decode_ref() {
        let payload = make_addr_payload(1);
        let entry = decode::<AddrMsg>(&payload).0.into_iter().next().unwrap();
        let bytes = entry.to_bytes();
        let (decoded, tail) = AddrEntry::decode_ref(&bytes).unwrap();
        assert_eq!(decoded.port(), entry.port());
        assert!(tail.is_empty());
    }

    #[test]
    fn addr_entry_decode_ref_truncated() {
        let err = AddrEntry::decode_ref(&[0u8; 15]).unwrap_err();
        assert!(matches!(err, CodecError::UnexpectedEof));
    }

    #[test]
    fn addr_entry_ipv4_detection() {
        let mut payload = make_addr_payload(1);
        let ip_offset = 1 + 4 + 8;
        payload[ip_offset..ip_offset + 12]
            .copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
        payload[ip_offset + 12..ip_offset + 16].copy_from_slice(&[10, 0, 0, 1]);
        let entry = decode::<AddrMsg>(&payload).0.into_iter().next().unwrap();
        assert_eq!(entry.ip_v4(), Some([10, 0, 0, 1]));
    }

    #[test]
    fn addr_entry_ipv6_no_v4() {
        let payload = make_addr_payload(1);
        let entry = decode::<AddrMsg>(&payload).0.into_iter().next().unwrap();
        assert_eq!(entry.ip_v4(), None);
    }

    // ── AddrV2 adversarial ───────────────────────────────────────────────────

    #[test]
    fn addrv2_unknown_network_within_limit() {
        let mut bytes = vec![0x01]; // count = 1
        bytes.extend_from_slice(&100u32.to_le_bytes());
        bytes.push(0x00); // services VarInt = 0
        bytes.push(0xff); // unknown network_id
        bytes.push(0x08); // addr-len VarInt = 8
        bytes.extend_from_slice(&[0xaa; 8]);
        bytes.extend_from_slice(&48_333u16.to_be_bytes());
        let msg = decode::<AddrV2Msg>(&bytes);
        assert_eq!(msg.0.len(), 1);
        assert!(matches!(
            msg.0[0].addr,
            AddrV2Addr::Unknown {
                network_id: 0xff,
                ..
            }
        ));
    }

    #[test]
    fn addrv2_addr_decode_ipv6() {
        let mut buf = vec![0x02, 0x10]; // Ipv6, len=16
        buf.extend_from_slice(&[1u8; 16]);
        let addr = AddrV2Addr::decode(&mut Cursor::new(&buf)).unwrap();
        assert!(matches!(addr, AddrV2Addr::Ipv6(_)));
    }

    #[test]
    fn addrv2_addr_decode_torv2() {
        let mut buf = vec![0x03, 0x0a]; // TorV2, len=10
        buf.extend_from_slice(&[0xab; 10]);
        let addr = AddrV2Addr::decode(&mut Cursor::new(&buf)).unwrap();
        assert!(matches!(addr, AddrV2Addr::TorV2(_)));
    }

    #[test]
    fn addrv2_addr_decode_torv3() {
        let mut buf = vec![0x04, 0x20]; // TorV3, len=32
        buf.extend_from_slice(&[0xcd; 32]);
        let addr = AddrV2Addr::decode(&mut Cursor::new(&buf)).unwrap();
        assert!(matches!(addr, AddrV2Addr::TorV3(_)));
    }

    #[test]
    fn addrv2_addr_decode_i2p() {
        let mut buf = vec![0x05, 0x20]; // I2p, len=32
        buf.extend_from_slice(&[0xef; 32]);
        let addr = AddrV2Addr::decode(&mut Cursor::new(&buf)).unwrap();
        assert!(matches!(addr, AddrV2Addr::I2p(_)));
    }

    #[test]
    fn addrv2_addr_decode_cjdns() {
        let mut buf = vec![0x06, 0x10]; // Cjdns, len=16
        buf.extend_from_slice(&[0x99; 16]);
        let addr = AddrV2Addr::decode(&mut Cursor::new(&buf)).unwrap();
        assert!(matches!(addr, AddrV2Addr::Cjdns(_)));
    }

    #[test]
    fn addrv2_addr_decode_wrong_length_rejected() {
        let mut buf = vec![0x01, 0x05]; // Ipv4 expects 4 bytes, giving 5
        buf.extend_from_slice(&[0; 5]);
        assert!(AddrV2Addr::decode(&mut Cursor::new(&buf)).is_err());
    }

    #[test]
    fn addrv2_unknown_network_exceeds_max_len() {
        let mut bytes = vec![0x01]; // count = 1
        bytes.extend_from_slice(&100u32.to_le_bytes());
        bytes.push(0x00);
        bytes.push(0xff); // unknown network_id
        // addr-len = 513 (exceeds MAX_UNKNOWN_LEN of 512)
        bytes.push(0xfd);
        bytes.extend_from_slice(&513u16.to_le_bytes());
        bytes.extend_from_slice(&vec![0u8; 513]);
        bytes.extend_from_slice(&48_333u16.to_be_bytes());
        let mut cur = std::io::Cursor::new(&bytes);
        assert!(AddrV2Msg::decode_limited(&mut cur).is_err());
    }

    // ── AddrV2Addr::decode additional branch coverage ──────────────────────

    #[test]
    fn addrv2_addr_decode_empty_stream_fails() {
        // Empty stream: the first read_exact for the network_id byte fails.
        let buf: &[u8] = &[];
        assert!(AddrV2Addr::decode(&mut Cursor::new(buf)).is_err());
    }

    #[test]
    fn addrv2_addr_decode_truncated_after_nid_fails() {
        // Network ID present but no VarInt for addr_len.
        let buf: &[u8] = &[0x01]; // Ipv4 network_id, no length
        assert!(AddrV2Addr::decode(&mut Cursor::new(buf)).is_err());
    }

    #[test]
    fn addrv2_addr_decode_truncated_body_ipv4_fails() {
        // Correct Ipv4 header (nid=0x01, len=4) but only 2 bytes of addr data.
        let buf: &[u8] = &[0x01, 0x04, 0x0a, 0x00];
        assert!(AddrV2Addr::decode(&mut Cursor::new(buf)).is_err());
    }

    #[test]
    fn addrv2_addr_decode_truncated_body_torv3_fails() {
        // Correct TorV3 header (nid=0x04, len=32) but only 10 bytes of data.
        let mut buf = vec![0x04, 0x20]; // TorV3, len=32
        buf.extend_from_slice(&[0xab; 10]);
        assert!(AddrV2Addr::decode(&mut Cursor::new(&buf)).is_err());
    }

    #[test]
    fn addrv2_addr_decode_unknown_zero_length() {
        // Unknown network_id with addr_len=0: valid edge case, empty address.
        let buf: &[u8] = &[0xfe, 0x00]; // unknown nid=0xFE, len=0
        let addr = AddrV2Addr::decode(&mut Cursor::new(buf)).unwrap();
        match addr {
            AddrV2Addr::Unknown { network_id, addr } => {
                assert_eq!(network_id, 0xfe);
                assert!(addr.is_empty());
            }
            other => panic!("expected Unknown, got: {other:?}"),
        }
    }

    #[test]
    fn addrv2_addr_decode_unknown_at_max_len() {
        // Unknown network_id with addr_len exactly at MAX_UNKNOWN_LEN (512).
        let mut buf = vec![0xfe]; // unknown nid
        // VarInt for 512: 0xfd prefix + 512 as u16 LE
        buf.push(0xfd);
        buf.extend_from_slice(&512u16.to_le_bytes());
        buf.extend_from_slice(&vec![0xaa; 512]);
        let addr = AddrV2Addr::decode(&mut Cursor::new(&buf)).unwrap();
        match addr {
            AddrV2Addr::Unknown { network_id, addr } => {
                assert_eq!(network_id, 0xfe);
                assert_eq!(addr.len(), 512);
            }
            other => panic!("expected Unknown, got: {other:?}"),
        }
    }

    #[test]
    fn addrv2_addr_decode_unknown_exceeds_max_directly() {
        // Test the MAX_UNKNOWN_LEN rejection at the AddrV2Addr level (not
        // through the full message decode, which was the only test before).
        let mut buf = vec![0xfe]; // unknown nid
        buf.push(0xfd);
        buf.extend_from_slice(&513u16.to_le_bytes());
        buf.extend_from_slice(&vec![0u8; 513]);
        assert!(AddrV2Addr::decode(&mut Cursor::new(&buf)).is_err());
    }

    #[test]
    fn addrv2_addr_decode_wrong_length_ipv6_rejected() {
        // Ipv6 (nid=0x02) expects 16 bytes, give 20.
        let mut buf = vec![0x02, 0x14]; // Ipv6, len=20
        buf.extend_from_slice(&[0; 20]);
        assert!(AddrV2Addr::decode(&mut Cursor::new(&buf)).is_err());
    }

    #[test]
    fn addrv2_addr_decode_wrong_length_i2p_rejected() {
        // I2p (nid=0x05) expects 32 bytes, give 16.
        let mut buf = vec![0x05, 0x10]; // I2p, len=16
        buf.extend_from_slice(&[0; 16]);
        assert!(AddrV2Addr::decode(&mut Cursor::new(&buf)).is_err());
    }

    #[test]
    fn addrv2_addr_decode_wrong_length_cjdns_rejected() {
        // Cjdns (nid=0x06) expects 16 bytes, give 4.
        let mut buf = vec![0x06, 0x04]; // Cjdns, len=4
        buf.extend_from_slice(&[0; 4]);
        assert!(AddrV2Addr::decode(&mut Cursor::new(&buf)).is_err());
    }

    #[test]
    fn addrv2_addr_decode_wrong_length_torv2_rejected() {
        // TorV2 (nid=0x03) expects 10 bytes, give 8.
        let mut buf = vec![0x03, 0x08]; // TorV2, len=8
        buf.extend_from_slice(&[0; 8]);
        assert!(AddrV2Addr::decode(&mut Cursor::new(&buf)).is_err());
    }

    #[test]
    fn addrv2_msg_rejects_oversize_count() {
        // count = 1001 through AddrV2Msg (vs AddrMsg which was already tested).
        let mut bytes = vec![0xfd];
        bytes.extend_from_slice(&1001u16.to_le_bytes());
        let mut cur = std::io::Cursor::new(&bytes);
        assert!(AddrV2Msg::decode_limited(&mut cur).is_err());
    }

    #[test]
    fn addrv2_entry_ip_v4_returns_none_for_non_ipv4() {
        // Build an AddrV2Entry with TorV3 address; ip_v4() must return None.
        let entry = AddrV2Entry {
            time: crate::primitives::BlockTime::new(100),
            services: Services::new(0),
            addr: AddrV2Addr::TorV3([0xab; 32]),
            port: Port::new(8333),
        };
        assert!(entry.ip_v4().is_none());
    }

    #[test]
    fn addrv2_addr_decode_ipv4_directly() {
        // Test the Ipv4 success path through AddrV2Addr::decode directly,
        // verifying bytes are read exactly.
        let buf: &[u8] = &[0x01, 0x04, 10, 20, 30, 40];
        let addr = AddrV2Addr::decode(&mut Cursor::new(buf)).unwrap();
        assert!(matches!(addr, AddrV2Addr::Ipv4([10, 20, 30, 40])));
    }

    #[test]
    fn addrv2_addr_decode_truncated_body_unknown_fails() {
        // Unknown network_id with addr_len=4 but only 2 bytes of data.
        let buf: &[u8] = &[0xfe, 0x04, 0xaa, 0xbb];
        assert!(AddrV2Addr::decode(&mut Cursor::new(buf)).is_err());
    }

    #[test]
    fn addrv2_addr_decode_truncated_body_i2p_fails() {
        // I2p (nid=0x05) expects 32 bytes, provide only 5.
        let mut buf = vec![0x05, 0x20]; // I2p, len=32
        buf.extend_from_slice(&[0xaa; 5]);
        assert!(AddrV2Addr::decode(&mut Cursor::new(&buf)).is_err());
    }

    #[test]
    fn addrv2_addr_decode_truncated_body_cjdns_fails() {
        // Cjdns (nid=0x06) expects 16 bytes, provide only 3.
        let mut buf = vec![0x06, 0x10]; // Cjdns, len=16
        buf.extend_from_slice(&[0xbb; 3]);
        assert!(AddrV2Addr::decode(&mut Cursor::new(&buf)).is_err());
    }

    #[test]
    fn addrv2_addr_decode_truncated_body_ipv6_fails() {
        // Ipv6 (nid=0x02) expects 16 bytes, provide only 8.
        let mut buf = vec![0x02, 0x10]; // Ipv6, len=16
        buf.extend_from_slice(&[0xcc; 8]);
        assert!(AddrV2Addr::decode(&mut Cursor::new(&buf)).is_err());
    }
}
