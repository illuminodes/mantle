use std::io::{Read, Write};

use crate::codec::{Decode, DecodeRef, Encode, Error as CodecError, VarInt};
use crate::difficulty::BlockHeight;

use super::envelope::{NetworkAddr, PeerNonce, ProtocolVersion, Services, Timestamp};

// ── Message payloads ──────────────────────────────────────────────────────────

/// `version` — sent first on connection establishment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMsg {
    pub version: ProtocolVersion,
    pub services: Services,
    pub timestamp: Timestamp,
    pub receiver: NetworkAddr,
    pub sender: NetworkAddr,
    pub nonce: PeerNonce,
    pub user_agent: String,
    pub start_height: BlockHeight,
    pub relay: bool,
}

impl Encode for VersionMsg {
    fn encode(&self, w: &mut impl Write) -> Result<(), CodecError> {
        self.version.encode(w)?;
        self.services.encode(w)?;
        self.timestamp.encode(w)?;
        self.receiver.encode(w)?;
        self.sender.encode(w)?;
        self.nonce.encode(w)?;
        self.user_agent.encode(w)?;
        i32::from_ne_bytes(self.start_height.to_u32().to_ne_bytes()).encode(w)?;
        u8::from(self.relay).encode(w)
    }
}

impl Decode for VersionMsg {
    fn decode(r: &mut impl Read) -> Result<Self, CodecError> {
        Ok(Self {
            version: ProtocolVersion::decode(r)?,
            services: Services::decode(r)?,
            timestamp: Timestamp::decode(r)?,
            receiver: NetworkAddr::decode(r)?,
            sender: NetworkAddr::decode(r)?,
            nonce: PeerNonce::decode(r)?,
            user_agent: VarInt::decode_string_limited::<256>(r)?,
            start_height: BlockHeight::new(u32::from_ne_bytes(i32::decode(r)?.to_ne_bytes())),
            relay: u8::decode(r)? != 0,
        })
    }
}

/// Zero-copy borrowed view of a `VersionMsg` — `user_agent` is a `&str` into
/// the source buffer instead of an owned `String`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionMsgRef<'a> {
    pub version: ProtocolVersion,
    pub services: Services,
    pub timestamp: Timestamp,
    pub receiver: NetworkAddr,
    pub sender: NetworkAddr,
    pub nonce: PeerNonce,
    pub user_agent: &'a str,
    pub start_height: BlockHeight,
    pub relay: bool,
}

impl<'a> DecodeRef<'a> for VersionMsgRef<'a> {
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), CodecError> {
        let (version, buf) = ProtocolVersion::decode_ref(buf)?;
        let (services, buf) = Services::decode_ref(buf)?;
        let (timestamp, buf) = Timestamp::decode_ref(buf)?;
        let (receiver, buf) = NetworkAddr::decode_ref(buf)?;
        let (sender, buf) = NetworkAddr::decode_ref(buf)?;
        let (nonce, buf) = PeerNonce::decode_ref(buf)?;
        let (user_agent, buf) = <&'a str>::decode_ref(buf)?;
        let (start_height_raw, buf) = i32::decode_ref(buf)?;
        let (relay_byte, buf) = u8::decode_ref(buf)?;
        Ok((
            Self {
                version,
                services,
                timestamp,
                receiver,
                sender,
                nonce,
                user_agent,
                start_height: BlockHeight::new(u32::from_ne_bytes(start_height_raw.to_ne_bytes())),
                relay: relay_byte != 0,
            },
            buf,
        ))
    }
}

impl VersionMsgRef<'_> {
    /// Materialise into an owned `VersionMsg`.
    #[must_use]
    pub fn to_owned(self) -> VersionMsg {
        VersionMsg {
            version: self.version,
            services: self.services,
            timestamp: self.timestamp,
            receiver: self.receiver,
            sender: self.sender,
            nonce: self.nonce,
            user_agent: self.user_agent.to_string(),
            start_height: self.start_height,
            relay: self.relay,
        }
    }
}

/// `ping` / `pong` — keepalive with a nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingMsg {
    pub nonce: PeerNonce,
}

impl Encode for PingMsg {
    fn encode(&self, w: &mut impl Write) -> Result<(), CodecError> {
        self.nonce.encode(w)
    }
}

impl Decode for PingMsg {
    fn decode(r: &mut impl Read) -> Result<Self, CodecError> {
        Ok(Self {
            nonce: PeerNonce::decode(r)?,
        })
    }
}

// pong has identical wire format
pub type PongMsg = PingMsg;

#[cfg(test)]
mod tests {
    use super::super::envelope::Port;
    use super::*;
    use std::io::Cursor;

    fn encode<T: Encode>(val: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        val.encode(&mut buf).expect("Vec<u8> write cannot fail");
        buf
    }

    fn decode<T: Decode>(bytes: &[u8]) -> T {
        T::decode(&mut Cursor::new(bytes)).expect("test data must decode")
    }

    fn decode_err<T: Decode + std::fmt::Debug>(bytes: &[u8]) -> CodecError {
        T::decode(&mut std::io::Cursor::new(bytes)).unwrap_err()
    }

    #[test]
    fn version_msg_roundtrip() {
        let msg = VersionMsg {
            version: ProtocolVersion::CURRENT,
            services: Services::NODE_NETWORK,
            timestamp: Timestamp::new(1_700_000_000),
            receiver: NetworkAddr {
                services: Services::NONE,
                ip: [0u8; 16],
                port: Port::MAINNET,
            },
            sender: NetworkAddr {
                services: Services::NODE_NETWORK,
                ip: [0u8; 16],
                port: Port::MAINNET,
            },
            nonce: PeerNonce::new(0xdead_beef),
            user_agent: "/mantle:0.1.0/".to_string(),
            start_height: BlockHeight::ZERO,
            relay: true,
        };
        let bytes = encode(&msg);
        assert_eq!(decode::<VersionMsg>(&bytes), msg);
    }

    #[test]
    fn version_msg_extreme_fields() {
        let addr = NetworkAddr {
            services: Services::NONE,
            ip: [0u8; 16],
            port: Port::new(0),
        };
        let msg = VersionMsg {
            version: ProtocolVersion::new(u32::MAX),
            services: Services::new(u64::MAX),
            timestamp: Timestamp::new(i64::MIN),
            receiver: addr,
            sender: addr,
            nonce: PeerNonce::new(u64::MAX),
            user_agent: String::new(),
            start_height: BlockHeight::new(u32::MAX),
            relay: false,
        };
        let bytes = encode(&msg);
        assert_eq!(decode::<VersionMsg>(&bytes), msg);
    }

    #[test]
    fn version_msg_invalid_utf8_user_agent() {
        let addr = NetworkAddr {
            services: Services::NONE,
            ip: [0u8; 16],
            port: Port::new(0),
        };
        let good = VersionMsg {
            version: ProtocolVersion::CURRENT,
            services: Services::NONE,
            timestamp: Timestamp::new(0),
            receiver: addr,
            sender: addr,
            nonce: PeerNonce::new(0),
            user_agent: "ok".to_string(),
            start_height: BlockHeight::ZERO,
            relay: false,
        };
        let mut bytes = encode(&good);
        // Fixed prefix: 4+8+8+26+26+8 = 80 bytes, then VarInt(2) at byte 80.
        let ua_offset = 80;
        bytes[ua_offset + 1] = 0xff;
        bytes[ua_offset + 2] = 0xfe;
        let e = decode_err::<VersionMsg>(&bytes);
        assert!(matches!(e, CodecError::InvalidUtf8(_) | CodecError::Io(_)));
    }

    #[test]
    fn ping_roundtrip() {
        let ping = PingMsg {
            nonce: PeerNonce::new(0xdead_beef_cafe),
        };
        let bytes = encode(&ping);
        assert_eq!(decode::<PingMsg>(&bytes), ping);
    }

    #[test]
    fn ping_zero_nonce() {
        let ping = PingMsg {
            nonce: PeerNonce::new(0),
        };
        let bytes = encode(&ping);
        assert_eq!(decode::<PingMsg>(&bytes), ping);
    }

    #[test]
    fn ping_max_nonce() {
        let ping = PingMsg {
            nonce: PeerNonce::new(u64::MAX),
        };
        let bytes = encode(&ping);
        assert_eq!(decode::<PingMsg>(&bytes), ping);
    }

    #[test]
    fn ping_truncated() {
        let e = decode_err::<PingMsg>(&[0x00; 4]);
        assert!(matches!(e, CodecError::UnexpectedEof | CodecError::Io(_)));
    }

    // ── VersionMsgRef ────────────────────────────────────────────────────────

    fn decode_ref<'a, T: DecodeRef<'a>>(buf: &'a [u8]) -> (T, &'a [u8]) {
        T::decode_ref(buf).expect("test data must decode")
    }

    #[test]
    fn version_msg_ref_roundtrip() {
        let msg = VersionMsg {
            version: ProtocolVersion::CURRENT,
            services: Services::NODE_NETWORK,
            timestamp: Timestamp::new(1_700_000_000),
            receiver: NetworkAddr {
                services: Services::NONE,
                ip: [0u8; 16],
                port: Port::MAINNET,
            },
            sender: NetworkAddr {
                services: Services::NODE_NETWORK,
                ip: [0u8; 16],
                port: Port::MAINNET,
            },
            nonce: PeerNonce::new(0xdead_beef),
            user_agent: "/mantle:0.1.0/".to_string(),
            start_height: BlockHeight::new(800_000),
            relay: true,
        };
        let bytes = encode(&msg);
        let (msg_ref, tail) = decode_ref::<VersionMsgRef>(&bytes);
        assert!(tail.is_empty());
        assert_eq!(msg_ref.version, msg.version);
        assert_eq!(msg_ref.services, msg.services);
        assert_eq!(msg_ref.timestamp, msg.timestamp);
        assert_eq!(msg_ref.nonce, msg.nonce);
        assert_eq!(msg_ref.user_agent, "/mantle:0.1.0/");
        assert_eq!(msg_ref.start_height, msg.start_height);
        assert!(msg_ref.relay);
    }

    #[test]
    fn version_msg_ref_to_owned_matches_original() {
        let msg = VersionMsg {
            version: ProtocolVersion::CURRENT,
            services: Services::NONE,
            timestamp: Timestamp::new(0),
            receiver: NetworkAddr {
                services: Services::NONE,
                ip: [0u8; 16],
                port: Port::new(0),
            },
            sender: NetworkAddr {
                services: Services::NONE,
                ip: [0u8; 16],
                port: Port::new(0),
            },
            nonce: PeerNonce::new(0),
            user_agent: "test".to_string(),
            start_height: BlockHeight::ZERO,
            relay: false,
        };
        let bytes = encode(&msg);
        let (msg_ref, _) = decode_ref::<VersionMsgRef>(&bytes);
        assert_eq!(msg_ref.to_owned(), msg);
    }

    #[test]
    fn version_msg_ref_user_agent_zero_copy() {
        let msg = VersionMsg {
            version: ProtocolVersion::CURRENT,
            services: Services::NONE,
            timestamp: Timestamp::new(0),
            receiver: NetworkAddr {
                services: Services::NONE,
                ip: [0u8; 16],
                port: Port::new(0),
            },
            sender: NetworkAddr {
                services: Services::NONE,
                ip: [0u8; 16],
                port: Port::new(0),
            },
            nonce: PeerNonce::new(0),
            user_agent: "/mantle/".to_string(),
            start_height: BlockHeight::ZERO,
            relay: false,
        };
        let bytes = encode(&msg);
        let (msg_ref, _) = decode_ref::<VersionMsgRef>(&bytes);
        let ua_ptr = msg_ref.user_agent.as_ptr() as usize;
        let buf_start = bytes.as_ptr() as usize;
        let buf_end = buf_start + bytes.len();
        assert!(
            ua_ptr >= buf_start && ua_ptr < buf_end,
            "user_agent must borrow from the input buffer"
        );
    }

    #[test]
    fn version_msg_ref_truncated_fails() {
        let msg = VersionMsg {
            version: ProtocolVersion::CURRENT,
            services: Services::NONE,
            timestamp: Timestamp::new(0),
            receiver: NetworkAddr {
                services: Services::NONE,
                ip: [0u8; 16],
                port: Port::new(0),
            },
            sender: NetworkAddr {
                services: Services::NONE,
                ip: [0u8; 16],
                port: Port::new(0),
            },
            nonce: PeerNonce::new(0),
            user_agent: "ok".to_string(),
            start_height: BlockHeight::ZERO,
            relay: false,
        };
        let bytes = encode(&msg);
        let truncated = &bytes[..bytes.len() / 2];
        assert!(VersionMsgRef::decode_ref(truncated).is_err());
    }

    #[test]
    fn version_msg_truncated_after_services() {
        let e = decode_err::<VersionMsg>(&[0u8; 12]);
        assert!(matches!(e, CodecError::UnexpectedEof | CodecError::Io(_)));
    }
}
