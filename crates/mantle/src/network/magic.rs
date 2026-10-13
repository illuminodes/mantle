use std::io::{Read, Write};

use crate::codec::{Decode, DecodeRef, Encode, Error as CodecError};

use super::command::Command;
use super::envelope::encode_message;

// ── Magic bytes ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Magic {
    Mainnet,
    Testnet3,
    Testnet4,
    Signet,
    Regtest,
    /// A 4-byte magic value that does not match any known network.
    Unknown([u8; 4]),
}

impl Magic {
    #[must_use]
    pub fn bytes(self) -> [u8; 4] {
        match self {
            Self::Mainnet => [0xf9, 0xbe, 0xb4, 0xd9],
            Self::Testnet3 => [0x0b, 0x11, 0x09, 0x07],
            Self::Testnet4 => [0x1c, 0x16, 0x3f, 0x28],
            Self::Signet => [0x0a, 0x03, 0xcf, 0x40],
            Self::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
            Self::Unknown(b) => b,
        }
    }

    /// Classify a 4-byte magic value. Returns `Magic::Unknown` if the bytes
    /// don't match any known network.
    #[must_use]
    pub fn classify(b: [u8; 4]) -> Self {
        match b {
            [0xf9, 0xbe, 0xb4, 0xd9] => Self::Mainnet,
            [0x0b, 0x11, 0x09, 0x07] => Self::Testnet3,
            [0x1c, 0x16, 0x3f, 0x28] => Self::Testnet4,
            [0x0a, 0x03, 0xcf, 0x40] => Self::Signet,
            [0xfa, 0xbf, 0xb5, 0xda] => Self::Regtest,
            other => Self::Unknown(other),
        }
    }

    /// Returns `Some(self)` if the magic is a known network, else `None`.
    #[must_use]
    pub fn from_bytes(b: [u8; 4]) -> Option<Self> {
        match Self::classify(b) {
            Self::Unknown(_) => None,
            known => Some(known),
        }
    }

    /// Frame a P2P message: writes a 24-byte header plus payload to `w`.
    ///
    /// # Errors
    /// Returns `InvalidData` if the payload exceeds `u32::MAX` bytes, or any
    /// I/O error from writing to `w`.
    pub fn frame(
        self,
        command: Command,
        payload: &[u8],
        w: &mut impl Write,
    ) -> Result<(), CodecError> {
        encode_message(self, command, payload, w)
    }
}

impl Encode for Magic {
    #[inline]
    fn encode(&self, w: &mut impl Write) -> Result<(), CodecError> {
        w.write_all(&self.bytes()).map_err(CodecError::Io)
    }
}

impl Decode for Magic {
    #[inline]
    fn decode(r: &mut impl Read) -> Result<Self, CodecError> {
        Ok(Self::classify(<[u8; 4]>::decode(r)?))
    }
}

impl<'a> DecodeRef<'a> for Magic {
    #[inline]
    fn decode_ref(buf: &'a [u8]) -> Result<(Self, &'a [u8]), CodecError> {
        let (b, tail) = <[u8; 4]>::decode_ref(buf)?;
        Ok((Self::classify(b), tail))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_roundtrip() {
        for m in [
            Magic::Mainnet,
            Magic::Testnet3,
            Magic::Testnet4,
            Magic::Signet,
        ] {
            assert_eq!(Magic::from_bytes(m.bytes()), Some(m));
        }
    }

    #[test]
    fn magic_unknown_bytes() {
        assert_eq!(Magic::from_bytes([0x00, 0x00, 0x00, 0x00]), None);
        assert_eq!(Magic::from_bytes([0xff, 0xff, 0xff, 0xff]), None);
    }
}
