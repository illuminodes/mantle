use std::fmt;

use mantle::primitives::{BlockHeader, BlockHeight, Hash256};

/// One block to download: its hash, plus the height when the source knew it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockTarget {
    pub hash: Hash256,
    pub height: Option<BlockHeight>,
}

impl BlockTarget {
    const HASH_HEX_LEN: usize = 64;
    const HEADER_HEX_LEN: usize = BlockHeader::ENCODED_LEN * 2;

    /// Parse one token: a 64-hex display-order hash, a 160-hex raw header,
    /// or a saved block file name `<height>-<hash>.block`.
    ///
    /// # Errors
    /// Returns an error if the token is none of those forms.
    pub fn parse(token: &str) -> Result<Self, String> {
        let name = token.rsplit('/').next().unwrap_or(token);
        let name = name.strip_suffix(".block").unwrap_or(name);
        if let Some((height, hash)) = name.split_once('-') {
            let height: u32 = height
                .parse()
                .map_err(|e| format!("invalid height in {token:?}: {e}"))?;
            return Ok(Self {
                hash: Self::parse_hash(hash)?,
                height: Some(BlockHeight::new(height)),
            });
        }
        match name.len() {
            Self::HASH_HEX_LEN => Ok(Self {
                hash: Self::parse_hash(name)?,
                height: None,
            }),
            Self::HEADER_HEX_LEN => Ok(Self {
                hash: Self::parse_header(name)?.hash(),
                height: None,
            }),
            n => Err(format!(
                "{token:?} is {n} characters; expected a 64-hex hash, a 160-hex header, \
                 or <height>-<hash>.block"
            )),
        }
    }

    #[must_use]
    pub const fn with_height(mut self, height: BlockHeight) -> Self {
        self.height = Some(height);
        self
    }

    fn parse_hash(hex: &str) -> Result<Hash256, String> {
        Hash256::from_display_hex(hex).map_err(|e| format!("invalid hash {hex:?}: {e}"))
    }

    fn parse_header(hex: &str) -> Result<BlockHeader, String> {
        let mut bytes = [0u8; BlockHeader::ENCODED_LEN];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| format!("invalid hex in header at offset {}", i * 2))?;
        }
        Ok(BlockHeader::from_slice(&bytes))
    }
}

impl fmt::Display for BlockTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.height {
            Some(h) => write!(f, "{} ({})", self.hash, h.to_u32()),
            None => write!(f, "{}", self.hash),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "000000001052ca40f382b01b9640bf8150e64746ee3346f33679dd8431bb7df0";
    const GENESIS_HEADER: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";

    #[test]
    fn parses_bare_hash() {
        let t = BlockTarget::parse(HASH).expect("parse");
        assert_eq!(t.hash.to_string(), HASH);
        assert_eq!(t.height, None);
    }

    #[test]
    fn parses_saved_block_file_name() {
        let t = BlockTarget::parse(&format!("failed-blocks/0002277-{HASH}.block")).expect("parse");
        assert_eq!(t.hash.to_string(), HASH);
        assert_eq!(t.height, Some(BlockHeight::new(2277)));
    }

    #[test]
    fn parses_raw_header_into_its_hash() {
        let t = BlockTarget::parse(GENESIS_HEADER).expect("parse");
        assert_eq!(
            t.hash.to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(BlockTarget::parse("abcd").is_err());
    }
}
