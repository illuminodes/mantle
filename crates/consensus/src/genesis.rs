/// Raw bytes of the Bitcoin mainnet genesis block (block 0).
/// Source: Bitcoin Core src/chainparams.cpp, `CreateGenesisBlock()`
pub const GENESIS_BLOCK_HEX: &str = concat!(
    "0100000000000000000000000000000000000000000000000000000000000000",
    "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa",
    "4b1e5e4a29ab5f49ffff001d1dac2b7c01010000000100000000000000000000",
    "00000000000000000000000000000000000000000000ffffffff4d04ffff001d",
    "0104455468652054696d65732030332f4a616e2f32303039204368616e63656c",
    "6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f75742066",
    "6f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe554827",
    "1967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4",
    "f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
);

/// The known genesis block header hash (displayed in reversed byte order).
pub const GENESIS_BLOCK_HASH: &str =
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

/// The known genesis coinbase txid (displayed in reversed byte order).
pub const GENESIS_TXID: &str = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{decode_hex, hash_to_hex};
    use mantle::codec::{Decode, DecodeRef};
    use mantle::hash::Hash256;
    use mantle::primitives::{Block, BlockHeader, BlockVersion, Nonce, TxVersion};
    use std::io::Cursor;

    #[test]
    fn genesis_header_fields() {
        let bytes = decode_hex(GENESIS_BLOCK_HEX);
        let (header, _) =
            BlockHeader::decode_ref(&bytes).expect("genesis block header must decode");

        assert_eq!(header.version(), BlockVersion::new(1));
        assert_eq!(
            header.time(),
            mantle::primitives::BlockTime::new(1_231_006_505)
        );
        assert_eq!(
            header.bits(),
            mantle::primitives::CompactBits::new(0x1d00_ffff)
        );
        assert_eq!(header.nonce(), Nonce::new(2_083_236_893));
        assert_eq!(header.prev_block(), mantle::primitives::Hash256::ZERO);
    }

    #[test]
    fn genesis_header_hash() {
        let bytes = decode_hex(GENESIS_BLOCK_HEX);
        let hash = Hash256::hash(&bytes[..BlockHeader::ENCODED_LEN]);
        assert_eq!(hash_to_hex(*hash.as_bytes()), GENESIS_BLOCK_HASH);
    }

    #[test]
    fn genesis_block_decode() {
        let bytes = decode_hex(GENESIS_BLOCK_HEX);
        let block = Block::decode(&mut Cursor::new(&bytes)).expect("genesis block must decode");

        assert_eq!(block.transactions.len(), 1);
        let tx = &block.transactions[0];
        assert_eq!(tx.version, TxVersion::new(1));
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(
            tx.outputs[0].value,
            mantle::primitives::Satoshi::new(50_0000_0000)
        ); // 50 BTC in satoshis
    }

    #[test]
    fn genesis_txid() {
        use mantle::codec::Encode;
        let bytes = decode_hex(GENESIS_BLOCK_HEX);
        let block = Block::decode(&mut Cursor::new(&bytes)).expect("genesis block must decode");

        let mut tx_bytes = Vec::new();
        block.transactions[0]
            .encode(&mut tx_bytes)
            .expect("Vec<u8> write cannot fail");
        let txid = Hash256::hash(&tx_bytes);
        assert_eq!(hash_to_hex(*txid.as_bytes()), GENESIS_TXID);
    }
}
