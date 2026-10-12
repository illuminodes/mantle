use mantle::primitives::{
    BlockHeader, BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Nonce,
};

use super::bip30::Bip30;
use crate::test_helpers::decode_hex;

const MAINNET_91842_HEADER: &str = "0100000020114beba985ecbf1351bf5f4d5495105dc2ca94f5bdbcac921e0a00000000009985d82954e10f2233a08905dc7b490eb444660c8759e324c7dfa3d28779d2d5f34ee04c56720e1b021838e1";

struct Headers;

impl Headers {
    fn mainnet_91842() -> BlockHeader {
        let bytes: [u8; 80] = decode_hex(MAINNET_91842_HEADER)
            .try_into()
            .expect("80-byte header");
        BlockHeader::from_bytes(bytes)
    }

    fn arbitrary() -> BlockHeader {
        BlockHeader::new(
            BlockVersion::new(1),
            Hash256::ZERO,
            Hash256::ZERO,
            BlockTime::new(0),
            CompactBits::new(0x1d00_ffff),
            Nonce::new(0),
        )
    }
}

#[test]
fn the_historical_duplicate_coinbase_block_is_exempt() {
    let header = Headers::mainnet_91842();
    assert_eq!(
        header.hash().to_display_hex(),
        "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"
    );
    assert!(!Bip30::new(BlockHeight::new(91_842), &header).is_enforced());
}

#[test]
fn the_exemption_needs_both_the_height_and_the_hash() {
    assert!(Bip30::new(BlockHeight::new(91_842), &Headers::arbitrary()).is_enforced());
    assert!(Bip30::new(BlockHeight::new(91_843), &Headers::mainnet_91842()).is_enforced());
}

#[test]
fn bip34_covers_heights_between_its_activation_and_the_repeat_limit() {
    let header = Headers::arbitrary();
    assert!(Bip30::new(BlockHeight::new(227_931), &header).is_enforced());
    assert!(!Bip30::new(BlockHeight::new(227_932), &header).is_enforced());
    assert!(!Bip30::new(BlockHeight::new(1_983_701), &header).is_enforced());
    assert!(Bip30::new(Bip30::BIP34_IMPLIES_BIP30_LIMIT, &header).is_enforced());
}
