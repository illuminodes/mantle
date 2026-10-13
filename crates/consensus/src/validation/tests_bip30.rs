use std::io::Cursor;

use mantle::codec::Decode;
use mantle::primitives::{
    Block, BlockHeader, BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Nonce,
    OutPoint, Satoshi, TxHash,
};

use super::bip30::Bip30;
use super::connect::connect_block;
use crate::chain_view::{Coin, ConnectScratch, MemoryChainView};
use crate::error::ValidationError;
use crate::test_helpers::decode_hex;

const MAINNET_91842_HEADER: &str = "0100000020114beba985ecbf1351bf5f4d5495105dc2ca94f5bdbcac921e0a00000000009985d82954e10f2233a08905dc7b490eb444660c8759e324c7dfa3d28779d2d5f34ee04c56720e1b021838e1";
const MAINNET_91842_COINBASE: &str = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff060456720e1b00ffffffff0100f2052a010000004341046896ecfc449cb8560594eb7f413f199deb9b4e5d947a142e7dc7d2de0b811b8e204833ea2a2fd9d4c7b153a8ca7661d0a0b7fc981df1f42f55d64b26b3da1e9cac00000000";
const DUPLICATED_COINBASE_TXID: &str =
    "d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599";

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

struct Mainnet91842;

impl Mainnet91842 {
    fn block() -> Block {
        let mut bytes = decode_hex(MAINNET_91842_HEADER);
        bytes.push(0x01);
        bytes.extend(decode_hex(MAINNET_91842_COINBASE));
        Block::decode(&mut Cursor::new(bytes)).expect("mainnet block 91842 decodes")
    }

    fn view_with_block_91812_coinbase_unspent() -> MemoryChainView {
        let mut view = MemoryChainView::new();
        view.insert_coin(
            OutPoint {
                txid: Hash256::from_display_hex(DUPLICATED_COINBASE_TXID).expect("txid hex"),
                vout: 0,
            },
            Coin {
                value: Satoshi::new(5_000_000_000),
                script_pubkey: vec![0xac].into(),
                height: BlockHeight::new(91_812),
                coinbase: true,
            },
        );
        view
    }

    fn connect(height: u32) -> Result<(), ValidationError> {
        let block = Self::block();
        let view = Self::view_with_block_91812_coinbase_unspent();
        connect_block(
            &block,
            BlockHeight::new(height),
            &view,
            &mut Vec::new(),
            &mut ConnectScratch::new(),
            &mut super::SkippedScripts,
            None,
        )
        .map(|_| ())
    }
}

#[test]
fn mainnet_block_91842_repeats_the_coinbase_txid_of_block_91812() {
    let block = Mainnet91842::block();
    assert_eq!(
        block.transactions[0].txid().expect("txid").to_display_hex(),
        DUPLICATED_COINBASE_TXID
    );
}

#[test]
fn mainnet_block_91842_connects_over_the_unspent_duplicate_at_its_own_height() {
    assert_eq!(Mainnet91842::connect(91_842), Ok(()));
}

#[test]
fn mainnet_block_91842_is_a_bip30_violation_at_any_other_height() {
    assert_eq!(
        Mainnet91842::connect(91_843),
        Err(ValidationError::Bip30Violation { tx_index: 0 })
    );
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
