use std::io::Cursor;

use mantle::codec::Decode;
use mantle::primitives::{BlockHeader, BlockHeight, Hash256, Satoshi, Transaction};

use crate::script::{ScriptFlags, verify_script};
use crate::test_helpers::decode_hex;

struct HistoricalSpend {
    block_header: &'static str,
    block_hash: &'static str,
    height: u32,
    tx: &'static str,
    script_pubkey: &'static str,
    amount: u64,
}

impl HistoricalSpend {
    const BIP16_EXCEPTION: Self = Self {
        block_header: "01000000d62ad381b32886ece7e9b98a1d642aa578387fb92491f52bbd030000000000009bd068bf7b83b212f4bd41379c924a2a7c785e371866778a53c93c25ff8696bebf8d574f0c350b1af3c64121",
        block_hash: "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22",
        height: 170_060,
        tx: "0100000001f6ea284ec7521f8a7d094a6cf4e6873098b90f90725ffd372b343189d7a4089c0100000026255121029b6d2c97b8b7c718c325d7be3ac30f7c9d67651bce0c929f55ee77ce58efcf8451aeffffffff0130570500000000001976a9145a3acbc7bbcc97c5ff16f5909c9d7d3fadb293a888ac00000000",
        script_pubkey: "a91419a7d869032368fd1f1e26e5e73a4ad0e474960e87",
        amount: 400_000,
    };

    const TAPROOT_EXCEPTION: Self = Self {
        block_header: "04e0ff375da237f10a988fca56d35ab14199c277fd0f4c7ab167000000000000000000007ac1d6fbe97e8899471097a3de8ca068bd04d52d243ffc72007247e4448dec77b47cfa6024961417403d1911",
        block_hash: "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad",
        height: 692_261,
        tx: "010000000441f1775384e60c9480a773ab1c84cf665204eb67cf3e964ab341bbedc53b3eb50000000000d50768000494ca412154fd498e6946e64b27f5641a1b634f9033a77b996e039efa598ab400000000000cb100009d73094e6bc8c1f5d124f2d2eec2a6f43879476bcc6df2feab99d24b8fc0417601000000000cb10000d61d17a952278701d1cda8a23f44d509b5b2b0a88204ae2568bae077046543fd01000000000cb10000026f6d02000000000017a914fb94f9a556bae3f98f44186e1ccaa4f5ff6a3187870000000000000000136a1168747470733a2f2f623130632e6d652f370cb10000",
        script_pubkey: "51200101010101010101010101010101010101010101010101010101010101010101",
        amount: 5_431,
    };

    fn header_hash(&self) -> Hash256 {
        let bytes: [u8; 80] = decode_hex(self.block_header)
            .try_into()
            .expect("80-byte header");
        BlockHeader::from_bytes(bytes).hash()
    }

    fn verify_first_input(&self, flags: ScriptFlags) -> Result<(), crate::script::ScriptError> {
        let tx = Transaction::decode(&mut Cursor::new(decode_hex(self.tx))).expect("tx decodes");
        let script_sig = tx.inputs[0].script_sig.to_vec();
        verify_script(
            &script_sig,
            &decode_hex(self.script_pubkey),
            &tx,
            0,
            Satoshi::new(self.amount),
            flags,
        )
    }

    fn flags_at_its_height(&self) -> ScriptFlags {
        ScriptFlags::for_height(BlockHeight::new(self.height))
    }
}

#[test]
fn the_fixtures_are_the_blocks_core_lists_as_script_flag_exceptions() {
    for spend in [HistoricalSpend::BIP16_EXCEPTION, HistoricalSpend::TAPROOT_EXCEPTION] {
        assert_eq!(spend.header_hash().to_display_hex(), spend.block_hash);
    }
}

#[test]
fn the_bip16_exception_spend_is_valid_with_the_flags_of_its_height() {
    let spend = HistoricalSpend::BIP16_EXCEPTION;
    assert!(!spend.flags_at_its_height().contains(ScriptFlags::P2SH));
    assert_eq!(spend.verify_first_input(spend.flags_at_its_height()), Ok(()));
}

#[test]
fn the_bip16_exception_spend_fails_once_p2sh_is_enforced() {
    let spend = HistoricalSpend::BIP16_EXCEPTION;
    let r = spend.verify_first_input(spend.flags_at_its_height() | ScriptFlags::P2SH);
    assert!(r.is_err(), "the redeem script has no signature, got {r:?}");
}

#[test]
fn the_taproot_exception_spend_is_valid_with_the_flags_of_its_height() {
    let spend = HistoricalSpend::TAPROOT_EXCEPTION;
    assert!(!spend.flags_at_its_height().contains(ScriptFlags::TAPROOT));
    assert_eq!(spend.verify_first_input(spend.flags_at_its_height()), Ok(()));
}

#[test]
fn the_taproot_exception_spend_fails_once_taproot_is_enforced() {
    let spend = HistoricalSpend::TAPROOT_EXCEPTION;
    let r = spend.verify_first_input(spend.flags_at_its_height() | ScriptFlags::TAPROOT);
    assert!(r.is_err(), "a v1 program with an empty witness must fail, got {r:?}");
}
