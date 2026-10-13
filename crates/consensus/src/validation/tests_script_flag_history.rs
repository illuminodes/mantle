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

    const MULTISIG_SIG_IN_REDEEM_SCRIPT: Self = Self {
        block_header: "",
        block_hash: "",
        height: 290_329,
        tx: "0100000002f9cbafc519425637ba4227f8d0a0b7160b4e65168193d5af39747891de98b5b5000000006b4830450221008dd619c563e527c47d9bd53534a770b102e40faa87f61433580e04e271ef2f960220029886434e18122b53d5decd25f1f4acb2480659fea20aabd856987ba3c3907e0121022b78b756e2258af13779c1a1f37ea6800259716ca4b7f0b87610e0bf3ab52a01ffffffff42e7988254800876b69f24676b3e0205b77be476512ca4d970707dd5c60598ab00000000fd260100483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a53034930460221008431bdfa72bc67f9d41fe72e94c88fb8f359ffa30b33c72c121c5a877d922e1002210089ef5fc22dd8bfc6bf9ffdb01a9862d27687d424d1fefbab9e9c7176844a187a014c9052483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a5303210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c7153aeffffffff01a08601000000000017a914d8dacdadb7462ae15cd906f1878706d0da8660e68700000000",
        script_pubkey: "a914d8dacdadb7462ae15cd906f1878706d0da8660e687",
        amount: 100_000,
    };

    fn header_hash(&self) -> Hash256 {
        let bytes: [u8; 80] = decode_hex(self.block_header)
            .try_into()
            .expect("80-byte header");
        BlockHeader::from_bytes(bytes).hash()
    }

    fn verify_first_input(&self, flags: ScriptFlags) -> Result<(), crate::script::ScriptError> {
        self.verify_input(0, flags)
    }

    fn verify_input(
        &self,
        n_in: usize,
        flags: ScriptFlags,
    ) -> Result<(), crate::script::ScriptError> {
        let tx = Transaction::decode(&mut Cursor::new(decode_hex(self.tx))).expect("tx decodes");
        let script_sig = tx.inputs[n_in].script_sig.to_vec();
        verify_script(
            &script_sig,
            &decode_hex(self.script_pubkey),
            &tx,
            n_in,
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
fn checkmultisig_deletes_every_signature_from_the_script_code_before_hashing() {
    let spend = HistoricalSpend::MULTISIG_SIG_IN_REDEEM_SCRIPT;
    assert_eq!(spend.verify_input(1, spend.flags_at_its_height()), Ok(()));
}

#[test]
fn the_taproot_exception_spend_fails_once_taproot_is_enforced() {
    let spend = HistoricalSpend::TAPROOT_EXCEPTION;
    let r = spend.verify_first_input(spend.flags_at_its_height() | ScriptFlags::TAPROOT);
    assert!(r.is_err(), "a v1 program with an empty witness must fail, got {r:?}");
}
