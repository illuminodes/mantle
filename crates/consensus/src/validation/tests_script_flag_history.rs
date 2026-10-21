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

    const TAPSCRIPT_INSCRIPTION: Self = Self {
        block_header: "",
        block_hash: "",
        height: 782_339,
        tx: "0100000000010121c3c94fae6a42f69653bc9fdceb74a26f9d69888a53fcedbaa2070a8c41220a0000000000fdffffff018813000000000000225120986092cbd1b7d7a41c3b9e9d34feb18da8a2fabfa495545c2a296e9bbc267ffe0340b1c01c2b10fc0bf6a9084c31b29e99dc46d39f01ce08d8707c6efd57c2f6ca82da02a04700019502773a445d0256dca8eefc00fec1091fb477b07524a25ded7bfdbe04204ec0da0ff89b98c9bdbc25945dc361f5f15ff5aa5b735c8aa788e2f793976bf9ac0063036f7264010109696d6167652f706e67004d080289504e470d0a1a0a0000000d494844520000002a0000002a08020000004aa15e0c0000044749444154789cc5565f4c536714ff614adc13b1adfc9129a2a3745253c8f8d3e8838ace41d63d94644b5c83b6488d0931cb743c14b2179305fb009318750fb08c6e04dd2483074ce824c27c41201a6b840446d055341b265dc2e358c61e8e1e2edffd7a6fefedc37ee9c3bde73bdff99df33be7fb6eb3feb9fd1bfe3f6cc964b335d46d0d756712c192097745d35500d6d0b9bf7a3f3717c464f5d650f7ea44f6d2d8372f1f4ce7b94f99d62023f1132dd14cb69ba427d9ff9d9c2cba1e00505859635a00f3d5137786304ccf5d571a4d0b60a6fa43d1cbcad7970fa64d0431434f5de7d2977f58e0a5c52b374c0890d1e4977cf6293ddc0b9ca70c8c463040cfa5275aa2c291a33c0e452f1b15c0f0ad9768894a675e188834916ef542d7d5a001347a040cf7bee87a402dbe6964a5f3c19596fe96b552702bacaca1877b81f33947d6d2f90e6534f90c9a79d29f4e419ad0a7570e3c1ba5934fa0194c7302f4c5b786ba7376b9982ffdab7ef5f9acaefe3af419fe9901a09d81163d73e7b94fe9d2f0dc311e7d774e3703093db356345da5695a79fcbd2ebd1a947461658d461e22bd546df7f65f00788e7d80f57536be57e106301cfd962dbe403380878f1ed36bcf4f59ea5042061bf44c9cb3cb450fd9892fdfceb503d861dfe60b86b0be7ebbb54d08029d777a3b3bea8e1f05d015be00e08bc8d7006277eeb2cf8bbfd7aa4e9ffcf9c79b6b455f9165f5f9ac9084ce9dbfc3be0d007347ca3dbc146e6d476747ddf1a344ccdc9b7cfa6f225b2bfe063d67c432d881d7dc801037ff843b02845bdbebe2f7d928f7894f8da88a96d0abf32869967cbf6be6e7fe587e9638f6a1464d828fc6e4a714bfa4d953f5ee3bd2a5829dc5d3ce327ebde53baceb63985e8dfc136e00bfc3bd618a4fddf21daeaddab2dbe9c9de5f8cb61b521f8d98fa77fe705f2f006fd7a5a6b69ead67225bcf44c8ded4d6e3edec60b7b527cfc828f84ca6397a9bac5e4771814d307abb2ef9b7dbf9f54afc3e8018307eed622da6763b3d6454faf42e3e71eddb6ff13a52ddad925bcfe27500282eb0297b4ff35ff77ead3a44ecceddd56b17017c32fcabb83436de183c0b2015bd28bec5eba86ff0abfda805b1b1f1d8d8b8b044978fc04d9eb4abbec14f25a92117bfb4ac7c612eaeacbe64673ec5f20543948152092537ad92f3e0c44c6959b99482b0497c2a7d69fef52db13017fff84835d3d3c3e2f29f78d30b298898fc23fd2344bfd7e91a1d1a90345a23b5d2b2f2c18919009c04c7250e293851e6d680e4e05d08b729330030383113e91f113852fdb4030a10c5577bf0248e0e0d0008377ea45d10414897a0165ffe6fc7e275e4e5ee5979f554390a7b9d2e4e82a1ec0b758a931e1d1ac8cbdd0360e5d55303e71e6f4c70645072339449d86cb66432c94b369b0d403299a48d346e748852d1a71c3d81bb3118ecefeb034046ea0827413e940a6f3c78a01a2ab50448464f387e8dc12000e2a6674a62697eb6bec15fdfe027562a9a36f2968307aaa59718e33f0578093c44c869530000000049454e44ae4260826821c14ec0da0ff89b98c9bdbc25945dc361f5f15ff5aa5b735c8aa788e2f793976bf900000000",
        script_pubkey: "5120709f6485132b905bf7cfe0eaafd76647cdec5fc186922315a5ad6dab00b12cc8",
        amount: 19_840,
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
    for spend in [
        HistoricalSpend::BIP16_EXCEPTION,
        HistoricalSpend::TAPROOT_EXCEPTION,
    ] {
        assert_eq!(spend.header_hash().to_display_hex(), spend.block_hash);
    }
}

#[test]
fn the_bip16_exception_spend_is_valid_with_the_flags_of_its_height() {
    let spend = HistoricalSpend::BIP16_EXCEPTION;
    assert!(!spend.flags_at_its_height().contains(ScriptFlags::P2SH));
    assert_eq!(
        spend.verify_first_input(spend.flags_at_its_height()),
        Ok(())
    );
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
    assert_eq!(
        spend.verify_first_input(spend.flags_at_its_height()),
        Ok(())
    );
}

#[test]
fn a_tapscript_checksig_signs_the_key_version_byte() {
    let spend = HistoricalSpend::TAPSCRIPT_INSCRIPTION;
    assert!(spend.flags_at_its_height().contains(ScriptFlags::TAPROOT));
    assert_eq!(
        spend.verify_first_input(spend.flags_at_its_height()),
        Ok(())
    );
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
    assert!(
        r.is_err(),
        "a v1 program with an empty witness must fail, got {r:?}"
    );
}
