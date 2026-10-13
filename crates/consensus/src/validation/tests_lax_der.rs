use std::io::Cursor;

use mantle::codec::Decode;
use mantle::primitives::{BlockHeight, Satoshi, Transaction};

use crate::script::{ScriptError, ScriptFlags, verify_script};
use crate::test_helpers::decode_hex;

struct PaddedDerSpend;

impl PaddedDerSpend {
    const HEIGHT: u32 = 124_276;
    const TX: &'static str = "01000000012316aac445c13ff31af5f3d1e2cebcada83e54ba10d15e01f49ec28bddc285aa000000008e4b3048022200002b83d59c1d23c08efd82ee0662fec23309c3adbcbd1f0b8695378db4b14e736602220000334a96676e58b1bb01784cb7c556dd8ce1c220171904da22e18fe1e7d1510db5014104d0fe07ff74c9ef5b00fed1104fad43ecf72dbab9e60733e4f56eacf24b20cf3b8cd945bcabcc73ba0158bf9ce769d43e94bd58c5c7e331a188922b3fe9ca1f5affffffff01c0c62d00000000001976a9147a2a3b481ca80c4ba7939c54d9278e50189d94f988ac00000000";
    const SCRIPT_PUBKEY: &'static str = "76a9147a2a3b481ca80c4ba7939c54d9278e50189d94f988ac";
    const AMOUNT: u64 = 3_000_000;

    fn verify(flags: ScriptFlags) -> Result<(), ScriptError> {
        let tx = Transaction::decode(&mut Cursor::new(decode_hex(Self::TX))).expect("tx decodes");
        let script_sig = tx.inputs[0].script_sig.to_vec();
        verify_script(
            &script_sig,
            &decode_hex(Self::SCRIPT_PUBKEY),
            &tx,
            0,
            Satoshi::new(Self::AMOUNT),
            flags,
        )
    }

    fn flags_at_its_height() -> ScriptFlags {
        ScriptFlags::for_height(BlockHeight::new(Self::HEIGHT))
    }
}

#[test]
fn a_signature_with_padded_der_integers_is_valid_before_bip66() {
    assert!(!PaddedDerSpend::flags_at_its_height().contains(ScriptFlags::DERSIG));
    assert_eq!(PaddedDerSpend::verify(PaddedDerSpend::flags_at_its_height()), Ok(()));
}

#[test]
fn the_same_signature_fails_once_bip66_is_enforced() {
    let r = PaddedDerSpend::verify(PaddedDerSpend::flags_at_its_height() | ScriptFlags::DERSIG);
    assert_eq!(r, Err(ScriptError::SigDer));
}
