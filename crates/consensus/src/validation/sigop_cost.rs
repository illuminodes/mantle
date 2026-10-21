use crate::script::Opcode;
use crate::script::interpreter::reader::ScriptReader;
use crate::script::verify::{is_push_only, witness_program_of};
use crate::tx_view::{InputView, OutputView, TxView, WitnessView};

/// BIP141 signature-operation cost of a block.
///
/// Legacy sigops (from every scriptSig and scriptPubKey) and P2SH redeem
/// script sigops are each weighted by the witness scale factor; witness
/// sigops count once. The limit is 80,000 units, which equals the pre-segwit
/// limit of 20,000 legacy sigops.
pub struct SigopCost;

impl SigopCost {
    pub(super) const MAX_BLOCK_COST: u64 = 80_000;
    pub(super) const WITNESS_SCALE_FACTOR: u64 = 4;
    const MAX_PUBKEYS_PER_MULTISIG: u64 = 20;

    /// Count sigops in `script`. With `accurate`, `OP_CHECKMULTISIG` preceded
    /// by `OP_1`..`OP_16` counts that many keys; otherwise it counts 20.
    /// Counting stops at the first malformed push, as in Core.
    #[must_use]
    pub fn count(script: &[u8], accurate: bool) -> u64 {
        let mut reader = ScriptReader::new(script);
        let mut total = 0u64;
        let mut previous: Option<Opcode> = None;
        while let Ok(Some(step)) = reader.next_step() {
            total += match step.opcode {
                Opcode::CheckSig | Opcode::CheckSigVerify => 1,
                Opcode::CheckMultiSig | Opcode::CheckMultiSigVerify => match previous {
                    Some(Opcode::OpN(n)) if accurate => u64::from(n),
                    _ => Self::MAX_PUBKEYS_PER_MULTISIG,
                },
                _ => 0,
            };
            previous = Some(step.opcode);
        }
        total
    }

    /// Legacy sigops of one transaction, before scaling.
    pub(super) fn legacy<T: TxView>(tx: &T) -> u64 {
        let inputs: u64 = tx
            .inputs()
            .map(|i| Self::count(i.script_sig(), false))
            .sum();
        let outputs: u64 = tx
            .outputs()
            .map(|o| Self::count(o.script_pubkey(), false))
            .sum();
        inputs + outputs
    }

    /// Sigops in the redeem script of a P2SH spend, before scaling.
    pub(super) fn p2sh(script_sig: &[u8], spent_spk: &[u8]) -> u64 {
        Self::redeem_script(script_sig, spent_spk).map_or(0, |redeem| Self::count(redeem, true))
    }

    /// Witness sigops of one input. `spent_spk` is the output being spent.
    pub(super) fn witness<I: InputView>(input: &I, spent_spk: &[u8]) -> u64 {
        if let Some((version, program)) = witness_program_of(spent_spk) {
            return Self::witness_program(version, &program, &input.witness());
        }
        if let Some(redeem) = Self::redeem_script(input.script_sig(), spent_spk)
            && let Some((version, program)) = witness_program_of(redeem)
        {
            return Self::witness_program(version, &program, &input.witness());
        }
        0
    }

    fn witness_program<W: WitnessView>(version: u8, program: &[u8], witness: &W) -> u64 {
        if version != 0 {
            return 0;
        }
        match program.len() {
            20 => 1,
            32 => witness
                .to_vec()
                .last()
                .map_or(0, |script| Self::count(script, true)),
            _ => 0,
        }
    }

    /// The last push of a push-only scriptSig spending a P2SH output.
    fn redeem_script<'a>(script_sig: &'a [u8], spent_spk: &[u8]) -> Option<&'a [u8]> {
        let is_p2sh = spent_spk.len() == 23
            && spent_spk[0] == 0xa9
            && spent_spk[1] == 0x14
            && spent_spk[22] == 0x87;
        if !is_p2sh || !is_push_only(script_sig) {
            return None;
        }
        let mut reader = ScriptReader::new(script_sig);
        let mut last = None;
        while let Ok(Some(step)) = reader.next_step() {
            last = Some(step.data);
        }
        last
    }
}
