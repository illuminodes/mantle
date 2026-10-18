//! The scriptSig shape BIP141 requires for P2SH-wrapped witness programs.

use crate::script::interpreter::reader::ScriptReader;

/// The single push of a P2SH redeem script, serialized the way a script
/// builder writes a byte vector: the shortest push opcode for its length.
pub struct RedeemPush;

impl RedeemPush {
    /// `true` if `script_sig` is one push of some data, encoded with the
    /// shortest push opcode for that data's length, and nothing else.
    #[must_use]
    pub fn is_sole_canonical_push(script_sig: &[u8]) -> bool {
        let mut reader = ScriptReader::new(script_sig);
        let Ok(Some(step)) = reader.next_step() else {
            return false;
        };
        if !matches!(reader.next_step(), Ok(None)) || !step.opcode.is_push() {
            return false;
        }
        script_sig == Self::encode(step.data).as_slice()
    }

    /// Shortest push of `data`.
    #[must_use]
    pub fn encode(data: &[u8]) -> Vec<u8> {
        let len = data.len();
        let mut out = Vec::with_capacity(len + 5);
        match len {
            0..=0x4b => out.push(u8::try_from(len).expect("fits")),
            0x4c..=0xff => {
                out.push(0x4c);
                out.push(u8::try_from(len).expect("fits"));
            }
            0x100..=0xffff => {
                out.push(0x4d);
                out.extend_from_slice(&u16::try_from(len).expect("fits").to_le_bytes());
            }
            _ => {
                out.push(0x4e);
                out.extend_from_slice(&u32::try_from(len).unwrap_or(u32::MAX).to_le_bytes());
            }
        }
        out.extend_from_slice(data);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_direct_push_of_a_witness_program_is_canonical() {
        let mut sig = vec![0x16, 0x00, 0x14];
        sig.extend_from_slice(&[7; 20]);
        assert!(RedeemPush::is_sole_canonical_push(&sig));
    }

    #[test]
    fn a_pushdata1_of_a_short_redeem_is_not_canonical() {
        let mut sig = vec![0x4c, 0x16, 0x00, 0x14];
        sig.extend_from_slice(&[7; 20]);
        assert!(!RedeemPush::is_sole_canonical_push(&sig));
    }

    #[test]
    fn extra_pushes_are_refused() {
        let mut sig = vec![0x00, 0x16, 0x00, 0x14];
        sig.extend_from_slice(&[7; 20]);
        assert!(!RedeemPush::is_sole_canonical_push(&sig));
    }

    #[test]
    fn op_n_is_not_a_push_of_bytes() {
        assert!(!RedeemPush::is_sole_canonical_push(&[0x51]));
        assert!(RedeemPush::is_sole_canonical_push(&[0x01, 0x01]));
    }
}
