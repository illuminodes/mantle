//! BIP342 pre-execution scan of a tapscript.

use crate::script::error::ScriptError;
use crate::script::interpreter::reader::ScriptReader;

/// Outcome of decoding a whole tapscript before it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TapscriptScan {
    /// The script contains an `OP_SUCCESSx` opcode, so the spend succeeds
    /// without executing it and without stack or size limits.
    HasOpSuccess,
    /// Every opcode decoded and none is `OP_SUCCESSx`; run the script.
    Executable,
}

impl TapscriptScan {
    /// Decode `script` opcode by opcode. A push running past the end before
    /// any `OP_SUCCESSx` is reached is `BadOpcode`.
    ///
    /// # Errors
    /// `BadOpcode` for a truncated push that precedes every `OP_SUCCESSx`.
    pub fn of(script: &[u8]) -> Result<Self, ScriptError> {
        let mut reader = ScriptReader::new(script);
        loop {
            match reader.next_step() {
                Ok(None) => return Ok(Self::Executable),
                Ok(Some(step)) if step.opcode.is_tapscript_success() => {
                    return Ok(Self::HasOpSuccess);
                }
                Ok(Some(_)) => {}
                Err(_) => return Err(ScriptError::BadOpcode),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_success_anywhere_succeeds_even_in_a_dead_branch() {
        assert_eq!(
            TapscriptScan::of(&[0x00, 0x63, 0x50, 0x68]),
            Ok(TapscriptScan::HasOpSuccess)
        );
        assert_eq!(
            TapscriptScan::of(&[0x6a, 0xbb]),
            Ok(TapscriptScan::HasOpSuccess)
        );
    }

    #[test]
    fn op_success_inside_push_data_does_not_count() {
        assert_eq!(
            TapscriptScan::of(&[0x01, 0x50, 0x51]),
            Ok(TapscriptScan::Executable)
        );
    }

    #[test]
    fn a_truncated_push_fails_only_if_it_comes_first() {
        assert_eq!(
            TapscriptScan::of(&[0x51, 0x05, 0x01]),
            Err(ScriptError::BadOpcode)
        );
        assert_eq!(
            TapscriptScan::of(&[0xbb, 0x05, 0x01]),
            Ok(TapscriptScan::HasOpSuccess)
        );
    }

    #[test]
    fn checksigadd_is_not_op_success() {
        assert_eq!(TapscriptScan::of(&[0xba]), Ok(TapscriptScan::Executable));
    }
}
