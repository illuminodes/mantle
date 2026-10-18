//! Pre-execution stateless checks on a script.
//!
//! Originally a full second walk of the script body (rejecting `OP_VERIF` /
//! `OP_VERNOTIF` and the legacy disabled opcode set everywhere they appear,
//! including in unexecuted `OP_IF` branches). The walk consumed ~30% of
//! NOP-script eval time per the bench analysis.
//!
//! That work now lives inline in `Interpreter::step`, which checks the
//! always-fail opcode set *before* the executing-branch skip. This
//! function is now O(1) — it only enforces the script-size cap.
//!
//! See [`Interpreter::step`] for the always-fail opcode rules.

use crate::script::error::ScriptError;
use crate::script::sig_version::SigVersion;

/// Maximum script length, in bytes (`MAX_SCRIPT_SIZE`).
pub const MAX_SCRIPT_SIZE: usize = 10_000;

/// Run pre-execution checks. O(1).
///
/// # Errors
/// `ScriptSize` if a legacy or segwit-v0 script exceeds 10000 bytes.
/// Tapscript has no size limit (BIP342).
#[inline]
pub fn pre_scan(script: &[u8], sig_version: SigVersion) -> Result<(), ScriptError> {
    if sig_version != SigVersion::Tapscript && script.len() > MAX_SCRIPT_SIZE {
        return Err(ScriptError::ScriptSize);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_script_passes() {
        assert!(pre_scan(&[], SigVersion::Base).is_ok());
    }

    #[test]
    fn size_cap() {
        let too_long = vec![0x00u8; MAX_SCRIPT_SIZE + 1];
        assert!(matches!(
            pre_scan(&too_long, SigVersion::Base),
            Err(ScriptError::ScriptSize)
        ));
        let ok = vec![0x00u8; MAX_SCRIPT_SIZE];
        assert!(pre_scan(&ok, SigVersion::Base).is_ok());
    }

    #[test]
    fn tapscript_has_no_size_cap() {
        let long = vec![0x61u8; MAX_SCRIPT_SIZE * 13];
        assert!(pre_scan(&long, SigVersion::Tapscript).is_ok());
        assert!(matches!(
            pre_scan(&long, SigVersion::WitnessV0),
            Err(ScriptError::ScriptSize)
        ));
    }

    #[test]
    fn long_well_formed_script_passes() {
        // 9000 bytes of OP_NOP — under cap.
        let script = vec![0x61u8; 9000];
        assert!(pre_scan(&script, SigVersion::Base).is_ok());
    }
}
