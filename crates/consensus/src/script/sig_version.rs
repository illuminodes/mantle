//! Signature-version selector for the script interpreter.
//!
//! Three sighash regimes coexist on mainnet today:
//! - `Base` — pre-segwit legacy. `OP_CODESEPARATOR` mutates the scriptCode
//!   for subsequent `OP_CHECKSIG` calls; `FindAndDelete` runs.
//! - `WitnessV0` — BIP143. New sighash preimage; no `FindAndDelete`.
//! - `Tapscript` — BIP341/342. New sighash, x-only pubkeys, Schnorr,
//!   `OP_CODESEPARATOR` semantics differ.
//!
//! M1 ships only `Base`. The other variants exist as variants so the
//! interpreter signature doesn't change when M2/M3 land.

/// Which sighash and execution regime applies to this script invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigVersion {
    /// Pre-segwit legacy script.
    Base,
    /// BIP141/143 — segwit version 0 (P2WPKH, P2WSH).
    WitnessV0,
    /// BIP341/342 — taproot script-path (tapscript).
    Tapscript,
}

impl SigVersion {
    /// `true` for the legacy regime where `FindAndDelete` and the
    /// `OP_CODESEPARATOR` scriptCode mutation apply.
    #[inline]
    #[must_use]
    pub const fn is_base(self) -> bool {
        matches!(self, Self::Base)
    }

    /// `true` for any segwit regime (v0 or taproot).
    #[inline]
    #[must_use]
    pub const fn is_witness(self) -> bool {
        matches!(self, Self::WitnessV0 | Self::Tapscript)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_classification() {
        assert!(SigVersion::Base.is_base());
        assert!(!SigVersion::Base.is_witness());
    }

    #[test]
    fn witness_classifications() {
        assert!(!SigVersion::WitnessV0.is_base());
        assert!(SigVersion::WitnessV0.is_witness());
        assert!(!SigVersion::Tapscript.is_base());
        assert!(SigVersion::Tapscript.is_witness());
    }
}
