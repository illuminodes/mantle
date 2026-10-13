/// Conformance testing glue: wraps libbitcoinconsensus (Bitcoin Core v26.0)
/// and exposes a Rust API for differential testing.
///
/// NEVER add this crate as a dependency of mantle-node or mantle.
/// It is test-infrastructure only.
pub mod conformance {
    pub use bitcoinconsensus::{
        VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY, VERIFY_DERSIG, VERIFY_NONE,
        VERIFY_NULLDUMMY, VERIFY_P2SH, VERIFY_TAPROOT, VERIFY_WITNESS,
    };

    pub use bitcoinconsensus::Utxo;

    /// Script verify flags (combine `VERIFY_*` constants with `|`).
    pub type ScriptFlags = u32;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ConformanceError(pub String);

    impl std::fmt::Display for ConformanceError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "conformance error: {}", self.0)
        }
    }

    impl std::error::Error for ConformanceError {}

    impl From<bitcoinconsensus::Error> for ConformanceError {
        fn from(e: bitcoinconsensus::Error) -> Self {
            Self(format!("{e}"))
        }
    }

    /// Verify a script using libbitcoinconsensus.
    ///
    /// - `script_pubkey`: the scriptPubKey of the output being spent.
    /// - `amount`: value of the output being spent, in satoshis.
    /// - `tx_to`: the raw serialized spending transaction.
    /// - `spent_outputs`: all outputs spent by this transaction (required for taproot).
    /// - `n_in`: index of the input in `tx_to` that spends this output.
    /// - `flags`: script verify flags (combine `VERIFY_*` constants).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the script fails to verify or the inputs are malformed.
    pub fn verify_script(
        script_pubkey: &[u8],
        amount: u64,
        tx_to: &[u8],
        spent_outputs: Option<&[Utxo]>,
        n_in: usize,
        flags: ScriptFlags,
    ) -> Result<(), ConformanceError> {
        bitcoinconsensus::verify_with_flags(
            script_pubkey,
            amount,
            tx_to,
            spent_outputs,
            n_in,
            flags,
        )
        .map_err(ConformanceError::from)
    }

    /// Compute the appropriate script flags for a given block height on mainnet.
    #[must_use]
    pub fn flags_for_height(height: u32) -> ScriptFlags {
        bitcoinconsensus::height_to_flags(height)
    }

    /// Returns the version string of the linked libbitcoinconsensus, for CI logging.
    #[must_use]
    pub fn linked_version() -> &'static str {
        "bitcoinconsensus-0.106.0+26.0"
    }
}
