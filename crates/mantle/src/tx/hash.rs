use crate::codec::Error;
use crate::hash::Hash256;

// ── TxHash ────────────────────────────────────────────────────────────────────

/// Implemented by any type that can compute a Bitcoin transaction id.
///
/// The required method [`txid_into`] writes the serialisation into a
/// caller-owned buffer to avoid a per-call heap allocation. The provided
/// [`txid`] allocates its own buffer; use it when the extra allocation is
/// acceptable.
///
/// Both `Transaction` and `TransactionRef<'_>` implement this trait, so code
/// that must handle either can be generic over `T: TxHash`.
pub trait TxHash {
    /// Compute the txid (`SHA256d` of the non-witness serialisation), reusing
    /// `buf` as scratch space. `buf` is cleared and refilled on every call.
    ///
    /// # Errors
    /// Propagates any I/O error from encoding (encoding into `Vec<u8>` never
    /// fails in practice).
    fn txid_into(&self, buf: &mut Vec<u8>) -> Result<Hash256, Error>;

    /// Compute the txid, allocating a fresh buffer internally.
    ///
    /// # Errors
    /// Propagates any I/O error from encoding.
    fn txid(&self) -> Result<Hash256, Error> {
        self.txid_into(&mut Vec::new())
    }
}
