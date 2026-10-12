use std::fmt;

use mantle::primitives::{BlockHeight, OutPoint};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UtxoError {
    OutputAlreadyExists(OutPoint),
    OutputNotFound(OutPoint),
    TooManyOutputs { txid_prefix: [u8; 8], count: usize },
    CoinbaseMaturity { outpoint: OutPoint, created: BlockHeight, spend: BlockHeight },
}

impl fmt::Display for UtxoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputAlreadyExists(op) => write!(f, "output already exists: {op:?}"),
            Self::OutputNotFound(op) => write!(f, "output not found: {op:?}"),
            Self::TooManyOutputs { count, .. } => {
                write!(f, "transaction has {count} outputs, max 256")
            }
            Self::CoinbaseMaturity {
                outpoint,
                created,
                spend,
            } => write!(
                f,
                "coinbase output {outpoint:?} created at {created} not mature at {spend}"
            ),
        }
    }
}

impl std::error::Error for UtxoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_all_variants_non_empty() {
        let op = OutPoint {
            txid: mantle::primitives::Hash256::ZERO,
            vout: 0,
        };
        let variants: Vec<UtxoError> = vec![
            UtxoError::OutputAlreadyExists(op),
            UtxoError::OutputNotFound(op),
            UtxoError::TooManyOutputs {
                txid_prefix: [0u8; 8],
                count: 999,
            },
            UtxoError::CoinbaseMaturity {
                outpoint: op,
                created: BlockHeight::new(1),
                spend: BlockHeight::new(50),
            },
        ];
        for v in &variants {
            let s = format!("{v}");
            assert!(!s.is_empty(), "Display for {v:?} should be non-empty");
        }
    }
}
