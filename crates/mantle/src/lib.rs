#![forbid(unsafe_code)]

pub mod amount;
pub mod block;
pub mod chain_work;
pub mod codec;
pub mod collections;
pub mod difficulty;
pub mod hash;
pub mod network;
pub mod script;
pub mod tx;

pub mod primitives {
    //! Re-exports for backward compatibility.
    pub use crate::amount::*;
    pub use crate::block::*;
    pub use crate::chain_work::ChainWork;
    pub use crate::difficulty::*;
    pub use crate::hash::{Hash256, HexError};
    pub use crate::script::*;
    pub use crate::tx::*;
}
