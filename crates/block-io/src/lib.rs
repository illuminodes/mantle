#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

mod handle;
mod single_op;
mod slab;
mod store;

pub use handle::{FileIoHandle, FileReq, FileResp, with_file_io};
pub use slab::{BufHandle, Slab, SlabReader, SlabToken, SlabWriter};
pub use store::{BlockStore, FileStore, HeaderStore};
