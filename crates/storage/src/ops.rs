use std::ops::Deref;

use mantle::primitives::{BlockHeader, BlockHeight, Hash256, OutPoint};
use mantle_consensus::chain_view::TipInfo;

use crate::handle::StorageHandle;
use crate::types::{
    CommitBlockReq, CommittedResp, LookupResult, StorageError, StorageReq, StorageResp,
};

/// Abstraction over `StorageHandle` used by `mantle-validator`.
///
/// Parameterised by `'req` — the lifetime of borrowed slices passed to
/// `send_lookup` / `commit_block_borrowed`.
///
/// The single implementation covers `StorageHandle<'ring, RReq, RResp>` for
/// any ring lifetime `'ring`. It uses `send_lookup_borrowed` (a synchronous
/// transmute helper) so that `'req` can be shorter than `'ring`. This lets
/// callers write `S: for<'x> StorageOps<'x>` and pass a scoped handle.
pub trait StorageOps<'req> {
    /// Fire a UTXO lookup request; does not wait for the response.
    ///
    /// # Errors
    /// Returns `StorageError` if the ring is full.
    fn send_lookup(
        &mut self,
        ops: &'req [OutPoint],
        out: &'req mut Vec<LookupResult>,
    ) -> Result<(), StorageError>;

    /// Collect the response from the most-recently fired `send_lookup`.
    ///
    /// # Errors
    /// Returns `StorageError` on ring or I/O failure.
    fn recv_lookup(&mut self) -> Result<(), StorageError>;

    /// Commit a block whose borrowed data lives for `'req`.
    ///
    /// # Errors
    /// Returns `StorageError` on ring or I/O failure.
    fn commit_block_borrowed(
        &mut self,
        req: CommitBlockReq<'req>,
    ) -> Result<CommittedResp, StorageError>;

    /// Last tip known to this handle.
    fn tip(&self) -> TipInfo;

    /// Read a header by hash.
    ///
    /// # Errors
    /// Returns `StorageError` on ring or I/O failure.
    fn read_header(&mut self, hash: Hash256) -> Result<Option<BlockHeader>, StorageError>;

    /// Read a header by height.
    ///
    /// # Errors
    /// Returns `StorageError` on ring or I/O failure.
    fn read_header_at(&mut self, h: BlockHeight) -> Result<Option<BlockHeader>, StorageError>;
}

// ── Single impl: StorageHandle<'ring, RReq, RResp> for any 'ring ─────────────
//
// `send_lookup` and `commit_block_borrowed` use `mem::transmute` to bridge the
// gap between `'req` (the data's lifetime) and `'ring` (the ring's lifetime).
// This is safe because both operations are synchronous — the request is pushed,
// the worker processes it, and the response is received before the method
// returns. The worker never holds a reference to the data after sending its
// response.
//
// Two lifetime parameters:
//   'ring — the ring's frame lifetime (tied to the `with_storage` scope, or
//           'static for the Arc-backed open() path).
//   'req  — the data's lifetime (can be shorter than 'ring; e.g. locals inside
//           validate_and_commit).
//
// Because `'ring` and `'req` are independent, a single `StorageHandle<'ring,
// ...>` implements `StorageOps<'req>` for *all* `'req`, satisfying the
// `for<'x> StorageOps<'x>` bound that pipeline functions require.

impl<'req, 'ring, RReq, RResp> StorageOps<'req> for StorageHandle<'ring, RReq, RResp>
where
    RReq: Deref<Target = quetzalcoatl::mpsc::RingBuffer<StorageReq<'ring>>>,
    RResp: Deref<Target = quetzalcoatl::spsc::RingBuffer<StorageResp>>,
{
    fn send_lookup(
        &mut self,
        ops: &'req [OutPoint],
        out: &'req mut Vec<LookupResult>,
    ) -> Result<(), StorageError> {
        StorageHandle::send_lookup_borrowed(self, ops, out)
    }

    fn recv_lookup(&mut self) -> Result<(), StorageError> {
        StorageHandle::recv_lookup(self)
    }

    fn commit_block_borrowed(
        &mut self,
        req: CommitBlockReq<'req>,
    ) -> Result<CommittedResp, StorageError> {
        StorageHandle::commit_block_borrowed(self, req)
    }

    fn tip(&self) -> TipInfo {
        StorageHandle::tip(self)
    }

    fn read_header(&mut self, hash: Hash256) -> Result<Option<BlockHeader>, StorageError> {
        StorageHandle::read_header(self, hash)
    }

    fn read_header_at(&mut self, h: BlockHeight) -> Result<Option<BlockHeader>, StorageError> {
        StorageHandle::read_header_at(self, h)
    }
}
