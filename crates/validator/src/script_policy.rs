use mantle::primitives::{BlockHeight, Hash256};
use mantle_consensus::chain_view::{ChainView, ConnectResult, ConnectScratch};
use mantle_consensus::error::ValidationError;
use mantle_consensus::script::ScriptExecutionCache;
use mantle_consensus::tx_view::BlockView;
use mantle_consensus::validation::{InlineScripts, SkippedScripts, connect_block};

use crate::script_pool::ScriptPool;

/// How the pipeline verifies a block's input scripts.
pub enum ScriptPolicy<'a> {
    /// Skip script verification; every other rule still runs.
    Skip,
    /// Verify on the calling thread, consulting the cache when one is given.
    Inline(Option<&'a mut ScriptExecutionCache>),
    /// Verify on a worker pool.
    Parallel(&'a mut ScriptPool),
}

/// The arguments of one `connect_block` call, minus the script checks.
pub(crate) struct ConnectCall<'c, 'b, B, V> {
    pub(crate) block: &'b B,
    pub(crate) height: BlockHeight,
    pub(crate) view: &'c V,
    pub(crate) scratch: &'c mut Vec<u8>,
    pub(crate) connect_scratch: &'c mut ConnectScratch,
    pub(crate) txids: Option<&'c [Hash256]>,
}

impl ScriptPolicy<'_> {
    /// Connect `call.block`, verifying its scripts as this policy says.
    ///
    /// A parallel scope opens and closes inside this call, so every queued
    /// check is finished before the view it borrows goes away.
    pub(crate) fn connect<'b, B, V>(
        &mut self,
        call: ConnectCall<'_, 'b, B, V>,
    ) -> Result<ConnectResult<'b>, ValidationError>
    where
        B: BlockView + Sync,
        V: ChainView,
    {
        let ConnectCall {
            block,
            height,
            view,
            scratch,
            connect_scratch,
            txids,
        } = call;
        match self {
            Self::Skip => connect_block(
                block,
                height,
                view,
                scratch,
                connect_scratch,
                &mut SkippedScripts,
                txids,
            ),
            Self::Inline(cache) => connect_block(
                block,
                height,
                view,
                scratch,
                connect_scratch,
                &mut InlineScripts::new(cache.as_deref_mut()),
                txids,
            ),
            Self::Parallel(pool) => pool.scope(|batch| {
                connect_block(block, height, view, scratch, connect_scratch, batch, txids)
            }),
        }
    }
}
