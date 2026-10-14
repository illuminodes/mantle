mod block_job;
mod in_flight_limit;
mod outcome;
mod pending_block;
mod prefetch;

#[cfg(test)]
mod tests;

use std::collections::VecDeque;

use mantle::collections::{BuildPrehashedHasher, PrehashedMap};
use mantle::primitives::OutPoint;
use mantle_consensus::chain_view::{ConnectScratch, TipInfo};
use mantle_consensus::error::ValidationError;
use mantle_consensus::validation::{SkippedScripts, connect_block};
use mantle_storage::ops::StorageOps;
use mantle_storage::types::{CommitBlockReq, LookupResult, StorageError};
use mantle_utxo_hash::UtxoSetHash;

pub use block_job::BlockJob;
pub use in_flight_limit::InFlightLimit;
pub use outcome::{Connected, Retired, Verdict, Wait};

use pending_block::{DetachedDelta, PendingBlock, ScriptState};
use prefetch::Prefetch;

use crate::prefetched_view::{CoinMap, HeaderSnapshot, PrefetchedView};
use crate::script_pool::{PoolBusy, ScriptPool};
use crate::utxo_hash_update::UtxoHashUpdate;
use crate::utxo_overlay::UtxoOverlay;

/// What to do with a block whose scripts fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnScriptFailure {
    /// Leave it and every later block out of storage.
    Stop,
    /// Commit it anyway so later blocks see the real chain's UTXO set.
    CommitAnyway,
}

/// Connects blocks ahead of their script checks and commits each one to
/// storage only after its scripts pass.
///
/// A block is connected against storage seen through a [`UtxoOverlay`] of
/// the blocks still waiting for scripts, its checks are queued on the
/// [`ScriptPool`], and its UTXO delta goes into the overlay. Blocks leave
/// in height order: once the oldest block's scripts are done it is written
/// to storage and its delta leaves the overlay. Up to the
/// [`InFlightLimit`] blocks wait at once, so the workers have checks queued
/// from several blocks while later blocks are connected.
///
/// Field order matters: `pool` drops first and waits for every check before
/// `pending` frees the blocks and coin maps they read.
pub struct ConnectPipeline {
    pool: ScriptPool,
    pending: VecDeque<PendingBlock>,
    pending_inputs: usize,
    overlay: UtxoOverlay,
    limit: InFlightLimit,
    on_failure: OnScriptFailure,
    verify_scripts: bool,
    stopped: bool,
    tip: TipInfo,
    prefetch: Option<Prefetch>,
    #[allow(clippy::box_collection)]
    spare_lookups: Vec<(Vec<OutPoint>, Box<Vec<LookupResult>>)>,
    scratch: Vec<u8>,
    connect_scratch: ConnectScratch,
    utxo_hash: Option<(UtxoSetHash, UtxoHashUpdate)>,
    spare_maps: Vec<CoinMap>,
    lookup_time: std::time::Duration,
}

impl ConnectPipeline {
    #[must_use]
    pub fn new(pool: ScriptPool, tip: TipInfo, limit: InFlightLimit) -> Self {
        Self {
            pool,
            pending: VecDeque::new(),
            pending_inputs: 0,
            overlay: UtxoOverlay::new(),
            limit,
            on_failure: OnScriptFailure::Stop,
            verify_scripts: true,
            stopped: false,
            tip,
            prefetch: None,
            spare_lookups: Vec::new(),
            scratch: Vec::new(),
            connect_scratch: ConnectScratch::new(),
            utxo_hash: None,
            spare_maps: Vec::new(),
            lookup_time: std::time::Duration::ZERO,
        }
    }

    /// Time spent waiting for storage lookups so far.
    #[must_use]
    pub fn lookup_time(&self) -> std::time::Duration {
        self.lookup_time
    }

    #[must_use]
    pub fn on_script_failure(mut self, on_failure: OnScriptFailure) -> Self {
        self.on_failure = on_failure;
        self
    }

    #[must_use]
    pub fn skip_scripts(mut self) -> Self {
        self.verify_scripts = false;
        self
    }

    #[must_use]
    pub fn with_utxo_hash(mut self, hash: UtxoSetHash) -> Self {
        self.utxo_hash = Some((hash, UtxoHashUpdate::new()));
        self
    }

    /// The running UTXO set hash, updated as blocks reach storage.
    pub fn utxo_hash(&mut self) -> Option<&mut UtxoSetHash> {
        self.utxo_hash.as_mut().map(|(hash, _)| hash)
    }

    /// Stop updating the UTXO set hash.
    pub fn stop_utxo_hash(&mut self) {
        self.utxo_hash = None;
    }

    #[must_use]
    pub fn workers(&self) -> usize {
        self.pool.workers()
    }

    #[must_use]
    pub fn script_busy(&self) -> PoolBusy {
        self.pool.busy()
    }

    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.pending.len()
    }

    /// `true` after a script failure under [`OnScriptFailure::Stop`]; later
    /// blocks are retired without being committed.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// The last block connected, which is ahead of storage by the blocks in
    /// flight.
    #[must_use]
    pub fn tip(&self) -> &TipInfo {
        &self.tip
    }

    /// Connect `job` against storage and the pending blocks, queue its
    /// script checks and record its UTXO delta.
    ///
    /// When `next` is given, its storage lookups are sent before `job` is
    /// connected, so storage answers them while this thread works; the
    /// answer is used when `next` is connected.
    ///
    /// # Errors
    /// Returns `StorageError` when a lookup fails; validation failures come
    /// back as [`Connected::Rejected`].
    pub fn connect<S>(
        &mut self,
        job: BlockJob,
        next: Option<&BlockJob>,
        storage: &mut S,
        headers: &HeaderSnapshot,
    ) -> Result<Connected, StorageError>
    where
        S: for<'x> StorageOps<'x>,
    {
        let job = Box::new(job);
        let coins = self.coins_for(&job, storage)?;
        if let Some(next) = next {
            self.send_prefetch(next, storage)?;
        }
        let connected = self.connect_with(&job, &coins, headers);
        let (delta, scripts) = match connected {
            Ok(connected) => connected,
            Err(error) => {
                self.recycle(coins);
                return Ok(Connected::Rejected { error, job });
            }
        };
        self.queue(job, delta, coins, scripts);
        Ok(Connected::Queued)
    }

    /// On success the returned delta borrows from `job.block` and the
    /// returned script id refers to checks that read `job` and `coins`; the
    /// caller must move all of them into the queue together.
    fn connect_with(
        &mut self,
        job: &BlockJob,
        coins: &CoinMap,
        headers: &HeaderSnapshot,
    ) -> Result<(DetachedDelta, ScriptState), ValidationError> {
        let view = PrefetchedView::new(coins, headers, self.tip.clone());
        let txids = job.inputs.txids_for(&job.block);
        if !self.verify_scripts {
            let result = connect_block(
                &job.block,
                job.height,
                &view,
                &mut self.scratch,
                &mut self.connect_scratch,
                &mut SkippedScripts,
                txids,
            )?;
            // SAFETY: `connect_block` builds `created` from `job.block`.
            let delta = unsafe { DetachedDelta::new(result.created, result.spent) };
            return Ok((delta, ScriptState::Skipped));
        }
        // SAFETY: the batch is released only after `connect_block` succeeds,
        // and `connect` then moves `job` and `coins`, which the checks
        // borrow, into a `PendingBlock` that outlives the checks; on any
        // early return the batch is dropped and waits for its checks.
        let mut batch = unsafe { self.pool.deferred_batch() };
        let result = connect_block(
            &job.block,
            job.height,
            &view,
            &mut self.scratch,
            &mut self.connect_scratch,
            &mut batch,
            txids,
        )?;
        let id = batch.release();
        // SAFETY: `connect_block` builds `created` from `job.block`.
        let delta = unsafe { DetachedDelta::new(result.created, result.spent) };
        Ok((delta, ScriptState::Running(id)))
    }

    /// Queue `job` without validating it, so later blocks see the UTXO set
    /// the real chain produced after a failed block.
    ///
    /// # Errors
    /// Returns `ValidationError` when the block's delta cannot be built.
    pub fn force(&mut self, job: Box<BlockJob>) -> Result<(), ValidationError> {
        let (created, spent) = job.inputs.delta(&job.block, job.height)?;
        // SAFETY: `BlockInputs::delta` builds `created` from `job.block`.
        let delta = unsafe { DetachedDelta::new(created, spent) };
        let coins = self.spare_map();
        self.queue(job, delta, coins, ScriptState::Forced);
        Ok(())
    }

    fn queue(
        &mut self,
        job: Box<BlockJob>,
        delta: DetachedDelta,
        coins: CoinMap,
        scripts: ScriptState,
    ) {
        self.overlay
            .apply(job.height, delta.created(), delta.spent());
        self.tip = TipInfo {
            hash: job.hash,
            height: job.height,
        };
        let pending = PendingBlock::new(job, delta, coins, scripts);
        self.pending_inputs += pending.inputs;
        self.pending.push_back(pending);
    }

    /// Commit the oldest block if its scripts are done, or, with
    /// [`Wait::Always`] or while over the in-flight limit, once they are.
    /// Returns `None` when nothing was retired.
    ///
    /// # Errors
    /// Returns `StorageError` when the commit fails.
    pub fn retire_next<S>(
        &mut self,
        storage: &mut S,
        wait: Wait,
    ) -> Result<Option<Retired>, StorageError>
    where
        S: for<'x> StorageOps<'x>,
    {
        let Some(front) = self.pending.front() else {
            return Ok(None);
        };
        let must_wait = wait == Wait::Always
            || self
                .limit
                .is_exceeded_by(self.pending.len(), self.pending_inputs);
        if let ScriptState::Running(id) = front.scripts
            && !must_wait
            && !self.pool.is_done(id)
        {
            return Ok(None);
        }
        let Some(pending) = self.pending.pop_front() else {
            return Ok(None);
        };
        self.receive_prefetch(storage)?;
        if let Some(prefetch) = &mut self.prefetch {
            prefetch.refresh(&self.overlay);
        }
        self.pending_inputs -= pending.inputs;
        let verdict = match pending.scripts {
            ScriptState::Running(id) => match self.pool.settle_block(id) {
                Ok(()) => Verdict::Valid,
                Err(error) => Verdict::ScriptFailed(error),
            },
            ScriptState::Skipped => Verdict::Valid,
            ScriptState::Forced => Verdict::Forced,
        };
        if matches!(verdict, Verdict::ScriptFailed(_)) && self.on_failure == OnScriptFailure::Stop {
            self.stopped = true;
        }
        let committed = !self.stopped;
        if committed {
            self.commit(&pending, storage)?;
        }
        self.overlay.retire(pending.job.height);
        let (height, hash) = (pending.job.height, pending.job.hash);
        let failed = matches!(verdict, Verdict::ScriptFailed(_));
        let (coins, failed_block) = pending.into_parts(failed);
        self.recycle(coins);
        Ok(Some(Retired {
            height,
            hash,
            verdict,
            committed,
            failed_block,
        }))
    }

    /// Commit every block still waiting, oldest first, waiting for each
    /// one's scripts.
    ///
    /// # Errors
    /// Returns `StorageError` when a commit fails.
    pub fn drain<S>(&mut self, storage: &mut S) -> Result<Vec<Retired>, StorageError>
    where
        S: for<'x> StorageOps<'x>,
    {
        let mut retired = Vec::with_capacity(self.pending.len());
        while let Some(block) = self.retire_next(storage, Wait::Always)? {
            retired.push(block);
        }
        self.receive_prefetch(storage)?;
        self.drop_prefetch();
        Ok(retired)
    }

    /// Wait for an outstanding prefetch, so storage can take other requests.
    fn receive_prefetch<S>(&mut self, storage: &mut S) -> Result<(), StorageError>
    where
        S: for<'x> StorageOps<'x>,
    {
        let Some(prefetch) = &mut self.prefetch else {
            return Ok(());
        };
        if prefetch.is_awaiting_storage() {
            let started = std::time::Instant::now();
            storage.recv_lookup()?;
            self.lookup_time += started.elapsed();
            prefetch.received();
        }
        Ok(())
    }

    fn drop_prefetch(&mut self) {
        if let Some(prefetch) = self.prefetch.take() {
            let (coins, lookups, results) = prefetch.into_parts();
            self.recycle(coins);
            self.spare_lookups.push((lookups, results));
        }
    }

    /// Send `next`'s storage lookups without waiting for the answer.
    fn send_prefetch<S>(&mut self, next: &BlockJob, storage: &mut S) -> Result<(), StorageError>
    where
        S: for<'x> StorageOps<'x>,
    {
        self.receive_prefetch(storage)?;
        self.drop_prefetch();
        let (mut lookups, mut results) = self.spare_lookups.pop().unwrap_or_default();
        lookups.clear();
        results.clear();
        lookups.extend(next.inputs.lookups().copied());
        let coins = self.spare_map();
        let mut prefetch = Prefetch::new(next.height, next.hash, lookups, results, coins);
        if prefetch.has_lookups() {
            let (ops, out) = prefetch.request();
            storage.send_lookup(ops, out)?;
            prefetch.mark_sent();
        }
        self.prefetch = Some(prefetch);
        Ok(())
    }

    fn commit<S>(&mut self, pending: &PendingBlock, storage: &mut S) -> Result<(), StorageError>
    where
        S: for<'x> StorageOps<'x>,
    {
        let job = &pending.job;
        storage.commit_block_borrowed(CommitBlockReq {
            token: job.token,
            height: job.height,
            hash: job.hash,
            prev_hash: job.block.header.prev_block(),
            header: job.block.header,
            created: pending.delta.created(),
            spent: pending.delta.spent(),
            block_bytes: None,
            durability: job.durability,
        })?;
        if let Some((hash, update)) = &mut self.utxo_hash {
            update.apply(
                hash,
                (job.height, job.hash),
                pending.delta.created(),
                pending.delta.spent(),
                &pending.coins,
            );
        }
        Ok(())
    }

    /// The coins `job` spends or probes, from the pending blocks where they
    /// changed and from storage otherwise, taken from a prefetch when one
    /// was sent for `job`. Outpoints created inside the block are registered
    /// as absent; `connect_block` resolves them itself.
    fn coins_for<S>(&mut self, job: &BlockJob, storage: &mut S) -> Result<CoinMap, StorageError>
    where
        S: for<'x> StorageOps<'x>,
    {
        self.receive_prefetch(storage)?;
        let mut coins = match self.prefetch.take() {
            Some(mut prefetch) if prefetch.is_for(job.height, job.hash) => {
                prefetch.refresh(&self.overlay);
                let (coins, lookups, results) = prefetch.into_parts();
                self.spare_lookups.push((lookups, results));
                coins
            }
            other => {
                self.prefetch = other;
                self.drop_prefetch();
                self.look_up(job, storage)?
            }
        };
        for op in &job.inputs.internal {
            coins.insert(*op, None);
        }
        Ok(coins)
    }

    fn look_up<S>(&mut self, job: &BlockJob, storage: &mut S) -> Result<CoinMap, StorageError>
    where
        S: for<'x> StorageOps<'x>,
    {
        let mut coins = self.spare_map();
        let (mut lookups, mut results) = self.spare_lookups.pop().unwrap_or_default();
        lookups.clear();
        for op in job.inputs.lookups() {
            match self.overlay.get(op) {
                Some(coin) => {
                    coins.insert(*op, coin.cloned());
                }
                None => lookups.push(*op),
            }
        }
        if !lookups.is_empty() {
            let started = std::time::Instant::now();
            storage.send_lookup(&lookups, &mut results)?;
            storage.recv_lookup()?;
            self.lookup_time += started.elapsed();
            for found in results.drain(..) {
                coins.insert(found.outpoint, found.coin);
            }
        }
        self.spare_lookups.push((lookups, results));
        Ok(coins)
    }

    fn spare_map(&mut self) -> CoinMap {
        self.spare_maps
            .pop()
            .unwrap_or_else(|| PrehashedMap::with_hasher(BuildPrehashedHasher))
    }

    fn recycle(&mut self, mut coins: CoinMap) {
        coins.clear();
        self.spare_maps.push(coins);
    }
}
