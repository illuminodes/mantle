# Persistence Architecture

Status: **implemented (v1).** The storage thread, ring-buffer handle and message types live in `crates/storage`. The engines are `RobinHoodEngine` (on-disk Robin Hood hash table with io_uring batching, used by `mantle-replay`) and `FlatEngine` (simple append log, used by tests and `StorageHandle::open`). Four superseded engine experiments are kept for reference in `archive/storage-engines`. This document is the original design; undo data and reorg support are not implemented.

This document covers the storage subsystem's architecture: the io_uring-driven storage thread, the inter-thread message types between it and the validator, and the constraints these decisions create. It does *not* cover the storage *engine* (the on-disk layout, UTXO representation, indexing) — that's a Phase 2 decision deliberately deferred until the message API is stable. See §"Deferred decisions" at the end.

Reading order: the §"Constraints" and §"Persistence options considered" sections are the *why*. The §"Storage thread architecture" and §"Message types" sections are the *what*. Skip to the latter if you just need the API.

---

## Constraints

From `principles.md`:
- §2 (conformance on the wire) — internal storage representation is unconstrained, but anything affecting peer-visible behavior is forbidden. Rules out Utreexo proofs on the wire.
- §3 (minimal deps) — RocksDB and LevelDB are out unless we have no alternative. Pure-Rust kv primitives are acceptable.
- §5 (thread-per-component) — storage owns one io_uring, one buffer pool, one set of file descriptors. Validator does not touch any of them.
- §6 (modern hardware) — io_uring is non-negotiable. Synchronous file IO is not used on hot paths.

From the project state:
- `ququmatz` provides io_uring bindings (raw syscalls, `#![no_std]`, no libc). `IoUring` is `!Send + !Sync` by construction — one ring per thread is enforced at the type level.
- `quetzalcoatl` provides lock-free ring buffers (SPSC, MPSC, SPMC, MPMC, broadcast). Bounded by construction; power-of-two capacities; cache-padded cursors.
- The network layer (`mantle::peer::Node`) already uses both crates: ququmatz `IoUring` for socket IO, quetzalcoatl `mpsc` for outbound and `spmc` for inbound. The storage subsystem follows the same template.

---

## Persistence options considered

For completeness — the full landscape was discussed before settling on the chosen path. Each option's status is recorded so it can be reconsidered if constraints change.

### Classical UTXO kv-store (Core-shape)
Map `OutPoint → Coin` in a kv-store (LevelDB/RocksDB/MDBX). This is what Core, btcd, and libbitcoin use.
- **Pros:** mature, well-understood, simple reorg via undo log, easy snapshots.
- **Cons:** grows unboundedly, disk-bound during IBD, contradicts §3 (minimal deps) if RocksDB is the primitive.
- **Status:** rejected as the *primitive*, but the *shape* (per-outpoint kv lookup) is the public access pattern of our storage layer regardless of how it's implemented internally.

### Utreexo (accumulator-based)
Replace the UTXO set with a forest of merkle accumulators; spends carry inclusion proofs.
- **Pros:** tiny verifying state, statelessness, alignment with future ZK work.
- **Cons:** proofs must come from somewhere; on-wire proof gossip violates §2; bridge-node duality (Floresta's approach) is explicitly out of scope.
- **Status:** rejected for v1. Reconsider only if proof distribution becomes a wire-protocol feature in mainline Bitcoin.

### Hybrid / era-based accumulator
Active "hot" UTXO in kv, frozen "cold" eras as accumulators.
- **Pros:** novel, bounded mutable state, retains good amortized cost.
- **Cons:** original research, complicates wire-level conformance if peer-visible (rejected by §2). Internal-only version doesn't justify the complexity.
- **Status:** rejected for v1. Genuinely interesting; could be revisited as a research side-project.

### MMR / Mimblewimble-style append-only structure
- **Status:** rejected. Poor fit for Bitcoin's UTXO model.

### ZK-validity / SNARK-verified state
- **Status:** rejected for v1; not technologically ready. Validator/storage interface should not foreclose future migration.

### Fully custom storage engine (page-structured, mmap, COW)
Hand-rolled engine optimized for UTXO workload + io_uring-native.
- **Pros:** maximum performance ceiling, perfect fit, minimal deps.
- **Cons:** months of work; storage engines need years to harden.
- **Status:** **deferred to Phase 2**. Possible Phase 3 replacement of the underlying primitive without rewriting the storage layer.

### Pure-Rust kv primitive (`redb`, `fjall`) + custom UTXO layer
Use a maintained pure-Rust kv crate as the primitive. Build the UTXO layer (schema, cache, reorg machinery) on top.
- **Pros:** no C deps, ACID and crash safety from the primitive, schema and access patterns under our control.
- **Cons:** the primitive's IO model is synchronous — does not natively integrate with io_uring.
- **Status:** **plausible fallback** if io_uring-native Phase 2 work stalls. Documented as the Plan B.

### Custom io_uring-native storage layer (chosen direction)
A storage thread owning a `ququmatz::IoUring`, driving file IO directly via `read_fixed`/`write_fixed`/`fsync` SQEs, communicating with the validator via `quetzalcoatl` ring buffers. The on-disk format and engine internals (page allocator, WAL, B-tree or LSM, etc.) are deferred (Phase 2).
- **Pros:** fits §3, §5, §6; reuses existing in-house primitives; no impedance mismatch.
- **Cons:** more responsibility (we own crash recovery, durability ordering, etc.).
- **Status:** **chosen for v1**. The rest of this document specifies it.

---

## Storage thread architecture

A single dedicated thread owns:
- One `ququmatz::IoUring` instance, configured with `.sqpoll(idle_ms).single_issuer()` (subject to tuning).
- A `BufferPool` of pre-registered buffer slots (`IoUring::register_buffers` and/or `register_provided_buffers`).
- A `RegisteredFiles` table for the storage engine's open file descriptors (`IoUring::register_files`).
- An `EventFd` registered with the ring, used by validator-side producers to wake the storage thread when the request channel transitions from empty to non-empty.
- The consumer end of the request ring (`StorageReq` from validator).
- The producer end of the response ring (`StorageResp` to validator).
- The `PendingTable` mapping `ReqToken` → in-progress operation state.

### Event loop

```
loop {
    // 1. Block until something happens. Two wake sources:
    //    a) eventfd CQE (a producer wrote to the eventfd)
    //    b) any IO CQE (a previously-submitted op completed)
    ring.submit_and_wait(1)?;

    // 2. Drain CQEs. Each CQE is either:
    //    - the eventfd read → re-arm it, then drain new requests
    //    - an IO completion → look up the originating op, advance it,
    //      possibly emit a StorageResp, possibly recycle a buffer slot
    while let Some(cqe) = ring.complete() {
        dispatch_cqe(cqe);
    }

    // 3. Drain the request ring (if not already drained from eventfd CQE).
    while let Some(req) = req_consumer.pop() {
        submit_for(req);  // pushes one or more SQEs, registers in PendingTable
    }

    // 4. Submit any newly-pushed SQEs.
    ring.submit()?;
}
```

This is structurally identical to `Node::poll_or_timeout` in `mantle::peer.rs:318`. The differences are: ops are file IO instead of socket IO; correlation tokens are validator-supplied instead of `(peer_id, op)` tuples; completions feed a response ring instead of an inbound message ring.

### Wakeup

Producers (validator threads) signal the storage thread by:
1. Pushing a `StorageReq` into the request ring (mpsc or spsc).
2. Writing 1 to the storage thread's `EventFd`.

The storage thread's ring has a standing `Sqe::read` SQE on the eventfd; producer's write completes that SQE, the storage thread wakes, drains, re-arms.

The eventfd write is the only syscall on the producer's hot path. The storage thread does not poll — it blocks in `submit_and_wait`. This pattern is described in `principles.md` §6.

### Buffer ownership

A `BufferSlot` is an opaque index into the storage thread's registered-buffer pool. At any moment, a slot is owned by exactly one party:

| Owner | When |
|---|---|
| Validator | After `BufferPool::reserve()`, before sending; after receiving in a `StorageResp`. |
| Storage thread | After receiving in a `StorageReq`; after a CQE matches its op. |
| Kernel | While an io_uring op against the slot is in flight. |

Transitions are explicit and message-driven. The validator side wraps slots in a `PooledBuffer<'pool>` handle whose `Drop` impl recycles. Slot indices crossing the channel are bare `BufferSlot(u32)` for serialization simplicity; the `PooledBuffer` wrapping happens at the seam.

Misbehavior — use-after-recycle, double-recycle, sending a slot the validator doesn't own — is a memory-safety bug. Wrapping in `PooledBuffer` makes the safe path the easy path.

### Linked submissions for atomic durability

io_uring's `IOSQE_IO_LINK` (exposed via `Sqe::link()`) lets us express ordered chains in a single submission. Block commit, for example:

```
write_fixed(undo_file, undo_bytes, ...)        .link()
write_fixed(state_file, state_delta, ...)      .link()
write_fixed(checkpoint_file, checkpoint, ...)  .link()
fsync(checkpoint_file, FsyncFlags::DATASYNC)
```

Four SQEs, one submission. If any earlier op fails the chain aborts. Only the final fsync's CQE matters for the response. This is more expressive than a typical kv-store's transaction API and is essentially free given the API surface ququmatz already exposes.

---

## Message types (validator ↔ storage)

The seam. These are the types crossing the ring buffers between validator and storage threads.

### Top-level envelopes

```rust
pub struct StorageReq {
    /// Validator-chosen correlation token. Storage echoes this back in the
    /// matching StorageResp. Also stuffed into io_uring user_data so a
    /// single token threads end-to-end (validator → ring → kernel → CQE
    /// → response).
    pub token: ReqToken,
    pub op: StorageOp,
}

pub enum StorageOp {
    LookupCoins(LookupCoinsReq),
    CommitBlock(CommitBlockReq),
    ApplyReorg(ApplyReorgReq),
    ReadHeader(ReadHeaderReq),
    ReadBlockBytes(ReadBlockBytesReq),
    UtxoSnapshot(UtxoSnapshotReq),
    Barrier,
    Shutdown,
}

pub struct StorageResp {
    pub token: ReqToken,
    pub result: StorageResult,
}

pub enum StorageResult {
    Coins(LookupCoinsResp),
    Committed(CommittedResp),
    Reorged(ReorgedResp),
    Header(HeaderResp),
    BlockBytes(BlockBytesResp),
    Snapshot(SnapshotResp),
    Barrier,
    Error(StorageError),
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct ReqToken(pub u64);
```

### `LookupCoinsReq` / `LookupCoinsResp`

The hot path. Sent millions of times during IBD.

```rust
pub struct LookupCoinsReq {
    pub outpoints: SmallVec<[OutPoint; 8]>,
    pub buffer_slots: SmallVec<[BufferSlot; 8]>,  // pre-reserved, one per outpoint
}

pub struct LookupCoinsResp {
    pub results: SmallVec<[LookupResult; 8]>,  // same order as request
}

pub enum LookupResult {
    Found { slot: BufferSlot, len: u32 },
    NotFound,
    Error(IoErrorCode),
}
```

Design notes:
- **Batched, not per-outpoint.** A single block has ~2000 inputs; per-outpoint requests would saturate the ring and miss the io_uring batch-submission win. Batches are validator's choice — likely per-tx initially, later possibly per-block. See §"Open questions."
- **Buffer slots pre-reserved by validator.** Validator allocates from `BufferPool` before sending. Storage thread fills the slot via `read_fixed`. No per-request allocation.
- **`SmallVec` inline for typical batches.** Most txs have ≤8 inputs; inlined. Larger batches heap-allocate; acceptable but worth profiling.
- **Result ordering matches request.** No hash lookup at the validator.

### `CommitBlockReq` / `CommittedResp`

```rust
pub struct CommitBlockReq {
    pub height: u32,
    pub block_hash: BlockHash,
    pub prev_hash: BlockHash,
    pub created: Box<[NewCoin]>,
    pub spent: Box<[OutPoint]>,
    pub block_bytes: Option<BufferSlot>,  // Some = also store raw block
    pub durability: Durability,
}

pub struct NewCoin {
    pub outpoint: OutPoint,
    pub value: u64,
    pub script_pubkey: BufferSlot,  // bytes in pool slot
    pub coinbase: bool,
    pub height: u32,
}

pub enum Durability {
    Memory,   // ack after in-memory metadata update
    Queued,   // ack after writes are queued to kernel
    Synced,   // ack after fsync — survives power loss
}

pub struct CommittedResp {
    pub new_tip: BlockHash,
    pub new_height: u32,
    pub undo_loc: UndoLoc,  // opaque; stored alongside the block ref
}
```

Design notes:
- **Block bytes optional.** Some flows (headers-first sync, replay) commit state without re-storing raw block. `Option<BufferSlot>` makes both cases natural.
- **`Durability` per-request.** IBD chooses `Memory`/`Queued` and fsyncs at checkpoint boundaries; tip-following with peer relay chooses `Synced`. The storage thread is the same code regardless.
- **`script_pubkey` as a slot, not inline.** Output scripts can be large (P2WSH, weird non-standard); inlining bloats the channel.

### `ApplyReorgReq` / `ReorgedResp`

```rust
pub struct ApplyReorgReq {
    pub disconnect: Box<[CommittedBlockRef]>,  // tip-to-fork order
    pub connect: Box<[CommitBlockReq]>,         // fork-to-new-tip order
    pub durability: Durability,
}

pub struct CommittedBlockRef {
    pub height: u32,
    pub block_hash: BlockHash,
    pub undo_loc: UndoLoc,
}

pub struct ReorgedResp {
    pub new_tip: BlockHash,
    pub new_height: u32,
}
```

Design notes:
- **Atomic by construction.** A reorg is *one* request, not a sequence. The storage thread executes it as a unit; the validator never observes a half-reorg state.
- **`undo_loc` is opaque.** Minted by the storage engine on commit, stored in chain-state metadata, threaded back on disconnect. Validator does not interpret it.

### Smaller messages

```rust
pub enum ReadHeaderReq {
    ByHash(BlockHash),
    ByHeight(u32),
}

pub struct HeaderResp {
    pub header: BlockHeader,  // 80 bytes; inline
    pub height: u32,
    pub work: U256,
}

pub struct ReadBlockBytesReq {
    pub locator: BlockLocator,  // hash or (file_id, offset, len)
    pub into: BufferSlot,
}

pub struct BlockBytesResp {
    pub slot: BufferSlot,
    pub len: u32,
}

pub struct UtxoSnapshotReq {
    pub kind: SnapshotKind,  // muhash, hash_serialized_3, etc.
}

pub struct SnapshotResp {
    pub digest: [u8; 32],
    pub utxo_count: u64,
    pub total_amount: u64,
}
```

### Errors

```rust
pub enum StorageError {
    UnknownToken,
    Corruption(CorruptionKind),
    Io { errno: i32, op: &'static str },
    OutOfBounds,
    ShuttingDown,
}
```

No `String` allocations. `&'static str` for operation names is fine — they're compile-time constants.

### Tip query: not a message

Tip hash, height, and total work are read frequently and updated infrequently. Round-tripping through the channel adds latency to no benefit. The chosen approach is a small shared-state struct with atomic fields:

```rust
pub struct TipState {
    pub hash: AtomicU256,        // some atomic-friendly representation
    pub height: AtomicU32,
    pub work: AtomicU256,
    // ...
}
```

The storage thread is the single writer (Release stores after commit completes). Validators are readers (Acquire loads). No mutex; no channel round-trip. This is the only state shared across the boundary, and it's read-mostly.

---

## Channel sizing

Both rings: capacity 1024 (power-of-two, quetzalcoatl-required).

- 1024 × ~64 bytes per message = 64 KiB per direction. Negligible.
- ~2000 inputs per block; batched per-tx means ~hundreds of in-flight requests. Headroom is healthy.
- Backpressure at 1024 in flight indicates validator producing requests far faster than storage can drain — diagnostic, not pathological.

Topology:
- Single validator thread + single storage thread → both rings are SPSC. Saves the FAA on the producer hot path.
- Multiple validator threads + single storage thread → request ring is MPSC, response ring is SPMC (storage routes by token).
- Most likely: one *coordinator* validator thread fans out to a script-verify worker pool and is the only thing talking to storage. SPSC seam.

We commit to the SPSC topology for v1 and revisit if the validator design changes.

### Token / `PendingTable`

Validator-side correlation:

```rust
pub struct PendingTable {
    slots: Box<[Option<Waiter>]>,  // power-of-two; index = token & MASK
}
```

`token & (capacity - 1)` indexes the slot. Bounded by ring capacity (in-flight ≤ ring depth). No allocation per request.

The token's top 16 bits identify the validator-side waiter (for debuggability under multiple workers); the rest is a monotonic counter. The whole 64-bit token also goes into io_uring's `user_data`, so a single value threads validator → channel → kernel → CQE → response.

---

## Crash recovery

The async-IO model means "what's on disk" lags "what validation thinks is current." On startup:

1. Open the latest durable checkpoint from the storage engine's perspective.
2. Identify the highest block whose commit was fsynced (`Durability::Synced`).
3. Re-validate any blocks above the durable tip by replaying from block files (which are appended-and-synced before the checkpoint write).

This must be designed alongside the engine, not retrofitted. The Phase 2 storage-engine spec will detail the on-disk durability boundary; this doc commits to *having* one.

The `Durability` enum on commit requests is the explicit knob: callers that need power-loss survival ask for `Synced`; callers that don't (IBD, batched recovery) get faster acks at the cost of replay-from-block-files on crash.

---

## Open questions

Documented so we don't have to re-derive them:

1. **Per-tx vs. per-block lookup batches.**
   Per-tx is simpler but limits parallelism; per-block exposes more parallelism to the storage thread but adds complexity to the validator. *Lean: per-tx for v1; revisit with profiling.*

2. **Inline `created`/`spent` lists vs. buffer-slot batches.**
   Large blocks allocate sizeable `Box<[NewCoin]>`. Worth moving to slots? *Lean: Box for v1; revisit with allocation profiling.*

3. **`Durability` per-request or per-storage-thread.**
   Per-request gives flexibility, per-thread is simpler. *Lean: per-request.*

4. **Atomic reorg vs. transaction-bracket.**
   `ApplyReorg` as one message, vs. `BeginReorg` / `Disconnect`* / `Connect`* / `CommitReorg`. *Lean: atomic-by-construction.*

5. **Single bidirectional ring vs. two unidirectional rings.**
   Two rings: ~64 KiB extra, retains spsc invariants, cleaner. *Decided: two rings.*

6. **Storage thread blocking on full response ring.**
   Storage must block (can't drop responses). It's the only drainer of the request ring, so blocking on response is self-balancing as long as `response_cap ≥ request_cap`. *Decided: equal-sized rings, storage blocks via `push_block` on response.*

---

## Deferred decisions

Things this document does *not* commit to. Phase 2 work.

- **On-disk format.** Layout of UTXO storage, undo data, block files, headers index. Subject of a separate design doc when ready.
- **Storage engine.** B-tree vs. LSM vs. custom; page allocator; WAL strategy; compaction policy.
- **Compression.** Whether and where (block bytes, undo, snapshots).
- **Pruning.** Mantle is a full node by default; pruning is post-v1.
- **Indexes.** `txindex`, address index, BIP157 compact filters — all post-v1, likely separate threads.
- **Multi-volume support.** Spreading chain data across multiple disks. Not in v1.

---

## Cross-references

- Crates underpinning this design: `ququmatz` (io_uring bindings) and `quetzalcoatl` (lock-free ring buffers).
- The networking subsystem in `mantle::peer` is the structural template — same shape (one io_uring per thread, two ring buffers for ICC, eventfd-style wakeup is the upgrade path).
- Validation pillar: `validation.md`.
- Architectural principles: `principles.md` in this directory.
