# Replay Architecture

Status: **implemented (v1)** in `crates/storage`, `crates/validator` and `replay/`. Not implemented: `--assume-valid` (parsed, ignored), UTXO-set hash comparison, reorg handling, and per-network consensus parameters (activation heights are mainnet values). Blocks come from P2P peers via `crates/fetcher`. The text below is the original design. The companion to `persistence.md`:
where `persistence.md` specifies the storage thread in isolation,
this document specifies the three-crate seam (`storage` / `validator` /
`replay`) that closes the M5 gate by running Stage 3 historical replay end
to end.

Reading order: §"Goal and non-goals" and §"Topology" first if you want the
shape; §"Crates" next for the file-level decomposition; §"Topology
revision to persistence.md" if you maintain that doc and want to know what
changes.

---

## Goal and non-goals

**Goal.** Stand up the smallest correct concurrent foundation that turns
`connect_block` into a process that survives restarts. Sufficient to drive
Stage 3 replay (mainnet, full script) on a single machine with multi-day
runtime acceptable, per the M5 exit criterion in `script.md`.

**Non-goals (explicit deferrals).**

- N / N+1 pipelining and write-through delta layers.
- Script-worker thread pool (parallel script verification).
- B-tree / WAL / page-allocator on-disk engine — v1 uses a flat-file shim
  behind an `Engine` trait.
- Async `ChainView`. Stays synchronous; async happens at the prefetch
  boundary, not inside `connect_block`.
- `PendingTable[token & MASK]` parking lot — added when more than one
  in-flight response consumer exists.
- Live-node validator thread. The validator crate exists; its thread does
  not yet.

The architectural goal is the right thread/ring seam. Throughput
optimisations land on top of that seam without re-shaping it.

---

## Topology

Three new crates, three threads, two ring pairs:

```
   ┌─────────────────┐      req ring (mpsc)      ┌─────────────────┐
   │   replay bin    │ ────────────────────────▶ │ storage thread  │
   │ (fetcher loop)  │ ◀──────────────────────── │  (own IoUring)  │
   └────────┬────────┘    resp ring (spsc)       └─────────────────┘
            │  in-process call (sync)                     ▲
            ▼                                             │
   ┌─────────────────┐ ───── StorageHandle ────────────── ┘
   │ validator crate │  (lookup_coins, commit_block, …)
   │  PrefetchedView │
   │  connect_block  │
   └─────────────────┘
```

Threads are bare `std::thread`; no `tokio`, no `crossbeam`.

1. **Replay thread** (binary main). Fetches block bytes, drives the loop,
   owns the `StorageHandle`. Coordinator role.
2. **Validator** is *not* a thread in v1 — a library called synchronously
   from the replay thread. The boundary is a separate crate so the live-node
   binary can later promote it onto its own thread without re-shaping any
   API.
3. **Storage thread**. Owns one `ququmatz::IoUring`, drives all file I/O,
   parks on `submit_and_wait(1)`, wakes on the request-ring eventfd.

### Why this earns "proper foundations"

- The seam is a ring pair, not a function call. Moving the validator
  off-thread later is a topology change, not an API change.
- Coin lookups are batched once per block via `PrefetchedView`. The replay
  thread sends one `LookupCoinsReq` covering every input the block will
  spend, parks on the response, builds the view, then calls `connect_block`
  synchronously. Per-input round-trips are gone.
- `ChainView` stays synchronous. `connect_block` is unchanged. Tests using
  `MemoryChainView` keep working.

### Topology decisions

- **Request ring.** `quetzalcoatl::mpsc::RingBuffer<StorageReq>`,
  capacity 1024. v1 has only the replay thread as a producer, but
  committing to MPSC now means the future live-node validator + P2P +
  mempool threads can push without re-typing the seam. Cost is one FAA
  per push.
- **Response ring.** `quetzalcoatl::spsc::RingBuffer<StorageResp>`,
  capacity 1024. The replay thread is the sole consumer.
- **Wakeup.** Storage thread keeps a standing `Sqe::read` on its own
  `EventFd`. Producers write 1 to the eventfd after every push. Eventfd is
  a counter — multiple writes coalesce into one wake. v1 writes
  unconditionally; the "observed_was_empty" elision is a follow-up.
- **Per-token waiting.** v1 issues one outstanding request at a time. The
  replay thread parks by reading the response ring directly, or by blocking
  on the response-ring eventfd via its own small `IoUring` — mirroring the
  peer event loop in `crates/transport`. No
  condvars, no parking-lot in v1.

### Topology revision to `persistence.md`

That doc commits to SPSC-both-ways for v1. This document upgrades the
**request** ring to MPSC; the **response** ring stays SPSC. Message types,
buffer pool, durability chains, and the `StorageReq`/`StorageResp`
enumerations are unchanged. Per-token parking is deferred until v1 grows a
second response consumer.

---

## Crates

### `crates/storage`

```
crates/storage/
├── Cargo.toml
└── src/
    ├── lib.rs            re-exports
    ├── types.rs          StorageReq, StorageResp, StorageOp, ReqToken,
    │                     StorageError, Durability, NewCoin,
    │                     CommitBlockReq, CommittedResp,
    │                     LookupCoinsReq, LookupCoinsResp, LookupResult,
    │                     ReadHeaderReq, ReadHeaderResp,
    │                     TipState, TipInfo
    ├── buffer.rs         BufferPool, BufferSlot, PooledBuffer<'pool>
    ├── thread.rs         StorageThread: owns IoUring + rings + Engine + eventfd
    ├── handle.rs         StorageHandle: producer-side API
    └── engine/
        ├── mod.rs        Engine trait
        └── flat.rs       FlatEngine: Phase 1 shim
```

No `pending.rs` in v1. No `chain_view.rs` here — the `ChainView` impl lives
in `crates/validator` because that's the consumer.

#### `Engine` trait — the future-proof seam

```rust
pub trait Engine {
    fn read_coin(&self, op: &OutPoint) -> Result<Option<Coin>, EngineError>;
    fn read_coins(&self, ops: &[OutPoint], out: &mut Vec<LookupResult>)
        -> Result<(), EngineError>;
    fn write_block(&mut self, b: &CommitBlockReq) -> Result<(), EngineError>;
    fn read_header(&self, hash: &Hash256)
        -> Result<Option<BlockHeader>, EngineError>;
    fn read_header_at(&self, h: BlockHeight)
        -> Result<Option<BlockHeader>, EngineError>;
    fn write_header(&mut self, h: BlockHeight, header: &BlockHeader)
        -> Result<(), EngineError>;
    fn flush(&mut self, d: Durability) -> Result<(), EngineError>;
    fn recover(&mut self) -> Result<TipInfo, EngineError>;
    fn tip(&self) -> TipInfo;
}
```

`FlatEngine` is one implementation. The Phase 2 B-tree engine plugs in
here without touching the storage thread, the message types, or the
validator.

#### `FlatEngine` — v1 shim

- `utxo.bin` — append-only log of `(OutPoint, Option<Coin>)` records
  (`Some` = create, `None` = spend). In-memory `HashMap<OutPoint,
  file_offset>` index; ~2–3 GB RAM at mainnet UTXO scale, acceptable for a
  dedicated replay machine. Rebuilt from the log up to `checkpoint.bin` on
  startup.
- `headers.bin` — fixed-width 116-byte records (hash 32 + header 80 +
  height 4) at sequential offsets keyed by height. In-memory
  `HashMap<Hash256, u32>` for hash → height.
- `blocks.bin` + `blocks.idx` — raw block bytes appended; index file maps
  height → (offset, len). Lets replay re-read a block on crash recovery.
- `checkpoint.bin` — last height for which `Durability::Synced` completed.
  Recovery ignores records beyond the checkpoint.

#### Storage thread event loop

Identical in shape to `Node::poll_or_timeout`:

```rust
loop {
    while let Some(req) = self.req_rx.pop() {
        self.dispatch(req)?;          // engine call + push response
    }
    self.ring.submit_and_wait(1)?;    // blocks on eventfd CQE
    while let Some(cqe) = self.ring.complete() { /* ack eventfd */ }
}
```

Dispatch is *synchronous* against `Engine` in v1, because `FlatEngine` is
synchronous. Wrapping a sync engine in async io_uring SQEs is theatre.
When the Phase 2 engine arrives, *that* engine submits SQEs and the loop
drains real CQEs. The interface is shaped right; only the body grows.

#### Public API

```rust
pub struct StorageHandle {
    req_tx: quetzalcoatl::mpsc::Producer<StorageReq>,
    resp_rx: quetzalcoatl::spsc::Consumer<StorageResp>,
    wake: Arc<EventFd>,
    tip: Arc<TipState>,
    next_token: u64,
}

impl StorageHandle {
    pub fn open(data_dir: &Path) -> Result<Self, StorageError>;
    pub fn lookup_coins(&mut self, ops: &[OutPoint])
        -> Result<Vec<LookupResult>, StorageError>;
    pub fn read_header(&mut self, hash: Hash256)
        -> Result<Option<BlockHeader>, StorageError>;
    pub fn read_header_at(&mut self, h: BlockHeight)
        -> Result<Option<BlockHeader>, StorageError>;
    pub fn commit_block(&mut self, req: CommitBlockReq)
        -> Result<CommittedResp, StorageError>;
    pub fn tip(&self) -> TipInfo;
    pub fn shutdown(self) -> Result<(), StorageError>;
}
```

Each call: take next token, push request, write 1 to the eventfd, park on
the response-ring eventfd via a small local `IoUring`. v1 issues one
in-flight request at a time, so token matching is trivial. When that
changes, add a `PendingTable[token & MASK]` slot array and keep the same
call shape.

### `crates/validator`

A library crate. Owns the validation seam *between* raw `connect_block`
and the storage handle. v1 has no thread of its own; the replay binary
calls into it synchronously.

```
crates/validator/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── prefetched_view.rs   PrefetchedView<'a>: implements ChainView
    └── pipeline.rs          validate_and_commit(...) helper
```

#### `PrefetchedView`

```rust
pub struct PrefetchedView<'a> {
    coins: PrehashedMap<OutPoint, Option<Coin>>,
    headers: &'a HeaderSnapshot,
    tip: TipInfo,
}

impl ChainView for PrefetchedView<'_> {
    fn get_coin(&self, op: &OutPoint) -> Result<Option<Coin>, ChainViewError> {
        self.coins.get(op).cloned().ok_or(ChainViewError::PrefetchMiss)
    }
    /* headers / MTP delegate to the snapshot */
}
```

`PrefetchMiss` is a programmer error, not a runtime condition. It means
the prefetcher missed an outpoint the block actually consumes — fail
loud.

#### `validate_and_commit`

The single entry point the replay binary calls per block:

```rust
pub fn validate_and_commit(
    block: &Block, height: BlockHeight,
    storage: &mut StorageHandle, headers: &HeaderSnapshot,
    skip_script: bool, exec_cache: Option<&mut ScriptExecutionCache>,
    durability: Durability,
) -> Result<CommittedResp, ValidationOrStorageError> {
    let outpoints = collect_inputs_minus_intra_block(block);
    let coins = storage.lookup_coins(&outpoints)?;
    let view = PrefetchedView::build(coins, headers, storage.tip());
    let mut scratch = Vec::new();
    let result = connect_block(block, height, &view, &mut scratch,
                               skip_script, exec_cache)?;
    storage.commit_block(CommitBlockReq {
        height,
        hash: block.hash(),
        prev_hash: block.header.prev_block,
        created: result.created,
        spent: result.spent,
        block_bytes: None,
        durability,
    })
}
```

Intra-block dependencies (tx N spends an output created by tx M < N in
the same block) are subtracted before the lookup *and* re-added to the
view. Easy to get wrong; covered by a fuzz test.

### `crates/replay`

Binary crate (`mantle-replay`). Drives Stage 3.

```
crates/replay/
├── Cargo.toml
└── src/
    ├── main.rs        CLI, opens StorageHandle, runs the loop
    ├── fetcher.rs     P2P block fetcher (cached on disk)
    └── report.rs      progress logging
```

#### Loop

```text
for height in start..=target:
    hash  = storage.read_header_at(height)?.hash
    raw   = fetcher.get_block(hash)?
    block = Block::decode(&raw)?
    validate_block_structure(&block)?
    validate_block_context(&block, height, &header_snapshot)?
    validator::validate_and_commit(
        &block, height, &mut storage, &header_snapshot,
        skip_script, Some(&mut exec_cache),
        if height % 2016 == 0 { Synced } else { Queued },
    )?
```

The header chain is seeded on first run via the `getheaders` flow in
`crates/fetcher` and stored in `headers.bin`. Subsequent runs read
headers from storage.

CLI flags: `--data-dir`, `--peer`, `--skip-script`, `--assume-valid
<hash>`, `--stop-height <N>`. The script flags map to `connect_block`'s
existing `skip_script` parameter.

---

## Workspace

`Cargo.toml` `[workspace] members` gains:

```toml
"crates/storage",
"crates/validator",
"replay",
```

`[workspace.dependencies]` already has `ququmatz` and `quetzalcoatl`. No
new external deps.

---

## Implementation order

- **S1.** `crates/storage`: `types.rs`, `buffer.rs`. Compile-only. Unit
  tests for buffer-pool reserve/recycle.
- **S2.** `crates/storage`: `engine/flat.rs`, synchronous, no io_uring.
  Tests: write a coin, reopen, read it back; 1 000 headers round-trip;
  partial-record crash recovery.
- **S3.** `crates/storage`: `thread.rs` + `handle.rs`. Wire `FlatEngine`
  behind the ring seam. Tests: `lookup_coins` and `commit_block`
  round-trips from another thread; `Durability::Memory` for speed.
- **S4.** `crates/validator`: `PrefetchedView`, `validate_and_commit`.
  Integration test: pre-seed UTXOs via `StorageHandle`, run a known-good
  block, verify `CommittedResp`, re-query to confirm delta. Fuzz test for
  intra-block dependency subtraction.
- **S5.** `crates/replay`: fetcher + main loop. Smoke test: first 1 000
  blocks `--skip-script`. Then full Stage 2 (`--skip-script` to tip).
  Then full Stage 3.

## Verification

```bash
cargo test -p mantle-storage
cargo test -p mantle-validator

# replay smoke (first 1 000 blocks, no script)
cargo run -p mantle-replay -- \
    --data-dir /tmp/mantle-replay \
    --peer <seed-peer-ip>:8333 \
    --skip-script --stop-height 1000

# full Stage 2
cargo run -p mantle-replay -- --data-dir /tmp/mantle-replay --skip-script

# full Stage 3 — closes the M5 gate
cargo run -p mantle-replay -- --data-dir /tmp/mantle-replay
```

Stage 3 completing end to end with a UTXO-set hash matching a reference
implementation closes M5.

---

## Cross-references

- `script.md` §"M5 exit criteria" — the gate this plan closes.
- `persistence.md` §"Storage thread architecture" — message types and
  buffer pool, unchanged. §"Topology" should be updated to note the
  request ring is MPSC in v1; see §"Topology revision" above.
- `principles.md` §5 (thread-per-component) — the basis for the
  three-thread topology.
- `crates/consensus/src/validation/connect.rs` — `connect_block` is
  called unmodified.
- `crates/transport` — template for the storage thread event loop and
  the response-ring eventfd park.
