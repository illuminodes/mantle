# Validation Architecture

Status: **implemented, not yet cross-checked against Core.** Stages 1, 2 and 3 exist in `crates/consensus/src/validation/`, including script verification, the witness commitment, lock-time finality, BIP68 sequence locks and BIP141 sigop cost. Remaining gaps are listed in §"Known gaps". Subject to revision as implementation continues.

This document covers the consensus-validation subsystem: how blocks and transactions are validated, how the validator interacts with the storage layer via `ChainView`, the script-verification strategy, and the cryptographic concerns specific to using `k256` instead of `libsecp256k1`. It does *not* cover mempool *policy* (relay rules, fee filters) — those are a separate layer above consensus.

Reading order: §"Constraints" and §"Prior art" set context. §"Staged validation" is the core of the design. §"ChainView" defines the seam to storage. §"Script strategy" and §"Cryptographic concerns" are where the principles bite hardest. §"Open questions" and §"Deferred decisions" are the parking lot.

---

## Constraints

From `principles.md`:
- §1 (clean-room independence) — no shared consensus code with Core, libbitcoinconsensus, or libbitcoinkernel in the shipped node. Every consensus rule is ours to derive and implement.
- §2 (wire conformance) — validation must produce the same accept/reject verdict as Core for every block the network has ever produced. Disagreement is a chain split.
- §3 (minimal deps) — `k256` and `sha2` are imported; no other crypto libraries. Script interpreter is hand-written.
- §4 (fuzzing first-class) — every consensus-critical function has a differential fuzzer against `libbitcoinconsensus`. The shipped node has zero Core deps; the test harness uses Core as ground truth.
- §5 (thread-per-component) — validation is a thread (or coordinated thread pool); validator never touches storage internals; communicates with storage via the ring-buffer message API.

From the project state:
- The persistence subsystem (see `persistence.md`) exposes a message-passing API. The validator's view of storage is a synchronous-feeling abstraction (`ChainView`) backed by token-correlated async messages.
- `mantle` already has codec, hash, and primitive types for headers and transactions.

---

## Prior art (what to learn and what to avoid)

Three implementations are the relevant reference points. The lesson is consistent across them.

**Bitcoin Core (`src/validation.cpp`, `src/script/`).**
- The `CheckBlock` / `ContextualCheckBlock` / `ConnectBlock` separation is the single most important idea Core got right. We adopt it.
- Script and signature caches are critical — script verification dominates IBD cost. A tx validated in mempool should not re-verify when mined.
- `cs_main` is the canonical example of what not to do. We do not have an equivalent.
- `ConnectBlock` is too monolithic. Our version is staged and each stage is independently testable.

**libbitcoin.**
- Reimplemented script. Caused multiple consensus divergences against Core. *The lesson is not "don't reimplement script"* — that is exactly what we are doing — *the lesson is that reimplementing script without an industrial-grade differential test pipeline is reckless.* (See §4 of `principles.md`.)

**btcd.**
- Same pattern as libbitcoin. Soft-fork lag because they re-derived activation logic from BIPs instead of testing against Core. Script divergences as well.

The unifying lesson: clean-room consensus is not the bug. *Clean-room consensus without a differential test pipeline against Core* is the bug. Mantle commits to the test pipeline up front (`conformance.md`, to be written) so this class of failure is structurally prevented, not merely hoped against.

---

## Staged validation

A block does not get one big `validate(block) -> Result<()>` function. It moves through three stages, each with progressively more state required:

### Stage 1: Structural (stateless)

**Status: implemented** — `validation::validate_block_structure` and the zero-copy `validate_block_wire` in `crates/consensus/src/validation/structure.rs`.

Inputs: the block itself.

Checks the block is well-formed in isolation:
- At least one transaction; first is coinbase; no subsequent tx may be coinbase.
- All transactions individually well-formed: non-empty inputs/outputs, output values ≤ `MAX_MONEY` (21M BTC), total output value ≤ `MAX_MONEY`, no duplicate inputs within a tx.
- Coinbase scriptSig length in [2, 100].
- Block weight (base serialization × 4) ≤ 4,000,000 weight units.
- Transaction count ≤ 1,000,000.
- Merkle root in the header matches the computed root of the transaction list.
- Header proof-of-work satisfies the *claimed* `nBits` (whether `nBits` is *correct* requires context; that's stage 2).

The BIP141 witness commitment, and the rejection of witness data in blocks without one, are enforced in Stage 2 (`validation/witness_commitment.rs`) because they need the block height.

These checks need no chain state. They run on raw bytes. They are the first line of defense against malformed/garbage blocks from peers.

**Why isolated:** stateless validation can run on every received block immediately, in parallel, before we've decided whether to accept it. It's also the easiest stage to fuzz exhaustively.

### Stage 2: Contextual (needs headers / chain index)

**Status: implemented** — `validation::validate_block_context` in `crates/consensus/src/validation/mod.rs`.

Inputs: the block + its predecessor header chain + difficulty/time history (via `ChainView`).

Checks rules that require knowing where the block fits in the chain:
- Parent header exists in the `ChainView`.
- `nBits` matches the expected difficulty for this height: carry parent's bits between retarget intervals; at a retarget boundary (every 2016 blocks), recompute from the actual elapsed time clamped to [target/4, target×4].
- Block timestamp > median of past 11 blocks (BIP113).
- Block timestamp ≤ wall-clock now + 2 hours.
- BIP34 (height ≥ 227,931): coinbase scriptSig begins with the minimally-encoded block height.
- Historical block version minimums: version ≥ 2 at height ≥ 227,931 (BIP34), ≥ 3 at height ≥ 363,725 (BIP66), ≥ 4 at height ≥ 388,381 (BIP65).

Soft-fork activation-flag computation (BIP9/BIP8) is deferred.

This stage does not touch the UTXO set. It runs against the header chain only, so headers-first sync can advance a long way before any UTXO work is needed.

### Stage 3: Connect (needs UTXO set)

**Status: implemented** — `validation::connect_block` in `crates/consensus/src/validation/connect.rs`. Checks input existence (including same-block spends in block order and rejection of in-block double spends), coinbase maturity, BIP30 (every output, with Core's BIP34 shortcut and the two exempt blocks), BIP141 sigop cost (`sigop_cost.rs`), BIP68 sequence locks (`sequence_locks.rs`), script verification per input, fee math and coinbase reward. Lock-time finality (`IsFinalTx`) runs in Stage 2 (`tx_finality.rs`). Undo data is not produced.

Inputs: the block + chain index + the live UTXO set at the parent block.

Checks the block is consistent with the spendable-outputs state:
- Every input's outpoint exists in the UTXO set.
- Coinbase inputs spend nothing (no outpoint lookup).
- BIP30 — no duplicate transactions overwriting unspent coinbases (with carve-outs for the historical exceptions).
- Coinbase maturity (100 blocks).
- Witness program rules per script flags.
- Sigops count (legacy + witness) ≤ block sigop budget.
- Script verification per input.
- Fee math: sum of input values ≥ sum of output values; coinbase reward ≤ subsidy + fees.

Output: a "connect result" — the UTXO updates (spend list, create list), the undo info needed to disconnect the block later, and the new chainstate.

This is the expensive stage. Script verification is its dominant cost. It must be structured to allow caching, parallelism, and `assumevalid`-style skipping.

### Why three stages, explicitly

- **Each stage is independently fuzzable.** Stage 1 fuzzers don't need a chain. Stage 2 fuzzers need a header chain but no UTXO set. Stage 3 fuzzers need both.
- **Each stage fails earlier.** A block that fails stage 1 is dropped before any expensive work. Network-side DoS resistance benefits.
- **Each stage has a different concurrency profile.** Stage 1 is embarrassingly parallel. Stage 2 needs the header chain (read-mostly). Stage 3 needs UTXO reads (the storage subsystem's hot path).
- **Each stage maps to a discrete API surface** — three functions, not one — so test coverage is meaningful per-stage.

---

## `ChainView`: the storage seam

**Status: implemented** in `crates/consensus/src/chain_view.rs`.

The validator does not call into the storage thread directly. It holds a `ChainView` — a trait providing the synchronous-feeling read API the validator needs.

```rust
pub trait ChainView {
    /// Look up a coin by outpoint. Returns the coin if present in the UTXO
    /// set at the view's tip, or None if absent (spent or never existed).
    fn get_coin(&self, outpoint: &OutPoint) -> Result<Option<Coin>, ChainViewError>;

    /// Batched lookup. Order of results matches order of outpoints.
    fn get_coins(&self, outpoints: &[OutPoint]) -> Result<Vec<Option<Coin>>, ChainViewError>;

    /// Header by hash.
    fn get_header(&self, hash: &Hash256) -> Result<Option<BlockHeader>, ChainViewError>;

    /// Header by height (canonical chain only).
    fn get_header_at(&self, height: u32) -> Result<Option<BlockHeader>, ChainViewError>;

    /// Median-time-past for BIP113 calculations.
    fn median_time_past(&self, header: &BlockHeader) -> Result<u32, ChainViewError>;

    /// Tip information.
    fn tip(&self) -> TipInfo;
}
```

**The ChainView trait is the only interface validation has into storage.** It is *not* an `&dyn ChainView` from the validator's perspective at runtime — it's a concrete handle that wraps the request/response ring buffers — but the *trait* exists to make every other ChainView pluggable for tests:

- `MemoryChainView` — **implemented**; in-memory, used by unit tests, fuzzers, and BIP vector tests.
- `PrefetchedView` — **implemented** in `crates/validator`; serves the coins a block needs after one batched storage lookup, plus a `HeaderSnapshot`. This is what replay uses.
- `CoreBackedChainView` — not implemented; would wrap a running Core node's RPC for differential testing.
- `ReplayChainView` — not implemented; would read from a static snapshot for benchmarking.

This abstraction is non-negotiable. It's what lets the validator be tested without bringing up the entire stack.

### How `get_coins` becomes a `LookupCoinsReq`

The production `ChainView` implementation:

1. Validator thread calls `view.get_coins(&outpoints)`.
2. Implementation reserves `outpoints.len()` slots from the `BufferPool`.
3. Sends a `LookupCoinsReq` with the slot indices and a fresh token.
4. Parks on the response ring (`pop_block` keyed by token).
5. Storage thread fills slots, posts `LookupCoinsResp`.
6. Implementation decodes the slots into `Coin` values, recycles the slots, returns.

From the validator's perspective: synchronous call, returns when storage is ready. From the runtime's perspective: the validator thread parks, other validation work proceeds elsewhere if any. This is the same pattern as a database driver — sync API on top of async transport.

**Implication:** the validator should batch `get_coins` aggressively. One call with 2000 outpoints is one round-trip; 2000 calls with one outpoint each is 2000. Batching is per-tx initially (matches the natural validation granularity) and possibly per-block later.

---

## Script strategy

Mantle implements its own script interpreter and signature validator. This is the highest-risk part of the project.

### What we implement

A Bitcoin script interpreter, hand-written in Rust, supporting:
- All opcodes consensus-active on mainnet (legacy, BIP16 P2SH, BIP141 segwit, BIP341/342 taproot/tapscript).
- All script flags: `MANDATORY_SCRIPT_VERIFY_FLAGS`, plus the soft-fork-gated flags (`STRICTENC`, `LOW_S`, `NULLDUMMY`, `WITNESS`, `TAPROOT`, etc.) per activation height.
- Sighash variants: legacy, BIP143 (segwit v0), BIP341 (taproot).
- BIP146 (low-S, strict-DER) when activated.
- The `SIGHASH_SINGLE` "1" bug — when `nIn >= nOut`, sighash is `0x0000…0001`. Consensus rule, not a bug to fix.

### What we don't implement

- Non-standard opcodes (`OP_CAT`, etc.) that are not consensus-active. They remain `OP_RETURN`-equivalent disabled.
- Anything beyond what mainline Core enforces. (See `principles.md` §2.)

### How we test it

This is where the strategy survives or doesn't. From `principles.md` §4:

1. **Differential script fuzzer.** Generates `(script_pubkey, script_sig, witness, flags)` tuples; runs through both Mantle and `libbitcoinconsensus`; asserts identical accept/reject verdicts. Runs continuously. Any divergence is a P0 bug.
2. **BIP test vectors.** Every BIP with test vectors (66, 143, 341, 342, ...) has its vectors in our regression suite. Vectors run on every test invocation.
3. **Historical replay.** The full-history validation pipeline (see `conformance.md`) exercises every script ever committed to Bitcoin's mainnet. Cannot be skipped for a release.
4. **Curated adversarial corpus.** Known-tricky scripts: sighash edge cases, malleated signatures historically accepted, BIP66 grandfathered transactions, the 2010 value-overflow, every CVE block we can reconstruct.

The shipped node has zero `libbitcoinconsensus` dependency. The test harness has it as a dev-dependency only. This is the only honest way.

### Why not just use `libbitcoinconsensus`?

Three reasons:
1. `principles.md` §1 — clean-room implementation is the project's reason for existing.
2. The Bitcoin protocol is more valuable as a specification than as a library; reimplementing it stress-tests the specification.
3. Consensus diversity is decentralization.

This is not a shortcut decision. It commits us to the differential-fuzzing pipeline as a permanent project investment, not a one-time effort.

---

## Cryptographic concerns: `k256` vs. `libsecp256k1`

We use [`k256`](https://docs.rs/k256) for ECDSA and Schnorr operations instead of `libsecp256k1`. They agree on what counts as a valid signature *of valid inputs*. They can disagree on edge cases that consensus cares about. We must mediate every disagreement at the consensus layer.

### Known disagreement surfaces

**1. Strict DER parsing (BIP66).**
Bitcoin's DER acceptance rules are stricter than most libraries' default DER parsers. Pre-BIP66, Core accepted some non-canonical DER encodings; post-BIP66, it doesn't. Reproducing this requires:
- A custom DER validator mirroring `IsValidSignatureEncoding` in Core's `src/script/interpreter.cpp`.
- Per-block-height activation gating (different rules apply to pre-BIP66 blocks).
- Not relying on `k256`'s DER parser for consensus decisions.

**2. Low-S enforcement (BIP62 / BIP146).**
ECDSA signatures have two valid representations `(r, s)` and `(r, n - s)`. Low-S enforcement requires `s ≤ n/2`. `k256` does not enforce this by default; we enforce it ourselves, gated on script flags.

**3. Pubkey encoding tolerance.**
Pre-segwit, Bitcoin accepts compressed (33-byte), uncompressed (65-byte), and hybrid (65-byte, leading byte 0x06 or 0x07) pubkey encodings in some script flag combinations. Our wrapper around `k256` must accept exactly the encodings Core accepts at each script flag level.

**4. Schnorr / BIP340.**
Taproot uses Schnorr signatures with x-only pubkeys and tagged hashes specific to BIP340. `k256` supports Schnorr but its API conventions may differ from BIP340 in details (tagging, encoding). Verify against BIP340 test vectors *and* against historical taproot spends.

**5. SIGHASH_SINGLE bug.**
Already mentioned. When `nIn >= nOut`, sighash returns `0x0000…0001`. Has historical real-world spends that depend on this. Our sighash code reproduces the bug; we do not "fix" it.

### Wrapper layer

These concerns argue for a thin Mantle-owned wrapper around `k256` rather than calling `k256` directly from script:

```rust
pub mod consensus_crypto {
    /// Verify an ECDSA signature with consensus-grade checks.
    /// Performs strict DER if `flags.contains(STRICTENC)`, low-S if `flags.contains(LOW_S)`,
    /// and respects all the pre-BIP66 grandfathering rules.
    pub fn verify_ecdsa(
        sig: &[u8], pubkey: &[u8], msg: &[u8; 32], flags: ScriptFlags,
    ) -> Result<(), CryptoError>;

    pub fn verify_schnorr(
        sig: &[u8], pubkey_xonly: &[u8; 32], msg: &[u8; 32],
    ) -> Result<(), CryptoError>;
}
```

The wrapper is the only place that directly touches `k256`. Script calls into the wrapper; the wrapper enforces consensus-grade encoding and value rules; only after those checks does it pass to `k256`. This isolates the cryptographic-library-disagreement risk to one module.

---

## Caches

Script verification dominates IBD cost. Caching is not optional.

### Script-execution cache

Keyed on `(wtxid, input index, spent amount, spent scriptPubKey, flags)`; stores successes only. The spending transaction must be part of the key: signatures commit to it, so a key without it lets a signature from one transaction validate another. Hits when:
- A tx is validated in mempool, then mined into a block (block validation hits the cache).
- A tx is validated as part of one block, then a near-identical block is also considered (rare on tip but happens during forks).

Size: bounded LRU; invalidation by capacity only, not by chain reorg (entries are pure functions of inputs).

### Signature cache

Keyed on `(sighash, signature, pubkey)` → `accept/reject`. Hits a strict subset of script-cache hits but is also useful when the same signature appears in multiple scripts (rare but possible).

### Header cache

Validated headers, indexed by hash and height. Already implicit in the chain-state structure but worth naming.

### `assumevalid`

A configurable block hash; ancestors of the assumed-valid hash skip script verification but still do all other consensus checks. Pragmatic acknowledgement that historical script verification has been done by everyone with a node since the beginning of time, and re-doing it during IBD is the dominant cost. *Optional*; default is set to a recent well-known block; can be disabled with a config flag.

---

## Mempool / block validation: same inner check

A long-known footgun in Core is that mempool validation and block validation share *some* logic but have diverged enough that bugs hide in the seam. CVE-2018-17144 (the inflation bug) lived partly in this gap.

Mantle's stance: **the consensus check is one function called from two policies.**

- `consensus::check_transaction(tx, view, flags) -> Result<(), Error>` — the inner check. Same code whether called from mempool admission or block connection.
- Mempool layer adds *policy* on top: fee thresholds, RBF rules, package limits, ancestor counts, dust rules. None of those are consensus.
- Block validation layer adds *block-level* checks: merkle, witness commitment, total fee budget, sigop budget. Calls `check_transaction` for each tx.

If a check exists in one but not the other, that's a design bug to be fixed, not a difference to be preserved. Reviewers should reject any PR that adds a consensus check on only one side.

---

## Concurrency

The validator's runtime model:

- One **coordinator** thread drives validation. It owns the `ChainView` handle (the producer side of the storage request ring), the chain index, and the in-progress block state.
- A **script-verify worker pool** receives parallel script-verification jobs from the coordinator. Each job is `(scriptSig, scriptPubKey, witness, amount, flags, sighash)` → `accept/reject`. Workers are stateless; they just compute.
- The coordinator gathers results, applies them to the in-progress block state, and emits commit messages to storage.

Communication:
- Coordinator → workers: `quetzalcoatl::spmc` ring (`ScriptJob`).
- Workers → coordinator: `quetzalcoatl::mpsc` ring (`ScriptResult`).
- Coordinator → storage: SPSC pair already specified in `persistence.md`.

This means the coordinator is the only thread interacting with storage. The workers do not have a `ChainView`; they get all the data they need handed to them in the job. This is deliberate — it keeps the storage seam clean and the workers trivially testable.

---

## Open questions

1. **Granularity of coordinator → workers script jobs.**
   Per-input is simplest; per-tx might amortize setup. *Lean: per-input for v1; revisit with profiling.*

2. **`assumevalid` default behavior.**
   Set a recent hash baked into releases vs. require explicit user opt-in. *Lean: set a default, document how to disable, consistent with Core.*

3. **Cache sizes.**
   How much memory to budget for script-cache and signature-cache. *Lean: configurable, defaults inspired by Core's, revisit with profiling.*

4. **Mempool placement.**
   Is mempool a separate thread, or part of the validation coordinator? Mempool admission is a frequent operation under tip-following; if it shares the coordinator thread it competes with block validation. *Lean: separate thread post-v1; for v1, share the coordinator since IBD doesn't have a mempool.*

5. **Block validation cancellation.**
   If a competing block at the same height arrives during validation of block A, do we cancel A's in-progress script jobs? *Lean: yes; needs a job-cancel path through the worker pool. Workers should check a per-job cancel flag periodically.*

6. **Header chain mutation discipline.**
   The header chain is read-mostly. Multiple readers (validator coordinator, network thread for headers responses, mempool) want to consult it; one writer (validator coordinator) extends it. *Lean: epoch-based reclamation or copy-on-write; explicitly *not* an `RwLock`.*

---

## Deferred decisions

Things this document does *not* commit to:

- **The exact script-cache eviction policy.** LRU is the obvious starting point; segmented LRU or a TinyLFU variant might be better with profiling.
- **Mempool architecture.** Policy rules, fee estimation, RBF, package validation. Whole separate doc.
- **RPC surface.** Once validator and storage are running, what queries do we expose? Doc per RPC family.
- **Sync strategies.** Headers-first is the default; assume the simple version for v1. Compact-block relay (BIP152) and parallel block download are post-v1.
- **Specific storage representation.** Validator only sees `ChainView`; the storage engine's on-disk format is `persistence.md`'s problem.

---

## Known gaps

Rules that differ from Core or are unverified. None of the block-level rules has been compared against Core on real chain data yet; see `conformance.md` §"Current coverage".

- **Block weight**: Stage 1 computes weight from the owned `Block`; the zero-copy `validate_block_wire` path counts base size only.
- **Network parameters**: soft-fork activation heights (`ScriptFlags::for_height`, BIP34/65/66 in `pow.rs`) are mainnet values. `mantle-replay` refuses to validate testnet and signet until per-network parameters exist.
- **BIP9/BIP8 deployment state** is not evaluated; activations are fixed heights.

Script flags are by height rather than Core's "on from genesis, minus two exempt blocks". On mainnet both give the same flags for every block: the two exempt blocks (170,060 and 692,261) are below the P2SH and taproot activation heights. `tests_script_flag_history` checks both exempt spends.

---

## Cross-references

- The storage seam is specified in `persistence.md` (this directory). Validator never bypasses `ChainView`.
- The conformance test infrastructure is specified in `conformance.md`. The `mantle-conformance` crate and the script differential fuzzer (`fuzz_script_differential`) are both active.
- Architectural principles: `principles.md` (this directory).
- `mantle` has the codecs, header types, and primitive types this design assumes. The validator lives in the `consensus` crate, which imports `mantle` without circular dependencies.
