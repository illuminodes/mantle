# Conformance and Test Infrastructure

Status: **partially implemented.** Layers 1–4 exist. Layer 5 exists as `mantle-replay` validating blocks fetched from peers, with UTXO-set MuHash comparison against Core values supplied by the operator (Stage 4 below). No reference values are committed to the repo yet. `mantle-blkdat`, reorg replay and the regression block corpus are not implemented. §"Current coverage" lists what is compared against Core today. Subject to revision as implementation continues.

This document specifies the test infrastructure that makes Mantle's clean-room consensus implementation viable. It is the operationalization of `principles.md` §4 ("Fuzzing and historical replay as first-class infrastructure") and the precondition that `validation.md` names: *we do not write production script code before the differential fuzzer can run.*

This is treated as core code, not a `tests/` afterthought. The crates and pipelines specified here are first-class engineering investments with their own ongoing maintenance budget.

Reading order: §"Why this exists" if you need the motivation. §"Layered test strategy" is the architecture. §"Crates" describes the concrete code units. §"CI strategy" is operational. §"Open questions" parks the unresolved bits.

---

## Why this exists

Two clean-room Bitcoin implementations in the past decade — libbitcoin and btcd — shipped consensus divergences against Core. Both projects had tests. Both projects had careful authors. Both projects shipped consensus bugs anyway, because the tests they had were not the right kind of tests.

The right kind of tests for a clean-room consensus implementation are:
1. **Differential** — every consensus-critical function compared against `libbitcoinconsensus` for every input that survives a fuzzer.
2. **Historical** — every block ever committed to mainnet is validated end-to-end. UTXO state hashes are compared against Core's at fixed checkpoints.
3. **Adversarial** — the entire library of historically-tricky blocks (CVE attempts, BIP66 grandfathering edge cases, the 2010 value-overflow incident, etc.) is a regression suite.

Mantle commits to all three, up front. Without them, our implementation strategy is reckless. With them, it is rigorous. The crates and pipelines in this document are not optional.

---

## Current coverage

What is checked against Bitcoin Core today, and what is not.

| Surface | Compared against Core | How |
|---|---|---|
| Script verification, per input | Yes, accept/reject only | `fuzz_script_differential` vs `bitcoinconsensus` 0.106 (Core v26) |
| Script flag activation heights (mainnet) | Yes | proptest vs `bitcoinconsensus::height_to_flags` |
| CSV edge cases | Yes | `fuzz/tests/csv_oracle_probe.rs` matrix |
| Known fuzzer crashes | Yes, replayed | `fuzz/tests/regression.rs` over `fuzz/tests/regression/` |
| Taproot and tapscript verification | Yes, all 2,244 cases agree | `conformance/tests/script_assets/` over Core's `script_assets_test.json` (qa-assets `bd0ccbd`), run in CI before the replay |
| Every mainnet block, genesis to 972,245 | Accepted, as Core did; 0 failures | `mantle-replay` from genesis with all scripts, CI job `full-chain-verify` on commit `d66dadd` |
| BIP vectors | Against BIP-published expectations, not Core | `conformance/tests/bip_vectors/` |
| MuHash3072 algorithm | Yes | Core's `crypto_tests` vectors in `crates/utxo-hash` |
| UTXO set after replay | When reference values are supplied | `mantle-replay --utxo-hash-file`, against `gettxoutsetinfo muhash <height>` |
| Block structure, context, connect | Valid mainnet blocks only (full replay); rejection of invalid blocks is not compared | — |
| Error kinds | No | — |

Limits of the current reference: `libbitcoinconsensus` was removed from Core in v28, so the `bitcoinconsensus` crate is frozen at v26 and covers only script verification. The UTXO-set hash covers the result of every block rule, but only for blocks Core accepted: it cannot show that Mantle rejects an invalid block. `libbitcoinkernel` would cover that.

---

## Layered test strategy

Five layers, in order of cost and depth.

### Layer 1: Structural fuzzers

`cargo-fuzz` targets that feed arbitrary bytes into parsers. Present in `fuzz/fuzz_targets/` for varint, primitives, and network messages. These catch panics, OOBs, and parser crashes. Necessary but not consensus-validating.

**Status:** implemented and ongoing. Targets: `fuzz_varint`, `fuzz_primitives`, `fuzz_network`.

### Layer 2: Differential fuzzers (consensus-critical)

The load-bearing layer. For each consensus-critical function, a fuzz target that:
1. Generates an input.
2. Runs it through Mantle.
3. Runs the same input through `libbitcoinconsensus` (via the `mantle-conformance` crate; see below).
4. Asserts identical accept/reject verdicts.

Targets in priority order:
- **Script interpreter and signature validation** — **implemented** in `fuzz/fuzz_targets/fuzz_script_differential.rs` (logic in `fuzz/src/lib.rs`). Decodes an arbitrary transaction, takes arbitrary spent outputs and flags masked to the consensus set, and asserts Mantle and `bitcoinconsensus` agree on accept/reject for every input. Both sides receive the same spent-output table, so taproot is compared when the table covers every input. Error kinds are not compared.
- **Transaction/block validation** (`CheckTransaction`-equivalents, merkle, weight, difficulty arithmetic) — not compared against Core. `libbitcoinconsensus` exposes only script verification.
- BIP9/BIP8 deployment-state evaluation — not implemented.

**Constraint:** any divergence is a P0 bug. The fuzzer must be running continuously somewhere with corpus persistence; CI runs a time-boxed sample of the corpus on every commit.

### Layer 3: Property-based tests

`proptest` for things with algebraic properties. **Implemented** in `conformance/tests/proptest.rs`:
- Codec roundtrip: `decode(encode(x)) == x` for `VarInt`, `BlockHeader`, `Transaction`, `Block`.
- `VarInt` canonicality: re-encoding a decoded value produces identical bytes; `encoded_len` matches actual byte count.
- Merkle tree: determinism, single-tx identity root, empty-slice returns `None`, odd-length duplicate invariant (≥ 3 txids).
- `flags_for_height` agrees with `bitcoinconsensus::height_to_flags` across heights 0..=900,000.
- The cached script verifier returns the same result as the uncached one, cold and warm.

`proptest` over `cargo-fuzz` here because shrinking matters and the time budget is bounded (these run every CI invocation, not continuously).

### Layer 4: BIP test vectors and adversarial corpus

Static test corpora hand-encoded as constants in the test binary — no runtime file I/O. **Implemented** in `conformance/tests/bip_vectors/`:
- Genesis block decode, hash, and txid match against known-good constants.
- Stage 1 rejection vectors: empty block, missing coinbase, null outpoint in non-coinbase tx, coinbase scriptSig length bounds, output value over `MAX_MONEY`, duplicate inputs, merkle root mismatch, invalid nBits, insufficient PoW.
- Stage 2 rejection vectors: unknown parent, unexpected difficulty, timestamp ≤ MTP, BIP34 height missing, block version too low.
- Stage 2 acceptance: BIP34-correct coinbase encoding, pre-BIP34 blocks, version boundary values.
- Genesis coinbase codec roundtrip, txid verification, null-outpoint structure.
- Sequence-field codec fidelity across all boundary values.
- `MemoryChainView` UTXO lifecycle (insert, lookup, spend, coinbase flag).

- Script-level vectors for BIP65, BIP66, BIP112, BIP143, BIP340, BIP341 and BIP342, including multi-input taproot and a real mainnet `SIGHASH_SINGLE|ANYONECANPAY` spend from block 767,434.

The design-era mention of consuming `tx_valid.json` / `tx_invalid.json` at runtime is superseded: vectors are inline constants, which is simpler and has no file-system dependency.

Runs on every `cargo test`. Fast.

### Layer 5: Historical replay

The full mainnet chain validated end-to-end against Mantle. Multiple stages of increasing thoroughness, described in §"Historical replay pipeline" below.

---

## Crates

Three new crates, each with a tightly scoped responsibility. All three are dev-only (or test-only); the shipped node never depends on any of them.

### `mantle-conformance`

**Status: implemented** at `conformance/`.

The differential-test glue, and the only crate that depends on `bitcoinconsensus`. `bench` reaches Core through it as a dev-dependency; no node crate depends on either. Uses the `bitcoinconsensus = "0.106.0"` crate, which bundles the Bitcoin Core v26 C++ source and builds it as part of `cargo build` — no system library dependency, pinned to a specific Core version, reproducible on any machine.

**Public surface (actual):**

```rust
pub mod conformance {
    // Re-exported script-flag constants from bitcoinconsensus v26:
    pub use bitcoinconsensus::{
        VERIFY_P2SH, VERIFY_DERSIG, VERIFY_NULLDUMMY,
        VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY,
        VERIFY_WITNESS, VERIFY_TAPROOT, VERIFY_NONE, Utxo,
    };

    pub type ScriptFlags = u32;

    pub struct ConformanceError(pub String);

    /// Verify a script using libbitcoinconsensus v26. Bug-compatible with Core v26.
    /// `spent_outputs` is required for taproot inputs (pass None to get
    /// ERR_SPENT_OUTPUTS_REQUIRED from both sides rather than a divergence).
    pub fn verify_script(
        script_pubkey: &[u8],
        amount: u64,
        tx_to: &[u8],
        spent_outputs: Option<&[Utxo]>,
        n_in: usize,
        flags: ScriptFlags,
    ) -> Result<(), ConformanceError>;

    /// Script flags appropriate for a given block height (mainnet activations).
    pub fn flags_for_height(height: u32) -> ScriptFlags;

    /// Version string of the linked bitcoinconsensus, for CI logging.
    pub fn linked_version() -> &'static str;
}
```

**Note on build approach:** the design document anticipated two options (pinned source build vs. system library). The `bitcoinconsensus` crate eliminates this choice — it always builds from its bundled pinned source. This is strictly better than the system-library option and simpler than a custom build-script.

**Constraint:** this crate is never in the dependency tree of the production node. It appears only as a dependency of `mantle-fuzz`, `mantle-bench` (dev) and its own tests. It is never a dependency of `mantle`, `mantle-consensus`, `mantle-validator` or `mantle-replay`.

### `mantle-blkdat`

**Status: not implemented.** `mantle-replay` fetches blocks over P2P instead (`crates/fetcher`, `crates/block-io`). Design below is unchanged.

A reader for Bitcoin Core's `blocks/blk*.dat` files. The format is documented and stable; we parse it directly, not via a Core RPC call.

**Public surface (sketch):**

```rust
pub struct BlockDirReader { /* ... */ }

impl BlockDirReader {
    /// Open a Core-format blocks directory.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, BlkDatError>;

    /// Iterate (height, raw_block_bytes) pairs in chain order.
    /// Reorders out-of-order blocks based on prev_hash linkage.
    pub fn iter_blocks(&self) -> impl Iterator<Item = Result<(u32, Vec<u8>), BlkDatError>>;
}
```

**Why a directory reader rather than RPC:**
- Faster — no network or process boundary.
- No dependency on a running Core process during tests.
- Format is essentially append-only; concurrent reads are safe while a Core node is writing (we just don't see blocks newer than what's been flushed).

**Constraint:** `mantle-blkdat` does not depend on `mantle` types. It returns raw bytes. Decoding into `Block` is the consumer's responsibility — keeps the test crate's compile graph clean and lets us swap the consumer's decoder without touching the reader.

### `mantle-replay`

**Status: implemented differently.** `replay/` is a binary, not a library harness. It fetches blocks from P2P peers, runs Stage 1, Stage 2 and `connect_block`, and commits to `RobinHoodEngine` storage. It has no stage selection and no snapshot diffing; the only comparison against Core is the optional UTXO-set MuHash (`--utxo-hash-file`). `--assume-valid` is refused. A full run from genesis to 972,245 with every script checked completed with no failures. The sketch below is the original design.

The harness that drives the historical-replay pipeline. Consumes `mantle-blkdat`'s block iterator, drives Mantle's validator through each stage, optionally compares against Core via `mantle-conformance` and via UTXO snapshots.

**Public surface (sketch):**

```rust
pub struct ReplayHarness { /* config */ }

impl ReplayHarness {
    pub fn new(blocks_dir: impl AsRef<Path>, config: ReplayConfig) -> Result<Self, _>;
    pub fn run(&mut self) -> ReplayReport;
}

pub enum ReplayStage {
    HeadersOnly,
    NoScript,
    Full,
    UtxoSnapshot { every_n_blocks: u32 },
    ReorgReplay,
    AdversarialCorpus,
}

pub struct ReplayReport {
    pub blocks_processed: u32,
    pub stage_durations: HashMap<ReplayStage, Duration>,
    pub divergences: Vec<Divergence>,
}
```

The harness is configured to run any subset of stages; CI invokes it with stage subsets matched to the run frequency (see §"CI strategy").

---

## Historical replay pipeline

The stages, in cost order. Each one is independently runnable; later stages assume earlier ones pass.

### Stage 0: Block source

Done by `mantle-blkdat`. Streams `(height, raw_block)` in chain order from a Core-format blocks directory. The directory is provided by the operator (a Core node run separately, syncing in the background).

### Stage 1: Headers-only replay

Validates the entire header chain end-to-end:
- Difficulty retargeting arithmetic.
- Median-time-past computations (BIP113).
- Version-bits / BIP9 deployment state evolution.
- Timestamp rules.

**Cost:** seconds-to-minutes on the full chain. Cheap.

**Frequency:** every CI run on `main`.

**Why first:** catches a huge class of bugs before any UTXO work. Header validation has its own subtle correctness traps (off-by-one errors in retarget windows, MTP edge cases) and isolating them at this stage simplifies diagnosis.

### Stage 2: Block validation without script

Connect every block, update the UTXO set, validate everything *except* script execution:
- All structural checks (Stage 1 of `validation.md`).
- All contextual checks (Stage 2 of `validation.md`).
- All Stage-3 checks except `verify_script`: BIP30, coinbase maturity, sigops counts, witness commitment, fee math.
- UTXO state transitions.

**Cost:** under an hour on commodity hardware on the full chain. Memory-bound, not CPU-bound.

**Frequency:** every CI run on `main`.

**Why second:** isolates non-cryptographic consensus rules. If something fails here, it's a logic bug, not a script bug — a much smaller search space.

### Stage 3: Full validation (with script)

Stage 2 + every script verification. This is the big one.

**Cost:** multi-day on commodity hardware. Days to weeks under fuzzer-style coverage.

**Frequency:** every release candidate. Continuously on a dedicated machine. Not every CI run.

### Stage 4: UTXO snapshot diffing

**Implemented:** `crates/utxo-hash` (`MuHash3072`, `UtxoSetHash`), applied per block by `UtxoHashUpdate` in `crates/validator`, checked by `mantle-replay --utxo-hash-file PATH`. The hash is maintained incrementally from genesis exactly as Core's coinstats index maintains it: unspendable outputs are skipped, coins created and spent in one block never enter, and the coinbases of blocks 91,722 and 91,812 (`IsBIP30Unspendable`) are left out. The reference file holds `<height> <muhash>` lines from `bitcoin-cli gettxoutsetinfo muhash <height>` on a node running `-coinstatsindex`. A mismatch is reported as a `utxo-hash` consensus failure. Tracking stops after a keep-going forced commit, because that block's prior coins are unknown. Not yet done: a committed reference set, and resuming the hash across replay restarts (`--utxo-hash-*` requires `--start-height 1`).

**Hash format:** matches Core's `gettxoutsetinfo muhash`. `hash_serialized_3` is not implemented; Core only reports it for the current tip, so it cannot serve as a per-height reference.

**Why this catches bugs Stage 3 doesn't:**
- A silent UTXO-state corruption that doesn't trip a validation error.
- Off-by-one errors that cancel out within a single block but accumulate.
- BIP30 grandfathering bugs that only manifest as a UTXO discrepancy.

**Frequency:** every full Stage-3 run.

### Stage 5: Reorg replay

Synthesize reorgs from real chain history. The chain has had many short reorgs; their losing forks are known. For each:
1. Force Mantle to follow the losing fork first.
2. Trigger a reorg to the canonical chain.
3. Verify final state matches the canonical UTXO snapshot.

**Why:** disconnect/reconnect logic is exercised on real data, not synthetic. Every reorg-related codepath is tested.

**Frequency:** every release candidate.

### Stage 6: Adversarial replay

A curated regression suite of historically-troublesome blocks. See §"Regression corpus" below.

**Frequency:** every CI run.

---

## Regression corpus

A static, version-controlled corpus of historically-significant blocks and transactions. The corpus grows over time but never shrinks: every consensus bug Core ever had becomes a permanent test in our suite.

### Initial population

- **BIP66 activation block (block 363,725).** Strict-DER signatures activated. Some pre-activation blocks contain non-canonical signatures.
- **BIP16 (P2SH) activation block (block 173,805).** Has historical edge cases around grandfathering.
- **BIP141 (segwit) activation block (block 481,824).** Witness commitment validation begins.
- **BIP341 (taproot) activation block (block 709,632).** Schnorr signatures, x-only pubkeys.
- **The 2010 value-overflow incident (block 74,638).** A transaction that created 184 billion BTC. The chain's most famous consensus bug, mitigated by reorg.
- **CVE-2018-17144 (inflation bug).** The double-spend-via-duplicate-input class. Not directly reproducible from mainnet (the bug was caught before exploitation), but synthetic test cases live here.
- **The March 2013 fork (block 225,430).** BDB lock limit caused a chain split.
- **Compact-block-relay edge cases (post-BIP152).** Blocks with prefilled tx ordering quirks.
- **Notable taproot oddities** as they accumulate (NUMS-point key-paths, complex script-trees).

### Format

Each entry is a small directory containing:
- `description.md` — what makes this block interesting.
- `block.bin` — raw block bytes.
- `prev_state.json` — minimal UTXO state required to validate this block (for use with `MemoryChainView`).
- `expected_result.json` — accept/reject and any expected error code.

The corpus is consumed by an integration test that walks the directory and asserts each entry validates as expected.

### Maintenance

When a new consensus bug, edge case, or interesting block is identified, an entry is added. Entries are never removed without explicit justification (they may be marked obsolete if the protocol changes — e.g., an opcode is reactivated — but kept for historical record).

---

## `ChainView` test implementations

Per `validation.md`, `ChainView` is a trait. The test infrastructure provides several implementations:

### `MemoryChainView`

**Status: implemented** in `crates/consensus/src/chain_view.rs`.

Pure-in-memory. UTXOs in a `HashMap<OutPoint, Coin>`, headers in a `Vec<BlockHeader>` indexed by height with a parallel `HashMap<Hash256, u32>` for hash → height lookup. Used by:
- Stage 1 and Stage 2 validation unit tests.
- Contextual fuzzers (no real chain needed).
- BIP test vectors (small synthetic chain states including chains of BIP34_HEIGHT = 227,931 headers).
- Property tests.

Public surface: `push_header`, `insert_coin`, `spend_coin`. Read access through the `ChainView` trait.

### `ReplayChainView`

**Status: not implemented.** Reads from a static UTXO snapshot file plus a header chain file. Used by `mantle-replay` to drive validation against a known-good prior state without bringing up the full storage subsystem.

### `CoreBackedChainView` *(optional, advanced)*

**Status: not implemented.** Stretch goal; not blocking initial validator development.

Wraps a running Core node's RPC. Used in differential testing: validate a block against Mantle and against Core, comparing not just the verdict but every intermediate state transition.

---

## CI strategy

The pipeline is partitioned by run frequency and cost. A bug caught in CI is cheaper than a bug caught in production by orders of magnitude, but tests that take days to run cannot block every PR. Layering by frequency lets us afford both.

### Per-PR (every commit pushed)

Must pass before merge. Runtime budget: ≤ 15 minutes total.

- All unit tests.
- All property tests (Layer 3).
- BIP test vectors (Layer 4).
- Adversarial corpus (Stage 6).
- Differential fuzzer (Layer 2): time-boxed sample of the persisted corpus, ~5 minutes per target.
- Build of `mantle-conformance` (verifies the FFI hookup hasn't broken).

### Nightly on `main`

Runtime budget: ≤ 2 hours.

- Headers-only replay (Stage 1).
- No-script block replay (Stage 2) on the full chain.
- Extended fuzzer pass on Layer-2 targets.

### Weekly / release-candidate

Runtime budget: as long as it takes; runs on a dedicated machine.

- Full validation replay (Stage 3) — multi-day.
- UTXO snapshot diffing (Stage 4).
- Reorg replay (Stage 5).

### Continuous

A dedicated machine running the differential fuzzers (Layer 2) 24/7 with persistent corpus. Any newly discovered crash or divergence is filed automatically. The fuzzer corpus is a permanent project asset, version-controlled separately from the main repo (or in a Git LFS-tracked directory).

### Ground-truth pinning

Every CI run logs the version of `libbitcoinconsensus` it linked against. When we update the pinned version, we get a clear log entry — a divergence that appears coincident with a Core version bump is informative.

---

## Open questions

1. **Where to host the continuous fuzzer.**
   Self-hosted runner vs. cloud. Cost matters; an always-on machine has nontrivial monthly burn. *No clear answer yet.*

2. **Corpus storage.**
   The fuzzer corpus and the regression block corpus are both blobs. Git LFS works but adds friction; a separate repo or an S3-backed cache might be cleaner. *Defer until we have something to store.*

3. **Pinned Core version cadence.**
   When Core releases a new version, do we update the pin immediately, or hold back? Fast updates surface compatibility issues early; slow updates reduce churn. *Lean: update on each Core minor release; document the diff in CI logs.*

4. **What to do when Core has a bug.**
   The differential fuzzer assumes Core is ground truth. If Core ships a CVE that flips a verdict on some input, our fuzzer will scream until we either pin to the pre-CVE version or accept the new behavior. *Procedure: pin pre-CVE temporarily, audit the change, decide whether Mantle adopts the new behavior or the old, document the decision.*

5. **Test-corpus licensing.**
   Bitcoin Core's `script_tests.json` etc. are MIT-licensed source-tree files. Including them in our repo is fine. The historical block corpus is just chain data — public domain. No issue, but worth being explicit.

6. **Cross-architecture validation.**
   `libbitcoinconsensus` behavior is bug-compatible across architectures, but our fuzzer may not be. Running CI on x86_64 and aarch64 catches `usize`-vs-`u32` issues, alignment bugs, etc. *Lean: yes, both archs in CI.*

---

## Deferred decisions

Things this document does *not* commit to:

- **Performance benchmarks of the validator itself.** That's `validation.md`'s problem; this doc is about correctness.
- **Mempool conformance.** Mempool *policy* is non-consensus and may legitimately differ from Core. Mempool *consensus* is covered by the inner-check sharing rule (`validation.md` §"Mempool / block validation"). A separate doc may eventually cover policy conformance.
- **Network-protocol conformance.** The wire-level "look like Core" goal (`principles.md` §2) is a different testing problem — black-box against a real Core peer. Worth its own doc.
- **RPC conformance.** Once Mantle has an RPC surface, comparing its responses to Core's is a separate (and easier) testing problem.

---

## Cross-references

- `principles.md` §4 — the principle this document operationalizes.
- `validation.md` — the validator design that depends on this infrastructure, including its §"Known gaps".
- `persistence.md` — the storage seam that `ChainView` test implementations stand in for.
- `fuzz/` — Layer 1 and the Layer 2 differential target (`fuzz_script_differential`) live here.
- `crates/consensus/` — Stage 1/2/3 validation, `ChainView`, `MemoryChainView`.
- `conformance/` — the FFI bridge to `bitcoinconsensus` v26 and the Layer 3/4 tests.
- `replay/` — the replay binary; `mantle-blkdat` does not exist.
