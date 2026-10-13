# Mantle: Architectural Principles

Cross-cutting stances that inform every pillar of the node. These are the *why* — when a design choice in any subsystem feels arbitrary, the answer should be derivable from this list.

## 1. Clean-room independence from Bitcoin Core

Mantle is a from-scratch implementation of the Bitcoin protocol. It shares no consensus code with Core, libbitcoinconsensus, or libbitcoinkernel. It uses different cryptographic primitives (`k256` instead of `libsecp256k1`) and minimizes external dependencies in general.

**Why:** Bitcoin's long-term health depends on it being *a protocol*, not *an implementation*. A monoculture where every node runs the same C++ codebase is a centralization pressure on the network. Independent implementations stress the protocol's specification, surface ambiguities, and provide failure-mode diversity.

**What this commits us to:**
- Every consensus rule must be derived, implemented, and verified against history without copying Core source.
- Cryptographic disagreements between `k256` and `libsecp256k1` (low-S enforcement edge cases, strict DER tolerance, pubkey encoding tolerance) are *our* problem to mediate at the consensus layer.
- Soft-fork archaeology — BIP66, BIP65, BIP68/112/113, BIP141, BIP341/342, etc. — must be reproduced exactly, including activation heights and transition-block edge cases.

**What this does *not* commit us to:**
- Refusing to depend on Core *for testing*. Differential fuzzing against `libbitcoinconsensus` is the only honest way to validate clean-room consensus code; the shipped node has zero Core deps, the test harness uses Core as ground truth. (See `validation.md` and `conformance.md`.)

## 2. Conformance over novelty on the wire

Mantle looks like a regular Bitcoin node to its peers. It speaks the existing P2P protocol, advertises only standard service bits, participates in compact block relay, and is indistinguishable from Core in any externally observable behavior.

**Why:** Two reasons. First, conformance is *the* test of independent implementation — if we drift on the wire we've failed the goal in §1. Second, anything else (Utreexo proof gossip, custom service bits, bridge-node duality) creates network-fragmentation risk that contradicts the decentralization argument.

**What this rules out:**
- Utreexo as a wire-visible feature. Internally-accumulator-backed UTXO is fine; gossiping proofs is not.
- Floresta-style "be both a normal node and a Utreexo bridge" duality.
- Any consensus-rule extension or relaxation beyond what mainline Core enforces.

**What this enables:**
- Internal architecture is unconstrained. We can be radically different *inside* — modern storage, io_uring-native IO, lock-free message passing — as long as the wire-level behavior matches.

## 3. Minimal external dependencies; pure Rust

Mantle prefers writing primitives over importing them when the import would pull in C code, large transitive dependency trees, or runtimes that conflict with our threading model.

**Why:** Three reasons. (1) Auditability — small dependency graph means smaller surface to review for supply-chain integrity. (2) Build simplicity — no `cmake`, `autotools`, or pkg-config archaeology. (3) Architectural fit — the off-the-shelf crates that match our io_uring-native, thread-per-component model don't exist; the closest options force adoption of an executor.

**What this commits us to:**
- We own primitives that production projects usually delegate. The two foundational ones already exist:
  - `ququmatz` — io_uring bindings via raw syscalls, `#![no_std]`, no libc.
  - `quetzalcoatl` — lock-free SPSC/MPSC/SPMC/MPMC/broadcast ring buffers, pure `std`.
- We will likely write our own UTXO storage layer (and possibly engine) rather than import RocksDB or LevelDB.

**What this does *not* commit us to:**
- Reinventing every wheel. Crypto (`k256`, `sha2`) is imported. Hex parsing, etc., where stable and small, is fine. The bar is "does this dependency justify its weight."

## 4. Fuzzing and historical replay as first-class infrastructure

Test infrastructure is treated as core code, not a `tests/` afterthought. Specifically:
- Differential fuzzers comparing Mantle against `libbitcoinconsensus` for every consensus-critical function (script, sighash, tx validation, block validation).
- Property tests with shrinking for codecs and invariants.
- A historical-replay pipeline that consumes Core's `blk*.dat` files and validates the entire chain end-to-end, with stages for headers-only, no-script, full, and reorg-replay variants.

**Why:** The combination of clean-room consensus and minimal deps means our blast radius for bugs is enormous. A consensus disagreement we don't catch in test surfaces as a chain split. libbitcoin and btcd both shipped consensus divergences for exactly this reason; the test infrastructure was the missing piece. Treating it as core code is non-negotiable.

**What this commits us to:**
- A `mantle-conformance` (or similar) crate linking `libbitcoinconsensus` via FFI. *Only used in tests.* Shipped node has zero Core deps.
- A blocks-data-file reader, a `ChainView` trait, and an in-memory `ChainView` implementation for tests, before any production validator code.
- A regression suite of historically-troublesome blocks (BIP66 activation, the 2010 value-overflow incident, every CVE-related block we can reconstruct).

## 5. Thread-per-component, message-passing, no shared mutable state

Mantle's runtime is built from single-owner threads communicating via lock-free ring buffers. There is no global lock equivalent to Core's `cs_main`. Each subsystem (network IO, validation, storage IO) is a thread with exclusive ownership of its stateful resources (ring, file descriptors, buffer pool).

**Why:** Core's `cs_main` is the canonical example of what not to do — a single mutex serializing validation, mempool, and net-processing has consumed a decade of refactoring effort and is *still* the dominant scaling problem. Designing in a lock-free message-passing topology from day one avoids that debt.

**What this commits us to:**
- Inter-thread communication is exclusively via `quetzalcoatl` rings (or future similar primitives).
- No `Arc<Mutex<T>>` on hot paths. Period.
- Each io_uring instance is owned by exactly one thread (`!Send + !Sync` is enforced by `ququmatz`).
- Backpressure is propagated through bounded queues; queues are bounded *by construction*.
- Failure domains are isolated: a slow disk does not stall the network; a peer flood does not stall validation.

**What this does *not* mean:**
- "No locks ever." Locks are fine for cold-path setup and configuration. The principle is about hot paths and shared mutable state.

## 6. Modern hardware as a design assumption

Mantle assumes NVMe storage, multi-core CPUs with deep memory hierarchies, and Linux 5.6+. We do not optimize for spinning disks, single-core machines, or pre-io_uring kernels.

**Why:** Bitcoin Core's storage and threading designs trace back to assumptions from the 2010s. Modern hardware has fundamentally different bottlenecks: random-read IOPS are abundant, queue depth matters more than seek time, false sharing is more expensive than syscalls. Designing for current hardware is a free win — and reaching for older assumptions has a real cost in complexity and lost performance.

**What this commits us to:**
- io_uring everywhere IO happens. No `read()`/`write()` syscalls on hot paths.
- Cache-line-aware data layout (`CachePadded` cursors, registered buffers aligned for direct IO).
- Linux-only for the foreseeable future. Cross-platform support is not a near-term goal.

## 7. Honest scope, deferred decisions

When a decision can be deferred without blocking the next concrete step, defer it. When it must be made, document the reasoning (including rejected alternatives) so future-us can revisit with new information.

**Why:** Mantle is a research project as much as it is a node. Premature commitment to a particular UTXO representation, a particular SNARK construction, or a particular reorg-handling discipline costs more in agility than it buys in clarity.

**What this looks like in practice:**
- Validator interfaces are designed against an abstract `ChainView` trait so the storage representation can change.
- The storage layer's primitive (custom engine vs. `redb`/`fjall` + custom UTXO layer) is a Phase 2 decision; Phase 1 builds against a stable storage-thread message API.
- Speculative architectures (Utreexo, ZK-validity, era-based accumulators) are documented as *currently rejected* with reasons, not erased — so they can be reconsidered when constraints change.

---

These principles are descriptive of decisions already made and prescriptive for decisions ahead. When a new subsystem is being designed, the first question is "which of these does the design touch, and is it consistent with them?" If a principle needs to be revised, that's a conversation worth having explicitly.
