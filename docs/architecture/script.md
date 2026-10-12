# Script Interpreter

Status: **implemented through M5.** The interpreter, legacy/BIP143/BIP341 sighash, segwit v0, taproot and tapscript live in `crates/consensus/src/script/`, and `connect_block` verifies every input. This document remains the design and staging record; the milestone sections below describe the plan as it was written. Deviations from that plan are listed in §"Current state".

The script interpreter is the highest-risk subsystem in Mantle. It is the load-bearing reason `mantle-conformance` exists, the dominant cost during IBD, and the surface where every clean-room Bitcoin implementation that has ever shipped — libbitcoin, btcd — has produced a consensus divergence. We treat it accordingly: no production script code is written ahead of differential coverage for that code; every milestone activates more of `fuzz_script_differential`, never less.

Reading order: §"Constraints" sets context. §"Module shape" is the static architecture. §"Milestones" is the staging plan and the bulk of this document. §"Disciplines" is what is enforced across every milestone. §"Open questions" parks unresolved bits.

---

## Constraints

From `principles.md`:
- §1 (clean-room independence) — script is hand-written; no Core source is copied. We read BIPs and observe Core *behavior* via the differential fuzzer, then derive.
- §3 (minimal deps) — `k256` and `sha2` are the only crypto. `ripemd` is a small additional dependency we accept (RIPEMD-160 is consensus-required and pure-Rust implementations are tiny).
- §4 (fuzzing first-class) — `fuzz_script_differential` is the gate. Every milestone enables a stricter assertion on it; no opcode ships without that fuzzer asserting parity for inputs that exercise it.

From `validation.md` §"Script strategy":
- The interpreter supports legacy, BIP16 P2SH, BIP141 segwit, and BIP341/342 taproot/tapscript.
- All script flags are flag-gated to their activation heights; soft-fork archaeology is reproduced exactly.
- BIP146 (low-S, strict-DER) is enforced when activated.
- The `SIGHASH_SINGLE` "1" bug is reproduced, not fixed.
- A thin `consensus_crypto` wrapper around `k256` is the only place the interpreter touches `k256`.

From `conformance.md`:
- Every consensus-critical function has a differential fuzz target. The script interpreter is the most important one.
- BIP65/66/112/143/340/341/342 vectors are inline in `conformance/tests/bip_vectors/`.
- Stage 3 of historical replay (full validation including script) is the long-running confidence signal.

From the project state:
- `connect_block` (Stage 3) currently performs UTXO existence, coinbase maturity, fee math, sigops budgeting, and BIP30. It does *not* call `verify_script`. Wiring that call in is part of M1.
- `Transaction` carries no witness data today (`TxIn` has only `previous_output`, `script_sig`, `sequence`). Adding witness data is part of M2 — segwit cannot be validated against a wire format that doesn't carry it.
- `ScriptSig` is `ScriptBuf<128>` and `ScriptPubKey` is `ScriptBuf<36>`, both inline-optimised. The interpreter takes raw `&[u8]` and never depends on the inline-vs-heap split.
- The differential fuzzer at `fuzz/fuzz_targets/fuzz_script_differential.rs` already runs `bitcoinconsensus::verify_with_flags` and discards the result. Activating its assertion is a one-line change *gated on the milestone we are currently in*.

---

## Module shape

A new directory `crates/consensus/src/script/`. Every milestone adds files; no file's contents are committed in this document, only its responsibility.

```
crates/consensus/src/script/
├── mod.rs            ── public API: verify_script, ScriptError, ScriptFlags
├── opcodes.rs        ── Opcode constants and a name() helper for diagnostics
├── num.rs            ── ScriptNum: Bitcoin's minimally-encoded variable-length int
├── stack.rs          ── Stack and AltStack with size caps (1000 items, 520 bytes/item)
├── interpreter.rs    ── eval_script: opcode dispatch loop
├── sighash.rs        ── legacy / BIP143 / BIP341 sighash computation
├── consensus_crypto.rs ── k256 wrapper enforcing strict-DER, low-S, encoding tolerance
└── flags.rs          ── ScriptFlags bitflags, flags_for_height
```

`mod.rs` re-exports `verify_script`, `ScriptError`, and `ScriptFlags`. Nothing else escapes the module. The interpreter is internal; the public surface is one function and one error type.

`verify_script`'s signature, target form (settles in M2 when witness lands; M1 ships without `witness` and `spent_outputs`):

```text
verify_script(
    script_pubkey: &[u8],
    script_sig: &[u8],
    witness: &[Vec<u8>],            // empty pre-segwit
    tx: &TransactionRef,
    n_in: usize,
    amount: Satoshi,
    spent_outputs: &[TxOutRef],     // required for taproot
    flags: ScriptFlags,
) -> Result<(), ScriptError>
```

This matches the shape of `bitcoinconsensus::verify_with_flags` so the differential fuzzer is a one-to-one comparison.

---

## Milestones

Each milestone is a shippable PR. Each one ends with a stricter `fuzz_script_differential` assertion and more BIP vectors in `conformance/tests/bip_vectors/`. We do not skip ahead.

### M1 — Legacy script verification end-to-end

**Scope.** A working, complete legacy script interpreter. Pre-segwit only. By the end of M1, every pre-block-481,824 mainnet input can be verified to parity with `libbitcoinconsensus`.

**What ships.**
- `script/{mod,opcodes,num,stack,interpreter,sighash,consensus_crypto,flags}.rs` created.
- `Opcode` constants for the entire consensus-active opcode set. Every opcode is at least *defined*; opcodes without legacy-only meaning may be implemented in later milestones (e.g., the witness-only opcodes are stubs that fail with `ScriptError::DisabledOpcode` if they execute pre-segwit).
- `ScriptNum` with Bitcoin's exact encoding rules: little-endian, sign-magnitude with a sign bit on the high byte, minimal-encoding rules under `SCRIPT_VERIFY_MINIMALDATA`. Range checks per opcode (4-byte limit on inputs to arithmetic; 5-byte tolerated only for `OP_CHECKLOCKTIMEVERIFY`).
- `Stack` and `AltStack` enforcing the 1000-item combined cap and the 520-byte per-element cap. Both are `Vec<Vec<u8>>` for now; no allocation tricks until the fuzzer is happy.
- All non-crypto opcodes implemented: push data (the entire 0x01..=0x4b + `OP_PUSHDATA1/2/4` family), control flow (`OP_IF/NOTIF/ELSE/ENDIF/VERIFY/RETURN`), stack ops (`OP_TOALTSTACK`/`OP_FROMALTSTACK`/`OP_DUP`/`OP_DROP`/`OP_SWAP`/`OP_PICK`/`OP_ROLL`/`OP_2DUP`/etc.), bitwise/comparison/arithmetic (the full `OP_ADD`-class list with the disabled subset returning `ScriptError::DisabledOpcode`), hashes (`OP_RIPEMD160`/`OP_SHA1`/`OP_SHA256`/`OP_HASH160`/`OP_HASH256`/`OP_CODESEPARATOR`).
- Legacy sighash with all four base modes (`SIGHASH_ALL/NONE/SINGLE/ANYONECANPAY`) and the `SIGHASH_SINGLE` "1" bug reproduced (when `nIn >= nOut`, sighash returns `0x0000…0001`).
- `consensus_crypto::verify_ecdsa` with a hand-rolled strict-DER validator (mirrors `IsValidSignatureEncoding` in Core's `interpreter.cpp` *by behavior*, not by source). Low-S enforcement gated on `SCRIPT_VERIFY_LOW_S`. Pubkey encoding tolerance gated on `SCRIPT_VERIFY_STRICTENC` (33-byte compressed, 65-byte uncompressed; hybrid 0x06/0x07 pubkeys accepted only without `STRICTENC`).
- `OP_CHECKSIG` / `OP_CHECKSIGVERIFY` / `OP_CHECKMULTISIG` / `OP_CHECKMULTISIGVERIFY`. `CHECKMULTISIG` reproduces the off-by-one "OP_0 padding" requirement (`SCRIPT_VERIFY_NULLDUMMY` flag-gated).
- BIP16 P2SH redeemScript dance: when scriptPubKey matches the P2SH pattern, take the last push from scriptSig as the redeem script, evaluate that against the remainder of the stack.
- `verify_script(...)` as the public entry point. Wired into `connect_block` as a fourth per-input check, after coin lookup but before fee math (script failure rejects the tx whether or not the value math would have).
- Per-input script flags computed via `flags_for_height(height)`, parity with `bitcoinconsensus::height_to_flags` for legacy bits. Witness/taproot bits are off in M1.

**What does *not* ship in M1.**
- Witness program detection. Pre-segwit-activation blocks have no witness programs in scriptPubKey by consensus, so the parser may simply fail-closed on those byte patterns — they do not appear in M1's test corpus.
- Schnorr, taproot, BIP340/341/342.
- Any segwit sighash. BIP143 is M2.
- The script-execution and signature caches. M5.

**Differential fuzzer activation.**
- The assertion in `fuzz_script_differential.rs` is enabled, masked to `(VERIFY_P2SH | VERIFY_DERSIG | VERIFY_NULLDUMMY | VERIFY_CHECKLOCKTIMEVERIFY | VERIFY_CHECKSEQUENCEVERIFY)`. Witness/taproot flag bits are stripped before comparison; if either side returns `ERR_WITNESS_*` we treat the input as out-of-scope and skip.
- The corpus seeds for the fuzzer are: every `script_tests.json` entry that touches only the M1 flag set (mined into the corpus directory at the start of M1), plus a small hand-rolled set of P2PKH/P2SH/CHECKMULTISIG cases.

**BIP vectors added.**
- BIP66 strict-DER vectors in `conformance/tests/bip_vectors/bip66.rs`. Both the well-known accept set and the rejected pre-BIP66 grandfathering corpus.
- A handful of legacy script-verify positive/negative pairs (P2PKH, bare multisig, P2SH-wrapped multisig).
- The 2010 value-overflow incident's precursor block in raw form, with assertion that script verification *passes* on the now-impossible tx (the bug was that the tx encoded outputs summing past `MAX_MONEY`, not that script verification rejected it; the structural Stage-1 check now rejects it. A test asserts both behaviors.)

**Exit criteria.**
- Every non-witness mainnet block from genesis through height 481,823 is consensus-validated by Mantle to parity with bitcoinconsensus on the curated corpus. (Stage 3 of historical replay can now run on the pre-segwit chain. We do not require the full multi-day Stage 3 run to land M1; we require it to land M5.)
- `fuzz_script_differential` runs for at least 24 hours on the corpus without divergence.
- All BIP66 vectors pass.
- `connect_block` rejects script failures with a new `ValidationError::ScriptVerifyFailed { tx_index, input_index, kind: ScriptError }`.

**Risks / known traps.**
- BIP66 strict-DER is fiddly. Core's `IsValidSignatureEncoding` is ~80 lines of C with no comments. We re-derive it from BIP66's prose and the differential fuzzer; the fuzzer is the test, not the spec.
- `OP_CHECKMULTISIG`'s OP_0 dummy element is itself a Bitcoin bug from 2010. It must be reproduced (a script that doesn't push `OP_0` before the signatures fails consensus). `NULLDUMMY` makes the rule stricter, not laxer.
- `OP_CODESEPARATOR` is rare but consensus-critical: it edits the scriptCode used by the next `OP_CHECKSIG`. Must not be hand-waved.
- Push opcodes' minimal-encoding rule under `MINIMALDATA` is enforced *during opcode dispatch*, not during parsing. Parsing accepts `OP_PUSHDATA1` with a length-1 push of `0x01`; execution under `MINIMALDATA` rejects it.

---

### M2 — Segwit v0 (BIP141 / BIP143)

**Scope.** Segwit-version-0 P2WPKH and P2WSH script paths, plus BIP143 sighash. By the end of M2, every mainnet input from segwit activation through taproot activation can be verified to parity.

**Wire-format prerequisite.**
- `TxIn` gains a `witness: Witness` field, where `Witness` is a `Vec<Vec<u8>>` of stack items (or, more likely, a small-array-optimised inline-up-to-N variant — same shape as `ScriptBuf`).
- `Transaction` decode learns the BIP144 marker/flag protocol: when the byte after the version is `0x00` followed by `0x01`, parse as a witness transaction. The non-witness serialisation (used for txid) does *not* include witness data; the witness serialisation (used for wtxid and for block weight calc) does.
- Block weight calculation updates: base size × 3 + total size × 1, replacing the current "× 4" placeholder.
- Witness commitment (BIP141) is verified on the coinbase: the last output of the coinbase contains a commitment to the witness merkle root.

These are wire-format and structural changes; they touch `crates/mantle/src/tx/` and `crates/consensus/src/validation/`. They are part of M2 even though M2 is nominally "the script interpreter" — segwit doesn't make sense without them.

**What ships.**
- BIP143 sighash: `SIGHASH_ALL/NONE/SINGLE` over the segwit-v0 sighash preimage (`hashPrevouts`, `hashSequence`, `outpoint`, `scriptCode`, `amount`, `nSequence`, `hashOutputs`, `nLocktime`, `sighashType`). The three `hashPrevouts/hashSequence/hashOutputs` precomputations are cached on `TransactionRef` for the duration of one tx's verification (a hashed-preimage cache, not the full script-execution cache).
- `verify_script` learns to detect a v0 witness program in scriptPubKey and dispatch to the witness-script evaluation rules:
  - P2WPKH: scriptPubKey is `OP_0 <20-byte pubkey hash>`. Witness is `[signature, pubkey]`. Constructs a synthetic P2PKH script and executes that.
  - P2WSH: scriptPubKey is `OP_0 <32-byte witness script hash>`. Witness is `[...stack..., witness_script]`. Hashes the last witness item, compares to the program, then evaluates the witness script with the remaining items as initial stack.
- The witness program parser rejects unknown segwit versions only when `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS` is set. Without that flag, unknown-version programs are valid (they pass without execution).
- `OP_CHECKSIG` family in segwit context uses BIP143 sighash. Legacy sighash is unreachable from a segwit script.
- `consensus_crypto::verify_ecdsa` is unchanged but is now reached via BIP143 preimages.

**Differential fuzzer activation.**
- The assertion mask grows by `VERIFY_WITNESS`. The fuzzer now compares verdicts on inputs containing witness programs.
- Corpus seeds expand to include taproot-era blocks' segwit-v0 inputs (taproot-era blocks contain a mix of v0 and v1; v0 inputs in those blocks are valid M2 corpus).

**BIP vectors added.**
- BIP143 sighash test vectors (the original BIP143 vectors plus any in `script_tests.json` that exercise v0).
- A coinbase witness-commitment positive/negative pair.
- A BIP144 marker/flag round-trip test.

**Exit criteria.**
- Every mainnet block from genesis through height 709,631 is consensus-validated to parity on the curated corpus.
- `fuzz_script_differential` runs for 48 hours on the M2 corpus without divergence.
- All BIP143 vectors pass.

**Risks / known traps.**
- Block weight calculation is easy to get subtly wrong. The `× 3 + × 1` formula is what Core uses; we test it against actual mainnet block weights as published.
- `wtxid` is `txid` for the coinbase. Off-by-one easy to make.
- Witness commitment validation: the commitment is in the *coinbase* witness, not the coinbase scriptSig. Different field.
- BIP143's `scriptCode` for P2WSH is the witness script itself; for P2WPKH it is a synthetic P2PKH-shaped script. Different rules for the two paths.

---

### M3 — Taproot / Tapscript (BIP340 / BIP341 / BIP342)

**Scope.** Schnorr signatures, x-only pubkeys, the BIP341 sighash with annex handling, and BIP342 tapscript (the per-leaf script execution rules).

**What ships.**
- `consensus_crypto::verify_schnorr` against `k256`. BIP340 tagged hashes implemented (`SHA256("BIP0340/challenge") || SHA256("BIP0340/challenge") || msg`). x-only pubkey rules. Strict 64-byte signature length.
- BIP341 sighash, including:
  - The new sighash flag values (`SIGHASH_DEFAULT = 0x00`, distinct from `SIGHASH_ALL`).
  - The `extension` field for tapscript (vs. key-path).
  - Annex handling (a witness item starting with `0x50` is the annex; included in sighash, not pushed to stack).
  - Spent-outputs hashing (requires `spent_outputs: &[TxOutRef]`, threaded through `verify_script`).
- Witness program v1 detection: scriptPubKey is `OP_1 <32-byte x-only pubkey>`.
- Key-path spend: witness contains exactly one (or two with annex) elements; the lone non-annex element is the Schnorr signature. Verified directly against the x-only pubkey in the program.
- Script-path spend: witness is `[...inputs..., script, control_block]`. Control block parses to a leaf version + internal key + merkle path. Leaf hash → merkle root → tweaked-key check.
- BIP342 tapscript: differs from legacy in opcode set (no `OP_CHECKMULTISIG`; new `OP_CHECKSIGADD`), no sigop budget per-script (a global tapscript sigop budget per-input weighted by witness size), and `OP_SUCCESSx` opcodes (any of a defined list of opcodes succeeds the script immediately, paving for future soft forks).
- All v1+ unknown-version programs are valid without `DISCOURAGE_UPGRADABLE_NOPS`; gated when set.

**Differential fuzzer activation.**
- The assertion mask grows by `VERIFY_TAPROOT`. `spent_outputs` is now passed (was `None` before, with both sides agreeing on `ERR_SPENT_OUTPUTS_REQUIRED`).
- Corpus seeds add taproot-era inputs.

**BIP vectors added.**
- BIP340 vectors (Schnorr).
- BIP341 sighash vectors.
- BIP342 tapscript vectors including `OP_CHECKSIGADD` and `OP_SUCCESSx`.

**Exit criteria.**
- Every mainnet block through current tip is consensus-validated to parity on the curated corpus.
- `fuzz_script_differential` runs for 72 hours on the M3 corpus without divergence.
- All BIP340/341/342 vectors pass.

**Risks / known traps.**
- BIP340 tagged hashes are subtle: the tag itself is hashed twice and prepended. `k256`'s Schnorr API may or may not expose this in the BIP340 form; if not, we hash the message in `consensus_crypto` and pass the digest.
- The merkle tree in the control block uses *non-sorted* hashing with a tag (`TapBranch`), unlike BIP141's transaction merkle. Easy to confuse.
- `OP_SUCCESSx` is a forward-compat soft-fork mechanism. Critical to *not* execute these opcodes — listing them in the script is sufficient for the script to succeed.
- `SIGHASH_DEFAULT` is `0x00`, which would have been an invalid sighash type pre-taproot. The two are distinguished by *length* of the signature: 64 bytes means default-all, 65 bytes means an explicit sighash byte follows.
- The `SIGHASH_SINGLE` "1" bug is *not* present in BIP341. Different sighash, different rules.

---

### M4 — Flag-gated soft-fork rules

**Scope.** The remaining flag-gated rules that aren't tied to a script version. Most of the wiring exists by M3; M4 closes the gaps.

**What ships.**
- `OP_CHECKLOCKTIMEVERIFY` (BIP65, `SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY`). Replaces `OP_NOP2`. Uses the 5-byte `ScriptNum` exception.
- `OP_CHECKSEQUENCEVERIFY` (BIP112, `SCRIPT_VERIFY_CHECKSEQUENCEVERIFY`). Replaces `OP_NOP3`. Interacts with `nSequence` masking rules.
- `MINIMALIF`, `NULLFAIL`, `CLEANSTACK`, `DISCOURAGE_UPGRADABLE_NOPS` flags fully enforced where they weren't already.
- `flags_for_height(height)` returns a bitset that matches `bitcoinconsensus::height_to_flags(height)` for every height. Property-tested.
- The activation height table is documented as a const `&[(BlockHeight, ScriptFlags)]` in `flags.rs`.

**Differential fuzzer activation.**
- All flags now compared. The fuzzer's `VALID_FLAGS_MASK` is the union of every flag bitcoinconsensus accepts.
- A property test asserts `flags_for_height(h)` matches bitcoinconsensus for every `h` in `0..=900_000`.

**BIP vectors added.**
- BIP65 (CLTV) and BIP112 (CSV) vectors.

**Exit criteria.**
- `flags_for_height` parity with bitcoinconsensus across every mainnet height.
- All BIP65/112 vectors pass.

**Risks / known traps.**
- `nSequence` masking for `OP_CSV` is two layers of bitfield gymnastics. The relative-locktime semantics distinguish "blocks" from "seconds" by a flag bit in `nSequence`; the comparison opcode masks before comparing.
- `CLEANSTACK` is only enforced under P2SH; pre-P2SH it's silently off. Easy to enforce universally and break legacy.
- `DISCOURAGE_UPGRADABLE_NOPS` interacts with witness-program-version unknown-but-valid logic.

---

### M5 — Caches

**Scope.** Performance, not correctness. Lands after M4 because cache bugs are easier to debug when the underlying interpreter is known-good.

**What ships.**
- `ScriptExecutionCache`: keyed on `(wtxid, input index, spent amount, spent scriptPubKey, flags)`; stores successes only. Bounded FIFO. Living under `crates/consensus/src/script/cache.rs`. (The original key design omitted the spending transaction, which let a replayed signature hit the cache for a different transaction; see §"Current state".)
- `SignatureCache`: keyed on `(sighash, signature, pubkey)`, value is verdict. Smaller, simpler, hits a strict subset of script-cache hits but also helps when the same signature is reused across scripts.
- `ScriptVerifier::verify_cached` takes the transaction's wtxid and a `&mut ScriptExecutionCache`; the uncached `verify` is preserved for tests and the fuzzer.
- Cache hit/miss counters exposed via a tiny telemetry hook (no global state; the cache owns its counters).
- Property test: any input that produced a verdict on a cold cache produces the same verdict via the cache.
- Differential fuzzer learns to compare cached vs. uncached: a tx with N identical inputs verified once cold, N-1 cached, must match a tx with N inputs verified all-cold.

**`assumevalid` integration.**
- A configurable block hash; ancestors of the assumed-valid hash skip script verification but still do all other consensus checks. Plumbed through `connect_block` as a `skip_script: bool` parameter. Default value is set to a recent well-known mainnet block; can be disabled with a config flag. Documented in node config.

**Exit criteria.**
- Stage-3 historical replay (full mainnet, with script) completes end-to-end on a single machine. Multi-day runtime is acceptable; correctness is not.
- Stage-4 UTXO snapshot diffing matches Core checkpoints at every height in the precomputed checkpoint set.
- Cache hit rate is non-zero on real workload (sanity check, not a hard threshold).

**Risks / known traps.**
- A wrong cache key (forgetting to include `flags`, `amount`, or the spending transaction itself) is a silent consensus bug — the cache returns a valid prior verdict for a different actual input. The key must include *every* input that affects the verdict.
- Hash collision on the cache key would be a consensus bug; we use double-SHA256 of the concatenation, not a fast hash, for the key — a 256-bit key in a HashMap is the conservative choice.

---

## Disciplines

These are non-negotiable across every milestone.

### 1. The differential fuzzer is the gate

No opcode, no sighash variant, no flag bit is implemented without the fuzzer asserting parity on inputs that exercise it. If the fuzzer can't reach the new code, the new code is dead and we're flying blind. The first commit of every milestone is the fuzzer-mask change that activates the new surface; the *last* commit is the BIP-vector regression test.

### 2. No copying from Core

We read the BIPs. We read Core's behavior via the fuzzer. We do not read Core's source. (Reading Core's *tests* — `script_tests.json` etc. — is fine; those are the protocol-level vectors, not implementation.) When we hit a wall on a BIP66-style under-specified rule, we round-trip via the fuzzer until our implementation matches Core's behavior, then comment the *behavior* we discovered, not the source we glanced at.

### 3. `consensus_crypto` is the only `k256` caller

The interpreter never imports `k256`. Every signature check goes through `consensus_crypto::verify_ecdsa` or `verify_schnorr`. This isolates the cryptographic-library disagreement risk to one module that we audit carefully and fuzz aggressively.

### 4. Stack and integer rules are in their own files

`stack.rs` and `num.rs` are not "utility" modules — they encode consensus rules (1000 / 520 caps; minimal-encoding; 4-byte arithmetic limit). They have their own unit tests, their own fuzz coverage, and they do not change between milestones except to add features.

### 5. `verify_script` is one function

There is exactly one entry point. It dispatches on scriptPubKey shape (P2SH / segwit-v0 / segwit-v1 / legacy) internally. Callers (`connect_block`, the fuzzer, mempool) call the same function. If we ever feel tempted to add a "cheaper variant," we add a flag, not a function.

### 6. Errors are structured

`ScriptError` is an enum, not a string. Every variant is one a caller might want to distinguish (`SigDer`, `SigHashtype`, `SigPushOnly`, `MinimalData`, `NumOverflow`, `BadOpcode`, `OpReturn`, `WitnessProgramMismatch`, etc.). The differential fuzzer compares accept/reject only — but our internal logging gets the structured kind for free, and we can later add per-error fuzzing if a particular error class becomes interesting.

### 7. Hot-path allocation is observed, not assumed

By M2 the interpreter runs on every input of every block. We do *not* preemptively optimise; we run dhat (the project's tool of choice — the existing perf data files at the repo root attest to this) at the end of M2 and again at M5, and address what shows up. Stack items are `Vec<u8>` until proven worth changing.

---

## Rust idioms (project-wide)

These bind every milestone of the script interpreter and every other module in Mantle. They restate the project's existing house style explicitly so that "what does idiomatic mean here" has a checkable answer.

### 8. Newtypes over bare primitives

Any `u32`/`u64`/`[u8; 32]` that has *meaning* gets a newtype. `BlockHeight`, `Satoshi`, `CompactBits`, `Hash256`, `OutPoint` are the existing examples; the script module continues that pattern. A signature is `Signature(Vec<u8>)` or `Signature<'a>(&'a [u8])`, not `&[u8]`. A pubkey is `PubKey`, not `&[u8]`. A sighash is `SigHash([u8; 32])`, not `[u8; 32]`. The compiler then catches "you passed an x-only pubkey where a compressed one was expected" without a single runtime check.

The cost is type-name noise. The benefit is that wiring mistakes — passing `amount` where `n_in` is expected, or a `wtxid` where a `txid` is expected — fail at compile time rather than as a consensus divergence.

### 9. Methods over free functions

If a function's first argument is `&self`-shaped (an owned or borrowed instance), it is a method. Free functions like `compute_merkle_root_reusing(txids, buf)` are written as `txids.merkle_root_reusing(buf)` with a small extension trait when the type is foreign. `Transaction::txid_into` already follows this; new code preserves the pattern.

Exceptions: pure functions that take no "primary" argument (e.g., a parser entry point taking `&[u8]`), and the `verify_script` entry point which deliberately mirrors the bitcoinconsensus signature for fuzzer parity. Those stay free; everything else is a method.

### 10. Enums over magic constants

Opcodes are an `Opcode` enum, not `const OP_DUP: u8 = 0x76`. Sighash flag bytes are a `SigHashType` enum, not `const SIGHASH_ALL: u8 = 0x01`. Script verify flags are a `ScriptFlags` newtype with associated `const` named bits, not bare `u32` literals at call sites. `ScriptError` variants are exhaustive, not "string-typed" via `format!`. The compiler's exhaustiveness check is the cheapest fuzzer we have; we use it.

The escape hatch is when a value is genuinely unstructured — a wire-byte during decode, before we have decided what it means. There the discriminant lives in the parser, the enum lives downstream, and the conversion happens at the boundary.

### 11. No external deps unless absolutely unavoidable

The bar in `principles.md` §3 is "does this dependency justify its weight." For the script interpreter the answer for almost everything is no. The expected list is exactly: `k256` (already imported, behind `consensus_crypto`), `sha2` (already imported), `ripemd` (small, pure-Rust, consensus-required, no replacement we'd write better). That is the entire dependency budget for `script/`.

We do *not* pull in `bitflags`, `thiserror`, `anyhow`, `bytes`, `arrayvec`, `num-traits`, or any general-purpose crate when a hand-rolled equivalent fits in a screenful. The project already has `Hash256`, `ScriptBuf`, `VarInt` written by hand for exactly this reason. If a candidate dependency comes up during a milestone, the answer is no by default; flipping that requires writing down what we'd lose by not having it.

---

## What this document does *not* commit to

- **Mempool standardness rules.** Those are policy, not consensus, and live above this layer.
- **Script disassembly / debugging tooling.** Useful but not consensus-critical; deferred indefinitely.
- **`OP_CAT` or other proposed-but-not-active opcodes.** They remain disabled until a soft fork activates them on mainnet.
- **A hand-rolled secp256k1.** `k256` is the chosen curve library; replacing it is a `principles.md` §3 conversation, not a script-interpreter conversation.
- **Caching policy details.** M5 will pick LRU or segmented-LRU based on profiling; this doc says "bounded LRU" without picking a specific policy.

---

## Open questions

1. **Witness type representation.** `Vec<Vec<u8>>` is the obvious model; an inline-optimised `WitnessBuf` mirroring `ScriptBuf` may be worth it for low-element-count witnesses (which is most of them). *Defer to M2; pick based on dhat.*

2. **`ScriptNum` representation.** Bitcoin's number type is variable-length up to 5 bytes. We can store it as `i64` and re-encode on push, or store as a `[u8; 5]+len`. The latter avoids re-encoding overhead at the cost of arithmetic going through encode/decode. *Defer to M1; pick based on bench.*

3. **Where activation heights live.** `flags.rs` is the obvious place; a separate `activations.rs` may be cleaner if BIP9/BIP8 deployment-state computation lands in the same era. *Defer to M4; reorganise if it pays for itself.*

4. **Whether `verify_script` should take `&Transaction` or `&TransactionRef`.** `TransactionRef` is the zero-copy form and avoids any allocation in the hot path; `Transaction` is the materialised form. The fuzzer takes raw bytes and is happy either way. *Lean: `TransactionRef`. Confirms with the existing zero-copy push from project memory.*

5. **Whether script flags are an enum bitset (newtype around u32) or a `bitflags!` invocation.** Newtype wins for simplicity; `bitflags!` wins for `Debug` output. *Lean: newtype. We have very few flag bits and a custom `Debug` is two dozen lines.*

---

## Current state

Implemented: M1–M5 as staged above. Deviations and known gaps:

- **Execution cache key.** Fixed in `58a8867`. The original key `(scriptSig, scriptPubKey, witness, amount, flags)` omitted the spending transaction and had no length prefixes, so a valid scriptSig copied into a second transaction spending an identically scripted output of equal value was accepted from cache without a signature check. The key is now `(wtxid, n_in, amount, len(spk), spk, flags)` and only successes are cached. Regression tests: `crates/consensus/src/validation/tests_script_cache.rs`.
- **BIP341 spent outputs in `connect_block`.** Fixed in `58a8867`. `connect_block` now builds the per-transaction spent-output table whenever an input spends a P2TR output; previously every multi-input taproot spend failed with `TaprootMissingSpentOutputs`.
- **`SignatureCache`** is implemented and exported but not wired into the interpreter.
- **Activation heights** are mainnet-only (`ScriptFlags::for_height`). Other networks need their own table before replay on them is meaningful.
- **Differential coverage** compares accept/reject verdicts only, not error kinds; the fuzzer reaches signature-valid paths rarely because inputs are unstructured bytes.

---

## Cross-references

- `principles.md` §1, §3, §4 — clean-room, minimal deps, fuzzing-first. The disciplines section above is the operational form of these.
- `validation.md` §"Script strategy", §"Cryptographic concerns" — the requirements this document plans against.
- `conformance.md` Layer 2 — the differential fuzzer this document is gated on.
- `fuzz/fuzz_targets/fuzz_script_differential.rs` and `fuzz/src/lib.rs` — the script differential fuzzer.
- `crates/consensus/src/validation/connect.rs::connect_block` and `validation/tx_script_context.rs` — where script verification is wired into Stage 3.
- `conformance/` — the `bitcoinconsensus` v26 FFI bridge that ground-truths every milestone.
