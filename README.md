# Mantle

A clean-room Bitcoin full-node implementation in Rust. No code is shared with
Bitcoin Core; consensus rules are derived from the BIPs and checked against
Core's behaviour with differential fuzzing.

**Status: experimental. Do not use Mantle to decide whether you have received
bitcoin.** `mantle-replay` has validated every mainnet block from genesis to
height 972,245, with all scripts checked, and reported no consensus failures
(commit `d66dadd`, 21.6 hours on an 18-core AMD EPYC). Tapscript and taproot
verification agrees with Core on all 2,244 cases of Core's
`script_assets_test.json`. This shows Mantle accepts the blocks Core accepted.
It does not show Mantle rejects every block Core would reject, and Mantle's
UTXO set has not yet been compared against Core's. See
`docs/architecture/validation.md` §"Known gaps" and
`docs/architecture/conformance.md` §"Current coverage".

Linux only: storage and networking use io_uring.

## Layout

| Path | Contents |
|---|---|
| `crates/mantle` | Primitives, codecs, P2P message types |
| `crates/consensus` | Block validation stages 1–3, script interpreter, sighash |
| `crates/storage` | Storage thread and UTXO engines (`RobinHoodEngine`, `FlatEngine`) |
| `crates/validator` | Batched coin prefetch and `connect_block` pipeline |
| `crates/transport`, `crates/fetcher`, `crates/block-io` | io_uring P2P transport, header and block download, block cache |
| `replay` | `mantle-replay`: fetch mainnet blocks from peers and validate them into storage |
| `conformance` | Bridge to `bitcoinconsensus` (Core v26), BIP vectors, Core's `script_assets` vectors, property tests |
| `fuzz` | cargo-fuzz targets, including the script differential against Core; `fuzz/bitcoinfuzz` is a work-in-progress bitcoinfuzz module |
| `bench` | divan benchmarks and dhat/pprof profilers |
| `archive` | Superseded storage experiments; not built by default |
| `docs/architecture` | Design documents |

## Building and testing

```
cargo build
cargo test
cargo test --manifest-path fuzz/Cargo.toml
cargo +nightly fuzz run fuzz_script_differential   # from fuzz/
```

The taproot differential test needs Core's vectors from
[bitcoin-core/qa-assets](https://github.com/bitcoin-core/qa-assets); it skips
without them:

```
SCRIPT_ASSETS_JSON=path/to/qa-assets/unit_test_data/script_assets_test.json \
    cargo test --release -p mantle-conformance --test script_assets
```

## Running a replay

```
cargo run --release -p mantle-replay -- \
    --peer-file peers.txt --stop-height 100000
```

Only mainnet validation is supported; other networks accept `--download-only`.

The GitLab CI job `full-chain-verify` runs the `script_assets` test and then a
replay from genesis to the tip with `--keep-going`, so every failure is listed
rather than only the first.

## License

MIT. See `LICENSE`.
