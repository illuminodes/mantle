# Mantle

A clean-room Bitcoin full-node implementation in Rust. No code is shared with
Bitcoin Core; consensus rules are derived from the BIPs and checked against
Core's behaviour with differential fuzzing.

**Status: experimental. Do not use Mantle to decide whether you have received
bitcoin.** Block validation implements the consensus rules but has not been
compared against Bitcoin Core on real chain data, and nothing yet compares
Mantle's UTXO set against Core's. See `docs/architecture/validation.md`
§"Known gaps" and `docs/architecture/conformance.md` §"Current coverage".

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
| `conformance` | Bridge to `bitcoinconsensus` (Core v26), BIP vectors, property tests |
| `fuzz` | cargo-fuzz targets, including the script differential against Core |
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

## Running a replay

```
cargo run --release -p mantle-replay -- \
    --peer-file peers.txt --stop-height 100000
```

Only mainnet validation is supported; other networks accept `--download-only`.

## License

MIT. See `LICENSE`.
