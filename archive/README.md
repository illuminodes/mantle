# archive

Superseded storage experiments, kept as historical reference. Not part of the
default build: these crates are workspace members but excluded from
`default-members`, so `cargo build` / `cargo test` at the root skip them.

| Crate | Contents |
|---|---|
| `storage-engines` | `ArenaEngine`, `DiskArenaEngine`, `TxGroupedEngine`, `ProductionEngine`, plus their WAL format, the `utxo_set` comparison bench, and the `storage-engines-dhat` / `storage-engines-pprof` profilers |
| `utxo-set` | In-memory and disk-backed UTXO set structures those engines are built on |
| `bloom` | Bloom filter used by `ProductionEngine` |
| `lru-cache` | LRU cache used by `ProductionEngine` |

The node uses `RobinHoodEngine` (replay) and `FlatEngine` (tests and
`StorageHandle::open`), both in `crates/storage`.

Build or test explicitly:

```
cargo test -p mantle-storage-engines -p mantle-utxo-set -p mantle-bloom -p mantle-lru
cargo bench -p mantle-storage-engines --bench utxo_set
cargo run --release -p mantle-storage-engines --bin storage-engines-pprof
```

The bench and pprof binary read ordinals fixtures from `bench/fixtures/`.
