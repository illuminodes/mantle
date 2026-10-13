use mantle::hash::Hash256;

fn main() {
    divan::main();
}

#[divan::bench(args = [0usize, 11, 256, 8192])]
fn sha256d_bench(bencher: divan::Bencher, len: usize) {
    let data = vec![0xabu8; len];
    bencher.bench(|| Hash256::hash(&data));
}

#[divan::bench]
fn checksum_32b() -> [u8; 4] {
    Hash256::checksum(b"a typical ping payload with nonce")
}

// ── Bitcoin Core parity ───────────────────────────────────────────────────────
// These benchmarks use the same input sizes as Bitcoin Core's src/bench/crypto_hash.cpp
// so the numbers can be compared directly.
//
// Core reference: CSHA256D over a 1 MB zero buffer (BUFFER_SIZE = 1'000'000).

/// sha256d over 1 MB — matches Bitcoin Core's `SHA256D` bench (`BUFFER_SIZE=1_000_000`).
#[divan::bench]
fn sha256d_1mb(bencher: divan::Bencher) {
    let data = vec![0u8; 1_000_000];
    bencher.bench(|| Hash256::hash(&data));
}

/// sha256d over 32 bytes — matches Core's `SHA256D_32b` variant.
#[divan::bench]
fn sha256d_32b(bencher: divan::Bencher) {
    let data = [0u8; 32];
    bencher.bench(|| Hash256::hash(&data));
}

/// sha256d over 64 KB — matches Core's SHA256D64 / 1024×64-byte-block variant.
#[divan::bench]
fn sha256d_64kb(bencher: divan::Bencher) {
    let data = vec![0u8; 65_536];
    bencher.bench(|| Hash256::hash(&data));
}
