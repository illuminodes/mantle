//! `mantle-replay` — Stage 3 historical replay binary.
//!
//! Drives the replay loop committed to in `docs/architecture/replay.md`:
//!
//! ```text
//! for height in start..=target:
//!     hash  = headers[height]
//!     bytes = fetcher.read_block_bytes(height)
//!     block = Block::decode(bytes)
//!     validate_block_structure(&block)?
//!     validate_block_context(&block, &header_snapshot)?
//!     validator::validate_and_commit(
//!         &block, height, &mut storage, &header_snapshot,
//!         skip_script, Some(&mut exec_cache),
//!         if height % 2016 == 0 { Synced } else { Memory },
//!     )?
//! ```
//!
//! CLI: `mantle-replay [--data-dir DIR] [--network NAME] [--peer HOST:PORT]…
//!                    [--skip-script] [--start-height N] [--stop-height N] [--help]`.

mod failures;
mod report;

use std::path::PathBuf;
use std::process::ExitCode;

use mantle::collections::{BuildPrehashedHasher, PrehashedMap};
use mantle::network::Network;
use mantle::primitives::{BlockHeader, BlockHeight, Hash256};
use mantle_consensus::script::ScriptExecutionCache;
use mantle_consensus::validation::{validate_block_context, validate_block_structure};
use mantle_storage::StorageHandle;
use mantle_storage::types::{Durability, ReqToken};
use mantle::primitives::Block;
use mantle_validator::{
    ForcedCommit, HeaderSnapshot, PipelineError, PipelineOpts, PrefetchedView, ReplayBufs,
};

use crate::failures::{FailureLog, FailureStage};
use crate::report::Reporter;
use mantle_fetcher::Fetcher;
use mantle_replay::block_files::BlockFiles;
use mantle_replay::peer_list::PeerList;
use mantle_replay::utxo_hash_check::{UtxoHashReference, UtxoHashTracker, UtxoHashVerdict};

struct ReplayCtx {
    storage: StorageHandle<'static>,
    skip_script: bool,
    allow_min_difficulty: bool,
    cache: ScriptExecutionCache,
    bufs: ReplayBufs,
    token: u64,
    forced: ForcedCommit,
    failures: Option<FailureLog>,
    failure_blocks: Option<BlockFiles>,
    utxo_hash: Option<UtxoHashTracker>,
}

/// Block at which `Durability::Synced` flushes everything to disk. Matches
/// difficulty-adjustment-period boundaries — a natural checkpoint cadence.
const SYNC_EVERY: u32 = 2_016;
/// Cap script-execution cache at this many entries.
const SCRIPT_CACHE_ENTRIES: usize = 64 * 1024;

// ── CLI ──────────────────────────────────────────────────────────────────────

struct Args {
    data_dir: PathBuf,
    block_cache_dir: Option<PathBuf>,
    network: Network,
    extra_peers: PeerList,
    skip_script: bool,
    download_only: bool,
    /// First height to validate. Defaults to `storage.tip().height + 1`.
    start_height: Option<BlockHeight>,
    /// Last height to validate (inclusive). Defaults to whatever the peer
    /// reports as its current tip after a single `getheaders` page.
    stop_height: Option<BlockHeight>,
    locator_hash: Option<Hash256>,
    verify: VerifyOpts,
}

struct VerifyOpts {
    keep_going: bool,
    failures_file: Option<PathBuf>,
    failure_blocks_dir: Option<PathBuf>,
    ephemeral: bool,
    window: usize,
    progress_every: std::time::Duration,
    utxo_hash_file: Option<PathBuf>,
    utxo_hash_every: Option<u32>,
}

impl VerifyOpts {
    fn utxo_hash_tracker(&self) -> Result<Option<UtxoHashTracker>, String> {
        if self.utxo_hash_file.is_none() && self.utxo_hash_every.is_none() {
            return Ok(None);
        }
        let reference = match &self.utxo_hash_file {
            Some(path) => UtxoHashReference::load(path)?,
            None => UtxoHashReference::default(),
        };
        Ok(Some(UtxoHashTracker::new(reference, self.utxo_hash_every)))
    }

    fn failure_log(&self) -> Result<Option<FailureLog>, String> {
        if !self.keep_going {
            return Ok(None);
        }
        FailureLog::new(self.failures_file.as_deref())
            .map(Some)
            .map_err(|e| format!("create failures file: {e}"))
    }

    fn failure_blocks(&self) -> Result<Option<BlockFiles>, String> {
        self.failure_blocks_dir
            .clone()
            .map(|dir| {
                BlockFiles::new(dir.clone())
                    .map_err(|e| format!("create failure blocks dir {}: {e}", dir.display()))
            })
            .transpose()
    }

    fn mode_suffix(&self) -> &'static str {
        match (self.keep_going, self.ephemeral) {
            (true, true) => ", keep-going, ephemeral",
            (true, false) => ", keep-going",
            (false, true) => ", ephemeral",
            (false, false) => "",
        }
    }
}

const DEFAULT_EPHEMERAL_WINDOW: usize = 1_000;

const HELP: &str = "\
mantle-replay — historical replay against a Bitcoin Core-compatible network

Usage:
    mantle-replay [OPTIONS]

Options:
    --data-dir DIR        Validated storage root (default: ./data/<network>)
    --block-cache-dir DIR Separate block/header cache for download-only runs.
                          Defaults to --data-dir.
    --network NAME        mainnet | testnet3 | testnet4 | signet | regtest
                          (default: mainnet). Aliases: main, test, testnet.
    --peer HOST:PORT      Extra P2P peer; may be repeated. Required when the
                          network has no built-in seed list (testnet3, signet,
                          regtest); optional otherwise (mainnet/testnet4).
    --peer-file PATH      Append one IP:PORT per line to the peer list.
                          Blank lines and `#`-prefixed comments are skipped.
                          Useful with the curated lists `discover-peers`
                          writes, or external sources like
                          https://testnet4.achownodes.xyz/seeds.txt.gz.
    --skip-script         Skip script verification (Stage 2; faster bring-up).
    --download-only       Fetch and cache blocks, without replaying or mutating
                          validated chain state. The only mode allowed on
                          networks other than mainnet, whose consensus
                          parameters are not implemented yet.
    --start-height N      First height to validate. Default: storage tip + 1.
    --stop-height N       Last height to validate (inclusive).
                          Default: peer tip from one getheaders call.
    --locator-hash HEX    Hash of the block immediately before START. Required
                          for historical download-only ranges.
    --keep-going          Do not stop at a consensus failure. Print it as a
                          `CONSENSUS FAILURE` line, apply the block's UTXO
                          changes unvalidated, and continue. Exits 1 at the
                          end if any failure was seen.
    --failures-file PATH  Also append each failure to PATH as TSV.
    --failure-blocks-dir DIR
                          Save the raw bytes of every block that fails a
                          consensus check to DIR/<height>-<hash>.block.
                          Must be outside --data-dir with --ephemeral.
    --ephemeral           Do not keep the chain: download blocks in windows,
                          delete each window after validating it, and remove
                          --data-dir on exit. Requires an empty --data-dir.
    --window N            Blocks per download window (default: 1000 with
                          --ephemeral, whole range otherwise).
    --progress-secs N     Seconds between replay progress lines (default: 2).
                          Raise it for long CI runs to stay under the job
                          log size limit.
    --utxo-hash-file PATH Track the UTXO set MuHash and compare it at each
                          height listed in PATH (`<height> <muhash>` lines,
                          from `bitcoin-cli gettxoutsetinfo muhash <height>`).
                          A mismatch is a consensus failure. Requires
                          --start-height 1 (the hash starts from genesis).
    --utxo-hash-every N   Track the UTXO set MuHash and print it every N
                          blocks as a `UTXO HASH` line.
    --help                Print this message and exit.
";

#[allow(clippy::too_many_lines)]
fn parse_args() -> Result<Args, String> {
    let mut data_dir: Option<PathBuf> = None;
    let mut block_cache_dir: Option<PathBuf> = None;
    let mut network = Network::Mainnet;
    let mut extra_peers = PeerList::new();
    let mut skip_script = false;
    let mut download_only = false;
    let mut start_height: Option<BlockHeight> = None;
    let mut stop_height: Option<BlockHeight> = None;
    let mut locator_hash: Option<Hash256> = None;
    let mut keep_going = false;
    let mut failures_file: Option<PathBuf> = None;
    let mut failure_blocks_dir: Option<PathBuf> = None;
    let mut ephemeral = false;
    let mut window: Option<usize> = None;
    let mut progress_secs: u64 = 2;
    let mut utxo_hash_file: Option<PathBuf> = None;
    let mut utxo_hash_every: Option<u32> = None;

    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--help" | "-h" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            "--data-dir" => {
                i += 1;
                let v = raw.get(i).ok_or("--data-dir requires a path")?;
                data_dir = Some(PathBuf::from(v));
            }
            "--block-cache-dir" => {
                i += 1;
                let v = raw.get(i).ok_or("--block-cache-dir requires a path")?;
                block_cache_dir = Some(PathBuf::from(v));
            }
            "--network" => {
                i += 1;
                let v = raw.get(i).ok_or("--network requires a name")?;
                network = Network::parse(v).ok_or_else(|| format!("unknown network: {v}"))?;
            }
            "--peer" => {
                i += 1;
                let v = raw.get(i).ok_or("--peer requires HOST:PORT")?;
                extra_peers.push_spec(v)?;
            }
            "--peer-file" => {
                i += 1;
                let v = raw.get(i).ok_or("--peer-file requires a path")?;
                let added = extra_peers.extend_from_file(std::path::Path::new(v))?;
                eprintln!("  loaded {added} peers from {v}");
            }
            "--locator-hash" => {
                i += 1;
                let v = raw.get(i).ok_or("--locator-hash requires a hex hash")?;
                locator_hash = Some(
                    Hash256::from_display_hex(v)
                        .map_err(|e| format!("invalid --locator-hash {v}: {e}"))?,
                );
            }
            "--skip-script" => {
                skip_script = true;
            }
            "--download-only" => {
                download_only = true;
            }
            "--keep-going" => {
                keep_going = true;
            }
            "--ephemeral" => {
                ephemeral = true;
            }
            "--failures-file" => {
                i += 1;
                let v = raw.get(i).ok_or("--failures-file requires a path")?;
                failures_file = Some(PathBuf::from(v));
            }
            "--failure-blocks-dir" => {
                i += 1;
                let v = raw.get(i).ok_or("--failure-blocks-dir requires a path")?;
                failure_blocks_dir = Some(PathBuf::from(v));
            }
            "--progress-secs" => {
                i += 1;
                let v = raw.get(i).ok_or("--progress-secs requires N")?;
                progress_secs = v
                    .parse()
                    .map_err(|e| format!("invalid --progress-secs {v}: {e}"))?;
            }
            "--utxo-hash-file" => {
                i += 1;
                let v = raw.get(i).ok_or("--utxo-hash-file requires a path")?;
                utxo_hash_file = Some(PathBuf::from(v));
            }
            "--utxo-hash-every" => {
                i += 1;
                let v = raw.get(i).ok_or("--utxo-hash-every requires N")?;
                let n: u32 = v
                    .parse()
                    .map_err(|e| format!("invalid --utxo-hash-every {v}: {e}"))?;
                if n == 0 {
                    return Err("--utxo-hash-every must be at least 1".to_string());
                }
                utxo_hash_every = Some(n);
            }
            "--window" => {
                i += 1;
                let v = raw.get(i).ok_or("--window requires N")?;
                let n: usize = v.parse().map_err(|e| format!("invalid --window {v}: {e}"))?;
                if n == 0 {
                    return Err("--window must be at least 1".to_string());
                }
                window = Some(n);
            }
            "--assume-valid" => {
                return Err(
                    "--assume-valid is not implemented; use --skip-script to skip all scripts"
                        .to_string(),
                );
            }
            "--start-height" => {
                i += 1;
                let v = raw.get(i).ok_or("--start-height requires N")?;
                let n: u32 = v
                    .parse()
                    .map_err(|e| format!("invalid --start-height {v}: {e}"))?;
                start_height = Some(BlockHeight::new(n));
            }
            "--stop-height" => {
                i += 1;
                let v = raw.get(i).ok_or("--stop-height requires N")?;
                let n: u32 = v
                    .parse()
                    .map_err(|e| format!("invalid --stop-height {v}: {e}"))?;
                stop_height = Some(BlockHeight::new(n));
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }

    if !download_only && network != Network::Mainnet {
        return Err(format!(
            "validation on {} is not supported: activation heights are mainnet-only; \
             use --download-only",
            network.name()
        ));
    }

    if ephemeral && download_only {
        return Err("--ephemeral discards blocks, so it cannot be combined with --download-only"
            .to_string());
    }
    if ephemeral && block_cache_dir.is_some() {
        return Err("--ephemeral keeps blocks under --data-dir; drop --block-cache-dir".to_string());
    }
    if failures_file.is_some() && !keep_going {
        return Err("--failures-file requires --keep-going".to_string());
    }
    let tracks_utxo_hash = utxo_hash_file.is_some() || utxo_hash_every.is_some();
    if tracks_utxo_hash && download_only {
        return Err("--utxo-hash-* needs a replay; drop --download-only".to_string());
    }
    if tracks_utxo_hash && start_height != Some(BlockHeight::new(1)) {
        return Err(
            "--utxo-hash-* hashes the UTXO set from genesis; pass --start-height 1 \
             with an empty --data-dir"
                .to_string(),
        );
    }
    if tracks_utxo_hash && skip_script {
        eprintln!("  note: --skip-script with --utxo-hash-* still compares UTXO sets");
    }

    let data_dir = data_dir.unwrap_or_else(|| PathBuf::from(format!("./data/{}", network.name())));
    if ephemeral
        && failure_blocks_dir
            .as_deref()
            .is_some_and(|d| d.starts_with(&data_dir))
    {
        return Err(
            "--failure-blocks-dir must be outside --data-dir, which --ephemeral deletes"
                .to_string(),
        );
    }
    let window = window.unwrap_or(if ephemeral {
        DEFAULT_EPHEMERAL_WINDOW
    } else {
        usize::MAX
    });

    Ok(Args {
        data_dir,
        block_cache_dir,
        network,
        extra_peers,
        skip_script,
        download_only,
        start_height,
        stop_height,
        locator_hash,
        verify: VerifyOpts {
            keep_going,
            failures_file,
            failure_blocks_dir,
            ephemeral,
            window,
            progress_every: std::time::Duration::from_secs(progress_secs),
            utxo_hash_file,
            utxo_hash_every,
        },
    })
}

// ── header snapshot construction ─────────────────────────────────────────────

/// Lookback applied to the snapshot when starting mid-chain. BIP68
/// time-based sequence locks need the median time past at the height of
/// any spent coin, however old, so the snapshot carries the whole header
/// chain back to genesis. Storage holds every committed header, so this is
/// a contiguous range read.
const SNAPSHOT_LOOKBACK: u32 = u32::MAX;

/// Build a `HeaderSnapshot` for validating `[start..=stop]`. The snapshot
/// must carry enough *prior* headers that
/// `validate_block_context` can resolve the parent of `start`, compute
/// MTP (needs 11 ancestors), and look up the previous retarget boundary
/// (needs 2 016 ancestors at retarget heights). Sources:
///
/// - `headers`: the just-resolved headers for `[start..=stop]`.
/// - `storage` (when `start > 1`): the most recent
///   `SNAPSHOT_LOOKBACK` committed headers preceding `start`. Storage
///   exposes `read_header_at` keyed by height, so this is a tight loop.
/// - `network.genesis_header()` (when `start == 1`): a synthetic height-0
///   pre-genesis slot so block 1 has a parent for MTP. Earlier code
///   pushed `headers[0]` (block 1) into this slot, which made MTP at
///   height 1 == block 1's own time — failing BIP113's strict-`>` rule.
fn build_snapshot(
    start: BlockHeight,
    headers: &[BlockHeader],
    network: Network,
    storage: &mut StorageHandle,
) -> Result<HeaderSnapshot, String> {
    if headers.is_empty() {
        return Err("no headers to build a snapshot from".to_string());
    }
    if start.to_u32() == 1 {
        let genesis = network.genesis_header().ok_or_else(|| {
            format!(
                "{} genesis header not yet baked in; supply --start-height \
                 along with a pre-populated headers.bin instead of starting \
                 from height 1",
                network.name()
            )
        })?;
        let mut entries: Vec<(Hash256, BlockHeader)> = Vec::with_capacity(headers.len() + 1);
        entries.push((genesis.hash(), genesis));
        for hdr in headers {
            entries.push((hdr.hash(), *hdr));
        }
        return HeaderSnapshot::new(BlockHeight::new(0), entries)
            .map_err(|e| format!("snapshot too large: {e:?}"));
    }
    // start > 1 — pull lookback from storage. Stored heights span
    // `[1..=tip]`, so we ask for `[max(1, start - SNAPSHOT_LOOKBACK)..=start - 1]`,
    // and prepend a synthetic height-0 slot carrying the network's genesis
    // header so that `expected_nbits` at the next retarget boundary
    // (which looks up `this_height - 2016`) finds a valid record at
    // height 0.
    let storage_lo = start.to_u32().saturating_sub(SNAPSHOT_LOOKBACK).max(1);
    let need_genesis = start.to_u32().saturating_sub(SNAPSHOT_LOOKBACK) == 0;
    let lookback_count = start.to_u32() - storage_lo;
    let mut entries: Vec<(Hash256, BlockHeader)> = Vec::with_capacity(
        usize::from(need_genesis) + usize::try_from(lookback_count).unwrap_or(0) + headers.len(),
    );
    let base = if need_genesis {
        let genesis = network.genesis_header().ok_or_else(|| {
            format!(
                "{} genesis header not yet baked in; cannot build a \
                 snapshot whose lookback reaches height 0",
                network.name()
            )
        })?;
        entries.push((genesis.hash(), genesis));
        BlockHeight::new(0)
    } else {
        BlockHeight::new(storage_lo)
    };
    for h in storage_lo..start.to_u32() {
        let hdr = storage
            .read_header_at(BlockHeight::new(h))
            .map_err(|e| format!("read stored header at {h}: {e}"))?
            .ok_or_else(|| format!("storage missing committed header at height {h}"))?;
        entries.push((hdr.hash(), hdr));
    }
    for hdr in headers {
        entries.push((hdr.hash(), *hdr));
    }
    HeaderSnapshot::new(base, entries).map_err(|e| format!("snapshot too large: {e:?}"))
}

// ── main ─────────────────────────────────────────────────────────────────────

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("{HELP}");
            return ExitCode::from(2);
        }
    };

    if args.verify.ephemeral
        && std::fs::read_dir(&args.data_dir).is_ok_and(|mut d| d.next().is_some())
    {
        eprintln!(
            "error: --ephemeral needs an empty or missing --data-dir; {} has files",
            args.data_dir.display()
        );
        return ExitCode::from(2);
    }

    if let Err(e) = std::fs::create_dir_all(&args.data_dir) {
        eprintln!(
            "error: cannot create data dir {}: {e}",
            args.data_dir.display()
        );
        return ExitCode::FAILURE;
    }

    let result = run(&args);

    if args.verify.ephemeral {
        match std::fs::remove_dir_all(&args.data_dir) {
            Ok(()) => eprintln!("  removed ephemeral data dir {}", args.data_dir.display()),
            Err(e) => eprintln!(
                "  warning: could not remove ephemeral data dir {}: {e}",
                args.data_dir.display()
            ),
        }
    }

    match result {
        Ok(0) => ExitCode::SUCCESS,
        Ok(failures) => {
            eprintln!("finished with {failures} consensus failure(s)");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("fatal: {e}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run(args: &Args) -> Result<u64, String> {
    eprintln!(
        "mantle-replay starting on {} (data-dir {})",
        args.network.name(),
        args.data_dir.display()
    );

    // ── Storage ──────────────────────────────────────────────────────────────
    let mut storage =
        StorageHandle::open_robin_hood(&args.data_dir).map_err(|e| format!("open storage: {e}"))?;
    let tip = storage.tip();
    let next_to_validate = BlockHeight::new(tip.height.to_u32().saturating_add(1));
    let start_height = args.start_height.unwrap_or(next_to_validate);
    if start_height < next_to_validate {
        return Err(format!(
            "--start-height {} precedes storage tip + 1 ({}); refusing to overwrite",
            start_height.to_u32(),
            next_to_validate.to_u32()
        ));
    }
    eprintln!(
        "  storage tip = {} ({:?}); validating from height {}",
        tip.height.to_u32(),
        tip.hash,
        start_height.to_u32(),
    );

    // ── Peers ────────────────────────────────────────────────────────────────
    // Peer list comes exclusively from `--peer` / `--peer-file`. DNS seeds
    // were unreliable in practice (stale entries that aggressively close on
    // version handshake, polluting the pool) — the curated lists from
    // `rank-peers` give us live peers without the seed-induced flakiness.
    if args.extra_peers.is_empty() {
        return Err(format!(
            "no peers: supply --peer HOST:PORT or --peer-file PATH (network={})",
            args.network.name()
        ));
    }
    let block_cache_dir = args
        .block_cache_dir
        .as_deref()
        .unwrap_or(&args.data_dir);
    std::fs::create_dir_all(block_cache_dir)
        .map_err(|e| format!("create block cache dir {}: {e}", block_cache_dir.display()))?;
    let mut fetcher = Fetcher::new(args.network, args.extra_peers.addrs().to_vec(), block_cache_dir)
        .map_err(|e| format!("fetcher init: {e}"))?;

    // ── Phase 1: sync all headers to tip ──────────────────────────────────
    let locator = if let Some(locator_hash) = args.locator_hash {
        locator_hash
    } else if start_height.to_u32() <= 1 {
        args.network.genesis_hash()
    } else if args.download_only && args.start_height.is_some() {
        return Err(
            "historical --download-only ranges require --locator-hash equal to the block before START"
                .to_string(),
        );
    } else {
        tip.hash
    };
    let stop_height = args.stop_height.unwrap_or(BlockHeight::new(u32::MAX));

    eprintln!(
        "  syncing headers from height {} to {}…",
        start_height.to_u32(),
        if stop_height.to_u32() == u32::MAX {
            "tip".to_string()
        } else {
            stop_height.to_u32().to_string()
        },
    );

    let header_pairs = fetcher
        .sync_headers(start_height, stop_height, locator)
        .map_err(|e| format!("sync headers: {e:?}"))?;

    if header_pairs.is_empty() {
        eprintln!("  no new headers from peers — already at tip");
        storage.shutdown().map_err(|e| format!("shutdown: {e}"))?;
        return Ok(0);
    }

    let actual_stop = header_pairs.last().unwrap().0;
    eprintln!(
        "  got {} headers ({}..={})",
        header_pairs.len(),
        start_height.to_u32(),
        actual_stop.to_u32(),
    );

    if args.download_only {
        eprintln!("  downloading blocks…");
        fetcher
            .fetch_blocks(&header_pairs)
            .map_err(|e| format!("fetch blocks: {e:?}"))?;
        eprintln!(
            "download complete: cached blocks {}..={} (no replay performed)",
            start_height.to_u32(),
            actual_stop.to_u32(),
        );
        return Ok(0);
    }

    // ── Phase 2: download + replay, one window at a time ───────────────
    let headers: Vec<BlockHeader> = header_pairs.iter().map(|(_, h)| *h).collect();
    let snapshot = build_snapshot(start_height, &headers, args.network, &mut storage)?;

    let allow_min_difficulty = matches!(args.network, Network::Testnet3 | Network::Testnet4);
    let mut ctx = ReplayCtx {
        storage,
        skip_script: args.skip_script,
        allow_min_difficulty,
        cache: ScriptExecutionCache::new(SCRIPT_CACHE_ENTRIES),
        bufs: ReplayBufs::new(),
        token: u64::from(tip.height.to_u32()).saturating_add(1),
        forced: ForcedCommit::new(),
        failures: args.verify.failure_log()?,
        failure_blocks: args.verify.failure_blocks()?,
        utxo_hash: args.verify.utxo_hash_tracker()?,
    };

    eprintln!(
        "  replaying {}..={} ({} script verification{})…",
        start_height.to_u32(),
        actual_stop.to_u32(),
        if args.skip_script { "skipping" } else { "with" },
        args.verify.mode_suffix(),
    );

    let mut reporter = Reporter::new(start_height, actual_stop, args.verify.progress_every);
    let last_committed = ctx.replay_range(
        &header_pairs,
        &args.verify,
        &mut fetcher,
        &snapshot,
        &mut reporter,
    )?;
    reporter.done(last_committed);

    eprintln!("IBD complete at height {}", last_committed.to_u32());
    let failures = ctx.summarize_failures();
    ctx.storage
        .shutdown()
        .map_err(|e| format!("shutdown storage: {e}"))?;
    Ok(failures)
}

impl ReplayCtx {
    fn replay_range<RReq, RResp>(
        &mut self,
        header_pairs: &[(BlockHeight, BlockHeader)],
        verify: &VerifyOpts,
        fetcher: &mut Fetcher<RReq, RResp>,
        snapshot: &HeaderSnapshot,
        reporter: &mut Reporter,
    ) -> Result<BlockHeight, String>
    where
        RReq: std::ops::Deref<Target = quetzalcoatl::mpsc::RingBuffer<mantle_block_io::FileReq>>,
        RResp: std::ops::Deref<Target = quetzalcoatl::spsc::RingBuffer<mantle_block_io::FileResp>>,
    {
        let mut last_committed = self.storage.tip().height;
        for window in header_pairs.chunks(verify.window) {
            let (first, _) = window[0];
            let (last, _) = window[window.len() - 1];
            eprintln!(
                "  downloading blocks {}..={}…",
                first.to_u32(),
                last.to_u32()
            );
            fetcher
                .fetch_blocks(window)
                .map_err(|e| format!("fetch blocks: {e:?}"))?;
            for (height, header) in window {
                self.replay_block(*height, *header, fetcher, snapshot)?;
                last_committed = *height;
                reporter.tick(*height);
            }
            if verify.ephemeral {
                fetcher
                    .discard_cached_blocks()
                    .map_err(|e| format!("discard blocks: {e}"))?;
            }
        }
        Ok(last_committed)
    }

    fn replay_block<RReq, RResp>(
        &mut self,
        height: BlockHeight,
        header: BlockHeader,
        fetcher: &mut Fetcher<RReq, RResp>,
        snapshot: &HeaderSnapshot,
    ) -> Result<(), String>
    where
        RReq: std::ops::Deref<Target = quetzalcoatl::mpsc::RingBuffer<mantle_block_io::FileReq>>,
        RResp: std::ops::Deref<Target = quetzalcoatl::spsc::RingBuffer<mantle_block_io::FileResp>>,
    {
        let hash = header.hash();
        let block = fetcher
            .read_block_decoded(height, hash)
            .map_err(|e| format!("read block {}: {e}", height.to_u32()))?;

        let mut saved = false;
        if let Err(e) = validate_block_structure(&block) {
            self.save_failed_block(height, hash, fetcher, &mut saved);
            self.fail(height, hash, FailureStage::Structure, &e)?;
        }

        let empty_coins = PrehashedMap::with_hasher(BuildPrehashedHasher);
        let context_view = PrefetchedView::new(&empty_coins, snapshot, self.storage.tip());
        if let Err(e) = validate_block_context(&block, &context_view, self.allow_min_difficulty) {
            self.save_failed_block(height, hash, fetcher, &mut saved);
            self.fail(height, hash, FailureStage::Context, &e)?;
        }

        let durability = if height.to_u32().is_multiple_of(SYNC_EVERY) {
            Durability::Synced
        } else {
            Durability::Memory
        };
        let token = ReqToken(self.token);
        self.token = self.token.saturating_add(1);

        let connected = self.bufs.validate_and_commit(
            &block,
            height,
            &mut self.storage,
            snapshot,
            PipelineOpts {
                skip_script: self.skip_script,
                exec_cache: Some(&mut self.cache),
                durability,
                token,
                utxo_hash: self.utxo_hash.as_mut().and_then(UtxoHashTracker::hash_mut),
            },
        );
        match connected {
            Ok(_) => self.check_utxo_hash(height, hash),
            Err(PipelineError::Validation(e)) => {
                self.save_failed_block(height, hash, fetcher, &mut saved);
                self.fail(height, hash, FailureStage::Connect, &e)?;
                if let Some(tracker) = &mut self.utxo_hash {
                    tracker.stop(height);
                }
                self.force_commit(&block, height, durability, token)
            }
            Err(e @ PipelineError::Storage(_)) => {
                Err(format!("validate_and_commit at {}: {e}", height.to_u32()))
            }
        }
    }

    fn save_failed_block<RReq, RResp>(
        &self,
        height: BlockHeight,
        hash: Hash256,
        fetcher: &mut Fetcher<RReq, RResp>,
        saved: &mut bool,
    ) where
        RReq: std::ops::Deref<Target = quetzalcoatl::mpsc::RingBuffer<mantle_block_io::FileReq>>,
        RResp: std::ops::Deref<Target = quetzalcoatl::spsc::RingBuffer<mantle_block_io::FileResp>>,
    {
        let Some(blocks) = &self.failure_blocks else {
            return;
        };
        if std::mem::replace(saved, true) {
            return;
        }
        let written = fetcher
            .read_block_bytes(height)
            .and_then(|bytes| blocks.save(Some(height), hash, &bytes));
        match written {
            Ok(path) => eprintln!("  saved failing block to {}", path.display()),
            Err(e) => eprintln!(
                "  warning: could not save failing block {}: {e}",
                height.to_u32()
            ),
        }
    }

    fn fail(
        &mut self,
        height: BlockHeight,
        hash: Hash256,
        stage: FailureStage,
        error: &dyn std::fmt::Display,
    ) -> Result<(), String> {
        match &mut self.failures {
            Some(log) => {
                log.record(height, hash, stage, error);
                Ok(())
            }
            None => Err(format!("{stage} check at {}: {error}", height.to_u32())),
        }
    }

    fn force_commit(
        &mut self,
        block: &Block,
        height: BlockHeight,
        durability: Durability,
        token: ReqToken,
    ) -> Result<(), String> {
        self.forced
            .commit(block, height, &mut self.storage, durability, token)
            .map(|_| ())
            .map_err(|e| format!("forced commit at {}: {e}", height.to_u32()))
    }

    fn check_utxo_hash(&mut self, height: BlockHeight, hash: Hash256) -> Result<(), String> {
        let Some(tracker) = &mut self.utxo_hash else {
            return Ok(());
        };
        match tracker.after_block(height) {
            UtxoHashVerdict::NotChecked => Ok(()),
            UtxoHashVerdict::Match(muhash) => {
                eprintln!("  utxo hash matches at height {}: {muhash}", height.to_u32());
                Ok(())
            }
            UtxoHashVerdict::Mismatch { expected, actual } => self.fail(
                height,
                hash,
                FailureStage::UtxoHash,
                &format!("UTXO set MuHash {actual}, Bitcoin Core reports {expected}"),
            ),
        }
    }

    fn summarize_failures(&self) -> u64 {
        if let Some(tracker) = &self.utxo_hash {
            tracker.print_summary();
        }
        self.failures.as_ref().map_or(0, |log| {
            log.print_summary();
            log.total()
        })
    }
}
