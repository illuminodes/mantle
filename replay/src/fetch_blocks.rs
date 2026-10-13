use std::path::{Path, PathBuf};
use std::process::ExitCode;

use mantle::network::Network;
use mantle_replay::block_download::BlockDownload;
use mantle_replay::block_files::BlockFiles;
use mantle_replay::peer_list::PeerList;
use mantle_replay::target_list::TargetList;

const HELP: &str = "\
fetch-blocks — download specific blocks by hash, with no header sync.

Each block is checked only for internal integrity (decodes as one block,
hashes to the requested hash, merkle root matches its transactions), then
written to OUT/<height>-<hash>.block, or OUT/<hash>.block when the height
is unknown. Blocks already in OUT are skipped.

Usage:
    fetch-blocks [OPTIONS] --out DIR (--peer HOST:PORT | --peer-file PATH)
                 [TARGET]... [--targets PATH]...

Targets (positional or one per line in a --targets file):
    HASH                  64-hex block hash, display order.
    HEADER                160-hex raw 80-byte header.
    HEIGHT-HASH[.block]   Saved block name, e.g. 0002277-0000…7df0.block.
    HEIGHT<TAB>HASH…      A --failures-file TSV row; extra columns ignored.
    Blank lines and # comments are skipped.

Options:
    --out DIR             Output directory for .block files.
    --targets PATH        Read targets from PATH; may be repeated.
    --network NAME        mainnet | testnet3 | testnet4 | signet | regtest
                          (default: mainnet).
    --peer HOST:PORT      P2P peer; may be repeated.
    --peer-file PATH      One IP:PORT per line, e.g. rank-peers output.
    --scratch-dir DIR     Download cache, removed on exit
                          (default: OUT/.fetch-scratch).
    --help                Print this message and exit.

Exits 1 if any block was not saved.
";

struct FetchBlocks {
    network: Network,
    peers: PeerList,
    targets: TargetList,
    out: PathBuf,
    scratch: Option<PathBuf>,
}

impl FetchBlocks {
    fn parse(raw: &[String]) -> Result<Option<Self>, String> {
        let mut network = Network::Mainnet;
        let mut peers = PeerList::new();
        let mut targets = TargetList::new();
        let mut out: Option<PathBuf> = None;
        let mut scratch: Option<PathBuf> = None;

        let mut args = raw.iter();
        while let Some(arg) = args.next() {
            let mut value = |flag: &str| {
                args.next()
                    .ok_or_else(|| format!("{flag} requires a value"))
            };
            match arg.as_str() {
                "--help" | "-h" => return Ok(None),
                "--network" => {
                    let v = value("--network")?;
                    network = Network::parse(v).ok_or_else(|| format!("unknown network: {v}"))?;
                }
                "--peer" => peers.push_spec(value("--peer")?)?,
                "--peer-file" => {
                    peers.extend_from_file(Path::new(value("--peer-file")?))?;
                }
                "--targets" => {
                    targets.extend_from_file(Path::new(value("--targets")?))?;
                }
                "--out" => out = Some(PathBuf::from(value("--out")?)),
                "--scratch-dir" => scratch = Some(PathBuf::from(value("--scratch-dir")?)),
                flag if flag.starts_with("--") => return Err(format!("unknown argument: {flag}")),
                token => targets.push_token(token)?,
            }
        }

        if peers.is_empty() {
            return Err("no peers: supply --peer HOST:PORT or --peer-file PATH".to_string());
        }
        if targets.is_empty() {
            return Err("no targets: pass block hashes or --targets PATH".to_string());
        }
        Ok(Some(Self {
            network,
            peers,
            targets,
            out: out.ok_or("--out is required")?,
            scratch,
        }))
    }

    fn run(self) -> Result<usize, String> {
        let files = BlockFiles::new(self.out.clone())
            .map_err(|e| format!("create {}: {e}", self.out.display()))?;
        let scratch = self
            .scratch
            .unwrap_or_else(|| self.out.join(".fetch-scratch"));
        eprintln!(
            "fetch-blocks: {} target(s), {} peer(s), network {}",
            self.targets.len(),
            self.peers.addrs().len(),
            self.network.name()
        );
        let outcomes = BlockDownload::new(self.network, &self.peers, scratch)?
            .fetch(self.targets.targets(), &files);

        let mut missing = 0;
        for (target, outcome) in self.targets.targets().iter().zip(&outcomes) {
            eprintln!("  {target}: {outcome}");
            missing += usize::from(!outcome.is_ok());
        }
        eprintln!(
            "fetch-blocks: {} saved or present, {missing} missing",
            outcomes.len() - missing
        );
        Ok(missing)
    }
}

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let cmd = match FetchBlocks::parse(&raw) {
        Ok(Some(cmd)) => cmd,
        Ok(None) => {
            print!("{HELP}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("error: {e}\n\n{HELP}");
            return ExitCode::from(2);
        }
    };
    match cmd.run() {
        Ok(0) => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("fatal: {e}");
            ExitCode::FAILURE
        }
    }
}
