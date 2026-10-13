use std::fmt;
use std::path::PathBuf;

use mantle::network::Network;
use mantle::primitives::{BlockHeight, Hash256};
use mantle_fetcher::Fetcher;

use crate::block_files::BlockFiles;
use crate::block_integrity::BlockIntegrity;
use crate::block_target::BlockTarget;
use crate::peer_list::PeerList;

/// Downloads chosen blocks by hash from P2P peers, with no header sync,
/// and writes each one that passes [`BlockIntegrity`] to a [`BlockFiles`] dir.
///
/// The fetcher's cache lives in a scratch directory that is removed on drop.
/// Blocks are cached under their position in the target list, not their
/// chain height, which may be unknown.
pub struct BlockDownload {
    fetcher: Fetcher,
    scratch: PathBuf,
}

pub enum Outcome {
    Saved(PathBuf),
    AlreadyPresent(PathBuf),
    NotReceived,
    Corrupt(String),
}

impl Outcome {
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Saved(_) | Self::AlreadyPresent(_))
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Saved(p) => write!(f, "saved {}", p.display()),
            Self::AlreadyPresent(p) => write!(f, "already present at {}", p.display()),
            Self::NotReceived => f.write_str("not received from any peer"),
            Self::Corrupt(e) => write!(f, "corrupt, not saved: {e}"),
        }
    }
}

impl BlockDownload {
    /// Any existing contents of `scratch` are deleted first, because its
    /// cache keys are list positions and would not match a new target list.
    ///
    /// # Errors
    /// Returns an error if the scratch dir or the fetcher cannot be created.
    pub fn new(network: Network, peers: &PeerList, scratch: PathBuf) -> Result<Self, String> {
        if scratch.exists() {
            std::fs::remove_dir_all(&scratch)
                .map_err(|e| format!("clear scratch dir {}: {e}", scratch.display()))?;
        }
        std::fs::create_dir_all(&scratch)
            .map_err(|e| format!("create scratch dir {}: {e}", scratch.display()))?;
        let fetcher = Fetcher::new(network, peers.addrs().to_vec(), &scratch)
            .map_err(|e| format!("fetcher init: {e}"))?;
        Ok(Self { fetcher, scratch })
    }

    /// Fetch every target not already in `out`. Returns one outcome per
    /// target, in order. A download that stops early still saves the blocks
    /// that arrived before it stopped.
    pub fn fetch(&mut self, targets: &[BlockTarget], out: &BlockFiles) -> Vec<Outcome> {
        let wanted: Vec<(BlockHeight, Hash256)> = targets
            .iter()
            .enumerate()
            .filter(|(_, t)| !out.path_for(t.height, t.hash).exists())
            .map(|(i, t)| (Self::cache_key(i), t.hash))
            .collect();
        if !wanted.is_empty() {
            eprintln!("  downloading {} block(s)…", wanted.len());
            if let Err(e) = self.fetcher.fetch_blocks_by_hash(&wanted) {
                eprintln!("  warning: download stopped early: {e}");
            }
        }
        targets
            .iter()
            .enumerate()
            .map(|(i, t)| self.store(Self::cache_key(i), *t, out))
            .collect()
    }

    fn store(&mut self, key: BlockHeight, target: BlockTarget, out: &BlockFiles) -> Outcome {
        let path = out.path_for(target.height, target.hash);
        if path.exists() {
            return Outcome::AlreadyPresent(path);
        }
        let Ok(bytes) = self.fetcher.read_block_bytes(key) else {
            return Outcome::NotReceived;
        };
        if let Err(e) = BlockIntegrity::check(&bytes, target.hash) {
            return Outcome::Corrupt(e.to_string());
        }
        match out.save(target.height, target.hash, &bytes) {
            Ok(path) => Outcome::Saved(path),
            Err(e) => Outcome::Corrupt(format!("write {}: {e}", path.display())),
        }
    }

    fn cache_key(index: usize) -> BlockHeight {
        BlockHeight::new(u32::try_from(index).expect("target count fits in u32"))
    }
}

impl Drop for BlockDownload {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.scratch) {
            eprintln!(
                "  warning: could not remove scratch dir {}: {e}",
                self.scratch.display()
            );
        }
    }
}
