use std::io::{Read, Write};
use std::path::Path;

use mantle::primitives::{BlockHeader, BlockTime, BlockVersion, Hash256, Nonce};

use crate::chain_generator::ChainGenerator;
use crate::chain_spec::ChainSpec;

/// A generated chain: the headers before it, which only serve median time
/// past and parent lookups, and the encoded blocks.
pub struct SyntheticChain {
    pub history: Vec<BlockHeader>,
    pub blocks: Vec<Vec<u8>>,
}

impl SyntheticChain {
    pub fn history() -> Vec<BlockHeader> {
        let mut prev = Hash256::ZERO;
        (ChainSpec::FIRST_HEIGHT - ChainSpec::HISTORY..ChainSpec::FIRST_HEIGHT)
            .map(|height| {
                let header = BlockHeader::new(
                    BlockVersion::new(0x2000_0000),
                    prev,
                    Hash256::ZERO,
                    BlockTime::new(ChainSpec::time_at(height)),
                    ChainSpec::BITS,
                    Nonce::new(0),
                );
                prev = header.hash();
                header
            })
            .collect()
    }

    /// # Errors
    /// Returns the I/O error from reading or writing the cache file.
    pub fn load_or_generate(spec: &ChainSpec) -> std::io::Result<Self> {
        let path = spec.cache_path();
        if let Ok(chain) = Self::load(&path) {
            eprintln!("loaded {} blocks from {}", chain.blocks.len(), path.display());
            return Ok(chain);
        }
        let started = std::time::Instant::now();
        let chain = Self::generate(spec);
        eprintln!(
            "generated {} blocks in {:.1}s",
            chain.blocks.len(),
            started.elapsed().as_secs_f64()
        );
        chain.save(&path)?;
        Ok(chain)
    }

    pub fn generate(spec: &ChainSpec) -> Self {
        let history = Self::history();
        let tip = history.last().expect("history is not empty").hash();
        let mut generator = ChainGenerator::new(*spec, tip);
        let blocks = (ChainSpec::FIRST_HEIGHT..=spec.last_height())
            .map(|height| generator.block_bytes(height))
            .collect();
        Self { history, blocks }
    }

    fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut file = std::io::BufWriter::new(std::fs::File::create(path)?);
        file.write_all(&u32::try_from(self.blocks.len()).expect("fits").to_le_bytes())?;
        for block in &self.blocks {
            file.write_all(&u32::try_from(block.len()).expect("fits").to_le_bytes())?;
            file.write_all(block)?;
        }
        file.flush()
    }

    fn load(path: &Path) -> std::io::Result<Self> {
        let mut file = std::io::BufReader::new(std::fs::File::open(path)?);
        let mut word = [0u8; 4];
        file.read_exact(&mut word)?;
        let count = u32::from_le_bytes(word);
        let mut blocks = Vec::with_capacity(count as usize);
        for _ in 0..count {
            file.read_exact(&mut word)?;
            let mut block = vec![0u8; u32::from_le_bytes(word) as usize];
            file.read_exact(&mut block)?;
            blocks.push(block);
        }
        Ok(Self {
            history: Self::history(),
            blocks,
        })
    }
}
