use std::fs;
use std::io;
use std::path::PathBuf;

use mantle::primitives::{BlockHeight, Hash256};

/// Writes the raw bytes of each block that fails a consensus check to its own
/// file, so failures from a remote run can be copied back and turned into
/// regression tests.
pub struct FailureBlocks {
    dir: PathBuf,
}

impl FailureBlocks {
    /// # Errors
    /// Returns an error if `dir` cannot be created.
    pub fn new(dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    #[must_use]
    pub fn path_for(&self, height: BlockHeight, hash: Hash256) -> PathBuf {
        self.dir
            .join(format!("{:07}-{hash}.block", height.to_u32()))
    }

    /// Write `bytes` to `<dir>/<height>-<hash>.block`. The bytes go to a
    /// temporary name first and are renamed into place, so a concurrent rsync
    /// never copies a partial file.
    ///
    /// # Errors
    /// Returns an error if the file cannot be written or renamed.
    pub fn save(&self, height: BlockHeight, hash: Hash256, bytes: &[u8]) -> io::Result<PathBuf> {
        let path = self.path_for(height, hash);
        let partial = path.with_extension("block.partial");
        fs::write(&partial, bytes)?;
        fs::rename(&partial, &path)?;
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saves_bytes_under_height_and_hash() {
        let dir = std::env::temp_dir().join(format!(
            "mantle-failure-blocks-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let blocks = FailureBlocks::new(dir.clone()).expect("create dir");
        let hash = Hash256::from_bytes([0x22; 32]);
        let path = blocks
            .save(BlockHeight::new(2277), hash, b"raw block")
            .expect("save");

        assert_eq!(path, blocks.path_for(BlockHeight::new(2277), hash));
        assert!(
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("0002277-")
        );
        assert_eq!(fs::read(&path).expect("read"), b"raw block");
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .expect("list")
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|x| x == "partial"))
            .collect();
        assert!(leftovers.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }
}
