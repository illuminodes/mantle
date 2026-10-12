use std::fs;
use std::io;
use std::path::PathBuf;

use mantle::primitives::{BlockHeight, Hash256};

/// Writes raw block bytes to one file per block: `<7-digit height>-<hash>.block`
/// when the height is known, `<hash>.block` otherwise.
pub struct BlockFiles {
    dir: PathBuf,
}

impl BlockFiles {
    /// # Errors
    /// Returns an error if `dir` cannot be created.
    pub fn new(dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    #[must_use]
    pub fn path_for(&self, height: Option<BlockHeight>, hash: Hash256) -> PathBuf {
        match height {
            Some(h) => self.dir.join(format!("{:07}-{hash}.block", h.to_u32())),
            None => self.dir.join(format!("{hash}.block")),
        }
    }

    /// Write `bytes` to [`Self::path_for`]. The bytes go to a temporary name
    /// first and are renamed into place, so a concurrent rsync never copies a
    /// partial file.
    ///
    /// # Errors
    /// Returns an error if the file cannot be written or renamed.
    pub fn save(
        &self,
        height: Option<BlockHeight>,
        hash: Hash256,
        bytes: &[u8],
    ) -> io::Result<PathBuf> {
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

    fn scratch_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "mantle-block-files-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ))
    }

    #[test]
    fn saves_bytes_under_height_and_hash() {
        let dir = scratch_dir();
        let blocks = BlockFiles::new(dir.clone()).expect("create dir");
        let hash = Hash256::from_bytes([0x22; 32]);
        let height = Some(BlockHeight::new(2277));
        let path = blocks.save(height, hash, b"raw block").expect("save");

        assert_eq!(path, blocks.path_for(height, hash));
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

    #[test]
    fn names_by_hash_alone_without_height() {
        let dir = scratch_dir();
        let blocks = BlockFiles::new(dir.clone()).expect("create dir");
        let hash = Hash256::from_bytes([0x33; 32]);
        let path = blocks.path_for(None, hash);
        assert_eq!(path.file_name().unwrap().to_string_lossy(), format!("{hash}.block"));
        let _ = fs::remove_dir_all(&dir);
    }
}
