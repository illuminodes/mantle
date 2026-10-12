use std::fmt;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use mantle::primitives::{BlockHeight, Hash256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureStage {
    Structure,
    Context,
    Connect,
}

impl FailureStage {
    const ALL: [Self; 3] = [Self::Structure, Self::Context, Self::Connect];

    const fn index(self) -> usize {
        match self {
            Self::Structure => 0,
            Self::Context => 1,
            Self::Connect => 2,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Structure => "structure",
            Self::Context => "context",
            Self::Connect => "connect",
        }
    }
}

impl fmt::Display for FailureStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Consensus failures seen during a keep-going replay.
///
/// Each failure is printed to stderr when it happens, so it shows up in a
/// streaming CI log, and appended to an optional TSV file.
pub struct FailureLog {
    counts: [u64; FailureStage::ALL.len()],
    file: Option<File>,
}

impl FailureLog {
    const RED: &'static str = "\x1b[1;31m";
    const RESET: &'static str = "\x1b[0m";

    /// # Errors
    /// Returns an error if the TSV file cannot be created.
    pub fn new(path: Option<&Path>) -> io::Result<Self> {
        let file = match path {
            Some(p) => {
                let mut f = File::create(p)?;
                writeln!(f, "height\thash\tstage\terror")?;
                Some(f)
            }
            None => None,
        };
        Ok(Self {
            counts: [0; FailureStage::ALL.len()],
            file,
        })
    }

    pub fn record(
        &mut self,
        height: BlockHeight,
        hash: Hash256,
        stage: FailureStage,
        error: &dyn fmt::Display,
    ) {
        self.counts[stage.index()] += 1;
        let n = self.total();
        eprintln!(
            "{}CONSENSUS FAILURE #{n}{} height={} hash={hash} stage={stage} error={error}",
            Self::RED,
            Self::RESET,
            height.to_u32(),
        );
        if let Some(f) = &mut self.file {
            let written = writeln!(f, "{}\t{hash}\t{stage}\t{error}", height.to_u32())
                .and_then(|()| f.flush());
            if let Err(e) = written {
                eprintln!("  warning: failures file write failed ({e}); continuing without it");
                self.file = None;
            }
        }
    }

    pub fn total(&self) -> u64 {
        self.counts.iter().sum()
    }

    pub fn print_summary(&self) {
        eprintln!("consensus failures: {} total", self.total());
        for stage in FailureStage::ALL {
            eprintln!("  {stage:<9} {}", self.counts[stage.index()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_per_stage_and_writes_tsv() {
        let path = std::env::temp_dir().join(format!(
            "mantle-failures-{}-{}.tsv",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let mut log = FailureLog::new(Some(&path)).expect("create");
        let hash = Hash256::from_bytes([0x11; 32]);
        log.record(BlockHeight::new(5), hash, FailureStage::Connect, &"NegativeFee");
        log.record(BlockHeight::new(9), hash, FailureStage::Context, &"TimestampTooEarly");
        log.record(BlockHeight::new(12), hash, FailureStage::Connect, &"MissingInput");

        assert_eq!(log.total(), 3);
        assert_eq!(log.counts[FailureStage::Connect.index()], 2);
        assert_eq!(log.counts[FailureStage::Context.index()], 1);

        let body = std::fs::read_to_string(&path).expect("read tsv");
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[1].starts_with("5\t"));
        assert!(lines[2].ends_with("\tcontext\tTimestampTooEarly"));
        let _ = std::fs::remove_file(&path);
    }
}
