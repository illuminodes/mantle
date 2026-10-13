use std::net::SocketAddrV4;
use std::path::Path;

/// P2P peer addresses collected from `--peer` flags and `--peer-file` lists.
#[derive(Debug, Default, Clone)]
pub struct PeerList {
    addrs: Vec<SocketAddrV4>,
}

impl PeerList {
    #[must_use]
    pub const fn new() -> Self {
        Self { addrs: Vec::new() }
    }

    /// Parse one `IP:PORT` and add it.
    ///
    /// # Errors
    /// Returns an error if `spec` is not an IPv4 socket address.
    pub fn push_spec(&mut self, spec: &str) -> Result<(), String> {
        let addr = spec
            .parse()
            .map_err(|e| format!("invalid peer {spec}: {e}"))?;
        self.addrs.push(addr);
        Ok(())
    }

    /// Add every peer in `body`, one `IP:PORT` per line. Blank lines and
    /// `#` comments are skipped. Returns how many peers were added.
    ///
    /// # Errors
    /// Returns an error naming the first line that is not a socket address.
    pub fn extend_from_text(&mut self, body: &str, source: &str) -> Result<usize, String> {
        let before = self.addrs.len();
        for (lineno, line) in body.lines().enumerate() {
            let trimmed = line.split('#').next().unwrap_or("").trim();
            if trimmed.is_empty() {
                continue;
            }
            let addr = trimmed
                .parse()
                .map_err(|e| format!("{source}:{}: invalid peer {trimmed:?}: {e}", lineno + 1))?;
            self.addrs.push(addr);
        }
        Ok(self.addrs.len() - before)
    }

    /// Add every peer listed in the file at `path`.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or has an invalid line.
    pub fn extend_from_file(&mut self, path: &Path) -> Result<usize, String> {
        let body = std::fs::read_to_string(path)
            .map_err(|e| format!("read peer file {}: {e}", path.display()))?;
        self.extend_from_text(&body, &path.display().to_string())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }

    #[must_use]
    pub fn addrs(&self) -> &[SocketAddrV4] {
        &self.addrs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lines_and_skips_comments() {
        let mut peers = PeerList::new();
        let added = peers
            .extend_from_text("# header\n1.2.3.4:8333  # 12 ms\n\n5.6.7.8:8333\n", "test")
            .expect("parse");
        assert_eq!(added, 2);
        assert_eq!(peers.addrs()[1], "5.6.7.8:8333".parse().unwrap());
    }

    #[test]
    fn reports_bad_line_number() {
        let err = PeerList::new()
            .extend_from_text("1.2.3.4:8333\nnope\n", "peers.txt")
            .unwrap_err();
        assert!(err.starts_with("peers.txt:2:"), "{err}");
    }
}
