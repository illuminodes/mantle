use std::path::Path;

use mantle::primitives::BlockHeight;

use crate::block_target::BlockTarget;

/// The blocks a `fetch-blocks` run should download, deduplicated by hash.
#[derive(Debug, Default)]
pub struct TargetList {
    targets: Vec<BlockTarget>,
}

impl TargetList {
    const TSV_HEADER: &'static str = "height";

    #[must_use]
    pub const fn new() -> Self {
        Self {
            targets: Vec::new(),
        }
    }

    /// Add one target given on the command line.
    ///
    /// # Errors
    /// Returns an error if `token` is not a recognised target form.
    pub fn push_token(&mut self, token: &str) -> Result<(), String> {
        self.push(BlockTarget::parse(token)?);
        Ok(())
    }

    /// Add every target in `body`. Each line is one target as accepted by
    /// [`BlockTarget::parse`], or a `--failures-file` TSV row
    /// (`height<TAB>hash<TAB>…`). Blank lines, `#` comments and the TSV
    /// header row are skipped. Returns how many targets were added.
    ///
    /// # Errors
    /// Returns an error naming the first line that cannot be parsed.
    pub fn extend_from_text(&mut self, body: &str, source: &str) -> Result<usize, String> {
        let before = self.targets.len();
        for (lineno, line) in body.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            let mut fields = line.split_whitespace();
            let Some(first) = fields.next() else {
                continue;
            };
            if first == Self::TSV_HEADER {
                continue;
            }
            let target = Self::parse_line(first, fields.next())
                .map_err(|e| format!("{source}:{}: {e}", lineno + 1))?;
            self.push(target);
        }
        Ok(self.targets.len() - before)
    }

    /// Add every target listed in the file at `path`.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or has an invalid line.
    pub fn extend_from_file(&mut self, path: &Path) -> Result<usize, String> {
        let body = std::fs::read_to_string(path)
            .map_err(|e| format!("read target file {}: {e}", path.display()))?;
        self.extend_from_text(&body, &path.display().to_string())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.targets.len()
    }

    #[must_use]
    pub fn targets(&self) -> &[BlockTarget] {
        &self.targets
    }

    fn parse_line(first: &str, second: Option<&str>) -> Result<BlockTarget, String> {
        match (first.parse::<u32>(), second) {
            (Ok(height), Some(hash)) => {
                Ok(BlockTarget::parse(hash)?.with_height(BlockHeight::new(height)))
            }
            _ => BlockTarget::parse(first),
        }
    }

    fn push(&mut self, target: BlockTarget) {
        match self.targets.iter_mut().find(|t| t.hash == target.hash) {
            Some(existing) => existing.height = existing.height.or(target.height),
            None => self.targets.push(target),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "000000001052ca40f382b01b9640bf8150e64746ee3346f33679dd8431bb7df0";
    const B: &str = "0000000006c9b1e6c82487e058b9fa9c001ee54700b33e061e1ebf2cd5b0b66a";

    #[test]
    fn reads_failures_tsv() {
        let tsv = format!(
            "height\thash\tstage\terror\n2277\t{A}\tconnect\tMissingInput\n2518\t{B}\tconnect\tx y\n"
        );
        let mut list = TargetList::new();
        assert_eq!(list.extend_from_text(&tsv, "f.tsv").expect("parse"), 2);
        assert_eq!(list.targets()[0].height, Some(BlockHeight::new(2277)));
        assert_eq!(list.targets()[1].hash.to_string(), B);
    }

    #[test]
    fn mixes_forms_and_dedups_keeping_height() {
        let body = format!("# from docs\n{A}\n\n0002277-{A}.block\n{B}  # second\n");
        let mut list = TargetList::new();
        list.extend_from_text(&body, "list").expect("parse");
        assert_eq!(list.len(), 2);
        assert_eq!(list.targets()[0].height, Some(BlockHeight::new(2277)));
        assert_eq!(list.targets()[1].height, None);
    }

    #[test]
    fn reports_bad_line_number() {
        let err = TargetList::new()
            .extend_from_text(&format!("{A}\nzz\n"), "list")
            .unwrap_err();
        assert!(err.starts_with("list:2:"), "{err}");
    }
}
