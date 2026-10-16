use mantle::primitives::{BlockHeader, BlockHeight, Hash256};

/// Decides whether a run of headers may join the chain being synchronized.
///
/// `admit` sees `headers` as heights `first..`, and either takes all of them
/// or none: a refused page leaves the admission as it was. The fetcher bans a
/// peer whose page is refused and waits for another peer's page.
pub trait HeaderAdmission {
    /// # Errors
    /// The reason the page is refused.
    fn admit(&mut self, first: BlockHeight, headers: &[BlockHeader]) -> Result<(), String>;
}

/// Takes every page that links to the previous one.
#[derive(Debug, Clone, Copy, Default)]
pub struct AdmitAll;

impl HeaderAdmission for AdmitAll {
    fn admit(&mut self, _first: BlockHeight, _headers: &[BlockHeader]) -> Result<(), String> {
        Ok(())
    }
}

/// A page of headers a peer sent in answer to `getheaders(locator)`.
pub(crate) struct HeaderPage<'a> {
    locator: Hash256,
    headers: &'a [BlockHeader],
}

impl<'a> HeaderPage<'a> {
    pub(crate) const fn new(locator: Hash256, headers: &'a [BlockHeader]) -> Self {
        Self { locator, headers }
    }

    /// Check that each header links to the one before it, starting at the
    /// locator, then hand the page to `admission`.
    pub(crate) fn admit(
        &self,
        first: BlockHeight,
        admission: &mut impl HeaderAdmission,
    ) -> Result<(), String> {
        let mut expected = self.locator;
        for (index, header) in self.headers.iter().enumerate() {
            if header.prev_block() != expected {
                return Err(format!("header {index} of the page does not link to the one before it"));
            }
            expected = header.hash();
        }
        admission.admit(first, self.headers)
    }
}

#[cfg(test)]
mod tests {
    use mantle::primitives::{BlockHeader, BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Nonce};

    use super::{AdmitAll, HeaderAdmission, HeaderPage};

    struct Refuse;

    impl HeaderAdmission for Refuse {
        fn admit(&mut self, _first: BlockHeight, _headers: &[BlockHeader]) -> Result<(), String> {
            Err("refused".to_string())
        }
    }

    fn header(prev: Hash256) -> BlockHeader {
        BlockHeader::new(
            BlockVersion::new(1),
            prev,
            Hash256::ZERO,
            BlockTime::new(1),
            CompactBits::new(0x207f_ffff),
            Nonce::new(0),
        )
    }

    #[test]
    fn a_linked_page_reaches_the_admission() {
        let first = header(Hash256::ZERO);
        let second = header(first.hash());
        let page = [first, second];
        let page = HeaderPage::new(Hash256::ZERO, &page);
        assert!(page.admit(BlockHeight::new(1), &mut AdmitAll).is_ok());
        assert!(page.admit(BlockHeight::new(1), &mut Refuse).is_err());
    }

    #[test]
    fn a_broken_link_is_refused_before_the_admission() {
        let first = header(Hash256::ZERO);
        let stray = header(Hash256::from_bytes([9; 32]));
        let page = [first, stray];
        assert!(HeaderPage::new(Hash256::ZERO, &page).admit(BlockHeight::new(1), &mut AdmitAll).is_err());
    }
}
