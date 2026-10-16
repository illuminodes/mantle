use crate::primitives::{BlockHeader, BlockHeight, BlockTime, BlockVersion, ChainWork, Hash256, Nonce};

use super::magic::Magic;

// ── Network ───────────────────────────────────────────────────────────────────

/// One of the well-known Bitcoin networks. CLIs use this to look up the
/// magic, default port, default seed peers, and genesis hash for a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet3,
    Testnet4,
    Signet,
    Regtest,
}

impl Network {
    /// Parse a `--network` flag value. Accepts the short names used by Bitcoin
    /// Core (`main`/`test`/`testnet4`/`signet`/`regtest`) and the long form
    /// (`mainnet`/`testnet3`/`testnet4`/`signet`/`regtest`), case-insensitive.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "main" | "mainnet" => Some(Self::Mainnet),
            "test" | "testnet" | "testnet3" => Some(Self::Testnet3),
            "testnet4" => Some(Self::Testnet4),
            "signet" => Some(Self::Signet),
            "regtest" => Some(Self::Regtest),
            _ => None,
        }
    }

    /// Short canonical name used in user-facing output.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet3 => "testnet3",
            Self::Testnet4 => "testnet4",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        }
    }

    /// P2P magic for this network.
    #[must_use]
    pub fn magic(self) -> Magic {
        match self {
            Self::Mainnet => Magic::Mainnet,
            Self::Testnet3 => Magic::Testnet3,
            Self::Testnet4 => Magic::Testnet4,
            Self::Signet => Magic::Signet,
            Self::Regtest => Magic::Regtest,
        }
    }

    /// Default P2P port for this network. Used when `--peer` does not include a
    /// port.
    #[must_use]
    pub fn default_port(self) -> u16 {
        match self {
            Self::Mainnet => 8333,
            Self::Testnet3 => 18333,
            Self::Testnet4 => 48333,
            Self::Signet => 38333,
            Self::Regtest => 18444,
        }
    }

    /// Genesis block hash in *internal* (little-endian) byte order — this is
    /// the form `Hash256` carries throughout the codebase, and the form a
    /// `getheaders` locator wants. The display-hex version (what block
    /// explorers show) is the byte-reverse of this.
    ///
    /// # Panics
    /// Never in practice: parses a fixed compile-time string. The `expect` is
    /// load-bearing only in the sense of guarding a typo if the constants are
    /// edited.
    #[must_use]
    pub fn genesis_hash(self) -> Hash256 {
        // Display-hex constants from Bitcoin Core's `chainparams.cpp`. Parsed
        // via `Hash256::from_display_hex` which handles the byte reversal.
        let display_hex = match self {
            Self::Mainnet => "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            Self::Testnet3 => "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
            Self::Testnet4 => "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
            Self::Signet => "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
            Self::Regtest => "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        };
        Hash256::from_display_hex(display_hex).expect("hardcoded genesis hash must parse")
    }

    /// Decoded genesis block header. Callers that need a pre-genesis snapshot
    /// slot (so block 1's `prev_block` and MTP lookups resolve) use this;
    /// callers that only need the hash should use [`Self::genesis_hash`].
    ///
    /// # Panics
    /// Never in practice: parses fixed compile-time hex strings.
    #[must_use]
    pub fn genesis_header(self) -> Option<BlockHeader> {
        let merkle =
            |hex| Hash256::from_display_hex(hex).expect("hardcoded genesis merkle_root must parse");
        match self {
            Self::Mainnet => Some(BlockHeader::new(
                BlockVersion::new(1),
                Hash256::ZERO,
                merkle(GENESIS_MERKLE_ROOT),
                BlockTime::new(1_231_006_505),
                crate::difficulty::CompactBits::new(0x1d00_ffff),
                Nonce::new(2_083_236_893),
            )),
            Self::Testnet4 => Some(BlockHeader::new(
                BlockVersion::new(1),
                Hash256::ZERO,
                merkle("7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e"),
                BlockTime::new(1_714_777_860),
                crate::difficulty::CompactBits::new(0x1d00_ffff),
                Nonce::new(393_743_547),
            )),
            Self::Signet => Some(BlockHeader::new(
                BlockVersion::new(1),
                Hash256::ZERO,
                merkle(GENESIS_MERKLE_ROOT),
                BlockTime::new(1_598_918_400),
                crate::difficulty::CompactBits::new(0x1e03_77ae),
                Nonce::new(52_613_770),
            )),
            Self::Testnet3 | Self::Regtest => None,
        }
    }

    /// A block every honest header chain passes through, from Bitcoin Core's
    /// `defaultAssumeValid`. A chain that skips it, or forks below it, is not
    /// the network's chain however valid each header looks on its own.
    ///
    /// # Panics
    /// Never in practice: parses a fixed compile-time string.
    #[must_use]
    pub fn checkpoint(self) -> Option<(BlockHeight, Hash256)> {
        let (height, display_hex) = match self {
            Self::Mainnet => (
                966_143,
                "00000000000000000000748969ec33043c0e52a763c6dd5193861f559f2c72e3",
            ),
            Self::Testnet3 | Self::Testnet4 | Self::Signet | Self::Regtest => return None,
        };
        let hash = Hash256::from_display_hex(display_hex).expect("hardcoded checkpoint must parse");
        Some((BlockHeight::new(height), hash))
    }

    /// The work Bitcoin Core's `nMinimumChainWork` requires of the network's
    /// chain; a chain with less is not the network's however valid it looks.
    /// Mainnet's value is taken at the same block as [`Self::checkpoint`].
    #[must_use]
    pub const fn minimum_chain_work(self) -> ChainWork {
        ChainWork::new(match self {
            Self::Mainnet => 0x1_45ec_036a_cc5b_a740_052a_f1a0,
            Self::Testnet3 => 0x17f4_9f70_2147_f10c_0eb6,
            Self::Testnet4 => 0x0e34_6a55_8455_ade8_eca9,
            Self::Signet => 0x1090_e9dc_1520,
            Self::Regtest => 0,
        })
    }

    /// Default seed peers as `host:port` strings. Entries may be either
    /// literal `IP:PORT` (mainnet's hand-picked list) or DNS `HOST:PORT`
    /// (testnet4 / signet — callers do the resolution at peer-list build
    /// time). Networks without a seed list return an empty slice — supply
    /// peers via `--peer`.
    #[must_use]
    pub fn default_seeds(self) -> &'static [&'static str] {
        match self {
            Self::Mainnet => MAINNET_SEEDS,
            Self::Testnet4 => TESTNET4_SEEDS,
            Self::Signet => SIGNET_SEEDS,
            Self::Testnet3 | Self::Regtest => &[],
        }
    }
}

/// Seed peers for mainnet bootstrap. Same set used by `mantle-node` and the
/// bench `fetch-fixtures` tool.
///
/// The DNS hostnames come from Bitcoin Core `chainparams.cpp::CMainParams`
/// and each resolves to many addresses, so callers that need more than a
/// handful of candidates get them. The literal addresses are kept as a
/// fallback for when DNS resolution is unavailable.
const MAINNET_SEEDS: &[&str] = &[
    "seed.bitcoin.sipa.be:8333",
    "dnsseed.bluematt.me:8333",
    "seed.bitcoinstats.com:8333",
    "seed.bitcoin.jonasschnelli.ch:8333",
    "seed.btc.petertodd.net:8333",
    "seed.bitcoin.sprovoost.nl:8333",
    "dnsseed.emzy.de:8333",
    "seed.bitcoin.wiz.biz:8333",
    "seed.mainnet.achownodes.xyz:8333",
    "5.161.244.95:8333",
    "172.105.64.213:8333",
    "61.68.41.135:8333",
    "43.154.28.63:8333",
    "62.93.65.111:8333",
];

/// Seed peers for testnet4 bootstrap. DNS hostnames from Bitcoin Core
/// `chainparams.cpp::CTestNet4Params`; the replay binary resolves them to
/// IPv4 addresses at peer-list build time.
const TESTNET4_SEEDS: &[&str] = &[
    "seed.testnet4.bitcoin.sprovoost.nl:48333",
    "seed.testnet4.wiz.biz:48333",
];

/// Seed peers for the default signet. DNS hostnames from Bitcoin Core
/// `chainparams.cpp::SigNetParams`.
const SIGNET_SEEDS: &[&str] = &[
    "seed.signet.bitcoin.sprovoost.nl:38333",
    "seed.signet.achownodes.xyz:38333",
];

/// Satoshi's coinbase merkle root, shared by mainnet and signet genesis blocks.
const GENESIS_MERKLE_ROOT: &str =
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_genesis_header_hashes_correctly() {
        // Load-bearing: catches a typo in the literal merkle_root / time /
        // nonce / bits before it silently corrupts the replay loop's MTP
        // check at block 1.
        let hdr = Network::Mainnet.genesis_header().expect("mainnet has one");
        assert_eq!(hdr.hash(), Network::Mainnet.genesis_hash());
    }

    #[test]
    fn mainnet_checkpoint_is_the_hash_of_its_header() {
        let raw = "0080f029fd68e7f483b653e990c206b5fb8d2a0a97a950fd76140100000000000000000039d8fd42e4ee02f5a12c49458d9418b6ea3a36fa21f87832aa3d840fd6bf15d685d6a06a5e35021734689e4e";
        let bytes: Vec<u8> = (0..raw.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&raw[at..at + 2], 16).expect("hex"))
            .collect();
        let header = BlockHeader::from_bytes(bytes.try_into().expect("80 bytes"));
        let (_, hash) = Network::Mainnet.checkpoint().expect("mainnet has one");
        assert_eq!(header.hash(), hash);
    }

    #[test]
    fn testnet4_genesis_header_hashes_correctly() {
        // Same load-bearing role as the mainnet test: tying the literal
        // header bytes to the documented testnet4 genesis hash.
        let hdr = Network::Testnet4
            .genesis_header()
            .expect("testnet4 has one");
        assert_eq!(hdr.hash(), Network::Testnet4.genesis_hash());
    }

    #[test]
    fn signet_genesis_header_hashes_correctly() {
        let hdr = Network::Signet.genesis_header().expect("signet has one");
        assert_eq!(hdr.hash(), Network::Signet.genesis_hash());
    }

    #[test]
    fn name_returns_non_empty_for_all_variants() {
        let variants = [
            Network::Mainnet,
            Network::Testnet3,
            Network::Testnet4,
            Network::Signet,
            Network::Regtest,
        ];
        for net in &variants {
            assert!(!net.name().is_empty(), "{net:?} name should be non-empty");
        }
    }

    #[test]
    fn magic_returns_distinct_for_all_variants() {
        let variants = [
            Network::Mainnet,
            Network::Testnet3,
            Network::Testnet4,
            Network::Signet,
            Network::Regtest,
        ];
        for net in &variants {
            // Just exercising the method; Magic is an enum so we can't do much
            // beyond checking it doesn't panic.
            let _m = net.magic();
        }
    }

    #[test]
    fn default_port_non_zero_for_all_variants() {
        let variants = [
            Network::Mainnet,
            Network::Testnet3,
            Network::Testnet4,
            Network::Signet,
            Network::Regtest,
        ];
        for net in &variants {
            assert!(net.default_port() > 0, "{net:?} port should be > 0");
        }
    }

    #[test]
    fn genesis_hash_non_zero_for_all_variants() {
        let variants = [
            Network::Mainnet,
            Network::Testnet3,
            Network::Testnet4,
            Network::Signet,
            Network::Regtest,
        ];
        for net in &variants {
            assert_ne!(
                net.genesis_hash(),
                Hash256::ZERO,
                "{net:?} genesis hash should be non-zero"
            );
        }
    }

    #[test]
    fn genesis_header_returns_some_for_supported_variants() {
        // Mainnet, Testnet4, and Signet have genesis headers.
        assert!(Network::Mainnet.genesis_header().is_some());
        assert!(Network::Testnet4.genesis_header().is_some());
        assert!(Network::Signet.genesis_header().is_some());
        // Testnet3 and Regtest return None (documented behavior).
        assert!(Network::Testnet3.genesis_header().is_none());
        assert!(Network::Regtest.genesis_header().is_none());
    }

    #[test]
    fn parse_all_variants() {
        assert_eq!(Network::parse("main"), Some(Network::Mainnet));
        assert_eq!(Network::parse("mainnet"), Some(Network::Mainnet));
        assert_eq!(Network::parse("MAINNET"), Some(Network::Mainnet));
        assert_eq!(Network::parse("test"), Some(Network::Testnet3));
        assert_eq!(Network::parse("testnet"), Some(Network::Testnet3));
        assert_eq!(Network::parse("testnet3"), Some(Network::Testnet3));
        assert_eq!(Network::parse("testnet4"), Some(Network::Testnet4));
        assert_eq!(Network::parse("signet"), Some(Network::Signet));
        assert_eq!(Network::parse("regtest"), Some(Network::Regtest));
        assert_eq!(Network::parse("unknown"), None);
    }

    #[test]
    fn default_seeds_mainnet_non_empty() {
        assert!(!Network::Mainnet.default_seeds().is_empty());
        assert!(!Network::Testnet4.default_seeds().is_empty());
        assert!(!Network::Signet.default_seeds().is_empty());
        assert!(Network::Regtest.default_seeds().is_empty());
    }
}
