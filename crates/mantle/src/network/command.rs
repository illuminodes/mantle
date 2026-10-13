// ── Command name ──────────────────────────────────────────────────────────────

/// 12-byte null-padded ASCII command name.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CommandName(pub [u8; 12]);

impl CommandName {
    #[must_use]
    pub fn new(s: &str) -> Self {
        let mut buf = [0u8; 12];
        let bytes = s.as_bytes();
        let len = bytes.len().min(12);
        buf[..len].copy_from_slice(&bytes[..len]);
        Self(buf)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        let end = self.0.iter().position(|&b| b == 0).unwrap_or(12);
        std::str::from_utf8(&self.0[..end]).unwrap_or("")
    }
}

impl std::fmt::Debug for CommandName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CommandName({:?})", self.as_str())
    }
}

impl From<Command> for CommandName {
    fn from(cmd: Command) -> Self {
        Self::new(cmd.as_str())
    }
}

// ── Command ───────────────────────────────────────────────────────────────────

/// All known Bitcoin P2P command names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Command {
    Version,
    Verack,
    Ping,
    Pong,
    GetAddr,
    Addr,
    GetHeaders,
    Headers,
    GetBlocks,
    Inv,
    GetData,
    Block,
    Tx,
    NotFound,
    MemPool,
    SendHeaders,
    SendCmpct,
    CmpctBlock,
    GetBlockTxn,
    BlockTxn,
    FeeFilter,
    WtxidRelay,
    SendAddrV2,
    AddrV2,
}

impl Command {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::Verack => "verack",
            Self::Ping => "ping",
            Self::Pong => "pong",
            Self::GetAddr => "getaddr",
            Self::Addr => "addr",
            Self::GetHeaders => "getheaders",
            Self::Headers => "headers",
            Self::GetBlocks => "getblocks",
            Self::Inv => "inv",
            Self::GetData => "getdata",
            Self::Block => "block",
            Self::Tx => "tx",
            Self::NotFound => "notfound",
            Self::MemPool => "mempool",
            Self::SendHeaders => "sendheaders",
            Self::SendCmpct => "sendcmpct",
            Self::CmpctBlock => "cmpctblock",
            Self::GetBlockTxn => "getblocktxn",
            Self::BlockTxn => "blocktxn",
            Self::FeeFilter => "feefilter",
            Self::WtxidRelay => "wtxidrelay",
            Self::SendAddrV2 => "sendaddrv2",
            Self::AddrV2 => "addrv2",
        }
    }

    /// Parse from a `CommandName`. Returns `None` if the command is unknown.
    #[must_use]
    pub fn from_command_name(name: CommandName) -> Option<Self> {
        name.as_str().parse().ok()
    }
}

impl std::str::FromStr for Command {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "version" => Ok(Self::Version),
            "verack" => Ok(Self::Verack),
            "ping" => Ok(Self::Ping),
            "pong" => Ok(Self::Pong),
            "getaddr" => Ok(Self::GetAddr),
            "addr" => Ok(Self::Addr),
            "getheaders" => Ok(Self::GetHeaders),
            "headers" => Ok(Self::Headers),
            "getblocks" => Ok(Self::GetBlocks),
            "inv" => Ok(Self::Inv),
            "getdata" => Ok(Self::GetData),
            "block" => Ok(Self::Block),
            "tx" => Ok(Self::Tx),
            "notfound" => Ok(Self::NotFound),
            "mempool" => Ok(Self::MemPool),
            "sendheaders" => Ok(Self::SendHeaders),
            "sendcmpct" => Ok(Self::SendCmpct),
            "cmpctblock" => Ok(Self::CmpctBlock),
            "getblocktxn" => Ok(Self::GetBlockTxn),
            "blocktxn" => Ok(Self::BlockTxn),
            "feefilter" => Ok(Self::FeeFilter),
            "wtxidrelay" => Ok(Self::WtxidRelay),
            "sendaddrv2" => Ok(Self::SendAddrV2),
            "addrv2" => Ok(Self::AddrV2),
            _ => Err(()),
        }
    }
}

impl AsRef<str> for Command {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Display for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_roundtrip() {
        let all = [
            Command::Version,
            Command::Verack,
            Command::Ping,
            Command::Pong,
            Command::GetAddr,
            Command::Addr,
            Command::GetHeaders,
            Command::Headers,
            Command::GetBlocks,
            Command::Inv,
            Command::GetData,
            Command::Block,
            Command::Tx,
            Command::NotFound,
            Command::MemPool,
            Command::SendHeaders,
            Command::SendCmpct,
            Command::CmpctBlock,
            Command::GetBlockTxn,
            Command::BlockTxn,
            Command::FeeFilter,
            Command::WtxidRelay,
            Command::SendAddrV2,
            Command::AddrV2,
        ];
        for cmd in all {
            assert_eq!(cmd.as_str().parse::<Command>(), Ok(cmd));
            assert_eq!(
                Command::from_command_name(CommandName::from(cmd)),
                Some(cmd)
            );
        }
    }

    #[test]
    fn command_unknown() {
        assert_eq!("notacommand".parse::<Command>(), Err(()));
        assert_eq!(
            Command::from_command_name(CommandName::new("notacommand")),
            None
        );
    }

    #[test]
    fn command_name_padding() {
        let cmd = CommandName::new("version");
        assert_eq!(&cmd.0[7..], &[0u8; 5]);
        assert_eq!(cmd.as_str(), "version");
    }

    #[test]
    fn command_name_null_terminator_in_middle() {
        let mut raw = [0u8; 12];
        raw[0] = b'p';
        raw[1] = b'i';
        raw[2] = b'n';
        raw[3] = b'g';
        raw[4] = 0x00; // null here
        raw[5] = b'X'; // garbage after null
        let name = CommandName(raw);
        assert_eq!(name.as_str(), "ping");
    }

    #[test]
    fn command_name_no_null_terminator() {
        let raw = [b'a'; 12];
        let name = CommandName(raw);
        assert_eq!(name.as_str(), "aaaaaaaaaaaa");
    }

    #[test]
    fn command_name_non_utf8_fallback() {
        let mut raw = [0u8; 12];
        raw[0] = 0xff;
        raw[1] = 0xfe;
        let name = CommandName(raw);
        // as_str() stops at the first 0x00 byte (index 2 here), yielding [0xff, 0xfe]
        // which is invalid UTF-8 — must return "" rather than panic.
        assert_eq!(name.as_str(), "");
    }
}
