use std::collections::HashSet;
use std::fs;
use std::io::{self, Cursor};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};

use mantle::network::{AddrMsg, AddrV2Addr, AddrV2Msg, Command, CommandName};

pub struct PeerBook {
    addresses: Vec<SocketAddrV4>,
    known: HashSet<SocketAddrV4>,
    banned: HashSet<SocketAddrV4>,
    next_index: usize,
    path: Option<PathBuf>,
}

impl PeerBook {
    pub fn memory(seeds: Vec<SocketAddrV4>) -> Self {
        Self::from_parts(seeds, None)
    }

    pub fn persistent(seeds: Vec<SocketAddrV4>, data_dir: &Path) -> io::Result<Self> {
        let path = data_dir.join("peers.txt");
        let mut addresses = seeds;
        match fs::read_to_string(&path) {
            Ok(body) => addresses.extend(
                body.lines()
                    .filter_map(|line| line.trim().parse::<SocketAddrV4>().ok()),
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        Ok(Self::from_parts(addresses, Some(path)))
    }

    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    pub fn reset(&mut self) {
        self.next_index = 0;
        self.banned.clear();
    }

    pub fn ban(&mut self, address: SocketAddrV4) {
        self.banned.insert(address);
    }

    pub fn next_avoiding(&mut self, avoid: &[SocketAddrV4]) -> Option<SocketAddrV4> {
        let len = self.addresses.len();
        for _ in 0..len {
            let index = self.next_index % len;
            self.next_index = index.wrapping_add(1);
            let address = self.addresses[index];
            if !avoid.contains(&address) && !self.banned.contains(&address) {
                return Some(address);
            }
        }
        None
    }

    pub fn decode(command: CommandName, payload: &[u8]) -> Vec<SocketAddrV4> {
        match Command::from_command_name(command) {
            Some(Command::Addr) => Self::decode_addr(payload),
            Some(Command::AddrV2) => Self::decode_addr_v2(payload),
            _ => Vec::new(),
        }
    }

    pub fn extend(
        &mut self,
        addresses: impl IntoIterator<Item = SocketAddrV4>,
    ) -> io::Result<usize> {
        let mut added = 0;
        for address in addresses {
            if address.ip().is_unspecified() || address.ip().is_multicast() || address.port() == 0 {
                continue;
            }
            if self.known.insert(address) {
                self.addresses.push(address);
                added += 1;
            }
        }
        if added > 0 {
            self.persist()?;
        }
        Ok(added)
    }

    fn from_parts(addresses: Vec<SocketAddrV4>, path: Option<PathBuf>) -> Self {
        let mut known = HashSet::new();
        let addresses = addresses
            .into_iter()
            .filter(|address| known.insert(*address))
            .collect();
        Self {
            addresses,
            known,
            banned: HashSet::new(),
            next_index: 0,
            path,
        }
    }

    fn decode_addr(payload: &[u8]) -> Vec<SocketAddrV4> {
        AddrMsg::decode_limited(&mut Cursor::new(payload))
            .map(|message| {
                message
                    .0
                    .into_iter()
                    .filter_map(|entry| {
                        entry.ip_v4().map(|octets| {
                            SocketAddrV4::new(Ipv4Addr::from(octets), entry.port().to_u16())
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn decode_addr_v2(payload: &[u8]) -> Vec<SocketAddrV4> {
        AddrV2Msg::decode_limited(&mut Cursor::new(payload))
            .map(|message| {
                message
                    .0
                    .into_iter()
                    .filter_map(|entry| match entry.addr {
                        AddrV2Addr::Ipv4(_) => entry.ip_v4(),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn persist(&self) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let temporary = path.with_extension("txt.tmp");
        let mut addresses = self.addresses.clone();
        addresses.sort_unstable();
        let body = addresses
            .iter()
            .map(SocketAddrV4::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        fs::write(&temporary, body)?;
        fs::rename(temporary, path)
    }
}

#[cfg(test)]
mod tests {
    use super::PeerBook;

    #[test]
    fn banned_addresses_are_skipped_until_reset() {
        let good: std::net::SocketAddrV4 = "127.0.0.1:8333".parse().unwrap();
        let bad: std::net::SocketAddrV4 = "127.0.0.2:8333".parse().unwrap();
        let mut book = PeerBook::memory(vec![bad, good]);
        book.ban(bad);
        assert_eq!(book.next_avoiding(&[]), Some(good));
        assert_eq!(book.next_avoiding(&[]), Some(good));
        book.ban(good);
        assert_eq!(book.next_avoiding(&[]), None);
        book.reset();
        assert_eq!(book.next_avoiding(&[]), Some(bad));
    }

    #[test]
    fn discovered_addresses_are_deduplicated() {
        let address = "127.0.0.1:8333".parse().unwrap();
        let mut book = PeerBook::memory(vec![address]);
        assert_eq!(book.extend([address]).unwrap(), 0);
        assert_eq!(book.len(), 1);
    }
}
