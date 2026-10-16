use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Cursor};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use mantle::network::{AddrMsg, AddrV2Addr, AddrV2Msg, Command, CommandName};

use crate::routable::Routable;

/// Seed addresses are kept as given. Addresses learned from peers or read
/// back from `peers.txt` must be publicly routable, and are capped in total
/// and per /16 group so one peer's `addr` flood cannot fill the book.
pub struct PeerBook {
    addresses: Vec<SocketAddrV4>,
    known: HashSet<SocketAddrV4>,
    groups: HashMap<[u8; 2], usize>,
    learned: usize,
    banned: HashMap<SocketAddrV4, Instant>,
    next_index: usize,
    path: Option<PathBuf>,
}

impl PeerBook {
    const BAN_DURATION: Duration = Duration::from_mins(10);
    pub(crate) const MAX_LEARNED: usize = 2_048;
    pub(crate) const MAX_PER_GROUP: usize = 8;

    pub fn memory(seeds: Vec<SocketAddrV4>) -> Self {
        Self::from_parts(seeds, None)
    }

    pub fn persistent(seeds: Vec<SocketAddrV4>, data_dir: &Path) -> io::Result<Self> {
        let path = data_dir.join("peers.txt");
        let stored: Vec<SocketAddrV4> = match fs::read_to_string(&path) {
            Ok(body) => body
                .lines()
                .filter_map(|line| line.trim().parse::<SocketAddrV4>().ok())
                .collect(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error),
        };
        let mut book = Self::from_parts(seeds, Some(path));
        book.learn(stored);
        Ok(book)
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
        self.ban_at(address, Instant::now());
    }

    pub fn banned_count(&self) -> usize {
        self.banned.len()
    }

    pub fn next_avoiding(&mut self, avoid: &[SocketAddrV4]) -> Option<SocketAddrV4> {
        self.next_avoiding_at(avoid, Instant::now())
    }

    fn ban_at(&mut self, address: SocketAddrV4, now: Instant) {
        self.banned.insert(address, now + Self::BAN_DURATION);
    }

    fn next_avoiding_at(&mut self, avoid: &[SocketAddrV4], now: Instant) -> Option<SocketAddrV4> {
        self.banned.retain(|_, until| *until > now);
        let len = self.addresses.len();
        for _ in 0..len {
            let index = self.next_index % len;
            self.next_index = index.wrapping_add(1);
            let address = self.addresses[index];
            if !avoid.contains(&address) && !self.banned.contains_key(&address) {
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
        let added = self.learn(addresses);
        if added > 0 {
            self.persist()?;
        }
        Ok(added)
    }

    fn learn(&mut self, addresses: impl IntoIterator<Item = SocketAddrV4>) -> usize {
        let mut added = 0;
        for routable in addresses.into_iter().filter_map(Routable::new) {
            if self.learned >= Self::MAX_LEARNED {
                break;
            }
            let address = routable.address();
            let in_group = self.groups.get(&routable.group()).copied().unwrap_or(0);
            if in_group >= Self::MAX_PER_GROUP || !self.known.insert(address) {
                continue;
            }
            self.groups.insert(routable.group(), in_group + 1);
            self.addresses.push(address);
            self.learned += 1;
            added += 1;
        }
        added
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
            groups: HashMap::new(),
            learned: 0,
            banned: HashMap::new(),
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
    fn bans_expire() {
        let address: std::net::SocketAddrV4 = "127.0.0.1:8333".parse().unwrap();
        let mut book = PeerBook::memory(vec![address]);
        let start = std::time::Instant::now();
        book.ban_at(address, start);
        assert_eq!(book.next_avoiding_at(&[], start), None);
        assert_eq!(
            book.next_avoiding_at(&[], start + PeerBook::BAN_DURATION),
            Some(address)
        );
        assert_eq!(book.banned_count(), 0);
    }

    #[test]
    fn discovered_addresses_are_deduplicated() {
        let address = "8.8.8.8:8333".parse().unwrap();
        let mut book = PeerBook::memory(vec![address]);
        assert_eq!(book.extend([address]).unwrap(), 0);
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn local_seeds_are_kept_but_local_discoveries_are_not() {
        let seed: std::net::SocketAddrV4 = "127.0.0.1:8333".parse().unwrap();
        let mut book = PeerBook::memory(vec![seed]);
        let learned = book
            .extend(["127.0.0.2:8333".parse().unwrap(), "10.1.1.1:8333".parse().unwrap()])
            .unwrap();
        assert_eq!(learned, 0);
        assert_eq!(book.next_avoiding(&[]), Some(seed));
    }

    #[test]
    fn one_group_cannot_fill_the_book() {
        let mut book = PeerBook::memory(Vec::new());
        let flood = (0..=255u8).map(|host| std::net::SocketAddrV4::new([81, 2, 3, host].into(), 8333));
        assert_eq!(book.extend(flood).unwrap(), PeerBook::MAX_PER_GROUP);
    }

    #[test]
    fn learned_addresses_stop_at_the_cap() {
        let mut book = PeerBook::memory(Vec::new());
        let spread = (1..=255u8).flat_map(|a| {
            (0..=255u8).map(move |b| std::net::SocketAddrV4::new([a, b, 1, 1].into(), 8333))
        });
        assert_eq!(book.extend(spread).unwrap(), PeerBook::MAX_LEARNED);
        assert_eq!(book.len(), PeerBook::MAX_LEARNED);
    }

    #[test]
    fn a_stored_file_is_filtered_on_load() {
        let dir = std::env::temp_dir().join(format!("peer-book-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("peers.txt"), "10.0.0.1:8333\n8.8.8.8:8333\n").unwrap();
        let book = PeerBook::persistent(Vec::new(), &dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(book.len(), 1);
    }
}
