use std::io::{Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use mantle::codec::{Decode, Encode};
use mantle::network::{Command, GetHeadersMsg, HeadersMsg, MessageHeader, Network, encode_message};
use mantle::primitives::{BlockHeader, BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Nonce};
use mantle_fetcher::Fetcher;

/// A regtest node that answers `getheaders` the way Bitcoin Core does: from
/// the newest locator hash on its own chain, or from genesis when none is.
struct FakeNode {
    stream: TcpStream,
    buffer: Vec<u8>,
    chain: Arc<Mutex<Vec<BlockHeader>>>,
    delay: Duration,
}

impl FakeNode {
    fn spawn(chain: Arc<Mutex<Vec<BlockHeader>>>) -> (SocketAddrV4, JoinHandle<()>) {
        Self::spawn_slow(chain, Duration::ZERO)
    }

    /// A node that waits `delay` before answering each `getheaders`.
    fn spawn_slow(chain: Arc<Mutex<Vec<BlockHeader>>>, delay: Duration) -> (SocketAddrV4, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let SocketAddr::V4(address) = listener.local_addr().expect("address") else {
            panic!("ipv4 expected");
        };
        let thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            Self { stream, buffer: Vec::new(), chain, delay }.serve();
        });
        (address, thread)
    }

    fn serve(mut self) {
        while let Some((command, payload)) = self.next_message() {
            match command.as_str() {
                "version" => {
                    let mut version = Vec::new();
                    mantle_transport::encode_version("/fake-node/", &mut version);
                    self.send(Command::Version, &version);
                    self.send(Command::Verack, &[]);
                }
                "getheaders" => {
                    let request = GetHeadersMsg::decode(&mut payload.as_slice()).expect("getheaders");
                    thread::sleep(self.delay);
                    let reply = HeadersMsg(self.after(&request.locator_hashes));
                    let mut body = Vec::new();
                    reply.encode(&mut body).expect("headers");
                    self.send(Command::Headers, &body);
                }
                _ => {}
            }
        }
    }

    fn after(&self, locator: &[Hash256]) -> Vec<BlockHeader> {
        let chain = self.chain.lock().expect("chain");
        let from = locator
            .iter()
            .find_map(|hash| {
                if *hash == Network::Regtest.genesis_hash() {
                    return Some(0);
                }
                chain.iter().position(|header| header.hash() == *hash).map(|index| index + 1)
            })
            .unwrap_or(0);
        chain[from..].to_vec()
    }

    fn send(&mut self, command: Command, payload: &[u8]) {
        let mut bytes = Vec::new();
        encode_message(Network::Regtest.magic(), command, payload, &mut bytes).expect("encode");
        let _ = self.stream.write_all(&bytes);
    }

    fn next_message(&mut self) -> Option<(mantle::network::CommandName, Vec<u8>)> {
        let mut chunk = [0u8; 4096];
        loop {
            if self.buffer.len() >= MessageHeader::ENCODED_LEN {
                let head: [u8; MessageHeader::ENCODED_LEN] =
                    self.buffer[..MessageHeader::ENCODED_LEN].try_into().expect("header");
                let header = MessageHeader::from_bytes(&head);
                let total = MessageHeader::ENCODED_LEN + header.length() as usize;
                if self.buffer.len() >= total {
                    let payload = self.buffer[MessageHeader::ENCODED_LEN..total].to_vec();
                    self.buffer.drain(..total);
                    return Some((header.command(), payload));
                }
            }
            let read = self.stream.read(&mut chunk).ok()?;
            if read == 0 {
                return None;
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }
}

struct ReorgFixture {
    dir: PathBuf,
}

impl ReorgFixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("fetcher-header-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        Self { dir }
    }

    fn branch(parent: Hash256, length: u32, salt: u32) -> Vec<BlockHeader> {
        let mut prev = parent;
        (0..length)
            .map(|index| {
                let header = BlockHeader::new(
                    BlockVersion::new(4),
                    prev,
                    Hash256::ZERO,
                    BlockTime::new(1_700_000_000 + index),
                    CompactBits::new(0x207f_ffff),
                    Nonce::new(salt),
                );
                prev = header.hash();
                header
            })
            .collect()
    }

    /// The kernel tears down a closed ring and its registered buffers on a
    /// workqueue, so right after the unit-test binary exits the memory they
    /// held can still count against this process and a new ring is refused.
    fn fetcher(&self, peers: &[SocketAddrV4]) -> Fetcher {
        let mut attempts = 0;
        loop {
            match Fetcher::new(Network::Regtest, peers.to_vec(), &self.dir) {
                Ok(fetcher) => return fetcher,
                Err(error) if attempts < 50 => {
                    attempts += 1;
                    eprintln!("ring not available yet: {error}");
                    thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(error) => panic!("fetcher: {error}"),
            }
        }
    }

    fn hashes(headers: &[(BlockHeight, BlockHeader)]) -> Vec<Hash256> {
        headers.iter().map(|(_, header)| header.hash()).collect()
    }
}

impl Drop for ReorgFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn a_sync_whose_cached_tip_was_orphaned_follows_the_longer_branch() {
    let fixture = ReorgFixture::new("reorg");
    let first = ReorgFixture::branch(Network::Regtest.genesis_hash(), 3, 0);
    let mut longer = first[..2].to_vec();
    longer.extend(ReorgFixture::branch(first[1].hash(), 2, 1));
    let chain = Arc::new(Mutex::new(first.clone()));
    let (address, node) = FakeNode::spawn(Arc::clone(&chain));

    let mut fetcher = fixture.fetcher(&[address]);
    let start = BlockHeight::new(1);
    let stop = BlockHeight::new(u32::MAX);
    let genesis = Network::Regtest.genesis_hash();
    let synced = fetcher.sync_headers(start, stop, genesis).expect("first sync");
    assert_eq!(ReorgFixture::hashes(&synced), first.iter().map(BlockHeader::hash).collect::<Vec<_>>());

    *chain.lock().expect("chain") = longer.clone();
    let resynced = fetcher.sync_headers(start, stop, genesis).expect("sync after the reorg");
    drop(fetcher);
    node.join().expect("node");

    assert_eq!(ReorgFixture::hashes(&resynced), longer.iter().map(BlockHeader::hash).collect::<Vec<_>>());
    assert_eq!(resynced.last().map(|(height, _)| *height), Some(BlockHeight::new(4)));
}

#[test]
fn a_survey_reports_each_peers_page_from_the_locator_without_admitting_any() {
    let fixture = ReorgFixture::new("survey");
    let genesis = Network::Regtest.genesis_hash();
    let shared = ReorgFixture::branch(genesis, 2, 0);
    let mut agreeing = shared.clone();
    agreeing.extend(ReorgFixture::branch(shared[1].hash(), 2, 0));
    let mut forked = shared.clone();
    forked.extend(ReorgFixture::branch(shared[1].hash(), 3, 9));
    let (first, first_node) = FakeNode::spawn(Arc::new(Mutex::new(agreeing.clone())));
    let (second, second_node) = FakeNode::spawn(Arc::new(Mutex::new(forked.clone())));
    let held: Vec<(BlockHeight, BlockHeader)> = (1..).map(BlockHeight::new).zip(shared).collect();

    let mut fetcher = fixture.fetcher(&[first, second]);
    let pages = fetcher.survey_headers(BlockHeight::new(1), genesis, &held).expect("survey");
    drop(fetcher);
    first_node.join().expect("first node");
    second_node.join().expect("second node");

    assert_eq!(pages.len(), 2);
    assert_eq!(pages[0].first, BlockHeight::new(3));
    assert_eq!(pages[0].headers, forked[2..].to_vec());
    assert_eq!(pages[0].senders, vec![second]);
    assert_eq!(pages[1].headers, agreeing[2..].to_vec());
    assert_eq!(pages[1].senders, vec![first]);
}

#[test]
fn the_branch_with_the_most_work_wins_even_when_it_answers_last() {
    let fixture = ReorgFixture::new("most-work");
    let genesis = Network::Regtest.genesis_hash();
    let light = ReorgFixture::branch(genesis, 3, 0);
    let heavy = ReorgFixture::branch(genesis, 5, 1);
    let (quick, quick_node) = FakeNode::spawn(Arc::new(Mutex::new(light)));
    let (slow, slow_node) = FakeNode::spawn_slow(Arc::new(Mutex::new(heavy.clone())), Duration::from_millis(500));

    let mut fetcher = fixture.fetcher(&[quick, slow]);
    let synced = fetcher
        .sync_headers(BlockHeight::new(1), BlockHeight::new(u32::MAX), genesis)
        .expect("sync");
    drop(fetcher);
    quick_node.join().expect("quick node");
    slow_node.join().expect("slow node");

    assert_eq!(ReorgFixture::hashes(&synced), heavy.iter().map(BlockHeader::hash).collect::<Vec<_>>());
}
