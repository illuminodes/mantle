#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use mantle::codec::{Decode, Encode};
use mantle::network::{Command, GetHeadersMsg, HeadersMsg, InvMsg, MessageHeader, Network, encode_message};
use mantle::primitives::{BlockHeader, BlockHeight, BlockTime, BlockVersion, CompactBits, Hash256, Nonce};
use mantle_fetcher::Fetcher;

/// A regtest node that answers `getheaders` the way Bitcoin Core does: from
/// the newest locator hash on its own chain, or from genesis when none is;
/// and `getdata` with the raw blocks it was given.
pub struct FakeNode {
    stream: TcpStream,
    buffer: Vec<u8>,
    chain: Arc<Mutex<Vec<BlockHeader>>>,
    blocks: HashMap<Hash256, Vec<u8>>,
    delay: Duration,
}

impl FakeNode {
    pub fn spawn(chain: Arc<Mutex<Vec<BlockHeader>>>) -> (SocketAddrV4, JoinHandle<()>) {
        Self::spawn_with(chain, HashMap::new(), Duration::ZERO)
    }

    /// A node that waits `delay` before answering each `getheaders`.
    pub fn spawn_slow(chain: Arc<Mutex<Vec<BlockHeader>>>, delay: Duration) -> (SocketAddrV4, JoinHandle<()>) {
        Self::spawn_with(chain, HashMap::new(), delay)
    }

    pub fn spawn_with(
        chain: Arc<Mutex<Vec<BlockHeader>>>,
        blocks: HashMap<Hash256, Vec<u8>>,
        delay: Duration,
    ) -> (SocketAddrV4, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let SocketAddr::V4(address) = listener.local_addr().expect("address") else {
            panic!("ipv4 expected");
        };
        let thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            Self { stream, buffer: Vec::new(), chain, blocks, delay }.serve();
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
                "getdata" => {
                    let request = InvMsg::decode(&mut payload.as_slice()).expect("getdata");
                    for entry in request.0 {
                        if let Some(block) = self.blocks.get(&entry.hash()).cloned() {
                            self.send(Command::Block, &block);
                        }
                    }
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

/// A scratch cache directory and the regtest chains the tests serve.
pub struct ChainFixture {
    pub dir: PathBuf,
}

impl ChainFixture {
    pub fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("fetcher-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        Self { dir }
    }

    pub fn branch(parent: Hash256, length: u32, salt: u32) -> Vec<BlockHeader> {
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

    /// The raw bytes of a block with `header` and one coinbase-shaped
    /// transaction. The fetcher decodes blocks but does not validate them.
    pub fn block(header: &BlockHeader) -> Vec<u8> {
        let mut bytes = header.to_bytes().to_vec();
        bytes.push(1);
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&[0; 32]);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(&[2, 0x51, 0x51]);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&50_u64.to_le_bytes());
        bytes.extend_from_slice(&[1, 0x51]);
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes
    }

    /// The kernel tears down a closed ring and its registered buffers on a
    /// workqueue, so right after the unit-test binary exits the memory they
    /// held can still count against this process and a new ring is refused.
    pub fn fetcher(&self, peers: &[SocketAddrV4]) -> Fetcher {
        let mut attempts = 0;
        loop {
            match Fetcher::new(Network::Regtest, peers.to_vec(), &self.dir) {
                Ok(fetcher) => return fetcher,
                Err(error) if attempts < 50 => {
                    attempts += 1;
                    eprintln!("ring not available yet: {error}");
                    thread::sleep(Duration::from_millis(100));
                }
                Err(error) => panic!("fetcher: {error}"),
            }
        }
    }

    pub fn hashes(headers: &[(BlockHeight, BlockHeader)]) -> Vec<Hash256> {
        headers.iter().map(|(_, header)| header.hash()).collect()
    }
}

impl Drop for ChainFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
