use std::io::Cursor;
use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::thread::JoinHandle;
use std::time::Instant;

use mantle::codec::Decode;
use mantle::network::Network;
use mantle::primitives::{Block, BlockHeader, BlockHeight, Hash256};
use mantle_fetcher::Fetcher;
use quetzalcoatl::capacity::Capacity;
use quetzalcoatl::spsc;

/// What the feed thread should fetch and how it should hand it over.
pub struct FeedPlan {
    pub network: Network,
    pub peers: Vec<SocketAddrV4>,
    pub cache_dir: PathBuf,
    pub start: BlockHeight,
    pub stop: BlockHeight,
    pub locator: Hash256,
    pub window: usize,
    pub discard_windows: bool,
    pub download_only: bool,
}

impl FeedPlan {
    const MAX_BUFFERED_BLOCKS: usize = 1024;
    const FETCH_ATTEMPTS: u32 = 5;

    /// One full window fits in the channel, so the feed thread can download
    /// window N+1 while the replay thread validates window N.
    fn buffered_blocks(&self) -> usize {
        self.window.clamp(1, Self::MAX_BUFFERED_BLOCKS)
    }
}

/// A downloaded block, not yet decoded.
pub struct FedBlock {
    pub height: BlockHeight,
    pub hash: Hash256,
    pub bytes: Vec<u8>,
}

impl FedBlock {
    /// # Errors
    /// Returns a message if the bytes do not decode or hash to `self.hash`.
    pub fn decode(&self) -> Result<Block, String> {
        let block = Block::decode(&mut Cursor::new(&self.bytes))
            .map_err(|e| format!("decode block {}: {e}", self.height.to_u32()))?;
        if block.header.hash() != self.hash {
            return Err(format!(
                "block {} hashes to {}, expected {}",
                self.height.to_u32(),
                block.header.hash(),
                self.hash
            ));
        }
        Ok(block)
    }
}

pub enum FeedItem {
    Headers(Vec<(BlockHeight, BlockHeader)>),
    Block(FedBlock),
    Failed(String),
}

/// Header sync and block download on a thread of their own.
///
/// The thread owns the [`Fetcher`] (its `io_uring` cannot cross threads),
/// sends the synced headers first, then streams blocks in height order over
/// a bounded channel. Both ends block on the channel; nothing polls. The
/// thread exits when it has sent every block, on a fatal error (after
/// sending [`FeedItem::Failed`]), or when the receiving side is dropped.
pub struct BlockFeed {
    items: Option<spsc::Consumer<FeedItem>>,
    thread: Option<JoinHandle<()>>,
}

impl BlockFeed {
    /// # Errors
    /// Returns the error from spawning the thread.
    pub fn spawn(plan: FeedPlan) -> std::io::Result<Self> {
        let (sender, items) =
            spsc::RingBuffer::new(Capacity::at_least(plan.buffered_blocks())).split();
        let thread = std::thread::Builder::new()
            .name("block-feed".into())
            .spawn(move || FeedWorker { plan, sender }.run())?;
        Ok(Self {
            items: Some(items),
            thread: Some(thread),
        })
    }

}

impl Iterator for BlockFeed {
    type Item = FeedItem;

    /// Blocks until the feed thread sends an item. `None` once the feed
    /// thread has finished and everything it sent was taken.
    fn next(&mut self) -> Option<FeedItem> {
        self.items.as_mut()?.pop_block()
    }
}

impl Drop for BlockFeed {
    fn drop(&mut self) {
        drop(self.items.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct FeedWorker {
    plan: FeedPlan,
    sender: spsc::Producer<FeedItem>,
}

impl FeedWorker {
    fn run(self) {
        match self.feed() {
            Ok(()) | Err(FeedStop::ReceiverGone) => {}
            Err(FeedStop::Failed(message)) => {
                let _ = self.sender.push_block(FeedItem::Failed(message));
            }
        }
    }

    fn send(&self, item: FeedItem) -> Result<(), FeedStop> {
        self.sender
            .push_block(item)
            .map_err(|_| FeedStop::ReceiverGone)
    }

    fn feed(&self) -> Result<(), FeedStop> {
        let plan = &self.plan;
        let mut fetcher = Fetcher::new(plan.network, plan.peers.clone(), &plan.cache_dir)
            .map_err(|e| FeedStop::Failed(format!("fetcher init: {e}")))?;
        let headers = fetcher
            .sync_headers(plan.start, plan.stop, plan.locator)
            .map_err(|e| FeedStop::Failed(format!("sync headers: {e:?}")))?;
        self.send(FeedItem::Headers(headers.clone()))?;
        if plan.download_only {
            return Self::fetch_window(&mut fetcher, &headers);
        }
        for window in headers.chunks(plan.window) {
            let started = Instant::now();
            Self::fetch_window(&mut fetcher, window)?;
            eprintln!(
                "  downloaded {}..={} in {:.1}s",
                window[0].0.to_u32(),
                window[window.len() - 1].0.to_u32(),
                started.elapsed().as_secs_f64()
            );
            for (height, header) in window {
                let bytes = fetcher.read_block_bytes(*height).map_err(|e| {
                    FeedStop::Failed(format!("read block {}: {e}", height.to_u32()))
                })?;
                self.send(FeedItem::Block(FedBlock {
                    height: *height,
                    hash: header.hash(),
                    bytes,
                }))?;
            }
            if plan.discard_windows {
                fetcher
                    .discard_cached_blocks()
                    .map_err(|e| FeedStop::Failed(format!("discard blocks: {e}")))?;
            }
        }
        Ok(())
    }

    fn fetch_window(
        fetcher: &mut Fetcher,
        window: &[(BlockHeight, BlockHeader)],
    ) -> Result<(), FeedStop> {
        let (Some(first), Some(last)) = (window.first(), window.last()) else {
            return Ok(());
        };
        let mut attempt = 1;
        while let Err(e) = fetcher.fetch_blocks(window) {
            if attempt >= FeedPlan::FETCH_ATTEMPTS {
                return Err(FeedStop::Failed(format!(
                    "fetch blocks: {e:?} after {attempt} attempts"
                )));
            }
            eprintln!(
                "  fetch retry {attempt}/{} for {}..={}: {e:?}",
                FeedPlan::FETCH_ATTEMPTS,
                first.0.to_u32(),
                last.0.to_u32()
            );
            attempt += 1;
        }
        Ok(())
    }
}

enum FeedStop {
    ReceiverGone,
    Failed(String),
}
