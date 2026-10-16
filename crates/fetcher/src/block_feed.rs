use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use mantle::primitives::{BlockHeader, BlockHeight};
use quetzalcoatl::capacity::Capacity;
use quetzalcoatl::spsc;

use crate::HeaderAdmission;
use crate::feed_item::FeedItem;
use crate::feed_request::{BlocksRequest, FeedRequest, HeaderRequest};
use crate::feed_worker::{FeedSpec, FeedWorker};

/// A [`crate::Fetcher`] on a thread of its own, serving header syncs and
/// block downloads one request at a time over bounded rings.
///
/// The fetcher, and its peer connections, live as long as the feed, so a
/// caller that polls the chain reuses them pass after pass. Both ends block
/// on the rings; nothing polls. Dropping the feed closes both rings and
/// joins the thread once its current network call returns.
pub struct BlockFeed<A> {
    requests: Option<spsc::Producer<FeedRequest<A>>>,
    items: Option<spsc::Consumer<FeedItem<A>>>,
    cancel: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl<A: HeaderAdmission + Send + 'static> BlockFeed<A> {
    const REQUEST_SLOTS: usize = 4;

    /// # Errors
    /// Returns the error from spawning the thread.
    pub fn spawn(spec: FeedSpec) -> std::io::Result<Self> {
        let (request_sender, requests) =
            spsc::RingBuffer::new(Capacity::at_least(Self::REQUEST_SLOTS)).split();
        let (item_sender, items) =
            spsc::RingBuffer::new(Capacity::at_least(spec.buffered.clamp(1, 1024))).split();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker = FeedWorker {
            spec,
            requests,
            items: item_sender,
            cancel: Arc::clone(&cancel),
        };
        let thread = std::thread::Builder::new()
            .name("block-feed".into())
            .spawn(move || worker.run())?;
        Ok(Self {
            requests: Some(request_sender),
            items: Some(items),
            cancel,
            thread: Some(thread),
        })
    }

    /// Synchronize headers, passing every page through `request.admission`,
    /// and hand the admission back with the headers.
    ///
    /// # Errors
    /// A message when the sync fails or the feed thread has gone.
    pub fn headers(&mut self, request: HeaderRequest<A>) -> Result<(Vec<(BlockHeight, BlockHeader)>, A), String> {
        self.push(FeedRequest::Headers(request))?;
        match self.next_item() {
            Some(FeedItem::Headers(headers, admission)) => Ok((headers, admission)),
            Some(FeedItem::Failed(message)) => Err(message),
            Some(_) => Err("block feed answered a header request out of turn".to_string()),
            None => Err("block feed thread has gone".to_string()),
        }
    }

    /// Start a download; take its blocks with [`Self::next_item`] until
    /// [`FeedItem::Done`] or [`FeedItem::Failed`].
    ///
    /// # Errors
    /// A message when the feed thread has gone.
    pub fn request_blocks(&mut self, request: BlocksRequest) -> Result<(), String> {
        self.cancel.store(false, Ordering::Relaxed);
        self.push(FeedRequest::Blocks(request))
    }

    /// Ask the running download not to start another window. The window
    /// already downloading still arrives, then [`FeedItem::Done`].
    pub fn stop_after_window(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// Drop every cached block file, keeping the headers.
    ///
    /// # Errors
    /// A message when the discard fails or the feed thread has gone.
    pub fn discard(&mut self) -> Result<(), String> {
        self.push(FeedRequest::Discard)?;
        match self.next_item() {
            Some(FeedItem::Done) => Ok(()),
            Some(FeedItem::Failed(message)) => Err(message),
            Some(_) => Err("block feed answered a discard out of turn".to_string()),
            None => Err("block feed thread has gone".to_string()),
        }
    }

    /// The next item, waiting for it; `None` once the thread has gone and
    /// everything it sent was taken.
    pub fn next_item(&mut self) -> Option<FeedItem<A>> {
        self.items.as_mut()?.pop_block()
    }

    fn push(&self, request: FeedRequest<A>) -> Result<(), String> {
        self.requests
            .as_ref()
            .ok_or_else(|| "block feed is closed".to_string())?
            .push_block(request)
            .map_err(|_| "block feed thread has gone".to_string())
    }
}

impl<A> Drop for BlockFeed<A> {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        drop(self.requests.take());
        drop(self.items.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use mantle::network::Network;
    use mantle::primitives::BlockHeight;

    use super::BlockFeed;
    use crate::{AdmitAll, BlocksRequest, FeedItem, FeedSpec, HeaderRequest};

    struct FeedFixture {
        dir: PathBuf,
    }

    impl FeedFixture {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("block-feed-{name}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("dir");
            Self { dir }
        }

        fn feed(&self) -> BlockFeed<AdmitAll> {
            BlockFeed::spawn(FeedSpec {
                network: Network::Regtest,
                peers: Vec::new(),
                cache_dir: self.dir.clone(),
                buffered: 4,
            })
            .expect("spawn")
        }
    }

    impl Drop for FeedFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn a_header_request_without_peers_fails_and_the_feed_keeps_serving() {
        let fixture = FeedFixture::new("no-peers");
        let mut feed = fixture.feed();
        let request = || HeaderRequest {
            start: BlockHeight::new(1),
            stop: BlockHeight::new(10),
            locator: Network::Regtest.genesis_hash(),
            admission: AdmitAll,
        };

        assert!(feed.headers(request()).is_err());
        assert!(feed.headers(request()).is_err());
        assert!(feed.discard().is_ok());
    }

    #[test]
    fn an_empty_download_ends_at_once() {
        let fixture = FeedFixture::new("empty");
        let mut feed = fixture.feed();
        feed.request_blocks(BlocksRequest {
            wanted: Vec::new(),
            window: 10,
            discard_each_window: false,
            deliver: true,
        })
        .expect("request");

        assert!(matches!(feed.next_item(), Some(FeedItem::Done)));
    }
}
