use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use mantle::network::Network;
use mantle::primitives::{BlockHeader, BlockHeight};
use quetzalcoatl::spsc;

use crate::feed_item::{FedBlock, FeedItem};
use crate::feed_request::{BlocksRequest, FeedRequest, HeaderRequest};
use crate::{Fetcher, HeaderAdmission};

/// Where a [`crate::BlockFeed`]'s fetcher connects and caches.
#[derive(Debug, Clone)]
pub struct FeedSpec {
    pub network: Network,
    pub peers: Vec<SocketAddrV4>,
    pub cache_dir: PathBuf,
    /// Blocks the hand-over ring holds; one window lets the next window
    /// download while the caller works on this one.
    pub buffered: usize,
}

pub(crate) enum FeedStop {
    ReceiverGone,
    Failed(String),
}

/// The thread side: owns the [`Fetcher`], whose `io_uring` cannot cross
/// threads, and answers requests one at a time.
pub(crate) struct FeedWorker<A> {
    pub(crate) spec: FeedSpec,
    pub(crate) requests: spsc::Consumer<FeedRequest<A>>,
    pub(crate) items: spsc::Producer<FeedItem<A>>,
    pub(crate) cancel: Arc<AtomicBool>,
}

impl<A: HeaderAdmission> FeedWorker<A> {
    pub(crate) const FETCH_ATTEMPTS: u32 = 5;

    pub(crate) fn run(mut self) {
        let spec = &self.spec;
        let mut fetcher = match Fetcher::new(spec.network, spec.peers.clone(), &spec.cache_dir) {
            Ok(fetcher) => fetcher,
            Err(error) => {
                let _ = self.items.push_block(FeedItem::Failed(format!("fetcher init: {error}")));
                return;
            }
        };
        while let Some(request) = self.requests.pop_block() {
            let outcome = match request {
                FeedRequest::Headers(request) => self.headers(&mut fetcher, request),
                FeedRequest::Blocks(request) => self.blocks(&mut fetcher, &request),
                FeedRequest::Discard => self.discard(&mut fetcher),
            };
            match outcome {
                Ok(()) => {}
                Err(FeedStop::ReceiverGone) => return,
                Err(FeedStop::Failed(message)) => {
                    if self.send(FeedItem::Failed(message)).is_err() {
                        return;
                    }
                }
            }
        }
    }

    fn send(&self, item: FeedItem<A>) -> Result<(), FeedStop> {
        self.items.push_block(item).map_err(|_| FeedStop::ReceiverGone)
    }

    fn headers(&self, fetcher: &mut Fetcher, request: HeaderRequest<A>) -> Result<(), FeedStop> {
        let HeaderRequest {
            start,
            stop,
            locator,
            mut admission,
        } = request;
        let headers = fetcher
            .sync_headers_admitted(start, stop, locator, &mut admission)
            .map_err(|error| FeedStop::Failed(format!("sync headers: {error}")))?;
        self.send(FeedItem::Headers(headers, admission))
    }

    fn discard(&self, fetcher: &mut Fetcher) -> Result<(), FeedStop> {
        fetcher
            .discard_cached_blocks()
            .map_err(|error| FeedStop::Failed(format!("discard blocks: {error}")))?;
        self.send(FeedItem::Done)
    }

    fn blocks(&self, fetcher: &mut Fetcher, request: &BlocksRequest) -> Result<(), FeedStop> {
        for window in request.wanted.chunks(request.window.max(1)) {
            if self.cancel.load(Ordering::Relaxed) {
                break;
            }
            let started = Instant::now();
            Self::fetch_window(fetcher, window)?;
            if request.deliver {
                for (height, header) in window {
                    let bytes = fetcher.read_block_bytes(*height).map_err(|error| {
                        FeedStop::Failed(format!("read block {}: {error}", height.to_u32()))
                    })?;
                    self.send(FeedItem::Block(FedBlock {
                        height: *height,
                        hash: header.hash(),
                        bytes,
                    }))?;
                }
            }
            if request.discard_each_window {
                fetcher
                    .discard_cached_blocks()
                    .map_err(|error| FeedStop::Failed(format!("discard blocks: {error}")))?;
            }
            self.send(FeedItem::WindowDone {
                first: window[0].0,
                last: window[window.len() - 1].0,
                elapsed: started.elapsed(),
            })?;
        }
        self.send(FeedItem::Done)
    }

    fn fetch_window(fetcher: &mut Fetcher, window: &[(BlockHeight, BlockHeader)]) -> Result<(), FeedStop> {
        let mut attempt = 1;
        while let Err(error) = fetcher.fetch_blocks(window) {
            if attempt >= Self::FETCH_ATTEMPTS {
                return Err(FeedStop::Failed(format!(
                    "fetch blocks: {error} after {attempt} attempts"
                )));
            }
            eprintln!(
                "  fetch retry {attempt}/{} for {}..={}: {error}",
                Self::FETCH_ATTEMPTS,
                window[0].0.to_u32(),
                window[window.len() - 1].0.to_u32()
            );
            attempt += 1;
        }
        Ok(())
    }
}
