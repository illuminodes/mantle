use std::collections::VecDeque;
use std::ops::Deref;

use quetzalcoatl::capacity::Capacity;
use quetzalcoatl::mpsc::RingBuffer as MpscRing;
use quetzalcoatl::spsc::RingBuffer as SpscRing;

use crate::background::{BackgroundTask, Inbox};
use crate::engine::Engine;
use crate::types::{
    CommittedResp, HeaderKey, LookupCoinsResp, StorageError, StorageReq, StorageResp,
};

const RING_CAP: usize = 1024;

pub(crate) struct StorageWorker<
    'a,
    'eng,
    RReq: Deref<Target = MpscRing<StorageReq<'a>>>,
    RResp: Deref<Target = SpscRing<StorageResp>>,
> {
    pub(crate) req_rx: quetzalcoatl::mpsc::Consumer<StorageReq<'a>, RReq>,
    pub(crate) resp_tx: quetzalcoatl::spsc::Producer<StorageResp, RResp>,
    pub(crate) engine: Box<dyn Engine + Send + 'eng>,
    /// Client requests that arrived while a response was held back, in
    /// arrival order.
    pub(crate) parked: VecDeque<StorageReq<'a>>,
}

impl<
    'a,
    'eng,
    RReq: Deref<Target = MpscRing<StorageReq<'a>>>,
    RResp: Deref<Target = SpscRing<StorageResp>>,
> StorageWorker<'a, 'eng, RReq, RResp>
{
    pub(crate) fn new(
        req_rx: quetzalcoatl::mpsc::Consumer<StorageReq<'a>, RReq>,
        resp_tx: quetzalcoatl::spsc::Producer<StorageResp, RResp>,
        engine: Box<dyn Engine + Send + 'eng>,
    ) -> Self {
        Self {
            req_rx,
            resp_tx,
            engine,
            parked: VecDeque::new(),
        }
    }

    pub(crate) fn run(mut self) {
        while let Some(req) = self.next_request() {
            let shutdown = matches!(req, StorageReq::Shutdown);
            let Some(resp) = self.dispatch(req) else {
                continue;
            };
            assert!(
                self.resp_tx.push(resp).is_ok(),
                "BUG: resp ring full — storage thread would deadlock",
            );
            if shutdown {
                return;
            }
        }
    }

    fn next_request(&mut self) -> Option<StorageReq<'a>> {
        self.parked.pop_front().or_else(|| self.req_rx.pop_block())
    }

    /// Handle background events until `done` holds, parking every client
    /// request that arrives meanwhile so responses keep their order.
    fn serve_background_until(&mut self, done: impl Fn(&dyn Engine) -> bool) {
        while !done(self.engine.as_ref()) {
            match self.req_rx.pop_block() {
                Some(StorageReq::Background(event)) => self.engine.on_background(event),
                Some(other) => self.parked.push_back(other),
                None => return,
            }
        }
    }

    fn dispatch(&mut self, req: StorageReq<'a>) -> Option<StorageResp> {
        let resp = match req {
            StorageReq::LookupCoins(r) => {
                let token = r.token;
                r.out.clear();
                let resp = self
                    .engine
                    .read_coins(r.outpoints, r.out)
                    .map(|()| LookupCoinsResp { token })
                    .map_err(|e| {
                        eprintln!("[w] read_coins error: {e}");
                        StorageError::from(e)
                    });
                StorageResp::LookupCoins(resp)
            }
            StorageReq::CommitBlock(r) => {
                let token = r.token;
                let durability = r.durability;
                let applied = self
                    .engine
                    .write_block(&r)
                    .and_then(|()| self.engine.flush(durability));
                drop(r);
                self.serve_background_until(|engine| !engine.awaits_background());
                let resp = applied
                    .and_then(|()| self.engine.background_health())
                    .map(|()| CommittedResp {
                        token,
                        tip: self.engine.tip(),
                    })
                    .map_err(StorageError::from);
                StorageResp::CommitBlock(resp)
            }
            StorageReq::ReadHeader(r) => {
                let token = r.token;
                let resp = match r.key {
                    HeaderKey::ByHash(h) => self.engine.read_header(&h),
                    HeaderKey::ByHeight(h) => self.engine.read_header_at(h),
                }
                .map(|header| crate::types::ReadHeaderResp { token, header })
                .map_err(StorageError::from);
                StorageResp::ReadHeader(resp)
            }
            StorageReq::Background(event) => {
                self.engine.on_background(event);
                return None;
            }
            StorageReq::Shutdown => {
                self.serve_background_until(|engine| engine.background_idle());
                if let Err(e) = self.engine.background_health() {
                    eprintln!("[w] storage shut down after a failed flush: {e}");
                }
                StorageResp::Shutdown
            }
        };
        Some(resp)
    }
}

/// Starts an engine's background threads, each holding a producer on the
/// storage thread's request ring.
pub(crate) struct BackgroundSpawn;

impl BackgroundSpawn {
    /// Spawn every task inside `scope`.
    pub(crate) fn scoped<'scope, 'env, 'a: 'env>(
        scope: &'scope std::thread::Scope<'scope, 'env>,
        tasks: Vec<BackgroundTask>,
        producer: &quetzalcoatl::mpsc::Producer<StorageReq<'a>, &'env MpscRing<StorageReq<'a>>>,
    ) {
        for task in tasks {
            let sender = producer.new_producer();
            scope.spawn(move || {
                task(Inbox::new(move |event| {
                    sender.push_block(StorageReq::Background(event)).is_ok()
                }));
            });
        }
    }

    /// Spawn every task as a detached thread.
    pub(crate) fn detached(
        tasks: Vec<BackgroundTask>,
        producer: &quetzalcoatl::mpsc::Producer<StorageReq<'static>>,
    ) -> std::io::Result<()> {
        for task in tasks {
            let sender = producer.clone();
            std::thread::Builder::new()
                .name("storage-bg".into())
                .spawn(move || {
                    task(Inbox::new(move |event| {
                        sender.push_block(StorageReq::Background(event)).is_ok()
                    }));
                })?;
        }
        Ok(())
    }
}

/// Run `f` with a `StorageHandle` backed by stack-local rings.
///
/// The handle's lifetime parameter is tied to the rings' stack frame, so
/// `send_lookup` / `lookup_coins` accept locally-borrowed `ops` and `out`
/// slices without any `unsafe` transmute.  The storage thread and the
/// engine's background threads run inside `std::thread::scope`, so they are
/// joined before `with_storage` returns.
///
/// # Errors
/// Returns `StorageError` if the engine's initial `tip()` cannot be read or
/// its background threads cannot be set up.
pub fn with_storage<E, F, R>(mut engine: E, f: F) -> Result<R, StorageError>
where
    E: Engine + Send,
    F: for<'req> FnOnce(
        &mut crate::handle::StorageHandle<'req, &MpscRing<StorageReq<'req>>, &SpscRing<StorageResp>>,
    ) -> R,
{
    let mut req_ring: MpscRing<StorageReq<'_>> = MpscRing::new(Capacity::exact(RING_CAP));
    let mut resp_ring: SpscRing<StorageResp> = SpscRing::new(Capacity::exact(RING_CAP));
    let initial_tip = engine.tip();
    let tasks = engine.background_tasks().map_err(StorageError::from)?;

    let result = std::thread::scope(|s| {
        let (req_tx, req_rx) = req_ring.split_borrowed();
        let (resp_tx, resp_rx) = resp_ring.split_borrowed();

        BackgroundSpawn::scoped(s, tasks, &req_tx);
        let worker = StorageWorker::new(req_rx, resp_tx, Box::new(engine));
        s.spawn(|| worker.run());

        let mut handle = crate::handle::StorageHandle::from_parts(req_tx, resp_rx, initial_tip);
        f(&mut handle)
    });

    Ok(result)
}
