use std::ops::Deref;

use quetzalcoatl::capacity::Capacity;
use quetzalcoatl::mpsc::RingBuffer as MpscRing;
use quetzalcoatl::spsc::RingBuffer as SpscRing;

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
}

impl<
    'a,
    RReq: Deref<Target = MpscRing<StorageReq<'a>>>,
    RResp: Deref<Target = SpscRing<StorageResp>>,
> StorageWorker<'a, '_, RReq, RResp>
{
    pub(crate) fn run(mut self) {
        while let Some(req) = self.req_rx.pop_block() {
            let shutdown = matches!(req, StorageReq::Shutdown);
            let resp = self.dispatch(req);
            assert!(
                self.resp_tx.push(resp).is_ok(),
                "BUG: resp ring full — storage thread would deadlock",
            );
            if shutdown {
                return;
            }
        }
    }

    fn dispatch(&mut self, req: StorageReq<'a>) -> StorageResp {
        match req {
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
                let resp = self
                    .engine
                    .write_block(&r)
                    .and_then(|()| self.engine.flush(durability))
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
            StorageReq::Shutdown => StorageResp::Shutdown,
        }
    }
}

/// Run `f` with a `StorageHandle` backed by stack-local rings.
///
/// The handle's lifetime parameter is tied to the rings' stack frame, so
/// `send_lookup` / `lookup_coins` accept locally-borrowed `ops` and `out`
/// slices without any `unsafe` transmute.  The storage thread runs inside
/// `std::thread::scope`, so its join is guaranteed before `with_storage`
/// returns.
///
/// # Errors
/// Returns `StorageError` if the engine's initial `tip()` cannot be read or
/// the scoped thread cannot be spawned.
pub fn with_storage<E, F, R>(engine: E, f: F) -> Result<R, StorageError>
where
    E: Engine + Send,
    F: for<'req> FnOnce(
        &mut crate::handle::StorageHandle<'req, &MpscRing<StorageReq<'req>>, &SpscRing<StorageResp>>,
    ) -> R,
{
    let mut req_ring: MpscRing<StorageReq<'_>> = MpscRing::new(Capacity::exact(RING_CAP));
    let mut resp_ring: SpscRing<StorageResp> = SpscRing::new(Capacity::exact(RING_CAP));
    let initial_tip = engine.tip();

    let result = std::thread::scope(|s| {
        let (req_tx, req_rx) = req_ring.split_borrowed();
        let (resp_tx, resp_rx) = resp_ring.split_borrowed();

        let worker = StorageWorker {
            req_rx,
            resp_tx,
            engine: Box::new(engine),
        };

        s.spawn(|| worker.run());

        let mut handle = crate::handle::StorageHandle::from_parts(req_tx, resp_rx, initial_tip);
        f(&mut handle)
    });

    Ok(result)
}
