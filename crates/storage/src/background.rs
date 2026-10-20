use std::fmt;

/// Bytes to write at one file offset.
pub struct Extent {
    pub offset: u64,
    pub bytes: Vec<u8>,
}

impl Extent {
    #[must_use]
    pub fn end(&self) -> u64 {
        self.offset + self.bytes.len() as u64
    }
}

impl fmt::Debug for Extent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Extent")
            .field("offset", &self.offset)
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// How a background flush ended: the table's live count, or why it failed.
pub type FlushOutcome = Result<u64, String>;

/// A message from an engine's background thread to the storage thread,
/// delivered through the same request ring as client requests so the
/// storage thread blocks on one queue.
#[derive(Debug)]
pub enum BackgroundEvent {
    /// Write these extents to the table, then acknowledge.
    WriteBack(Vec<Extent>),
    /// The table file was replaced by a grown copy with `slot_count` slots;
    /// reopen it, then acknowledge.
    TableReplaced { slot_count: u64 },
    /// The flush thread finished applying `epoch`.
    FlushEnded { epoch: u64, outcome: FlushOutcome },
    /// The data of `epoch` reached the disk, or failed to.
    Settled { epoch: u64, outcome: FlushOutcome },
    /// A background thread could not start.
    Failed(String),
}

/// The sending side of the storage thread's request ring, held by one
/// background thread.
pub struct Inbox<'s> {
    send: Box<dyn Fn(BackgroundEvent) -> bool + Send + 's>,
}

impl<'s> Inbox<'s> {
    pub fn new(send: impl Fn(BackgroundEvent) -> bool + Send + 's) -> Self {
        Self {
            send: Box::new(send),
        }
    }

    /// Returns `false` once the storage thread is gone.
    #[must_use]
    pub fn send(&self, event: BackgroundEvent) -> bool {
        (self.send)(event)
    }
}

/// A thread body an engine wants run beside the storage thread for as long
/// as the storage thread runs.
pub type BackgroundTask = Box<dyn for<'s> FnOnce(Inbox<'s>) + Send>;
