/// A simple fixed-capacity byte buffer pool.
///
/// v1 is a thin wrapper — callers borrow a slot, use it, then return it.
/// The pool avoids repeated large allocations during the replay hot path.
pub struct BufferPool {
    slots: Vec<Vec<u8>>,
    capacity: usize,
}

impl BufferPool {
    /// Create a pool pre-filled with `count` buffers each of `buf_size` bytes.
    #[must_use]
    pub fn new(count: usize, buf_size: usize) -> Self {
        Self {
            slots: (0..count).map(|_| Vec::with_capacity(buf_size)).collect(),
            capacity: buf_size,
        }
    }

    /// Take a buffer from the pool, or allocate a fresh one if the pool is empty.
    pub fn acquire(&mut self) -> Vec<u8> {
        self.slots
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(self.capacity))
    }

    /// Return a buffer to the pool. The buffer is cleared before re-pooling.
    pub fn release(&mut self, mut buf: Vec<u8>) {
        buf.clear();
        self.slots.push(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_release_roundtrip() {
        let mut pool = BufferPool::new(2, 1024);
        let mut buf = pool.acquire();
        buf.extend_from_slice(b"hello");
        pool.release(buf);
        let recycled = pool.acquire();
        assert!(recycled.is_empty(), "released buffer should be cleared");
    }

    #[test]
    fn acquire_beyond_pool_size() {
        let mut pool = BufferPool::new(1, 64);
        let _a = pool.acquire();
        let _b = pool.acquire(); // pool is now empty — allocates fresh
    }
}
