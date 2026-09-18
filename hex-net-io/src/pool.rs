use std::{
    alloc::{self, Layout},
    num::NonZeroU32,
    ptr::NonNull,
    sync::{Mutex, MutexGuard, PoisonError},
};

const PAGE: usize = 4096;
const BATCH: usize = 32;

/// Fixed-size packet buffers carved out of one contiguous, page-aligned region.
pub struct Pool {
    region: NonNull<u8>,
    layout: Layout,
    buffer_size: usize,
    buffer_count: u32,
    shared: Mutex<Vec<u32>>, // free indices not held by any cache
}

// SAFETY: the pool never reads or writes buffer memory itself. Each index lives
// in exactly one place at a time (shared list, one cache, or one PacketBuf), so
// only its single owner can touch that buffer, from whichever thread holds it.
unsafe impl Send for Pool {}
unsafe impl Sync for Pool {}

impl Pool {
    pub fn new(buffer_count: NonZeroU32, buffer_size: NonZeroU32) -> Self {
        let buffer_count = buffer_count.get();
        let buffer_size = buffer_size.get() as usize;

        let bytes = (buffer_count as usize)
            .checked_mul(buffer_size)
            .and_then(|b| b.checked_next_multiple_of(PAGE))
            .expect("pool size overflows usize");

        let layout = Layout::from_size_align(bytes, PAGE).expect("invalid pool layout");

        // SAFETY: layout has nonzero size.
        let ptr = unsafe { alloc::alloc(layout) };
        let region = NonNull::new(ptr).unwrap_or_else(|| alloc::handle_alloc_error(layout));

        // Fault in every page now, so first use never page-faults on the hot path.
        // This also initializes every byte, which makes handing out &[u8] sound.
        // SAFETY: region is valid for `bytes` writes.
        unsafe { region.write_bytes(0, bytes) };

        Self {
            region,
            layout,
            buffer_size,
            buffer_count,
            shared: Mutex::new((0..buffer_count).rev().collect()), // Reversed so pops hand out low indices first.
        }
    }

    #[inline]
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    #[inline]
    pub fn capacity(&self) -> u32 {
        self.buffer_count
    }

    /// A per-thread cache. Create one per thread that acquires or releases buffers.
    pub fn local(&self) -> LocalCache<'_> {
        LocalCache { pool: self, free: Vec::with_capacity(2 * BATCH) }
    }

    fn shared(&self) -> MutexGuard<'_, Vec<u32>> {
        // Vec push/extend/drain can't panic mid-operation here (capacity is
        // reserved), so a poisoned lock still guards a consistent list.
        self.shared.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[inline]
    fn buffer_ptr(&self, index: u32) -> *mut u8 {
        debug_assert!(index < self.buffer_count);
        // SAFETY: index < count, so the offset is inside the region.
        unsafe { self.region.as_ptr().add(index as usize * self.buffer_size) }
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        // SAFETY: allocated in `new` with this layout. Handles and caches borrow
        // the pool, so none can outlive it.
        unsafe { alloc::dealloc(self.region.as_ptr(), self.layout) };
    }
}

/// Per-thread stack of free indices. Talks to the shared list in batches.
pub struct LocalCache<'p> {
    pool: &'p Pool,
    free: Vec<u32>, // never exceeds 2 * BATCH
}

impl<'p> LocalCache<'p> {
    #[inline]
    pub fn acquire(&mut self) -> Option<PacketBuf<'p>> {
        if self.free.is_empty() {
            self.refill();
        }

        Some(PacketBuf { pool: self.pool, idx: self.free.pop()?, len: 0 })
    }

    #[inline]
    pub fn release(&mut self, buf: PacketBuf<'p>) {
        if !std::ptr::eq(buf.pool, self.pool) {
            // Belongs to another pool; its Drop returns it there.
            // Caching it here would let this pool hand out a duplicate index.
            core::mem::drop(buf);
            return;
        }

        let index = buf.idx;
        std::mem::forget(buf); // skip Drop's slow path
        if self.free.len() == 2 * BATCH {
            self.flush(BATCH);
        }
        self.free.push(index);
    }

    #[cold]
    fn refill(&mut self) {
        let mut shared = self.pool.shared();
        let start = shared.len().saturating_sub(BATCH);
        self.free.extend(shared.drain(start..));
    }

    #[cold]
    fn flush(&mut self, n: usize) {
        let start = self.free.len() - n;
        let mut shared = self.pool.shared();
        shared.extend(self.free.drain(start..));
    }
}

impl Drop for LocalCache<'_> {
    fn drop(&mut self) {
        let n = self.free.len();
        if n > 0 {
            self.flush(n);
        }
    }
}

/// Exclusive handle to one buffer.
/// Not Clone, so one handle per buffer, always.
pub struct PacketBuf<'p> {
    pool: &'p Pool,
    idx: u32,
    len: u32,
}

impl PacketBuf<'_> {
    /// Stable buffer number, for registering, e.g. with io_uring.
    #[inline]
    pub fn index(&self) -> u32 {
        self.idx
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.pool.buffer_size
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn set_len(&mut self, len: usize) {
        assert!(len <= self.capacity(), "len exceeds buffer capacity");
        self.len = len as u32;
    }

    /// The valid data: bytes 0..len.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: this handle is the only owner of the buffer; len <= capacity;
        // every byte was initialized when the pool was created.
        unsafe { std::slice::from_raw_parts(self.pool.buffer_ptr(self.idx), self.len as usize) }
    }

    /// The whole buffer, for writing into. Call set_len afterward.
    #[inline]
    pub fn as_mut_capacity(&mut self) -> &mut [u8] {
        // SAFETY: as above, and &mut self guarantees no other borrow of this handle.
        unsafe { std::slice::from_raw_parts_mut(self.pool.buffer_ptr(self.idx), self.pool.buffer_size) }
    }
}

impl Drop for PacketBuf<'_> {
    fn drop(&mut self) {
        // Slow path for buffers not returned through a LocalCache.
        self.pool.shared().push(self.idx);
    }
}
