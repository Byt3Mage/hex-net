//! Fixed-capacity containers.
//!
//! Correct for counts of small records. Not for payload storage: reserving
//! worst-case space per slot multiplies waste by the slot count, which is what
//! the arena exists for.

use core::ops::{Deref, DerefMut};

/// A vector whose capacity is a compile-time constant.
#[derive(Debug, Clone, Copy)]
pub struct FixedVec<T: Copy, const CAP: usize> {
    items: [T; CAP],
    len: u32,
}

impl<T: Copy + Default, const CAP: usize> Default for FixedVec<T, CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy + Default, const CAP: usize> FixedVec<T, CAP> {
    pub fn new() -> Self {
        Self::new_with_default(|_| T::default())
    }

    /// Returns `None` rather than truncating: a partial key or ticket would
    /// fail later in ways that are hard to trace back here.
    pub fn from_slice(source: &[T]) -> Option<Self> {
        if source.len() > CAP {
            return None;
        }
        let mut out = Self::new();
        out.items[..source.len()].copy_from_slice(source);
        out.len = source.len() as u32;
        Some(out)
    }
}

impl<T: Copy, const CAP: usize> FixedVec<T, CAP> {
    pub fn new_with_default<F: FnMut(usize) -> T>(default: F) -> Self {
        const { assert!(CAP <= (u32::MAX as usize)) };
        Self { items: std::array::from_fn(default), len: 0 }
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
    pub fn is_full(&self) -> bool {
        self.len() == CAP
    }

    /// Returns false when full.
    #[inline]
    #[must_use]
    pub fn push(&mut self, item: T) -> bool {
        if self.is_full() {
            return false;
        }
        let at = self.len();
        self.items[at] = item;
        self.len += 1;
        true
    }

    /// Returns false when the whole slice does not fit; nothing is written.
    pub fn extend_from_slice(&mut self, source: &[T]) -> bool {
        let at = self.len();
        let end = at + source.len();
        if end > CAP {
            return false;
        }
        self.items[at..end].copy_from_slice(source);
        self.len = end as u32;
        true
    }

    /// Removes preserving order, so queues stay oldest-first.
    pub fn remove(&mut self, at: usize) -> Option<T> {
        if at >= self.len() {
            return None;
        }
        let item = self.items[at];
        let len = self.len();
        for index in at..(len - 1) {
            self.items[index] = self.items[index + 1];
        }
        self.len -= 1;
        Some(item)
    }

    pub fn retain(&mut self, mut f: impl FnMut(&T) -> bool) {
        let mut write = 0;
        let len = self.len();

        for read in 0..len {
            let item = &self.items[read];
            if f(item) {
                self.items[write] = *item;
                write += 1;
            }
        }

        self.len = write as u32;
    }

    #[inline]
    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl<T: Copy, const N: usize> Deref for FixedVec<T, N> {
    type Target = [T];

    #[inline]
    fn deref(&self) -> &[T] {
        &self.items[..self.len()]
    }
}

impl<T: Copy, const N: usize> DerefMut for FixedVec<T, N> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        let len = self.len();
        &mut self.items[..len]
    }
}

/// Fixed-capacity FIFO that drops its oldest entry when full, so an
/// application that stops draining events cannot make a connection grow.
#[derive(Clone, Copy)]
pub struct RingQueue<T: Copy, const N: usize> {
    items: [T; N],
    head: usize,
    len: usize,
    dropped: u64,
}

impl<T: Copy + Default, const N: usize> Default for RingQueue<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy + Default, const N: usize> RingQueue<T, N> {
    pub fn new() -> Self {
        const { assert!(N.is_power_of_two() && (N > 0)) };
        Self {
            items: [T::default(); N],
            head: 0,
            len: 0,
            dropped: 0,
        }
    }

    pub fn push(&mut self, item: T) {
        if self.len == N {
            self.head = (self.head + 1) & (N - 1);
            self.len -= 1;
            self.dropped += 1;
        }
        let at = (self.head + self.len) & (N - 1);
        self.items[at] = item;
        self.len += 1;
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let item = self.items[self.head];
        self.head = (self.head + 1) & (N - 1);
        self.len -= 1;
        Some(item)
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Entries discarded because the queue was full.
    #[inline]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}
