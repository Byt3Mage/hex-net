//! Block-allocated storage for message payloads.
//!
//! Messages vary in size and are freed out of order, since acknowledgements
//! arrive out of order. Fixed blocks chained by index give deterministic
//! allocation with no fragmentation and no heap traffic.
//!
//! One arena per direction per connection. Sized by bytes outstanding —
//! bandwidth times round trip — not by a message count, since many small
//! messages and few large ones cost the same.

use std::array;

/// Bytes per block. Most messages fit in one; the waste on a short message
/// is bounded by this, and the chain walk on a long one is short.
pub const BLOCK: usize = 64;

const NONE: u16 = u16::MAX;

/// A stored message: where its chain starts and how long it is.
///
/// Four bytes, so the structures that reference messages stay small enough to
/// hold many of them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MessageRef {
    first: u16,
    len: u16,
}

impl MessageRef {
    /// A reference to nothing, distinguishable from a zero-length message.
    pub const NONE: MessageRef = MessageRef { first: NONE, len: 0 };

    #[inline]
    pub const fn is_none(self) -> bool {
        self.first == NONE
    }

    #[inline]
    pub const fn len(self) -> usize {
        self.len as usize
    }

    #[inline]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

/// A fixed pool of blocks shared by every message in one direction.
///
/// `N` blocks give `N * BLOCK` bytes of capacity.
pub struct Arena<const N: usize> {
    blocks: [[u8; BLOCK]; N],
    /// Chain links: the next block of a message, or the next free block.
    next: [u16; N],
    free_head: u16,
    free_count: u16,
}

impl<const N: usize> Default for Arena<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Arena<N> {
    pub fn new() -> Self {
        const { assert!(N > 0 && N < (u16::MAX as usize)) };

        Self {
            blocks: [[0u8; BLOCK]; N],
            next: array::from_fn(|i| if (i + 1) < N { (i + 1) as u16 } else { NONE }),
            free_head: 0,
            free_count: N as u16,
        }
    }

    #[inline]
    pub fn capacity_bytes(&self) -> usize {
        N * BLOCK
    }

    #[inline]
    pub fn free_bytes(&self) -> usize {
        (self.free_count as usize) * BLOCK
    }

    /// Blocks a payload of this length occupies. A zero-length message still
    /// takes one, so it has an address.
    #[inline]
    pub fn blocks_for(len: usize) -> usize {
        len.div_ceil(BLOCK).max(1)
    }

    /// Reserves space without writing. Returns `None` when there is not enough
    /// room, which is the backpressure signal: the application is producing
    /// faster than the connection can drain.
    pub fn reserve(&mut self, len: usize) -> Option<MessageRef> {
        if len > (u16::MAX as usize) {
            return None;
        }

        let needed = Self::blocks_for(len);

        if needed > (self.free_count as usize) {
            return None;
        }

        let first = self.free_head;
        let mut block = first;
        for step in 0..needed {
            let following = self.next[block as usize];
            if (step + 1) == needed {
                // Detach the chain from the free list.
                self.next[block as usize] = NONE;
                self.free_head = following;
            } else {
                block = following;
            }
        }

        self.free_count -= needed as u16;
        Some(MessageRef { first, len: len as u16 })
    }

    /// Writes into a reserved message at `offset`. Returns false when the write
    /// would run past its length.
    ///
    /// Pieces may be written in any order, which is what fragment reassembly
    /// needs.
    pub fn write_at(&mut self, message: MessageRef, offset: usize, bytes: &[u8]) -> bool {
        if message.is_none() || (offset + bytes.len()) > message.len() {
            return false;
        }

        if bytes.is_empty() {
            return true;
        }

        // Walk to the block holding `offset`.
        let mut block = message.first;
        for _ in 0..(offset / BLOCK) {
            block = self.next[block as usize];
            if block == NONE {
                return false;
            }
        }

        let mut written = 0;
        let mut within = offset % BLOCK;
        while written < bytes.len() {
            if block == NONE {
                return false;
            }
            let take = (BLOCK - within).min(bytes.len() - written);
            self.blocks[block as usize][within..(within + take)].copy_from_slice(&bytes[written..(written + take)]);
            written += take;
            within = 0;
            block = self.next[block as usize];
        }
        true
    }

    /// Reserves and fills in one step.
    pub fn store(&mut self, payload: &[u8]) -> Option<MessageRef> {
        let message = self.reserve(payload.len())?;
        if !self.write_at(message, 0, payload) {
            self.release(message);
            return None;
        }
        Some(message)
    }

    /// Copies a stored message into `out`. Returns its length, or `None` when
    /// `out` is too small.
    pub fn load(&self, message: MessageRef, out: &mut [u8]) -> Option<usize> {
        if message.is_none() || (out.len() < message.len()) {
            return None;
        }

        let mut block = message.first;
        let mut read = 0;
        while read < message.len() {
            if block == NONE {
                return None;
            }
            let take = (message.len() - read).min(BLOCK);
            out[read..(read + take)].copy_from_slice(&self.blocks[block as usize][..take]);
            read += take;
            block = self.next[block as usize];
        }
        Some(message.len())
    }

    /// Returns a message's blocks to the free list.
    pub fn release(&mut self, message: MessageRef) {
        if message.is_none() {
            return;
        }

        let mut block = message.first;
        loop {
            let following = self.next[block as usize];
            self.next[block as usize] = self.free_head;
            self.free_head = block;
            self.free_count += 1;

            if following == NONE {
                break;
            }
            block = following;
        }
    }

    /// Visits a message's blocks in order, for writing into a packet without
    /// staging it through an intermediate buffer.
    pub fn chunks(&self, message: MessageRef) -> Chunks<'_, N> {
        Chunks {
            arena: self,
            block: message.first,
            remaining: if message.is_none() { 0 } else { message.len() },
        }
    }
}

pub struct Chunks<'a, const N: usize> {
    arena: &'a Arena<N>,
    block: u16,
    remaining: usize,
}

impl<'a, const N: usize> Iterator for Chunks<'a, N> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if (self.remaining == 0) || (self.block == NONE) {
            return None;
        }
        let take = self.remaining.min(BLOCK);
        let chunk = &self.arena.blocks[self.block as usize][..take];
        self.block = self.arena.next[self.block as usize];
        self.remaining -= take;
        Some(chunk)
    }
}
