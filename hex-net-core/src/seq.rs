//! Packet numbering: the basis of loss detection, duplicate rejection,
//! acknowledgement, and AEAD nonce uniqueness.

use core::fmt;

/// A packet's position in one direction of one connection. Starts at 1; zero
/// means none yet.
///
/// Full width in memory, truncated to sixteen bits on the wire, so only
/// `reconstruct` ever deals with wraparound.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sequence(u64);

/// The sixteen bits of a sequence carried in a packet header.
///
/// Kept distinct from `Sequence` because a wire value is ambiguous until
/// resolved against a reference point.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct WireSequence(pub u16);

impl Sequence {
    pub const NONE: Sequence = Sequence(0);
    pub const FIRST: Sequence = Sequence(1);

    /// Builds a sequence from a raw counter value. Used where another
    /// monotonic counter borrows the reconstruction rule.
    #[inline]
    pub const fn from_raw(value: u64) -> Sequence {
        Sequence(value)
    }

    #[inline]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub fn next(self) -> Sequence {
        Sequence(self.0.checked_add(1).expect("sequence overflow"))
    }

    #[inline]
    pub const fn to_wire(self) -> WireSequence {
        WireSequence(self.0 as u16)
    }

    #[inline]
    pub fn checked_since(self, earlier: Sequence) -> Option<u64> {
        self.0.checked_sub(earlier.0)
    }

    #[inline]
    pub fn saturating_sub(self, n: u64) -> Sequence {
        Sequence(self.0.saturating_sub(n))
    }
}

impl fmt::Display for Sequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Resolves a wire value to the full sequence nearest `reference`.
///
/// Correct while the true sequence is within 32,767 of the reference. At any
/// realistic packet rate that is far longer than a connection survives
/// without traffic, so the idle timeout closes the connection long before the
/// window is at risk.
///
/// Returns `None` when the nearest candidate would be negative.
#[inline]
pub fn reconstruct(reference: Sequence, wire: WireSequence) -> Option<Sequence> {
    let delta = (wire.0.wrapping_sub(reference.0 as u16) as i16) as i64;
    reference.0.checked_add_signed(delta).map(Sequence)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowError {
    Duplicate,
    /// Older than the window remembers, so duplication cannot be ruled out.
    TooOld,
}

/// The last 64 sequences received from a peer.
///
/// Serves as both the AEAD replay window and the source of acknowledgement
/// fields in outgoing headers.
#[derive(Debug, Default, Clone)]
pub struct ReceiveWindow {
    newest: Sequence,
    /// Bit i set means (newest - i) was received; bit 0 is `newest` itself.
    mask: u64,
}

impl ReceiveWindow {
    /// Whether a sequence may be accepted. Commits nothing.
    #[inline]
    pub fn check(&self, seq: Sequence) -> Result<(), WindowError> {
        if seq > self.newest {
            return Ok(());
        }
        let offset = self.newest.0 - seq.0;
        if seq.is_none() || (offset >= 64) {
            return Err(WindowError::TooOld);
        }
        if (self.mask & (1 << offset)) != 0 {
            return Err(WindowError::Duplicate);
        }
        Ok(())
    }

    /// Records a sequence. Call only after `check` passed and the packet
    /// authenticated: committing an unauthenticated sequence would let one
    /// forged packet advance the window past all genuine traffic.
    #[inline]
    pub fn insert(&mut self, seq: Sequence) {
        if seq > self.newest {
            let shift = seq.0 - self.newest.0;
            // A shift of 64 or more is undefined, and leaves nothing in range
            // regardless.
            self.mask = if shift >= 64 { 0 } else { self.mask << shift };
            self.mask |= 1;
            self.newest = seq;
        } else {
            let offset = self.newest.0 - seq.0;
            if offset < 64 {
                self.mask |= 1 << offset;
            }
        }
    }

    #[inline]
    pub fn newest(&self) -> Sequence {
        self.newest
    }

    /// Bit i set means (newest - 1 - i) was received.
    #[inline]
    pub fn ack_bits(&self) -> u32 {
        (self.mask >> 1) as u32
    }
}

/// A fixed ring keyed by sequence number.
///
/// `N` is a compile-time power of two, so a slot is a mask against an
/// immediate. Entries are overwritten once the ring wraps.
pub struct SequenceBuffer<T, const N: usize> {
    /// Which sequence owns each slot; `Sequence::NONE` marks it free.
    seqs: [Sequence; N],
    items: [T; N],
}

impl<T: Default + Copy, const N: usize> Default for SequenceBuffer<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Default + Copy, const N: usize> SequenceBuffer<T, N> {
    pub fn new() -> Self {
        const { assert!(N.is_power_of_two() && (N > 0)) };
        Self {
            seqs: [Sequence::NONE; N],
            items: [T::default(); N],
        }
    }

    #[inline(always)]
    fn slot(seq: Sequence) -> usize {
        (seq.0 as usize) & (N - 1)
    }

    #[inline]
    pub fn insert(&mut self, seq: Sequence, item: T) {
        debug_assert!(!seq.is_none());
        let at = Self::slot(seq);
        self.seqs[at] = seq;
        self.items[at] = item;
    }

    #[inline]
    pub fn get(&self, seq: Sequence) -> Option<&T> {
        let at = Self::slot(seq);
        ((!seq.is_none()) && (self.seqs[at] == seq)).then(|| &self.items[at])
    }

    #[inline]
    pub fn get_mut(&mut self, seq: Sequence) -> Option<&mut T> {
        let at = Self::slot(seq);
        if seq.is_none() || (self.seqs[at] != seq) {
            return None;
        }
        Some(&mut self.items[at])
    }

    #[inline]
    pub fn remove(&mut self, seq: Sequence) -> Option<T> {
        let at = Self::slot(seq);
        if seq.is_none() || (self.seqs[at] != seq) {
            return None;
        }
        self.seqs[at] = Sequence::NONE;
        Some(core::mem::take(&mut self.items[at]))
    }
}
