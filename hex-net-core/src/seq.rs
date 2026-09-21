//! Packet numbering: the basis of loss detection, duplicate rejection,
//! acknowledgement, and AEAD nonce uniqueness.

use core::{fmt, num::NonZeroU64};

/// A packet's position in one direction of one connection. Starts at 1.
///
/// Nonzero, so "no packet yet" is `Option<Sequence>`.
///
/// Full width in memory, truncated to sixteen bits on the wire, so only
/// `resolve` ever deals with wraparound.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sequence(NonZeroU64);

/// The sixteen bits of a counter carried in a packet.
///
/// Kept distinct from the full value because a wire value is ambiguous until
/// resolved against a reference point.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct WireSequence(pub u16);

impl Sequence {
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    #[inline]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    #[inline]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    #[inline]
    pub fn next(self) -> Self {
        Self(self.0.checked_add(1).expect("sequence overflow"))
    }

    #[inline]
    pub const fn to_wire(self) -> WireSequence {
        WireSequence(self.0.get() as u16)
    }

    /// The sequence `n` before this one, or `None` when that would reach zero.
    #[inline]
    pub fn checked_sub(self, n: u64) -> Option<Self> {
        self.get().checked_sub(n).and_then(Sequence::new)
    }

    /// Resolves a wire value to the full sequence nearest `reference`, where
    /// `None` means nothing has been seen yet and resolves against zero.
    #[inline]
    pub fn resolve(reference: Option<Sequence>, wire: WireSequence) -> Option<Sequence> {
        reconstruct(reference.map_or(0, Sequence::get), wire).and_then(Sequence::new)
    }
}

impl fmt::Display for Sequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get())
    }
}

/// Resolves sixteen wire bits to the full counter value nearest `reference`.
///
/// Shared by every monotonic counter that travels truncated: packet
/// sequences, message ids, and ticks. Correct while the true value is within
/// 32,767 of the reference. At any realistic packet rate that is far longer
/// than a connection survives without traffic, so the idle timeout closes the
/// connection long before the window is at risk.
///
/// Returns `None` when the nearest candidate would be negative.
#[inline]
pub fn reconstruct(reference: u64, wire: WireSequence) -> Option<u64> {
    let delta = (wire.0.wrapping_sub(reference as u16) as i16) as i64;
    reference.checked_add_signed(delta)
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
    newest: Option<Sequence>,
    /// Bit i set means (newest - i) was received; bit 0 is `newest` itself.
    mask: u64,
}

impl ReceiveWindow {
    /// Whether a sequence may be accepted. Commits nothing.
    #[inline]
    pub fn check(&self, seq: Sequence) -> Result<(), WindowError> {
        let Some(newest) = self.newest else { return Ok(()) };
        if seq > newest {
            return Ok(());
        }
        let offset = newest.get() - seq.get();
        if offset >= 64 {
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
    pub fn insert(&mut self, sequence: Sequence) {
        match self.newest {
            Some(newest) if sequence <= newest => {
                let offset = newest.get() - sequence.get();
                if offset < 64 {
                    self.mask |= 1 << offset;
                }
            }
            Some(newest) => {
                let shift = sequence.get() - newest.get();
                // A shift of 64 or more is undefined, and leaves nothing in
                // range regardless.
                self.mask = if shift >= 64 { 0 } else { self.mask << shift };
                self.mask |= 1;
                self.newest = Some(sequence);
            }
            None => {
                self.mask = 1;
                self.newest = Some(sequence);
            }
        }
    }

    #[inline]
    pub fn newest(&self) -> Option<Sequence> {
        self.newest
    }

    /// Bit i set means (newest - 1 - i) was received.
    #[inline]
    pub fn ack_bits(&self) -> u32 {
        (self.mask >> 1) as u32
    }
}

struct Entry<T> {
    seq: Sequence,
    item: T,
}

/// A fixed ring keyed by sequence number.
///
/// `N` is a compile-time power of two, so a slot is a mask against an
/// immediate. An insert that lands on an occupied slot evicts the occupant and
/// returns it, so the caller always learns what was displaced.
pub struct SequenceBuffer<T, const N: usize> {
    /// `Sequence` is nonzero, so an empty slot costs no extra space.
    slots: [Option<Entry<T>>; N],
}

impl<T, const N: usize> Default for SequenceBuffer<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> SequenceBuffer<T, N> {
    pub fn new() -> Self {
        const { assert!(N > 0 && N.is_power_of_two()) };
        Self { slots: [const { None }; N] }
    }

    #[inline(always)]
    fn slot(seq: Sequence) -> usize {
        (seq.get() as usize) & (N - 1)
    }

    /// Stores `item` under `seq`, returning whatever the slot held before.
    #[inline]
    pub fn insert(&mut self, seq: Sequence, item: T) -> Option<(Sequence, T)> {
        self.slots[Self::slot(seq)]
            .replace(Entry { seq, item })
            .map(|evicted| (evicted.seq, evicted.item))
    }

    #[inline]
    pub fn get(&self, seq: Sequence) -> Option<&T> {
        self.slots[Self::slot(seq)]
            .as_ref()
            .and_then(|e| (e.seq == seq).then_some(&e.item))
    }

    #[inline]
    pub fn get_mut(&mut self, seq: Sequence) -> Option<&mut T> {
        self.slots[Self::slot(seq)]
            .as_mut()
            .and_then(|e| (e.seq == seq).then_some(&mut e.item))
    }

    #[inline]
    pub fn remove(&mut self, seq: Sequence) -> Option<T> {
        let slot = &mut self.slots[Self::slot(seq)];
        match slot {
            Some(entry) if entry.seq == seq => slot.take().map(|entry| entry.item),
            _ => None,
        }
    }
}
