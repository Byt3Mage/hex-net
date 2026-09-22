//! Deadlines for a fixed set of slots, at most one each: an indexed binary
//! min-heap.
//!
//! Each slot's entry knows where it sits, so a deadline is moved or cancelled
//! in place rather than superseded by a new entry. The heap therefore never
//! holds more entries than slots, never holds a stale one, and never grows
//! past the storage allocated when it is made.

use crate::time::Timestamp;

const ABSENT: u32 = u32::MAX;

#[derive(Clone, Copy)]
struct Entry {
    at: Timestamp,
    slot: u32,
}

impl Entry {
    /// Earliest first, ties broken by slot, so deadlines that coincide are
    /// serviced in a reproducible order.
    #[inline]
    fn precedes(self, other: Entry) -> bool {
        (self.at, self.slot) < (other.at, other.slot)
    }
}

pub struct TimerHeap {
    /// `entries[..len]` is the heap.
    entries: Box<[Entry]>,
    len: usize,
    /// Indexed by slot: where that slot's entry is in `entries`, or `ABSENT`.
    positions: Box<[u32]>,
}

impl TimerHeap {
    /// Room for one deadline for each of `slots` slots, numbered from zero.
    pub fn with_slots(slots: u32) -> TimerHeap {
        assert!(slots < ABSENT, "slot count must leave u32::MAX free as a sentinel");
        let slots = slots as usize;
        TimerHeap {
            entries: vec![Entry { at: Timestamp::ZERO, slot: ABSENT }; slots].into(),
            len: 0,
            positions: vec![ABSENT; slots].into(),
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The slot's deadline, if it has one.
    #[inline]
    pub fn deadline(&self, slot: u32) -> Option<Timestamp> {
        let at = *self.positions.get(slot as usize)?;
        (at != ABSENT).then(|| self.entries[at as usize].at)
    }

    /// The earliest deadline and its slot.
    #[inline]
    pub fn peek(&self) -> Option<(Timestamp, u32)> {
        (self.len > 0).then(|| (self.entries[0].at, self.entries[0].slot))
    }

    /// Gives `slot` the deadline `at`, replacing any it had, earlier or later.
    pub fn set(&mut self, slot: u32, at: Timestamp) {
        let position = self.positions[slot as usize];
        if position == ABSENT {
            let position = self.len;
            self.len += 1;
            self.place(position, Entry { at, slot });
            self.sift_up(position);
            return;
        }

        let position = position as usize;
        let earlier = at < self.entries[position].at;
        self.entries[position].at = at;
        if earlier {
            self.sift_up(position);
        } else {
            self.sift_down(position);
        }
    }

    /// Removes `slot`'s deadline, if it has one.
    pub fn cancel(&mut self, slot: u32) {
        let position = self.positions[slot as usize];
        if position != ABSENT {
            self.remove_at(position as usize);
        }
    }

    /// Removes and returns the earliest slot whose deadline is at or before
    /// `now`.
    pub fn pop_due(&mut self, now: Timestamp) -> Option<u32> {
        let (at, slot) = self.peek()?;
        if at > now {
            return None;
        }
        self.remove_at(0);
        Some(slot)
    }

    fn remove_at(&mut self, position: usize) {
        let removed = self.entries[position].slot;
        self.positions[removed as usize] = ABSENT;

        self.len -= 1;
        if position == self.len {
            return;
        }

        // The last entry fills the hole, then moves whichever way restores
        // the order: it may belong above or below where the hole was.
        let last = self.entries[self.len];
        self.place(position, last);
        if (position > 0) && last.precedes(self.entries[parent(position)]) {
            self.sift_up(position);
        } else {
            self.sift_down(position);
        }
    }

    fn sift_up(&mut self, mut position: usize) {
        let entry = self.entries[position];
        while position > 0 {
            let above = parent(position);
            if !entry.precedes(self.entries[above]) {
                break;
            }
            self.place(position, self.entries[above]);
            position = above;
        }
        self.place(position, entry);
    }

    fn sift_down(&mut self, mut position: usize) {
        let entry = self.entries[position];
        loop {
            let left = (2 * position) + 1;
            if left >= self.len {
                break;
            }
            let right = left + 1;
            let child =
                if (right < self.len) && self.entries[right].precedes(self.entries[left]) { right } else { left };
            if !self.entries[child].precedes(entry) {
                break;
            }
            self.place(position, self.entries[child]);
            position = child;
        }
        self.place(position, entry);
    }

    /// Writes `entry` at `position` and records where it is.
    #[inline]
    fn place(&mut self, position: usize, entry: Entry) {
        self.entries[position] = entry;
        self.positions[entry.slot as usize] = position as u32;
    }
}

#[inline]
const fn parent(position: usize) -> usize {
    (position - 1) / 2
}
