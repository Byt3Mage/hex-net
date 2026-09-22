//! Time as a plain value, so a simulated clock can drive the protocol exactly.

use core::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::seq::{self, WireSequence};

/// Nanoseconds since an arbitrary origin, always monotonic.
///
/// Not `std::time::Instant`, which cannot be constructed from a value; tests
/// and the network simulator need to set time explicitly.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    pub const ZERO: Timestamp = Timestamp(0);
    /// Far enough ahead to stand in for "no deadline".
    pub const MAX: Timestamp = Timestamp(u64::MAX);

    #[inline]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    #[inline]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// Zero when `earlier` is actually later, which can happen between
    /// timestamps from different sources.
    #[inline]
    pub fn saturating_since(self, earlier: Timestamp) -> Duration {
        Duration::from_nanos(self.0.saturating_sub(earlier.0))
    }

    #[inline]
    pub fn checked_add(self, d: Duration) -> Option<Timestamp> {
        let nanos = u64::try_from(d.as_nanos()).ok()?;
        self.0.checked_add(nanos).map(Timestamp)
    }

    #[inline]
    pub fn checked_sub(self, d: Duration) -> Option<Timestamp> {
        let nanos = u64::try_from(d.as_nanos()).ok()?;
        self.0.checked_sub(nanos).map(Timestamp)
    }

    #[inline]
    pub fn saturating_add(self, d: Duration) -> Timestamp {
        self.checked_add(d).unwrap_or(Timestamp::MAX)
    }

    #[inline]
    pub fn saturating_sub(self, d: Duration) -> Timestamp {
        self.checked_sub(d).unwrap_or(Timestamp::MAX)
    }
}

/// Source of the current time for drivers. The protocol itself always
/// receives the time as a parameter.
pub trait Clock {
    fn now(&self) -> Timestamp;
}

/// Real monotonic time, measured from construction.
#[derive(Clone, Copy, Debug)]
pub struct MonotonicClock {
    origin: Instant,
}

impl MonotonicClock {
    pub fn new() -> Self {
        Self { origin: Instant::now() }
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for MonotonicClock {
    #[inline]
    fn now(&self) -> Timestamp {
        Timestamp(u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX))
    }
}

/// Time that moves only when told to.
///
/// Atomic so one clock can be shared by reference across a test's parties.
pub struct ManualClock {
    nanos: AtomicU64,
}

impl ManualClock {
    pub fn new(start: Timestamp) -> Self {
        Self { nanos: AtomicU64::new(start.0) }
    }

    pub fn set(&self, t: Timestamp) {
        let previous = self.nanos.swap(t.0, Ordering::Relaxed);
        assert!(t.0 >= previous, "ManualClock moved backward");
    }

    pub fn advance(&self, d: Duration) {
        let nanos = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
        let _ = self
            .nanos
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| Some(n.saturating_add(nanos)));
    }
}

impl Clock for ManualClock {
    #[inline]
    fn now(&self) -> Timestamp {
        Timestamp(self.nanos.load(Ordering::Relaxed))
    }
}

/// A simulation step number.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tick(u32);

impl Tick {
    pub const ZERO: Tick = Tick(0);

    #[inline]
    pub const fn new(n: u32) -> Self {
        Self(n)
    }

    #[inline]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Panics on overflow rather than wrapping: a wrapped tick would break
    /// every comparison built on it.
    #[inline]
    pub fn next(self) -> Tick {
        Tick(self.0.checked_add(1).expect("tick counter overflow"))
    }

    #[inline]
    pub fn checked_add(self, n: u32) -> Option<Tick> {
        self.0.checked_add(n).map(Tick)
    }

    #[inline]
    pub fn checked_since(self, earlier: Tick) -> Option<u32> {
        self.0.checked_sub(earlier.0)
    }

    #[inline]
    pub fn to_wire(self) -> WireSequence {
        WireSequence(self.0 as u16)
    }

    /// Rebuilt from sixteen wire bits against a tick the receiver knows,
    /// using the same nearest-candidate rule as packet sequences.
    #[inline]
    pub fn from_wire(reference: Tick, wire: WireSequence) -> Option<Tick> {
        let full = seq::reconstruct(reference.0 as u64, wire)?;
        u32::try_from(full).ok().map(Tick)
    }
}

/// Maps time onto fixed-length ticks, with a length that can change at
/// runtime without disturbing tick numbering.
#[derive(Clone, Copy, Debug)]
pub struct TickClock {
    /// When `base_tick` started.
    base_time: Timestamp,
    base_tick: Tick,
    /// Nanoseconds per tick.
    period: u64,
}

impl TickClock {
    pub fn new(start: Timestamp, period: Duration) -> Self {
        Self {
            base_time: start,
            base_tick: Tick::ZERO,
            period: period_nanos(period),
        }
    }

    #[inline]
    pub fn period(&self) -> Duration {
        Duration::from_nanos(self.period)
    }

    /// The tick in progress at `now`. Times before the base count as the base
    /// tick.
    #[inline]
    pub fn tick_at(&self, now: Timestamp) -> Tick {
        let elapsed = now.0.saturating_sub(self.base_time.0);
        let ticks = u32::try_from(elapsed / self.period).unwrap_or(u32::MAX);
        Tick(self.base_tick.0.saturating_add(ticks))
    }

    /// When `tick` starts, or `None` for ticks preceding the last period
    /// change.
    #[inline]
    pub fn start_of(&self, tick: Tick) -> Option<Timestamp> {
        let n = tick.0.checked_sub(self.base_tick.0)?;
        let offset = (n as u64).checked_mul(self.period)?;
        self.base_time.0.checked_add(offset).map(Timestamp)
    }

    /// Changes the tick length from the tick in progress at `now`.
    ///
    /// Tick numbers stay continuous: each tick advances the same amount of
    /// simulation time and simply takes longer in real time.
    pub fn set_period(&mut self, now: Timestamp, period: Duration) {
        let tick = self.tick_at(now);
        if let Some(start) = self.start_of(tick) {
            self.base_time = start;
            self.base_tick = tick;
        }
        self.period = period_nanos(period);
    }
}

fn period_nanos(period: Duration) -> u64 {
    let nanos = u64::try_from(period.as_nanos()).expect("tick period too long");
    assert!(nanos > 0, "tick period must be nonzero");
    nanos
}
