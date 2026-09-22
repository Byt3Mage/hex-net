//! Time as a plain value, so a simulated clock can drive the protocol exactly.
//!
//! One instant type and one length type, both nanoseconds in a `u64`, which is
//! 584 years of range. The protocol's arithmetic is therefore integer
//! arithmetic: `Duration` normalises through a division by a billion on every
//! operation, and the transport does dozens of them per packet.

use core::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::seq::{self, WireSequence};

/// A length of time, in nanoseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Span(u64);

impl Span {
    pub const ZERO: Span = Span(0);
    pub const MAX: Span = Span(u64::MAX);

    const NANOS_PER_MICRO: u64 = 1_000;
    const NANOS_PER_MILLI: u64 = 1_000_000;
    pub const NANOS_PER_SECOND: u64 = 1_000_000_000;

    #[inline]
    pub const fn from_nanos(nanos: u64) -> Span {
        Span(nanos)
    }

    #[inline]
    pub const fn from_micros(micros: u64) -> Span {
        Span(micros.saturating_mul(Self::NANOS_PER_MICRO))
    }

    #[inline]
    pub const fn from_millis(millis: u64) -> Span {
        Span(millis.saturating_mul(Self::NANOS_PER_MILLI))
    }

    #[inline]
    pub const fn from_secs(secs: u64) -> Span {
        Span(secs.saturating_mul(Self::NANOS_PER_SECOND))
    }

    /// Saturates rather than wrapping, so a length beyond the range becomes the
    /// longest expressible one.
    #[inline]
    pub const fn from_duration(d: Duration) -> Span {
        let nanos = d.as_nanos();
        if nanos > (u64::MAX as u128) { Span::MAX } else { Span(nanos as u64) }
    }

    #[inline]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn as_duration(self) -> Duration {
        Duration::from_nanos(self.0)
    }

    /// For reporting, where a rate or a ratio is wanted rather than a count.
    #[inline]
    pub fn as_secs_f64(self) -> f64 {
        (self.0 as f64) / (Self::NANOS_PER_SECOND as f64)
    }

    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub const fn saturating_add(self, other: Span) -> Span {
        Span(self.0.saturating_add(other.0))
    }

    #[inline]
    pub const fn saturating_sub(self, other: Span) -> Span {
        Span(self.0.saturating_sub(other.0))
    }

    #[inline]
    pub const fn saturating_mul(self, factor: u32) -> Span {
        Span(self.0.saturating_mul(factor as u64))
    }

    /// `(self * NUM) / DEN`, for the fixed ratios the protocol's timers are built
    /// from. The divisor is a constant, so it is checked at compile time.
    #[inline]
    pub const fn scaled<const NUM: u32, const DEN: u32>(self) -> Span {
        const { assert!(DEN > 0, "a scaled span needs a nonzero divisor") };
        Span(self.0.saturating_mul(NUM as u64) / (DEN as u64))
    }

    /// How far this is from `other`, whichever is larger.
    #[inline]
    pub const fn abs_diff(self, other: Span) -> Span {
        Span(self.0.abs_diff(other.0))
    }

    #[inline]
    pub const fn min(self, other: Span) -> Span {
        if self.0 <= other.0 { self } else { other }
    }

    #[inline]
    pub const fn max(self, other: Span) -> Span {
        if self.0 >= other.0 { self } else { other }
    }
}

/// An instant on a monotonic clock, in nanoseconds since that clock's origin.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    pub const ZERO: Timestamp = Timestamp(0);
    pub const MAX: Timestamp = Timestamp(u64::MAX);

    #[inline]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    #[inline]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// How long ago `earlier` was, or zero if it is not earlier: a clock
    /// reading from one pass and a kernel arrival stamp from another can
    /// legitimately arrive out of order.
    #[inline]
    pub const fn since(self, earlier: Timestamp) -> Span {
        Span(self.0.saturating_sub(earlier.0))
    }

    #[inline]
    pub const fn checked_add(self, span: Span) -> Option<Timestamp> {
        match self.0.checked_add(span.0) {
            Some(nanos) => Some(Timestamp(nanos)),
            None => None,
        }
    }

    #[inline]
    pub const fn checked_sub(self, span: Span) -> Option<Timestamp> {
        match self.0.checked_sub(span.0) {
            Some(nanos) => Some(Timestamp(nanos)),
            None => None,
        }
    }

    /// Later than any real deadline, so a saturated sum is never mistaken for
    /// one that has come.
    #[inline]
    pub const fn saturating_add(self, span: Span) -> Timestamp {
        Timestamp(self.0.saturating_add(span.0))
    }

    /// The clock's origin, for an instant that far back, since nothing before
    /// the origin exists.
    #[inline]
    pub const fn saturating_sub(self, span: Span) -> Timestamp {
        Timestamp(self.0.saturating_sub(span.0))
    }
}

/// Source of the current time for drivers. The protocol itself always takes
/// the instant it runs at as an argument, so a simulation drives it exactly.
pub trait Clock {
    fn now(&self) -> Timestamp;
}

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

/// A clock moved by hand, for tests.
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

    pub fn advance(&self, span: Span) {
        let _ = self
            .nanos
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| Some(n.saturating_add(span.0)));
    }
}

impl Clock for ManualClock {
    #[inline]
    fn now(&self) -> Timestamp {
        Timestamp(self.nanos.load(Ordering::Relaxed))
    }
}

/// A simulation step, counted by the application rather than the transport.
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

    #[inline]
    pub fn from_wire(reference: Tick, wire: WireSequence) -> Option<Tick> {
        let full = seq::reconstruct(reference.0 as u64, wire)?;
        u32::try_from(full).ok().map(Tick)
    }
}

/// A tick period that cannot be zero, so no clock built from one can divide by
/// zero or stand still.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TickPeriod(Span);

impl TickPeriod {
    /// `None` for a period of no time, which would make every instant every
    /// tick.
    #[inline]
    pub const fn new(period: Span) -> Option<TickPeriod> {
        if period.is_zero() { None } else { Some(TickPeriod(period)) }
    }

    /// The period for a rate in ticks per second.
    #[inline]
    pub const fn from_hz(hz: u32) -> Option<TickPeriod> {
        if hz == 0 {
            return None;
        }
        TickPeriod::new(Span::from_nanos(Span::NANOS_PER_SECOND / (hz as u64)))
    }

    #[inline]
    pub const fn get(self) -> Span {
        self.0
    }
}

/// Maps instants to ticks and back at a fixed rate.
#[derive(Clone, Copy, Debug)]
pub struct TickClock {
    base_time: Timestamp,
    base_tick: Tick,
    period: TickPeriod,
}

impl TickClock {
    pub const fn new(start: Timestamp, period: TickPeriod) -> Self {
        Self { base_time: start, base_tick: Tick::ZERO, period }
    }

    #[inline]
    pub const fn period(&self) -> Span {
        self.period.get()
    }

    #[inline]
    pub fn tick_at(&self, now: Timestamp) -> Tick {
        let elapsed = now.since(self.base_time).as_nanos();
        let ticks = u32::try_from(elapsed / self.period.get().as_nanos()).unwrap_or(u32::MAX);
        Tick(self.base_tick.0.saturating_add(ticks))
    }

    #[inline]
    pub fn start_of(&self, tick: Tick) -> Option<Timestamp> {
        let n = tick.0.checked_sub(self.base_tick.0)?;
        let offset = u64::from(n).checked_mul(self.period.get().as_nanos())?;
        self.base_time.0.checked_add(offset).map(Timestamp)
    }

    /// Rebases on the tick in progress, so changing the rate neither skips a
    /// tick nor repeats one.
    pub fn set_period(&mut self, now: Timestamp, period: TickPeriod) {
        let tick = self.tick_at(now);
        if let Some(start) = self.start_of(tick) {
            self.base_time = start;
            self.base_tick = tick;
        }
        self.period = period;
    }
}
