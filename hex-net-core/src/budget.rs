//! Per-connection send allowance: a token bucket, and the controller that
//! moves its rate.
//!
//! The bucket is counted in bytes with 32 fractional bits, and its rate is
//! kept as bytes earned per nanosecond in the same fixed point. A refill is
//! then a multiply and a compare, where rate-times-elapsed-over-a-billion
//! would be a 128-bit division on every packet.

use crate::{
    ack::Rtt,
    channel::MESSAGE_FRAME_OVERHEAD,
    config::{BudgetConfig, MIN_RATE},
    time::{Span, Timestamp},
    wire::{Header, TAG_LEN},
};

/// Fractional bits in every byte count the bucket holds.
const FRACTION_BITS: u32 = 32;

/// The bucket holds at most this fraction of a second's worth of rate, so a
/// connection that has been quiet can burst but not unboundedly.
const BURST_FRACTION: u32 = 4;

const LOSS_THRESHOLD_NUMERATOR: u32 = 1;
const LOSS_THRESHOLD_DENOMINATOR: u32 = 50;

const QUEUE_THRESHOLD_DIVISOR: u32 = 4;
const MIN_QUEUE_DELAY: Span = Span::from_millis(10);

const BACKOFF_NUMERATOR: u32 = 3;
const BACKOFF_DENOMINATOR: u32 = 4;

const RECOVERY_FRACTION: u32 = 16;

/// Floor on how often the controller reads its window, so a short round trip
/// does not make it react to a handful of packets.
const MIN_ASSESS_INTERVAL: Span = Span::from_millis(100);

/// Tracked packets a window needs before its loss rate means anything.
const MIN_LOSS_SAMPLES: u32 = 20;

/// Bytes a second, as bytes per nanosecond in fixed point.
///
/// Nonzero for every rate the configuration admits, which is what lets
/// `ready_for` divide by it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Refill(u64);

impl Refill {
    #[inline]
    const fn of(rate: u32) -> Refill {
        // A u32 shifted left by 32 always fits a u64, so the only rounding is
        // the division, which loses under a nanobyte a second.
        Refill(((rate as u64) << FRACTION_BITS) / Span::NANOS_PER_SECOND)
    }

    /// What `elapsed` earns, saturating rather than wrapping: an idle
    /// connection's elapsed time is unbounded and the bucket is capped anyway.
    #[inline]
    const fn earned(self, elapsed: Span) -> u64 {
        elapsed.as_nanos().saturating_mul(self.0)
    }

    /// How long `deficit` fixed-point bytes take to earn, rounded up, so the
    /// deadline it produces is never early.
    #[inline]
    const fn time_for(self, deficit: u64) -> Span {
        Span::from_nanos(deficit.div_ceil(self.0))
    }
}

/// `time_for` divides by the refill, so the slowest rate the configuration
/// admits must still earn something every nanosecond in fixed point.
const _: () = assert!(
    Refill::of(MIN_RATE).0 > 0,
    "the slowest admissible rate earns no tokens"
);

/// Bytes in fixed point, for the bucket's level and its capacity.
#[inline]
const fn tokens(bytes: u64) -> u64 {
    bytes << FRACTION_BITS
}

#[inline]
const fn whole_bytes(tokens: u64) -> u32 {
    // Every level the bucket holds comes from a u32 byte count, so the whole
    // part is one too.
    (tokens >> FRACTION_BITS) as u32
}

pub struct Budget {
    config: BudgetConfig,

    rate: u32,
    refill: Refill,
    tokens: u64,
    capacity: u64,
    last_refill: Timestamp,

    last_assessed: Timestamp,
    window_sent: u32,
    window_lost: u32,
}

impl Budget {
    pub fn new(now: Timestamp, config: BudgetConfig) -> Self {
        let capacity = capacity_for(config.rate(), config);
        Self {
            config,
            rate: config.rate(),
            refill: Refill::of(config.rate()),
            tokens: capacity,
            capacity,
            last_refill: now,
            last_assessed: now,
            window_sent: 0,
            window_lost: 0,
        }
    }

    /// The current allowance in bytes a second. Below the configured rate means
    /// the controller has backed off.
    #[inline]
    pub fn rate(&self) -> u32 {
        self.rate
    }

    #[inline]
    pub fn is_constrained(&self) -> bool {
        self.rate < self.config.rate()
    }

    /// Bytes this connection may spend on the next datagram, header and tag
    /// included.
    pub fn available(&mut self, now: Timestamp) -> u32 {
        self.advance(now);
        whole_bytes(self.tokens).min(self.config.max_packet() as u32)
    }

    fn advance(&mut self, now: Timestamp) {
        let elapsed = now.since(self.last_refill);
        if elapsed.is_zero() {
            return;
        }
        self.last_refill = now;
        self.tokens = self
            .tokens
            .saturating_add(self.refill.earned(elapsed))
            .min(self.capacity);
    }

    /// When the allowance will cover a datagram carrying `payload_len` bytes of
    /// message, so a driver can wake to send rather than waiting out a timer.
    ///
    /// Measured from the last refill, which is when the level it compares
    /// against was current.
    pub fn ready_for(&self, payload_len: usize) -> Timestamp {
        let datagram = Header::MAX_LEN + TAG_LEN + MESSAGE_FRAME_OVERHEAD + payload_len;
        // Never above what `available` can report, and `MIN_PACKET` keeps every
        // message within that.
        let needed = u64::from(
            u32::try_from(datagram)
                .unwrap_or(u32::MAX)
                .min(self.config.max_packet() as u32),
        );

        let deficit = tokens(needed).saturating_sub(self.tokens);
        if deficit == 0 {
            return self.last_refill;
        }
        self.last_refill.saturating_add(self.refill.time_for(deficit))
    }

    /// Spends a datagram's bytes. Ack-eliciting packets are the ones the
    /// controller counts, since only they can be reported lost.
    pub fn on_sent(&mut self, len: u16, eliciting: bool) {
        self.tokens = self.tokens.saturating_sub(tokens(u64::from(len)));
        if eliciting {
            self.window_sent = self.window_sent.saturating_add(1);
        }
    }

    pub fn on_lost(&mut self) {
        self.window_lost = self.window_lost.saturating_add(1);
    }

    /// A packet declared lost turned out to have arrived, so the evidence that
    /// prompted a backoff is withdrawn.
    pub fn on_spurious(&mut self) {
        self.window_lost = self.window_lost.saturating_sub(1);
    }

    /// A new path has none of the old one's history.
    pub fn on_path_change(&mut self, now: Timestamp) {
        self.set_rate(self.config.rate());
        self.last_assessed = now;
        self.window_sent = 0;
        self.window_lost = 0;
    }

    /// Moves the rate once a round trip, on enough evidence to read.
    pub fn assess(&mut self, now: Timestamp, rtt: &Rtt) {
        if now.since(self.last_assessed) < assess_interval(rtt) {
            return;
        }
        self.last_assessed = now;

        if self.window_sent < MIN_LOSS_SAMPLES {
            // Too few packets to read anything from. The window is kept rather
            // than cleared, so evidence accumulates across quiet passes.
            return;
        }

        // lost / sent > NUMERATOR / DENOMINATOR, cross-multiplied in u64 so
        // neither side can overflow.
        let lossy = (u64::from(self.window_lost) * u64::from(LOSS_THRESHOLD_DENOMINATOR))
            > (u64::from(self.window_sent) * u64::from(LOSS_THRESHOLD_NUMERATOR));
        self.window_sent = 0;
        self.window_lost = 0;

        if lossy || is_queueing(rtt) {
            self.decrease();
        } else {
            self.increase();
        }
    }

    fn decrease(&mut self) {
        let reduced = ((self.rate / BACKOFF_DENOMINATOR) * BACKOFF_NUMERATOR).max(MIN_RATE);
        self.set_rate(reduced);
    }

    fn increase(&mut self) {
        let step = (self.config.rate() / RECOVERY_FRACTION).max(1);
        let raised = self.rate.saturating_add(step).min(self.config.rate());
        self.set_rate(raised);
    }

    /// The rate, what it earns per nanosecond, and the burst it allows are one
    /// decision, so they are set together and cannot disagree.
    fn set_rate(&mut self, rate: u32) {
        self.rate = rate;
        self.refill = Refill::of(rate);
        self.capacity = capacity_for(rate, self.config);
        self.tokens = self.tokens.min(self.capacity);
    }
}

/// A quarter second of rate, but never less than one maximum-size packet, or
/// the bucket could never fill enough to send one.
fn capacity_for(rate: u32, config: BudgetConfig) -> u64 {
    tokens(u64::from((rate / BURST_FRACTION).max(config.max_packet() as u32)))
}

fn assess_interval(rtt: &Rtt) -> Span {
    rtt.smoothed().max(MIN_ASSESS_INTERVAL)
}

/// Queueing shows as a smoothed round trip standing above the path's recent
/// best by more than jitter explains.
fn is_queueing(rtt: &Rtt) -> bool {
    let Some(min) = rtt.min() else { return false };
    let margin = Span::from_nanos(min.as_nanos() / u64::from(QUEUE_THRESHOLD_DIVISOR)).max(MIN_QUEUE_DELAY);
    rtt.smoothed() > min.saturating_add(margin)
}
