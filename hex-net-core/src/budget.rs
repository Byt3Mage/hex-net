//! Per-connection send allowance.

use std::time::Duration;

use crate::{
    ack::Rtt,
    channel::{MAX_MESSAGE, MESSAGE_FRAME_OVERHEAD},
    time::Timestamp,
    wire::{Header, MAX_DATAGRAM, TAG_LEN},
};

/// Lowest rate the controller will fall to, in bytes per second. Roughly a
/// header, a tag, and a few control frames thirty times a second, so
/// acknowledgements and keepalives still fit at the floor.
pub const MIN_RATE: u32 = 2000;

/// Smallest allowance that can still carry the largest message (header,
/// tag, one full message frame). Below it, a maximum-size message would
/// never fit any datagram's allowance and would wait forever.
pub const MIN_PACKET: usize = Header::MAX_LEN + TAG_LEN + MESSAGE_FRAME_OVERHEAD + MAX_MESSAGE;

/// How much may accumulate while idle, as a divisor of the per-second rate.
/// A quarter second lets a connection that has been quiet send a burst
/// without letting a long silence build an unbounded one.
const BURST_FRACTION: u32 = 4;

/// Loss above this fraction, measured over a window, starts backing off.
/// Below it, occasional loss is normal and not worth reacting to.
const LOSS_THRESHOLD_NUMERATOR: u32 = 1;
const LOSS_THRESHOLD_DENOMINATOR: u32 = 50;

/// Queueing is inferred when the smoothed RTT exceeds the path's minimum by
/// more than a quarter of that minimum, and by more than `MIN_QUEUE_DELAY`.
/// The relative part scales with long paths; the absolute part keeps ordinary
/// access-network jitter on a short path from reading as congestion.
const QUEUE_THRESHOLD_DIVISOR: u32 = 4;
const MIN_QUEUE_DELAY: Duration = Duration::from_millis(10);

/// Multiplicative decrease applied when conditions are bad.
const BACKOFF_NUMERATOR: u32 = 3;
const BACKOFF_DENOMINATOR: u32 = 4;

/// Additive increase applied when conditions are good, as a fraction of the
/// configured rate. Recovery is slower than backoff, which keeps the
/// controller from oscillating across the threshold.
const RECOVERY_FRACTION: u32 = 16;

/// How often the controller reassesses. Roughly a round trip, so each
/// decision is made on evidence produced since the last one.
const MIN_ASSESS_INTERVAL: Duration = Duration::from_millis(100);

/// Tracked packets in the loss window before its rate is trusted. Two losses
/// out of three packets is not a two-thirds loss rate.
const MIN_LOSS_SAMPLES: u32 = 20;

const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// A validated allowance: at least `MIN_RATE`, and a packet cap between
/// `MIN_PACKET` and `MAX_DATAGRAM`.
#[derive(Clone, Copy, Debug)]
pub struct BudgetConfig {
    rate: u32,
    max_packet: u16,
}

impl BudgetConfig {
    /// 64 kbps, the per-player allowance the interest budget is sized around.
    pub const DEFAULT: BudgetConfig = match BudgetConfig::new(8000, MAX_DATAGRAM) {
        Some(config) => config,
        None => panic!("the default budget violates its own bounds"),
    };

    /// `rate` is bytes per second, counted over the whole datagram including
    /// headers and the authentication tag. `max_packet` caps how much of the
    /// bucket one send can consume regardless of what has accumulated.
    pub const fn new(rate: u32, max_packet: usize) -> Option<BudgetConfig> {
        const { assert!(MIN_PACKET <= MAX_DATAGRAM) };
        const { assert!(MAX_DATAGRAM <= (u16::MAX as usize)) };

        if (rate < MIN_RATE) || (max_packet < MIN_PACKET) || (max_packet > MAX_DATAGRAM) {
            return None;
        }
        Some(BudgetConfig { rate, max_packet: max_packet as u16 })
    }

    #[inline]
    pub const fn rate(&self) -> u32 {
        self.rate
    }

    #[inline]
    pub const fn max_packet(&self) -> usize {
        self.max_packet as usize
    }
}

/// Token bucket with a rate the controller adjusts.
///
/// Counts whole datagrams rather than payloads. A connection sending many small
/// packets consumes a large capacity in headers, and the budget should see that.
pub struct Budget {
    config: BudgetConfig,
    /// Current allowance in bytes per second, between `MIN_RATE` and the
    /// configured rate.
    rate: u32,
    /// Bytes available to send now.
    tokens: u32,
    /// Cap on `tokens`, so idleness cannot accumulate an unbounded burst.
    capacity: u32,
    last_refill: Timestamp,
    /// Refill earned but not yet a whole byte, in billionths of a byte, so
    /// always below one billion. Carried forward so the delivered rate does
    /// not depend on how often the budget is consulted.
    residue: u64,

    last_assessed: Timestamp,
    /// Ack-eliciting packets sent and lost since the last assessment. Packets
    /// carrying only acknowledgements are excluded from both. They are never
    /// tracked, so they can never be counted lost.
    window_sent: u32,
    window_lost: u32,
}

impl Budget {
    pub fn new(now: Timestamp, config: BudgetConfig) -> Self {
        let capacity = capacity_for(config.rate, config);
        Self {
            config,
            rate: config.rate,
            tokens: capacity,
            capacity,
            last_refill: now,
            residue: 0,
            last_assessed: now,
            window_sent: 0,
            window_lost: 0,
        }
    }

    /// The current allowance in bytes per second.
    #[inline]
    pub fn rate(&self) -> u32 {
        self.rate
    }

    /// Whether the controller has reduced the rate below what was configured.
    /// The application's cue to produce less, since the transport can only
    /// queue what it is given.
    #[inline]
    pub fn is_constrained(&self) -> bool {
        self.rate < self.config.rate
    }

    /// Bytes available for the next packet, after refilling for elapsed time.
    ///
    /// Zero means nothing may be sent this pass. The caller must still send
    /// control-only packets when one is owed. Acknowledgements and keepalives
    /// are what let the connection recover, so withholding them would worsen
    /// the problem the budget is responding to.
    pub fn available(&mut self, now: Timestamp) -> u32 {
        self.refill(now);
        self.tokens.min(u32::from(self.config.max_packet))
    }

    fn refill(&mut self, now: Timestamp) {
        let elapsed = now.saturating_since(self.last_refill);
        if elapsed.is_zero() {
            return;
        }
        self.last_refill = now;

        let earned = (elapsed.as_nanos() * u128::from(self.rate)) + u128::from(self.residue);
        let gained = earned / NANOS_PER_SECOND;
        self.residue = (earned % NANOS_PER_SECOND) as u64;

        let gained = u32::try_from(gained).unwrap_or(u32::MAX);
        self.tokens = self.tokens.saturating_add(gained);
        if self.tokens >= self.capacity {
            // A full bucket earns nothing further, fractional bytes included.
            self.tokens = self.capacity;
            self.residue = 0;
        }
    }

    pub fn ready_for(&self, payload_len: usize) -> Timestamp {
        let datagram = Header::MAX_LEN + TAG_LEN + MESSAGE_FRAME_OVERHEAD + payload_len;
        // Never above what `available` can report.
        // `MIN_PACKET` keeps every message within it.
        let needed = u32::try_from(datagram)
            .unwrap_or(u32::MAX)
            .min(u32::from(self.config.max_packet));

        let deficit = needed.saturating_sub(self.tokens);

        if deficit == 0 {
            return self.last_refill;
        }

        // The residue is below one byte, and the deficit is at least one,
        // so this cannot underflow.
        let owed = (u128::from(deficit) * NANOS_PER_SECOND) - u128::from(self.residue);
        let nanos = owed.div_ceil(u128::from(self.rate));
        let duration = Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX));
        self.last_refill.saturating_add(duration)
    }

    /// Records a packet that was sent. `eliciting` is false for packets
    /// carrying only acknowledgements.
    pub fn on_sent(&mut self, len: u16, eliciting: bool) {
        self.tokens = self.tokens.saturating_sub(u32::from(len));
        if eliciting {
            self.window_sent = self.window_sent.saturating_add(1);
        }
    }

    /// Records a packet declared lost.
    pub fn on_lost(&mut self) {
        self.window_lost = self.window_lost.saturating_add(1);
    }

    /// Records a packet declared lost that was acknowledged after all. Undoes
    /// the loss if it is still in the current window; one already assessed has
    /// had its effect.
    pub fn on_spurious(&mut self) {
        self.window_lost = self.window_lost.saturating_sub(1);
    }

    /// Starts over on a new path. The old path's rate says nothing about the
    /// new one, and its loss window describes a route no longer in use.
    pub fn on_path_change(&mut self, now: Timestamp) {
        self.rate = self.config.rate;
        self.update_capacity();
        self.last_assessed = now;
        self.window_sent = 0;
        self.window_lost = 0;
    }

    /// Reassesses the rate against observed loss and delay.
    ///
    /// Called once per pass; it does its own work only when enough time and
    /// enough packets have accumulated for the evidence to mean anything.
    pub fn assess(&mut self, now: Timestamp, rtt: &Rtt) {
        if now.saturating_since(self.last_assessed) < assess_interval(rtt) {
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
        self.rate = ((self.rate / BACKOFF_DENOMINATOR) * BACKOFF_NUMERATOR).max(MIN_RATE);
        self.update_capacity();
    }

    fn increase(&mut self) {
        let step = (self.config.rate / RECOVERY_FRACTION).max(1);
        self.rate = self.rate.saturating_add(step).min(self.config.rate);
        self.update_capacity();
    }

    fn update_capacity(&mut self) {
        self.capacity = capacity_for(self.rate, self.config);
        self.tokens = self.tokens.min(self.capacity);
    }
}

/// Never below one full packet, or a low rate would make a full packet
/// unsendable no matter how long the connection waited.
fn capacity_for(rate: u32, config: BudgetConfig) -> u32 {
    (rate / BURST_FRACTION).max(u32::from(config.max_packet))
}

/// Reassessment interval: a round trip, floored, since a decision made faster
/// than that would act on effects from the previous decision.
fn assess_interval(rtt: &Rtt) -> Duration {
    rtt.smoothed().max(MIN_ASSESS_INTERVAL)
}

/// A round trip well above the path's recent minimum means packets are sitting
/// in a queue somewhere on it. No minimum yet means no baseline, so no verdict.
fn is_queueing(rtt: &Rtt) -> bool {
    let Some(min) = rtt.min() else { return false };
    let margin = (min / QUEUE_THRESHOLD_DIVISOR).max(MIN_QUEUE_DELAY);
    rtt.smoothed() > (min + margin)
}
