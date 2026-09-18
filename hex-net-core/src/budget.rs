//! Per-connection send allowance.

use std::time::Duration;

use crate::ack::Rtt;
use crate::time::Timestamp;

/// Lowest rate the controller will fall to. Below this a connection cannot
/// carry acknowledgements and keepalives reliably, and dropping it is more
/// honest than pretending it works.
pub const MIN_RATE: u32 = 8_000;

/// How much may accumulate while idle, as a multiple of the per-second rate.
/// A quarter second lets a connection that has been quiet send a burst
/// without letting a long silence build an unbounded one.
const BURST_FRACTION: u32 = 4;

/// Loss above this fraction, measured over a window, starts backing off.
/// Below it, occasional loss is normal and not worth reacting to.
const LOSS_THRESHOLD: f32 = 0.02;

/// RTT this far above the connection's minimum indicates a filling queue.
const DELAY_THRESHOLD_NUMERATOR: u32 = 5;
const DELAY_THRESHOLD_DENOMINATOR: u32 = 4;

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

/// Packets in the loss window before its rate is trusted. Two losses out of
/// three packets is not a two-thirds loss rate.
const MIN_LOSS_SAMPLES: u32 = 20;

#[derive(Clone, Copy, Debug)]
pub struct BudgetConfig {
    /// Bytes per second this connection is allowed, counted over the whole
    /// datagram including headers and the authentication tag.
    pub rate: u32,
    /// Largest single packet, which caps how much of the bucket one send can
    /// consume regardless of what has accumulated.
    pub max_packet: u32,
}

impl BudgetConfig {
    /// 64 kbps, the per-player allowance the interest budget is sized around.
    pub const DEFAULT: BudgetConfig = BudgetConfig { rate: 8_000, max_packet: 1200 };
}

/// Token bucket with a rate the controller adjusts.
///
/// Counts whole datagrams, not payloads: a connection sending many small
/// packets consumes real capacity in headers, and the budget should see that.
pub struct Budget {
    config: BudgetConfig,
    /// Current allowance in bytes per second, between MIN_RATE and the
    /// configured rate.
    rate: u32,
    /// Bytes available to send now.
    tokens: u32,
    /// Cap on `tokens`, so idleness cannot accumulate an unbounded burst.
    capacity: u32,
    last_refill: Timestamp,

    last_assessed: Timestamp,
    /// Packets sent and lost since the last assessment.
    window_sent: u32,
    window_lost: u32,
}

impl Budget {
    pub fn new(now: Timestamp, config: BudgetConfig) -> Self {
        let capacity = (config.rate / BURST_FRACTION).max(config.max_packet);
        Self {
            config,
            rate: config.rate,
            tokens: capacity,
            capacity,
            last_refill: now,
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
    #[inline]
    pub fn is_constrained(&self) -> bool {
        self.rate < self.config.rate
    }

    /// Bytes available for the next packet, after refilling for elapsed time.
    ///
    /// Zero means nothing may be sent this pass. The caller must still send
    /// control-only packets when one is owed: acknowledgements and keepalives
    /// are what let the connection recover, so withholding them would deepen
    /// the very problem the budget is responding to.
    pub fn available(&mut self, now: Timestamp) -> u32 {
        self.refill(now);
        self.tokens.min(self.config.max_packet)
    }

    fn refill(&mut self, now: Timestamp) {
        let elapsed = now.saturating_since(self.last_refill);
        if elapsed.is_zero() {
            return;
        }

        // Integer arithmetic throughout: nanoseconds times a byte rate stays
        // inside u128, and the result is bytes.
        let gained = ((elapsed.as_nanos() * (self.rate as u128)) / 1_000_000_000) as u64;
        if gained == 0 {
            // Not yet a whole byte's worth. Leaving last_refill alone lets the
            // remainder accumulate instead of being rounded away every pass.
            return;
        }

        self.tokens = self
            .tokens
            .saturating_add(u32::try_from(gained).unwrap_or(u32::MAX))
            .min(self.capacity);
        self.last_refill = now;
    }

    /// Records a packet that was sent.
    pub fn on_sent(&mut self, len: usize) {
        let len = u32::try_from(len).unwrap_or(u32::MAX);
        self.tokens = self.tokens.saturating_sub(len);
        self.window_sent = self.window_sent.saturating_add(1);
    }

    /// Records a packet declared lost.
    pub fn on_lost(&mut self) {
        self.window_lost = self.window_lost.saturating_add(1);
    }

    /// Reassesses the rate against observed loss and delay.
    ///
    /// Called once per pass; it does its own work only when enough time and
    /// enough packets have accumulated for the evidence to mean anything.
    pub fn assess(&mut self, now: Timestamp, rtt: &Rtt) {
        if now.saturating_since(self.last_assessed) < self.assess_interval(rtt) {
            return;
        }
        self.last_assessed = now;

        if self.window_sent < MIN_LOSS_SAMPLES {
            // Too few packets to read anything from. The window is kept rather
            // than cleared, so evidence accumulates across quiet passes.
            return;
        }

        let loss = (self.window_lost as f32) / (self.window_sent as f32);
        self.window_sent = 0;
        self.window_lost = 0;

        // A round trip well above the connection's own minimum means packets
        // are sitting in a queue somewhere on the path.
        let queueing = rtt.smoothed() > ((rtt.min() * DELAY_THRESHOLD_NUMERATOR) / DELAY_THRESHOLD_DENOMINATOR);

        if (loss > LOSS_THRESHOLD) || queueing {
            self.decrease();
        } else {
            self.increase();
        }
    }

    /// Reassessment interval: a round trip, floored, since a decision made
    /// faster than that would act on effects from the previous decision.
    fn assess_interval(&self, rtt: &Rtt) -> Duration {
        rtt.smoothed().max(MIN_ASSESS_INTERVAL)
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
        self.capacity = (self.rate / BURST_FRACTION).max(self.config.max_packet);
        self.tokens = self.tokens.min(self.capacity);
    }
}
