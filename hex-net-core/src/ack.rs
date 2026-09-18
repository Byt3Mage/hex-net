//! Delivery tracking: what got through, what did not, and how long the round
//! trip takes.
//!
//! Reports sequence numbers only. Layers above keep their own record of what
//! each packet carried.

use std::time::Duration;

use crate::seq::{Sequence, SequenceBuffer};
use crate::time::Timestamp;

/// A packet this far behind the largest acknowledged one is declared lost.
/// Three is deep enough to tolerate ordinary network reordering.
const REORDER_THRESHOLD: u64 = 3;

/// The loss timer is 9/8 of the RTT estimate.
const TIME_THRESHOLD_NUMERATOR: u32 = 9;
const TIME_THRESHOLD_DENOMINATOR: u32 = 8;

/// Floor for the loss timer, so a fast link does not produce a timer shorter
/// than the tick that drives it.
const MIN_LOSS_DELAY: Duration = Duration::from_millis(2);

/// Assumed RTT before the first measurement.
const INITIAL_RTT: Duration = Duration::from_millis(100);

/// Wire resolution of the acknowledgement delay field.
pub const ACK_DELAY_UNIT: Duration = Duration::from_micros(250);

/// What became of a packet. Emitted once per packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delivered {
    pub sequence: Sequence,
    pub confirmed: bool,
}

impl Delivered {
    #[inline(always)]
    pub fn yes(sequence: Sequence) -> Self {
        Self { sequence, confirmed: true }
    }

    #[inline(always)]
    pub fn no(sequence: Sequence) -> Self {
        Self { sequence, confirmed: false }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum State {
    #[default]
    InFlight,
    /// Confirmed. Final.
    Acked,
    /// Declared lost. Not final: a late acknowledgement can still arrive.
    Lost,
}

#[derive(Clone, Copy, Default)]
struct Sent {
    sent_at: Timestamp,
    size: u16,
    state: State,
}

/// Round-trip estimate following RFC 6298.
#[derive(Clone, Copy, Debug)]
pub struct Rtt {
    latest: Duration,
    /// Smoothed average, used for timers.
    smoothed: Duration,
    /// Mean deviation: jitter. Two paths with the same average but different
    /// jitter need different timer margins.
    variation: Duration,
    /// Lowest ever seen, approximating the path with empty queues.
    min: Duration,
    has_sample: bool,
}

impl Default for Rtt {
    fn default() -> Self {
        Self {
            latest: INITIAL_RTT,
            smoothed: INITIAL_RTT,
            variation: INITIAL_RTT / 2,
            min: INITIAL_RTT,
            has_sample: false,
        }
    }
}

impl Rtt {
    #[inline]
    pub fn smoothed(&self) -> Duration {
        self.smoothed
    }

    #[inline]
    pub fn latest(&self) -> Duration {
        self.latest
    }

    #[inline]
    pub fn variation(&self) -> Duration {
        self.variation
    }

    #[inline]
    pub fn min(&self) -> Duration {
        self.min
    }

    fn update(&mut self, sample: Duration, ack_delay: Duration) {
        self.latest = sample;
        self.min = self.min.min(sample);

        if !self.has_sample {
            self.smoothed = sample;
            self.variation = sample / 2;
            self.min = sample;
            self.has_sample = true;
            return;
        }

        // Remove the peer's holding time, but never below the best round trip
        // seen: a correction that deep means the reported delay is wrong.
        let adjusted = match sample.checked_sub(ack_delay) {
            Some(adjusted) if adjusted >= self.min => adjusted,
            _ => sample,
        };

        let deviation = adjusted.abs_diff(self.smoothed);

        // Deliberately slow: one outlier moves the estimate by an eighth, so a
        // transient spike does not blow up every timer built on it.
        self.variation = ((self.variation * 3) + deviation) / 4;
        self.smoothed = ((self.smoothed * 7) + adjusted) / 8;
    }
}

/// Sender-side delivery tracking for one connection.
///
/// `N` is how many sent packets are remembered, and must cover everything that
/// can be in flight. A record overwritten while still in flight yields no
/// notification at all, which would stall any reliable message riding on it. At
/// thirty packets a second, 128 is over four seconds of history.
pub struct Delivery<const N: usize = 128> {
    sent: SequenceBuffer<Sent, N>,
    /// Highest sequence handed to `on_sent`, bounding the loss scan.
    largest_sent: Sequence,
    /// Oldest sequence not yet resolved, so the scan is proportional to what is
    /// actually outstanding rather than to the buffer size.
    oldest_unresolved: Sequence,
    largest_acked: Sequence,
    /// When an ack-eliciting packet last went out. Packets carrying only
    /// acknowledgements are excluded: the peer does not acknowledge those, so
    /// they prove nothing about the path and yield no round-trip sample.
    last_eliciting: Timestamp,
    rtt: Rtt,
    bytes_in_flight: u32,
    spurious_losses: u64,
}

impl<const N: usize> Delivery<N> {
    /// `now` seeds the liveness timestamp, so a new connection does not look as
    /// though it has been silent since the epoch.
    pub fn new(now: Timestamp) -> Self {
        Self {
            sent: SequenceBuffer::new(),
            largest_sent: Sequence::NONE,
            oldest_unresolved: Sequence::FIRST,
            largest_acked: Sequence::NONE,
            last_eliciting: now,
            rtt: Rtt::default(),
            bytes_in_flight: 0,
            spurious_losses: 0,
        }
    }

    #[inline]
    pub fn rtt(&self) -> &Rtt {
        &self.rtt
    }

    /// When an ack-eliciting packet last went out, which is what keepalive
    /// timing and liveness depend on.
    #[inline]
    pub fn last_eliciting(&self) -> Timestamp {
        self.last_eliciting
    }

    #[inline]
    pub fn bytes_in_flight(&self) -> u32 {
        self.bytes_in_flight
    }

    /// Packets declared lost that were later acknowledged. Compare against
    /// total losses; above about one percent the thresholds need loosening.
    #[inline]
    pub fn spurious_losses(&self) -> u64 {
        self.spurious_losses
    }

    /// Records a packet on its way out.
    ///
    /// `ack_eliciting` is false for packets carrying nothing but
    /// acknowledgements. Those are not tracked: a peer does not acknowledge
    /// pure acknowledgements, so waiting for one would produce a phantom loss.
    pub fn on_sent(&mut self, now: Timestamp, sequence: Sequence, size: usize, ack_eliciting: bool) {
        self.largest_sent = self.largest_sent.max(sequence);
        if !ack_eliciting {
            return;
        }
        // Updated here rather than by the caller, so the timestamp and the
        // decision to track the packet cannot disagree.
        self.last_eliciting = now;
        let size = u16::try_from(size).unwrap_or(u16::MAX);
        self.sent
            .insert(sequence, Sent { sent_at: now, size, state: State::InFlight });
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(size as u32);
    }

    /// Applies an acknowledgement. `ack` is the peer's newest received
    /// sequence, already resolved and validated against what was sent; `bits`
    /// is its history, where bit i means (ack - 1 - i) also arrived.
    ///
    /// `notify` is called once for each newly confirmed packet.
    pub fn on_ack(
        &mut self,
        now: Timestamp,
        ack: Sequence,
        ack_delay: Duration,
        bits: u32,
        mut notify: impl FnMut(Delivered),
    ) {
        let confirmed_now = self.resolve(ack, &mut notify);

        for offset in 0..32u64 {
            if (bits & (1 << offset)) != 0 {
                let sequence = ack.saturating_sub(offset + 1);
                if !sequence.is_none() {
                    self.resolve(sequence, &mut notify);
                }
            }
        }

        // Only the newest acknowledged packet gives a timing sample. One header
        // confirms up to 33 packets, but the others may have arrived long
        // before and would inflate the estimate.
        if ack > self.largest_acked {
            self.largest_acked = ack;
            if confirmed_now && let Some(record) = self.sent.get(ack) {
                self.rtt.update(now.saturating_since(record.sent_at), ack_delay);
            }
        }
        self.advance_oldest();
    }

    /// Marks one packet delivered. Returns true only when this call confirmed a
    /// packet still in flight, which is the only case fit to sample RTT.
    fn resolve(&mut self, sequence: Sequence, notify: &mut impl FnMut(Delivered)) -> bool {
        let spurious = {
            let Some(record) = self.sent.get_mut(sequence) else {
                return false;
            };

            match record.state {
                // Acknowledgement bitfields repeat across many headers; each
                // packet is reported once.
                State::Acked => return false,
                State::Lost => {
                    record.state = State::Acked;
                    true
                }
                State::InFlight => {
                    record.state = State::Acked;
                    let size = record.size;
                    self.bytes_in_flight = self.bytes_in_flight.saturating_sub(size as u32);
                    notify(Delivered::yes(sequence));
                    return true;
                }
            }
        };

        if spurious {
            // Its contents were already resent, and timing from a packet
            // written off as lost is not trustworthy.
            self.spurious_losses += 1;
        }
        false
    }

    /// Declares overdue packets lost.
    ///
    /// Two rules, because each catches what the other misses. The packet
    /// threshold fires when later packets were acknowledged, which is the
    /// common case under flowing traffic. The time threshold covers the tail,
    /// where nothing later was sent to trigger the first.
    pub fn detect_lost(&mut self, now: Timestamp, mut notify: impl FnMut(Delivered)) {
        let delay = self.loss_delay();
        let threshold = self.largest_acked.saturating_sub(REORDER_THRESHOLD);

        let mut sequence = self.oldest_unresolved;
        while sequence <= self.largest_sent {
            let Some(record) = self.sent.get(sequence) else {
                sequence = sequence.next();
                continue;
            };
            if record.state != State::InFlight {
                sequence = sequence.next();
                continue;
            }

            let expired = now.saturating_since(record.sent_at) >= delay;
            if (sequence <= threshold) || expired {
                let size = record.size;
                if let Some(record) = self.sent.get_mut(sequence) {
                    record.state = State::Lost;
                }
                self.bytes_in_flight = self.bytes_in_flight.saturating_sub(size as u32);
                notify(Delivered::no(sequence));
            } else {
                // Send times are non-decreasing, so nothing later has expired
                // either.
                break;
            }
            sequence = sequence.next();
        }
        self.advance_oldest();
    }

    /// When `detect_lost` should next run, if anything is outstanding.
    pub fn next_loss_time(&self) -> Option<Timestamp> {
        let mut sequence = self.oldest_unresolved;
        while sequence <= self.largest_sent {
            if let Some(record) = self.sent.get(sequence)
                && record.state == State::InFlight
            {
                return Some(record.sent_at.saturating_add(self.loss_delay()));
            }
            sequence = sequence.next();
        }
        None
    }

    fn loss_delay(&self) -> Duration {
        let base = self.rtt.smoothed.max(self.rtt.latest);
        let scaled = (base * TIME_THRESHOLD_NUMERATOR) / TIME_THRESHOLD_DENOMINATOR;
        scaled.max(MIN_LOSS_DELAY)
    }

    fn advance_oldest(&mut self) {
        while self.oldest_unresolved <= self.largest_sent {
            match self.sent.get(self.oldest_unresolved) {
                Some(record) if record.state == State::InFlight => break,
                _ => self.oldest_unresolved = self.oldest_unresolved.next(),
            }
        }
    }
}

/// Quantizes an acknowledgement delay for the header.
#[inline]
pub fn encode_ack_delay(delay: Duration) -> u8 {
    let units = delay.as_micros() / ACK_DELAY_UNIT.as_micros();
    u8::try_from(units).unwrap_or(u8::MAX)
}

#[inline]
pub fn decode_ack_delay(encoded: u8) -> Duration {
    ACK_DELAY_UNIT * (encoded as u32)
}
