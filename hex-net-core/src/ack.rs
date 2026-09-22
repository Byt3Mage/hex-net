//! Delivery tracking: what got through, what did not, and how long the round
//! trip takes.
//!
//! The ledger stores, for each packet in flight, whatever the layers above
//! need back when its fate is known, and hands it back exactly once. There is
//! no second table keyed by sequence to fall out of step with this one.

use crate::{
    config::{ACK_DELAY_UNIT, MaxAckDelay},
    seq::{Sequence, SequenceBuffer},
    time::{Span, Timestamp},
};

/// A packet this far behind the largest acknowledged one is declared lost.
/// Three is deep enough to tolerate ordinary network reordering.
const REORDER_THRESHOLD: u64 = 3;

/// A packet older than the largest acknowledged one is declared lost once it
/// has been outstanding for 9/8 of the RTT estimate.
const TIME_THRESHOLD_NUMERATOR: u32 = 9;
const TIME_THRESHOLD_DENOMINATOR: u32 = 8;

/// Weight of the history in the smoothed round trip and its deviation: one
/// sample moves the average by an eighth and the deviation by a quarter, so a
/// transient spike does not blow up every timer built on them.
const SMOOTHING_WEIGHT: u64 = 7;
const SMOOTHING_DIVISOR: u64 = 8;
const DEVIATION_WEIGHT: u64 = 3;
const DEVIATION_DIVISOR: u64 = 4;

/// Floor for every timer, so a fast link does not produce one shorter than
/// the tick that drives it.
const TIMER_GRANULARITY: Span = Span::from_millis(2);
/// Assumed RTT before the first measurement.
const INITIAL_RTT: Span = Span::from_millis(100);

/// Consecutive probe timeouts without an acknowledgement, which the probe
/// timeout doubles for.
///
/// Bounded at construction, so the doubling it drives is always a shift the
/// machine can make and the timer it produces stays finite. Past the bound the
/// idle timeout decides the connection's fate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ProbeBackoff(u32);

impl ProbeBackoff {
    const MAX: u32 = 6;

    #[inline]
    const fn factor(self) -> u32 {
        1u32 << self.0
    }

    #[inline]
    const fn doubled(self) -> ProbeBackoff {
        let next = self.0 + 1;
        ProbeBackoff(if next > Self::MAX { Self::MAX } else { next })
    }
}

const _: () = assert!(
    ProbeBackoff::MAX < u32::BITS,
    "the probe backoff must be a shift in range"
);

/// Packets sent per probe timeout. Two, because the case that produces a
/// probe is usually a burst of loss, and a single probe is likely to be lost
/// with it. A second costs one small packet and halves the chance of waiting
/// out another, doubled timeout.
const PROBE_PACKETS: u8 = 2;

/// The minimum RTT is taken over a window of this length, so a route change
/// or one unusually fast sample stops defining "no queueing" once it ages out.
const MIN_RTT_WINDOW: Span = Span::from_secs(10);
/// Half the window, which is how often the minimum rolls over.
const MIN_RTT_HALF_WINDOW: Span = Span::from_nanos(MIN_RTT_WINDOW.as_nanos() / 2);

/// What became of a packet. Each tracked packet produces exactly one
/// `Acked` or `Lost`, carrying the record stored when it was sent. A packet
/// declared lost and acknowledged afterwards additionally produces
/// `Spurious`, which carries nothing because the record was already returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolved<P> {
    Acked(P),
    Lost(P),
    Spurious,
}

/// What an outgoing packet asks of the ledger.
pub enum Outgoing<P> {
    /// Carries nothing but acknowledgements. The peer does not acknowledge
    /// those, so tracking one would produce a phantom loss.
    AckOnly,
    /// Carries frames the peer acknowledges, and the record to return when
    /// its fate is known.
    Eliciting(P),
}

/// Probes are owed: the tail of the flight has gone unacknowledged for a full
/// probe timeout. Send this many ack-eliciting packets, carrying
/// unacknowledged data where there is any to carry.
#[must_use]
pub struct Probe {
    pub packets: u8,
}

enum State<P> {
    /// The record is held here until the packet resolves, then moved out.
    InFlight(P),
    /// Confirmed. Final.
    Acked,
    /// Declared lost. Not final: a late acknowledgement can still arrive.
    Lost,
}

struct Sent<P> {
    sent_at: Timestamp,
    state: State<P>,
}

/// Minimum over a sliding window, kept as two half-windows so it needs no
/// sample history: the reported minimum covers between one half and the whole
/// window.
#[derive(Clone, Copy, Debug)]
struct WindowedMin {
    current: Span,
    previous: Span,
    epoch: Timestamp,
}

impl WindowedMin {
    fn new(now: Timestamp, sample: Span) -> Self {
        Self { current: sample, previous: sample, epoch: now }
    }

    fn update(&mut self, now: Timestamp, sample: Span) {
        if now.since(self.epoch) >= MIN_RTT_HALF_WINDOW {
            self.previous = self.current;
            self.current = sample;
            self.epoch = now;
        } else {
            self.current = self.current.min(sample);
        }
    }

    fn get(&self) -> Span {
        self.current.min(self.previous)
    }
}

#[derive(Clone, Copy, Debug)]
struct Estimate {
    latest: Span,
    /// Smoothed average, used for timers.
    smoothed: Span,
    /// Mean deviation: jitter. Two paths with the same average but different
    /// jitter need different timer margins, which the probe timeout applies.
    variation: Span,
    /// Lowest seen recently, approximating the path with empty queues.
    min: WindowedMin,
}

/// Round-trip estimate following RFC 6298, with the acknowledgement-delay
/// handling of RFC 9002.
#[derive(Clone, Copy, Debug, Default)]
pub struct Rtt {
    /// `None` until the first sample; the accessors report the initial
    /// assumption in the meantime.
    estimate: Option<Estimate>,
}

impl Rtt {
    #[inline]
    pub fn smoothed(&self) -> Span {
        self.estimate.map_or(INITIAL_RTT, |e| e.smoothed)
    }

    #[inline]
    pub fn latest(&self) -> Span {
        self.estimate.map_or(INITIAL_RTT, |e| e.latest)
    }

    #[inline]
    pub fn variation(&self) -> Span {
        self.estimate.map_or(INITIAL_RTT.scaled::<1, 2>(), |e| e.variation)
    }

    /// The windowed minimum, or `None` before any measurement: there is no
    /// baseline to compare queueing against until the path has been sampled.
    #[inline]
    pub fn min(&self) -> Option<Span> {
        self.estimate.map(|e| e.min.get())
    }

    /// Forgets the path. Used when the peer's address changes, since every
    /// figure here described the old route.
    pub fn reset(&mut self) {
        self.estimate = None;
    }

    fn update(&mut self, now: Timestamp, sample: Span, ack_delay: Span) {
        let Some(estimate) = &mut self.estimate else {
            // The first sample stands alone: there is no baseline yet to judge
            // the reported delay against, so it is not subtracted.
            self.estimate = Some(Estimate {
                latest: sample,
                smoothed: sample,
                variation: sample.scaled::<1, 2>(),
                min: WindowedMin::new(now, sample),
            });
            return;
        };

        estimate.latest = sample;
        estimate.min.update(now, sample);

        // Remove the peer's holding time, but never below the best round trip
        // seen: a correction that deep means the reported delay is wrong.
        let min = estimate.min.get();
        let corrected = sample.saturating_sub(ack_delay);
        let adjusted = if corrected >= min { corrected } else { sample };
        let deviation = adjusted.abs_diff(estimate.smoothed);

        estimate.variation = Span::from_nanos(
            ((estimate.variation.as_nanos() * DEVIATION_WEIGHT) + deviation.as_nanos()) / DEVIATION_DIVISOR,
        );
        estimate.smoothed = Span::from_nanos(
            ((estimate.smoothed.as_nanos() * SMOOTHING_WEIGHT) + adjusted.as_nanos()) / SMOOTHING_DIVISOR,
        );
    }
}

/// Sender-side delivery tracking for one connection.
///
/// `P` is what the layers above stored with each packet; it comes back in the
/// packet's `Resolved` event.
///
/// `N` is how many tracked packets can be outstanding. Sending a tracked packet
/// into a slot whose occupant is still in flight declares the occupant lost
/// rather than forgetting it, so every record is returned regardless of `N`;
/// `N` only bounds how long a packet can wait before that happens. At sixty
/// packets a second, 64 is over a second of history.
pub struct Delivery<P, const N: usize = 64> {
    sent: SequenceBuffer<Sent<P>, N>,
    /// Highest sequence handed to `on_sent`, bounding every scan.
    largest_sent: Option<Sequence>,
    /// No packet before this one is in flight, so scans begin here rather than
    /// at the start of the buffer.
    oldest_unresolved: Sequence,
    largest_acked: Option<Sequence>,
    /// When an ack-eliciting packet last went out. Packets carrying only
    /// acknowledgements are excluded. The peer does not acknowledge those, so
    /// they prove nothing about the path.
    last_eliciting: Timestamp,
    rtt: Rtt,
    /// Tracked packets whose fate is still unknown.
    in_flight: u32,
    probes: ProbeBackoff,
    /// Longest the peer holds an acknowledgement. The probe timeout allows for
    /// it, since the peer is entitled to wait this long.
    peer_ack_delay: Span,
}

impl<P, const N: usize> Delivery<P, N> {
    /// `now` seeds the liveness timestamp, so a new connection does not look as
    /// though it has been silent since the epoch. `peer_ack_delay` is how long
    /// the peer may hold an acknowledgement.
    pub fn new(now: Timestamp, peer_ack_delay: MaxAckDelay) -> Self {
        Self {
            sent: SequenceBuffer::new(),
            largest_sent: None,
            oldest_unresolved: Sequence::FIRST,
            largest_acked: None,
            last_eliciting: now,
            rtt: Rtt::default(),
            in_flight: 0,
            probes: ProbeBackoff::default(),
            peer_ack_delay: peer_ack_delay.get(),
        }
    }

    #[inline]
    pub fn rtt(&self) -> &Rtt {
        &self.rtt
    }

    #[inline]
    pub fn in_flight(&self) -> u32 {
        self.in_flight
    }

    /// When an ack-eliciting packet last went out, which is what keepalive
    /// timing and the probe timeout depend on.
    #[inline]
    pub fn last_eliciting(&self) -> Timestamp {
        self.last_eliciting
    }

    /// Forgets the path's timing. Records in flight stay tracked. They may yet
    /// be acknowledged over the new path.
    pub fn on_path_change(&mut self) {
        self.rtt.reset();
        self.probes = ProbeBackoff::default();
    }

    /// Records a packet on its way out.
    ///
    /// `notify` receives `Lost` for a still-unresolved packet whose slot this
    /// one takes.
    pub fn on_sent(
        &mut self,
        now: Timestamp,
        sequence: Sequence,
        outgoing: Outgoing<P>,
        mut notify: impl FnMut(Resolved<P>),
    ) {
        self.largest_sent = self.largest_sent.max(Some(sequence));

        if let Outgoing::Eliciting(record) = outgoing {
            // Updated here rather than by the caller, so the timestamp and the
            // decision to track the packet cannot disagree.
            self.last_eliciting = now;
            let sent = Sent { sent_at: now, state: State::InFlight(record) };
            self.in_flight += 1;

            if let Some((_, evicted)) = self.sent.insert(sequence, sent)
                && let State::InFlight(record) = evicted.state
            {
                // Resolved here as lost rather than by detection, so it leaves
                // the flight here too.
                self.in_flight -= 1;
                notify(Resolved::Lost(record));
            }
        }
        self.advance_oldest();
    }

    /// Applies an acknowledgement, then runs loss detection against it.
    ///
    /// `ack` is the peer's newest received sequence, already resolved and
    /// validated against what was sent; `bits` is its history, where bit i
    /// means (ack - 1 - i) also arrived. `ack_delay` is how long the peer held
    /// the acknowledgement, or `None` when it held it longer than the field
    /// can express, in which case the packet yields no RTT sample.
    pub fn on_ack(
        &mut self,
        now: Timestamp,
        ack: Sequence,
        ack_delay: Option<Span>,
        bits: u32,
        mut notify: impl FnMut(Resolved<P>),
    ) {
        let newest_sent_at = self.resolve(ack, &mut notify);
        let mut confirmed_any = newest_sent_at.is_some();

        for offset in 0..32u64 {
            if (bits & (1 << offset)) != 0
                && let Some(sequence) = ack.checked_sub(offset + 1)
            {
                confirmed_any |= self.resolve(sequence, &mut notify).is_some();
            }
        }

        // Only the newest acknowledged packet gives a timing sample. One header
        // confirms up to 33 packets, but the others may have arrived long
        // before and would inflate the estimate.
        if self.largest_acked.is_none_or(|largest| ack > largest) {
            self.largest_acked = Some(ack);
            if let (Some(sent_at), Some(ack_delay)) = (newest_sent_at, ack_delay) {
                self.rtt.update(now, now.since(sent_at), ack_delay);
            }
        }

        // Progress, so the path is alive and the probe backoff starts over.
        if confirmed_any {
            self.probes = ProbeBackoff::default();
        }

        // Run now rather than waiting for a timer: this acknowledgement may
        // have put earlier packets past the reorder threshold.
        self.detect_lost(now, &mut notify);
    }

    /// Runs loss detection, and reports whether the probe timeout expired.
    ///
    /// A probe is not a loss. It asks the peer for an acknowledgement, whose
    /// arrival then lets the thresholds judge the packets before it.
    pub fn on_timeout(&mut self, now: Timestamp, mut notify: impl FnMut(Resolved<P>)) -> Option<Probe> {
        self.detect_lost(now, &mut notify);
        let deadline = self.probe_deadline()?;
        if now < deadline {
            return None;
        }
        self.probes = self.probes.doubled();
        Some(Probe { packets: PROBE_PACKETS })
    }

    /// When `on_timeout` next has work, if anything is outstanding.
    pub fn next_timeout(&self) -> Option<Timestamp> {
        match (self.loss_time(), self.probe_deadline()) {
            (Some(loss), Some(probe)) => Some(loss.min(probe)),
            (loss, probe) => loss.or(probe),
        }
    }

    /// Marks one packet delivered. Returns its send time only when this call
    /// confirmed a packet still in flight, which is the only case fit to
    /// sample RTT.
    fn resolve(&mut self, sequence: Sequence, notify: &mut impl FnMut(Resolved<P>)) -> Option<Timestamp> {
        let record = self.sent.get_mut(sequence)?;
        match core::mem::replace(&mut record.state, State::Acked) {
            State::Acked => None,
            State::Lost => {
                // Its contents were already resent, and timing from a packet
                // written off as lost is not trustworthy.
                notify(Resolved::Spurious);
                None
            }
            State::InFlight(payload) => {
                self.in_flight -= 1;
                notify(Resolved::Acked(payload));
                Some(record.sent_at)
            }
        }
    }

    /// Declares overdue packets lost. Only packets older than the largest
    /// acknowledged one are judged. A packet after it may simply not have
    /// arrived yet, and the probe timeout covers that tail.
    ///
    /// The count rule fires as soon as enough later packets were acknowledged.
    /// The time rule catches a packet with too few later packets behind it to
    /// trip the count.
    fn detect_lost(&mut self, now: Timestamp, notify: &mut impl FnMut(Resolved<P>)) {
        let Some(largest_acked) = self.largest_acked else { return };
        let delay = self.loss_delay();
        let threshold = largest_acked.checked_sub(REORDER_THRESHOLD);
        let mut sequence = self.oldest_unresolved;
        while sequence < largest_acked {
            if let Some(record) = self.sent.get_mut(sequence)
                && let State::InFlight(_) = record.state
            {
                let by_count = threshold.is_some_and(|threshold| sequence <= threshold);
                let by_time = now.since(record.sent_at) >= delay;
                if !(by_count || by_time) {
                    // Both rules are monotone in sequence: later packets are
                    // closer to the largest acknowledged and were sent no
                    // earlier. Nothing further on qualifies either.
                    break;
                }
                if let State::InFlight(payload) = core::mem::replace(&mut record.state, State::Lost) {
                    self.in_flight -= 1;
                    notify(Resolved::Lost(payload));
                }
            }
            sequence = sequence.next();
        }
        self.advance_oldest();
    }

    /// The oldest packet still in flight, if any.
    fn oldest_in_flight(&self) -> Option<&Sent<P>> {
        self.sent
            .get(self.oldest_unresolved)
            .filter(|record| matches!(record.state, State::InFlight(_)))
    }

    /// When the time rule next declares a loss. Only the oldest in-flight
    /// packet matters, and only when it precedes the largest acknowledged.
    fn loss_time(&self) -> Option<Timestamp> {
        if self.oldest_unresolved >= self.largest_acked? {
            return None;
        }
        Some(self.oldest_in_flight()?.sent_at.saturating_add(self.loss_delay()))
    }

    /// When the tail of the flight is owed a probe, if anything is in flight.
    ///
    /// Measured from the last ack-eliciting send. Allows the round trip, four
    /// deviations of jitter, and the peer's permitted holding time, so an
    /// acknowledgement that is merely late does not trigger it.
    fn probe_deadline(&self) -> Option<Timestamp> {
        let _ = self.oldest_in_flight()?;
        let base = self
            .rtt
            .smoothed()
            .saturating_add(self.rtt.variation().saturating_mul(4).max(TIMER_GRANULARITY))
            .saturating_add(self.peer_ack_delay);
        Some(
            self.last_eliciting
                .saturating_add(base.saturating_mul(self.probes.factor())),
        )
    }

    fn loss_delay(&self) -> Span {
        let base = self.rtt.smoothed().max(self.rtt.latest());
        base.scaled::<TIME_THRESHOLD_NUMERATOR, TIME_THRESHOLD_DENOMINATOR>()
            .max(TIMER_GRANULARITY)
    }

    fn advance_oldest(&mut self) {
        let Some(largest_sent) = self.largest_sent else { return };
        while (self.oldest_unresolved <= largest_sent) && self.oldest_in_flight().is_none() {
            self.oldest_unresolved = self.oldest_unresolved.next();
        }
    }
}

/// Quantizes an acknowledgement delay for the header. The largest value is
/// reserved to mean "at least this long", so a saturated delay is never
/// mistaken for a measured one.
#[inline]
pub fn encode_ack_delay(delay: Span) -> u8 {
    let units = delay.as_nanos() / ACK_DELAY_UNIT.as_nanos();
    u8::try_from(units).unwrap_or(u8::MAX)
}

/// The delay a header reports, or `None` when it saturated and the true delay
/// is unknown.
#[inline]
pub fn decode_ack_delay(encoded: u8) -> Option<Span> {
    (encoded != u8::MAX).then(|| ACK_DELAY_UNIT.saturating_mul(u32::from(encoded)))
}
