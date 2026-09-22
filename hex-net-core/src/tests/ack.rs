//! The delivery ledger: outcomes, loss rules, probes, and RTT sampling.

use crate::{
    ack::{Delivery, Outgoing, Resolved, decode_ack_delay, encode_ack_delay},
    config::MaxAckDelay,
    seq::Sequence,
    time::{Span, Timestamp},
};

fn seq(n: u64) -> Sequence {
    Sequence::new(n).expect("nonzero literal")
}

fn at(ms: u64) -> Timestamp {
    Timestamp::from_nanos(ms * 1_000_000)
}

/// A ledger whose records are the packet's own number, so every outcome
/// names the packet it belongs to.
struct Ledger {
    delivery: Delivery<u64, 8>,
    outcomes: Vec<Resolved<u64>>,
}

impl Ledger {
    fn new() -> Self {
        Self {
            delivery: Delivery::new(at(0), MaxAckDelay::DEFAULT),
            outcomes: Vec::new(),
        }
    }

    fn send(&mut self, now: Timestamp, n: u64) {
        self.delivery
            .on_sent(now, seq(n), Outgoing::Eliciting(n), |r| self.outcomes.push(r));
    }

    fn send_ack_only(&mut self, now: Timestamp, n: u64) {
        self.delivery
            .on_sent(now, seq(n), Outgoing::AckOnly, |r| self.outcomes.push(r));
    }

    fn ack(&mut self, now: Timestamp, n: u64, bits: u32) {
        self.delivery
            .on_ack(now, seq(n), Some(Span::ZERO), bits, |r| self.outcomes.push(r));
    }

    fn tick(&mut self, now: Timestamp) -> u8 {
        self.delivery
            .on_timeout(now, |r| self.outcomes.push(r))
            .map_or(0, |probe| probe.packets)
    }

    fn take(&mut self) -> Vec<Resolved<u64>> {
        std::mem::take(&mut self.outcomes)
    }
}

#[test]
fn an_acknowledgement_returns_the_record_and_samples_rtt() {
    let mut ledger = Ledger::new();
    ledger.send(at(0), 1);
    ledger.ack(at(40), 1, 0);

    assert_eq!(ledger.take(), vec![Resolved::Acked(1)]);
    assert_eq!(ledger.delivery.rtt().smoothed(), Span::from_millis(40));
    assert_eq!(ledger.delivery.rtt().min(), Some(Span::from_millis(40)));
}

#[test]
fn the_reorder_rule_fires_on_the_acknowledgement_itself() {
    let mut ledger = Ledger::new();
    for n in 1..=5 {
        ledger.send(at(0), n);
    }
    // 5 arrived, and 4 and 3 before it; 1 and 2 did not.
    ledger.ack(at(1), 5, 0b11);

    let outcomes = ledger.take();
    assert!(outcomes.contains(&Resolved::Lost(1)));
    assert!(outcomes.contains(&Resolved::Lost(2)));
    assert!(outcomes.contains(&Resolved::Acked(5)));
    assert_eq!(outcomes.len(), 5, "every packet resolved exactly once: {outcomes:?}");
}

#[test]
fn the_time_rule_judges_only_packets_before_the_largest_acknowledged() {
    let mut ledger = Ledger::new();
    ledger.send(at(0), 1);
    ledger.send(at(0), 2);
    ledger.send(at(0), 3);
    ledger.ack(at(40), 2, 0);
    assert_eq!(ledger.take(), vec![Resolved::Acked(2)]);

    // 1 precedes the largest acknowledged, so it has a loss deadline; 3 does
    // not, however long it waits.
    let deadline = ledger.delivery.next_timeout().expect("something outstanding");
    assert_eq!(deadline, at(45));
    assert_eq!(ledger.tick(at(44)), 0);
    assert!(ledger.take().is_empty());

    assert_eq!(ledger.tick(at(45)), 0);
    assert_eq!(ledger.take(), vec![Resolved::Lost(1)]);
}

#[test]
fn an_unacknowledged_tail_is_probed_not_declared_lost() {
    let mut ledger = Ledger::new();
    ledger.send(at(0), 1);

    // Unmeasured: 100 ms assumed, 50 ms deviation, plus the peer's holding time.
    let first = at(0).saturating_add(Span::from_millis(100 + 200).saturating_add(MaxAckDelay::DEFAULT.get()));
    assert_eq!(ledger.delivery.next_timeout(), Some(first));
    assert_eq!(ledger.tick(at(324)), 0);
    assert_eq!(ledger.tick(first), 2, "a probe timeout owes two packets");
    assert!(ledger.take().is_empty(), "a probe is not a loss");

    // Backoff: measured from the last eliciting send, doubled.
    let second = at(0).saturating_add(
        Span::from_millis(100 + 200)
            .saturating_add(MaxAckDelay::DEFAULT.get())
            .saturating_mul(2),
    );
    assert_eq!(ledger.delivery.next_timeout(), Some(second));

    // The probe's acknowledgement puts packet 1 before the largest acked.
    ledger.send(first, 2);
    ledger.ack(first.saturating_add(Span::from_millis(40)), 2, 0);
    assert_eq!(ledger.take(), vec![Resolved::Acked(2), Resolved::Lost(1)]);
}

#[test]
fn a_record_displaced_from_its_slot_is_reported_lost() {
    let mut ledger = Ledger::new();
    for n in 1..=8 {
        ledger.send(at(0), n);
    }
    assert!(ledger.take().is_empty());

    // The ring holds eight; the ninth tracked packet takes packet 1's slot.
    ledger.send(at(0), 9);
    assert_eq!(ledger.take(), vec![Resolved::Lost(1)]);
    // Resolved, so it has left the flight: every packet sent is either
    // resolved or in flight, never both.
    assert_eq!(ledger.delivery.in_flight(), 8);
}

#[test]
fn a_late_acknowledgement_after_a_loss_is_reported_spurious() {
    let mut ledger = Ledger::new();
    for n in 1..=5 {
        ledger.send(at(0), n);
    }
    ledger.ack(at(1), 5, 0b11);
    ledger.take();

    // Bits for 4, 3, 2, and 1: the two declared lost were only late.
    ledger.ack(at(2), 5, 0b1111);
    assert_eq!(ledger.take(), vec![Resolved::Spurious, Resolved::Spurious]);
}

#[test]
fn acknowledgement_only_packets_are_never_tracked() {
    let mut ledger = Ledger::new();
    ledger.send_ack_only(at(0), 1);
    ledger.send(at(0), 2);
    ledger.send_ack_only(at(0), 3);
    ledger.ack(at(10), 2, 0);

    assert_eq!(ledger.take(), vec![Resolved::Acked(2)]);
    assert_eq!(ledger.delivery.next_timeout(), None, "nothing is left in flight");
}

#[test]
fn a_saturated_delay_yields_no_sample() {
    let mut ledger = Ledger::new();
    ledger.send(at(0), 1);
    let outcomes = &mut ledger.outcomes;
    ledger
        .delivery
        .on_ack(at(200), seq(1), decode_ack_delay(u8::MAX), 0, |r| outcomes.push(r));

    assert_eq!(ledger.take(), vec![Resolved::Acked(1)]);
    assert_eq!(ledger.delivery.rtt().min(), None, "unknown holding time, so no sample");
    assert_eq!(decode_ack_delay(encode_ack_delay(Span::from_millis(80))), None);
    assert_eq!(
        decode_ack_delay(encode_ack_delay(Span::from_millis(10))),
        Some(Span::from_millis(10))
    );
}

#[test]
fn the_minimum_rtt_ages_out() {
    let mut ledger = Ledger::new();
    let mut now = at(0);
    let mut n = 1;
    let mut exchange = |ledger: &mut Ledger, now: &mut Timestamp, rtt: u64| {
        ledger.send(*now, n);
        *now = now.saturating_add(Span::from_millis(rtt));
        ledger.ack(*now, n, 0);
        n += 1;
    };

    exchange(&mut ledger, &mut now, 20);
    assert_eq!(ledger.delivery.rtt().min(), Some(Span::from_millis(20)));

    // The route lengthens. Within the window the old minimum holds; after it,
    // the new path defines the baseline.
    for _ in 0..200 {
        exchange(&mut ledger, &mut now, 60);
    }
    assert_eq!(ledger.delivery.rtt().min(), Some(Span::from_millis(60)));
}
