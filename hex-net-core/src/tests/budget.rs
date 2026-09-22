//! The send allowance: its bounds, its refill, and its controller.

use std::time::Duration;

use crate::ack::{Delivery, Outgoing, Rtt};
use crate::budget::{Budget, BudgetConfig, MIN_PACKET, MIN_RATE};
use crate::config::MaxAckDelay;
use crate::seq::Sequence;
use crate::time::Timestamp;
use crate::wire::MAX_DATAGRAM;

fn at_micros(us: u64) -> Timestamp {
    Timestamp::from_nanos(us * 1_000)
}

#[test]
fn a_config_outside_its_bounds_cannot_be_built() {
    assert!(BudgetConfig::new(MIN_RATE - 1, MAX_DATAGRAM).is_none());
    assert!(BudgetConfig::new(MIN_RATE, MIN_PACKET - 1).is_none());
    assert!(BudgetConfig::new(MIN_RATE, MAX_DATAGRAM + 1).is_none());
    assert!(BudgetConfig::new(MIN_RATE, MIN_PACKET).is_some());
    assert!(
        BudgetConfig::DEFAULT.rate() > MIN_RATE,
        "the default leaves room to back off"
    );
}

#[test]
fn the_delivered_rate_does_not_depend_on_how_often_it_is_read() {
    let config = BudgetConfig::DEFAULT;
    let mut budget = Budget::new(Timestamp::ZERO, config);
    budget.on_sent(u16::MAX, false);

    // Consulted every 1.1 ms for 200 ms, spending everything each time.
    let mut spent = 0u64;
    let mut now = 0;
    while now < 200_000 {
        now += 1_100;
        let available = budget.available(at_micros(now));
        budget.on_sent(available as u16, false);
        spent += u64::from(available);
    }

    let expected = (u64::from(config.rate()) * now) / 1_000_000;
    assert!(expected.abs_diff(spent) <= 1, "spent {spent}, expected {expected}");
}

#[test]
fn loss_backs_off_to_the_floor_and_recovers_to_the_ceiling() {
    let config = BudgetConfig::DEFAULT;
    let mut budget = Budget::new(Timestamp::ZERO, config);
    let rtt = Rtt::default();
    let mut now = Timestamp::ZERO;

    for _ in 0..40 {
        for _ in 0..20 {
            budget.on_sent(100, true);
            budget.on_lost();
        }
        now = now.saturating_add(Duration::from_millis(100));
        budget.assess(now, &rtt);
        assert!(budget.rate() >= MIN_RATE);
    }
    assert_eq!(budget.rate(), MIN_RATE);
    assert!(budget.is_constrained());

    for _ in 0..40 {
        for _ in 0..20 {
            budget.on_sent(100, true);
        }
        now = now.saturating_add(Duration::from_millis(100));
        budget.assess(now, &rtt);
        assert!(budget.rate() <= config.rate());
    }
    assert_eq!(budget.rate(), config.rate());
    assert!(!budget.is_constrained());
}

#[test]
fn acknowledgement_only_packets_do_not_dilute_the_loss_rate() {
    let mut budget = Budget::new(Timestamp::ZERO, BudgetConfig::DEFAULT);
    let rtt = Rtt::default();

    // 20 tracked packets with 1 lost is 5%, over the 2% threshold. Counting a
    // thousand acknowledgements alongside would make it 0.1%.
    for _ in 0..20 {
        budget.on_sent(100, true);
    }
    for _ in 0..1000 {
        budget.on_sent(30, false);
    }
    budget.on_lost();
    budget.assess(Timestamp::ZERO.saturating_add(Duration::from_millis(100)), &rtt);
    assert!(budget.is_constrained());
}

#[test]
fn jitter_on_a_short_path_is_not_queueing() {
    let config = BudgetConfig::DEFAULT;
    let mut budget = Budget::new(Timestamp::ZERO, config);
    let mut delivery: Delivery<(), 8> = Delivery::new(Timestamp::ZERO, MaxAckDelay::DEFAULT);
    let mut now = Timestamp::ZERO;

    // A 10 ms path wandering up to 16 ms: a 25% margin alone would call this
    // congestion.
    for n in 1..=100u64 {
        let rtt = if (n % 2) == 0 { 10 } else { 16 };
        let sequence = Sequence::new(n).expect("nonzero");
        delivery.on_sent(now, sequence, Outgoing::Eliciting(()), |_| {});
        now = now.saturating_add(Duration::from_millis(rtt));
        delivery.on_ack(now, sequence, Some(Duration::ZERO), 0, |_| {});
        budget.on_sent(100, true);
        budget.assess(now, delivery.rtt());
    }
    assert!(!budget.is_constrained(), "rate fell to {}", budget.rate());
}
