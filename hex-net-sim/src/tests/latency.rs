//! The transport over a wire with delay, driven by the deadlines each side
//! reports rather than by a fixed tick.

use std::time::Duration;

use hex_net_core::{
    channel::{ChannelKind, ChannelSet},
    config::{MaxAckDelay, TransportConfig},
    connector::State as ClientState,
    stats::Counter,
};

use crate::pair::{Datagram, Pair};

const ORDERED: ChannelSet = ChannelSet::new([ChannelKind::ReliableOrdered]);

const ONE_WAY: Duration = Duration::from_millis(40);

/// Connects, then trades enough messages for both RTT estimates to settle on
/// the path.
fn converged_pair() -> Pair {
    let mut pair = Pair::with_latency(ORDERED, 1, ONE_WAY);
    assert!(pair.settle(), "the handshake completed");
    for _ in 0..8 {
        pair.client_send(0, b"sample");
        pair.server_send(0, b"sample");
        assert!(pair.settle());
    }
    pair
}

#[test]
fn the_round_trip_is_measured_over_a_slow_link() {
    let pair = converged_pair();
    let rtt = pair.client_rtt();
    assert!(
        (rtt >= (ONE_WAY * 2)) && (rtt <= ((ONE_WAY * 2) + Duration::from_millis(1))),
        "measured {rtt:?} over a {:?} round trip",
        ONE_WAY * 2
    );
}

#[test]
fn a_reliable_message_over_a_slow_link_is_sent_once() {
    let mut pair = converged_pair();
    let delivered = pair.client_inbox.len();

    pair.server_send(0, b"once");
    assert!(pair.settle());

    assert_eq!(pair.client_inbox.len(), delivered + 1);
    assert_eq!(pair.server_counters.get(Counter::PacketsLost), 0);
    assert_eq!(pair.client_counters.get(Counter::PacketsLost), 0);
}

#[test]
fn a_path_that_slows_down_is_probed_not_declared_lost() {
    // The estimate says 80 ms. The path now takes 200 ms, so the
    // acknowledgement arrives long after 9/8 of the estimate. Nothing was
    // lost, and nothing may be declared lost.
    let mut pair = converged_pair();
    pair.set_latency(Duration::from_millis(100));

    let delivered = pair.server_inbox.len();
    pair.client_send(0, b"slow");
    assert!(pair.run_for(Duration::from_secs(2)), "every deadline was serviced");

    assert_eq!(pair.server_inbox.len(), delivered + 1, "delivered exactly once");
    assert_eq!(pair.client_counters.get(Counter::PacketsLost), 0);
    assert_eq!(pair.server_counters.get(Counter::PacketsLost), 0);
    assert_eq!(pair.client_counters.get(Counter::PacketsSpuriouslyLost), 0);
}

#[test]
fn a_burst_over_budget_resumes_as_soon_as_the_budget_allows() {
    // Three 1000-byte messages, one per datagram, against a 2000-byte bucket
    // refilling at 8000 bytes a second: the first goes at once, the second
    // about 10 ms later, the third about 130 ms after that. Nothing else is
    // due for a second, so only the budget's own deadline can wake the client
    // in time.
    let mut pair = Pair::new(ORDERED, 1);
    assert!(pair.settle(), "the handshake completed");

    let payload = [0xAB; 1000];
    for _ in 0..3 {
        pair.client_send(0, &payload);
    }
    assert!(pair.run_for(Duration::from_millis(300)), "every deadline was serviced");

    assert_eq!(pair.server_inbox.len(), 3, "the whole burst arrived");
}

#[test]
fn an_idle_connection_driven_by_deadlines_stays_up() {
    let mut pair = converged_pair();

    assert!(pair.run_for(Duration::from_secs(30)), "every deadline was serviced");

    assert_eq!(pair.client_state(), ClientState::Connected);
    assert_eq!(pair.server.num_connections(), 1);
    assert_eq!(pair.client_counters.get(Counter::PacketsLost), 0);
    assert_eq!(pair.server_counters.get(Counter::PacketsLost), 0);
}

/// A connected pair on a wire with no delay, both sides holding
/// acknowledgements for the default time.
fn deferring_pair() -> Pair {
    let mut pair = Pair::with_transport(ORDERED, 1, Duration::ZERO, TransportConfig::DEFAULT);
    assert!(pair.settle(), "the handshake completed");
    assert_eq!(pair.client_state(), ClientState::Connected);
    pair
}

/// Datagrams the server has sent, oldest first.
fn from_server(pair: &Pair) -> Vec<&Datagram> {
    pair.trace.iter().filter(|d| d.from == pair.server_addr).collect()
}

#[test]
fn an_acknowledgement_waits_for_a_packet_with_frames_to_carry_it() {
    let mut pair = deferring_pair();

    pair.client_send(0, b"input");
    pair.pass();
    pair.pass();
    let before = from_server(&pair).len();
    pair.pass();
    assert_eq!(from_server(&pair).len(), before, "the server held its acknowledgement");

    pair.server_send(0, b"snapshot");
    pair.pass();
    let sent = from_server(&pair);
    assert_eq!(
        sent.len(),
        before + 1,
        "one packet carried the message and the acknowledgement"
    );
    let header = sent[before].header().expect("a payload header");
    assert!(header.ack.is_some(), "the acknowledgement rode on the message");
}

#[test]
fn an_acknowledgement_with_nothing_to_carry_it_goes_alone_at_its_deadline() {
    let mut pair = deferring_pair();
    let delay = MaxAckDelay::DEFAULT.get();

    pair.client_send(0, b"input");
    pair.pass();
    pair.pass();
    let before = from_server(&pair).len();

    pair.advance(delay - Duration::from_millis(1));
    pair.pass();
    assert_eq!(from_server(&pair).len(), before, "still within the delay");

    pair.advance(Duration::from_millis(1));
    pair.pass();
    let sent = from_server(&pair);
    assert_eq!(sent.len(), before + 1, "the acknowledgement went out alone");
    assert!(sent[before].header().expect("a payload header").ack.is_some());
}

#[test]
fn a_gap_in_the_peers_packets_is_acknowledged_at_once() {
    let mut pair = deferring_pair();

    // One packet arrives, so the server has a sequence to judge the next
    // against.
    pair.client_send(0, b"first");
    pair.pass();
    pair.pass();

    // The packet carrying this never arrives, so the one after it leaves a gap.
    pair.silence_client(true);
    pair.client_send(0, b"lost");
    pair.pass();
    pair.pass();
    pair.silence_client(false);

    let before = from_server(&pair).len();
    pair.client_send(0, b"next");
    pair.pass();
    pair.pass();

    assert_eq!(
        from_server(&pair).len(),
        before + 1,
        "the gap was reported without waiting out the delay"
    );
}
