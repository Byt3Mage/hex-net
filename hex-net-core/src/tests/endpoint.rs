//! The endpoint's handshake limits.

use std::net::SocketAddr;

use crate::{
    channel::{ChannelKind, ChannelSet},
    ctx::Ctx,
    endpoint::{Action, DropReason, Endpoint, EndpointConfig},
    packet::Packet,
    stats::Counters,
    time::Timestamp,
    wire::{HANDSHAKE_LEN, MAX_DATAGRAM, PacketKind},
};

const CHANNELS: ChannelSet = ChannelSet::new([ChannelKind::ReliableOrdered]);

fn endpoint() -> Endpoint {
    Endpoint::new(EndpointConfig::new(16), [0x5A; 32], &CHANNELS)
}

/// A handshake packet of the right length that will not authenticate: every
/// check before decryption passes, so only the limiter can refuse it early.
fn handshake(kind: PacketKind) -> Packet {
    let mut packet = [0u8; MAX_DATAGRAM];
    packet[0] = kind as u8;
    packet
}

fn send(endpoint: &mut Endpoint, counters: &mut Counters, from: &str, kind: PacketKind) -> Action {
    let from: SocketAddr = from.parse().expect("literal address");
    let mut ctx = Ctx::new(Timestamp::ZERO, counters);
    let mut buf = handshake(kind);
    let mut out = [0u8; MAX_DATAGRAM];
    endpoint.handle_datagram(&mut ctx, from, &mut buf, HANDSHAKE_LEN, &mut out, &mut |_, _, _| {})
}

#[test]
fn changing_source_port_does_not_refill_the_bucket() {
    let mut endpoint = endpoint();
    let mut counters = Counters::new();

    for port in 0..32 {
        let action = send(
            &mut endpoint,
            &mut counters,
            &format!("203.0.113.7:{}", 40_000 + port),
            PacketKind::Request,
        );
        assert_ne!(action, Action::Dropped(DropReason::RateLimited), "within the burst");
    }
    let action = send(&mut endpoint, &mut counters, "203.0.113.7:50000", PacketKind::Request);
    assert_eq!(action, Action::Dropped(DropReason::RateLimited));

    let action = send(&mut endpoint, &mut counters, "198.51.100.9:40000", PacketKind::Request);
    assert_ne!(
        action,
        Action::Dropped(DropReason::RateLimited),
        "another host is unaffected"
    );
}

#[test]
fn a_request_flood_does_not_starve_responses() {
    let mut endpoint = endpoint();
    let mut counters = Counters::new();

    let mut limited = false;
    for host in 0..2048u32 {
        let [a, b, c, d] = (0x0A00_0000 | host).to_be_bytes();
        let from = format!("{a}.{b}.{c}.{d}:40000");
        limited |=
            send(&mut endpoint, &mut counters, &from, PacketKind::Request) == Action::Dropped(DropReason::RateLimited);
    }
    assert!(limited, "the global request budget ran out");

    let action = send(&mut endpoint, &mut counters, "192.0.2.1:40000", PacketKind::Response);
    assert_ne!(action, Action::Dropped(DropReason::RateLimited));
}
