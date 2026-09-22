//! What the outgoing header reports about received traffic.

use crate::{
    packet::PacketCrypto,
    seq::Sequence,
    time::Timestamp,
    wire::{ConnectionId, ServerNonce},
};

fn seq(n: u64) -> Sequence {
    Sequence::new(n).expect("nonzero literal")
}

fn at(ms: u64) -> Timestamp {
    Timestamp::from_nanos(ms * 1_000_000)
}

#[test]
fn the_reported_delay_starts_when_the_named_packet_arrived() {
    let mut crypto = PacketCrypto::new(ConnectionId(1), &[1; 32], &[2; 32]);
    assert!(crypto.ack_state().is_none(), "nothing to acknowledge yet");

    crypto.record_eliciting(seq(5), at(0));
    crypto.record_eliciting(seq(6), at(20));
    // A straggler does not become the newest, so it does not move the clock.
    crypto.record_eliciting(seq(4), at(30));

    let state = crypto.ack_state().expect("packets arrived");
    assert_eq!(state.newest, seq(6));
    assert_eq!(state.received_at, at(20));
    assert_eq!(state.bits, 0b11);
}

#[test]
fn an_acknowledgement_ahead_of_the_send_counter_is_refused() {
    let crypto = PacketCrypto::new(ConnectionId(1), &[1; 32], &[2; 32]);
    assert_eq!(crypto.resolve_ack(seq(1).to_wire()), None, "nothing has been sent");
}

#[test]
fn every_connection_and_every_attempt_gets_its_own_keys() {
    use crate::crypto::Keys;
    use crate::wire::ClientNonce;

    let session = Keys {
        client_to_server: [7; 32],
        server_to_client: [9; 32],
    };
    let base = session.for_connection(ConnectionId(1), ClientNonce(1), ServerNonce(1));

    // The same inputs derive the same keys on both sides of a handshake.
    let again = session.for_connection(ConnectionId(1), ClientNonce(1), ServerNonce(1));
    assert_eq!(base.client_to_server(), again.client_to_server());
    assert_eq!(base.server_to_client(), again.server_to_client());

    // A different connection, a different attempt, or a different challenge
    // with the same session keys derives something else entirely. The last is
    // the server's own guarantee: it holds when the id and the client's nonce
    // both repeat.
    let other_id = session.for_connection(ConnectionId(2), ClientNonce(1), ServerNonce(1));
    let other_attempt = session.for_connection(ConnectionId(1), ClientNonce(2), ServerNonce(1));
    let other_challenge = session.for_connection(ConnectionId(1), ClientNonce(1), ServerNonce(2));
    for derived in [other_id, other_attempt, other_challenge] {
        assert_ne!(base.client_to_server(), derived.client_to_server());
        assert_ne!(base.server_to_client(), derived.server_to_client());
    }

    // Neither direction ever encrypts with the key the backend issued.
    assert_ne!(base.client_to_server(), &session.client_to_server);
    assert_ne!(base.server_to_client(), &session.server_to_client);
}

#[test]
fn a_request_carries_its_nonce_after_the_ticket() {
    use crate::wire::{ClientNonce, HANDSHAKE_LEN, MAX_DATAGRAM, encode_request, handshake_blob, request_nonce};

    let ticket = [0xAB; 126];
    let mut packet = [0u8; MAX_DATAGRAM];
    let len = encode_request(&ticket, ClientNonce(0x1122_3344_5566_7788), &mut packet).expect("frame");

    assert_eq!(len, HANDSHAKE_LEN, "padded like every handshake packet");
    assert_eq!(
        handshake_blob(&packet[..len]),
        Some(&ticket[..]),
        "the ticket is untouched"
    );
    assert_eq!(request_nonce(&packet[..len]), Some(ClientNonce(0x1122_3344_5566_7788)));
}
