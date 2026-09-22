use std::time::Duration;

use hex_net_core::{
    channel::{ChannelKind, ChannelSet},
    connector::State as ClientState,
    crypto::{Key, MAX_BLOB, NONCE_LEN},
    endpoint::Event as ServerEvent,
    handshake::{
        Acceptor, HandshakeError, MAX_USER_DATA, RESUME_GRACE, SessionId, Ticket, TicketId, UserData, encrypt_ticket,
    },
    packet::Packet,
    shard::ShardId,
    time::Timestamp,
    wire::{ClientNonce, HANDSHAKE_LEN, MAX_DATAGRAM, PacketKind, ServerNonce, encode_handshake},
};

use crate::pair::{Pair, session_keys};

const ORDERED: ChannelSet = ChannelSet::new([ChannelKind::ReliableOrdered]);

#[test]
fn a_ticket_round_trips_through_a_request() {
    let backend_key: Key = [0x5A; 32];
    let acceptor = Acceptor::new(backend_key);
    let now = Timestamp::ZERO;
    let keys = session_keys(1);

    let mut user_data = UserData::new();
    assert!(user_data.extend_from_slice(b"opaque to the transport"));

    let original = Ticket {
        expires_at: now.saturating_add(Duration::from_secs(60)),
        client_id: 0x0123_4567_89AB_CDEF,
        session: None,
        keys,
        user_data,
    };

    let mut encrypted = [0u8; MAX_BLOB];
    let len = encrypt_ticket(&backend_key, &original, &mut encrypted).expect("encrypt");

    let mut packet = [0u8; MAX_DATAGRAM];
    encode_handshake(PacketKind::Request, &encrypted[..len], &mut packet).expect("frame");

    let decoded = acceptor.decrypt_ticket(&packet[..HANDSHAKE_LEN]).expect("decrypt");

    assert_eq!(decoded.client_id, original.client_id);
    assert_eq!(decoded.expires_at, original.expires_at);
    assert_eq!(decoded.session, None);
    assert_eq!(decoded.user_data.as_ref(), original.user_data.as_ref());
    assert_eq!(decoded.keys.client_to_server, keys.client_to_server);
    assert_eq!(decoded.keys.server_to_client, keys.server_to_client);
}

#[test]
fn a_resume_ticket_names_its_session() {
    // A resume ticket is sealed by the server rather than the backend, and
    // decrypt_ticket must accept both without being told which to expect.
    let acceptor = Acceptor::new([0x5A; 32]);
    let now = Timestamp::ZERO;

    let ticket = Ticket {
        expires_at: now,
        client_id: 7,
        session: Some(SessionId(42)),
        keys: session_keys(7),
        user_data: UserData::new(),
    };

    let mut encrypted = [0u8; MAX_BLOB];
    let len = acceptor
        .encrypt_resume_ticket(now, ticket, &mut encrypted)
        .expect("encrypt");

    let mut packet: Packet = [0u8; MAX_DATAGRAM];
    encode_handshake(PacketKind::Request, &encrypted[..len], &mut packet).expect("frame");

    let decoded = acceptor.decrypt_ticket(&packet[..HANDSHAKE_LEN]).expect("decrypt");
    assert_eq!(decoded.session, Some(SessionId(42)));
    // The lifetime is reset on issue, so the ticket outlives the grace period.
    assert!(decoded.expires_at > now.saturating_add(RESUME_GRACE));
}

#[test]
fn a_foreign_key_does_not_open_a_ticket() {
    let acceptor = Acceptor::new([0x5A; 32]);
    let now = Timestamp::ZERO;

    let ticket = Ticket {
        expires_at: now.saturating_add(Duration::from_secs(60)),
        client_id: 1,
        session: None,
        keys: session_keys(1),
        user_data: UserData::new(),
    };

    // Sealed by someone who is neither this server nor its backend.
    let mut encrypted = [0u8; MAX_BLOB];
    let len = encrypt_ticket(&[0xAA; 32], &ticket, &mut encrypted).expect("encrypt");

    let mut packet: Packet = [0u8; MAX_DATAGRAM];
    encode_handshake(PacketKind::Request, &encrypted[..len], &mut packet).expect("frame");

    assert!(matches!(
        acceptor.decrypt_ticket(&packet[..HANDSHAKE_LEN]),
        Err(HandshakeError::BadAuth)
    ));
}

#[test]
fn a_tampered_ticket_fails_authentication() {
    let backend_key: Key = [0x5A; 32];
    let acceptor = Acceptor::new(backend_key);
    let now = Timestamp::ZERO;

    let ticket = Ticket {
        expires_at: now.saturating_add(Duration::from_secs(60)),
        client_id: 1,
        session: None,
        keys: session_keys(1),
        user_data: UserData::new(),
    };

    let mut encrypted = [0u8; MAX_BLOB];
    let len = encrypt_ticket(&backend_key, &ticket, &mut encrypted).expect("encrypt");

    // Every byte of the blob is covered by the tag, so flipping any one of
    // them must be caught: nonce, ciphertext, and tag alike.
    for at in [0, NONCE_LEN, len - 1] {
        let mut broken = encrypted;
        broken[at] ^= 0x01;

        let mut packet: Packet = [0u8; MAX_DATAGRAM];
        encode_handshake(PacketKind::Request, &broken[..len], &mut packet).expect("frame");

        assert!(
            matches!(
                acceptor.decrypt_ticket(&packet[..HANDSHAKE_LEN]),
                Err(HandshakeError::BadAuth)
            ),
            "a flip at byte {at} was not detected"
        );
    }
}

#[test]
fn a_cookie_binds_the_address_that_presented_the_ticket() {
    let acceptor = Acceptor::new([0x5A; 32]);
    let now = Timestamp::ZERO;

    let ticket = Ticket {
        expires_at: now.saturating_add(Duration::from_secs(60)),
        client_id: 99,
        session: Some(SessionId::new(3, ShardId::FIRST)),
        keys: session_keys(99),
        user_data: UserData::new(),
    };

    // Both families: the IPv6 arm is twelve bytes wider, so an offset the two
    // sides disagree on shows up there and not on IPv4.
    for text in ["10.0.0.2:40000", "[2001:db8::1]:40000", "[::1]:1"] {
        let addr = text.parse().expect("literal address");

        let mut encrypted = [0u8; MAX_BLOB];
        let len = acceptor
            .encrypt_cookie(
                now,
                addr,
                ClientNonce(0x5EED),
                ServerNonce(0x5E4F),
                TicketId([0x1D; TicketId::LEN]),
                &ticket,
                &mut encrypted,
            )
            .expect("encrypt");

        let mut packet: Packet = [0u8; MAX_DATAGRAM];
        encode_handshake(PacketKind::Response, &encrypted[..len], &mut packet).expect("frame");

        let cookie = acceptor.decrypt_cookie(&packet[..HANDSHAKE_LEN]).expect("decrypt");

        assert_eq!(cookie.addr, addr, "{text}");
        assert_eq!(cookie.nonce, ClientNonce(0x5EED), "{text}");
        assert_eq!(cookie.server_nonce, ServerNonce(0x5E4F), "{text}");
        assert_eq!(cookie.issued_at, now);
        assert_eq!(cookie.ticket_id, TicketId([0x1D; TicketId::LEN]), "{text}");
        assert_eq!(cookie.ticket.session, ticket.session);
        assert_eq!(
            cookie.ticket.keys.client_to_server, ticket.keys.client_to_server,
            "the session keys must survive the cookie: they are all the client has"
        );
    }
}

#[test]
fn a_cookie_carries_a_full_user_data_payload() {
    // The largest ticket the size assertions allow, inside a cookie with the
    // widest address prefix. If MAX_COOKIE were short by a few bytes this is
    // where it would show.
    let acceptor = Acceptor::new([0x5A; 32]);
    let now = Timestamp::ZERO;

    let mut user_data = UserData::new();
    assert!(user_data.extend_from_slice(&[0xC3; MAX_USER_DATA]));

    let ticket = Ticket {
        expires_at: now.saturating_add(Duration::from_secs(60)),
        client_id: u64::MAX,
        session: Some(SessionId::new(u64::MAX, ShardId::FIRST)),
        keys: session_keys(5),
        user_data,
    };

    let addr = "[2001:db8::1]:65535".parse().expect("literal address");
    let mut encrypted = [0u8; MAX_BLOB];
    let len = acceptor
        .encrypt_cookie(
            now,
            addr,
            ClientNonce(0x5EED),
            ServerNonce(0x5E4F),
            TicketId([0x1D; TicketId::LEN]),
            &ticket,
            &mut encrypted,
        )
        .expect("a full ticket fits a cookie");

    let mut packet: Packet = [0u8; MAX_DATAGRAM];
    encode_handshake(PacketKind::Response, &encrypted[..len], &mut packet).expect("frame");

    let cookie = acceptor.decrypt_cookie(&packet[..HANDSHAKE_LEN]).expect("decrypt");
    assert_eq!(cookie.addr, addr);
    assert_eq!(cookie.ticket.user_data.as_ref(), &[0xC3; MAX_USER_DATA][..]);
}

#[test]
fn a_cookie_from_another_server_is_rejected() {
    // The server key is generated per Acceptor, so a cookie is only openable
    // by the instance that issued it.
    let issuer = Acceptor::new([0x5A; 32]);
    let other = Acceptor::new([0x5A; 32]);
    let now = Timestamp::ZERO;

    let ticket = Ticket {
        expires_at: now.saturating_add(Duration::from_secs(60)),
        client_id: 1,
        session: None,
        keys: session_keys(1),
        user_data: UserData::new(),
    };

    let addr = "10.0.0.2:40000".parse().expect("literal address");
    let mut encrypted = [0u8; MAX_BLOB];
    let len = issuer
        .encrypt_cookie(
            now,
            addr,
            ClientNonce(0x5EED),
            ServerNonce(0x5E4F),
            TicketId([0x1D; TicketId::LEN]),
            &ticket,
            &mut encrypted,
        )
        .expect("encrypt");

    let mut packet: Packet = [0u8; MAX_DATAGRAM];
    encode_handshake(PacketKind::Response, &encrypted[..len], &mut packet).expect("frame");

    assert_eq!(
        other.decrypt_cookie(&packet[..HANDSHAKE_LEN]).err(),
        Some(HandshakeError::BadAuth)
    );
}

#[test]
fn undersized_handshake_packets_are_refused_before_any_work() {
    // A reply to a short packet would amplify, so the length check comes first.
    let acceptor = Acceptor::new([0x5A; 32]);
    let packet = [0u8; HANDSHAKE_LEN - 1];

    assert!(matches!(
        acceptor.decrypt_ticket(&packet),
        Err(HandshakeError::Undersized)
    ));
    assert!(matches!(
        acceptor.decrypt_cookie(&packet),
        Err(HandshakeError::Undersized)
    ));
}

#[test]
fn garbage_never_panics_the_handshake_decoders() {
    let acceptor = Acceptor::new([0x5A; 32]);
    let mut state = 0x9E37_79B9_7F4A_7C15u64;

    for _ in 0..2_000 {
        let mut packet = [0u8; HANDSHAKE_LEN];
        for chunk in packet.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let bytes = state.to_le_bytes();
            let take = chunk.len();
            chunk.copy_from_slice(&bytes[..take]);
        }

        let _ = acceptor.decrypt_ticket(&packet);
        let _ = acceptor.decrypt_cookie(&packet);
    }
}

#[test]
fn the_handshake_is_five_datagrams() {
    let mut pair = Pair::new(ORDERED, 1);

    // Each hop costs a pass: a packet produced while delivering is delivered
    // by the next pass, never the one that made it.

    // 1. The client opens with its ticket, padded so a reply cannot amplify.
    pair.pass();
    assert_eq!(pair.trace[0].kind(), Some(PacketKind::Request));
    assert_eq!(pair.trace[0].len, HANDSHAKE_LEN);
    assert_eq!(pair.server.num_connections(), 0, "a request allocates nothing");

    // 2. The server answers with a cookie, still holding no state.
    pair.pass();
    assert_eq!(pair.trace[1].kind(), Some(PacketKind::Challenge));
    assert_eq!(pair.trace[1].len, HANDSHAKE_LEN);
    assert_eq!(pair.server.num_connections(), 0, "a challenge allocates nothing");

    // 3. The client echoes the cookie, which proves it receives at its address.
    pair.pass();
    assert_eq!(pair.client_state(), ClientState::Responding);
    assert_eq!(pair.trace[2].kind(), Some(PacketKind::Response));
    assert_eq!(pair.server.num_connections(), 0, "the response has not been read yet");

    // 4. Only now does a connection exist, and its first packet is the
    //    acceptance frame.
    pair.pass();
    assert_eq!(pair.server.num_connections(), 1);
    assert_eq!(pair.trace[3].kind(), Some(PacketKind::Payload));

    // 5. Decrypting it is what acceptance means; the client answers with an
    //    acknowledgement.
    pair.pass();
    assert_eq!(pair.client_state(), ClientState::Connected);
    assert_eq!(pair.trace[4].kind(), Some(PacketKind::Payload));
    assert!(pair.trace[4].header().expect("payload").ack.is_some());

    // The server takes that acknowledgement and says nothing back: an ack-only
    // packet is not itself acknowledged, so the exchange stops.
    pair.pass();
    assert_eq!(pair.trace.len(), 5);
    assert!(pair.is_quiet());
}

#[test]
fn the_handshake_settles_with_one_connection() {
    let mut pair = Pair::new(ORDERED, 1);
    assert!(pair.settle(), "the exchange never went quiet");

    assert_eq!(pair.client_state(), ClientState::Connected);
    assert_eq!(pair.server.num_connections(), 1);

    let connected = pair
        .server_events
        .iter()
        .filter(|e| matches!(e, ServerEvent::Connected { resumed: false, .. }))
        .count();
    assert_eq!(connected, 1);
}

#[test]
fn every_payload_header_carries_the_connection_id_the_server_assigned() {
    let mut pair = Pair::new(ORDERED, 1);
    assert!(pair.settle());

    // Zero is a valid id: the first occupancy of the first slot on the first
    // shard. What matters is that both directions carry the one the server
    // assigned, since the server routes by it.
    let assigned = pair.server.connections()[0].id();
    
    assert_eq!(pair.client.connection().expect("connected").id(), assigned);
    let payloads: Vec<_> = pair
        .trace
        .iter()
        .filter(|d| d.kind() == Some(PacketKind::Payload))
        .collect();

    assert!(payloads.len() >= 2, "both directions sent one");
    for datagram in payloads {
        let header = datagram.header().expect("payload headers parse");
        assert_eq!(header.conn_id, assigned, "every payload names the assigned connection");
    }
}

#[test]
fn only_packets_worth_acknowledging_are_acknowledged() {
    // The rule that keeps the two sides from acknowledging each other forever,
    // and the one that keeps round-trip samples honest.
    let mut pair = Pair::new(ORDERED, 1);
    assert!(pair.settle());

    pair.client_send(0, b"something to ack");
    assert!(pair.settle());

    let acks: Vec<_> = pair
        .trace
        .iter()
        .filter_map(|d| d.header())
        .filter_map(|h| h.ack)
        .collect();

    assert!(!acks.is_empty(), "acknowledgements were exchanged");
    assert!(
        pair.is_quiet(),
        "the exchange stopped rather than acknowledging acknowledgements"
    );
}

#[test]
fn a_message_crosses_in_one_round() {
    let mut pair = Pair::new(ORDERED, 1);
    assert!(pair.settle());

    pair.client_send(0, b"hello");
    assert!(pair.settle());

    assert_eq!(pair.server_inbox, vec![(0u8, b"hello".to_vec())]);
}

#[test]
fn messages_cross_in_both_directions() {
    let mut pair = Pair::new(ORDERED, 1);
    assert!(pair.settle());

    pair.client_send(0, b"from the client");
    pair.server_send(0, b"from the server");
    assert!(pair.settle());

    assert_eq!(pair.server_inbox, vec![(0u8, b"from the client".to_vec())]);
    assert_eq!(pair.client_inbox, vec![(0u8, b"from the server".to_vec())]);
}

#[test]
fn ordered_messages_arrive_in_order() {
    let mut pair = Pair::new(ORDERED, 1);
    assert!(pair.settle());

    for n in 0..16u32 {
        pair.client_send(0, &n.to_le_bytes());
    }
    assert!(pair.run_until(Duration::from_millis(16), |p| p.server_inbox.len() >= 16));

    for (n, (channel, payload)) in pair.server_inbox.iter().enumerate() {
        assert_eq!(*channel, 0);
        assert_eq!(payload.as_slice(), &(n as u32).to_le_bytes());
    }
}

#[test]
fn a_reliable_message_is_acknowledged_and_sent_once() {
    // Nothing is lost here, so a reliable message has no reason to repeat.
    let mut pair = Pair::new(ORDERED, 1);
    assert!(pair.settle());

    let before = pair.trace.len();
    pair.client_send(0, b"once");
    assert!(pair.run_until(Duration::from_millis(16), |p| !p.server_inbox.is_empty()));
    assert!(pair.settle());

    assert_eq!(pair.server_inbox.len(), 1, "delivered exactly once");
    assert!(
        (pair.trace.len() - before) <= 4,
        "a single message took {} datagrams",
        pair.trace.len() - before
    );
}

#[test]
fn an_idle_connection_exchanges_keepalives() {
    let mut pair = Pair::new(ORDERED, 1);
    assert!(pair.settle());

    let before = pair.trace.len();
    // Past the one-second keepalive interval, well short of the ten-second
    // idle timeout.
    pair.advance(Duration::from_millis(1100));
    assert!(pair.settle());

    assert!(
        pair.trace.len() > before,
        "an idle connection must still prove the path works"
    );
    assert_eq!(pair.server.num_connections(), 1);
    assert_eq!(pair.client_state(), ClientState::Connected);
}

#[test]
fn an_idle_connection_survives_well_past_the_timeout() {
    let mut pair = Pair::new(ORDERED, 1);
    assert!(pair.settle());

    // Thirty seconds of no application traffic at all.
    for _ in 0..30 {
        pair.advance(Duration::from_secs(1));
        assert!(pair.settle());
    }

    assert_eq!(pair.server.num_connections(), 1, "the server timed a live client out");
    assert_eq!(pair.client_state(), ClientState::Connected);
}

#[test]
fn a_silent_client_is_timed_out_and_its_session_suspended() {
    let mut pair = Pair::new(ORDERED, 1);
    assert!(pair.settle());

    // The client stops being heard without sending a close notice, as a
    // crashed process would.
    pair.silence_client(true);

    for _ in 0..12 {
        pair.advance(Duration::from_secs(1));
        assert!(pair.settle());
    }

    assert_eq!(
        pair.server.num_connections(),
        0,
        "the server kept a connection it stopped hearing from"
    );
    assert!(
        pair.server_events
            .iter()
            .any(|e| matches!(e, ServerEvent::Disconnected { suspended: true, .. })),
        "an unexpected drop holds the session for the grace period"
    );
}

#[test]
fn a_closed_client_frees_the_server_slot() {
    let mut pair = Pair::new(ORDERED, 1);
    assert!(pair.settle());

    pair.client.close();
    assert!(pair.settle());

    assert_eq!(pair.server.num_connections(), 0);
    assert!(
        pair.server_events
            .iter()
            .any(|e| matches!(e, ServerEvent::Disconnected { suspended: false, .. })),
        "a deliberate close ends the session rather than suspending it"
    );
}

#[test]
fn a_settled_connection_sends_nothing() {
    // A repeated acknowledgement rides on packets that are going out anyway.
    // It must never be the reason one does, or an idle connection transmits at
    // the full tick rate for as long as it lives.
    let mut pair = Pair::new(ORDERED, 1);
    assert!(pair.settle());

    let settled = pair.trace.len();
    for _ in 0..20 {
        pair.pass();
    }

    assert_eq!(
        pair.trace.len(),
        settled,
        "an idle connection produced {} extra packets with the clock stopped",
        pair.trace.len() - settled
    );
}
