//! A group of endpoints sharing one address: every datagram reaches its owner,
//! and a ticket or session behaves as it does on a lone endpoint whichever
//! member a request happens to land on.

use std::net::SocketAddr;

use crate::{
    channel::{ChannelKind, ChannelSet},
    config::TransportConfig,
    connector::{Action as ClientAction, Connector, State},
    crypto::{Key, Keys, MAX_BLOB},
    ctx::Ctx,
    endpoint::{Action, Destinations, DropReason, Endpoint, EndpointConfig, Event, PacketSink},
    handshake::{EncryptedTicket, HandshakeError, SessionId, Ticket, TicketId, UserData, encrypt_ticket},
    packet::Packet,
    shard::{MAX_SHARDS, ShardCount, ShardGroup, ShardId},
    stats::{Counter, Counters},
    time::Timestamp,
    wire::{ConnectionId, GENERATION_BITS, MAX_DATAGRAM, owner_shard},
};

const CHANNELS: ChannelSet = ChannelSet::new([ChannelKind::ReliableOrdered]);
const BACKEND: Key = [0x5A; 32];
const SHARDS: usize = 4;

fn server() -> SocketAddr {
    "10.0.0.1:9000".parse().expect("literal address")
}

fn keys() -> Keys {
    Keys {
        client_to_server: [1; 32],
        server_to_client: [2; 32],
    }
}

fn group() -> Vec<Endpoint> {
    group_with_capacity(64)
}

fn group_with_capacity(capacity: u32) -> Vec<Endpoint> {
    let group = ShardGroup::new(ShardCount::new(SHARDS).expect("a valid size"));
    group
        .shards()
        .map(|shard| Endpoint::new(EndpointConfig::sharded(capacity, shard), BACKEND, &CHANNELS))
        .collect()
}

fn ticket(client_id: u64, session: Option<SessionId>) -> EncryptedTicket {
    let ticket = Ticket {
        expires_at: Timestamp::from_nanos(60_000_000_000),
        client_id,
        session,
        keys: keys(),
        user_data: UserData::new(),
    };
    let mut sealed = [0u8; MAX_BLOB];
    let len = encrypt_ticket(&BACKEND, &ticket, &mut sealed).expect("a ticket fits");
    EncryptedTicket::from_slice(&sealed[..len]).expect("a ticket fits")
}

fn connector(ticket: EncryptedTicket) -> Connector {
    Connector::connect(
        Timestamp::ZERO,
        server(),
        ticket,
        keys(),
        CHANNELS,
        TransportConfig::DEFAULT,
    )
}

/// One datagram in flight, copied out of whatever built it.
struct Datagram {
    bytes: Packet,
    len: usize,
}

impl Datagram {
    fn of(bytes: &Packet, len: usize) -> Datagram {
        Datagram { bytes: *bytes, len }
    }

    fn owner(&self) -> Option<ShardId> {
        owner_shard(&self.bytes[..self.len])
    }
}

/// Collects what one drain produces.
#[derive(Default)]
struct Sink {
    sent: Vec<(Destinations, Datagram)>,
    slot: Option<Packet>,
}

impl PacketSink for Sink {
    fn next_slot(&mut self) -> Option<&mut Packet> {
        Some(self.slot.insert([0u8; MAX_DATAGRAM]))
    }

    fn commit(&mut self, to: Destinations, len: usize) {
        let bytes = self.slot.take().expect("a slot was handed out");
        self.sent.push((to, Datagram::of(&bytes, len)));
    }
}

/// Delivers a datagram to one endpoint of the group. Returns the action and
/// the reply it wrote, if any.
fn deliver(
    endpoint: &mut Endpoint,
    counters: &mut Counters,
    from: SocketAddr,
    datagram: &Datagram,
) -> (Action, Datagram) {
    let mut ctx = Ctx::new(Timestamp::ZERO, counters);
    let mut buf = datagram.bytes;
    let mut out = [0u8; MAX_DATAGRAM];
    let action = endpoint.handle_datagram(&mut ctx, from, &mut buf, datagram.len, &mut out, &mut |_, _, _| {});
    let len = match action {
        Action::Respond { len, .. } => len,
        _ => 0,
    };
    (action, Datagram::of(&out, len))
}

/// The client's next handshake or payload packet.
fn transmit(client: &mut Connector, counters: &mut Counters) -> Datagram {
    let mut ctx = Ctx::new(Timestamp::ZERO, counters);
    let mut out = [0u8; MAX_DATAGRAM];
    let len = client
        .poll_transmit(&mut ctx, &mut out)
        .expect("the client has something to send");
    Datagram::of(&out, len)
}

/// Hands a datagram from the server to the client. Returns what it sent back.
fn receive(client: &mut Connector, counters: &mut Counters, datagram: &Datagram) -> Option<Datagram> {
    let mut ctx = Ctx::new(Timestamp::ZERO, counters);
    let mut buf = datagram.bytes;
    let mut out = [0u8; MAX_DATAGRAM];
    match client.handle_datagram(&mut ctx, server(), &mut buf, datagram.len, &mut out, &mut |_, _| {}) {
        ClientAction::Send(len) => Some(Datagram::of(&out, len)),
        _ => None,
    }
}

/// Any member other than `home`.
fn elsewhere(home: ShardId) -> usize {
    (home.index() + 1) % SHARDS
}

/// Runs a handshake for a ticket naming `session`, whose request lands on a
/// shard other than the ticket's home. Returns the client, the home shard,
/// and what the home made of the response.
fn handshake_via_another_shard(
    endpoints: &mut [Endpoint],
    counters: &mut Counters,
    from: SocketAddr,
    client_id: u64,
    session: Option<SessionId>,
) -> (Connector, ShardId, Action) {
    let sealed = ticket(client_id, session);
    handshake_with(endpoints, counters, from, sealed, session)
}

/// As `handshake_via_another_shard`, presenting a ticket already sealed.
fn handshake_with(
    endpoints: &mut [Endpoint],
    counters: &mut Counters,
    from: SocketAddr,
    sealed: EncryptedTicket,
    session: Option<SessionId>,
) -> (Connector, ShardId, Action) {
    let mut client = connector(sealed);
    let request = transmit(&mut client, counters);
    assert_eq!(request.owner(), None, "a request may be answered anywhere");

    let ticket_id = TicketId::of_request(&request.bytes[..request.len]).expect("a request carries its ticket");
    let home = ShardCount::new(SHARDS)
        .and_then(|count| count.home(session, ticket_id))
        .expect("the ticket has a home");

    let (action, challenge) = deliver(&mut endpoints[elsewhere(home)], counters, from, &request);
    assert!(matches!(action, Action::Respond { .. }), "{action:?}");

    let response = receive(&mut client, counters, &challenge).expect("the challenge is answered");
    assert_eq!(
        response.owner(),
        Some(home),
        "the response is addressed to the ticket's home"
    );

    let misrouted = counters.get(Counter::PacketsMisrouted);
    let (action, _) = deliver(&mut endpoints[elsewhere(home)], counters, from, &response);
    assert_eq!(action, Action::Forward(home));
    assert_eq!(counters.get(Counter::PacketsMisrouted), misrouted + 1);

    let (action, _) = deliver(&mut endpoints[home.index()], counters, from, &response);
    (client, home, action)
}

/// Delivers the home's pending packets to the client.
fn flush_to_client(endpoint: &mut Endpoint, client: &mut Connector, counters: &mut Counters) {
    let mut sink = Sink::default();
    endpoint.drain_transmits(&mut Ctx::new(Timestamp::ZERO, counters), &mut sink);
    for (_, datagram) in &sink.sent {
        let _ = receive(client, counters, datagram);
    }
}

#[test]
fn ids_carry_their_shard_slot_and_generation() {
    let top_slot = ConnectionId::SLOTS - 1;
    let top_generation = (1u32 << GENERATION_BITS) - 1;
    for shard in ShardCount::new(MAX_SHARDS).expect("the largest group").ids() {
        for (slot, generation) in [(0, 0), (1, 1), (top_slot, top_generation), (0x1234, 0x2A5)] {
            let id = ConnectionId::new(slot, generation, shard);
            assert_eq!((id.shard(), id.slot(), id.generation()), (shard, slot, generation));
        }
        assert_eq!(SessionId::new(u64::MAX, shard).shard(), shard);
    }
    assert_eq!(
        ConnectionId::new(0, 1 << GENERATION_BITS, ShardId::FIRST),
        ConnectionId::new(0, 0, ShardId::FIRST),
        "a wrapped generation starts over"
    );
}

#[test]
fn group_sizes_outside_the_id_space_do_not_exist() {
    assert_eq!(ShardCount::new(0), None);
    assert_eq!(ShardCount::new(MAX_SHARDS + 1), None);
    let group = ShardGroup::new(ShardCount::new(3).expect("a valid size"));
    assert!(group.shard(ShardId::from_byte(2)).is_some());
    assert!(group.shard(ShardId::from_byte(3)).is_none());
}

#[test]
fn new_players_spread_over_every_shard() {
    let count = ShardCount::new(SHARDS).expect("a valid size");
    let mut seen = [0u32; SHARDS];
    for n in 0..4096u32 {
        let mut id = [0u8; TicketId::LEN];
        id[..4].copy_from_slice(&n.wrapping_mul(0x9E37_79B9).to_le_bytes());
        let home = count.home(None, TicketId(id)).expect("a new player always has a home");
        seen[home.index()] += 1;
    }
    assert!(seen.iter().all(|&n| n > 900), "{seen:?}");
}

#[test]
fn a_handshake_started_on_one_shard_completes_on_the_tickets_home() {
    let mut endpoints = group();
    let mut counters = Counters::new();
    let from: SocketAddr = "192.0.2.10:40000".parse().expect("literal address");

    let (mut client, home, action) = handshake_via_another_shard(&mut endpoints, &mut counters, from, 7, None);
    let Action::Connected(handle) = action else { panic!("the home accepted: {action:?}") };

    let conn_id = endpoints[home.index()]
        .connection(handle)
        .expect("the connection exists")
        .id();
    assert_eq!(conn_id.shard(), home, "the home issues ids carrying its own shard");
    for (index, endpoint) in endpoints.iter().enumerate() {
        let expected = usize::from(index == home.index());
        assert_eq!(endpoint.num_connections(), expected, "shard {index}");
    }

    flush_to_client(&mut endpoints[home.index()], &mut client, &mut counters);
    assert_eq!(client.state(), State::Connected);

    client
        .connection_mut()
        .expect("connected")
        .send(0, b"ping")
        .expect("room to send");
    let payload = transmit(&mut client, &mut counters);
    assert_eq!(payload.owner(), Some(home), "a payload names its connection's shard");

    let (action, _) = deliver(&mut endpoints[elsewhere(home)], &mut counters, from, &payload);
    assert_eq!(action, Action::Forward(home));
    let (action, _) = deliver(&mut endpoints[home.index()], &mut counters, from, &payload);
    assert_eq!(action, Action::Routed(handle));
}

#[test]
fn a_resume_returns_to_the_shard_holding_the_session() {
    let mut endpoints = group();
    let mut counters = Counters::new();
    let first: SocketAddr = "192.0.2.20:40000".parse().expect("literal address");

    let (_, home, action) = handshake_via_another_shard(&mut endpoints, &mut counters, first, 9, None);
    assert!(matches!(action, Action::Connected(_)), "{action:?}");
    let session = match endpoints[home.index()].poll_event() {
        Some(Event::Connected { session, resumed: false, .. }) => session,
        other => panic!("expected a new session, got {other:?}"),
    };
    assert_eq!(session.shard(), home, "a session carries the shard holding it");

    // Relaunched, from a new port, which the kernel may hash anywhere.
    let second: SocketAddr = "192.0.2.20:40001".parse().expect("literal address");
    let (_, resumed_on, action) = handshake_via_another_shard(&mut endpoints, &mut counters, second, 9, Some(session));
    assert_eq!(resumed_on, home);
    assert!(matches!(action, Action::Connected(_)), "{action:?}");
    assert!(
        matches!(
            endpoints[home.index()].poll_event(),
            Some(Event::Connected { resumed: true, session: resumed, .. }) if resumed == session
        ),
        "the session was taken over where it lives"
    );
}

#[test]
fn a_ticket_stays_single_use_whichever_shard_its_copy_reaches() {
    let mut endpoints = group();
    let mut counters = Counters::new();
    let sealed = ticket(11, None);

    let owner: SocketAddr = "192.0.2.30:40000".parse().expect("literal address");
    let (_, home, action) = handshake_with(&mut endpoints, &mut counters, owner, sealed, None);
    let Action::Connected(handle) = action else { panic!("the owner connected: {action:?}") };

    let thief: SocketAddr = "198.51.100.66:50000".parse().expect("literal address");
    let (_, copied_home, action) = handshake_with(&mut endpoints, &mut counters, thief, sealed, None);
    assert_eq!(copied_home, home, "every copy of a ticket has the same home");
    assert_eq!(
        action,
        Action::Connected(handle),
        "treated as the owner's retry, answered at the owner's address"
    );

    let connections: usize = endpoints.iter().map(Endpoint::num_connections).sum();
    assert_eq!(connections, 1, "the copy produced no connection anywhere");
}

#[test]
fn a_session_no_member_can_hold_is_refused_at_the_request() {
    let mut endpoints = group();
    let mut counters = Counters::new();
    let from: SocketAddr = "192.0.2.40:40000".parse().expect("literal address");

    let mut client = connector(ticket(13, Some(SessionId::new(1, ShardId::from_byte(SHARDS as u8)))));
    let request = transmit(&mut client, &mut counters);
    let (action, _) = deliver(&mut endpoints[0], &mut counters, from, &request);
    assert_eq!(
        action,
        Action::Dropped(DropReason::Handshake(HandshakeError::NoSession))
    );
}

#[test]
fn a_datagram_naming_a_shard_outside_the_group_is_dropped() {
    let mut endpoints = group();
    let mut counters = Counters::new();
    let from: SocketAddr = "192.0.2.50:40000".parse().expect("literal address");

    let mut bytes = [0u8; MAX_DATAGRAM];
    bytes[1..5].copy_from_slice(&ConnectionId::new(1, 1, ShardId::from_byte(200)).0.to_le_bytes());
    let (action, _) = deliver(&mut endpoints[0], &mut counters, from, &Datagram::of(&bytes, 64));
    assert_eq!(action, Action::Dropped(DropReason::NoSuchShard));
    assert_eq!(counters.get(Counter::PacketsMisrouted), 0);
}

#[test]
fn a_packet_for_an_earlier_occupant_of_a_slot_is_not_routed() {
    let mut endpoints = group();
    let mut counters = Counters::new();
    let from: SocketAddr = "192.0.2.60:40000".parse().expect("literal address");

    let (mut client, home, action) = handshake_via_another_shard(&mut endpoints, &mut counters, from, 15, None);
    assert!(matches!(action, Action::Connected(_)), "{action:?}");
    flush_to_client(&mut endpoints[home.index()], &mut client, &mut counters);

    client
        .connection_mut()
        .expect("connected")
        .send(0, b"ping")
        .expect("room to send");
    let mut payload = transmit(&mut client, &mut counters);

    // The same slot, one occupancy earlier: what a delayed packet from the
    // slot's previous connection carries.
    let id = ConnectionId(u32::from_le_bytes(payload.bytes[1..5].try_into().expect("four bytes")));
    let earlier = ConnectionId::new(id.slot(), id.generation().wrapping_sub(1), id.shard());
    payload.bytes[1..5].copy_from_slice(&earlier.0.to_le_bytes());

    let (action, _) = deliver(&mut endpoints[home.index()], &mut counters, from, &payload);
    assert_eq!(action, Action::Dropped(DropReason::UnknownConnection));
}

#[test]
fn a_full_shard_refuses_a_takeover_without_closing_the_held_connection() {
    let mut endpoints = group_with_capacity(1);
    let mut counters = Counters::new();
    let first: SocketAddr = "192.0.2.70:40000".parse().expect("literal address");

    let (_, home, action) = handshake_via_another_shard(&mut endpoints, &mut counters, first, 17, None);
    let Action::Connected(held) = action else {
        panic!("the first connection was accepted: {action:?}")
    };
    let session = match endpoints[home.index()].poll_event() {
        Some(Event::Connected { session, .. }) => session,
        other => panic!("expected a new session, got {other:?}"),
    };

    let second: SocketAddr = "192.0.2.70:40001".parse().expect("literal address");
    let (_, _, action) = handshake_via_another_shard(&mut endpoints, &mut counters, second, 17, Some(session));
    assert_eq!(action, Action::Dropped(DropReason::Full));
    assert!(
        endpoints[home.index()]
            .connection(held)
            .is_some_and(|conn| conn.is_open()),
        "the held connection keeps its session"
    );
}
