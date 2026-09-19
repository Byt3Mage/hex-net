//! End-to-end transport tests over the simulated network.

use std::net::SocketAddr;
use std::time::Duration;

use hex_net_core::budget::BudgetConfig;
use hex_net_core::channel::{ChannelKind, ChannelSet};
use hex_net_core::connector::{Action as ClientAction, Connector, State as ClientState};
use hex_net_core::crypto::{Key, Keys, MAX_BLOB};
use hex_net_core::ctx::Ctx;
use hex_net_core::endpoint::{
    Action as ServerAction, Destinations, Endpoint, EndpointConfig, Event as ServerEvent, PacketSink,
};
use hex_net_core::handshake::{EncryptedTicket, Ticket, UserData, encrypt_ticket};
use hex_net_core::packet::Packet;
use hex_net_core::stats::Counters;
use hex_net_core::time::Timestamp;
use hex_net_core::wire::MAX_DATAGRAM;

use crate::{LinkConfig, Network, Rng};

/// Datagrams produced in one transmit pass.
const BATCH: usize = 16;

/// Upper bound on iterations, so a test that never reaches its condition fails
/// rather than hanging.
const MAX_STEPS: usize = 20_000;

/// Service passes within one step. A zero-latency link delivers a packet the
/// instant it is sent, so without a cap the inner loop would never finish.
const MAX_PASSES_PER_STEP: usize = 64;

fn keys(seed: u64) -> Keys {
    let mut rng = Rng::new(seed);
    let mut make = || {
        let mut key: Key = [0u8; 32];
        for chunk in key.chunks_mut(8) {
            let bytes = rng.next_u64().to_le_bytes();
            let take = chunk.len();
            chunk.copy_from_slice(&bytes[..take]);
        }
        key
    };
    Keys { client_to_server: make(), server_to_client: make() }
}

/// Stands in for whatever a backend issues after authenticating a player.
fn issue_ticket(backend_key: &Key, now: Timestamp, client_id: u64, session_keys: &Keys) -> EncryptedTicket {
    let ticket = Ticket {
        expires_at: now.saturating_add(Duration::from_secs(60)),
        // A real backend would draw this from its own counter or a random
        // source; one per issued ticket is all the server requires.
        token_id: client_id,
        client_id,
        session: None,
        keys: *session_keys,
        user_data: UserData::new(),
    };
    let mut encrypted = [0u8; MAX_BLOB];
    let len = encrypt_ticket(backend_key, &ticket, &mut encrypted).expect("ticket fits");
    EncryptedTicket::from_slice(&encrypted[..len]).unwrap()
}
/// Collects packets from a transmit pass, then hands them to the network.
struct Batch {
    buffers: Vec<Packet>,
    outgoing: Vec<(SocketAddr, usize)>,
    next: usize,
}

impl Batch {
    fn new() -> Self {
        Self {
            buffers: std::iter::repeat_n([0u8; MAX_DATAGRAM], BATCH).collect(),
            outgoing: Vec::new(),
            next: 0,
        }
    }

    fn reset(&mut self) {
        self.outgoing.clear();
        self.next = 0;
    }
}

impl PacketSink for Batch {
    fn next_slot(&mut self) -> Option<&mut Packet> {
        if self.next >= self.buffers.len() {
            return None;
        }
        Some(&mut self.buffers[self.next])
    }

    fn commit(&mut self, to: Destinations, len: usize) {
        self.outgoing.push((to.primary, len));
        let written = self.next;
        self.next += 1;

        // A probe gets a copy of the same packet, so both the old and the new
        // address see it while validation is in progress.
        if let Some(probe) = to.probe
            && self.next < self.buffers.len()
        {
            let (done, rest) = self.buffers.split_at_mut(self.next);
            rest[0][..len].copy_from_slice(&done[written][..len]);
            self.outgoing.push((probe, len));
            self.next += 1;
        }
    }
}

/// One client under test.
struct Client {
    connector: Connector,
    addr: SocketAddr,
    /// Messages delivered to this client, as (channel, payload).
    received: Vec<(u8, Vec<u8>)>,
}

/// A server, some clients, and the network between them.
struct Harness {
    net: Network,
    server: Endpoint,
    server_addr: SocketAddr,
    clients: Vec<Client>,

    backend_key: Key,
    channels: ChannelSet,
    budget: BudgetConfig,

    counters: Counters,
    batch: Batch,
    scratch: Box<Packet>,
    out: Box<Packet>,

    /// Everything the endpoint has emitted.
    events: Vec<ServerEvent>,
    /// Messages the server received, as (source address, channel, payload).
    server_received: Vec<(SocketAddr, u8, Vec<u8>)>,

    step: Duration,
}

impl Harness {
    fn new<const N: usize>(seed: u64, capacity: u32, server_link: LinkConfig, channels: [ChannelKind; N]) -> Self {
        let mut net = Network::new(seed);
        let server_addr = net.add_host(server_link);
        let backend_key = [0x5Au8; 32];
        let channels = ChannelSet::new(channels);

        Self {
            net,
            server: Endpoint::new(EndpointConfig::new(capacity), backend_key, &channels),
            server_addr,
            clients: Vec::new(),
            backend_key,
            channels,
            budget: BudgetConfig::DEFAULT,
            counters: Counters::new(),
            batch: Batch::new(),
            scratch: Box::new([0u8; MAX_DATAGRAM]),
            out: Box::new([0u8; MAX_DATAGRAM]),
            events: Vec::new(),
            server_received: Vec::new(),
            step: Duration::from_millis(16),
        }
    }

    #[inline]
    fn now(&self) -> Timestamp {
        self.net.now()
    }

    /// Adds a client and starts its handshake. Returns its index.
    fn connect(&mut self, link: LinkConfig, client_id: u64) -> usize {
        let addr = self.net.add_host(link);
        let session_keys = keys(client_id.wrapping_mul(0x9E37_79B9) | 1);
        let ticket = issue_ticket(&self.backend_key, self.now(), client_id, &session_keys);

        let connector = Connector::connect(
            self.now(),
            self.server_addr,
            ticket,
            session_keys,
            self.channels,
            self.budget,
        );

        self.clients.push(Client { connector, addr, received: Vec::new() });
        self.clients.len() - 1
    }

    /// Advances one step, servicing every party at each intermediate delivery so
    /// packets due mid-step are not held back to the boundary.
    fn step(&mut self) {
        let until = self.net.now().saturating_add(self.step);

        for _ in 0..MAX_PASSES_PER_STEP {
            let Some(at) = self.net.next_delivery() else { break };
            if at > until {
                break;
            }
            self.net.advance_to(at);
            self.service();
        }
        self.net.advance_to(until);
        self.service();
    }

    fn run_until(&mut self, mut condition: impl FnMut(&Self) -> bool) -> bool {
        for _ in 0..MAX_STEPS {
            if condition(self) {
                return true;
            }
            self.step();
        }
        condition(self)
    }

    fn run_for(&mut self, duration: Duration) {
        let until = self.net.now().saturating_add(duration);
        while self.net.now() < until {
            self.step();
        }
    }

    fn service(&mut self) {
        self.service_server();
        self.service_clients();
    }

    fn service_server(&mut self) {
        let now = self.net.now();

        // Fields are destructured so the endpoint and the network can be
        // borrowed at once; they are disjoint, which a method call would hide.
        let Harness {
            net,
            server,
            server_addr,
            counters,
            batch,
            scratch,
            out,
            events,
            server_received,
            ..
        } = self;

        while let Some(received) = net.recv(*server_addr, scratch) {
            let mut ctx = Ctx::new(received.at, counters);
            let mut inbound: Vec<(u8, Vec<u8>)> = Vec::new();
            let mut on_message = |channel, payload: &[u8]| inbound.push((channel, payload.to_vec()));

            let action = server.handle_datagram(&mut ctx, received.from, scratch, received.len, out, &mut on_message);

            for (channel, payload) in inbound {
                server_received.push((received.from, channel, payload));
            }

            if let ServerAction::Respond { addr, len } = action {
                net.send(*server_addr, addr, &out[..len]);
            }
        }

        let mut ctx = Ctx::new(now, counters);
        server.handle_timeout(&mut ctx);
        while let Some(event) = server.poll_event() {
            events.push(event);
        }

        batch.reset();
        server.drain_transmits(&mut ctx, batch);
        for (index, (addr, len)) in batch.outgoing.iter().copied().enumerate() {
            net.send(*server_addr, addr, &batch.buffers[index][..len]);
        }
    }

    fn service_clients(&mut self) {
        let now = self.net.now();

        let Harness {
            net, clients, counters, scratch, out, server_addr, ..
        } = self;

        for client in clients.iter_mut() {
            while let Some(received) = net.recv(client.addr, scratch) {
                let mut ctx = Ctx::new(received.at, counters);
                let mut inbound: Vec<(u8, Vec<u8>)> = Vec::new();

                let action = {
                    let mut on_message = |channel: u8, payload: &[u8]| {
                        inbound.push((channel, payload.to_vec()));
                    };
                    client.connector.handle_datagram(
                        &mut ctx,
                        received.from,
                        scratch,
                        received.len,
                        out,
                        &mut on_message,
                    )
                };

                client.received.extend(inbound);

                if let ClientAction::Send(len) = action {
                    net.send(client.addr, *server_addr, &out[..len]);
                }
            }

            let mut ctx = Ctx::new(now, counters);
            client.connector.handle_timeout(&mut ctx);

            if let Some(len) = client.connector.poll_transmit(&mut ctx, out) {
                net.send(client.addr, *server_addr, &out[..len]);
            }
        }
    }

    fn all_connected(&self) -> bool {
        !self.clients.is_empty()
            && self
                .clients
                .iter()
                .all(|c| c.connector.state() == ClientState::Connected)
    }

    fn client_send(&mut self, index: usize, channel: u8, payload: &[u8]) {
        self.clients[index]
            .connector
            .connection_mut()
            .expect("connected")
            .send(channel, payload)
            .expect("send queued");
    }

    fn server_send_all(&mut self, channel: u8, payload: &[u8]) {
        for conn in self.server.connections_mut() {
            conn.send(channel, payload).expect("send queued");
        }
    }
}

const RELIABLE_ORDERED: [ChannelKind; 1] = [ChannelKind::ReliableOrdered];
const FOUR_KINDS: [ChannelKind; 4] = [
    ChannelKind::Unreliable,
    ChannelKind::UnreliableSequenced,
    ChannelKind::ReliableUnordered,
    ChannelKind::ReliableOrdered,
];

#[test]
fn handshake_completes_on_a_perfect_link() {
    let mut h = Harness::new(1, 16, LinkConfig::PERFECT, RELIABLE_ORDERED);
    h.connect(LinkConfig::PERFECT, 1);

    assert!(h.run_until(|h| h.all_connected()), "handshake did not complete");
    assert_eq!(h.server.len(), 1);
}

#[test]
fn handshake_survives_heavy_loss() {
    let mut h = Harness::new(0xC0FFEE, 16, LinkConfig::AWFUL, RELIABLE_ORDERED);
    h.connect(LinkConfig::AWFUL, 1);

    assert!(h.run_until(|h| h.all_connected()), "handshake failed under loss");
    assert!(h.net.dropped_loss > 0, "the test did not exercise loss");
}

#[test]
fn many_clients_connect() {
    let mut h = Harness::new(42, 64, LinkConfig::GOOD, RELIABLE_ORDERED);
    for id in 0..32u64 {
        h.connect(LinkConfig::POOR, id + 1);
    }

    assert!(h.run_until(|h| h.all_connected()), "not every client connected");
    assert_eq!(h.server.len(), 32);

    let connected = h
        .events
        .iter()
        .filter(|e| matches!(e, ServerEvent::Connected { .. }))
        .count();
    assert_eq!(connected, 32);
}

#[test]
fn reliable_messages_arrive_in_order_under_loss() {
    let mut h = Harness::new(7, 16, LinkConfig::POOR, RELIABLE_ORDERED);
    let client = h.connect(LinkConfig::POOR, 1);
    assert!(h.run_until(|h| h.all_connected()));

    for n in 0..40u32 {
        h.client_send(client, 0, &n.to_le_bytes());
    }

    let arrived = h.run_until(|h| h.server_received.len() >= 40);
    assert!(arrived, "only {} of 40 arrived", h.server_received.len());

    for (n, (_, channel, payload)) in h.server_received.iter().enumerate().take(40) {
        assert_eq!(*channel, 0);
        assert_eq!(payload.as_slice(), &(n as u32).to_le_bytes());
    }
}

#[test]
fn every_channel_kind_delivers() {
    let mut h = Harness::new(99, 16, LinkConfig::GOOD, FOUR_KINDS);
    let client = h.connect(LinkConfig::GOOD, 1);
    assert!(h.run_until(|h| h.all_connected()));

    for channel in 0..4u8 {
        h.client_send(client, channel, &[channel; 8]);
    }

    assert!(
        h.run_until(|h| h.server_received.len() >= 4),
        "only {} of 4 arrived",
        h.server_received.len()
    );

    let mut seen: Vec<u8> = h.server_received.iter().map(|(_, c, _)| *c).collect();
    seen.sort_unstable();
    assert_eq!(seen, vec![0, 1, 2, 3]);
}

#[test]
fn messages_flow_from_server_to_client() {
    let mut h = Harness::new(11, 16, LinkConfig::POOR, RELIABLE_ORDERED);
    let client = h.connect(LinkConfig::POOR, 1);
    assert!(h.run_until(|h| h.all_connected()));

    for n in 0..20u32 {
        h.server_send_all(0, &n.to_le_bytes());
    }

    assert!(
        h.run_until(|h| h.clients[client].received.len() >= 20),
        "only {} of 20 arrived",
        h.clients[client].received.len()
    );

    for (n, (channel, payload)) in h.clients[client].received.iter().enumerate().take(20) {
        assert_eq!(*channel, 0);
        assert_eq!(payload.as_slice(), &(n as u32).to_le_bytes());
    }
}

#[test]
fn rtt_converges_on_the_links_latency() {
    let mut h = Harness::new(3, 16, LinkConfig::GOOD, RELIABLE_ORDERED);
    let client = h.connect(LinkConfig::GOOD, 1);
    assert!(h.run_until(|h| h.all_connected()));

    h.run_for(Duration::from_secs(5));

    let rtt = h.clients[client]
        .connector
        .connection()
        .expect("connected")
        .rtt()
        .smoothed();

    // 15ms each way plus up to 3ms of jitter, so a round trip is 30-36ms.
    assert!(
        (rtt >= Duration::from_millis(25)) && (rtt <= Duration::from_millis(60)),
        "round trip estimate {rtt:?} is implausible for this link"
    );
}

#[test]
fn an_idle_connection_stays_alive_on_keepalives() {
    let mut h = Harness::new(5, 16, LinkConfig::GOOD, RELIABLE_ORDERED);
    h.connect(LinkConfig::GOOD, 1);
    assert!(h.run_until(|h| h.all_connected()));

    // Well past the ten-second idle timeout with no application traffic.
    h.run_for(Duration::from_secs(30));

    assert_eq!(h.server.len(), 1, "the server timed the connection out");
    assert!(h.all_connected(), "the client lost its connection");
}

#[test]
fn a_closed_client_frees_its_slot() {
    let mut h = Harness::new(13, 16, LinkConfig::GOOD, RELIABLE_ORDERED);
    let client = h.connect(LinkConfig::GOOD, 1);
    assert!(h.run_until(|h| h.all_connected()));

    h.clients[client].connector.close();
    assert!(h.run_until(|h| h.server.is_empty()), "the server kept the connection");

    let disconnected = h
        .events
        .iter()
        .any(|e| matches!(e, ServerEvent::Disconnected { suspended: false, .. }));
    assert!(disconnected, "a deliberate close should end the session");
}

#[test]
fn a_vanished_client_suspends_its_session() {
    let mut h = Harness::new(17, 16, LinkConfig::GOOD, RELIABLE_ORDERED);
    h.connect(LinkConfig::GOOD, 1);
    assert!(h.run_until(|h| h.all_connected()));

    // No close notice: the client simply stops, as a crashed process would.
    h.clients.clear();

    assert!(
        h.run_until(|h| h.server.is_empty()),
        "the server did not time the connection out"
    );

    let suspended = h
        .events
        .iter()
        .any(|e| matches!(e, ServerEvent::Disconnected { suspended: true, .. }));
    assert!(suspended, "an unexpected drop should suspend the session");
}

#[test]
fn a_retried_handshake_does_not_create_a_second_connection() {
    // A lost acceptance makes the client resend its Response. The server must
    // recognise the ticket and answer the connection it already made.
    let mut h = Harness::new(23, 16, LinkConfig::POOR, RELIABLE_ORDERED);
    h.connect(LinkConfig::AWFUL, 1);

    assert!(h.run_until(|h| h.all_connected()), "handshake did not complete");
    h.run_for(Duration::from_secs(3));

    assert_eq!(h.server.len(), 1, "the retries produced extra connections");

    let connected = h
        .events
        .iter()
        .filter(|e| matches!(e, ServerEvent::Connected { .. }))
        .count();
    assert_eq!(connected, 1, "the server accepted the same ticket twice");
}
