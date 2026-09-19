//! One client, one server, and a wire between them.
//!
//! No loss, no latency, no scheduling: a datagram that is sent is on the wire,
//! and a datagram that is delivered is gone. The point is to watch the two
//! sides talk and assert on every packet that crosses, before anything is
//! simulated.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;

use hex_net_core::{
    budget::BudgetConfig,
    channel::ChannelSet,
    connector::{Action as ClientAction, Connector, State as ClientState},
    crypto::{Key, Keys, MAX_BLOB},
    ctx::Ctx,
    endpoint::{
        Action as ServerAction, Destinations, DropReason, Endpoint, EndpointConfig, Event as ServerEvent, PacketSink,
    },
    handshake::{EncryptedTicket, SessionId, Ticket, UserData, encrypt_ticket},
    packet::Packet,
    stats::Counters,
    time::Timestamp,
    wire::{Header, MAX_DATAGRAM, PacketKind},
};

/// Passes `settle` will run before giving up, so a test that never quiesces
/// fails rather than hanging.
const SETTLE_LIMIT: usize = 64;

/// A datagram as it crossed the wire, kept for inspection.
pub struct Datagram {
    pub from: SocketAddr,
    pub to: SocketAddr,
    pub len: usize,
    data: Packet,
}

impl Datagram {
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// The packet kind from the first byte, as a receiver would route on it.
    pub fn kind(&self) -> Option<PacketKind> {
        (self.len > 0).then(|| PacketKind::from_byte(self.data[0])).flatten()
    }

    /// The cleartext header, for payload packets. Handshake packets have none.
    pub fn header(&self) -> Option<Header> {
        if self.kind() != Some(PacketKind::Payload) {
            return None;
        }
        Header::decode(self.bytes()).ok().map(|(header, _)| header)
    }
}

/// Messages an application received, as (channel, payload).
pub type Inbox = Vec<(u8, Vec<u8>)>;

/// Collects packets from `drain_transmits` onto the wire.
///
/// One slot, reused: `commit` copies out, so the same buffer serves every
/// packet in a pass. Never returns `None`, since a single connection cannot
/// outrun it.
struct Outbox<'a> {
    queue: &'a mut VecDeque<Datagram>,
    trace: &'a mut Vec<Datagram>,
    from: SocketAddr,
    slot: Box<Packet>,
}

impl PacketSink for Outbox<'_> {
    fn next_slot(&mut self) -> Option<&mut Packet> {
        Some(&mut self.slot)
    }

    fn commit(&mut self, to: Destinations, len: usize) {
        push(self.queue, self.trace, self.from, to.primary, &self.slot[..len]);

        // While a path is being validated the same packet goes to both the old
        // address and the one under test.
        if let Some(probe) = to.probe {
            push(self.queue, self.trace, self.from, probe, &self.slot[..len]);
        }
    }
}

fn push(queue: &mut VecDeque<Datagram>, trace: &mut Vec<Datagram>, from: SocketAddr, to: SocketAddr, bytes: &[u8]) {
    let mut data = [0u8; MAX_DATAGRAM];
    let len = bytes.len().min(MAX_DATAGRAM);
    data[..len].copy_from_slice(&bytes[..len]);

    trace.push(Datagram { from, to, len, data });
    queue.push_back(Datagram { from, to, len, data });
}

/// A server and a client with a wire between them.
pub struct Pair {
    now: Timestamp,

    pub server: Endpoint,
    pub server_addr: SocketAddr,
    pub server_counters: Counters,
    /// Events the endpoint has emitted, oldest first.
    pub server_events: Vec<ServerEvent>,
    pub server_inbox: Inbox,
    pub server_actions: Vec<ServerAction>,

    pub client: Connector,
    pub client_addr: SocketAddr,
    pub client_counters: Counters,
    pub client_inbox: Inbox,
    pub client_actions: Vec<ClientAction>,
    pub client_silenced: bool,

    to_server: VecDeque<Datagram>,
    to_client: VecDeque<Datagram>,

    /// Every datagram that has crossed, in order.
    pub trace: Vec<Datagram>,

    scratch: Box<Packet>,
    out: Box<Packet>,
}

impl Pair {
    /// Builds a pair whose client already holds a ticket for the server.
    ///
    /// `client_id` and `token_id` are the backend's to choose; one ticket per
    /// connection attempt is all the server requires.
    pub fn new(channels: ChannelSet, client_id: u64) -> Self {
        let now = Timestamp::ZERO;
        let backend_key: Key = [0x5A; 32];
        let server_addr: SocketAddr = str::parse("10.0.0.1:9000").expect("literal address");
        let client_addr: SocketAddr = str::parse("10.0.0.2:40000").expect("literal address");

        let keys = session_keys(client_id);
        let ticket = issue_ticket(&backend_key, now, client_id, client_id, None, &keys);

        Self {
            now,
            server: Endpoint::new(EndpointConfig::new(16), backend_key, &channels),
            server_addr,
            server_counters: Counters::new(),
            server_events: Vec::new(),
            server_inbox: Vec::new(),
            server_actions: Vec::new(),

            client: Connector::connect(now, server_addr, ticket, keys, channels, BudgetConfig::DEFAULT),
            client_addr,
            client_counters: Counters::new(),
            client_inbox: Vec::new(),
            client_actions: Vec::new(),
            client_silenced: false,

            to_server: VecDeque::new(),
            to_client: VecDeque::new(),
            trace: Vec::new(),
            scratch: Box::new([0u8; MAX_DATAGRAM]),
            out: Box::new([0u8; MAX_DATAGRAM]),
        }
    }

    #[inline]
    pub fn now(&self) -> Timestamp {
        self.now
    }

    /// Moves the clock. Delivers nothing on its own: a pass does that.
    pub fn advance(&mut self, by: Duration) {
        self.now = self.now.saturating_add(by);
    }

    #[inline]
    pub fn is_quiet(&self) -> bool {
        self.to_server.is_empty() && self.to_client.is_empty()
    }

    #[inline]
    pub fn client_state(&self) -> ClientState {
        self.client.state()
    }

    /// One pass: deliver what is on the wire, run both sides' timers, then let
    /// both sides transmit.
    ///
    /// Delivery takes a snapshot, so a packet produced during this pass is
    /// delivered by the next one. That bounds a pass even though the wire has
    /// no latency.
    pub fn pass(&mut self) {
        self.deliver();
        self.tick();
        self.transmit();
    }

    /// Runs passes until nothing is in flight. Returns false if it never
    /// quiesced, which means something is producing a packet every pass.
    pub fn settle(&mut self) -> bool {
        for _ in 0..SETTLE_LIMIT {
            self.pass();
            if self.is_quiet() {
                return true;
            }
        }
        false
    }

    /// Runs passes until `condition` holds, advancing the clock by `step`
    /// between them. Returns false if it never held.
    pub fn run_until(&mut self, step: Duration, mut condition: impl FnMut(&Self) -> bool) -> bool {
        for _ in 0..SETTLE_LIMIT {
            if condition(self) {
                return true;
            }
            self.pass();
            if self.is_quiet() {
                self.advance(step);
            }
        }
        condition(self)
    }

    /// Discards everything the client sends from here on, modelling a crashed
    /// process rather than an orderly close.
    pub fn drop_client_traffic(&mut self) {
        self.to_server.clear();
    }

    /// Discards everything the client sends from here on, modelling a crashed
    /// process rather than an orderly close. The client keeps running; its
    /// packets simply never arrive.
    pub fn silence_client(&mut self, silent: bool) {
        self.client_silenced = silent;
    }

    fn deliver(&mut self) {
        let inbound_server = std::mem::take(&mut self.to_server);
        let inbound_client = std::mem::take(&mut self.to_client);

        // A silenced client still runs and still transmits; nothing it sends
        // reaches the server, which is what a crashed process looks like from
        // the far end.
        if !self.client_silenced {
            for datagram in inbound_server {
                self.deliver_to_server(datagram);
            }
        }

        for datagram in inbound_client {
            self.deliver_to_client(datagram);
        }
    }

    fn deliver_to_server(&mut self, datagram: Datagram) {
        self.scratch[..datagram.len].copy_from_slice(datagram.bytes());

        let Pair {
            now,
            server,
            server_counters,
            server_inbox,
            scratch,
            out,
            to_client,
            trace,
            server_addr,
            ..
        } = self;

        let mut ctx = Ctx::new(*now, server_counters);
        let mut received: Inbox = Vec::new();
        let mut on_message = |channel, payload: &[u8]| received.push((channel, payload.to_vec()));
        let action = server.handle_datagram(&mut ctx, datagram.from, scratch, datagram.len, out, &mut on_message);

        server_inbox.extend(received);

        // A challenge is the one reply produced without any state existing for
        // the sender, so it does not come from `drain_transmits`.
        if let ServerAction::Respond { addr, len } = action {
            push(to_client, trace, *server_addr, addr, &out[..len]);
        }
    }

    fn deliver_to_client(&mut self, datagram: Datagram) {
        self.scratch[..datagram.len].copy_from_slice(datagram.bytes());

        let Pair {
            now,
            client,
            client_counters,
            client_inbox,
            scratch,
            out,
            to_server,
            trace,
            client_addr,
            server_addr,
            ..
        } = self;

        let mut ctx = Ctx::new(*now, client_counters);
        let mut received: Inbox = Vec::new();
        let mut on_message = |channel, payload: &[u8]| received.push((channel, payload.to_vec()));
        let action = client.handle_datagram(&mut ctx, datagram.from, scratch, datagram.len, out, &mut on_message);

        client_inbox.extend(received);

        // The cookie echo, answered immediately rather than waiting for the next transmit.
        if let ClientAction::Send(len) = action {
            push(to_server, trace, *client_addr, *server_addr, &out[..len]);
        }
    }

    fn tick(&mut self) {
        let mut server_ctx = Ctx::new(self.now, &mut self.server_counters);
        self.server.handle_timeout(&mut server_ctx);
        while let Some(event) = self.server.poll_event() {
            self.server_events.push(event);
        }

        let mut client_ctx = Ctx::new(self.now, &mut self.client_counters);
        let _ = self.client.handle_timeout(&mut client_ctx);
    }

    fn transmit(&mut self) {
        let Pair {
            now,
            server,
            server_counters,
            server_addr,
            client,
            client_counters,
            client_addr,
            to_server,
            to_client,
            trace,
            out,
            ..
        } = self;

        let mut server_ctx = Ctx::new(*now, server_counters);
        let mut outbox = Outbox {
            queue: to_client,
            trace,
            from: *server_addr,
            slot: Box::new([0u8; MAX_DATAGRAM]),
        };
        server.drain_transmits(&mut server_ctx, &mut outbox);

        let mut client_ctx = Ctx::new(*now, client_counters);
        if let Some(len) = client.poll_transmit(&mut client_ctx, out) {
            push(to_server, trace, *client_addr, *server_addr, &out[..len]);
        }
    }

    /// Queues a message on the client's connection.
    pub fn client_send(&mut self, channel: u8, payload: &[u8]) {
        self.client
            .connection_mut()
            .expect("client is connected")
            .send(channel, payload)
            .expect("send queued");
    }

    /// Queues a message on the server's only connection.
    pub fn server_send(&mut self, channel: u8, payload: &[u8]) {
        self.server.connections_mut()[0]
            .send(channel, payload)
            .expect("send queued");
    }

    /// The kinds of every datagram that has crossed, in order.
    pub fn trace_kinds(&self) -> Vec<Option<PacketKind>> {
        self.trace.iter().map(Datagram::kind).collect()
    }
    /// Every reason the endpoint gave for discarding a datagram.
    pub fn server_drops(&self) -> Vec<DropReason> {
        self.server_actions
            .iter()
            .filter_map(|action| match action {
                ServerAction::Dropped(reason) => Some(*reason),
                _ => None,
            })
            .collect()
    }

    /// A one-line-per-datagram transcript of the exchange.
    pub fn transcript(&self) -> String {
        use std::fmt::Write;

        let mut out = String::new();
        for datagram in &self.trace {
            let direction = if datagram.to == self.server_addr { "c->s" } else { "s->c" };
            let _ = writeln!(out, "{direction} {:?} {} bytes", datagram.kind(), datagram.len);
        }
        for action in &self.server_actions {
            let _ = writeln!(out, "server: {action:?}");
        }
        for action in &self.client_actions {
            let _ = writeln!(out, "client: {action:?}");
        }
        out
    }
}

/// Two independent keys for one session. A backend would draw these from a
/// random source; a fixed seed keeps a test reproducible.
pub fn session_keys(seed: u64) -> Keys {
    let mut state = seed | 1;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    let mut key = || {
        let mut bytes: Key = [0u8; 32];
        for chunk in bytes.chunks_mut(8) {
            chunk.copy_from_slice(&next().to_le_bytes());
        }
        bytes
    };
    Keys { client_to_server: key(), server_to_client: key() }
}

/// Stands in for whatever a backend issues once a player has authenticated.
pub fn issue_ticket(
    backend_key: &Key,
    now: Timestamp,
    token_id: u64,
    client_id: u64,
    session: Option<SessionId>,
    keys: &Keys,
) -> EncryptedTicket {
    let ticket = Ticket {
        expires_at: now.saturating_add(Duration::from_secs(60)),
        token_id,
        client_id,
        session,
        keys: *keys,
        user_data: UserData::new(),
    };

    let mut encrypted = [0u8; MAX_BLOB];
    let len = encrypt_ticket(backend_key, &ticket, &mut encrypted).expect("ticket fits a blob");
    EncryptedTicket::from_slice(&encrypted[..len]).expect("ticket fits a blob")
}
