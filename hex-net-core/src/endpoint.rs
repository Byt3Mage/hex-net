//! The server's front door: routing, handshakes, and session lifetime.

use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, VecDeque},
    hash::{BuildHasher, RandomState},
    marker::PhantomData,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use crate::{
    channel::ChannelSet,
    config::TransportConfig,
    connection::{CloseReason, Connection, Event as ConnEvent, RecvError, Server},
    crypto::{Key, MAX_BLOB},
    ctx::Ctx,
    handshake::{
        Acceptor, COOKIE_LIFETIME, EncryptedTicket, HandshakeError, RESUME_GRACE, SessionId, Ticket, TicketId,
    },
    packet::Packet,
    shard::{Shard, ShardId},
    slab::{Handle, Slab},
    stats::Counter,
    time::Timestamp,
    timer::TimerHeap,
    wire::{
        ConnectionId, HANDSHAKE_LEN, Header, PacketKind, ServerNonce, encode_challenge, owner_shard, request_nonce,
    },
};

#[inline(always)]
const fn ix(handle: Handle<ServerConnection>) -> usize {
    handle.index() as usize
}

/// Handshake packets allowed per source IP. A burst of 32, then 16 a second.
/// A legitimate client sends two plus a few retries. The headroom is for a
/// carrier-grade NAT putting many players behind one address during a
/// reconnect storm.
struct PerAddress;

impl RefillPolicy for PerAddress {
    const BURST: u32 = 32;
    const INTERVAL: Duration = Duration::from_micros(62500);
}

/// Handshake requests processed per second across all sources, bounding the
/// decryption work a distributed flood can force regardless of how many
/// addresses it uses. 8,000 a second admits a full 10k reconnect in about a
/// second, at roughly a microsecond of AEAD work each.
struct GlobalRequests;

impl RefillPolicy for GlobalRequests {
    const BURST: u32 = 1024;
    const INTERVAL: Duration = Duration::from_micros(125);
}

/// The same bound for cookie echoes, held separately. A response proves its
/// sender receives at its address, so a flood of spoofed requests must not be
/// able to starve the clients completing a handshake.
struct GlobalResponses;

impl RefillPolicy for GlobalResponses {
    const BURST: u32 = GlobalRequests::BURST;
    const INTERVAL: Duration = GlobalRequests::INTERVAL;
}

/// How many closures or expiries are processed per pass. The remainder is picked
/// up next pass, so a mass disconnection does not produce an unbounded burst
/// inside one tick.
const REAP_BATCH: usize = 64;

/// The most connections one endpoint holds: one per slot a connection id can
/// name.
pub const MAX_CONNECTIONS: u32 = ConnectionId::SLOTS;

/// Deployment parameters. The only things in the transport that scale with
/// connection count.
#[derive(Clone, Copy, Debug)]
pub struct EndpointConfig {
    /// Clamped to [MAX_CONNECTIONS].
    pub capacity: u32,
    /// Rate-limiter slots. Direct-mapped, under a keyed hash, so distinct
    /// addresses occasionally share a bucket. Oversizing relative to
    /// `capacity` makes that rare, and a shared bucket only throttles.
    pub limiter_slots: usize,
    pub transport: TransportConfig,
    /// Which member of its group this endpoint is. An endpoint alone on its
    /// address is the only member of a group of one.
    pub shard: Shard,
}

impl EndpointConfig {
    pub fn new(capacity: u32) -> Self {
        Self::sharded(capacity, Shard::solo())
    }

    pub fn sharded(capacity: u32, shard: Shard) -> Self {
        Self {
            capacity,
            limiter_slots: ((capacity as usize) * 8).next_power_of_two().max(1024),
            transport: TransportConfig::DEFAULT,
            shard,
        }
    }
}

/// Every connection an endpoint owns is a server-side one.
pub type ServerConnection = Connection<Server>;

/// Called with each delivered message and the connection it arrived on, during
/// the call that received it. The payload borrows the packet buffer.
pub type OnServerMessage<'a> = &'a mut dyn FnMut(Handle<ServerConnection>, u8, &[u8]);

/// What the caller should do with a datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Done,
    /// Send `out[..len]` to `addr`. Produced without allocating any state for
    /// the sender.
    Respond {
        addr: SocketAddr,
        len: usize,
    },
    Routed(Handle<ServerConnection>),
    Connected(Handle<ServerConnection>),
    /// Belongs to another shard of this endpoint's group. Handled by nothing
    /// here: whoever delivered it may pass `buf[..len]` on to that shard,
    /// with the same source address and arrival time.
    Forward(ShardId),
    Dropped(DropReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    Malformed,
    UnknownConnection,
    Rejected,
    RateLimited,
    Handshake(HandshakeError),
    Full,
    NoSuchShard,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// `session` is fresh for a new player, or the one being reattached.
    Connected {
        handle: Handle<ServerConnection>,
        session: SessionId,
        resumed: bool,
    },
    /// When `suspended`, the session can still be resumed within the grace
    /// period and the avatar should stay in the world.
    Disconnected {
        session: SessionId,
        reason: CloseReason,
        suspended: bool,
    },
    /// The grace period lapsed; the avatar can be removed.
    SessionExpired(SessionId),
    /// The peer now arrives from a new address, which has been verified.
    Migrated {
        handle: Handle<ServerConnection>,
        session: SessionId,
        addr: SocketAddr,
    },
}

impl Default for Event {
    fn default() -> Self {
        Event::SessionExpired(SessionId(0))
    }
}

#[derive(Clone, Copy)]
enum SessionState {
    Live(Handle<ServerConnection>),
    Suspended { since: Timestamp },
}

/// A ticket that has produced a connection.
///
/// Kept until the ticket expires, so it can never produce another: after
/// expiry `check_ticket` refuses it anyway, and nothing is lost by forgetting.
/// The expiry itself lives in `redeemed_expiry`, which orders the forgetting.
#[derive(Clone, Copy)]
struct Redeemed {
    /// The connection it produced, while that connection lives. A retried
    /// response for the same ticket is answered from it.
    connection: Option<Handle<ServerConnection>>,
}

/// A session in the world, kept across the connections that carry it.
#[derive(Clone, Copy)]
struct Session {
    /// The `client_id` of the ticket that created it. Only a ticket for the
    /// same player may resume it.
    owner: u64,
    state: SessionState,
}
/// The endpoint's bookkeeping for one connection slot, kept beside the slab so
/// a connection carries nothing about how it is scheduled. Reset whenever the
/// slot changes hands.
#[derive(Clone, Copy, Default)]
struct Schedule {
    /// Queued in `ready`.
    ready: bool,
    /// Queued in `retiring`.
    retiring: bool,
    /// Why the connection closed, kept from the event that announced it so
    /// retirement still knows even though events are drained as they arrived.
    closed_with: CloseReason,
}

/// Where a packet should go. Two addresses while a connection is validating a
/// new path: the old one still carries traffic, the new one is being tested.
#[derive(Clone, Copy, Debug)]
pub struct Destinations {
    pub primary: SocketAddr,
    pub probe: Option<SocketAddr>,
}

/// Receives packets produced during a transmit pass.
///
/// Passed into the drain rather than called after it, so packets are written
/// straight into the caller's send batch with no intermediate buffering.
pub trait PacketSink {
    /// Hands over space for one packet, or `None` when full, which ends the pass
    /// early.
    fn next_slot(&mut self) -> Option<&mut Packet>;

    /// Commits the slot last returned by `next_slot`.
    fn commit(&mut self, to: Destinations, len: usize);
}

/// Owns every connection on one socket.
pub struct Endpoint {
    config: EndpointConfig,
    channels: ChannelSet,

    connections: Slab<ServerConnection>,

    /// Tickets already spent, so a retried handshake reaches the connection
    /// it created and a replayed one is refused.
    redeemed: HashMap<TicketId, Redeemed>,
    /// Spent tickets in order of expiry, so they are forgotten without a scan.
    redeemed_expiry: BinaryHeap<Reverse<(Timestamp, TicketId)>>,

    sessions: HashMap<SessionId, Session>,

    acceptor: Acceptor,
    limiter: RateLimiter,

    requests: Bucket<GlobalRequests>,
    responses: Bucket<GlobalResponses>,

    next_session_sequence: u64,

    /// Indexed by a handle's slot.
    schedules: Box<[Schedule]>,
    /// Each connection's next deadline, keyed by slot, so a timer pass visits
    /// only the connections that are due rather than every connection. At
    /// most one entry per slot, moved in place when the deadline changes.
    timers: TimerHeap,
    /// Connections that may have something to send, e.g., touched by a datagram,
    /// timer, or the application since they last transmitted. First in, first
    /// out, so a sink that fills resumes where it stopped.
    ready: VecDeque<Handle<ServerConnection>>,
    /// Closed connections awaiting removal.
    retiring: VecDeque<Handle<ServerConnection>>,
    /// Suspended sessions in order of suspension, which is also the order their
    /// grace periods lapse. An entry whose session has since resumed, or been
    /// suspended again, no longer matches the session table and is skipped.
    suspended: VecDeque<(Timestamp, SessionId)>,

    /// Events not yet polled, oldest first. Never overwritten: an event
    /// lost is a player the application never learns arrived or left.
    ///
    /// Reserved for the most one pass can produce. `handle_timeout` reports
    /// at most `REAP_BATCH` departures and `REAP_BATCH` lapsed sessions, and
    /// at most one migration per connection it services; a datagram produces
    /// at most one event. A driver that polls after each timeout pass and each
    /// receive batch therefore never grows it.
    events: VecDeque<Event>,
}

impl Endpoint {
    pub fn new(mut config: EndpointConfig, backend_key: Key, channels: &ChannelSet) -> Self {
        config.capacity = config.capacity.min(MAX_CONNECTIONS);
        // Headroom above capacity: a hash map grows before it is literally full,
        // and growing would allocate on the handshake path.
        let reserve = (config.capacity as usize) + ((config.capacity as usize) / 4) + 16;

        Self {
            config,
            channels: *channels,
            connections: Slab::with_capacity(config.capacity),
            redeemed: HashMap::with_capacity(reserve),
            redeemed_expiry: BinaryHeap::with_capacity(reserve),
            sessions: HashMap::with_capacity(reserve),
            acceptor: Acceptor::for_shard(backend_key, &config.shard),
            limiter: RateLimiter::new(config.limiter_slots),
            requests: Bucket::full(),
            responses: Bucket::full(),
            next_session_sequence: 1,
            schedules: vec![Schedule::default(); config.capacity as usize].into(),
            timers: TimerHeap::with_slots(config.capacity),
            ready: VecDeque::with_capacity(reserve),
            retiring: VecDeque::with_capacity(reserve),
            suspended: VecDeque::with_capacity(reserve),
            events: VecDeque::with_capacity((config.capacity as usize) + (2 * REAP_BATCH)),
        }
    }

    /// Which member of its group this endpoint is.
    #[inline]
    pub fn shard(&self) -> ShardId {
        self.config.shard.id()
    }

    #[inline]
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    #[inline]
    pub fn connection(&self, handle: Handle<ServerConnection>) -> Option<&ServerConnection> {
        self.connections.get(handle)
    }

    /// Mutable access, for sending or closing. The connection is queued to
    /// transmit on the next drain, since whatever the caller does may give it
    /// something to send.
    #[inline]
    pub fn connection_mut(&mut self, handle: Handle<ServerConnection>) -> Option<&mut ServerConnection> {
        if !self.connections.contains(handle) {
            return None;
        }
        self.touch(handle);
        self.connections.get_mut(handle)
    }

    #[inline]
    pub fn connections(&self) -> &[ServerConnection] {
        self.connections.as_slice()
    }

    #[inline]
    pub fn handles(&mut self) -> impl Iterator<Item = Handle<ServerConnection>> + '_ {
        self.connections.iter().map(|(h, _)| h)
    }

    #[inline]
    pub fn num_connections(&self) -> usize {
        self.connections.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.num_connections() == 0
    }

    /// Issues a resume ticket to a connected player. Call periodically so the
    /// client always holds a fresh one.
    pub fn issue_resume_ticket(
        &mut self,
        now: Timestamp,
        handle: Handle<ServerConnection>,
        ticket: Ticket,
    ) -> Result<(), HandshakeError> {
        let mut encrypted = [0u8; MAX_BLOB];
        let len = self.acceptor.encrypt_resume_ticket(now, ticket, &mut encrypted)?;
        let stored = EncryptedTicket::from_slice(&encrypted[..len]).ok_or(HandshakeError::Malformed)?;
        let conn = self.connection_mut(handle).ok_or(HandshakeError::NoSession)?;
        conn.send_resume_ticket(stored);
        Ok(())
    }

    /// Processes one datagram. `buf[..len]` may be decrypted in place, a
    /// challenge is written to `out` when the result is `Respond`, and
    /// `on_message` is called for each message delivered.
    pub fn handle_datagram(
        &mut self,
        ctx: &mut Ctx,
        from: SocketAddr,
        buf: &mut Packet,
        len: usize,
        out: &mut Packet,
        on_message: OnServerMessage,
    ) -> Action {
        if let Some(owner) = owner_shard(&buf[..len])
            && (owner != self.shard())
        {
            return self.misrouted(ctx, owner);
        }

        let Some(kind) = peek_kind(buf, len) else {
            ctx.counters.inc(Counter::PacketsMalformed);
            return Action::Dropped(DropReason::Malformed);
        };

        match kind {
            PacketKind::Payload => self.route_payload(ctx, from, buf, len, on_message),
            PacketKind::Request => self.handle_request(ctx, from, buf, len, out),
            PacketKind::Response => self.handle_response(ctx, from, buf, len),
            PacketKind::Challenge => {
                // Servers never receive challenges.
                ctx.counters.inc(Counter::PacketsMalformed);
                Action::Dropped(DropReason::Malformed)
            }
        }
    }

    /// A datagram owned by another shard. Named for the caller to pass on when
    /// the shard exists, and dropped when it does not, since then no endpoint
    /// anywhere holds what it refers to.
    fn misrouted(&mut self, ctx: &mut Ctx, owner: ShardId) -> Action {
        if self.config.shard.count().contains(owner) {
            ctx.counters.inc(Counter::PacketsMisrouted);
            Action::Forward(owner)
        } else {
            ctx.counters.inc(Counter::PacketsUnknownConnection);
            Action::Dropped(DropReason::NoSuchShard)
        }
    }

    /// Routes by connection id, never by source address: a client whose NAT
    /// rebinds arrives from a new address with the same id and must keep
    /// working. The connection verifies the new address before trusting it.
    fn route_payload(
        &mut self,
        ctx: &mut Ctx,
        from: SocketAddr,
        buf: &mut Packet,
        len: usize,
        on_message: OnServerMessage,
    ) -> Action {
        let Ok((header, _)) = Header::decode(&buf[..len]) else {
            ctx.counters.inc(Counter::PacketsMalformed);
            return Action::Dropped(DropReason::Malformed);
        };
        let Some(handle) = self
            .connections
            .handle_at(header.conn_id.slot())
            .filter(|&handle| self.conn_id_of(handle) == header.conn_id)
        else {
            ctx.counters.inc(Counter::PacketsUnknownConnection);
            return Action::Dropped(DropReason::UnknownConnection);
        };
        let Some(conn) = self.connections.get_mut(handle) else {
            ctx.counters.inc(Counter::PacketsUnknownConnection);
            return Action::Dropped(DropReason::UnknownConnection);
        };

        let mut forward = |channel: u8, payload: &[u8]| on_message(handle, channel, payload);
        match conn.handle_datagram(ctx, from, buf, len, &mut forward) {
            Ok(()) | Err(RecvError::BadPayload) => {
                self.touch(handle);
                self.pump_events(handle);
                Action::Routed(handle)
            }
            Err(_) => Action::Dropped(DropReason::Rejected),
        }
    }

    fn handle_request(
        &mut self,
        ctx: &mut Ctx,
        from: SocketAddr,
        buf: &Packet,
        len: usize,
        out: &mut Packet,
    ) -> Action {
        if let Err(reason) = self.charge_handshake(ctx, from, PacketKind::Request) {
            return Action::Dropped(reason);
        }

        let ticket = match self.acceptor.decrypt_ticket(&buf[..len]) {
            Ok(t) => t,
            Err(err) => return Action::Dropped(DropReason::Handshake(err)),
        };

        let (Some(nonce), Some(ticket_id)) = (request_nonce(&buf[..len]), TicketId::of_request(&buf[..len])) else {
            return Action::Dropped(DropReason::Malformed);
        };

        let Some(home) = self.acceptor.home(&ticket, ticket_id) else {
            return Action::Dropped(DropReason::Handshake(HandshakeError::NoSession));
        };

        // Any shard answers a request, but only the ticket's home holds the
        // session it names and the record of whether it is spent. Elsewhere
        // only expiry can be judged; the cookie is addressed to the home,
        // which checks the rest when the response reaches it.
        if home == self.shard() {
            if let Err(err) = self.check_ticket(ctx.now, &ticket) {
                return Action::Dropped(DropReason::Handshake(err));
            }
            // Refused here rather than only at the response, so a replayed
            // ticket costs the server no cookie.
            if let Some(Redeemed { connection: None }) = self.redeemed.get(&ticket_id) {
                return Action::Dropped(DropReason::Handshake(HandshakeError::Spent));
            }
        } else if let Err(error) = ticket.check_expiry(ctx.now) {
            return Action::Dropped(DropReason::Handshake(error));
        }

        // Drawn per challenge, not per connection: the cookie seals it, so
        // the server holds nothing for a handshake until one completes.
        let server_nonce = ServerNonce::random();
        let mut cookie = [0u8; MAX_BLOB];
        let cookie_len =
            match self
                .acceptor
                .encrypt_cookie(ctx.now, from, nonce, server_nonce, ticket_id, &ticket, &mut cookie)
            {
                Ok(cookie_len) => cookie_len,
                Err(error) => return Action::Dropped(DropReason::Handshake(error)),
            };

        match encode_challenge(&cookie[..cookie_len], server_nonce, out) {
            Ok(len) => Action::Respond { addr: from, len },
            Err(_) => Action::Dropped(DropReason::Malformed),
        }
    }

    fn handle_response(&mut self, ctx: &mut Ctx, from: SocketAddr, buf: &Packet, len: usize) -> Action {
        if let Err(reason) = self.charge_handshake(ctx, from, PacketKind::Response) {
            return Action::Dropped(reason);
        }

        let cookie = match self.acceptor.decrypt_cookie(&buf[..len]) {
            Ok(cookie) => cookie,
            Err(error) => return Action::Dropped(DropReason::Handshake(error)),
        };

        if cookie.addr != from {
            return Action::Dropped(DropReason::Handshake(HandshakeError::AddressMismatch));
        }
        if ctx.now.saturating_since(cookie.issued_at) > COOKIE_LIFETIME {
            return Action::Dropped(DropReason::Handshake(HandshakeError::Expired));
        }

        // A spent ticket produces nothing new. While its connection lives, a
        // response presenting it is a client whose acceptance was lost: re-send
        // the acceptance there, which a replay from elsewhere gains nothing by,
        // since it goes to the connection's own address. Once the connection
        // has ended, the ticket is simply refused.
        //
        // Checked before the ticket, because accepting a resume turns its
        // session from suspended to live, which `check_ticket` would treat as
        // a takeover rather than a retry.
        if let Some(redeemed) = self.redeemed.get(&cookie.ticket_id) {
            if let Some(handle) = redeemed.connection
                && let Some(conn) = self.connection_mut(handle)
            {
                conn.resend_acceptance();
                return Action::Connected(handle);
            }
            return Action::Dropped(DropReason::Handshake(HandshakeError::Spent));
        }

        // Rechecked here as well as at the request. Up to COOKIE_LIFETIME has
        // passed, during which a grace period may have lapsed or another
        // response may already have claimed the session.
        if let Err(error) = self.check_ticket(ctx.now, &cookie.ticket) {
            return Action::Dropped(DropReason::Handshake(error));
        }

        // Refused before anything changes. A takeover closes the connection
        // holding the session, which must not happen for a player the server
        // then has no room for.
        if self.connections.len() >= (self.connections.capacity() as usize) {
            ctx.counters.inc(Counter::ConnectionsRejectedFull);
            return Action::Dropped(DropReason::Full);
        }

        let (session, resumed) = match cookie.ticket.session {
            Some(session) => (session, true),
            None => {
                let session = SessionId::new(self.next_session_sequence, self.shard());
                self.next_session_sequence += 1;
                (session, false)
            }
        };

        // Taking over a live session closes the connection that held it.
        // The notice goes out on the next drain and retirement follows.
        if let Some(session) = self.sessions.get(&session)
            && let SessionState::Live(prev) = session.state
            && let Some(conn) = self.connection_mut(prev)
        {
            conn.close(CloseReason::Replaced);
        }

        // The id is derived from the slot the connection is about to take,
        // and the keys from the id and both handshake nonces.
        let shard = self.shard();
        let (channels, transport) = (self.channels, self.config.transport);
        let inserted = self.connections.insert_with(|handle| {
            let conn_id = conn_id_for(handle, shard);
            let keys = cookie
                .ticket
                .keys
                .for_connection(conn_id, cookie.nonce, cookie.server_nonce);
            Connection::accept(
                ctx.now,
                conn_id,
                session,
                cookie.ticket_id,
                from,
                &keys,
                channels,
                transport,
            )
        });
        let Some(handle) = inserted else {
            ctx.counters.inc(Counter::ConnectionsRejectedFull);
            return Action::Dropped(DropReason::Full);
        };

        self.schedules[ix(handle)] = Schedule::default();
        self.touch(handle);
        self.sessions.insert(
            session,
            Session {
                owner: cookie.ticket.client_id,
                state: SessionState::Live(handle),
            },
        );
        self.redeemed
            .insert(cookie.ticket_id, Redeemed { connection: Some(handle) });
        self.redeemed_expiry
            .push(Reverse((cookie.ticket.expires_at, cookie.ticket_id)));
        self.events.push_back(Event::Connected { handle, session, resumed });
        Action::Connected(handle)
    }

    /// The id of the connection `handle` refers to.
    #[inline]
    fn conn_id_of(&self, handle: Handle<ServerConnection>) -> ConnectionId {
        conn_id_for(handle, self.shard())
    }

    /// The single place ticket policy lives: expiry, and whether a resume is
    /// permitted for the session named. Only the ticket's home shard can
    /// apply it, since only it holds the session.
    fn check_ticket(&self, now: Timestamp, ticket: &Ticket) -> Result<(), HandshakeError> {
        ticket.check_expiry(now)?;

        let Some(session) = ticket.session else { return Ok(()) };
        let Some(record) = self.sessions.get(&session) else { return Err(HandshakeError::NoSession) };

        // Another player's session is refused the same as a missing one is,
        // so a ticket learns nothing about a session it doesn't own.
        if record.owner != ticket.client_id {
            return Err(HandshakeError::NoSession);
        }

        match record.state {
            // Still attached. The player is reconnecting before the old connection
            // noticed it was gone (usually in a crash). The new connection takes
            // over the session.
            SessionState::Live(_) => Ok(()),
            SessionState::Suspended { since } if now.saturating_since(since) < RESUME_GRACE => Ok(()),
            SessionState::Suspended { .. } => Err(HandshakeError::NoSession),
        }
    }

    /// Produces at most one packet for each connection that may have something
    /// to send, then rearms its timer.
    ///
    /// Visits only connections touched since they last transmitted. If the
    /// sink fills, the rest stay queued and the next drain starts with them.
    pub fn drain_transmits(&mut self, ctx: &mut Ctx, sink: &mut impl PacketSink) {
        while let Some(&handle) = self.ready.front() {
            let Some(slot) = sink.next_slot() else { return };
            self.ready.pop_front();

            // A retired connection's handle can still be queued.
            // Its slot's bookkeeping now belongs to whatever occupies
            // the slot.
            let Some(conn) = self.connections.get_mut(handle) else { continue };
            let schedule = &mut self.schedules[ix(handle)];
            schedule.ready = false;

            if let Some(len) = conn.poll_transmit(ctx, slot) {
                sink.commit(Destinations { primary: conn.addr(), probe: conn.probe_addr() }, len);
            }

            // Moves the connection's timer to its current deadline, or queues
            // it for removal once it has closed.
            match conn.next_timeout() {
                Some(at) => self.timers.set(handle.index(), at),
                None => {
                    self.timers.cancel(handle.index());
                    if !schedule.retiring {
                        schedule.retiring = true;
                        self.retiring.push_back(handle);
                    }
                }
            }
        }
    }

    /// Services the connections whose deadlines have passed, retires closed
    /// connections, and expires suspended sessions.
    ///
    /// A serviced connection is queued to transmit, since a timer usually means
    /// something is owed: an acknowledgement, a probe, a keepalive. Its timer is
    /// rearmed after that transmit, not here, because deadlines such as an owed
    /// acknowledgement stay due until the packet goes out.
    pub fn handle_timeout(&mut self, ctx: &mut Ctx) {
        while let Some(slot) = self.timers.pop_due(ctx.now) {
            // Every entry belongs to a live connection and retirement cancels it.
            let Some(handle) = self.connections.handle_at(slot) else { continue };
            if let Some(conn) = self.connections.get_mut(handle) {
                conn.handle_timeout(ctx);
            }
            self.touch(handle);
            self.pump_events(handle);
        }
        self.reap(ctx.now);
        self.expire_sessions(ctx.now);
        self.forget_expired_tickets(ctx.now);
    }

    /// Forgets spent tickets past their expiry. They need no deadline of
    /// their own. Holding one longer only costs memory, and `check_ticket`
    /// refuses an expired ticket regardless.
    fn forget_expired_tickets(&mut self, now: Timestamp) {
        while let Some(&Reverse((at, id))) = self.redeemed_expiry.peek()
            && (at < now)
        {
            self.redeemed_expiry.pop();
            self.redeemed.remove(&id);
        }
    }

    /// The earliest time `handle_timeout` or `drain_transmits` next has work,
    /// or `None` when there is nothing to wait for.
    ///
    /// A connection queued to transmit or awaiting removal makes the answer
    /// `Timestamp::ZERO`, i.e., already due, whatever the time.
    pub fn next_timeout(&self) -> Option<Timestamp> {
        if !self.ready.is_empty() || !self.retiring.is_empty() {
            return Some(Timestamp::ZERO);
        }
        let timer = self.timers.peek().map(|(at, _)| at);
        let session = self
            .suspended
            .front()
            .map(|(since, _)| since.saturating_add(RESUME_GRACE));
        timer.into_iter().chain(session).min()
    }

    /// Moves a connection's events out to the endpoint's own queue.
    ///
    /// Run whenever a connection is serviced, so migrations reach the
    /// application promptly rather than waiting for retirement, by which
    /// time the connection's own queue may have overwritten them.
    fn pump_events(&mut self, handle: Handle<ServerConnection>) {
        let Some(conn) = self.connections.get_mut(handle) else { return };
        let session = conn.session();

        let mut migrated = None;
        let mut closed = None;

        while let Some(event) = conn.poll_event() {
            match event {
                ConnEvent::Migrated(addr) => migrated = Some(addr),
                ConnEvent::Closed(reason) => closed = Some(reason),
                ConnEvent::ResumeTicketReceived => { /*Client-only event*/ }
            }
        }

        if let Some(addr) = migrated {
            self.events.push_back(Event::Migrated { handle, session, addr });
        }

        if let Some(reason) = closed {
            self.schedules[ix(handle)].closed_with = reason;
        }
    }

    /// Queues a connection to transmit on the next drain.
    fn touch(&mut self, handle: Handle<ServerConnection>) {
        let schedule = &mut self.schedules[ix(handle)];
        if !schedule.ready {
            schedule.ready = true;
            self.ready.push_back(handle);
        }
    }

    /// Removes closed connections and decides whether their session survives.
    ///
    /// A player who disconnected on purpose is gone. One who dropped may be
    /// reconnecting already, so their place is held.
    fn reap(&mut self, now: Timestamp) {
        for _ in 0..REAP_BATCH {
            let Some(handle) = self.retiring.pop_front() else { return };
            self.retire(handle, now);
        }
    }

    fn retire(&mut self, handle: Handle<ServerConnection>, now: Timestamp) {
        self.pump_events(handle);

        let Some(conn) = self.connections.get(handle) else { return };
        let (session, ticket_id) = (conn.session(), conn.ticket_id());
        let reason = core::mem::take(&mut self.schedules[ix(handle)]).closed_with;

        // The ticket stays spent until it expires. Only the retry path closes.
        if let Some(redeemed) = self.redeemed.get_mut(&ticket_id) {
            redeemed.connection = None;
        }

        self.timers.cancel(handle.index());
        self.connections.remove(handle);

        let mut suspended = false;

        // A session resumed elsewhere already points at its new connection.
        // This one is only the husk of the old attachment and must not
        // overwrite it.
        if let Some(record) = self.sessions.get_mut(&session)
            && let SessionState::Live(holder) = record.state
            && holder == handle
        {
            if !matches!(reason, CloseReason::Requested | CloseReason::ServerShutdown) {
                suspended = true;
                record.state = SessionState::Suspended { since: now };
                self.suspended.push_back((now, session));
            } else {
                self.sessions.remove(&session);
            }
        }

        self.events
            .push_back(Event::Disconnected { session, reason, suspended });
    }

    /// Removes sessions whose grace period has lapsed, oldest first, at most a
    /// batch per call.
    fn expire_sessions(&mut self, now: Timestamp) {
        let mut expired = 0;

        while (expired < REAP_BATCH)
            && let Some(&(since, session)) = self.suspended.front()
            && (now.saturating_since(since) >= RESUME_GRACE)
        {
            self.suspended.pop_front();

            if let Some(record) = self.sessions.get(&session)
                && let SessionState::Suspended { since: suspended } = record.state
                && suspended == since
            {
                self.sessions.remove(&session);
                self.events.push_back(Event::SessionExpired(session));
                expired += 1;
            }
        }
    }

    /// Closes every connection with a notice. Keep draining transmits for a pass
    /// or two afterwards so the notices go out.
    pub fn shutdown(&mut self) {
        let handles: Vec<_> = self.handles().collect();
        for handle in handles {
            if let Some(conn) = self.connection_mut(handle) {
                conn.close(CloseReason::ServerShutdown);
            }
        }
    }

    /// Spends handshake budget, per address and globally.
    ///
    /// Each handshake packet costs a decryption, so an unbounded flood is a CPU
    /// attack even though none of them allocate. The per-address bucket stops
    /// one host; the global budget stops a distributed flood where every source
    /// is individually within its limit.
    fn charge_handshake(&mut self, ctx: &mut Ctx, from: SocketAddr, kind: PacketKind) -> Result<(), DropReason> {
        let charged = match kind {
            PacketKind::Response => charge(&mut self.responses, &mut self.limiter, ctx.now, from),
            _ => charge(&mut self.requests, &mut self.limiter, ctx.now, from),
        };

        if !charged {
            ctx.counters.inc(Counter::HandshakesRateLimited);
            return Err(DropReason::RateLimited);
        }

        Ok(())
    }
}

/// The id of the connection `handle` refers to on `shard`. A slab generation
/// is odd while occupied and advances twice per occupancy, so half of it
/// counts the slot's occupancies.
#[inline]
fn conn_id_for(handle: Handle<ServerConnection>, shard: ShardId) -> ConnectionId {
    ConnectionId::new(handle.index(), handle.generation() >> 1, shard)
}

fn charge<P: RefillPolicy>(
    global: &mut Bucket<P>,
    limiter: &mut RateLimiter,
    now: Timestamp,
    from: SocketAddr,
) -> bool {
    let Some(token) = global.reserve(now) else { return false };
    if !limiter.take(now, from) {
        return false;
    }
    token.spend();
    true
}

/// Reads the kind from a raw first byte. Handshake packets shorter than their
/// padding are rejected before any work is done, since a reply to one would
/// amplify.
#[inline]
fn peek_kind(buf: &[u8], len: usize) -> Option<PacketKind> {
    if len == 0 {
        return None;
    }
    let kind = PacketKind::from_byte(buf[0])?;
    match kind {
        PacketKind::Payload => Some(kind),
        _ if len >= HANDSHAKE_LEN => Some(kind),
        _ => None,
    }
}

/// How a token bucket fills. Up to `BURST` tokens, one per `INTERVAL`.
///
/// A type rather than a value, so a bucket is bound to one policy for its
/// whole life and cannot be refilled under another.
trait RefillPolicy {
    const BURST: u32;
    const INTERVAL: Duration;
}

struct Bucket<P> {
    tokens: u32,
    last_refill: Timestamp,
    policy: PhantomData<P>,
}

impl<P> Copy for Bucket<P> {}
impl<P> Clone for Bucket<P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P: RefillPolicy> Bucket<P> {
    fn full() -> Self {
        Self {
            tokens: P::BURST,
            last_refill: Timestamp::ZERO,
            policy: PhantomData,
        }
    }

    /// Credits whole intervals elapsed. The partial interval is kept by
    /// advancing `last_refill` only by what was credited, unless the bucket
    /// filled, in which case waiting earns nothing further.
    fn refill(&mut self, now: Timestamp) {
        let elapsed = now.saturating_since(self.last_refill).as_nanos();
        let intervals = elapsed / P::INTERVAL.as_nanos();
        if intervals == 0 {
            return;
        }

        let missing = P::BURST - self.tokens;
        match u32::try_from(intervals) {
            Ok(intervals) if intervals < missing => {
                self.tokens += intervals;
                self.last_refill = self.last_refill.saturating_add(P::INTERVAL * intervals);
            }
            _ => {
                self.tokens = P::BURST;
                self.last_refill = now;
            }
        }
    }

    /// Refills, then holds one token if there is one. The token is taken only
    /// if the reservation is spent.
    fn reserve(&mut self, now: Timestamp) -> Option<Reservation<'_, P>> {
        self.refill(now);
        (self.tokens > 0).then_some(Reservation { bucket: self })
    }
}

/// One token known to be present in its bucket.
#[must_use]
struct Reservation<'a, P> {
    bucket: &'a mut Bucket<P>,
}

impl<P> Reservation<'_, P> {
    fn spend(self) {
        // Nonzero, since the reservation exists only while a token does,
        // and it holds the only reference to the bucket.
        self.bucket.tokens -= 1;
    }
}

/// Per-address token bucket in a fixed, direct-mapped table.
///
/// Spraying source addresses cannot grow it. Addresses whose slots collide
/// share one bucket, which only throttles them together. The hash is
/// keyed per process, so an attacker cannot aim a collision at a particular
/// client
struct RateLimiter {
    slots: Box<[Bucket<PerAddress>]>,
    mask: usize,
    hasher: std::hash::RandomState,
}

impl RateLimiter {
    fn new(slots: usize) -> Self {
        let slots = slots.next_power_of_two();
        Self {
            slots: vec![Bucket::full(); slots].into(),
            mask: slots - 1,
            hasher: RandomState::new(),
        }
    }

    fn take(&mut self, now: Timestamp, addr: SocketAddr) -> bool {
        let slot = (self.hasher.hash_one(source_key(addr)) as usize) & self.mask;
        match self.slots[slot].reserve(now) {
            Some(token) => {
                token.spend();
                true
            }
            None => false,
        }
    }
}

/// What identifies a source for rate limiting. The IP alone, since ports are
/// free to change. An IPv6 host commonly holds a whole /64, so only that prefix
/// counts. Limiting the full address would let one host rotate through
/// addresses as easily as through ports.
#[derive(Hash)]
enum SourceKey {
    V4(u32),
    V6Prefix(u64),
}

fn source_key(addr: SocketAddr) -> SourceKey {
    match addr.ip() {
        IpAddr::V4(ip) => SourceKey::V4(ip.to_bits()),
        IpAddr::V6(ip) => SourceKey::V6Prefix((ip.to_bits() >> 64) as u64),
    }
}
