//! The server's front door: routing, handshakes, and session lifetime.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::budget::BudgetConfig;
use crate::channel::{ChannelSet, OnMessage};
use crate::connection::{CloseReason, Connection, Event as ConnEvent, RecvError, ServerRole};
use crate::crypto::{Key, MAX_BLOB};
use crate::ctx::Ctx;
use crate::fixed::{FixedVec, RingQueue};
use crate::handshake::{Acceptor, COOKIE_LIFETIME, EncryptedTicket, HandshakeError, RESUME_GRACE, SessionId, Ticket};
use crate::packet::Packet;
use crate::slab::{Handle, Slab};
use crate::stats::Counter;
use crate::time::Timestamp;
use crate::wire::{ConnectionId, HANDSHAKE_LEN, Header, PacketKind, encode_handshake};

/// Handshake packets allowed per source address per second. A legitimate client
/// sends two; a few retries are normal.
const HANDSHAKE_BURST: u16 = 8;
const HANDSHAKE_REFILL_INTERVAL: Duration = Duration::from_millis(125);

/// Handshake packets processed per service pass, bounding the decryption work a
/// distributed flood can force regardless of how many addresses it uses.
const GLOBAL_HANDSHAKE_BUDGET: u16 = 256;

/// How many closures or expiries are processed per pass. The remainder is picked
/// up next pass, so a mass disconnection does not produce an unbounded burst
/// inside one tick.
const REAP_BATCH: usize = 64;

/// Deployment parameters. The only things in the transport that scale with
/// connection count.
#[derive(Clone, Copy, Debug)]
pub struct EndpointConfig {
    pub capacity: u32,
    /// Rate-limiter slots. Direct-mapped, so distinct addresses can share a
    /// bucket; oversizing relative to `capacity` makes that rare, and a shared
    /// bucket only throttles.
    pub limiter_slots: usize,
    pub budget: BudgetConfig,
}

impl EndpointConfig {
    pub fn new(capacity: u32) -> Self {
        Self {
            capacity,
            limiter_slots: ((capacity as usize) * 8).next_power_of_two().max(1024),
            budget: BudgetConfig::DEFAULT,
        }
    }
}

/// Every connection an endpoint owns is a server-side one.
pub type ServerConnection = Connection<ServerRole>;

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
    Dropped(DropReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    Malformed,
    UnknownConnection,
    /// Failed decryption, duplicate, or replayed.
    Rejected,
    RateLimited,
    Handshake(HandshakeError),
    Full,
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
}

impl Default for Event {
    fn default() -> Self {
        Event::SessionExpired(SessionId(0))
    }
}

/// A connection retired this pass.
#[derive(Clone, Copy)]
struct Closure {
    conn_id: ConnectionId,
    session: SessionId,
    token_id: u64,
    reason: CloseReason,
}

#[derive(Clone, Copy)]
enum SessionState {
    Live(Handle<ServerConnection>),
    Suspended { since: Timestamp },
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
    /// Tickets already accepted, so a retried handshake reaches the connection
    /// it created rather than making another.
    accepted: HashMap<u64, Handle<ServerConnection>>,
    /// Connection ids are monotonic rather than slot-derived, because a
    /// slot-derived id would repeat once its per-slot counter wrapped, and an id
    /// must not repeat while a session's keys are live.
    routes: HashMap<ConnectionId, Handle<ServerConnection>>,
    sessions: HashMap<SessionId, SessionState>,

    acceptor: Acceptor,
    limiter: RateLimiter,

    next_conn_id: u32,
    next_session_id: u64,
    handshake_budget: u16,
    /// Where the next transmit pass begins, so a sink that fills does not starve
    /// the same connections every pass.
    resume_at: u32,

    events: RingQueue<Event, 64>,
}

impl Endpoint {
    pub fn new(config: EndpointConfig, backend_key: Key, channels: &ChannelSet) -> Self {
        // Headroom above capacity: a hash map grows before it is literally full,
        // and growing would allocate on the handshake path.
        let reserve = (config.capacity as usize) + ((config.capacity as usize) / 4) + 16;

        Self {
            config,
            channels: *channels,
            connections: Slab::with_capacity(config.capacity),
            accepted: HashMap::with_capacity(reserve),
            routes: HashMap::with_capacity(reserve),
            sessions: HashMap::with_capacity(reserve),
            acceptor: Acceptor::new(backend_key),
            limiter: RateLimiter::new(config.limiter_slots),
            // Starts above zero so a restarted server does not immediately
            // reissue ids that clients from the previous run still hold.
            next_conn_id: 1,
            next_session_id: 1,
            handshake_budget: GLOBAL_HANDSHAKE_BUDGET,
            resume_at: 0,
            events: RingQueue::new(),
        }
    }

    #[inline]
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop()
    }

    #[inline]
    pub fn connection(&self, handle: Handle<ServerConnection>) -> Option<&ServerConnection> {
        self.connections.get(handle)
    }

    #[inline]
    pub fn connection_mut(&mut self, handle: Handle<ServerConnection>) -> Option<&mut ServerConnection> {
        self.connections.get_mut(handle)
    }

    #[inline]
    pub fn connections(&self) -> &[ServerConnection] {
        self.connections.as_slice()
    }

    #[inline]
    pub fn connections_mut(&mut self) -> &mut [ServerConnection] {
        self.connections.as_mut_slice()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
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
        let conn = self.connections.get_mut(handle).ok_or(HandshakeError::NoSession)?;
        let stored = EncryptedTicket::from_slice(&encrypted[..len]).ok_or(HandshakeError::Malformed)?;
        conn.send_resume_ticket(stored);
        Ok(())
    }

    // ---------------------------------------------------------------- receive

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
        on_message: OnMessage,
    ) -> Action {
        let Some(kind) = peek_kind(buf, len) else {
            ctx.counters.inc(Counter::PacketsMalformed);
            return Action::Dropped(DropReason::Malformed);
        };

        match kind {
            PacketKind::Payload => self.route_payload(ctx, from, buf, len, on_message),
            PacketKind::Request => self.handle_request(ctx, from, buf, len, out),
            PacketKind::Response => self.handle_response(ctx, from, buf, len),
            // Servers never receive challenges.
            PacketKind::Challenge => {
                ctx.counters.inc(Counter::PacketsMalformed);
                Action::Dropped(DropReason::Malformed)
            }
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
        on_message: OnMessage,
    ) -> Action {
        let Ok((header, _)) = Header::decode(&buf[..len]) else {
            ctx.counters.inc(Counter::PacketsMalformed);
            return Action::Dropped(DropReason::Malformed);
        };
        let Some(&handle) = self.routes.get(&header.conn_id) else {
            ctx.counters.inc(Counter::PacketsUnknownConnection);
            return Action::Dropped(DropReason::UnknownConnection);
        };
        let Some(conn) = self.connections.get_mut(handle) else {
            self.routes.remove(&header.conn_id); // The route outlived its connection.
            ctx.counters.inc(Counter::PacketsUnknownConnection);
            return Action::Dropped(DropReason::UnknownConnection);
        };

        match conn.handle_datagram(ctx, from, buf, len, on_message) {
            Ok(()) | Err(RecvError::BadPayload) => Action::Routed(handle),
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
        if let Err(reason) = self.charge_handshake(ctx, from) {
            return Action::Dropped(reason);
        }

        let ticket = match self.acceptor.decrypt_ticket(&buf[..len]) {
            Ok(ticket) => ticket,
            Err(error) => return Action::Dropped(DropReason::Handshake(error)),
        };
        if let Err(error) = self.check_ticket(ctx.now, &ticket) {
            return Action::Dropped(DropReason::Handshake(error));
        }

        let mut cookie = [0u8; MAX_BLOB];
        let cookie_len = match self.acceptor.encrypt_cookie(ctx.now, from, &ticket, &mut cookie) {
            Ok(cookie_len) => cookie_len,
            Err(error) => return Action::Dropped(DropReason::Handshake(error)),
        };

        match encode_handshake(PacketKind::Challenge, &cookie[..cookie_len], out) {
            Ok(len) => Action::Respond { addr: from, len },
            Err(_) => Action::Dropped(DropReason::Malformed),
        }
    }

    fn handle_response(&mut self, ctx: &mut Ctx, from: SocketAddr, buf: &Packet, len: usize) -> Action {
        if let Err(reason) = self.charge_handshake(ctx, from) {
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

        // A client whose acceptance was lost retries with the same cookie. The
        // ticket is the identity: re-send the acceptance on the connection it
        // already produced rather than creating a second one.
        //
        // Checked before the ticket, because accepting a resume turns its
        // session from suspended to live, which is exactly what `check_ticket`
        // rejects. A retry would otherwise be refused rather than recognised.
        if let Some(&handle) = self.accepted.get(&cookie.ticket.token_id) {
            if let Some(conn) = self.connections.get_mut(handle) {
                conn.resend_acceptance();
                return Action::Connected(handle);
            }
            self.accepted.remove(&cookie.ticket.token_id);
        }

        // Rechecked here as well as at the request: up to COOKIE_LIFETIME has
        // passed, during which a grace period may have lapsed or another
        // response may already have claimed the session.
        if let Err(error) = self.check_ticket(ctx.now, &cookie.ticket) {
            return Action::Dropped(DropReason::Handshake(error));
        }

        let resumed = cookie.ticket.session.is_some();
        let session = match cookie.ticket.session {
            Some(session) => session,
            None => {
                let session = SessionId(self.next_session_id);
                self.next_session_id += 1;
                session
            }
        };

        let conn_id = ConnectionId(self.next_conn_id);
        let conn = Connection::accept(
            ctx.now,
            conn_id,
            session,
            cookie.ticket.token_id,
            from,
            &cookie.ticket.keys,
            self.channels,
            self.config.budget,
        );

        let Ok(handle) = self.connections.insert(conn) else {
            ctx.counters.inc(Counter::ConnectionsRejectedFull);
            return Action::Dropped(DropReason::Full);
        };

        // Consumed only on success, so a failed insert does not burn an id.
        self.next_conn_id = self.next_conn_id.wrapping_add(1);
        self.routes.insert(conn_id, handle);
        self.sessions.insert(session, SessionState::Live(handle));
        self.accepted.insert(cookie.ticket.token_id, handle);

        self.events.push(Event::Connected { handle, session, resumed });
        Action::Connected(handle)
    }

    /// The single place ticket policy lives: expiry, and whether a resume is
    /// permitted for the session named.
    fn check_ticket(&self, now: Timestamp, ticket: &Ticket) -> Result<(), HandshakeError> {
        if now > ticket.expires_at {
            return Err(HandshakeError::Expired);
        }

        let Some(session) = ticket.session else { return Ok(()) };

        match self.sessions.get(&session) {
            Some(SessionState::Suspended { since }) if now.saturating_since(*since) <= RESUME_GRACE => Ok(()),
            _ => Err(HandshakeError::NoSession),
        }
    }

    // --------------------------------------------------------------- transmit

    /// Produces one packet per connection that has something to send.
    ///
    /// Visits connections from `resume_at`, which advances when a pass ends
    /// early, so a sink that is consistently too small delays later connections
    /// rather than starving them.
    pub fn drain_transmits(&mut self, ctx: &mut Ctx, sink: &mut impl PacketSink) {
        let connections = self.connections.as_mut_slice();
        if connections.is_empty() {
            return;
        }

        let start = (self.resume_at as usize) % connections.len();
        for offset in 0..connections.len() {
            let index = (start + offset) % connections.len();

            let Some(slot) = sink.next_slot() else {
                self.resume_at = index as u32;
                return;
            };

            let conn = &mut connections[index];
            let Some(len) = conn.poll_transmit(ctx, slot) else {
                continue;
            };
            sink.commit(Destinations { primary: conn.addr(), probe: conn.probe_addr() }, len);
        }
        self.resume_at = 0;
    }

    // ----------------------------------------------------------------- timers

    /// Runs connection timers, retires closed connections, expires suspended
    /// sessions, and refills the handshake budget.
    pub fn handle_timeout(&mut self, ctx: &mut Ctx) {
        self.handshake_budget = GLOBAL_HANDSHAKE_BUDGET;

        for conn in self.connections.as_mut_slice() {
            conn.handle_timeout(ctx);
        }
        self.reap(ctx.now);
        self.expire_sessions(ctx.now);
    }

    /// Removes closed connections and decides whether their session survives.
    ///
    /// A player who disconnected on purpose is gone; one who dropped may be
    /// reconnecting already, so their place is held.
    fn reap(&mut self, now: Timestamp) {
        // Optional slots: an enum with no meaningful default should not be given
        // one merely to satisfy a container.
        let mut closed: FixedVec<Option<Closure>, REAP_BATCH> = FixedVec::new();

        for conn in self.connections.as_mut_slice() {
            let mut reason = None;
            // Drained fully, so a close is not missed behind other events.
            while let Some(event) = conn.poll_event() {
                if let ConnEvent::Closed(why) = event {
                    reason = Some(why);
                }
            }
            let reason = reason.or_else(|| conn.is_closed().then_some(CloseReason::TimedOut));

            if let Some(reason) = reason {
                let closure = Closure {
                    conn_id: conn.id(),
                    session: conn.session(),
                    token_id: conn.token_id(),
                    reason,
                };
                if !closed.push(Some(closure)) {
                    break;
                }
            }
        }

        for closure in closed.iter().flatten().copied() {
            let Some(handle) = self.routes.remove(&closure.conn_id) else { continue };
            self.connections.remove(handle);
            self.accepted.remove(&closure.token_id);

            let suspended = !matches!(closure.reason, CloseReason::Requested | CloseReason::ServerShutdown);
            if suspended {
                self.sessions
                    .insert(closure.session, SessionState::Suspended { since: now });
            } else {
                self.sessions.remove(&closure.session);
            }
            self.events.push(Event::Disconnected {
                session: closure.session,
                reason: closure.reason,
                suspended,
            });
        }
    }

    fn expire_sessions(&mut self, now: Timestamp) {
        let mut expired: FixedVec<SessionId, REAP_BATCH> = FixedVec::new();

        for (&session, state) in self.sessions.iter() {
            if let SessionState::Suspended { since } = state
                && (now.saturating_since(*since) > RESUME_GRACE)
                && !expired.push(session)
            {
                break;
            }
        }
        for session in expired.iter().copied() {
            self.sessions.remove(&session);
            self.events.push(Event::SessionExpired(session));
        }
    }

    /// Closes every connection with a notice. Keep draining transmits for a pass
    /// or two afterwards so the notices go out.
    pub fn shutdown(&mut self) {
        for conn in self.connections.as_mut_slice() {
            conn.close(CloseReason::ServerShutdown);
        }
    }

    // ------------------------------------------------------------ rate limits

    /// Spends handshake budget, per address and globally.
    ///
    /// Each handshake packet costs a decryption, so an unbounded flood is a CPU
    /// attack even though none of them allocate. The per-address bucket stops
    /// one host; the global budget stops a distributed flood where every source
    /// is individually within its limit.
    fn charge_handshake(&mut self, ctx: &mut Ctx, from: SocketAddr) -> Result<(), DropReason> {
        if self.handshake_budget == 0 {
            ctx.counters.inc(Counter::HandshakesRateLimited);
            return Err(DropReason::RateLimited);
        }
        if !self.limiter.take(ctx.now, from) {
            ctx.counters.inc(Counter::HandshakesRateLimited);
            return Err(DropReason::RateLimited);
        }
        self.handshake_budget -= 1;
        Ok(())
    }
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

/// Per-address token bucket in a fixed, direct-mapped table.
///
/// Spraying source addresses cannot grow it, and a collision only means two
/// addresses share a bucket, which throttles rather than blocks.
struct RateLimiter {
    slots: Box<[Bucket]>,
    mask: usize,
}

#[derive(Clone, Copy)]
struct Bucket {
    key: u64,
    tokens: u16,
    last_refill: Timestamp,
}

impl Default for Bucket {
    fn default() -> Self {
        Self {
            key: 0,
            tokens: HANDSHAKE_BURST,
            last_refill: Timestamp::ZERO,
        }
    }
}

impl RateLimiter {
    fn new(slots: usize) -> Self {
        let slots = slots.next_power_of_two();
        Self {
            slots: vec![Bucket::default(); slots].into_boxed_slice(),
            mask: slots - 1,
        }
    }

    fn take(&mut self, now: Timestamp, addr: SocketAddr) -> bool {
        let key = hash_addr(addr);
        let slot = &mut self.slots[(key as usize) & self.mask];

        if slot.key != key {
            *slot = Bucket { key, tokens: HANDSHAKE_BURST, last_refill: now };
        } else {
            let elapsed = now.saturating_since(slot.last_refill);
            let refills = (elapsed.as_nanos() / HANDSHAKE_REFILL_INTERVAL.as_nanos()) as u64;
            if refills > 0 {
                let gained = u16::try_from(refills).unwrap_or(u16::MAX);
                slot.tokens = slot.tokens.saturating_add(gained).min(HANDSHAKE_BURST);
                let steps = refills.min(u32::MAX as u64) as u32;
                slot.last_refill = slot.last_refill.saturating_add(HANDSHAKE_REFILL_INTERVAL * steps);
            }
        }

        if slot.tokens == 0 {
            return false;
        }
        slot.tokens -= 1;
        true
    }
}

/// FNV-1a over the address and port. Adequate here: the result only picks a slot
/// and confirms its occupant, and guards no ordered structure.
fn hash_addr(addr: SocketAddr) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET;
    let mut feed = |byte: u8| {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(PRIME);
    };

    match addr.ip() {
        IpAddr::V4(ip) => ip.octets().iter().for_each(|b| feed(*b)),
        IpAddr::V6(ip) => ip.octets().iter().for_each(|b| feed(*b)),
    }
    // Port included, so clients behind one NAT do not share a bucket.
    addr.port().to_le_bytes().iter().for_each(|b| feed(*b));
    hash
}
