//! The client's side: driving one handshake and one connection.

use std::net::SocketAddr;
use std::time::Duration;

use crate::budget::BudgetConfig;
use crate::channel::{ChannelSet, OnMessage};
use crate::connection::{ClientRole, CloseReason, Connection, Event as ConnEvent, RecvError, ResumeTicket};
use crate::crypto::{Keys, MAX_BLOB};
use crate::ctx::Ctx;
use crate::fixed::FixedVec;
use crate::packet::Packet;
use crate::stats::Counter;
use crate::time::Timestamp;
use crate::wire::{ConnectionId, HANDSHAKE_LEN, Header, PacketKind, encode_handshake, handshake_blob};

/// Handshake steps are resent on this interval until answered.
const RETRY_INTERVAL: Duration = Duration::from_millis(250);

/// Gives up after this long, about twenty attempts.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectError {
    /// The server never answered. It says nothing when it refuses a ticket
    /// either: a reply would confirm which forged tickets are closer to valid,
    /// and would give an unauthenticated sender something to amplify.
    TimedOut,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Sent a ticket; waiting for a challenge.
    Requesting,
    /// Echoing a cookie; waiting for the first payload packet.
    Responding,
    Connected,
    Failed(ConnectError),
    Closed(CloseReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Done,
    /// Send `out[..len]` to the server.
    Send(usize),
    /// The handshake completed; `connection_mut` is available.
    Connected,
    /// The attempt or the connection ended; check `state`.
    Ended,
}

/// A client has one socket and one peer, so it owns a single connection.
pub struct Connector {
    server: SocketAddr,
    state: State,

    /// The encrypted ticket being presented, kept so it can be resent.
    ticket: FixedVec<u8, MAX_BLOB>,
    /// The cookie from the challenge, echoed until the server accepts it.
    cookie: Option<FixedVec<u8, MAX_BLOB>>,

    /// Known before the handshake: a new player's keys arrive from the backend
    /// alongside the ticket, and a resuming player already holds them.
    keys: Keys,
    channels: ChannelSet,
    budget: BudgetConfig,

    started: Timestamp,
    last_attempt: Timestamp,

    connection: Option<Connection<ClientRole>>,
}

impl Connector {
    /// Starts a new connection. `ticket` and `keys` come from the backend after
    /// the player authenticates.
    ///
    /// Also used to resume a dropped session with the ticket the server issued during
    /// it, reusing the same keys.
    ///
    /// Safe because the server assigns a new connection id, and the id forms
    /// half of every nonce. The session id lives inside the encypted ticket, where
    /// only the server can read it.
    pub fn connect(
        now: Timestamp,
        server: SocketAddr,
        ticket: ResumeTicket,
        keys: Keys,
        channels: ChannelSet,
        budget: BudgetConfig,
    ) -> Self {
        Self {
            server,
            state: State::Requesting,
            ticket,
            cookie: None,
            keys,
            channels,
            budget,
            started: now,
            last_attempt: Timestamp::ZERO,
            connection: None,
        }
    }

    #[inline]
    pub fn state(&self) -> State {
        self.state
    }

    #[inline]
    pub fn connection(&self) -> Option<&Connection<ClientRole>> {
        self.connection.as_ref()
    }

    #[inline]
    pub fn connection_mut(&mut self) -> Option<&mut Connection<ClientRole>> {
        self.connection.as_mut()
    }

    /// Processes one datagram from the server.
    pub fn handle_datagram(
        &mut self,
        ctx: &mut Ctx,
        from: SocketAddr,
        buf: &mut Packet,
        len: usize,
        out: &mut Packet,
        on_message: OnMessage,
    ) -> Action {
        // A client talks to exactly one server; anything else is noise or an
        // injection attempt.
        if from != self.server {
            ctx.counters.inc(Counter::PacketsUnknownConnection);
            return Action::Done;
        }

        let Some(kind) = (len > 0).then(|| PacketKind::from_byte(buf[0])).flatten() else {
            ctx.counters.inc(Counter::PacketsMalformed);
            return Action::Done;
        };

        match (self.state, kind) {
            (State::Requesting, PacketKind::Challenge) => self.on_challenge(ctx, buf, len, out),
            (State::Responding, PacketKind::Payload) => self.on_accepted(ctx, buf, len, on_message),
            (State::Connected, PacketKind::Payload) => self.on_payload(ctx, buf, len, on_message),
            _ => {
                ctx.counters.inc(Counter::PacketsMalformed);
                Action::Done
            }
        }
    }

    fn on_challenge(&mut self, ctx: &mut Ctx, buf: &Packet, len: usize, out: &mut Packet) -> Action {
        if len < HANDSHAKE_LEN {
            ctx.counters.inc(Counter::PacketsMalformed);
            return Action::Done;
        }
        let Some(blob) = handshake_blob(&buf[..len]) else {
            ctx.counters.inc(Counter::PacketsMalformed);
            return Action::Done;
        };
        let Some(cookie) = FixedVec::from_slice(blob) else {
            ctx.counters.inc(Counter::PacketsMalformed);
            return Action::Done;
        };

        // The cookie is opaque, encrypted with a key only the server holds. It is
        // echoed unchanged to prove this address receives.
        self.cookie = Some(cookie);
        self.state = State::Responding;
        self.last_attempt = ctx.now;

        match self.write_handshake(out) {
            Some(len) => Action::Send(len),
            None => Action::Done,
        }
    }

    fn on_accepted(&mut self, ctx: &mut Ctx, buf: &mut Packet, len: usize, on_message: OnMessage) -> Action {
        // The server assigns the connection id, so it is learned from the first
        // packet it sends.
        let Ok((header, _)) = Header::decode(&buf[..len]) else {
            ctx.counters.inc(Counter::PacketsMalformed);
            return Action::Done;
        };

        let conn_id = header.conn_id.unwrap_or(ConnectionId(0));
        let mut conn = Connection::connect(ctx.now, conn_id, self.server, &self.keys, self.channels, self.budget);

        // Verified by decrypting: a forged acceptance cannot authenticate, and
        // failing here leaves the cookie retrying, since the real acceptance may
        // still be in flight.
        if conn.handle_datagram(ctx, self.server, buf, len, on_message).is_err() {
            return Action::Done;
        }

        self.connection = Some(conn);
        self.state = State::Connected;
        Action::Connected
    }

    fn on_payload(&mut self, ctx: &mut Ctx, buf: &mut Packet, len: usize, on_message: OnMessage) -> Action {
        let server = self.server;
        let Some(conn) = self.connection.as_mut() else { return Action::Done };

        match conn.handle_datagram(ctx, server, buf, len, on_message) {
            Ok(()) | Err(RecvError::BadPayload) => {}
            Err(_) => return Action::Done,
        }
        self.drain_connection_events()
    }

    fn drain_connection_events(&mut self) -> Action {
        let Some(conn) = self.connection.as_mut() else { return Action::Done };
        let mut ended = None;

        while let Some(event) = conn.poll_event() {
            if let ConnEvent::Closed(reason) = event {
                ended = Some(reason);
            }
        }

        match ended {
            Some(reason) => {
                self.state = State::Closed(reason);
                Action::Ended
            }
            None => Action::Done,
        }
    }

    /// Produces the next packet. During the handshake this resends the current
    /// step on `RETRY_INTERVAL`; once connected it delegates to the connection.
    pub fn poll_transmit(&mut self, ctx: &mut Ctx, out: &mut Packet) -> Option<usize> {
        match self.state {
            State::Requesting | State::Responding => {
                if ctx.now.saturating_since(self.last_attempt) < RETRY_INTERVAL {
                    return None;
                }
                self.last_attempt = ctx.now;
                self.write_handshake(out)
            }
            State::Connected => self.connection.as_mut()?.poll_transmit(ctx, out),
            State::Failed(_) | State::Closed(_) => None,
        }
    }

    /// Writes the current handshake step, padded to HANDSHAKE_LEN.
    fn write_handshake(&self, out: &mut Packet) -> Option<usize> {
        let (kind, blob): (PacketKind, &[u8]) = match self.state {
            State::Requesting => (PacketKind::Request, &self.ticket),
            State::Responding => (PacketKind::Response, self.cookie.as_ref()?),
            _ => return None,
        };
        encode_handshake(kind, blob, out).ok()
    }

    pub fn handle_timeout(&mut self, ctx: &mut Ctx) -> Action {
        match self.state {
            State::Requesting | State::Responding => {
                if ctx.now.saturating_since(self.started) >= HANDSHAKE_TIMEOUT {
                    self.state = State::Failed(ConnectError::TimedOut);
                    return Action::Ended;
                }
                Action::Done
            }
            State::Connected => {
                if let Some(conn) = self.connection.as_mut() {
                    conn.handle_timeout(ctx);
                }
                self.drain_connection_events()
            }
            State::Failed(_) | State::Closed(_) => Action::Done,
        }
    }

    pub fn next_timeout(&self) -> Option<Timestamp> {
        match self.state {
            State::Requesting | State::Responding => Some(
                self.last_attempt
                    .saturating_add(RETRY_INTERVAL)
                    .min(self.started.saturating_add(HANDSHAKE_TIMEOUT)),
            ),
            State::Connected => self.connection.as_ref()?.next_timeout(),
            State::Failed(_) | State::Closed(_) => None,
        }
    }

    /// Begins an orderly close. Keep polling transmits for a pass or two so the
    /// notice reaches the server; otherwise it waits out the idle timeout and
    /// suspends the session needlessly.
    pub fn close(&mut self) {
        if let Some(conn) = self.connection.as_mut() {
            conn.close(CloseReason::Requested);
        }
    }

    /// The most recent resume ticket the server sent. Stored with the keys, it is
    /// what `resume` needs after a drop.
    pub fn take_resume_ticket(&mut self) -> Option<ResumeTicket> {
        self.connection.as_mut()?.take_resume_ticket()
    }
}
