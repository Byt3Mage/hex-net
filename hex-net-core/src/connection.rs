//! One peer's state machine, parameterised by which side of it we are.
//!
//! Everything that differs between the two sides is either associated state on
//! the role or an inherent method on one instantiation, so a client connection
//! has no path-validation state and a server connection has no received ticket.

use std::net::SocketAddr;
use std::time::Duration;

use crate::ack::{Delivery, Rtt, decode_ack_delay, encode_ack_delay};
use crate::bits::{BitReader, BitWriter, ReadError};
use crate::budget::{Budget, BudgetConfig};
use crate::channel::{ChannelSet, Channels, OnMessage, PacketMessages, SendError};
use crate::crypto::{Key, Keys, MAX_BLOB};
use crate::ctx::Ctx;
use crate::fixed::RingQueue;
use crate::handshake::{EncryptedTicket, SessionId};
use crate::packet::{DecryptError, Packet, PacketCrypto};
use crate::seq::{Sequence, WindowError};
use crate::stats::Counter;
use crate::time::Timestamp;
use crate::wire::{ConnectionId, ControlKind, FrameKind, Header, PacketKind, TAG_LEN};

/// No packet received for this long and the connection is dead.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Minimum send rate, which holds NAT mappings open and gives the peer a steady
/// liveness signal.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(1);

/// Longest an acknowledgement may wait for a packet to ride on.
pub const MAX_ACK_DELAY: Duration = Duration::from_millis(25);

/// A close notice is unreliable, so it goes out more than once.
const CLOSE_SENDS: u8 = 3;

/// How long an unproven path is probed before it is abandoned.
const PATH_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CloseReason {
    /// The application asked to disconnect.
    Requested = 0,
    TimedOut = 1,
    /// An authenticated peer sent something the protocol does not allow.
    ProtocolViolation = 2,
    ServerShutdown = 3,
}

impl CloseReason {
    const BITS: u32 = 3;

    fn from_bits(bits: u32) -> Option<CloseReason> {
        match bits {
            0 => Some(CloseReason::Requested),
            1 => Some(CloseReason::TimedOut),
            2 => Some(CloseReason::ProtocolViolation),
            3 => Some(CloseReason::ServerShutdown),
            _ => None,
        }
    }
}

/// Why a datagram was discarded. All are routine on the open internet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecvError {
    Malformed,
    Duplicate,
    /// Forged, corrupted, or encrypted with a different key.
    Unauthenticated,
    /// Decrypted, but its frames did not parse, or carried a control frame this
    /// side may not receive. Closes the connection.
    BadPayload,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// The peer's address changed and the new one has been verified.
    Migrated(SocketAddr),
    /// A resume ticket arrived; collect it with `take_resume_ticket`.
    ResumeTicketReceived,
    Closed(CloseReason),
}

impl Default for Event {
    fn default() -> Self {
        Event::Closed(CloseReason::Requested)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    Open,
    /// Sending close notices. Accepts no further application data.
    Closing {
        reason: CloseReason,
        remaining: u8,
    },
    Closed,
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::ClientRole {}
    impl Sealed for super::ServerRole {}
}

/// Which side of a connection this is.
///
/// Sealed: the two sides of the protocol are fixed, and an outside
/// implementation could not satisfy the wire contract.
pub trait Role: Sized + sealed::Sealed {
    /// State only this side holds.
    type State;

    /// Splits a session's keys into this side's transmit and receive pair.
    fn split_keys(keys: &Keys) -> (Key, Key);

    /// Handles a control frame other than Ping or Close, which are symmetric
    /// and handled in shared code.
    ///
    /// A frame only the opposite side sends is a protocol violation: an
    /// authenticated peer producing one is broken or hostile.
    fn read_control(conn: &mut Connection<Self>, kind: ControlKind, r: &mut BitReader) -> Result<(), ReadError>;

    /// Writes this side's control frames. Returns whether anything was written.
    fn write_control(conn: &mut Connection<Self>, w: &mut BitWriter) -> bool;

    /// An authenticated packet arrived from an address other than the current
    /// one.
    fn on_address_change(conn: &mut Connection<Self>, now: Timestamp, from: SocketAddr, sequence: Sequence);

    /// Role-specific timer work, run after the shared timers.
    fn on_timeout(conn: &mut Connection<Self>, now: Timestamp);

    /// Role-specific deadline, folded into `next_timeout`.
    fn next_deadline(conn: &Connection<Self>) -> Option<Timestamp>;
}

/// Identifies the server by address, so it never validates paths. It answers
/// challenges rather than issuing them.
pub struct ClientRole;

pub struct ClientState {
    /// Set when a ticket arrives, cleared when the application takes it.
    ticket_unread: bool,
    /// A challenge token awaiting its echo.
    pending_path_response: Option<u64>,
}

/// Validates any address change before trusting it, and issues resume tickets.
pub struct ServerRole;

pub struct ServerState {
    session: SessionId,
    /// The ticket this connection was accepted from, so a retried handshake can
    /// be recognised and the connection released from the accepted table.
    token_id: u64,
    /// Queued until the acceptance frame has gone out.
    pending_accept: bool,
    probe: Option<Probe>,
    pending_path_challenge: Option<u64>,
}

#[derive(Clone, Copy)]
struct Probe {
    addr: SocketAddr,
    token: u64,
    started: Timestamp,
}

/// Independent of every other connection, which is what lets a server process
/// them in parallel without locks. Never touches a socket.
pub struct Connection<R: Role> {
    id: ConnectionId,
    /// Where packets are sent. Changes only after path validation.
    addr: SocketAddr,
    lifecycle: Lifecycle,

    /// - Server: A ticket queued for delivery.
    /// - Client: The most recent ticket the server sent.
    ticket: Option<EncryptedTicket>,

    crypto: PacketCrypto,
    delivery: Delivery<128>,
    budget: Budget,
    channels: Channels,

    /// When a packet needing acknowledgement arrived, so the delay can be
    /// reported and subtracted from the peer's RTT sample.
    ack_pending: Option<Timestamp>,

    last_received: Timestamp,
    pending_ping: bool,

    events: RingQueue<Event, 16>,
    role: R::State,
}

impl<R: Role> Connection<R> {
    fn new(
        now: Timestamp,
        id: ConnectionId,
        addr: SocketAddr,
        keys: &Keys,
        channels: ChannelSet,
        budget: BudgetConfig,
        role: R::State,
    ) -> Self {
        let (tx, rx) = R::split_keys(keys);

        Self {
            id,
            addr,
            lifecycle: Lifecycle::Open,
            ticket: None,
            // The connection id forms half of every nonce, so a resumed session
            // may reuse its keys under a newly assigned id.
            crypto: PacketCrypto::new(id, &tx, &rx),
            delivery: Delivery::new(now),
            budget: Budget::new(now, budget),
            channels: Channels::new(channels),
            ack_pending: None,
            last_received: now,
            pending_ping: false,
            events: RingQueue::new(),
            role,
        }
    }

    #[inline]
    pub fn id(&self) -> ConnectionId {
        self.id
    }

    #[inline]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    #[inline]
    pub fn rtt(&self) -> &Rtt {
        self.delivery.rtt()
    }

    /// The current send allowance in bytes per second. Below the configured rate
    /// means the controller has backed off.
    #[inline]
    pub fn send_rate(&self) -> u32 {
        self.budget.rate()
    }

    #[inline]
    pub fn is_closed(&self) -> bool {
        self.lifecycle == Lifecycle::Closed
    }

    #[inline]
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop()
    }

    /// Queues a message on a channel.
    #[inline]
    pub fn send(&mut self, channel: u8, payload: &[u8]) -> Result<(), SendError> {
        self.channels.send(channel, payload)
    }

    /// Begins an orderly close. The next few packets carry the notice.
    pub fn close(&mut self, reason: CloseReason) {
        if self.lifecycle == Lifecycle::Open {
            self.lifecycle = Lifecycle::Closing { reason, remaining: CLOSE_SENDS };
        }
    }

    // ---------------------------------------------------------------- receive

    /// Processes one datagram. `buf[..len]` is decrypted in place, and
    /// `on_message` is called for each message it delivers, with a payload
    /// borrowed from that buffer.
    pub fn handle_datagram(
        &mut self,
        ctx: &mut Ctx,
        from: SocketAddr,
        buf: &mut Packet,
        len: usize,
        on_message: OnMessage,
    ) -> Result<(), RecvError> {
        if self.lifecycle == Lifecycle::Closed {
            return Err(RecvError::Closed);
        }

        let opened = match self.crypto.decrypt(buf, len) {
            Ok(opened) => opened,
            Err(DecryptError::Malformed) => {
                ctx.counters.inc(Counter::PacketsMalformed);
                return Err(RecvError::Malformed);
            }
            Err(DecryptError::Replay(WindowError::Duplicate)) => {
                ctx.counters.inc(Counter::PacketsDuplicate);
                return Err(RecvError::Duplicate);
            }
            Err(DecryptError::Replay(WindowError::TooOld)) => {
                ctx.counters.inc(Counter::PacketsTooOld);
                return Err(RecvError::Duplicate);
            }
            Err(DecryptError::Unauthenticated) => {
                ctx.counters.inc(Counter::DecryptFailures);
                return Err(RecvError::Unauthenticated);
            }
        };

        self.last_received = ctx.now;
        ctx.counters.inc(Counter::DatagramsReceived);
        ctx.counters.add(Counter::BytesReceived, len as u64);

        self.handle_ack(ctx, &opened.header);

        let body = &buf[opened.body];
        let eliciting = match self.read_frames(body, on_message) {
            Ok(eliciting) => eliciting,
            Err(_) => {
                ctx.counters.inc(Counter::PacketsMalformed);
                // An authenticated peer sending unparseable frames, or a frame
                // only the other role may send, is broken or hostile; either way
                // the connection cannot continue.
                self.close(CloseReason::ProtocolViolation);
                return Err(RecvError::BadPayload);
            }
        };

        if eliciting {
            self.crypto.record_eliciting(opened.sequence);
            if self.ack_pending.is_none() {
                self.ack_pending = Some(ctx.now);
            }
        }

        if from != self.addr {
            R::on_address_change(self, ctx.now, from, opened.sequence);
        }
        Ok(())
    }

    fn handle_ack(&mut self, ctx: &mut Ctx, header: &Header) {
        let Some(wire_ack) = header.ack else { return };
        let Some(ack) = self.crypto.resolve_ack(wire_ack) else { return };

        let mut acked = 0u64;
        self.delivery.on_ack(
            ctx.now,
            ack,
            decode_ack_delay(header.ack_delay),
            header.ack_bits,
            |event| {
                acked += event.confirmed as u64;
                self.channels.on_delivery(event);
            },
        );
        ctx.counters.add(Counter::PacketsAcked, acked);
    }

    /// Reads frames until padding or the end of the payload.
    ///
    /// Returns whether the packet carried anything worth acknowledging: a packet
    /// of nothing but acknowledgements must not itself be acknowledged, or the
    /// two sides would acknowledge each other forever.
    fn read_frames(&mut self, body: &[u8], on_message: OnMessage) -> Result<bool, ReadError> {
        let mut r = BitReader::new(body);
        let mut eliciting = false;
        while r.bits_remaining() >= (FrameKind::BITS as usize) {
            match FrameKind::read(&mut r)? {
                FrameKind::Padding => break,
                FrameKind::Control => self.read_control(&mut r)?,
                FrameKind::Message => self.channels.read_message(&mut r, on_message)?,
                _ => return Err(ReadError::OutOfRange),
            }
            eliciting = true;
        }
        Ok(eliciting)
    }

    /// Ping and Close are symmetric; everything else is role-specific.
    fn read_control(&mut self, r: &mut BitReader) -> Result<(), ReadError> {
        match ControlKind::read(r)? {
            ControlKind::Ping => Ok(()),
            ControlKind::Close => {
                let reason = CloseReason::from_bits(r.read_bits(CloseReason::BITS)?).ok_or(ReadError::OutOfRange)?;
                self.lifecycle = Lifecycle::Closed;
                self.events.push(Event::Closed(reason));
                Ok(())
            }
            other => R::read_control(self, other, r),
        }
    }

    /// Builds the next packet, if there is one. Returns its length in `buf`.
    ///
    /// One packet per call: coalescing everything for a peer into a single
    /// datagram amortizes 28 bytes of IP and UDP overhead plus our header and
    /// the authentication tag.
    pub fn poll_transmit(&mut self, ctx: &mut Ctx, buf: &mut Packet) -> Option<usize> {
        if self.lifecycle == Lifecycle::Closed {
            return None;
        }

        self.budget.assess(ctx.now, self.delivery.rtt());
        let allowance = self.budget.available(ctx.now) as usize;

        let ticket = self.crypto.next_sequence();
        let sequence = ticket.sequence();
        let header = self.build_header(ctx.now, sequence);
        let body = self.crypto.begin(&header, buf);
        let header_len = body.start;

        let mut w = BitWriter::new(&mut buf[body]);

        // Control frames ignore the budget: acknowledgements and keepalives are
        // what let a constrained connection discover conditions improved, and a
        // close notice must go out even when nothing else can.
        let mut eliciting = self.write_control(&mut w);

        // What remains of the allowance after the parts already committed to
        // this datagram, which the budget counts in full.
        let overhead = header_len + TAG_LEN + w.bits_written().div_ceil(8);
        let channel_limit = allowance.saturating_sub(overhead);

        let mut staged = PacketMessages::new();

        if (self.lifecycle == Lifecycle::Open) && (channel_limit > 0) {
            eliciting |= self.channels.write_frames(&mut w, &mut staged, channel_limit);
        }

        if !eliciting && header.ack.is_none() {
            // Nothing to say and no acknowledgement owed. Keepalives come from
            // the timer, which queues a ping.
            self.channels.on_packet_aborted(staged);
            return None;
        }

        let _ = FrameKind::Padding.write(&mut w);
        let body_end = header_len + w.finish();

        let Ok(len) = self.crypto.encrypt(ticket, buf, header_len, body_end) else {
            self.channels.on_packet_aborted(staged);
            return None;
        };

        self.channels.on_packet_sent(sequence, staged);

        self.delivery.on_sent(ctx.now, sequence, len, eliciting);
        self.budget.on_sent(len);
        self.ack_pending = None;
        ctx.counters.inc(Counter::DatagramsSent);
        ctx.counters.add(Counter::BytesSent, len as u64);

        if let Lifecycle::Closing { reason, remaining } = self.lifecycle {
            self.lifecycle = match remaining.checked_sub(1) {
                Some(0) | None => {
                    self.events.push(Event::Closed(reason));
                    Lifecycle::Closed
                }
                Some(left) => Lifecycle::Closing { reason, remaining: left },
            };
        }
        Some(len)
    }

    fn build_header(&self, now: Timestamp, sequence: Sequence) -> Header {
        let newest = self.crypto.newest_acknowledged();

        let (ack, ack_delay) = match self.ack_pending {
            Some(since) => (Some(newest.to_wire()), encode_ack_delay(now.saturating_since(since))),
            // Repeating the newest sequence costs three bytes and gives the peer
            // another chance to learn about packets whose earlier
            // acknowledgements were lost.
            None if !newest.is_none() => (Some(newest.to_wire()), 0),
            None => (None, 0),
        };

        Header {
            kind: PacketKind::Payload,
            conn_id: self.id,
            sequence: sequence.to_wire(),
            ack,
            ack_delay,
            ack_bits: if ack.is_some() { self.crypto.ack_bits() } else { 0 },
        }
    }

    /// Close first, then this side's own frames, then a keepalive ping. Anything
    /// that does not fit is left queued for the next packet.
    fn write_control(&mut self, w: &mut BitWriter) -> bool {
        let mut wrote = self.write_close(w);
        wrote |= R::write_control(self, w);
        wrote |= self.write_ping(w);
        wrote
    }

    fn write_close(&mut self, w: &mut BitWriter) -> bool {
        let Lifecycle::Closing { reason, .. } = self.lifecycle else {
            return false;
        };
        let at = w.checkpoint();
        let ok = FrameKind::Control.write(w).is_ok()
            && ControlKind::Close.write(w).is_ok()
            && w.write_bits(reason as u32, CloseReason::BITS).is_ok();
        if !ok {
            w.rollback(at);
        }
        ok
    }

    fn write_ping(&mut self, w: &mut BitWriter) -> bool {
        if !self.pending_ping {
            return false;
        }
        let at = w.checkpoint();
        let ok = FrameKind::Control.write(w).is_ok() && ControlKind::Ping.write(w).is_ok();
        if ok {
            self.pending_ping = false;
        } else {
            w.rollback(at);
        }
        ok
    }

    // ----------------------------------------------------------------- timers

    /// Runs loss detection, keepalives, the idle timeout, and the role's own
    /// timer work.
    pub fn handle_timeout(&mut self, ctx: &mut Ctx) {
        if self.lifecycle == Lifecycle::Closed {
            return;
        }

        if ctx.now.saturating_since(self.last_received) >= IDLE_TIMEOUT {
            self.lifecycle = Lifecycle::Closed;
            self.events.push(Event::Closed(CloseReason::TimedOut));
            return;
        }

        let channels = &mut self.channels;
        let budget = &mut self.budget;
        let mut lost = 0u64;
        self.delivery.detect_lost(ctx.now, |event| {
            lost += 1;
            budget.on_lost();
            channels.on_delivery(event);
        });
        ctx.counters.add(Counter::PacketsLost, lost);

        if ctx.now.saturating_since(self.delivery.last_eliciting()) >= KEEPALIVE_INTERVAL {
            self.pending_ping = true;
        }

        R::on_timeout(self, ctx.now);
    }

    /// The earliest time this connection next needs servicing.
    pub fn next_timeout(&self) -> Option<Timestamp> {
        if self.lifecycle == Lifecycle::Closed {
            return None;
        }

        let mut earliest = self.last_received.saturating_add(IDLE_TIMEOUT);

        if let Some(at) = self.delivery.next_loss_time() {
            earliest = earliest.min(at);
        }
        if let Some(since) = self.ack_pending {
            earliest = earliest.min(since.saturating_add(MAX_ACK_DELAY));
        }
        if let Some(at) = R::next_deadline(self) {
            earliest = earliest.min(at);
        }
        earliest = earliest.min(self.delivery.last_eliciting().saturating_add(KEEPALIVE_INTERVAL));

        Some(earliest)
    }
}

// ----------------------------------------------------------------- client

impl Role for ClientRole {
    type State = ClientState;

    fn split_keys(keys: &Keys) -> (Key, Key) {
        (keys.client_to_server, keys.server_to_client)
    }

    fn read_control(conn: &mut Connection<Self>, kind: ControlKind, r: &mut BitReader) -> Result<(), ReadError> {
        match kind {
            ControlKind::PathChallenge => {
                conn.role.pending_path_response = Some(r.read_u64()?);
                Ok(())
            }

            ControlKind::ResumeTicket => {
                let len = r.read_range(0, MAX_BLOB as u32)? as usize;
                r.align()?;
                let bytes = r.peek_bytes(len).ok_or(ReadError::Eof)?;
                let received = EncryptedTicket::from_slice(bytes).ok_or(ReadError::OutOfRange)?;
                r.skip_bytes(len)?;

                // Only the newest ticket is useful.
                conn.ticket = Some(received);
                conn.role.ticket_unread = true;
                conn.events.push(Event::ResumeTicketReceived);
                Ok(())
            }

            // Carries nothing: a server only produces it for a connection it
            // has created, and it authenticated, so its arrival is the proof.
            ControlKind::Accepted => Ok(()),

            // Only a server receives a path response; Ping and Close never reach
            // here.
            _ => Err(ReadError::OutOfRange),
        }
    }

    fn write_control(conn: &mut Connection<Self>, w: &mut BitWriter) -> bool {
        let Some(token) = conn.role.pending_path_response else {
            return false;
        };
        if write_control_u64(w, ControlKind::PathResponse, token) {
            conn.role.pending_path_response = None;
            true
        } else {
            false
        }
    }

    /// A client sends to one server address, and its driver rejects datagrams
    /// from anywhere else, so this cannot be reached.
    fn on_address_change(_conn: &mut Connection<Self>, _now: Timestamp, _from: SocketAddr, _sequence: Sequence) {}

    fn on_timeout(_conn: &mut Connection<Self>, _now: Timestamp) {}

    fn next_deadline(_conn: &Connection<Self>) -> Option<Timestamp> {
        None
    }
}

impl Connection<ClientRole> {
    /// Created once the server's first packet reveals the assigned connection id.
    pub fn connect(
        now: Timestamp,
        id: ConnectionId,
        addr: SocketAddr,
        keys: &Keys,
        channels: ChannelSet,
        budget: BudgetConfig,
    ) -> Self {
        Self::new(
            now,
            id,
            addr,
            keys,
            channels,
            budget,
            ClientState { ticket_unread: false, pending_path_response: None },
        )
    }

    /// Takes the most recent ticket the server sent, if one has arrived since
    /// the last call.
    ///
    /// Returns a copy and keeps it, so a caller that fails to persist it can ask
    /// again after the next arrival.
    pub fn take_resume_ticket(&mut self) -> Option<EncryptedTicket> {
        if !self.role.ticket_unread {
            return None;
        }
        self.role.ticket_unread = false;
        self.ticket
    }
}

// ----------------------------------------------------------------- server

impl Role for ServerRole {
    type State = ServerState;

    fn split_keys(keys: &Keys) -> (Key, Key) {
        (keys.server_to_client, keys.client_to_server)
    }

    fn read_control(conn: &mut Connection<Self>, kind: ControlKind, r: &mut BitReader) -> Result<(), ReadError> {
        match kind {
            ControlKind::PathResponse => {
                let token = r.read_u64()?;
                let Some(pending) = conn.role.probe else {
                    return Ok(());
                };
                if pending.token == token {
                    conn.role.probe = None;
                    conn.addr = pending.addr;
                    conn.events.push(Event::Migrated(pending.addr));
                }
                Ok(())
            }

            // Only a client receives these; Ping and Close never reach here.
            _ => Err(ReadError::OutOfRange),
        }
    }

    fn write_control(conn: &mut Connection<Self>, w: &mut BitWriter) -> bool {
        let mut wrote = false;

        if conn.role.pending_accept {
            let at = w.checkpoint();
            let ok = FrameKind::Control.write(w).is_ok() && ControlKind::Accepted.write(w).is_ok();
            if ok {
                conn.role.pending_accept = false;
                wrote = true;
            } else {
                w.rollback(at);
            }
        }

        if let Some(token) = conn.role.pending_path_challenge
            && write_control_u64(w, ControlKind::PathChallenge, token)
        {
            conn.role.pending_path_challenge = None;
            wrote = true;
        }

        if let Some(queued) = conn.ticket {
            let at = w.checkpoint();
            let ok = FrameKind::Control.write(w).is_ok()
                && ControlKind::ResumeTicket.write(w).is_ok()
                && w.write_range(queued.len() as u32, 0, MAX_BLOB as u32).is_ok()
                && w.align().is_ok()
                && w.write_bytes(&queued).is_ok();
            if ok {
                conn.ticket = None;
                wrote = true;
            } else {
                // Did not fit, so it stays queued for the next packet.
                w.rollback(at);
            }
        }
        wrote
    }

    /// The new address is challenged while real traffic continues to the old
    /// one, so a packet replayed from a forged source cannot redirect the
    /// connection.
    fn on_address_change(conn: &mut Connection<Self>, now: Timestamp, from: SocketAddr, sequence: Sequence) {
        if let Some(pending) = conn.role.probe
            && pending.addr == from
        {
            return;
        }

        let token = sequence.get().wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ now.as_nanos().rotate_left(17);
        conn.role.probe = Some(Probe { addr: from, token, started: now });
        conn.role.pending_path_challenge = Some(token);
    }

    fn on_timeout(conn: &mut Connection<Self>, now: Timestamp) {
        let Some(pending) = conn.role.probe else { return };
        if now.saturating_since(pending.started) >= PATH_TIMEOUT {
            // Unproven; the existing address keeps carrying traffic.
            conn.role.probe = None;
        }
    }

    fn next_deadline(conn: &Connection<Self>) -> Option<Timestamp> {
        let pending = conn.role.probe?;
        Some(pending.started.saturating_add(PATH_TIMEOUT))
    }
}

impl Connection<ServerRole> {
    pub fn accept(
        now: Timestamp,
        id: ConnectionId,
        session: SessionId,
        token_id: u64,
        addr: SocketAddr,
        keys: &Keys,
        channels: ChannelSet,
        budget: BudgetConfig,
    ) -> Self {
        Self::new(
            now,
            id,
            addr,
            keys,
            channels,
            budget,
            ServerState {
                session,
                token_id,
                pending_accept: true,
                probe: None,
                pending_path_challenge: None,
            },
        )
    }

    /// Queues the acceptance frame again, for a client that retried its
    /// handshake because the first acceptance was lost.
    pub fn resend_acceptance(&mut self) {
        self.role.pending_accept = true;
    }

    /// The session this connection serves. A client has no use for its own
    /// session id: it lives inside the sealed resume ticket, readable only here.
    #[inline]
    pub fn session(&self) -> SessionId {
        self.role.session
    }

    /// The ticket this connection was accepted from.
    #[inline]
    pub fn token_id(&self) -> u64 {
        self.role.token_id
    }

    /// The address being probed, if any. A packet sent to the primary address is
    /// also sent here until the probe is answered.
    #[inline]
    pub fn probe_addr(&self) -> Option<SocketAddr> {
        self.role.probe.map(|probe| probe.addr)
    }

    /// Queues a resume ticket for delivery. Call periodically so the client
    /// always holds a fresh one.
    pub fn send_resume_ticket(&mut self, ticket: EncryptedTicket) {
        self.ticket = Some(ticket);
    }
}

fn write_control_u64(w: &mut BitWriter, kind: ControlKind, value: u64) -> bool {
    let at = w.checkpoint();
    let ok = FrameKind::Control.write(w).is_ok()
        && kind.write(w).is_ok()
        && w.write_bits(value as u32, 32).is_ok()
        && w.write_bits((value >> 32) as u32, 32).is_ok();
    if !ok {
        w.rollback(at);
    }
    ok
}
