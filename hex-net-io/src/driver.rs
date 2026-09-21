//! The loop that joins a socket to the transport: feed received datagrams in,
//! run what is due, send what comes out, and report when to come back.
//!
//! `step` never blocks. Waiting, for the socket to become readable or for the
//! returned deadline to arrive, belongs to the caller, which is what lets one
//! driver run over a real socket and over the simulator alike.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use hex_net_core::{
    connector::{Action as ClientAction, Connector, State},
    ctx::Ctx,
    endpoint::{Action as ServerAction, Destinations, Endpoint, Event, PacketSink, ServerConnection},
    packet::Packet,
    slab::Handle,
    stats::{Counter, Counters},
    time::Timestamp,
    wire::MAX_DATAGRAM,
};

use crate::{Received, Socket, Transmit};

/// Datagrams taken from the socket per call.
const RECV_BATCH: usize = 32;

/// Packets built before the socket is called to send them. A packet going to
/// a path under validation is sent twice, so a flush carries up to twice
/// this many datagrams.
const SEND_BATCH: usize = 32;

const MAX_TRANSMITS: usize = SEND_BATCH * 2;

/// What the server-side application sees of the transport.
pub trait ServerApp {
    /// A message arrived on `conn` at `at`, which is when the datagram
    /// carrying it reached the socket. The payload is only valid during the
    /// call.
    fn on_message(&mut self, at: Timestamp, conn: Handle<ServerConnection>, channel: u8, payload: &[u8]);

    fn on_event(&mut self, event: Event);

    /// Runs once per step, after input and timers and before output, so
    /// whatever it queues goes out in the same step.
    fn update(&mut self, now: Timestamp, endpoint: &mut Endpoint);

    /// When `update` next needs to run regardless of traffic, such as the next
    /// simulation tick.
    fn next_wake(&self) -> Option<Timestamp>;
}

/// What the client-side application sees of the transport.
pub trait ClientApp {
    /// A message arrived at `at`, which is when the datagram carrying it
    /// reached the socket. The payload is only valid during the call.
    fn on_message(&mut self, at: Timestamp, channel: u8, payload: &[u8]);

    /// The connector changed state: connected, failed, or closed.
    fn on_state(&mut self, state: State);

    /// Runs once per step, after input and timers and before output, so
    /// whatever it queues goes out in the same step.
    fn update(&mut self, now: Timestamp, connector: &mut Connector);

    /// When `update` next needs to run regardless of traffic.
    fn next_wake(&self) -> Option<Timestamp>;
}

/// Receive buffers and the metadata the socket fills in beside them.
struct Inbox {
    packets: Box<[Packet; RECV_BATCH]>,
    received: [Received; RECV_BATCH],
}

impl Inbox {
    fn new() -> Self {
        Self {
            packets: Box::new([[0u8; MAX_DATAGRAM]; RECV_BATCH]),
            received: [Received { from: unspecified(), len: 0, at: Timestamp::ZERO }; _],
        }
    }

    /// Fills the batch from the socket. Returns how many arrived.
    fn fill(&mut self, socket: &mut impl Socket) -> io::Result<usize> {
        let mut buffers = self.packets.each_mut().map(|packet| packet.as_mut_slice());
        socket.recv_batch(&mut buffers, &mut self.received)
    }
}

/// Packets awaiting a send call. Built in place by the transport, so nothing is
/// copied between building a packet and handing it to the socket.
struct Outbox {
    packets: Box<[Packet; SEND_BATCH]>,
    dests: [Destinations; SEND_BATCH],
    lens: [usize; SEND_BATCH],
    used: usize,
}

impl Outbox {
    fn new() -> Self {
        Self {
            packets: Box::new([[0u8; MAX_DATAGRAM]; SEND_BATCH]),
            dests: [Destinations { primary: unspecified(), probe: None }; SEND_BATCH],
            lens: [0; SEND_BATCH],
            used: 0,
        }
    }

    #[inline]
    fn is_full(&self) -> bool {
        self.used == SEND_BATCH
    }

    /// Queues a copy of a packet built elsewhere: a handshake reply.
    fn push(&mut self, to: SocketAddr, bytes: &[u8]) {
        let len = bytes.len().min(MAX_DATAGRAM);
        self.packets[self.used][..len].copy_from_slice(&bytes[..len]);
        self.commit(Destinations { primary: to, probe: None }, len);
    }

    /// Sends everything queued. Datagrams the socket did not take are dropped
    /// and counted: the transport already recovers from loss, and holding them
    /// for a retry would only make them staler.
    fn flush(&mut self, socket: &mut impl Socket, counters: &mut Counters) -> io::Result<()> {
        if self.used == 0 {
            return Ok(());
        }

        let mut buffers: [&[u8]; MAX_TRANSMITS] = [&[]; MAX_TRANSMITS];
        let mut transmits = [Transmit { to: unspecified(), len: 0 }; MAX_TRANSMITS];
        let mut count = 0;

        for slot in 0..self.used {
            let to = self.dests[slot];
            let bytes = &self.packets[slot][..self.lens[slot]];
            for addr in [Some(to.primary), to.probe].into_iter().flatten() {
                buffers[count] = bytes;
                transmits[count] = Transmit { to: addr, len: bytes.len() };
                count += 1;
            }
        }
        self.used = 0;

        let sent = socket.send_batch(&buffers[..count], &transmits[..count])?;
        counters.add(Counter::SendFailures, (count - sent.min(count)) as u64);
        Ok(())
    }
}

impl PacketSink for Outbox {
    fn next_slot(&mut self) -> Option<&mut Packet> {
        if self.is_full() {
            return None;
        }
        Some(&mut self.packets[self.used])
    }

    fn commit(&mut self, to: Destinations, len: usize) {
        self.dests[self.used] = to;
        self.lens[self.used] = len;
        self.used += 1;
    }
}

/// Runs an endpoint over a socket.
pub struct ServerDriver<S: Socket> {
    socket: S,
    endpoint: Endpoint,
    counters: Counters,
    inbox: Inbox,
    reply: Box<Packet>,
    outbox: Outbox,
}

impl<S: Socket> ServerDriver<S> {
    pub fn new(socket: S, endpoint: Endpoint) -> Self {
        Self {
            socket,
            endpoint,
            counters: Counters::new(),
            inbox: Inbox::new(),
            reply: Box::new([0u8; MAX_DATAGRAM]),
            outbox: Outbox::new(),
        }
    }

    #[inline]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Changes made here are sent on the next step.
    #[inline]
    pub fn endpoint_mut(&mut self) -> &mut Endpoint {
        &mut self.endpoint
    }

    #[inline]
    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    #[inline]
    pub fn socket(&self) -> &S {
        &self.socket
    }

    /// Does everything due at `now`: takes every waiting datagram, services
    /// expired timers, lets the application update, and sends the result.
    ///
    /// Returns when to call again if no datagram arrives first. A time at or
    /// before `now` means immediately.
    pub fn step(&mut self, now: Timestamp, app: &mut impl ServerApp) -> io::Result<Option<Timestamp>> {
        self.receive(app)?;

        let mut ctx = Ctx::new(now, &mut self.counters);
        self.endpoint.handle_timeout(&mut ctx);
        while let Some(event) = self.endpoint.poll_event() {
            app.on_event(event);
        }

        app.update(now, &mut self.endpoint);
        self.transmit(now)?;

        Ok(earliest(self.endpoint.next_timeout(), app.next_wake()))
    }

    fn receive(&mut self, app: &mut impl ServerApp) -> io::Result<()> {
        loop {
            let count = self.inbox.fill(&mut self.socket)?;
            for index in 0..count {
                let received = self.inbox.received[index];
                // The kernel's arrival time, not ours, so scheduling delay stays
                // out of every RTT sample.
                let action = self.endpoint.handle_datagram(
                    &mut Ctx::new(received.at, &mut self.counters),
                    received.from,
                    &mut self.inbox.packets[index],
                    received.len.min(MAX_DATAGRAM),
                    &mut self.reply,
                    &mut |conn, channel, payload| app.on_message(received.at, conn, channel, payload),
                );
                if let ServerAction::Respond { addr, len } = action {
                    if self.outbox.is_full() {
                        self.outbox.flush(&mut self.socket, &mut self.counters)?;
                    }
                    self.outbox.push(addr, &self.reply[..len]);
                }
            }
            if count < RECV_BATCH {
                return Ok(());
            }
        }
    }

    /// Drains the endpoint into send batches until it has nothing more.
    fn transmit(&mut self, now: Timestamp) -> io::Result<()> {
        loop {
            let mut ctx = Ctx::new(now, &mut self.counters);
            self.endpoint.drain_transmits(&mut ctx, &mut self.outbox);
            let filled = self.outbox.is_full();
            self.outbox.flush(&mut self.socket, &mut self.counters)?;
            if !filled {
                return Ok(());
            }
        }
    }
}

/// Runs a connector over a socket.
pub struct ClientDriver<S: Socket> {
    socket: S,
    connector: Connector,
    counters: Counters,
    inbox: Inbox,
    reply: Box<Packet>,
    outbox: Outbox,
    reported: State,
}

impl<S: Socket> ClientDriver<S> {
    pub fn new(socket: S, connector: Connector) -> Self {
        let reported = connector.state();
        Self {
            socket,
            connector,
            counters: Counters::new(),
            inbox: Inbox::new(),
            reply: Box::new([0u8; MAX_DATAGRAM]),
            outbox: Outbox::new(),
            reported,
        }
    }

    #[inline]
    pub fn connector(&self) -> &Connector {
        &self.connector
    }

    /// Changes made here are sent on the next step.
    #[inline]
    pub fn connector_mut(&mut self) -> &mut Connector {
        &mut self.connector
    }

    #[inline]
    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    #[inline]
    pub fn socket(&self) -> &S {
        &self.socket
    }

    /// Does everything due at `now`, as `ServerDriver::step` does.
    ///
    /// Sends at most one packet. A connection builds one per call, and whatever
    /// is left over makes the returned deadline immediate.
    pub fn step(&mut self, now: Timestamp, app: &mut impl ClientApp) -> io::Result<Option<Timestamp>> {
        self.receive(app)?;

        let mut ctx = Ctx::new(now, &mut self.counters);
        let _ = self.connector.handle_timeout(&mut ctx);
        self.report(app);

        app.update(now, &mut self.connector);

        let mut ctx = Ctx::new(now, &mut self.counters);
        if let Some(slot) = self.outbox.next_slot()
            && let Some(len) = self.connector.poll_transmit(&mut ctx, slot)
        {
            let to = Destinations { primary: self.connector.server(), probe: None };
            self.outbox.commit(to, len);
        }
        self.outbox.flush(&mut self.socket, &mut self.counters)?;
        self.report(app);

        Ok(earliest(self.connector.next_timeout(), app.next_wake()))
    }

    fn receive(&mut self, app: &mut impl ClientApp) -> io::Result<()> {
        let server = self.connector.server();
        loop {
            let count = self.inbox.fill(&mut self.socket)?;
            for index in 0..count {
                let received = self.inbox.received[index];
                let action = self.connector.handle_datagram(
                    &mut Ctx::new(received.at, &mut self.counters),
                    received.from,
                    &mut self.inbox.packets[index],
                    received.len.min(MAX_DATAGRAM),
                    &mut self.reply,
                    &mut |channel, payload| app.on_message(received.at, channel, payload),
                );
                if let ClientAction::Send(len) = action {
                    if self.outbox.is_full() {
                        self.outbox.flush(&mut self.socket, &mut self.counters)?;
                    }
                    self.outbox.push(server, &self.reply[..len]);
                }
                self.report(app);
            }
            if count < RECV_BATCH {
                return Ok(());
            }
        }
    }

    fn report(&mut self, app: &mut impl ClientApp) {
        let state = self.connector.state();
        if state != self.reported {
            self.reported = state;
            app.on_state(state);
        }
    }
}

fn earliest(a: Option<Timestamp>, b: Option<Timestamp>) -> Option<Timestamp> {
    a.into_iter().chain(b).min()
}

/// Filler for batch slots the socket has not written.
fn unspecified() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
}
