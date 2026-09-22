//! The workload every scenario runs, and the checks every run must pass.
//!
//! The clients send numbered streams, the server echoes them back, and
//! `check` states what that must have produced: nothing lost, nothing
//! duplicated, nothing out of order, nothing left queued, and counters that
//! add up.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    net::SocketAddr,
    time::Duration,
};

use hex_net_core::{
    budget::BudgetConfig,
    channel::SendError,
    connection::CloseReason,
    connector::{Connector, State},
    endpoint::{Endpoint, Event, ServerConnection},
    handshake::SessionId,
    slab::Handle,
    stats::{Counter, Counters},
    time::Timestamp,
};
use hex_net_io::driver::{ClientApp, ServerApp};

use crate::world::World;

/// A message: the client's index, then its sequence number.
pub fn encode(client: u32, seq: u32) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&client.to_le_bytes());
    bytes[4..].copy_from_slice(&seq.to_le_bytes());
    bytes
}

pub fn decode(payload: &[u8]) -> (u32, u32) {
    let client = u32::from_le_bytes(payload[..4].try_into().expect("four bytes"));
    let seq = u32::from_le_bytes(payload[4..8].try_into().expect("four bytes"));
    (client, seq)
}

/// A connection the server saw end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ending {
    pub session: SessionId,
    pub reason: CloseReason,
    pub suspended: bool,
}

/// Sends every message back where it came from, and records what arrived.
#[derive(Default)]
pub struct Echo {
    queued: VecDeque<(Handle<ServerConnection>, u8, Vec<u8>)>,
    /// Sequence numbers per client, in arrival order.
    pub received: HashMap<u32, Vec<u32>>,
    pub connected: usize,
    pub resumed: usize,
    pub endings: Vec<Ending>,
    pub expired: Vec<SessionId>,
    pub migrations: Vec<SocketAddr>,
    pub sessions: Vec<SessionId>,
}

impl ServerApp for Echo {
    fn on_message(&mut self, _at: Timestamp, conn: Handle<ServerConnection>, channel: u8, payload: &[u8]) {
        let (client, seq) = decode(payload);
        self.received.entry(client).or_default().push(seq);
        self.queued.push_back((conn, channel, payload.to_vec()));
    }

    fn on_event(&mut self, event: Event) {
        match event {
            Event::Connected { session, resumed, .. } => {
                self.connected += 1;
                self.resumed += usize::from(resumed);
                self.sessions.push(session);
            }
            Event::Disconnected { session, reason, suspended } => {
                self.endings.push(Ending { session, reason, suspended });
            }
            Event::SessionExpired(session) => self.expired.push(session),
            Event::Migrated { addr, .. } => self.migrations.push(addr),
        }
    }

    fn update(&mut self, _now: Timestamp, endpoint: &mut Endpoint) {
        while let Some((conn, channel, payload)) = self.queued.front() {
            let Some(connection) = endpoint.connection_mut(*conn) else {
                self.queued.pop_front();
                continue;
            };
            match connection.send(*channel, payload) {
                Ok(()) => {
                    self.queued.pop_front();
                }
                // Resumed when acknowledgements free space, which steps the
                // server again.
                Err(SendError::WouldBlock) => return,
                Err(error) => panic!("echo refused: {error:?}"),
            }
        }
    }

    fn next_wake(&self) -> Option<Timestamp> {
        None
    }
}

/// How a client paces its stream.
#[derive(Clone, Copy, Debug)]
pub struct Pace {
    /// Gap between messages within a burst.
    pub interval: Duration,
    /// Messages per burst, or `None` for one unbroken stream.
    pub burst: Option<u32>,
    /// Quiet time after each burst. The last message of a burst is the tail
    /// the transport has nothing following it to detect a loss with.
    pub gap: Duration,
}

impl Pace {
    /// One message every `interval`, without pause.
    pub const fn steady(interval: Duration) -> Pace {
        Pace { interval, burst: None, gap: Duration::ZERO }
    }
}

/// Sends `total` numbered messages at `pace` once connected, and records the
/// echoes with what each round trip took.
pub struct Chatter {
    id: u32,
    total: u32,
    pace: Pace,
    connected: bool,
    next_send: Option<Timestamp>,
    sent_at: Vec<Timestamp>,
    pub sent: u32,
    pub echoes: Vec<u32>,
    pub round_trips: Vec<(u32, Duration)>,
    pub states: Vec<State>,
}

impl Chatter {
    pub fn new(id: usize, total: u32, interval: Duration) -> Self {
        Self::paced(id, total, Pace::steady(interval))
    }

    pub fn paced(id: usize, total: u32, pace: Pace) -> Self {
        Self {
            id: u32::try_from(id).expect("client index fits"),
            total,
            pace,
            connected: false,
            next_send: None,
            sent_at: Vec::new(),
            sent: 0,
            echoes: Vec::new(),
            round_trips: Vec::new(),
            states: Vec::new(),
        }
    }
    /// Whether a message number was the last of its burst.
    pub fn is_tail(&self, seq: u32) -> bool {
        match self.pace.burst {
            Some(burst) => (seq + 1).is_multiple_of(burst),
            None => (seq + 1) == self.total,
        }
    }
}

impl ClientApp for Chatter {
    fn on_message(&mut self, at: Timestamp, _channel: u8, payload: &[u8]) {
        let (client, seq) = decode(payload);
        assert_eq!(client, self.id, "an echo reached the wrong client");
        self.echoes.push(seq);

        if let Some(sent_at) = self.sent_at.get(seq as usize) {
            self.round_trips.push((seq, at.saturating_since(*sent_at)));
        }
    }

    fn on_state(&mut self, state: State) {
        self.connected = state == State::Connected;
        self.states.push(state);
    }

    fn update(&mut self, now: Timestamp, connector: &mut Connector) {
        if !self.connected || (self.sent >= self.total) {
            return;
        }
        let due = *self.next_send.get_or_insert(now);
        if due > now {
            return;
        }
        let Some(connection) = connector.connection_mut() else { return };
        match connection.send(0, &encode(self.id, self.sent)) {
            Ok(()) => {
                self.sent_at.push(now);
                self.sent += 1;
            }
            Err(SendError::WouldBlock) => {}
            Err(error) => panic!("send refused: {error:?}"),
        }

        // A burst's last message is followed by silence, which is what makes
        // it a tail: nothing after it can reveal that it was lost.
        let tail = self.is_tail(self.sent.saturating_sub(1));
        let wait = if tail { self.pace.interval + self.pace.gap } else { self.pace.interval };
        self.next_send = Some(now.saturating_add(wait));
    }

    fn next_wake(&self) -> Option<Timestamp> {
        (self.connected && (self.sent < self.total)).then_some(self.next_send?)
    }
}

/// Something a run was not allowed to do.
#[derive(Clone, Debug)]
pub enum Violation {
    /// A stream that should have been 0, 1, 2, ... was not: a message was
    /// lost, duplicated, or delivered out of order.
    Stream {
        client: usize,
        at: &'static str,
        expected: u32,
        got: Vec<u32>,
    },
    /// Messages still queued or unacknowledged after the run settled.
    Pending { who: String, messages: usize },
    /// Tracked packets did not all resolve: acked plus lost plus in flight
    /// should equal the number sent.
    Counters {
        who: String,
        tracked: u64,
        acked: u64,
        lost: u64,
        in_flight: u64,
    },
    /// A client's stream was recorded by more than one server shard, so its
    /// connection moved between them.
    Split { client: usize, shards: Vec<usize> },
    /// A connection ended when the scenario expected none to.
    Ended(Ending),
    /// A client did not finish connected.
    NotConnected { client: usize, state: State },
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Violation::Stream { client, at, expected, got } => {
                write!(
                    f,
                    "client {client}: {at} should have been 0..{expected}, got {} entries {:?}",
                    got.len(),
                    Sample(got)
                )
            }
            Violation::Pending { who, messages } => write!(f, "{who}: {messages} messages still pending"),
            Violation::Counters { who, tracked, acked, lost, in_flight } => write!(
                f,
                "{who}: {tracked} packets tracked, {acked} acked, {lost} lost, {in_flight} in flight"
            ),
            Violation::Split { client, shards } => write!(f, "client {client}: recorded by shards {shards:?}"),
            Violation::Ended(ending) => write!(f, "a connection ended: {ending:?}"),
            Violation::NotConnected { client, state } => write!(f, "client {client} ended in state {state:?}"),
        }
    }
}

/// The first few entries of a stream, so a failure prints something readable.
struct Sample<'a>(&'a [u32]);

impl fmt::Debug for Sample<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let head = &self.0[..self.0.len().min(12)];
        write!(f, "{head:?}")?;
        if self.0.len() > head.len() {
            write!(f, "..")?;
        }
        Ok(())
    }
}

/// One server shard of a settled run: its endpoint, the app it ran, and its
/// driver's counters. An unsharded server is a run with one.
pub struct ServerView<'a> {
    pub app: &'a Echo,
    pub endpoint: &'a Endpoint,
    pub counters: &'a Counters,
}

/// One client of a settled run.
pub struct ClientView<'a> {
    pub app: &'a Chatter,
    pub connector: &'a Connector,
    pub counters: &'a Counters,
}

/// What `check` reads from a run, whatever network carried it: the
/// simulator's `World`, or real sockets.
pub trait Settled {
    fn server_count(&self) -> usize;
    fn server_view(&self, shard: usize) -> ServerView<'_>;
    fn client_count(&self) -> usize;
    fn client_view(&self, index: usize) -> ClientView<'_>;
    /// Enough to reproduce the run, printed with its violations.
    fn provenance(&self) -> String;
}

impl Settled for World<Echo, Chatter> {
    fn server_count(&self) -> usize {
        1
    }

    fn server_view(&self, _shard: usize) -> ServerView<'_> {
        ServerView {
            app: self.server_app(),
            endpoint: self.server().endpoint(),
            counters: self.server().counters(),
        }
    }

    fn client_count(&self) -> usize {
        self.clients()
    }

    fn client_view(&self, index: usize) -> ClientView<'_> {
        ClientView {
            app: self.client_app(index),
            connector: self.client(index).connector(),
            counters: self.client(index).counters(),
        }
    }

    fn provenance(&self) -> String {
        format!("seed {}", self.seed())
    }
}

/// Everything a settled run of this workload must satisfy.
///
/// Call once traffic has drained: it requires every message to have completed
/// its round trip. `total` is how many each client was told to send.
pub fn check(run: &impl Settled, total: u32) -> Vec<Violation> {
    let mut violations = Vec::new();
    let servers: Vec<ServerView<'_>> = (0..run.server_count()).map(|shard| run.server_view(shard)).collect();

    for server in &servers {
        for ending in &server.app.endings {
            violations.push(Violation::Ended(*ending));
        }
    }

    for index in 0..run.client_count() {
        let id = u32::try_from(index).expect("client index fits");
        let client = run.client_view(index);
        let state = client.connector.state();
        if state != State::Connected {
            violations.push(Violation::NotConnected { client: index, state });
        }

        // A connection lives on one shard for its whole life, so its stream
        // must be recorded by exactly one.
        let holders: Vec<usize> = (0..servers.len())
            .filter(|&shard| servers[shard].app.received.contains_key(&id))
            .collect();
        if holders.len() > 1 {
            violations.push(Violation::Split { client: index, shards: holders.clone() });
        }
        let received = holders
            .first()
            .and_then(|&shard| servers[shard].app.received.get(&id).cloned())
            .unwrap_or_default();
        if !is_exactly(&received, total) {
            violations.push(Violation::Stream {
                client: index,
                at: "the server's record",
                expected: total,
                got: received,
            });
        }
        if !is_exactly(&client.app.echoes, total) {
            violations.push(Violation::Stream {
                client: index,
                at: "the echoes",
                expected: total,
                got: client.app.echoes.clone(),
            });
        }

        if let Some(connection) = client.connector.connection() {
            let messages = connection.pending_messages();
            if messages > 0 {
                violations.push(Violation::Pending { who: format!("client {index}"), messages });
            }
            reconcile(
                format!("client {index}"),
                client.counters,
                u64::from(connection.packets_in_flight()),
                &mut violations,
            );
        }
    }

    for (shard, server) in servers.iter().enumerate() {
        let mut in_flight = 0u64;
        for connection in server.endpoint.connections() {
            let messages = connection.pending_messages();
            if messages > 0 {
                violations.push(Violation::Pending {
                    who: format!("server {shard} connection {}", connection.id().0),
                    messages,
                });
            }
            in_flight += u64::from(connection.packets_in_flight());
        }
        reconcile(format!("server {shard}"), server.counters, in_flight, &mut violations);
    }

    violations
}

/// Exactly 0, 1, 2, ... up to `total`: no loss, no duplicates, no reordering.
fn is_exactly(stream: &[u32], total: u32) -> bool {
    ((stream.len() as u64) == u64::from(total))
        && stream.iter().enumerate().all(|(i, &seq)| (i as u64) == u64::from(seq))
}

/// Every tracked packet resolved or is still outstanding; none vanished.
fn reconcile(who: String, counters: &Counters, in_flight: u64, violations: &mut Vec<Violation>) {
    let tracked = counters.get(Counter::PacketsTracked);
    let acked = counters.get(Counter::PacketsAcked);
    let lost = counters.get(Counter::PacketsLost);
    if tracked != (acked + lost + in_flight) {
        violations.push(Violation::Counters { who, tracked, acked, lost, in_flight });
    }
}

/// Panics with every violation, and what is needed to replay the run.
pub fn assert_clean(run: &impl Settled, total: u32) {
    let violations = check(run, total);
    if violations.is_empty() {
        return;
    }
    let report: Vec<String> = violations.iter().map(Violation::to_string).collect();
    panic!(
        "{}, {} violations:\n  {}",
        run.provenance(),
        report.len(),
        report.join("\n  ")
    );
}

/// What a run cost and how it felt, for soaks where the question is load and
/// latency rather than correctness.
#[derive(Clone, Debug)]
pub struct Report {
    pub clients: usize,
    pub simulated: Duration,
    /// Datagrams the wire carried, and how many it destroyed.
    pub datagrams: u64,
    pub lost_on_wire: u64,
    /// Server bytes sent per connection per second, against its budget.
    pub bytes_per_connection: f64,
    pub budget: u32,
    /// Packets the server tracked, declared lost, and later found delivered.
    pub tracked: u64,
    pub declared_lost: u64,
    pub spurious: u64,
    /// Round trips of every echo, sorted.
    pub round_trips: Vec<Duration>,
    /// Round trips of echoes for a burst's last message, sorted. Nothing
    /// follows these, so only a probe can reveal that one was lost.
    pub tail_round_trips: Vec<Duration>,
    /// Clients that received every echo they were owed.
    pub complete: usize,
}

impl Report {
    pub fn percentile(sorted: &[Duration], fraction: f64) -> Duration {
        if sorted.is_empty() {
            return Duration::ZERO;
        }
        let last = sorted.len() - 1;
        sorted[((last as f64) * fraction) as usize]
    }

    pub fn round_trip(&self, fraction: f64) -> Duration {
        Self::percentile(&self.round_trips, fraction)
    }

    pub fn tail_round_trip(&self, fraction: f64) -> Duration {
        Self::percentile(&self.tail_round_trips, fraction)
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{} clients over {:?}: {} datagrams, {} lost on the wire",
            self.clients, self.simulated, self.datagrams, self.lost_on_wire
        )?;
        writeln!(
            f,
            "  server sent {:.0} bytes per connection per second, of {} allowed",
            self.bytes_per_connection, self.budget
        )?;
        writeln!(
            f,
            "  packets: {} tracked, {} declared lost, {} of those arrived after all",
            self.tracked, self.declared_lost, self.spurious
        )?;
        writeln!(
            f,
            "  round trip: p50 {:?}, p99 {:?}, worst {:?}",
            self.round_trip(0.5),
            self.round_trip(0.99),
            self.round_trips.last().copied().unwrap_or_default()
        )?;
        write!(
            f,
            "  tails only: p50 {:?}, p99 {:?}, worst {:?} ({} of {} clients complete)",
            self.tail_round_trip(0.5),
            self.tail_round_trip(0.99),
            self.tail_round_trips.last().copied().unwrap_or_default(),
            self.complete,
            self.clients
        )
    }
}

/// Measures a finished run. `simulated` is how long it covered, which sets
/// the denominator for rates.
pub fn report(world: &World<Echo, Chatter>, simulated: Duration, total: u32) -> Report {
    let counters = world.server().counters();
    let stats = world.wire_stats();

    let mut round_trips = Vec::new();
    let mut tail_round_trips = Vec::new();
    let mut complete = 0;

    for index in 0..world.clients() {
        let app = world.client_app(index);
        complete += usize::from(app.echoes.len() == (total as usize));
        for (seq, elapsed) in &app.round_trips {
            round_trips.push(*elapsed);
            if app.is_tail(*seq) {
                tail_round_trips.push(*elapsed);
            }
        }
    }
    round_trips.sort_unstable();
    tail_round_trips.sort_unstable();

    let seconds = simulated.as_secs_f64().max(f64::MIN_POSITIVE);
    let per_connection = (counters.get(Counter::BytesSent) as f64) / seconds / (world.clients().max(1) as f64);

    Report {
        clients: world.clients(),
        simulated,
        datagrams: stats.delivered,
        lost_on_wire: stats.lost,
        bytes_per_connection: per_connection,
        budget: BudgetConfig::DEFAULT.rate(),
        tracked: counters.get(Counter::PacketsTracked),
        declared_lost: counters.get(Counter::PacketsLost),
        spurious: counters.get(Counter::PacketsSpuriouslyLost),
        round_trips,
        tail_round_trips,
        complete,
    }
}
