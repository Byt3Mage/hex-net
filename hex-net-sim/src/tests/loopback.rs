//! The simulator's workload over real sockets on the loopback interface, held
//! to the same checks: every message delivered once and in order, nothing left
//! pending, and counters that reconcile.
//!
//! Each server shard and each client runs its own `run` loop on its own
//! thread, so these also exercise waiting on readiness and deadlines, and
//! waking a waiting loop to stop it.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use crate::{
    pair::{issue_ticket, session_keys},
    scenario::{Chatter, ClientView, Echo, ServerView, Settled, assert_clean},
};
use hex_net_core::{
    budget::BudgetConfig,
    channel::{ChannelKind, ChannelSet},
    connector::{Connector, State},
    crypto::Key,
    endpoint::{Endpoint, EndpointConfig, Event, ServerConnection},
    shard::Shard,
    slab::Handle,
    time::{Clock, MonotonicClock, Timestamp},
};
use hex_net_io::{
    Socket, Wait,
    driver::{ClientApp, ClientDriver, ServerApp, ServerDriver},
    portable::PortableSocket,
    run::{run_client, run_server, stop_pair},
};

const BACKEND_KEY: Key = [0x3C; 32];

const ORDERED: ChannelSet = ChannelSet::new([ChannelKind::ReliableOrdered]);

/// One message per 128 Hz tick.
const INTERVAL: Duration = Duration::from_micros(7812);

const TOTAL: u32 = 128;

/// Longest a run may take to settle before it is stopped and checked as it
/// stands.
const LIMIT: Duration = Duration::from_secs(30);

/// A source address for client `index`. Linux delivers all of 127/8 to the
/// loopback interface, so each client can be its own host, as players are,
/// and the handshake limiter charges each separately. Elsewhere they share one.
fn client_ip(index: usize) -> Ipv4Addr {
    if cfg!(target_os = "linux") {
        let [_, _, a, b] = u32::try_from(index + 2).expect("client index fits").to_be_bytes();
        Ipv4Addr::new(127, 1, a, b)
    } else {
        Ipv4Addr::LOCALHOST
    }
}

fn server_addr() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn endpoint(shard: Shard) -> Endpoint {
    Endpoint::new(EndpointConfig::sharded(1024, shard), BACKEND_KEY, &ORDERED)
}

fn connector(clock: &MonotonicClock, server: SocketAddr, index: usize) -> Connector {
    let client_id = (index as u64) + 1;
    let keys = session_keys(client_id);
    let ticket = issue_ticket(&BACKEND_KEY, clock.now(), client_id, None, &keys);
    Connector::connect(clock.now(), server, ticket, keys, ORDERED, BudgetConfig::DEFAULT)
}

/// What the threads of a run report while it goes.
struct Progress {
    connected: AtomicUsize,
    finished: AtomicUsize,
    /// Per shard: whether every connection it holds has had everything it
    /// sent acknowledged.
    quiet: Box<[AtomicBool]>,
}

impl Progress {
    fn new(shards: usize) -> Arc<Progress> {
        Arc::new(Progress {
            connected: AtomicUsize::new(0),
            finished: AtomicUsize::new(0),
            quiet: (0..shards).map(|_| AtomicBool::new(false)).collect(),
        })
    }

    fn settled(&self, clients: usize) -> bool {
        (self.connected.load(Ordering::Acquire) == clients)
            && (self.finished.load(Ordering::Acquire) == clients)
            && self.quiet.iter().all(|quiet| quiet.load(Ordering::Acquire))
    }
}

/// `Echo`, reporting connections and quiet to the thread watching the run.
struct Serving {
    echo: Echo,
    shard: usize,
    progress: Arc<Progress>,
}

impl ServerApp for Serving {
    fn on_message(&mut self, at: Timestamp, conn: Handle<ServerConnection>, channel: u8, payload: &[u8]) {
        self.echo.on_message(at, conn, channel, payload);
    }

    fn on_event(&mut self, event: Event) {
        if let Event::Connected { .. } = event {
            self.progress.connected.fetch_add(1, Ordering::AcqRel);
        }
        self.echo.on_event(event);
    }

    fn update(&mut self, now: Timestamp, endpoint: &mut Endpoint) {
        self.echo.update(now, endpoint);
        let quiet = endpoint
            .connections()
            .iter()
            .all(|connection| connection.pending_messages() == 0);
        self.progress.quiet[self.shard].store(quiet, Ordering::Release);
    }

    fn next_wake(&self) -> Option<Timestamp> {
        self.echo.next_wake()
    }
}

/// `Chatter`, reporting once every echo is in and everything it sent has been
/// acknowledged.
struct Finishing {
    chatter: Chatter,
    total: u32,
    finished: bool,
    progress: Arc<Progress>,
}

impl ClientApp for Finishing {
    fn on_message(&mut self, at: Timestamp, channel: u8, payload: &[u8]) {
        self.chatter.on_message(at, channel, payload);
    }

    fn on_state(&mut self, state: State) {
        self.chatter.on_state(state);
    }

    fn update(&mut self, now: Timestamp, connector: &mut Connector) {
        self.chatter.update(now, connector);
        if self.finished || (self.chatter.echoes.len() != (self.total as usize)) {
            return;
        }
        if connector
            .connection()
            .is_some_and(|connection| connection.pending_messages() == 0)
        {
            self.finished = true;
            self.progress.finished.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn next_wake(&self) -> Option<Timestamp> {
        self.chatter.next_wake()
    }
}

/// A finished run: every driver and app, back from their threads.
struct Loopback<S: Socket> {
    backend: &'static str,
    servers: Vec<(ServerDriver<S>, Serving)>,
    clients: Vec<(ClientDriver<S>, Finishing)>,
    settled: bool,
}

impl<S: Socket> Settled for Loopback<S> {
    fn server_count(&self) -> usize {
        self.servers.len()
    }

    fn server_view(&self, shard: usize) -> ServerView<'_> {
        let (driver, app) = &self.servers[shard];
        ServerView {
            app: &app.echo,
            endpoint: driver.endpoint(),
            counters: driver.counters(),
        }
    }

    fn client_count(&self) -> usize {
        self.clients.len()
    }

    fn client_view(&self, index: usize) -> ClientView<'_> {
        let (driver, app) = &self.clients[index];
        ClientView {
            app: &app.chatter,
            connector: driver.connector(),
            counters: driver.counters(),
        }
    }

    fn provenance(&self) -> String {
        let outcome = if self.settled { "settled" } else { "stopped unsettled" };
        format!(
            "{} backend, {} shards, {} clients, {outcome}",
            self.backend,
            self.servers.len(),
            self.clients.len()
        )
    }
}

/// Runs every server and client on a thread of its own until the workload has
/// settled or `LIMIT` has passed, then stops them all and hands them back.
fn run<S>(
    backend: &'static str,
    clock: MonotonicClock,
    servers: Vec<ServerDriver<S>>,
    clients: Vec<ClientDriver<S>>,
) -> Loopback<S>
where
    S: Socket + Wait + Send + 'static,
{
    let progress = Progress::new(servers.len());
    let client_count = clients.len();
    let mut stoppers = Vec::new();

    let server_threads: Vec<_> = servers
        .into_iter()
        .enumerate()
        .map(|(shard, mut driver)| {
            let (stopper, signal) = stop_pair(driver.socket().waker().expect("a waker"));
            stoppers.push(stopper);
            let mut app = Serving {
                echo: Echo::default(),
                shard,
                progress: Arc::clone(&progress),
            };
            thread::spawn(move || {
                run_server(&mut driver, &mut app, &clock, &signal).expect("the server loop ran");
                (driver, app)
            })
        })
        .collect();

    let client_threads: Vec<_> = clients
        .into_iter()
        .enumerate()
        .map(|(index, mut driver)| {
            let (stopper, signal) = stop_pair(driver.socket().waker().expect("a waker"));
            stoppers.push(stopper);
            let mut app = Finishing {
                chatter: Chatter::new(index, TOTAL, INTERVAL),
                total: TOTAL,
                finished: false,
                progress: Arc::clone(&progress),
            };
            thread::spawn(move || {
                run_client(&mut driver, &mut app, &clock, &signal).expect("the client loop ran");
                (driver, app)
            })
        })
        .collect();

    let started = Instant::now();
    let settled = loop {
        if progress.settled(client_count) {
            break true;
        }
        if started.elapsed() >= LIMIT {
            break false;
        }
        thread::sleep(Duration::from_millis(5));
    };

    for stopper in &stoppers {
        stopper.stop().expect("the loop was woken");
    }

    Loopback {
        backend,
        servers: server_threads
            .into_iter()
            .map(|thread| thread.join().expect("the server thread"))
            .collect(),
        clients: client_threads
            .into_iter()
            .map(|thread| thread.join().expect("the client thread"))
            .collect(),
        settled,
    }
}

fn portable_client(clock: &MonotonicClock, server: SocketAddr, index: usize) -> ClientDriver<PortableSocket> {
    let socket = PortableSocket::bind(SocketAddr::from((client_ip(index), 0)), *clock).expect("a client socket");
    ClientDriver::new(socket, connector(clock, server, index))
}

#[test]
fn portable_sockets_carry_the_workload() {
    const CLIENTS: usize = 16;
    let clock = MonotonicClock::new();

    let socket = PortableSocket::bind(server_addr(), clock).expect("a server socket");
    let server = socket.local_addr().expect("a bound address");
    let driver = ServerDriver::new(socket, endpoint(Shard::solo()));
    let clients = (0..CLIENTS)
        .map(|index| portable_client(&clock, server, index))
        .collect();

    let run = run("portable", clock, vec![driver], clients);
    assert_clean(&run, TOTAL);
    assert_eq!(run.servers[0].1.echo.connected, CLIENTS);
}

#[test]
fn a_stop_wakes_a_waiting_portable_loop() {
    let clock = MonotonicClock::new();
    let socket = PortableSocket::bind(server_addr(), clock).expect("a server socket");
    stops_promptly(clock, ServerDriver::new(socket, endpoint(Shard::solo())));
}

/// A server with nothing to do waits without limit; only the stopper's wake
/// can end that wait.
fn stops_promptly<S>(clock: MonotonicClock, mut driver: ServerDriver<S>)
where
    S: Socket + Wait + Send + 'static,
{
    let (stopper, signal) = stop_pair(driver.socket().waker().expect("a waker"));
    let progress = Progress::new(1);
    let thread = thread::spawn(move || {
        let mut app = Serving { echo: Echo::default(), shard: 0, progress };
        run_server(&mut driver, &mut app, &clock, &signal).expect("the server loop ran");
    });

    thread::sleep(Duration::from_millis(50));
    let asked = Instant::now();
    stopper.stop().expect("the loop was woken");
    thread.join().expect("the server thread");
    assert!(
        asked.elapsed() < Duration::from_secs(1),
        "the loop took {:?} to stop",
        asked.elapsed()
    );
}

#[cfg(target_os = "linux")]
mod linux {
    use hex_net_io::linux::{LinuxSocket, SocketOptions, bind_group};

    use super::*;

    /// A client needs little buffering: a few packets per tick at most.
    const CLIENT_OPTIONS: SocketOptions = SocketOptions { recv_buffer: 256 << 10, send_buffer: 256 << 10 };

    fn client(clock: &MonotonicClock, server: SocketAddr, index: usize) -> ClientDriver<LinuxSocket> {
        let addr = SocketAddr::from((client_ip(index), 0));
        let socket = LinuxSocket::bind(addr, *clock, CLIENT_OPTIONS).expect("a client socket");
        ClientDriver::new(socket, connector(clock, server, index))
    }

    #[test]
    fn linux_sockets_carry_the_workload() {
        const CLIENTS: usize = 64;
        let clock = MonotonicClock::new();

        let socket = LinuxSocket::bind(server_addr(), clock, SocketOptions::default()).expect("a server socket");
        let server = socket.local_addr().expect("a bound address");
        let driver = ServerDriver::new(socket, endpoint(Shard::solo()));
        let clients = (0..CLIENTS).map(|index| client(&clock, server, index)).collect();

        let run = run("linux", clock, vec![driver], clients);
        assert_clean(&run, TOTAL);
        assert_eq!(run.servers[0].1.echo.connected, CLIENTS);
    }

    /// Kernel timestamps put arrivals on the loop's own timeline. A stamp on
    /// another timeline would put an echo before the message that caused it,
    /// or an hour after, and a round trip would read as zero or absurd.
    #[test]
    fn round_trips_are_measured_from_kernel_arrival_times() {
        let clock = MonotonicClock::new();
        let socket = LinuxSocket::bind(server_addr(), clock, SocketOptions::default()).expect("a server socket");
        let server = socket.local_addr().expect("a bound address");
        let driver = ServerDriver::new(socket, endpoint(Shard::solo()));

        let run = run("linux", clock, vec![driver], vec![client(&clock, server, 0)]);
        assert_clean(&run, TOTAL);

        let chatter = &run.clients[0].1.chatter;
        assert_eq!(chatter.round_trips.len(), TOTAL as usize);
        for (seq, elapsed) in &chatter.round_trips {
            assert!(
                (*elapsed > Duration::ZERO) && (*elapsed < Duration::from_secs(1)),
                "message {seq} took {elapsed:?}"
            );
        }
    }

    #[test]
    fn a_sharded_group_keeps_every_connection_on_its_home_shard() {
        const SHARDS: usize = 4;
        const CLIENTS: usize = 64;
        let clock = MonotonicClock::new();

        let group = ShardGroup::new(ShardCount::new(SHARDS).expect("a valid group size"));
        let members = bind_group(server_addr(), &group, clock, SocketOptions::default()).expect("a group");
        let server = members[0].1.local_addr().expect("a bound address");
        let drivers = members
            .into_iter()
            .map(|(shard, socket)| ServerDriver::new(socket, endpoint(shard)))
            .collect();
        let clients = (0..CLIENTS).map(|index| client(&clock, server, index)).collect();

        let run = run("linux", clock, drivers, clients);
        assert_clean(&run, TOTAL);

        let mut connected = 0;
        for (shard, (driver, app)) in run.servers.iter().enumerate() {
            assert!(app.echo.connected > 0, "shard {shard} was given no connections");
            assert_eq!(
                driver.counters().get(Counter::PacketsMisrouted),
                0,
                "the kernel steered a datagram to shard {shard} that it does not own"
            );
            for connection in driver.endpoint().connections() {
                assert_eq!(connection.id().shard().index(), shard);
            }
            connected += app.echo.connected;
        }
        assert_eq!(connected, CLIENTS);
    }

    #[test]
    fn a_stop_wakes_a_waiting_linux_loop() {
        let clock = MonotonicClock::new();
        let socket = LinuxSocket::bind(server_addr(), clock, SocketOptions::default()).expect("a server socket");
        stops_promptly(clock, ServerDriver::new(socket, endpoint(Shard::solo())));
    }
}
