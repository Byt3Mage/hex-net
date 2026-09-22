//! Packets per second through one endpoint, under the traffic an MMO at
//! fast-FPS fidelity makes: every client sends an input every 128 Hz tick, and
//! the server sends every client a snapshot every tick.
//!
//! The server runs its own loop on its own thread. Every client runs on one
//! load thread, each stepped only when its deadline comes, so the load costs
//! what the clients' transport costs and nothing more.
//!
//! `cargo bench -p hex-net-io --bench pps -- [--clients N] [--seconds S] [--portable]`
//!
//! Rates are counted in messages. Each tick puts one message in each datagram,
//! so they equal datagram rates, which the whole-run totals printed last
//! confirm. On Linux, CPU time is read from the kernel's per-thread accounting,
//! which gives the server's cost per datagram independent of how many cores
//! the machine has or what else is competing for them.

use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    env,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use hex_net_core::{
    budget::BudgetConfig,
    channel::{ChannelKind, ChannelSet},
    connector::{Connector, State},
    crypto::Key,
    endpoint::{Endpoint, EndpointConfig, Event, ServerConnection},
    slab::Handle,
    stats::Counter,
    time::{Clock, MonotonicClock, Timestamp},
    wire::MAX_DATAGRAM,
};
use hex_net_io::{
    Socket, Wait,
    driver::{ClientApp, ClientDriver, ServerApp, ServerDriver},
    portable::PortableSocket,
    run::{run_server, stop_pair},
};
use hex_net_sim::pair::{issue_ticket, session_keys};

const BACKEND_KEY: Key = [0x71; 32];

const CHANNELS: ChannelSet = ChannelSet::new([ChannelKind::UnreliableSequenced]);

const TICK: Duration = Duration::from_micros(7812);

const INPUT_LEN: usize = 32;

const SNAPSHOT_LEN: usize = 200;

/// A 200-byte snapshot 128 times a second is about 35 KB/s with headers;
/// the default budget is sized for far lighter traffic.
const RATE: u32 = 64_000;

/// How long every client has to finish its handshake.
const CONNECT_LIMIT: Duration = Duration::from_secs(60);

/// Run after the last handshake and before measuring, so the window starts
/// in steady state.
const WARM_UP: Duration = Duration::from_secs(1);

struct Options {
    clients: usize,
    seconds: u64,
    portable: bool,
}

impl Options {
    fn parse() -> Options {
        let mut options = Options {
            clients: 1000,
            seconds: 5,
            portable: !cfg!(target_os = "linux"),
        };
        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--clients" => options.clients = number(args.next(), "--clients"),
                "--seconds" => options.seconds = number(args.next(), "--seconds"),
                "--portable" => options.portable = true,
                // Added by `cargo bench` itself.
                "--bench" => {}
                other => panic!("unknown argument {other}"),
            }
        }
        options
    }
}

fn number<T: std::str::FromStr>(value: Option<String>, flag: &str) -> T {
    value
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("{flag} takes a number"))
}

fn budget() -> BudgetConfig {
    BudgetConfig::new(RATE, MAX_DATAGRAM).expect("the benchmark budget is within bounds")
}

/// Counts every thread adds to as it goes, read by the thread measuring.
#[derive(Default)]
struct Tally {
    connected: AtomicU64,
    inputs_sent: AtomicU64,
    inputs_received: AtomicU64,
    snapshots_sent: AtomicU64,
    snapshots_refused: AtomicU64,
    snapshots_received: AtomicU64,
    /// Server ticks begun more than a whole tick late.
    ticks_late: AtomicU64,
}

impl Tally {
    fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

/// One reading of everything a window is measured by.
#[derive(Clone, Copy)]
struct Sample {
    at: Instant,
    inputs_sent: u64,
    inputs_received: u64,
    snapshots_sent: u64,
    snapshots_refused: u64,
    snapshots_received: u64,
    ticks_late: u64,
    server_cpu: Option<Duration>,
    load_cpu: Option<Duration>,
}

impl Sample {
    fn take(tally: &Tally, server: &Option<String>, load: &Option<String>) -> Sample {
        Sample {
            at: Instant::now(),
            inputs_sent: Tally::get(&tally.inputs_sent),
            inputs_received: Tally::get(&tally.inputs_received),
            snapshots_sent: Tally::get(&tally.snapshots_sent),
            snapshots_refused: Tally::get(&tally.snapshots_refused),
            snapshots_received: Tally::get(&tally.snapshots_received),
            ticks_late: Tally::get(&tally.ticks_late),
            server_cpu: server.as_deref().and_then(cpu_time),
            load_cpu: load.as_deref().and_then(cpu_time),
        }
    }
}

/// Where the kernel accounts the calling thread's CPU time, or `None` off
/// Linux.
fn thread_accounting() -> Option<String> {
    let link = std::fs::read_link("/proc/thread-self").ok()?;
    Some(format!("/proc/{}/schedstat", link.display()))
}

/// Time on CPU so far, the first field of a thread's `schedstat`.
fn cpu_time(path: &str) -> Option<Duration> {
    let stat = std::fs::read_to_string(path).ok()?;
    let nanos = stat.split_whitespace().next()?.parse().ok()?;
    Some(Duration::from_nanos(nanos))
}

/// Sends every connection a snapshot each tick, and counts inputs.
struct Broadcast {
    connections: Vec<Handle<ServerConnection>>,
    snapshot: [u8; SNAPSHOT_LEN],
    next_tick: Option<Timestamp>,
    tally: Arc<Tally>,
}

impl ServerApp for Broadcast {
    fn on_message(&mut self, _at: Timestamp, _conn: Handle<ServerConnection>, _channel: u8, _payload: &[u8]) {
        Tally::add(&self.tally.inputs_received, 1);
    }

    fn on_event(&mut self, event: Event) {
        if let Event::Connected { handle, .. } = event {
            self.connections.push(handle);
            Tally::add(&self.tally.connected, 1);
        }
    }

    fn update(&mut self, now: Timestamp, endpoint: &mut Endpoint) {
        let due = *self.next_tick.get_or_insert(now);
        if due > now {
            return;
        }

        let (mut sent, mut refused) = (0, 0);
        for handle in &self.connections {
            let Some(connection) = endpoint.connection_mut(*handle) else { continue };
            match connection.send(0, &self.snapshot) {
                Ok(()) => sent += 1,
                Err(_) => refused += 1,
            }
        }
        Tally::add(&self.tally.snapshots_sent, sent);
        Tally::add(&self.tally.snapshots_refused, refused);

        // A server that falls a whole tick behind starts the next one from
        // now rather than running the missed ones back to back.
        let next = due.saturating_add(TICK);
        self.next_tick = Some(if next <= now {
            Tally::add(&self.tally.ticks_late, 1);
            now.saturating_add(TICK)
        } else {
            next
        });
    }

    fn next_wake(&self) -> Option<Timestamp> {
        self.next_tick
    }
}

/// Sends an input each tick once connected, and counts snapshots.
struct Player {
    connected: bool,
    input: [u8; INPUT_LEN],
    next_input: Option<Timestamp>,
    tally: Arc<Tally>,
}

impl ClientApp for Player {
    fn on_message(&mut self, _at: Timestamp, _channel: u8, _payload: &[u8]) {
        Tally::add(&self.tally.snapshots_received, 1);
    }

    fn on_state(&mut self, state: State) {
        self.connected = state == State::Connected;
    }

    fn update(&mut self, now: Timestamp, connector: &mut Connector) {
        if !self.connected {
            return;
        }
        let due = *self.next_input.get_or_insert(now);
        if due > now {
            return;
        }
        if let Some(connection) = connector.connection_mut()
            && connection.send(0, &self.input).is_ok()
        {
            Tally::add(&self.tally.inputs_sent, 1);
        }
        let next = due.saturating_add(TICK);
        self.next_input = Some(if next <= now { now.saturating_add(TICK) } else { next });
    }

    fn next_wake(&self) -> Option<Timestamp> {
        if self.connected { self.next_input } else { None }
    }
}

/// A distinct loopback host per client on Linux, so the handshake limiter
/// charges each separately, as it would real players.
fn client_ip(index: usize) -> Ipv4Addr {
    if cfg!(target_os = "linux") {
        let [_, _, a, b] = u32::try_from(index + 2).expect("client index fits").to_be_bytes();
        Ipv4Addr::new(127, 1, a, b)
    } else {
        Ipv4Addr::LOCALHOST
    }
}

fn connector(clock: &MonotonicClock, server: SocketAddr, index: usize) -> Connector {
    let client_id = (index as u64) + 1;
    let keys = session_keys(client_id);
    let ticket = issue_ticket(&BACKEND_KEY, clock.now(), client_id, None, &keys);
    Connector::connect(clock.now(), server, ticket, keys, CHANNELS, budget())
}

/// Steps every client when its deadline comes, until `stop` is raised.
/// Returns where the kernel accounts this thread's CPU time, before starting.
fn load<S: Socket>(
    clock: MonotonicClock,
    mut clients: Vec<(ClientDriver<S>, Player)>,
    stop: Arc<AtomicBool>,
    accounting: mpsc::Sender<Option<String>>,
) -> Vec<(ClientDriver<S>, Player)> {
    accounting
        .send(thread_accounting())
        .expect("the measuring thread is listening");

    let start = clock.now();
    let mut due: BinaryHeap<Reverse<(Timestamp, usize)>> = (0..clients.len()).map(|i| Reverse((start, i))).collect();

    while !stop.load(Ordering::Relaxed) {
        let now = clock.now();
        while let Some(&Reverse((at, index))) = due.peek() {
            if at > now {
                break;
            }
            due.pop();
            let (driver, app) = &mut clients[index];
            let next = driver.step(now, app).expect("a client step");
            // A connector always has a timer while connecting or connected;
            // one without has closed, and is looked at again in case its
            // socket has something to report.
            due.push(Reverse((next.unwrap_or(now.saturating_add(TICK)).max(now), index)));
        }

        if let Some(&Reverse((at, _))) = due.peek() {
            let now = clock.now();
            if at > now {
                thread::sleep(at.saturating_since(now));
            }
        }
    }
    clients
}

fn run<S>(options: &Options, clock: MonotonicClock, socket: S, clients: Vec<ClientDriver<S>>)
where
    S: Socket + Wait + Send + 'static,
{
    let tally = Arc::new(Tally::default());
    let capacity = u32::try_from(options.clients).expect("client count fits");
    let config = EndpointConfig { budget: budget(), ..EndpointConfig::new(capacity) };
    let mut server = ServerDriver::new(socket, Endpoint::new(config, BACKEND_KEY, &CHANNELS));

    let (server_accounting_tx, server_accounting) = mpsc::channel();
    let (stopper, signal) = stop_pair(server.socket().waker().expect("a waker"));
    let server_tally = Arc::clone(&tally);
    let server_thread = thread::spawn(move || {
        server_accounting_tx
            .send(thread_accounting())
            .expect("the measuring thread is listening");
        let mut app = Broadcast {
            connections: Vec::with_capacity(capacity as usize),
            snapshot: [0x5E; SNAPSHOT_LEN],
            next_tick: None,
            tally: server_tally,
        };
        run_server(&mut server, &mut app, &clock, &signal).expect("the server loop ran");
        server
    });

    let players = clients
        .into_iter()
        .map(|driver| {
            let app = Player {
                connected: false,
                input: [0x1A; INPUT_LEN],
                next_input: None,
                tally: Arc::clone(&tally),
            };
            (driver, app)
        })
        .collect();
    let stop_load = Arc::new(AtomicBool::new(false));
    let (load_accounting_tx, load_accounting) = mpsc::channel();
    let load_stop = Arc::clone(&stop_load);
    let load_thread = thread::spawn(move || load(clock, players, load_stop, load_accounting_tx));

    let server_path = server_accounting.recv().expect("the server thread started");
    let load_path = load_accounting.recv().expect("the load thread started");

    let connecting = Instant::now();
    let target = options.clients as u64;
    while (Tally::get(&tally.connected) < target) && (connecting.elapsed() < CONNECT_LIMIT) {
        thread::sleep(Duration::from_millis(10));
    }
    let connected = Tally::get(&tally.connected);
    println!(
        "{} backend: {connected} of {} clients connected in {:.2?}",
        if options.portable { "portable" } else { "linux" },
        options.clients,
        connecting.elapsed()
    );

    thread::sleep(WARM_UP);
    let before = Sample::take(&tally, &server_path, &load_path);
    thread::sleep(Duration::from_secs(options.seconds));
    let after = Sample::take(&tally, &server_path, &load_path);

    stop_load.store(true, Ordering::Relaxed);
    stopper.stop().expect("the server loop was woken");
    let server = server_thread.join().expect("the server thread");
    let clients = load_thread.join().expect("the load thread");

    report(connected, &before, &after);
    totals(&server, &clients);
}

fn report(connected: u64, before: &Sample, after: &Sample) {
    let seconds = after.at.duration_since(before.at).as_secs_f64();
    let rate = |a: u64, b: u64| ((b - a) as f64) / seconds;
    let ratio = |part: u64, whole: u64| if whole == 0 { 0.0 } else { ((part as f64) * 100.0) / (whole as f64) };

    let inputs_in = rate(before.inputs_received, after.inputs_received);
    let snapshots_out = rate(before.snapshots_sent, after.snapshots_sent);
    let server_pps = inputs_in + snapshots_out;
    let offered = (connected as f64) * (Duration::from_secs(1).as_secs_f64() / TICK.as_secs_f64());

    println!("measured over {seconds:.2} s at 128 Hz, {offered:.0} inputs/s offered");
    println!("  server: {inputs_in:.0} inputs/s in, {snapshots_out:.0} snapshots/s out, {server_pps:.0} datagrams/s");
    println!(
        "  delivered: {:.2}% of inputs, {:.2}% of snapshots",
        ratio(
            after.inputs_received - before.inputs_received,
            after.inputs_sent - before.inputs_sent
        ),
        ratio(
            after.snapshots_received - before.snapshots_received,
            after.snapshots_sent - before.snapshots_sent
        )
    );
    println!(
        "  snapshots refused by the budget: {}, server ticks started late: {}",
        after.snapshots_refused - before.snapshots_refused,
        after.ticks_late - before.ticks_late
    );

    if let (Some(server_before), Some(server_after)) = (before.server_cpu, after.server_cpu) {
        let busy = (server_after - server_before).as_secs_f64();
        println!(
            "  server thread: {:.1}% of a core, {:.0} datagrams per CPU-second, {:.2} µs per datagram",
            (busy * 100.0) / seconds,
            server_pps * (seconds / busy.max(f64::MIN_POSITIVE)),
            (busy * 1e6) / (server_pps * seconds).max(1.0)
        );
    }
    if let (Some(load_before), Some(load_after)) = (before.load_cpu, after.load_cpu) {
        let busy = (load_after - load_before).as_secs_f64();
        println!("  load thread: {:.1}% of a core", (busy * 100.0) / seconds);
    }
}

/// Whole-run datagram totals from the drivers' own counters, against the
/// message totals: equal counts confirm a message per datagram.
fn totals<S: Socket>(server: &ServerDriver<S>, clients: &[(ClientDriver<S>, Player)]) {
    let server_counters = server.counters();
    let client_sent: u64 = clients
        .iter()
        .map(|(driver, _)| driver.counters().get(Counter::DatagramsSent))
        .sum();
    println!(
        "  whole run: server received {} and sent {} datagrams ({} send failures); clients sent {}",
        server_counters.get(Counter::DatagramsReceived),
        server_counters.get(Counter::DatagramsSent),
        server_counters.get(Counter::SendFailures),
        client_sent
    );
}

fn main() {
    let options = Options::parse();
    let clock = MonotonicClock::new();
    let any_port = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));

    #[cfg(target_os = "linux")]
    if !options.portable {
        use hex_net_io::linux::{LinuxSocket, SocketOptions};

        // A client handles one peer's traffic; a small buffer is plenty and
        // keeps a thousand of them cheap.
        let client_options = SocketOptions { recv_buffer: 64 << 10, send_buffer: 64 << 10 };
        let socket = LinuxSocket::bind(any_port, clock, SocketOptions::default()).expect("a server socket");
        let server = socket.local_addr().expect("a bound address");
        let clients = (0..options.clients)
            .map(|index| {
                let addr = SocketAddr::from((client_ip(index), 0));
                let socket = LinuxSocket::bind(addr, clock, client_options).expect("a client socket");
                ClientDriver::new(socket, connector(&clock, server, index))
            })
            .collect();
        run(&options, clock, socket, clients);
        return;
    }

    let socket = PortableSocket::bind(any_port, clock).expect("a server socket");
    let server = socket.local_addr().expect("a bound address");
    let clients = (0..options.clients)
        .map(|index| {
            let socket = PortableSocket::bind(SocketAddr::from((client_ip(index), 0)), clock).expect("a client socket");
            ClientDriver::new(socket, connector(&clock, server, index))
        })
        .collect();
    run(&options, clock, socket, clients);
}
