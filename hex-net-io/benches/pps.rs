//! Datagrams per second through one endpoint, under the traffic a
//! high-fidelity MMO makes: a 60 Hz server simulation, every client sending
//! its inputs at 30 Hz with the last three ticks in each for redundancy, and
//! the server sending every client a snapshot at 20 or 30 Hz and a reliable
//! event once a second.
//!
//! The server runs its own loop on its own thread. Clients are spread over one
//! or more load threads, each stepping its clients only when their deadlines
//! come, so the load costs what the clients' transport costs and nothing more.
//!
//! `cargo bench -p hex-net-io --bench pps -- [--clients N] [--seconds S]
//! [--snapshot-hz 20|30] [--load-threads T] [--portable]`
//!
//! Rates are real datagrams, read from the server's own counters, so packets
//! carrying only acknowledgements are counted like any other. On Linux, CPU
//! time comes from the kernel's per-thread accounting, split into user and
//! system time, which gives the server's cost per datagram independent of how
//! many cores the machine has or what else competes for them. System time
//! includes, on loopback, delivering each sent datagram into the receiving
//! socket.
//!
//! Every client binds its own socket, so the open-file limit must exceed the
//! client count: `ulimit -n 20000` before `--clients 10000`.

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
    channel::{ChannelKind, ChannelSet},
    config::{BudgetConfig, MaxAckDelay, TransportConfig},
    connector::{Connector, State},
    crypto::Key,
    endpoint::{Endpoint, EndpointConfig, Event, ServerConnection},
    slab::Handle,
    stats::Counter,
    time::{Clock, MonotonicClock, Span, Timestamp},
    wire::MAX_DATAGRAM,
};
use hex_net_io::{
    Socket, Wait,
    driver::{ClientApp, ClientDriver, ServerApp, ServerDriver},
    portable::PortableSocket,
    run::{serve_step, stop_pair},
};
use hex_net_sim::pair::{issue_ticket, session_keys};

const BACKEND_KEY: Key = [0x71; 32];

/// Snapshots and inputs travel on the sequenced channel, each direction its
/// own; events on the ordered one.
const STATE: u8 = 0;
const EVENTS: u8 = 1;
const CHANNELS: ChannelSet = ChannelSet::new([ChannelKind::UnreliableSequenced, ChannelKind::ReliableOrdered]);

/// The server simulation's rate. Snapshot rates divide it.
const SIM_HZ: u32 = 60;

/// Sim ticks between a client's inputs: 30 Hz.
const TICKS_PER_INPUT: u32 = 2;

/// Sim ticks each input carries, so a lost packet costs nothing while the next
/// arrives.
const INPUT_REDUNDANCY: usize = 3;

/// One tick of one player's input: movement, look, buttons, and the tick.
const INPUT_TICK_LEN: usize = 24;

const INPUT_LEN: usize = INPUT_TICK_LEN * INPUT_REDUNDANCY;

/// A delta-compressed snapshot of a player's area of interest.
const SNAPSHOT_LEN: usize = 480;

/// A reliable event: chat, inventory, a quest update.
const EVENT_LEN: usize = 64;

/// Sim ticks between one client's events: one a second, staggered over
/// clients so the server sends a steady trickle rather than a burst.
const TICKS_PER_EVENT: u32 = SIM_HZ;

/// A 480-byte snapshot 30 times a second is about 16 KB/s with headers; the
/// default budget is sized for lighter traffic.
const RATE: u32 = 64_000;

/// Longer than the gap between one side's packets, so every acknowledgement
/// rides on an input or a snapshot and none goes out alone.
const MAX_ACK_DELAY: Span = Span::from_millis(50);

/// How long every client has to finish its handshake.
const CONNECT_LIMIT: Duration = Duration::from_secs(60);

/// Run after the last handshake and before measuring, so the window starts
/// in steady state.
const WARM_UP: Duration = Duration::from_secs(2);

/// Server cost is projected onto this many players at the target rate.
const TARGET_PLAYERS: f64 = 10_000.0;

/// Datagrams per player per second the target workload makes, both ways.
const TARGET_RATE: f64 = 60.0;

struct Options {
    clients: usize,
    seconds: u64,
    snapshot_hz: u32,
    load_threads: usize,
    portable: bool,
}

impl Options {
    fn parse() -> Options {
        let mut options = Options {
            clients: 1000,
            seconds: 5,
            snapshot_hz: 30,
            load_threads: thread::available_parallelism().map_or(1, |n| n.get().saturating_sub(1).max(1)),
            portable: !cfg!(target_os = "linux"),
        };
        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--clients" => options.clients = number(args.next(), "--clients"),
                "--seconds" => options.seconds = number(args.next(), "--seconds"),
                "--snapshot-hz" => options.snapshot_hz = number(args.next(), "--snapshot-hz"),
                "--load-threads" => options.load_threads = number(args.next(), "--load-threads"),
                "--portable" => options.portable = true,
                // Added by `cargo bench` itself.
                "--bench" => {}
                other => panic!("unknown argument {other}"),
            }
        }
        assert!(
            (options.snapshot_hz > 0) && SIM_HZ.is_multiple_of(options.snapshot_hz),
            "--snapshot-hz must divide {SIM_HZ}"
        );
        assert!(options.load_threads > 0, "--load-threads must be at least 1");
        options
    }

    fn ticks_per_snapshot(&self) -> u32 {
        SIM_HZ / self.snapshot_hz
    }
}

fn number<T: std::str::FromStr>(value: Option<String>, flag: &str) -> T {
    value
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("{flag} takes a number"))
}

fn tick_period() -> Span {
    Span::from_nanos(Span::NANOS_PER_SECOND / u64::from(SIM_HZ))
}

fn transport() -> TransportConfig {
    TransportConfig::DEFAULT
        .with_budget(BudgetConfig::new(RATE, MAX_DATAGRAM).expect("the benchmark budget is within bounds"))
        .with_max_ack_delay(MaxAckDelay::new(MAX_ACK_DELAY).expect("the benchmark delay is within the header's range"))
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
    events_sent: AtomicU64,
    events_received: AtomicU64,
    /// Server ticks begun more than a whole tick late.
    ticks_late: AtomicU64,
    /// The server driver's own counters, published after every step.
    server_datagrams_in: AtomicU64,
    server_datagrams_out: AtomicU64,
    server_tracked_out: AtomicU64,
}

impl Tally {
    fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    fn set(counter: &AtomicU64, n: u64) {
        counter.store(n, Ordering::Relaxed);
    }

    fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

/// A thread's time on CPU, and how it divides between user and system time.
#[derive(Clone, Copy, Default)]
struct CpuTime {
    total: Duration,
    user: Duration,
    system: Duration,
}

impl CpuTime {
    fn since(self, earlier: CpuTime) -> CpuTime {
        CpuTime {
            total: self.total.saturating_sub(earlier.total),
            user: self.user.saturating_sub(earlier.user),
            system: self.system.saturating_sub(earlier.system),
        }
    }

    /// The share of `total` spent in the kernel. `total` is exact; the split
    /// is counted in scheduler ticks, so it is applied as a ratio.
    fn system_share(self) -> f64 {
        let split = (self.user + self.system).as_secs_f64();
        if split == 0.0 { 0.0 } else { self.system.as_secs_f64() / split }
    }
}

/// Where the kernel accounts the calling thread's CPU time, or `None` off
/// Linux.
fn thread_accounting() -> Option<String> {
    let link = std::fs::read_link("/proc/thread-self").ok()?;
    Some(format!("/proc/{}", link.display()))
}

/// Time on CPU so far from `schedstat`, split by `stat`'s user and system
/// ticks.
fn cpu_time(thread: &str) -> Option<CpuTime> {
    let schedstat = std::fs::read_to_string(format!("{thread}/schedstat")).ok()?;
    let total = Duration::from_nanos(schedstat.split_whitespace().next()?.parse().ok()?);

    // The command name may contain spaces and parentheses, so fields are
    // counted from the last ')'. utime and stime are the 14th and 15th
    // fields, the 12th and 13th after it.
    let stat = std::fs::read_to_string(format!("{thread}/stat")).ok()?;
    let mut fields = stat.get((stat.rfind(')')? + 1)..)?.split_whitespace().skip(11);
    let user: u64 = fields.next()?.parse().ok()?;
    let system: u64 = fields.next()?.parse().ok()?;
    let tick = clock_tick()?;

    Some(CpuTime {
        total,
        user: tick * (user as u32),
        system: tick * (system as u32),
    })
}

#[cfg(target_os = "linux")]
fn clock_tick() -> Option<Duration> {
    // SAFETY: sysconf reads a configuration value and takes no pointers.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    (hz > 0).then(|| Duration::from_nanos(1_000_000_000 / (hz as u64)))
}

#[cfg(not(target_os = "linux"))]
fn clock_tick() -> Option<Duration> {
    None
}

/// Datagrams the kernel dropped for want of receive buffer, machine-wide.
fn receive_buffer_drops() -> Option<u64> {
    let snmp = std::fs::read_to_string("/proc/net/snmp").ok()?;
    let mut udp = snmp.lines().filter(|line| line.starts_with("Udp:"));
    let names = udp.next()?.split_whitespace();
    let values = udp.next()?.split_whitespace();
    names
        .zip(values)
        .find(|(name, _)| *name == "RcvbufErrors")
        .and_then(|(_, value)| value.parse().ok())
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
    events_sent: u64,
    events_received: u64,
    ticks_late: u64,
    datagrams_in: u64,
    datagrams_out: u64,
    tracked_out: u64,
    kernel_drops: Option<u64>,
    server_cpu: Option<CpuTime>,
    load_cpu: Option<CpuTime>,
}

impl Sample {
    fn take(tally: &Tally, server: &Option<String>, load: &[Option<String>]) -> Sample {
        let load_cpu = load.iter().try_fold(CpuTime::default(), |sum, thread| {
            let time = cpu_time(thread.as_deref()?)?;
            Some(CpuTime {
                total: sum.total + time.total,
                user: sum.user + time.user,
                system: sum.system + time.system,
            })
        });
        Sample {
            at: Instant::now(),
            inputs_sent: Tally::get(&tally.inputs_sent),
            inputs_received: Tally::get(&tally.inputs_received),
            snapshots_sent: Tally::get(&tally.snapshots_sent),
            snapshots_refused: Tally::get(&tally.snapshots_refused),
            snapshots_received: Tally::get(&tally.snapshots_received),
            events_sent: Tally::get(&tally.events_sent),
            events_received: Tally::get(&tally.events_received),
            ticks_late: Tally::get(&tally.ticks_late),
            datagrams_in: Tally::get(&tally.server_datagrams_in),
            datagrams_out: Tally::get(&tally.server_datagrams_out),
            tracked_out: Tally::get(&tally.server_tracked_out),
            kernel_drops: receive_buffer_drops(),
            server_cpu: server.as_deref().and_then(cpu_time),
            load_cpu,
        }
    }
}

/// Runs the 60 Hz simulation: a snapshot to every connection on snapshot
/// ticks, and each connection's event on its own tick of the second.
struct World {
    connections: Vec<Handle<ServerConnection>>,
    snapshot: [u8; SNAPSHOT_LEN],
    event: [u8; EVENT_LEN],
    ticks_per_snapshot: u32,
    tick: u32,
    next_tick: Option<Timestamp>,
    tally: Arc<Tally>,
}

impl ServerApp for World {
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

        let snapshot_tick = self.tick.is_multiple_of(self.ticks_per_snapshot);
        let event_slot = self.tick % TICKS_PER_EVENT;
        let (mut snapshots, mut refused, mut events) = (0, 0, 0);

        for (index, handle) in self.connections.iter().enumerate() {
            let Some(connection) = endpoint.connection_mut(*handle) else { continue };
            if snapshot_tick {
                match connection.send(STATE, &self.snapshot) {
                    Ok(()) => snapshots += 1,
                    Err(_) => refused += 1,
                }
            }
            if ((index as u32) % TICKS_PER_EVENT) == event_slot && connection.send(EVENTS, &self.event).is_ok() {
                events += 1;
            }
        }
        Tally::add(&self.tally.snapshots_sent, snapshots);
        Tally::add(&self.tally.snapshots_refused, refused);
        Tally::add(&self.tally.events_sent, events);
        self.tick = self.tick.wrapping_add(1);

        // A server that falls a whole tick behind starts the next one from
        // now rather than running the missed ones back to back.
        let next = due.saturating_add(tick_period());
        self.next_tick = Some(if next <= now {
            Tally::add(&self.tally.ticks_late, 1);
            now.saturating_add(tick_period())
        } else {
            next
        });
    }

    fn next_wake(&self) -> Option<Timestamp> {
        self.next_tick
    }
}

/// Sends an input every other sim tick once connected, starting at an offset
/// of its own so the clients' inputs spread evenly over the period, and counts
/// what arrives.
struct Player {
    connected: bool,
    input: [u8; INPUT_LEN],
    /// Fraction of the input period this client lags the others by.
    phase: Span,
    next_input: Option<Timestamp>,
    tally: Arc<Tally>,
}

impl ClientApp for Player {
    fn on_message(&mut self, _at: Timestamp, channel: u8, _payload: &[u8]) {
        match channel {
            STATE => Tally::add(&self.tally.snapshots_received, 1),
            _ => Tally::add(&self.tally.events_received, 1),
        }
    }

    fn on_state(&mut self, state: State) {
        self.connected = state == State::Connected;
    }

    fn update(&mut self, now: Timestamp, connector: &mut Connector) {
        if !self.connected {
            return;
        }
        let due = *self.next_input.get_or_insert(now.saturating_add(self.phase));
        if due > now {
            return;
        }
        if let Some(connection) = connector.connection_mut()
            && connection.send(STATE, &self.input).is_ok()
        {
            Tally::add(&self.tally.inputs_sent, 1);
        }
        let period = input_period();
        let next = due.saturating_add(period);
        self.next_input = Some(if next <= now { now.saturating_add(period) } else { next });
    }

    fn next_wake(&self) -> Option<Timestamp> {
        if self.connected { self.next_input } else { None }
    }
}

fn input_period() -> Span {
    tick_period().saturating_mul(TICKS_PER_INPUT)
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
    Connector::connect(clock.now(), server, ticket, keys, CHANNELS, transport())
}

/// Steps every client when its deadline comes, until `stop` is raised.
/// Reports where the kernel accounts this thread's CPU time before starting.
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
            due.push(Reverse((
                next.unwrap_or(now.saturating_add(tick_period())).max(now),
                index,
            )));
        }

        if let Some(&Reverse((at, _))) = due.peek() {
            let now = clock.now();
            if at > now {
                thread::sleep(at.since(now).as_duration());
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
    let config = EndpointConfig {
        transport: transport(),
        ..EndpointConfig::new(capacity)
    };
    let mut server = ServerDriver::new(socket, Endpoint::new(config, BACKEND_KEY, &CHANNELS));

    let (server_accounting_tx, server_accounting) = mpsc::channel();
    let (stopper, signal) = stop_pair(server.socket().waker().expect("a waker"));
    let server_tally = Arc::clone(&tally);
    let ticks_per_snapshot = options.ticks_per_snapshot();
    let server_thread = thread::spawn(move || {
        server_accounting_tx
            .send(thread_accounting())
            .expect("the measuring thread is listening");
        let mut app = World {
            connections: Vec::with_capacity(capacity as usize),
            snapshot: [0x5E; SNAPSHOT_LEN],
            event: [0xE7; EVENT_LEN],
            ticks_per_snapshot,
            tick: 0,
            next_tick: None,
            tally: Arc::clone(&server_tally),
        };
        while !signal.is_requested() {
            serve_step(&mut server, &mut app, &clock).expect("the server loop ran");
            let counters = server.counters();
            Tally::set(
                &server_tally.server_datagrams_in,
                counters.get(Counter::DatagramsReceived),
            );
            Tally::set(&server_tally.server_datagrams_out, counters.get(Counter::DatagramsSent));
            Tally::set(&server_tally.server_tracked_out, counters.get(Counter::PacketsTracked));
        }
        server
    });

    // Round-robin, so every thread carries clients of every phase.
    let load_threads = options.load_threads.min(clients.len().max(1));
    let mut shares: Vec<Vec<(ClientDriver<S>, Player)>> = (0..load_threads).map(|_| Vec::new()).collect();
    let spread = options.clients.max(1) as u32;
    for (index, driver) in clients.into_iter().enumerate() {
        let app = Player {
            connected: false,
            input: [0x1A; INPUT_LEN],
            phase: Span::from_nanos(
                (input_period().as_nanos() * u64::from((index as u32) % spread)) / u64::from(spread),
            ),
            next_input: None,
            tally: Arc::clone(&tally),
        };
        shares[index % load_threads].push((driver, app));
    }

    let stop_load = Arc::new(AtomicBool::new(false));
    let (load_accounting_tx, load_accounting) = mpsc::channel();
    let load_handles: Vec<_> = shares
        .into_iter()
        .map(|share| {
            let stop = Arc::clone(&stop_load);
            let accounting = load_accounting_tx.clone();
            thread::spawn(move || load(clock, share, stop, accounting))
        })
        .collect();
    drop(load_accounting_tx);

    let server_path = server_accounting.recv().expect("the server thread started");
    let load_paths: Vec<_> = (0..load_threads)
        .map(|_| load_accounting.recv().expect("a load thread started"))
        .collect();

    let connecting = Instant::now();
    let target = options.clients as u64;
    while (Tally::get(&tally.connected) < target) && (connecting.elapsed() < CONNECT_LIMIT) {
        thread::sleep(Duration::from_millis(10));
    }
    let connected = Tally::get(&tally.connected);
    println!(
        "{} backend: {connected} of {} clients connected in {:.2?}, {load_threads} load thread(s)",
        if options.portable { "portable" } else { "linux" },
        options.clients,
        connecting.elapsed()
    );

    thread::sleep(WARM_UP);
    let before = Sample::take(&tally, &server_path, &load_paths);
    thread::sleep(Duration::from_secs(options.seconds));
    let after = Sample::take(&tally, &server_path, &load_paths);

    stop_load.store(true, Ordering::Relaxed);
    stopper.stop().expect("the server loop was woken");
    let server = server_thread.join().expect("the server thread");
    let clients: Vec<_> = load_handles
        .into_iter()
        .flat_map(|handle| handle.join().expect("a load thread"))
        .collect();

    report(options, connected, &before, &after);
    totals(&server, &clients);
}

fn report(options: &Options, connected: u64, before: &Sample, after: &Sample) {
    let seconds = after.at.duration_since(before.at).as_secs_f64();
    let rate = |a: u64, b: u64| ((b - a) as f64) / seconds;
    let ratio = |part: u64, whole: u64| if whole == 0 { 0.0 } else { ((part as f64) * 100.0) / (whole as f64) };
    let players = (connected as f64).max(1.0);

    let datagrams_in = rate(before.datagrams_in, after.datagrams_in);
    let datagrams_out = rate(before.datagrams_out, after.datagrams_out);
    let ack_only_out = datagrams_out - rate(before.tracked_out, after.tracked_out);
    let datagrams = datagrams_in + datagrams_out;

    println!(
        "measured over {seconds:.2} s: sim {SIM_HZ} Hz, inputs {} Hz carrying {INPUT_REDUNDANCY} ticks, snapshots {} Hz, events 1 Hz",
        SIM_HZ / TICKS_PER_INPUT,
        options.snapshot_hz
    );
    println!(
        "  offered: {:.0} inputs/s in, {:.0} snapshots/s and {:.0} events/s out",
        rate(before.inputs_sent, after.inputs_sent),
        rate(before.snapshots_sent, after.snapshots_sent),
        rate(before.events_sent, after.events_sent)
    );
    println!(
        "  server datagrams: {datagrams_in:.0}/s in, {datagrams_out:.0}/s out ({ack_only_out:.0}/s acknowledgement only), {datagrams:.0}/s total, {:.1} per player per second",
        datagrams / players
    );
    println!(
        "  delivered: {:.2}% of inputs, {:.2}% of snapshots, {:.2}% of events",
        ratio(
            after.inputs_received - before.inputs_received,
            after.inputs_sent - before.inputs_sent
        ),
        ratio(
            after.snapshots_received - before.snapshots_received,
            after.snapshots_sent - before.snapshots_sent
        ),
        ratio(
            after.events_received - before.events_received,
            after.events_sent - before.events_sent
        )
    );
    println!(
        "  snapshots refused by the budget: {}, server ticks started late: {}",
        after.snapshots_refused - before.snapshots_refused,
        after.ticks_late - before.ticks_late
    );
    if let (Some(a), Some(b)) = (before.kernel_drops, after.kernel_drops) {
        println!("  kernel receive-buffer drops, machine-wide: {}", b - a);
    }

    if let (Some(server_before), Some(server_after)) = (before.server_cpu, after.server_cpu) {
        let used = server_after.since(server_before);
        let busy = used.total.as_secs_f64();
        let per_datagram = (busy * 1e6) / (datagrams * seconds).max(1.0);
        let system = used.system_share();
        println!(
            "  server thread: {:.1}% of a core, {:.0} datagrams per CPU-second, {per_datagram:.2} µs per datagram ({:.2} user, {:.2} system)",
            (busy * 100.0) / seconds,
            datagrams * (seconds / busy.max(f64::MIN_POSITIVE)),
            per_datagram * (1.0 - system),
            per_datagram * system
        );
        println!(
            "  at this cost, {TARGET_PLAYERS:.0} players at {TARGET_RATE:.0} datagrams/s each need {:.2} cores",
            (per_datagram * TARGET_PLAYERS * TARGET_RATE) / 1e6
        );
    }
    if let (Some(load_before), Some(load_after)) = (before.load_cpu, after.load_cpu) {
        let busy = load_after.since(load_before).total.as_secs_f64();
        println!("  load threads: {:.1}% of a core in total", (busy * 100.0) / seconds);
    }
}

/// Whole-run datagram totals from the drivers' own counters.
fn totals<S: Socket>(server: &ServerDriver<S>, clients: &[(ClientDriver<S>, Player)]) {
    let server_counters = server.counters();
    let client_total = |counter| -> u64 { clients.iter().map(|(driver, _)| driver.counters().get(counter)).sum() };
    let client_sent = client_total(Counter::DatagramsSent);
    println!(
        "  whole run: server received {} and sent {} datagrams ({} send failures); clients sent {} ({} acknowledgement only)",
        server_counters.get(Counter::DatagramsReceived),
        server_counters.get(Counter::DatagramsSent),
        server_counters.get(Counter::SendFailures),
        client_sent,
        client_sent - client_total(Counter::PacketsTracked).min(client_sent)
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
        // keeps ten thousand of them cheap.
        let client_options = SocketOptions { recv_buffer: 64 << 10, send_buffer: 64 << 10 };
        let server_options = SocketOptions { recv_buffer: 32 << 20, send_buffer: 16 << 20 };
        let socket = LinuxSocket::bind(any_port, clock, server_options).expect("a server socket");
        let server = socket.local_addr().expect("a bound address");
        let clients = (0..options.clients)
            .map(|index| {
                let addr = SocketAddr::from((client_ip(index), 0));
                let socket = LinuxSocket::bind(addr, clock, client_options)
                    .expect("a client socket (raise `ulimit -n` above the client count)");
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
            let socket = PortableSocket::bind(SocketAddr::from((client_ip(index), 0)), clock)
                .expect("a client socket (raise `ulimit -n` above the client count)");
            ClientDriver::new(socket, connector(&clock, server, index))
        })
        .collect();
    run(&options, clock, socket, clients);
}
