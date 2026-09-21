//! A simulated network: links with latency, jitter, loss, burst loss, and
//! duplication, and sockets over it that implement the same trait a real
//! socket does.
//!
//! Every random decision draws from one generator, and arrivals at the same
//! instant keep the order they were sent in, so a seed replays exactly.

use std::{
    cell::{Cell, RefCell},
    cmp::Ordering,
    collections::{BinaryHeap, HashMap, VecDeque},
    io,
    net::SocketAddr,
    rc::Rc,
    time::Duration,
};

use hex_net_core::time::Timestamp;
use hex_net_io::{Received, Socket, Transmit};

/// splitmix64: small, fast, and good enough to drive network conditions.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in [0, 1), from the top 53 bits.
    pub fn unit(&mut self) -> f64 {
        ((self.next_u64() >> 11) as f64) * (1.0 / ((1u64 << 53) as f64))
    }

    pub fn chance(&mut self, probability: f64) -> bool {
        self.unit() < probability
    }

    /// Uniform in [0, max].
    pub fn duration_up_to(&mut self, max: Duration) -> Duration {
        let nanos = u64::try_from(max.as_nanos()).unwrap_or(u64::MAX);
        if nanos == 0 {
            return Duration::ZERO;
        }
        Duration::from_nanos(self.next_u64() % (nanos + 1))
    }
}

/// Loss that arrives in runs, as on a congested or fading link: the
/// Gilbert-Elliott model. Each datagram may move the link between a good
/// state, which loses at the link's base rate, and a bad one, which loses at
/// this burst's rate.
#[derive(Clone, Copy, Debug)]
pub struct Burst {
    /// Chance per datagram of entering the bad state.
    pub enter: f64,
    /// Chance per datagram of leaving it.
    pub leave: f64,
    /// Loss rate while in it.
    pub loss: f64,
}

/// Conditions in one direction of one path.
#[derive(Clone, Copy, Debug)]
pub struct Link {
    pub latency: Duration,
    /// Extra delay drawn uniformly from zero to this, per datagram. More jitter
    /// than the gap between datagrams reorders them.
    pub jitter: Duration,
    /// Chance of losing a datagram outside a burst.
    pub loss: f64,
    pub burst: Option<Burst>,
    /// Chance of delivering a datagram twice.
    pub duplicate: f64,
}

impl Link {
    /// Fixed delay, nothing lost, nothing reordered.
    pub const fn clean(latency: Duration) -> Link {
        Link {
            latency,
            jitter: Duration::ZERO,
            loss: 0.0,
            burst: None,
            duplicate: 0.0,
        }
    }
}

struct Direction {
    link: Link,
    in_burst: bool,
}

impl Direction {
    fn new(link: Link) -> Self {
        Self { link, in_burst: false }
    }

    /// Advances the burst state and decides whether this datagram is lost.
    fn loses(&mut self, rng: &mut Rng) -> bool {
        let Some(burst) = self.link.burst else {
            return rng.chance(self.link.loss);
        };
        self.in_burst = if self.in_burst { !rng.chance(burst.leave) } else { rng.chance(burst.enter) };
        rng.chance(if self.in_burst { burst.loss } else { self.link.loss })
    }
}

/// The two directions between one client and the server.
struct Path {
    up: Direction,
    down: Direction,
}

struct Arrival {
    at: Timestamp,
    /// Send order, so arrivals at the same instant keep it.
    order: u64,
    from: SocketAddr,
    to: SocketAddr,
    data: Vec<u8>,
}

impl PartialEq for Arrival {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Arrival {}

impl Ord for Arrival {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reversed, because `BinaryHeap` pops its greatest entry first.
        other.at.cmp(&self.at).then_with(|| other.order.cmp(&self.order))
    }
}

impl PartialOrd for Arrival {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A datagram that has arrived and waits to be read.
struct Landed {
    from: SocketAddr,
    at: Timestamp,
    data: Vec<u8>,
}

/// What the wire has done, for assertions and for sizing a run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WireStats {
    pub sent: u64,
    pub lost: u64,
    pub duplicated: u64,
    /// Sent to an address with no path, so dropped.
    pub unroutable: u64,
    pub delivered: u64,
}

/// Every datagram in flight between the server and its clients.
pub struct Wire {
    now: Timestamp,
    rng: Rng,
    server: SocketAddr,
    /// Keyed by client address.
    paths: HashMap<SocketAddr, Path>,
    in_flight: BinaryHeap<Arrival>,
    inboxes: HashMap<SocketAddr, VecDeque<Landed>>,
    /// Addresses whose inbox became non-empty since last taken, each once.
    landed: Vec<SocketAddr>,
    order: u64,
    stats: WireStats,
    /// FNV-1a over every send decision and delivery, so two runs can be
    /// compared with one number.
    fingerprint: u64,
}

impl Wire {
    pub fn new(seed: u64, server: SocketAddr) -> Self {
        Self {
            now: Timestamp::ZERO,
            rng: Rng::new(seed),
            server,
            paths: HashMap::new(),
            in_flight: BinaryHeap::new(),
            inboxes: HashMap::new(),
            landed: Vec::new(),
            order: 0,
            stats: WireStats::default(),
            fingerprint: 0xcbf2_9ce4_8422_2325,
        }
    }

    #[inline]
    pub fn now(&self) -> Timestamp {
        self.now
    }

    #[inline]
    pub fn stats(&self) -> WireStats {
        self.stats
    }

    #[inline]
    pub fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    /// Connects a client address to the server.
    pub fn add_path(&mut self, client: SocketAddr, up: Link, down: Link) {
        self.paths
            .insert(client, Path { up: Direction::new(up), down: Direction::new(down) });
    }

    /// Moves a client to a new address, as a NAT rebinding does: its path and
    /// anything already on its way follow it, and the server learns the new
    /// address only from the next packet it receives.
    pub fn rebind(&mut self, old: SocketAddr, new: SocketAddr) {
        if let Some(path) = self.paths.remove(&old) {
            self.paths.insert(new, path);
        }
        if let Some(waiting) = self.inboxes.remove(&old) {
            self.inboxes.entry(new).or_default().extend(waiting);
        }
        for addr in self.landed.iter_mut() {
            if *addr == old {
                *addr = new;
            }
        }

        let mut in_flight: Vec<Arrival> = self.in_flight.drain().collect();
        for arrival in in_flight.iter_mut() {
            if arrival.to == old {
                arrival.to = new;
            }
        }
        self.in_flight = in_flight.into_iter().collect();
    }

    /// Changes a path's conditions for datagrams sent from here on.
    pub fn set_links(&mut self, client: SocketAddr, up: Link, down: Link) {
        if let Some(path) = self.paths.get_mut(&client) {
            path.up.link = up;
            path.down.link = down;
        }
    }

    /// When the next datagram lands, or now if one has landed unread.
    pub fn next_arrival(&self) -> Option<Timestamp> {
        if !self.landed.is_empty() {
            return Some(self.now);
        }
        self.in_flight.peek().map(|arrival| arrival.at)
    }

    /// Moves the clock and lands everything due by then.
    pub fn advance(&mut self, now: Timestamp) {
        self.now = self.now.max(now);
        while let Some(arrival) = self.in_flight.peek()
            && (arrival.at <= self.now)
        {
            let Some(arrival) = self.in_flight.pop() else { break };
            self.mix(arrival.at.as_nanos());
            self.mix(addr_bits(arrival.to));
            self.stats.delivered += 1;

            let inbox = self.inboxes.entry(arrival.to).or_default();
            if inbox.is_empty() {
                self.landed.push(arrival.to);
            }
            inbox.push_back(Landed {
                from: arrival.from,
                at: arrival.at,
                data: arrival.data,
            });
        }
    }

    /// Addresses with datagrams waiting, in the order they first landed.
    pub fn take_landed(&mut self) -> Vec<SocketAddr> {
        std::mem::take(&mut self.landed)
    }

    fn send(&mut self, from: SocketAddr, to: SocketAddr, bytes: &[u8]) {
        self.stats.sent += 1;
        let (client, upstream) = if to == self.server { (from, true) } else { (to, false) };
        let Some(path) = self.paths.get_mut(&client) else {
            self.stats.unroutable += 1;
            return;
        };
        let direction = if upstream { &mut path.up } else { &mut path.down };

        if direction.loses(&mut self.rng) {
            self.stats.lost += 1;
            self.mix(u64::MAX);
            return;
        }
        let link = direction.link;
        let copies = if self.rng.chance(link.duplicate) { 2 } else { 1 };
        if copies == 2 {
            self.stats.duplicated += 1;
        }

        for _ in 0..copies {
            let delay = link.latency + self.rng.duration_up_to(link.jitter);
            let at = self.now.saturating_add(delay);
            self.order += 1;
            self.mix(at.as_nanos());
            self.in_flight.push(Arrival {
                at,
                order: self.order,
                from,
                to,
                data: bytes.to_vec(),
            });
        }
    }

    fn receive(&mut self, addr: SocketAddr) -> Option<Landed> {
        self.inboxes.get_mut(&addr)?.pop_front()
    }

    fn mix(&mut self, value: u64) {
        for byte in value.to_le_bytes() {
            self.fingerprint ^= u64::from(byte);
            self.fingerprint = self.fingerprint.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
}

fn addr_bits(addr: SocketAddr) -> u64 {
    match addr {
        SocketAddr::V4(v4) => (u64::from(v4.ip().to_bits()) << 16) | u64::from(v4.port()),
        SocketAddr::V6(v6) => ((v6.ip().to_bits() as u64) << 16) | u64::from(v6.port()),
    }
}

/// One node's view of the wire.
pub struct SimSocket {
    wire: Rc<RefCell<Wire>>,
    addr: Rc<Cell<SocketAddr>>,
}

impl SimSocket {
    pub fn new(wire: Rc<RefCell<Wire>>, addr: Rc<Cell<SocketAddr>>) -> Self {
        Self { wire, addr }
    }
}

impl Socket for SimSocket {
    fn recv_batch(&mut self, buffers: &mut [&mut [u8]], out: &mut [Received]) -> io::Result<usize> {
        let mut wire = self.wire.borrow_mut();
        let mut count = 0;
        while (count < buffers.len()) && (count < out.len()) {
            let Some(landed) = wire.receive(self.addr.get()) else { break };
            let buffer = &mut buffers[count];
            let len = landed.data.len().min(buffer.len());
            buffer[..len].copy_from_slice(&landed.data[..len]);
            out[count] = Received { from: landed.from, len, at: landed.at };
            count += 1;
        }
        Ok(count)
    }

    fn send_batch(&mut self, buffers: &[&[u8]], transmits: &[Transmit]) -> io::Result<usize> {
        let mut wire = self.wire.borrow_mut();
        for (bytes, transmit) in buffers.iter().zip(transmits) {
            wire.send(self.addr.get(), transmit.to, &bytes[..transmit.len.min(bytes.len())]);
        }
        Ok(buffers.len().min(transmits.len()))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr.get())
    }
}
