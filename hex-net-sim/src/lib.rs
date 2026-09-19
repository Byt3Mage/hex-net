//! An in-memory network for driving the transport deterministically.
//!
//! Time only moves when told to, so a run of several simulated minutes
//! completes in milliseconds, and every random decision comes from one seed, so
//! a failing run replays exactly.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, VecDeque};
use std::net::SocketAddr;
use std::time::Duration;

use hex_net_core::packet::Packet;
use hex_net_core::time::Timestamp;
use hex_net_core::wire::MAX_DATAGRAM;

#[cfg(test)]
mod transport;

/// How a simulated link behaves. Applied to what a host sends, so the two
/// directions of a connection can differ, as real ones do.
#[derive(Clone, Copy, Debug)]
pub struct LinkConfig {
    /// One-way delay before jitter.
    pub latency: Duration,
    /// Random delay added on top, uniform in [0, jitter].
    pub jitter: Duration,
    /// Chance a packet is dropped, 0.0 to 1.0.
    pub loss: f32,
    /// Chance a packet is delivered twice.
    pub duplication: f32,
    /// Chance a packet's delivery is pushed back behind later ones. Separate
    /// from jitter so reordering can be tested without inflating the round trip.
    pub reorder: f32,
    /// Extra delay applied to a reordered packet.
    pub reorder_delay: Duration,
    /// Bytes per second, or None for unlimited.
    pub bandwidth: Option<u32>,
    /// Packets in flight before the link starts dropping, modelling a router
    /// queue: once full, new packets are discarded rather than queued.
    pub capacity: usize,
}

impl LinkConfig {
    /// Instant and lossless. The baseline for tests about protocol logic rather
    /// than network behaviour.
    pub const PERFECT: LinkConfig = LinkConfig {
        latency: Duration::ZERO,
        jitter: Duration::ZERO,
        loss: 0.0,
        duplication: 0.0,
        reorder: 0.0,
        reorder_delay: Duration::ZERO,
        bandwidth: None,
        capacity: 4096,
    };

    /// Wired broadband: low latency, negligible loss.
    pub const GOOD: LinkConfig = LinkConfig {
        latency: Duration::from_millis(15),
        jitter: Duration::from_millis(3),
        loss: 0.001,
        duplication: 0.0,
        reorder: 0.001,
        reorder_delay: Duration::from_millis(20),
        bandwidth: None,
        capacity: 4096,
    };

    /// Mobile or congested wifi. Unpleasant, and entirely ordinary for real
    /// players.
    pub const POOR: LinkConfig = LinkConfig {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(40),
        loss: 0.05,
        duplication: 0.005,
        reorder: 0.02,
        reorder_delay: Duration::from_millis(60),
        bandwidth: Some(256_000),
        capacity: 256,
    };

    /// Deliberately hostile. Nothing should break; things may be slow.
    pub const AWFUL: LinkConfig = LinkConfig {
        latency: Duration::from_millis(200),
        jitter: Duration::from_millis(150),
        loss: 0.30,
        duplication: 0.02,
        reorder: 0.10,
        reorder_delay: Duration::from_millis(200),
        bandwidth: Some(64_000),
        capacity: 64,
    };
}

/// xorshift64*. Fast and adequate for shaping traffic; not for anything
/// security-related.
#[derive(Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        // Zero is a fixed point of xorshift.
        Self(seed | 1)
    }

    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform in [0, 1). The top 24 bits are exactly an f32 mantissa, so every
    /// value is representable and the distribution has no gaps.
    #[inline]
    pub fn next_f32(&mut self) -> f32 {
        ((self.next_u64() >> 40) as f32) / ((1u32 << 24) as f32)
    }

    #[inline]
    pub fn chance(&mut self, probability: f32) -> bool {
        (probability > 0.0) && (self.next_f32() < probability)
    }

    /// Uniform in [0, max].
    #[inline]
    pub fn duration_up_to(&mut self, max: Duration) -> Duration {
        if max.is_zero() {
            return Duration::ZERO;
        }
        let nanos = max.as_nanos() as u64;
        Duration::from_nanos(self.next_u64() % (nanos + 1))
    }
}

/// A datagram waiting for its delivery time.
struct InFlight {
    deliver_at: Timestamp,
    /// Breaks ties in delivery order. Without it, two packets due at the same
    /// nanosecond would come out in whatever order the heap produced, and a
    /// failing run would not replay.
    seq: u64,
    to: SocketAddr,
    from: SocketAddr,
    len: usize,
    data: Box<Packet>,
}

impl PartialEq for InFlight {
    fn eq(&self, other: &Self) -> bool {
        (self.deliver_at == other.deliver_at) && (self.seq == other.seq)
    }
}
impl Eq for InFlight {}

impl Ord for InFlight {
    fn cmp(&self, other: &Self) -> Ordering {
        // BinaryHeap is a max-heap; reversed so the earliest delivery is on top.
        other
            .deliver_at
            .cmp(&self.deliver_at)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}
impl PartialOrd for InFlight {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A datagram that has arrived and not yet been read.
struct Arrived {
    from: SocketAddr,
    at: Timestamp,
    len: usize,
    data: Box<Packet>,
}

/// One endpoint's mailbox and outbound link.
struct Host {
    addr: SocketAddr,
    uplink: LinkConfig,
    inbox: VecDeque<Arrived>,
    /// When this link is next free to send, for bandwidth accounting.
    busy_until: Timestamp,
    in_flight: usize,
}

/// What a host read off its socket.
#[derive(Clone, Copy, Debug)]
pub struct Received {
    pub from: SocketAddr,
    pub len: usize,
    /// When the datagram arrived, standing in for a kernel receive timestamp.
    pub at: Timestamp,
}

/// An in-memory network connecting simulated hosts.
pub struct Network {
    hosts: Vec<Host>,
    flight: BinaryHeap<InFlight>,
    rng: Rng,
    now: Timestamp,
    next_seq: u64,

    pub sent: u64,
    pub delivered: u64,
    pub dropped_loss: u64,
    pub dropped_capacity: u64,
    pub duplicated: u64,
    pub reordered: u64,
}

impl Network {
    pub fn new(seed: u64) -> Self {
        Self {
            hosts: Vec::new(),
            flight: BinaryHeap::new(),
            rng: Rng::new(seed),
            now: Timestamp::ZERO,
            next_seq: 0,
            sent: 0,
            delivered: 0,
            dropped_loss: 0,
            dropped_capacity: 0,
            duplicated: 0,
            reordered: 0,
        }
    }

    /// Adds a host. The returned address is what other hosts send to.
    pub fn add_host(&mut self, uplink: LinkConfig) -> SocketAddr {
        let index = self.hosts.len();
        let addr: SocketAddr = format!("10.0.{}.{}:{}", index / 250, (index % 250) + 1, 10000 + index)
            .parse()
            .expect("generated address is valid");

        self.hosts.push(Host {
            addr,
            uplink,
            inbox: VecDeque::new(),
            busy_until: Timestamp::ZERO,
            in_flight: 0,
        });
        addr
    }

    /// Changes a host's outbound link mid-run, so a test can degrade a
    /// connection partway through and watch it adapt.
    pub fn set_uplink(&mut self, addr: SocketAddr, config: LinkConfig) {
        if let Some(index) = self.index_of(addr) {
            self.hosts[index].uplink = config;
        }
    }

    #[inline]
    pub fn now(&self) -> Timestamp {
        self.now
    }

    /// The next moment anything is due, so a loop can jump straight to it.
    pub fn next_delivery(&self) -> Option<Timestamp> {
        self.flight.peek().map(|packet| packet.deliver_at)
    }

    pub fn is_idle(&self) -> bool {
        self.flight.is_empty() && self.hosts.iter().all(|host| host.inbox.is_empty())
    }

    pub fn advance(&mut self, by: Duration) {
        self.advance_to(self.now.saturating_add(by));
    }

    /// Moves time forward, delivering everything due along the way.
    pub fn advance_to(&mut self, until: Timestamp) {
        while let Some(next) = self.flight.peek() {
            if next.deliver_at > until {
                break;
            }
            let packet = self.flight.pop().expect("just peeked");
            self.now = packet.deliver_at;
            self.deliver(packet);
        }
        self.now = self.now.max(until);
    }

    /// Queues one datagram, applying the sender's link conditions.
    pub fn send(&mut self, from: SocketAddr, to: SocketAddr, data: &[u8]) {
        let Some(index) = self.index_of(from) else { return };
        let config = self.hosts[index].uplink;
        self.sent += 1;

        // A full router queue drops rather than queues. This is what congestion
        // actually looks like, and why a sender must respect a byte budget.
        if self.hosts[index].in_flight >= config.capacity {
            self.dropped_capacity += 1;
            return;
        }
        if self.rng.chance(config.loss) {
            self.dropped_loss += 1;
            return;
        }
        // An unknown destination is silently dropped, exactly as UDP would.
        if self.index_of(to).is_none() {
            return;
        }

        // Serialization delay: a link can only clock out so many bytes per
        // second, so back-to-back packets queue behind each other.
        let mut depart = self.now;
        if let Some(bandwidth) = config.bandwidth {
            depart = depart.max(self.hosts[index].busy_until);
            let nanos = ((data.len() as u64) * 1_000_000_000) / (bandwidth as u64);
            self.hosts[index].busy_until = depart.saturating_add(Duration::from_nanos(nanos));
        }

        let mut delay = config.latency + self.rng.duration_up_to(config.jitter);
        if self.rng.chance(config.reorder) {
            delay += config.reorder_delay;
            self.reordered += 1;
        }
        let deliver_at = depart.saturating_add(delay);

        self.push(from, to, data, deliver_at);
        self.hosts[index].in_flight += 1;

        if self.rng.chance(config.duplication) {
            // A duplicate arrives slightly later, which is what makes it
            // detectable as a duplicate rather than a reorder.
            let extra = self.rng.duration_up_to(Duration::from_millis(5));
            self.push(from, to, data, deliver_at.saturating_add(extra));
            self.hosts[index].in_flight += 1;
            self.duplicated += 1;
        }
    }

    /// Reads one datagram for `addr`, copying it into `buf`.
    ///
    /// An oversized datagram is truncated rather than rejected, as a real
    /// `recvfrom` with a short buffer would do.
    pub fn recv(&mut self, addr: SocketAddr, buf: &mut Packet) -> Option<Received> {
        let index = self.index_of(addr)?;
        let arrived = self.hosts[index].inbox.pop_front()?;

        let len = arrived.len.min(MAX_DATAGRAM);
        buf[..len].copy_from_slice(&arrived.data[..len]);

        Some(Received { from: arrived.from, len, at: arrived.at })
    }

    fn deliver(&mut self, packet: InFlight) {
        let Some(index) = self.index_of(packet.to) else { return };

        self.hosts[index].in_flight = self.hosts[index].in_flight.saturating_sub(1);
        self.hosts[index].inbox.push_back(Arrived {
            from: packet.from,
            at: packet.deliver_at,
            len: packet.len,
            data: packet.data,
        });
        self.delivered += 1;
    }

    fn push(&mut self, from: SocketAddr, to: SocketAddr, data: &[u8], deliver_at: Timestamp) {
        let len = data.len().min(MAX_DATAGRAM);
        let mut buffer = Box::new([0u8; MAX_DATAGRAM]);
        buffer[..len].copy_from_slice(&data[..len]);

        self.flight.push(InFlight {
            deliver_at,
            seq: self.next_seq,
            to,
            from,
            len,
            data: buffer,
        });
        self.next_seq += 1;
    }

    fn index_of(&self, addr: SocketAddr) -> Option<usize> {
        self.hosts.iter().position(|host| host.addr == addr)
    }
}
