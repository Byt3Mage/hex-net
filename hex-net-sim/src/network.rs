use std::{collections::BinaryHeap, io, net::SocketAddr, time::Duration};

use hex_net_core::time::Timestamp;
use hex_net_io::{Received, Socket, Transmit};

use crate::link::{LinkConfig, Rng};

/// A packet in flight, waiting for its delivery time.
struct InFlight {
    deliver_at: Timestamp,
    /// Breaks ties in delivery order, so equal timestamps resolve the same
    /// way on every run. Without it, heap order would be arbitrary and runs
    /// would not reproduce.
    seq: u64,
    to: SocketAddr,
    from: SocketAddr,
    data: Vec<u8>,
}

impl PartialEq for InFlight {
    fn eq(&self, other: &Self) -> bool {
        (self.deliver_at == other.deliver_at) && (self.seq == other.seq)
    }
}
impl Eq for InFlight {}

impl Ord for InFlight {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // BinaryHeap is a max-heap; reverse so the earliest delivery is on
        // top.
        other
            .deliver_at
            .cmp(&self.deliver_at)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}
impl PartialOrd for InFlight {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// One endpoint's mailbox: what has been delivered to it and not yet read.
struct Host {
    addr: SocketAddr,
    inbox: std::collections::VecDeque<(Received, Vec<u8>)>,
    /// Applied to packets this host sends.
    uplink: LinkConfig,
    /// Bandwidth accounting: when this link is next free to send.
    busy_until: Timestamp,
    in_flight: usize,
}

/// An in-memory network connecting simulated hosts.
///
/// Time only moves when you move it, so a test can run an hour of protocol
/// behaviour in milliseconds, and a failing run replays exactly from its seed.
pub struct Network {
    hosts: Vec<Host>,
    flight: BinaryHeap<InFlight>,
    rng: Rng,
    now: Timestamp,
    next_seq: u64,
    /// Totals, for asserting on what a test actually exercised.
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

    /// Add a host. The returned address is what other hosts send to.
    pub fn add_host(&mut self, uplink: LinkConfig) -> SocketAddr {
        let index = self.hosts.len();
        let addr: SocketAddr = format!("10.0.0.{}:{}", (index / 1000) + 1, 10000 + index)
            .parse()
            .expect("generated address is valid");

        self.hosts.push(Host {
            addr,
            inbox: std::collections::VecDeque::new(),
            uplink,
            busy_until: Timestamp::ZERO,
            in_flight: 0,
        });
        addr
    }

    /// Change a host's outbound link mid-run. Lets a test degrade a
    /// connection partway through and watch it adapt.
    pub fn set_uplink(&mut self, addr: SocketAddr, config: LinkConfig) {
        if let Some(host) = self.host_mut(addr) {
            host.uplink = config;
        }
    }

    #[inline]
    pub fn now(&self) -> Timestamp {
        self.now
    }

    /// Move time forward, delivering everything due along the way.
    pub fn advance(&mut self, by: Duration) {
        self.advance_to(self.now.saturating_add(by));
    }

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

    /// The next moment anything is due. Lets a test loop jump straight to the
    /// next event instead of stepping a millisecond at a time.
    pub fn next_delivery(&self) -> Option<Timestamp> {
        self.flight.peek().map(|packet| packet.deliver_at)
    }

    /// Everything has arrived and nothing is queued.
    pub fn is_idle(&self) -> bool {
        self.flight.is_empty() && self.hosts.iter().all(|host| host.inbox.is_empty())
    }

    fn deliver(&mut self, packet: InFlight) {
        let received = Received {
            from: packet.from,
            len: packet.data.len(),
            at: packet.deliver_at,
        };

        let Some(host) = self.host_mut(packet.to) else { return };
        host.in_flight = host.in_flight.saturating_sub(1);
        host.inbox.push_back((received, packet.data));
        self.delivered += 1;
    }

    fn host_mut(&mut self, addr: SocketAddr) -> Option<&mut Host> {
        self.hosts.iter_mut().find(|host| host.addr == addr)
    }

    fn host_index(&self, addr: SocketAddr) -> Option<usize> {
        self.hosts.iter().position(|host| host.addr == addr)
    }

    /// Queue one packet, applying the sender's link conditions.
    fn transmit(&mut self, from: SocketAddr, to: SocketAddr, data: &[u8]) {
        let Some(index) = self.host_index(from) else { return };
        let config = self.hosts[index].uplink;
        self.sent += 1;

        // Router queue full: drop. This is what congestion actually looks
        // like, and it is why a sender must respect a byte budget.
        if self.hosts[index].in_flight >= config.capacity {
            self.dropped_capacity += 1;
            return;
        }
        if self.rng.chance(config.loss) {
            self.dropped_loss += 1;
            return;
        }
        // Unknown destination: silently dropped, exactly as UDP would.
        if self.host_index(to).is_none() {
            return;
        }

        // Serialization delay: a link can only push so many bytes per second,
        // so back-to-back packets queue behind each other.
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

    fn push(&mut self, from: SocketAddr, to: SocketAddr, data: &[u8], deliver_at: Timestamp) {
        self.flight.push(InFlight {
            deliver_at,
            seq: self.next_seq,
            to,
            from,
            data: data.to_vec(),
        });
        self.next_seq += 1;
    }
}

/// A host's view of the network, implementing `Socket`.
///
/// Holds a raw pointer rather than a borrow so several sockets can share one
/// network in a single-threaded test. Safe because the simulator is
/// explicitly single-threaded: `SimSocket` is neither `Send` nor `Sync`, and
/// it borrows the network for its lifetime.
pub struct SimSocket<'n> {
    network: *mut Network,
    addr: SocketAddr,
    _borrow: std::marker::PhantomData<&'n mut Network>,
}

impl<'n> SimSocket<'n> {
    /// # Panics
    /// If `addr` was not produced by `network.add_host`.
    pub fn new(network: &'n mut Network, addr: SocketAddr) -> Self {
        assert!(
            network.host_index(addr).is_some(),
            "address does not belong to this network"
        );
        Self { network, addr, _borrow: std::marker::PhantomData }
    }

    #[inline]
    fn network(&mut self) -> &mut Network {
        // SAFETY: the pointer came from a &mut borrow held for 'n, and
        // SimSocket is !Send + !Sync, so no other thread can hold one. Within
        // a thread, each call borrows for the duration of that call only.
        unsafe { &mut *self.network }
    }
}

impl Socket for SimSocket<'_> {
    fn recv_batch(&mut self, buffers: &mut [&mut [u8]], out: &mut [Received]) -> io::Result<usize> {
        debug_assert_eq!(buffers.len(), out.len());
        let addr = self.addr;
        let network = self.network();

        let Some(index) = network.host_index(addr) else {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "host removed"));
        };

        let mut filled = 0;
        while filled < buffers.len() {
            let Some((received, data)) = network.hosts[index].inbox.pop_front() else { break };

            // Oversized datagrams are truncated, not rejected — the same
            // thing a real recvfrom does with a short buffer.
            let len = data.len().min(buffers[filled].len());
            buffers[filled][..len].copy_from_slice(&data[..len]);
            out[filled] = Received { len, ..received };
            filled += 1;
        }
        Ok(filled)
    }

    fn send_batch(&mut self, buffers: &[&[u8]], transmits: &[Transmit]) -> io::Result<usize> {
        debug_assert_eq!(buffers.len(), transmits.len());
        let addr = self.addr;
        let network = self.network();

        for (buffer, transmit) in buffers.iter().zip(transmits.iter()) {
            network.transmit(addr, transmit.to, &buffer[..transmit.len]);
        }
        Ok(transmits.len())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }
}
