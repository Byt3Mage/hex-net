//! A server and many clients over a simulated wire, driven the way a real
//! event loop would drive them: each node is stepped only when a datagram has
//! landed for it or a deadline it reported has come.

use std::cell::{Cell, RefCell};
use std::cmp::Ordering;
use std::collections::{BTreeSet, BinaryHeap, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;

use hex_net_core::budget::BudgetConfig;
use hex_net_core::channel::ChannelSet;
use hex_net_core::connector::Connector;
use hex_net_core::crypto::{Key, Keys};
use hex_net_core::endpoint::{Endpoint, EndpointConfig};
use hex_net_core::handshake::{EncryptedTicket, SessionId};
use hex_net_core::time::Timestamp;
use hex_net_io::driver::{ClientApp, ClientDriver, ServerApp, ServerDriver};

use crate::net::{Link, SimSocket, Wire, WireStats};
use crate::pair::{issue_ticket, session_keys};

/// Steps at one instant before the run is declared stuck: some deadline stays
/// due however often its node is stepped.
const STALL_LIMIT: usize = 10_000;

const BACKEND_KEY: Key = [0x5A; 32];

/// Which node: the server, or a client by index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Node {
    Server,
    Client(usize),
}

/// A run that stopped making progress: the same instant came due over and
/// over. Carries what is needed to replay it.
#[derive(Debug)]
pub struct Stall {
    pub seed: u64,
    pub at: Timestamp,
    pub nodes: Vec<Node>,
}

/// A node's deadline. Ordered earliest first, ties by node.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Wake {
    at: Timestamp,
    node: Node,
}

impl Ord for Wake {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reversed, because `BinaryHeap` pops its greatest entry first.
        other.at.cmp(&self.at).then_with(|| other.node.cmp(&self.node))
    }
}

impl PartialOrd for Wake {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct Client<C> {
    driver: ClientDriver<SimSocket>,
    app: C,
    /// Shared with the socket, so a rebinding moves both.
    addr: Rc<Cell<SocketAddr>>,
    /// A crashed client is never stepped again: no timers, no transmits,
    /// nothing read. What the server sent it simply piles up unread.
    crashed: bool,
}

/// A server and its clients.
pub struct World<S: ServerApp, C: ClientApp> {
    seed: u64,
    now: Timestamp,
    wire: Rc<RefCell<Wire>>,
    channels: ChannelSet,
    server_addr: SocketAddr,

    server: ServerDriver<SimSocket>,
    server_app: S,
    clients: Vec<Client<C>>,
    addresses: HashMap<SocketAddr, Node>,

    /// Deadlines each node reported, earliest first. An entry whose time no
    /// longer matches `armed` is stale.
    wakes: BinaryHeap<Wake>,
    armed: HashMap<Node, Timestamp>,
    /// Each client's most recent ticket, for replaying.
    tickets: HashMap<usize, EncryptedTicket>,
    /// Nodes to step at the current instant regardless of deadlines: new, or
    /// changed from outside.
    pending: BTreeSet<Node>,
}

impl<S: ServerApp, C: ClientApp> World<S, C> {
    /// A server with room for `capacity` connections and no clients yet.
    pub fn new(seed: u64, capacity: u32, channels: ChannelSet, server_app: S) -> Self {
        let server_addr = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 9000));
        let wire = Rc::new(RefCell::new(Wire::new(seed, server_addr)));
        let endpoint = Endpoint::new(EndpointConfig::new(capacity), BACKEND_KEY, &channels);
        let socket = SimSocket::new(Rc::clone(&wire), Rc::new(Cell::new(server_addr)));

        let mut addresses = HashMap::new();
        addresses.insert(server_addr, Node::Server);

        Self {
            seed,
            now: Timestamp::ZERO,
            wire,
            channels,
            server_addr,
            server: ServerDriver::new(socket, endpoint),
            server_app,
            clients: Vec::new(),
            addresses,
            wakes: BinaryHeap::new(),
            armed: HashMap::new(),
            tickets: HashMap::new(),
            pending: BTreeSet::from([Node::Server]),
        }
    }

    /// Adds a client that starts connecting at once, over a path with `up`
    /// conditions towards the server and `down` conditions back. Returns its
    /// index.
    pub fn add_client(&mut self, up: Link, down: Link, app: C) -> usize {
        let index = self.clients.len();
        let ticket = issue_ticket(&BACKEND_KEY, self.now, (index as u64) + 1, None, &self.keys(index));
        self.add_client_with_ticket(up, down, ticket, app)
    }

    /// A connector for a client with a freshly sealed ticket, resuming
    /// `session` when given one.
    fn new_connector(&mut self, index: usize, session: Option<SessionId>) -> Connector {
        let ticket = issue_ticket(&BACKEND_KEY, self.now, (index as u64) + 1, session, &self.keys(index));
        self.connector_with(index, ticket)
    }

    /// Every ticket for a client carries the same session keys, deliberately:
    /// the transport binds each connection's keys to its own handshake, so a
    /// reconnect must work even when a backend reuses them.
    fn keys(&self, index: usize) -> Keys {
        session_keys(self.seed ^ ((index as u64) + 1))
    }

    /// A connector presenting `ticket`, remembered as the client's latest so
    /// it can be replayed.
    fn connector_with(&mut self, index: usize, ticket: EncryptedTicket) -> Connector {
        self.tickets.insert(index, ticket);
        let keys = self.keys(index);
        Connector::connect(
            self.now,
            self.server_addr,
            ticket,
            keys,
            self.channels,
            BudgetConfig::DEFAULT,
        )
    }

    /// The sealed ticket a client last presented, as anyone watching its
    /// network could copy it from the request.
    pub fn ticket(&self, index: usize) -> EncryptedTicket {
        self.tickets[&index]
    }

    /// Adds a client at a new address presenting `ticket`, which need not be
    /// its own: an attacker replaying a captured request. Returns its index.
    pub fn add_client_with_ticket(&mut self, up: Link, down: Link, ticket: EncryptedTicket, app: C) -> usize {
        let index = self.clients.len();
        let [a, b] = u16::try_from(index + 1).expect("at most 65,535 clients").to_be_bytes();
        let addr = Rc::new(Cell::new(SocketAddr::from((Ipv4Addr::new(10, 1, a, b), 40_000))));
        self.wire.borrow_mut().add_path(addr.get(), up, down);

        let socket = SimSocket::new(Rc::clone(&self.wire), Rc::clone(&addr));
        let connector = self.connector_with(index, ticket);
        self.clients.push(Client {
            driver: ClientDriver::new(socket, connector),
            app,
            addr: Rc::clone(&addr),
            crashed: false,
        });
        self.addresses.insert(addr.get(), Node::Client(index));
        self.pending.insert(Node::Client(index));
        index
    }

    /// Starts a client over presenting the exact ticket it last connected
    /// with, as someone who captured that request and replays it would.
    pub fn replay_ticket(&mut self, index: usize, app: C) {
        let ticket = self.tickets[&index];
        let connector = self.connector_with(index, ticket);
        self.replace_driver(index, connector, app);
    }

    /// Stops a client dead, as a crashed process does: it stops reading,
    /// stops sending, and never says goodbye.
    pub fn crash_client(&mut self, index: usize) {
        self.clients[index].crashed = true;
        self.pending.remove(&Node::Client(index));
        self.armed.remove(&Node::Client(index));
    }

    /// Closes a client's connection with a notice, as quitting does.
    pub fn close_client(&mut self, index: usize) {
        self.clients[index].driver.connector_mut().close();
        self.pending.insert(Node::Client(index));
    }

    /// Moves a client to a new source address, as a NAT rebinding does, and
    /// returns it. The connection continues; the server must validate the new
    /// path before trusting it.
    pub fn rebind_client(&mut self, index: usize) -> SocketAddr {
        let old = self.clients[index].addr.get();
        let mut new = old;
        new.set_port(old.port() + 1);

        self.wire.borrow_mut().rebind(old, new);
        self.clients[index].addr.set(new);
        self.addresses.remove(&old);
        self.addresses.insert(new, Node::Client(index));
        self.pending.insert(Node::Client(index));
        new
    }

    /// Starts a client over on a fresh connection that resumes `session`, as
    /// relaunching the game does. Its recorded state starts over with `app`.
    pub fn reconnect_client(&mut self, index: usize, session: SessionId, app: C) {
        let connector = self.new_connector(index, Some(session));
        self.replace_driver(index, connector, app);
    }

    fn replace_driver(&mut self, index: usize, connector: Connector, app: C) {
        let socket = SimSocket::new(Rc::clone(&self.wire), Rc::clone(&self.clients[index].addr));

        let client = &mut self.clients[index];
        client.driver = ClientDriver::new(socket, connector);
        client.app = app;
        client.crashed = false;
        self.pending.insert(Node::Client(index));
    }

    /// Closes every connection with a notice.
    pub fn shutdown_server(&mut self) {
        self.server.endpoint_mut().shutdown();
        self.pending.insert(Node::Server);
    }

    #[inline]
    pub fn seed(&self) -> u64 {
        self.seed
    }

    #[inline]
    pub fn now(&self) -> Timestamp {
        self.now
    }

    #[inline]
    pub fn clients(&self) -> usize {
        self.clients.len()
    }

    #[inline]
    pub fn server(&self) -> &ServerDriver<SimSocket> {
        &self.server
    }

    #[inline]
    pub fn server_app(&self) -> &S {
        &self.server_app
    }

    #[inline]
    pub fn client(&self, index: usize) -> &ClientDriver<SimSocket> {
        &self.clients[index].driver
    }

    #[inline]
    pub fn client_app(&self, index: usize) -> &C {
        &self.clients[index].app
    }

    /// The application may change what it wants to send, so the client is
    /// stepped again at the current instant.
    pub fn client_app_mut(&mut self, index: usize) -> &mut C {
        self.pending.insert(Node::Client(index));
        &mut self.clients[index].app
    }

    /// Changes a client's path for datagrams sent from here on.
    pub fn set_links(&mut self, index: usize, up: Link, down: Link) {
        let addr = self.clients[index].addr.get();
        self.wire.borrow_mut().set_links(addr, up, down);
    }

    pub fn wire_stats(&self) -> WireStats {
        self.wire.borrow().stats()
    }

    /// One number standing for everything that crossed the wire and when.
    pub fn fingerprint(&self) -> u64 {
        self.wire.borrow().fingerprint()
    }

    /// Runs until `duration` of simulated time has passed, stepping each node
    /// at every datagram landing for it and every deadline it reported.
    pub fn run_for(&mut self, duration: Duration) -> Result<(), Stall> {
        let end = self.now.saturating_add(duration);
        let mut steps_at_instant = 0;

        loop {
            let next = self.next_event();
            match next {
                Some(at) if at <= end => {
                    if at > self.now {
                        self.now = at;
                        steps_at_instant = 0;
                    }
                }
                _ => {
                    self.now = end;
                    self.wire.borrow_mut().advance(end);
                    return Ok(());
                }
            }

            self.wire.borrow_mut().advance(self.now);
            let due = self.take_due();

            steps_at_instant += 1;
            if steps_at_instant > STALL_LIMIT {
                return Err(Stall {
                    seed: self.seed,
                    at: self.now,
                    nodes: due.into_iter().collect(),
                });
            }

            for node in due {
                self.step(node);
            }
        }
    }

    /// The earliest of the next landing, the next deadline, and now if any
    /// node is pending.
    fn next_event(&self) -> Option<Timestamp> {
        let pending = (!self.pending.is_empty()).then_some(self.now);
        let arrival = self.wire.borrow().next_arrival();
        let wake = self.wakes.peek().map(|wake| wake.at);
        pending.into_iter().chain(arrival).chain(wake).min()
    }

    /// Every node with work at the current instant, in a fixed order.
    fn take_due(&mut self) -> BTreeSet<Node> {
        let mut due = std::mem::take(&mut self.pending);

        for addr in self.wire.borrow_mut().take_landed() {
            if let Some(&node) = self.addresses.get(&addr) {
                due.insert(node);
            }
        }
        due.retain(|node| match node {
            Node::Server => true,
            Node::Client(index) => !self.clients[*index].crashed,
        });

        while let Some(&wake) = self.wakes.peek()
            && (wake.at <= self.now)
        {
            self.wakes.pop();
            if self.armed.get(&wake.node) == Some(&wake.at) {
                self.armed.remove(&wake.node);
                due.insert(wake.node);
            }
        }
        due
    }

    fn step(&mut self, node: Node) {
        let next = match node {
            Node::Server => self.server.step(self.now, &mut self.server_app),
            Node::Client(index) => {
                let client = &mut self.clients[index];
                if client.crashed {
                    return;
                }
                client.driver.step(self.now, &mut client.app)
            }
        };
        let next = next.expect("simulated sockets never fail");

        match next {
            Some(at) if at <= self.now => {
                self.pending.insert(node);
            }
            Some(at) => self.arm(node, at),
            None => {}
        }
    }

    /// Records a node's deadline. Only one earlier than the armed one is
    /// pushed; a later one is picked up when the armed one surfaces and the
    /// node is stepped again.
    fn arm(&mut self, node: Node, at: Timestamp) {
        let earlier = self.armed.get(&node).is_none_or(|&armed| at < armed);
        if earlier {
            self.armed.insert(node, at);
            self.wakes.push(Wake { at, node });
        }
    }
}
