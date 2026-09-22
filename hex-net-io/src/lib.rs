//! The transport over real sockets: batched UDP backends, the driver that
//! joins one to the sans-IO core, and the loop that waits between steps.
//!
//! Two backends implement `Socket`. `portable::PortableSocket` runs anywhere
//! the standard library has UDP. `linux::LinuxSocket` moves a batch per system
//! call, stamps each datagram with the kernel's arrival time, and binds the
//! groups that let one address be served by an endpoint per core.

use std::{
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use hex_net_core::time::Timestamp;

pub mod driver;
pub mod portable;
pub mod run;

#[cfg(target_os = "linux")]
pub mod linux;

/// One received datagram: where it came from, how much data, and when the
/// kernel saw it.
#[derive(Clone, Copy, Debug)]
pub struct Received {
    pub from: SocketAddr,
    pub len: usize,
    /// When the packet actually arrived, from the kernel where available.
    /// Using this instead of "when we got round to reading it" keeps our own
    /// scheduling delay out of every RTT sample.
    pub at: Timestamp,
}

/// One datagram to send.
#[derive(Clone, Copy, Debug)]
pub struct Transmit {
    pub to: SocketAddr,
    pub len: usize,
}

/// A UDP socket, batched. Implemented by the portable backend, the Linux
/// backend, and the simulator.
///
/// Batching is in the trait rather than bolted on because a server at 300k
/// packets per second cannot afford a syscall each way per packet, and a
/// backend that can only do one at a time implements the batch as a loop.
///
/// Addresses are always canonical: an IPv4 peer reached through a dual-stack
/// socket appears as IPv4, and is written as IPv4 when sending.
pub trait Socket {
    /// Fill `buffers` with received datagrams. Returns how many were filled.
    /// Never blocks, so zero means nothing was waiting.
    ///
    /// `buffers` and `out` must be the same length; `out[i]` describes what
    /// landed in `buffers[i]`. Datagrams that cannot be ours are consumed
    /// without being reported: empty ones, and ones too long for their buffer
    /// where the platform says so. Where it does not, the truncated bytes are
    /// reported and fail authentication in the transport.
    fn recv_batch(&mut self, buffers: &mut [&mut [u8]], out: &mut [Received]) -> io::Result<usize>;

    /// Send datagrams, in order. Returns how many were taken from the front.
    ///
    /// A short count means the send buffer is full; the caller decides whether
    /// to retry or drop the rest. A datagram the operating system refuses for
    /// reasons of its own, such as an unreachable destination, counts as
    /// taken: to the transport that is loss on the path, which it recovers
    /// from. An error means the socket itself has failed.
    fn send_batch(&mut self, buffers: &[&[u8]], transmits: &[Transmit]) -> io::Result<usize>;

    /// The address this socket is bound to.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// A socket that can block until it may have something to read.
pub trait Wait {
    /// Interrupts a `wait` in progress, or makes the next one return at once.
    type Waker: Wake + Clone + Send + Sync + 'static;

    /// Blocks until a datagram may be waiting, the waker is woken, or
    /// `timeout` passes. `None` waits without limit. Returning is only a hint:
    /// the caller steps and finds out what, if anything, arrived.
    fn wait(&self, timeout: Option<Duration>) -> io::Result<()>;

    /// Blocks until the waker is woken or `timeout` passes, whatever arrives
    /// on the socket meanwhile. Returns whether a wake arrived, consuming it.
    ///
    /// Lets a loop gather datagrams in the kernel between steps, so each
    /// step's system calls are shared by a larger batch.
    fn park(&self, timeout: Duration) -> io::Result<bool>;

    /// A handle that wakes this socket's waits from any thread.
    fn waker(&self) -> io::Result<Self::Waker>;
}

/// Wakes a waiting loop.
pub trait Wake {
    fn wake(&self) -> io::Result<()>;
}

/// The address as the transport sees it: IPv4 peers of a dual-stack socket
/// arrive as IPv4-mapped IPv6, and are handed on as plain IPv4.
#[inline]
pub(crate) fn canonical(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => addr,
        },
        SocketAddr::V4(_) => addr,
    }
}

/// The address to hand the operating system for `to`: an IPv6 socket reaches
/// an IPv4 peer through its mapped form.
#[inline]
pub(crate) fn outgoing(to: SocketAddr, local_is_v6: bool) -> SocketAddr {
    match to {
        SocketAddr::V4(v4) if local_is_v6 => SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
        _ => to,
    }
}

/// Where a waker aimed at a socket bound to `local` should send: the socket's
/// own address, with an unspecified IP replaced by loopback.
#[inline]
pub(crate) fn reachable(local: SocketAddr) -> SocketAddr {
    let ip = match local.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, local.port())
}
