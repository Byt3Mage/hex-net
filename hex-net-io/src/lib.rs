use std::{io, net::SocketAddr};

use hex_net_core::time::Timestamp;

pub mod driver;
mod pool;

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
pub trait Socket {
    /// Fill `buffers` with received datagrams. Returns how many were filled.
    /// Never blocks, so zero means nothing was waiting.
    ///
    /// `buffers` and `out` must be the same length; `out[i]` describes what
    /// landed in `buffers[i]`.
    fn recv_batch(&mut self, buffers: &mut [&mut [u8]], out: &mut [Received]) -> io::Result<usize>;

    /// Send datagrams. Returns how many were sent. A short count is normal when
    /// the send buffer is full. The caller decides whether to retry or drop.
    fn send_batch(&mut self, buffers: &[&[u8]], transmits: &[Transmit]) -> io::Result<usize>;

    /// The address this socket is bound to.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}
