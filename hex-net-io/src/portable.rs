//! UDP through the standard library alone: one system call per datagram, and
//! arrival times taken when a datagram is read.
//!
//! For every platform other than Linux, and as the reference the Linux backend
//! is measured against. An endpoint on this backend is alone on its address:
//! only Linux spreads one address across sockets in a way that can be steered.

use std::{
    io::{self, ErrorKind},
    net::{SocketAddr, UdpSocket},
    sync::Arc,
    time::Duration,
};

use hex_net_core::time::{Clock, MonotonicClock};

use crate::{Received, Socket, Transmit, Wait, Wake, canonical, outgoing, reachable};

/// A nonblocking standard-library UDP socket.
pub struct PortableSocket {
    socket: UdpSocket,
    clock: MonotonicClock,
    local: SocketAddr,
}

impl PortableSocket {
    /// Binds to `addr`. `clock` stamps arrivals, so it must be a copy of the
    /// clock the driver is stepped with.
    pub fn bind(addr: SocketAddr, clock: MonotonicClock) -> io::Result<PortableSocket> {
        PortableSocket::from_std(UdpSocket::bind(addr)?, clock)
    }

    /// Takes over a socket already bound, and makes it nonblocking.
    pub fn from_std(socket: UdpSocket, clock: MonotonicClock) -> io::Result<PortableSocket> {
        socket.set_nonblocking(true)?;
        let local = canonical(socket.local_addr()?);
        Ok(PortableSocket { socket, clock, local })
    }
}

impl Socket for PortableSocket {
    fn recv_batch(&mut self, buffers: &mut [&mut [u8]], out: &mut [Received]) -> io::Result<usize> {
        let limit = buffers.len().min(out.len());
        let mut count = 0;

        while count < limit {
            match self.socket.recv_from(buffers[count]) {
                Ok((0, _)) => {}
                Ok((len, from)) => {
                    out[count] = Received { from: canonical(from), len, at: self.clock.now() };
                    count += 1;
                }
                Err(error) => match receive_error(&error) {
                    ReceiveError::Empty => break,
                    ReceiveError::Skip => {}
                    ReceiveError::Fatal => return Err(error),
                },
            }
        }
        Ok(count)
    }

    fn send_batch(&mut self, buffers: &[&[u8]], transmits: &[Transmit]) -> io::Result<usize> {
        let limit = buffers.len().min(transmits.len());
        let v6 = self.local.is_ipv6();
        let mut taken = 0;

        while taken < limit {
            let transmit = transmits[taken];
            let bytes = &buffers[taken][..transmit.len.min(buffers[taken].len())];
            match self.socket.send_to(bytes, outgoing(transmit.to, v6)) {
                Ok(_) => taken += 1,
                Err(err) if err.kind() == ErrorKind::Interrupted => {}
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(_) => taken += 1,
            }
        }
        Ok(taken)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

impl Wait for PortableSocket {
    type Waker = PortableWaker;

    /// The standard library cannot wait for readability on a nonblocking
    /// socket, so the socket blocks for the length of one peek with a read
    /// timeout, and goes back to nonblocking before anything reads it.
    fn wait(&self, timeout: Option<Duration>) -> io::Result<()> {
        if timeout == Some(Duration::ZERO) {
            return Ok(());
        }

        self.socket.set_read_timeout(timeout)?;
        self.socket.set_nonblocking(false)?;
        // Whatever the peek finds, including an error, is for the next receive
        // to deal with; timing out is the ordinary way for it to end.
        let _ = self.socket.peek_from(&mut [0u8; 1]);
        self.socket.set_nonblocking(true)
    }

    fn waker(&self) -> io::Result<PortableWaker> {
        let target = reachable(self.local);
        let unspecified: SocketAddr = match target {
            SocketAddr::V4(_) => (std::net::Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let socket = UdpSocket::bind(unspecified)?;
        Ok(PortableWaker { socket: Arc::new(socket), target })
    }
}

/// Wakes a `PortableSocket` by sending it an empty datagram, which ends the
/// wait's peek and is then discarded by the receive, since no packet of the
/// protocol is empty.
#[derive(Clone)]
pub struct PortableWaker {
    socket: Arc<UdpSocket>,
    target: SocketAddr,
}

impl Wake for PortableWaker {
    fn wake(&self) -> io::Result<()> {
        self.socket.send_to(&[], self.target).map(|_| ())
    }
}

enum ReceiveError {
    /// Nothing more is waiting.
    Empty,
    /// This datagram failed; the next may not.
    Skip,
    Fatal,
}

fn receive_error(error: &io::Error) -> ReceiveError {
    match error.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => ReceiveError::Empty,
        // An interrupted call read nothing and can simply be made again.
        ErrorKind::Interrupted => ReceiveError::Skip,
        // Windows reports an ICMP unreachable caused by an earlier send on the
        // next receive, as a reset.
        ErrorKind::ConnectionReset | ErrorKind::ConnectionRefused => ReceiveError::Skip,
        _ if datagram_too_long(error) => ReceiveError::Skip,
        _ => ReceiveError::Fatal,
    }
}

/// Windows fails a receive whose datagram was longer than the buffer, having
/// already discarded it. Elsewhere the datagram is silently truncated.
#[cfg(windows)]
fn datagram_too_long(error: &io::Error) -> bool {
    const WSAEMSGSIZE: i32 = 10040;
    error.raw_os_error() == Some(WSAEMSGSIZE)
}

#[cfg(not(windows))]
fn datagram_too_long(_: &io::Error) -> bool {
    false
}
