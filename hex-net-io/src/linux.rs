//! UDP on Linux: a batch per system call each way, arrival times from the
//! kernel, and groups of sockets on one address steered to their shards by
//! the kernel.
//!
//! Every `unsafe` block here is a system call, or the construction of a value
//! the call reads, and says what the call is given. Addresses and control
//! messages are encoded and parsed as bytes, in safe code, against the kernel's
//! fixed layouts.
//!
//! Segmentation offload is deliberately absent. `UDP_SEGMENT` and `UDP_GRO`
//! pay off for runs of equal-sized datagrams to or from one peer, and the
//! transport never produces those: a drain builds at most one packet per
//! connection, a client sends at most one per step, and a player's packets
//! arrive a tick apart. Receive offload would also force 64 KiB receive
//! buffers and a copy out of them for every datagram.

use std::{
    fs::File,
    io::{self, ErrorKind, Read, Write},
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    ptr,
    sync::Arc,
    time::{Duration, SystemTime},
};

use hex_net_core::{
    shard::{SHARD_BITS, Shard, ShardGroup},
    time::{Clock, MonotonicClock, Span, Timestamp},
    wire::{HANDSHAKE_BODY_OFFSET, HANDSHAKE_LEN, MIN_PAYLOAD_HEADER, PacketKind, SHARD_OFFSET, flags::KIND_MASK},
};

use crate::{Received, Socket, Transmit, Wait, Wake, canonical, outgoing};

/// Datagrams moved per system call. A driver batch is smaller; this bounds the
/// arrays built on the stack for each call.
const MAX_BATCH: usize = 64;

/// Room for one socket address: `sockaddr_in6` is the largest the socket can
/// report.
const NAME_LEN: usize = 28;

/// Room for the control messages one datagram can carry: a timestamp.
const CONTROL_LEN: usize = 64;

/// The kernel's `cmsghdr`: a `size_t` length, then level and type.
const WORD: usize = mem::size_of::<usize>();
const CMSG_HEADER: usize = WORD + 8;
const _: () = assert!(mem::size_of::<libc::cmsghdr>() == CMSG_HEADER);

/// The steering program reads the shard as one byte of the connection id and
/// one byte ahead of the cookie.
const _: () = assert!(SHARD_BITS == 8);

/// Sizes asked of the kernel for each socket's buffers. A server of a thousand
/// players emits a thousand datagrams in a burst each tick, which the default
/// send buffer of roughly 200 KiB cannot hold. The kernel caps each at
/// `net.core.rmem_max` and `net.core.wmem_max`.
#[derive(Clone, Copy, Debug)]
pub struct SocketOptions {
    pub recv_buffer: usize,
    pub send_buffer: usize,
}

impl Default for SocketOptions {
    fn default() -> Self {
        Self { recv_buffer: 4 << 20, send_buffer: 4 << 20 }
    }
}

/// Storage the kernel writes a peer's address into, or reads one from.
#[derive(Clone, Copy)]
#[repr(C, align(8))]
struct Name([u8; NAME_LEN]);

/// Storage the kernel writes a datagram's control messages into.
#[derive(Clone, Copy)]
#[repr(C, align(8))]
struct Control([u8; CONTROL_LEN]);

/// A nonblocking UDP socket driven with `recvmmsg` and `sendmmsg`.
pub struct LinuxSocket {
    socket: UdpSocket,
    local: SocketAddr,
    clock: MonotonicClock,
    /// Readable whenever a waker has fired since the last wait.
    event: Arc<File>,
    names: Box<[Name; MAX_BATCH]>,
    controls: Box<[Control; MAX_BATCH]>,
    /// Keeps every socket of this one's group open while any member lives, so
    /// the group's order never changes and steering stays correct.
    _group: Option<Arc<Anchor>>,
}

impl LinuxSocket {
    /// Binds a socket alone on `addr`. `clock` stamps arrivals, so it must be
    /// a copy of the clock the driver is stepped with.
    pub fn bind(addr: SocketAddr, clock: MonotonicClock, options: SocketOptions) -> io::Result<LinuxSocket> {
        LinuxSocket::new(open(addr, options, false)?, clock, None)
    }

    fn new(socket: UdpSocket, clock: MonotonicClock, group: Option<Arc<Anchor>>) -> io::Result<LinuxSocket> {
        Ok(LinuxSocket {
            local: canonical(socket.local_addr()?),
            socket,
            clock,
            event: Arc::new(event_fd()?),
            names: Box::new([Name([0; NAME_LEN]); MAX_BATCH]),
            controls: Box::new([Control([0; CONTROL_LEN]); MAX_BATCH]),
            _group: group,
        })
    }
}

/// Binds one socket per member of `group` on `addr`, and has the kernel steer
/// each datagram to the member that owns it.
///
/// The sockets share the address through `SO_REUSEPORT`. A classic BPF
/// program attached to the group reads the owning shard from the cleartext a
/// datagram begins with, by the rule `wire::owner_shard` states: the
/// connection id of a payload packet, the byte ahead of the cookie in a
/// challenge response. Anything else, a request among it, is spread by the
/// kernel's hash of the source, since any member can answer it.
///
/// The program returns a position in the group, which is the order the
/// sockets were bound in, so member `i` is bound `i`-th. A member leaving the
/// group would shift the others, so every socket keeps all of them open.
///
/// With a port of zero the first socket's port is used for the rest.
pub fn bind_group(
    addr: SocketAddr,
    group: &ShardGroup,
    clock: MonotonicClock,
    options: SocketOptions,
) -> io::Result<Vec<(Shard, LinuxSocket)>> {
    let mut addr = addr;
    let mut sockets = Vec::with_capacity(group.count().get());
    for _ in group.shards() {
        let socket = open(addr, options, true)?;
        addr.set_port(socket.local_addr()?.port());
        sockets.push(socket);
    }

    attach_steering(&sockets[0])?;

    let anchor = Arc::new(Anchor {
        _members: sockets.iter().map(UdpSocket::try_clone).collect::<io::Result<_>>()?,
    });

    group
        .shards()
        .zip(sockets)
        .map(|(shard, socket)| Ok((shard, LinuxSocket::new(socket, clock, Some(Arc::clone(&anchor)))?)))
        .collect()
}

/// Duplicates of a group's sockets.
struct Anchor {
    _members: Vec<UdpSocket>,
}

impl Socket for LinuxSocket {
    fn recv_batch(&mut self, buffers: &mut [&mut [u8]], out: &mut [Received]) -> io::Result<usize> {
        let limit = buffers.len().min(out.len()).min(MAX_BATCH);
        if limit == 0 {
            return Ok(0);
        }

        loop {
            let mut iov = [libc::iovec { iov_base: ptr::null_mut(), iov_len: 0 }; MAX_BATCH];
            let mut msgs = [empty_mmsghdr(); MAX_BATCH];
            for index in 0..limit {
                iov[index] = libc::iovec {
                    iov_base: buffers[index].as_mut_ptr().cast(),
                    iov_len: buffers[index].len(),
                };
                let header = &mut msgs[index].msg_hdr;
                header.msg_name = self.names[index].0.as_mut_ptr().cast();
                header.msg_namelen = NAME_LEN as libc::socklen_t;
                header.msg_iov = &raw mut iov[index];
                header.msg_iovlen = 1;
                header.msg_control = self.controls[index].0.as_mut_ptr().cast();
                header.msg_controllen = CONTROL_LEN as _;
            }

            // SAFETY: `msgs[..limit]` each describe one iovec over a distinct
            // caller buffer, a name buffer of NAME_LEN bytes and a control
            // buffer of CONTROL_LEN bytes, all of which outlive the call and are
            // not otherwise accessed during it. A null timeout means none.
            let received = unsafe {
                libc::recvmmsg(
                    self.socket.as_raw_fd(),
                    msgs.as_mut_ptr(),
                    limit as libc::c_uint,
                    libc::MSG_DONTWAIT,
                    ptr::null_mut(),
                )
            };
            if received < 0 {
                let error = io::Error::last_os_error();
                match error.kind() {
                    ErrorKind::WouldBlock => return Ok(0),
                    ErrorKind::Interrupted => continue,
                    _ => return Err(error),
                }
            }

            let received = received as usize;
            let now = self.clock.now();
            let wall = SystemTime::now();
            let mut count = 0;

            for index in 0..received {
                let header = &msgs[index].msg_hdr;
                let len = msgs[index].msg_len as usize;
                if (len == 0) || ((header.msg_flags & libc::MSG_TRUNC) != 0) {
                    continue;
                }
                let Some(from) = decode_name(&self.names[index], header.msg_namelen as usize) else { continue };
                let control = &self.controls[index].0[..header.msg_controllen.min(CONTROL_LEN)];
                let at = arrival(control, now, wall);

                // A skipped datagram leaves a gap; later ones move down so that
                // `out[i]` keeps describing `buffers[i]`.
                if count < index {
                    let (head, tail) = buffers.split_at_mut(index);
                    let Some(target) = head[count].get_mut(..len) else { continue };
                    target.copy_from_slice(&tail[0][..len]);
                }
                out[count] = Received { from: canonical(from), len, at };
                count += 1;
            }

            if (count > 0) || (received < limit) {
                return Ok(count);
            }
        }
    }

    fn send_batch(&mut self, buffers: &[&[u8]], transmits: &[Transmit]) -> io::Result<usize> {
        let limit = buffers.len().min(transmits.len());
        let v6 = self.local.is_ipv6();
        let mut taken = 0;

        while taken < limit {
            let chunk = (limit - taken).min(MAX_BATCH);
            let mut iov = [libc::iovec { iov_base: ptr::null_mut(), iov_len: 0 }; MAX_BATCH];
            let mut msgs = [empty_mmsghdr(); MAX_BATCH];
            for index in 0..chunk {
                let transmit = transmits[taken + index];
                let bytes = buffers[taken + index];
                let bytes = &bytes[..transmit.len.min(bytes.len())];
                iov[index] = libc::iovec {
                    iov_base: bytes.as_ptr().cast_mut().cast(),
                    iov_len: bytes.len(),
                };

                let name_len = encode_name(outgoing(transmit.to, v6), &mut self.names[index]);
                let header = &mut msgs[index].msg_hdr;
                header.msg_name = self.names[index].0.as_mut_ptr().cast();
                header.msg_namelen = name_len;
                header.msg_iov = &raw mut iov[index];
                header.msg_iovlen = 1;
            }

            // SAFETY: `msgs[..chunk]` each describe one iovec over caller bytes,
            // which the kernel only reads, and a name buffer holding an encoded
            // address of the length given. All outlive the call.
            let sent = unsafe {
                libc::sendmmsg(
                    self.socket.as_raw_fd(),
                    msgs.as_mut_ptr(),
                    chunk as libc::c_uint,
                    libc::MSG_DONTWAIT,
                )
            };
            if sent >= 0 {
                taken += sent as usize;
                continue;
            }

            let error = io::Error::last_os_error();
            match error.kind() {
                ErrorKind::WouldBlock => return Ok(taken),
                ErrorKind::Interrupted => {}
                _ if error.raw_os_error() == Some(libc::ENOBUFS) => return Ok(taken),
                // Refused for this destination alone: the datagram is gone,
                // and the rest may still go.
                _ => taken += 1,
            }
        }
        Ok(taken)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

impl Wait for LinuxSocket {
    type Waker = LinuxWaker;

    fn wait(&self, timeout: Option<Duration>) -> io::Result<()> {
        let mut fds = [
            libc::pollfd {
                fd: self.socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.event.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let limit = timeout.map(|timeout| libc::timespec {
            tv_sec: libc::time_t::try_from(timeout.as_secs()).unwrap_or(libc::time_t::MAX),
            tv_nsec: timeout.subsec_nanos() as libc::c_long,
        });
        let limit = limit.as_ref().map_or(ptr::null(), ptr::from_ref);

        // SAFETY: `fds` is two initialised pollfd, the count given. `limit` is
        // null or points at a timespec that outlives the call. A null signal
        // mask leaves the thread's mask as it is.
        let ready = unsafe { libc::ppoll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, limit, ptr::null()) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == ErrorKind::Interrupted { Ok(()) } else { Err(error) };
        }

        if (fds[1].revents & libc::POLLIN) != 0 {
            let mut count = [0u8; 8];
            match (&*self.event).read(&mut count) {
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn park(&self, timeout: Duration) -> io::Result<bool> {
        let mut fds = [libc::pollfd {
            fd: self.event.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        let limit = libc::timespec {
            tv_sec: libc::time_t::try_from(timeout.as_secs()).unwrap_or(libc::time_t::MAX),
            tv_nsec: timeout.subsec_nanos() as libc::c_long,
        };

        // SAFETY: `fds` is one initialised pollfd, the count given. `limit`
        // outlives the call. A null signal mask leaves the thread's mask as it
        // is.
        let ready = unsafe {
            libc::ppoll(
                fds.as_mut_ptr(),
                fds.len() as libc::nfds_t,
                &raw const limit,
                ptr::null(),
            )
        };
        if ready < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == ErrorKind::Interrupted { Ok(false) } else { Err(error) };
        }
        if (fds[0].revents & libc::POLLIN) == 0 {
            return Ok(false);
        }

        let mut count = [0u8; 8];
        match (&*self.event).read(&mut count) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn waker(&self) -> io::Result<LinuxWaker> {
        Ok(LinuxWaker(Arc::clone(&self.event)))
    }
}

/// Wakes a `LinuxSocket`'s wait through its eventfd.
#[derive(Clone)]
pub struct LinuxWaker(Arc<File>);

impl Wake for LinuxWaker {
    fn wake(&self) -> io::Result<()> {
        match (&*self.0).write(&1u64.to_ne_bytes()) {
            Ok(_) => Ok(()),
            // The counter is saturated, so a wake is already pending.
            Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// Opens a nonblocking UDP socket with kernel receive timestamps and the
/// requested buffers, and binds it.
fn open(addr: SocketAddr, options: SocketOptions, reuse_port: bool) -> io::Result<UdpSocket> {
    let domain = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };

    // SAFETY: no pointers are passed. A nonnegative result is a new descriptor
    // owned by nothing else, which `OwnedFd` then owns.
    let fd = unsafe {
        let fd = libc::socket(
            domain,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::IPPROTO_UDP,
        );
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        OwnedFd::from_raw_fd(fd)
    };

    set_option(&fd, libc::SOL_SOCKET, libc::SO_TIMESTAMPNS, 1)?;
    set_option(
        &fd,
        libc::SOL_SOCKET,
        libc::SO_RCVBUF,
        clamp_to_int(options.recv_buffer),
    )?;
    set_option(
        &fd,
        libc::SOL_SOCKET,
        libc::SO_SNDBUF,
        clamp_to_int(options.send_buffer),
    )?;
    if reuse_port {
        set_option(&fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1)?;
    }

    let mut name = Name([0; NAME_LEN]);
    let len = encode_name(addr, &mut name);
    // SAFETY: `name` holds an encoded address of `len` bytes and outlives the
    // call.
    let bound = unsafe { libc::bind(fd.as_raw_fd(), name.0.as_ptr().cast(), len) };
    if bound < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(UdpSocket::from(fd))
}

fn set_option(fd: &OwnedFd, level: libc::c_int, option: libc::c_int, value: libc::c_int) -> io::Result<()> {
    // SAFETY: the pointer and length describe `value`, which outlives the call.
    let result = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            option,
            (&raw const value).cast(),
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn clamp_to_int(size: usize) -> libc::c_int {
    libc::c_int::try_from(size).unwrap_or(libc::c_int::MAX)
}

/// A nonblocking eventfd, as a file so it is read and written safely.
fn event_fd() -> io::Result<File> {
    // SAFETY: no pointers are passed. A nonnegative result is a new descriptor
    // owned by nothing else, which `File` then owns.
    unsafe {
        let fd = libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(File::from_raw_fd(fd))
    }
}

/// A message header with no name, buffers or control space, for the batch
/// calls to fill in.
fn empty_mmsghdr() -> libc::mmsghdr {
    // SAFETY: `mmsghdr` is plain data, and all zeroes is a valid value of it:
    // null pointers and zero lengths. It is built this way because some libc
    // targets give `msghdr` private padding fields that a literal cannot name.
    unsafe { mem::zeroed() }
}

/// Attaches the steering program to the group `socket` belongs to.
fn attach_steering(socket: &UdpSocket) -> io::Result<()> {
    let mut program = steering_program();
    let fprog = libc::sock_fprog {
        len: program.len() as libc::c_ushort,
        filter: program.as_mut_ptr(),
    };

    // SAFETY: `fprog` describes `program`, both of which outlive the call; the
    // kernel copies the program before returning.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_REUSEPORT_CBPF,
            (&raw const fprog).cast(),
            mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Returned to let the kernel pick a member by hashing the source: any value
/// past the end of the group does that.
const ANY_MEMBER: u32 = u32::MAX;

/// Classic BPF selecting the group member that owns a datagram. Offsets are
/// from the start of the UDP payload.
///
/// ```text
///  0  A = length
///  1  if A >= MIN_PAYLOAD_HEADER goto 2 else goto 12
///  2  A = byte[0]
///  3  A &= kind mask
///  4  if A == Payload goto 6 else goto 5
///  5  if A == Response goto 8 else goto 12
///  6  A = byte[SHARD_OFFSET]                  the connection id's shard
///  7  return A
///  8  A = length
///  9  if A >= HANDSHAKE_LEN goto 10 else goto 12
/// 10  A = byte[HANDSHAKE_BODY_OFFSET]         the cookie's home
/// 11  return A
/// 12  return ANY_MEMBER
/// ```
fn steering_program() -> [libc::sock_filter; 13] {
    const LD_LEN: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_LEN) as u16;
    const LD_BYTE: u16 = (libc::BPF_LD | libc::BPF_B | libc::BPF_ABS) as u16;
    const AND: u16 = (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as u16;
    const JGE: u16 = (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16;
    const JEQ: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    const RET_A: u16 = (libc::BPF_RET | BPF_A) as u16;
    const RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
    const BPF_A: u32 = 0x10;

    const fn op(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    [
        op(LD_LEN, 0, 0, 0),
        op(JGE, 0, 10, MIN_PAYLOAD_HEADER as u32),
        op(LD_BYTE, 0, 0, 0),
        op(AND, 0, 0, KIND_MASK as u32),
        op(JEQ, 1, 0, PacketKind::Payload as u32),
        op(JEQ, 2, 6, PacketKind::Response as u32),
        op(LD_BYTE, 0, 0, SHARD_OFFSET as u32),
        op(RET_A, 0, 0, 0),
        op(LD_LEN, 0, 0, 0),
        op(JGE, 0, 2, HANDSHAKE_LEN as u32),
        op(LD_BYTE, 0, 0, HANDSHAKE_BODY_OFFSET as u32),
        op(RET_A, 0, 0, 0),
        op(RET_K, 0, 0, ANY_MEMBER),
    ]
}

/// Writes `addr` as a `sockaddr_in` or `sockaddr_in6`. Returns its length.
fn encode_name(addr: SocketAddr, name: &mut Name) -> libc::socklen_t {
    let bytes = &mut name.0;
    match addr {
        SocketAddr::V4(v4) => {
            bytes[0..2].copy_from_slice(&(libc::AF_INET as libc::sa_family_t).to_ne_bytes());
            bytes[2..4].copy_from_slice(&v4.port().to_be_bytes());
            bytes[4..8].copy_from_slice(&v4.ip().octets());
            bytes[8..16].fill(0);
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(v6) => {
            bytes[0..2].copy_from_slice(&(libc::AF_INET6 as libc::sa_family_t).to_ne_bytes());
            bytes[2..4].copy_from_slice(&v6.port().to_be_bytes());
            bytes[4..8].copy_from_slice(&v6.flowinfo().to_be_bytes());
            bytes[8..24].copy_from_slice(&v6.ip().octets());
            bytes[24..28].copy_from_slice(&v6.scope_id().to_ne_bytes());
            mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    }
}

/// Reads the address the kernel wrote. `None` for a family this socket cannot
/// have received from.
fn decode_name(name: &Name, len: usize) -> Option<SocketAddr> {
    let bytes = name.0.get(..len)?;
    let family = libc::sa_family_t::from_ne_bytes(bytes.get(0..2)?.try_into().ok()?);
    let port = u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?);
    match libc::c_int::from(family) {
        libc::AF_INET => {
            let octets: [u8; 4] = bytes.get(4..8)?.try_into().ok()?;
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        libc::AF_INET6 => {
            let flowinfo = u32::from_be_bytes(bytes.get(4..8)?.try_into().ok()?);
            let octets: [u8; 16] = bytes.get(8..24)?.try_into().ok()?;
            let scope = u32::from_ne_bytes(bytes.get(24..28)?.try_into().ok()?);
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                port,
                flowinfo,
                scope,
            )))
        }
        _ => None,
    }
}

/// When a datagram reached the kernel, on the monotonic timeline.
///
/// The kernel stamps arrivals with the wall clock, so the stamp's age is
/// measured against the wall clock now and subtracted from the monotonic time
/// now. A stamp in the future, which a wall clock stepped backwards produces,
/// counts as arriving now.
fn arrival(control: &[u8], now: Timestamp, wall: SystemTime) -> Timestamp {
    match kernel_stamp(control) {
        // A stamp from before the monotonic clock's origin, or a wall clock
        // that has stepped, leaves the datagram older than the clock can
        // express. Reading it as now costs one scheduling delay in an RTT
        // sample; reading it as an underflow would put arrival in the far
        // future and stop the connection ever timing out.
        Some(stamp) => {
            let age = Span::from_duration(wall.duration_since(stamp).unwrap_or(Duration::ZERO));
            now.checked_sub(age).unwrap_or(now)
        }
        None => now,
    }
}

/// The `SCM_TIMESTAMPNS` among a datagram's control messages.
fn kernel_stamp(control: &[u8]) -> Option<SystemTime> {
    let mut at = 0;
    while (at + CMSG_HEADER) <= control.len() {
        let len = usize::from_ne_bytes(control[at..(at + WORD)].try_into().ok()?);
        let level = i32::from_ne_bytes(control[(at + WORD)..(at + WORD + 4)].try_into().ok()?);
        let kind = i32::from_ne_bytes(control[(at + WORD + 4)..(at + CMSG_HEADER)].try_into().ok()?);
        if len < CMSG_HEADER {
            return None;
        }
        let data = control.get((at + cmsg_align(CMSG_HEADER))..(at + len))?;
        if (level == libc::SOL_SOCKET) && (kind == libc::SCM_TIMESTAMPNS) {
            return timespec(data);
        }
        at += cmsg_align(len);
    }
    None
}

#[inline]
const fn cmsg_align(len: usize) -> usize {
    (len + (WORD - 1)) & !(WORD - 1)
}

/// A `timespec` as the kernel wrote it: two 64-bit fields, or two 32-bit ones
/// on targets whose time is still 32 bits wide.
fn timespec(data: &[u8]) -> Option<SystemTime> {
    let (seconds, nanos) = match data.len() {
        16 => (
            i64::from_ne_bytes(data[0..8].try_into().ok()?),
            i64::from_ne_bytes(data[8..16].try_into().ok()?),
        ),
        8 => (
            i64::from(i32::from_ne_bytes(data[0..4].try_into().ok()?)),
            i64::from(i32::from_ne_bytes(data[4..8].try_into().ok()?)),
        ),
        _ => return None,
    };
    let seconds = u64::try_from(seconds).ok()?;
    let nanos = u32::try_from(nanos).ok().filter(|&nanos| nanos < 1_000_000_000)?;
    SystemTime::UNIX_EPOCH.checked_add(Duration::new(seconds, nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_survive_the_kernel_layout() {
        for text in ["10.1.2.3:40000", "[2001:db8::7]:9", "[::ffff:10.1.2.3]:1", "0.0.0.0:0"] {
            let addr: SocketAddr = text.parse().expect("literal address");
            let mut name = Name([0xAA; NAME_LEN]);
            let len = encode_name(addr, &mut name);
            assert_eq!(decode_name(&name, len as usize), Some(addr), "{text}");
        }
    }

    #[test]
    fn a_timestamp_is_found_among_control_messages() {
        let mut control = [0u8; CONTROL_LEN];
        let first = CMSG_HEADER + 4;
        control[..WORD].copy_from_slice(&first.to_ne_bytes());
        control[WORD..(WORD + 4)].copy_from_slice(&libc::IPPROTO_IP.to_ne_bytes());
        let second = cmsg_align(first);
        control[second..(second + WORD)].copy_from_slice(&(CMSG_HEADER + 16).to_ne_bytes());
        control[(second + WORD)..(second + WORD + 4)].copy_from_slice(&libc::SOL_SOCKET.to_ne_bytes());
        control[(second + WORD + 4)..(second + CMSG_HEADER)].copy_from_slice(&libc::SCM_TIMESTAMPNS.to_ne_bytes());
        let data = second + cmsg_align(CMSG_HEADER);
        control[data..(data + 8)].copy_from_slice(&1_700_000_000i64.to_ne_bytes());
        control[(data + 8)..(data + 16)].copy_from_slice(&250_000_000i64.to_ne_bytes());

        let stamp = kernel_stamp(&control[..(data + 16)]).expect("the timestamp is found");
        assert_eq!(
            stamp.duration_since(SystemTime::UNIX_EPOCH).expect("after the epoch"),
            Duration::new(1_700_000_000, 250_000_000)
        );
    }

    #[test]
    fn an_arrival_is_placed_its_age_before_now() {
        let wall = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let now = Timestamp::from_nanos(5_000_000_000);
        let mut control = [0u8; CMSG_HEADER + 16];
        control[..WORD].copy_from_slice(&(CMSG_HEADER + 16).to_ne_bytes());
        control[WORD..(WORD + 4)].copy_from_slice(&libc::SOL_SOCKET.to_ne_bytes());
        control[(WORD + 4)..CMSG_HEADER].copy_from_slice(&libc::SCM_TIMESTAMPNS.to_ne_bytes());
        control[CMSG_HEADER..(CMSG_HEADER + 8)].copy_from_slice(&999i64.to_ne_bytes());
        control[(CMSG_HEADER + 8)..].copy_from_slice(&750_000_000i64.to_ne_bytes());

        assert_eq!(arrival(&control, now, wall), Timestamp::from_nanos(4_750_000_000));
        assert_eq!(arrival(&[], now, wall), now, "no stamp means now");
    }
}
