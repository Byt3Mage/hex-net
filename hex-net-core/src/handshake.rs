//! Establishing a connection without allocating for unverified senders.
//!
//! Two round trips. The server allocates nothing until a client has proven it
//! receives at the address it claims, and every handshake packet is padded so a
//! reply is never larger than the request.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::bits::{BitReader, BitWriter, ReadError, WriteError};
use crate::crypto::{self, Blob, Key, Keys};
use crate::fixed::FixedVec;
use crate::time::Timestamp;
use crate::wire::{HANDSHAKE_LEN, PROTOCOL_ID, handshake_blob};

/// How long a client has to return a cookie.
pub const COOKIE_LIFETIME: Duration = Duration::from_secs(10);

/// How long a disconnected player's session stays resumable.
pub const RESUME_GRACE: Duration = Duration::from_secs(45);

/// Resume tickets outlive the grace period, so one issued just before a drop is
/// still usable.
pub const RESUME_TICKET_LIFETIME: Duration = Duration::from_secs(180);

pub const MAX_USER_DATA: usize = 256;

/// Worst-case plaintext sizes.
pub const MAX_TICKET: usize = 128 + MAX_USER_DATA;
pub const MAX_COOKIE: usize = MAX_TICKET + 32;

const _: () = {
    // A change to MAX_USER_DATA fails the build rather than truncating a ticket
    // at runtime. The ticket's fixed part is 90 bytes; a cookie adds at most 25.
    assert!(MAX_TICKET >= (98 + MAX_USER_DATA));
    assert!(MAX_COOKIE >= (MAX_TICKET + 25));
    assert!(crate::crypto::MAX_BLOB >= (MAX_COOKIE + 28));
};

pub type UserData = FixedVec<u8, MAX_USER_DATA>;

/// A player's presence in the world, outliving any single connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub u64);

/// The client's credential: sealed by the backend for a new player, or by this
/// server for a resuming one. Opaque to the client.
#[derive(Clone, Copy)]
pub struct Ticket {
    pub expires_at: Timestamp,
    /// Unique per issued ticket. Lets the server recognise a retried handshake
    /// as the same one rather than accepting it twice.
    pub token_id: u64,
    pub client_id: u64,
    /// `None` for a new player; `Some` names the session being resumed.
    pub session: Option<SessionId>,
    pub keys: Keys,
    /// Passed through to the game untouched.
    pub user_data: UserData,
}

/// A cookie's contents, once opened.
#[derive(Clone, Copy)]
pub struct Cookie {
    pub issued_at: Timestamp,
    /// The address the cookie was issued to. A response from anywhere else is
    /// rejected, which is what proves the client receives where it claims.
    pub addr: SocketAddr,
    pub ticket: Ticket,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeError {
    /// Shorter than the required padding, so a reply could amplify.
    Undersized,
    /// Failed authentication, or was not a ticket at all.
    BadAuth,
    Expired,
    AddressMismatch,
    /// Names a session that has expired or is not suspended.
    NoSession,
    Malformed,
}

/// Sealing and opening of tickets and cookies.
///
/// Stateless apart from two keys. Expiry, session liveness, grace periods and
/// admission are the endpoint's decisions, since it holds the state they depend
/// on; this type answers only whether bytes are authentic.
pub struct Acceptor {
    /// Shared with the backend that issues tickets for new players.
    backend_key: Key,
    /// Known only to this server. Seals cookies and resume tickets.
    server_key: Key,
}

impl Acceptor {
    pub fn new(backend_key: Key) -> Self {
        Self { backend_key, server_key: crypto::generate_key() }
    }

    /// Opens a ticket from a connection request, sealed by either the backend or
    /// by this server. Which it was is visible in `Ticket::session`.
    pub fn decrypt_ticket(&self, packet: &[u8]) -> Result<Ticket, HandshakeError> {
        if packet.len() < HANDSHAKE_LEN {
            return Err(HandshakeError::Undersized);
        }

        let blob = handshake_blob(packet).ok_or(HandshakeError::Malformed)?;
        let aad = PROTOCOL_ID.to_le_bytes();

        let mut plain = [0u8; MAX_TICKET];
        let len = crypto::decrypt_blob(&self.backend_key, blob, &aad, &mut plain)
            .or_else(|_| crypto::decrypt_blob(&self.server_key, blob, &aad, &mut plain))
            .map_err(|_| HandshakeError::BadAuth)?;

        decode_ticket(&plain[..len])
    }

    /// Seals a cookie binding a ticket to the address that presented it.
    pub fn encrypt_cookie(
        &self,
        now: Timestamp,
        addr: SocketAddr,
        ticket: &Ticket,
        out: &mut [u8],
    ) -> Result<usize, HandshakeError> {
        let blob = encode_cookie(now, addr, ticket).map_err(|_| HandshakeError::Malformed)?;
        let aad = PROTOCOL_ID.to_le_bytes();
        crypto::encrypt_blob(&self.server_key, blob.as_slice(), &aad, out).map_err(|_| HandshakeError::Malformed)
    }

    /// Opens a cookie returned in a challenge response.
    pub fn decrypt_cookie(&self, packet: &[u8]) -> Result<Cookie, HandshakeError> {
        if packet.len() < HANDSHAKE_LEN {
            return Err(HandshakeError::Undersized);
        }
        let blob = handshake_blob(packet).ok_or(HandshakeError::Malformed)?;

        let mut plain = [0u8; MAX_COOKIE];
        let len = crypto::encrypt_blob(&self.server_key, blob, &PROTOCOL_ID.to_le_bytes(), &mut plain)
            .map_err(|_| HandshakeError::BadAuth)?;

        decode_cookie(&plain[..len])
    }

    /// Seals a resume ticket for a connected player.
    pub fn encrypt_resume_ticket(
        &self,
        now: Timestamp,
        mut ticket: Ticket,
        out: &mut [u8],
    ) -> Result<usize, HandshakeError> {
        ticket.expires_at = now.saturating_add(RESUME_TICKET_LIFETIME);
        encrypt_ticket(&self.server_key, &ticket, out)
    }
}

/// Seals a ticket. The backend calls this after authenticating a player; the
/// sealed bytes go to the client, which presents them unmodified.
pub fn encrypt_ticket(key: &Key, ticket: &Ticket, out: &mut [u8]) -> Result<usize, HandshakeError> {
    let mut plain = [0u8; MAX_TICKET];
    let len = encode_ticket(ticket, &mut plain).map_err(|_| HandshakeError::Malformed)?;
    let aad = PROTOCOL_ID.to_le_bytes();
    crypto::encrypt_blob(key, &plain[..len], &aad, out).map_err(|_| HandshakeError::Malformed)
}

/// Returns the length written. `out` must be at least MAX_TICKET bytes, which is
/// what makes the writes below infallible.
fn encode_ticket(t: &Ticket, out: &mut [u8; MAX_TICKET]) -> Result<usize, WriteError> {
    let mut w = BitWriter::new(out);

    w.write_u64(t.expires_at.as_nanos())?;
    w.write_u64(t.token_id)?;
    w.write_u64(t.client_id)?;
    w.write_bool(t.session.is_some())?;
    w.write_u64(t.session.unwrap_or_default().0)?;
    write_key(&mut w, &t.keys.client_to_server)?;
    write_key(&mut w, &t.keys.server_to_client)?;

    w.write_range(t.user_data.len() as u32, 0, MAX_USER_DATA as u32)?;
    w.align()?;
    w.write_bytes(&t.user_data)?;

    Ok(w.finish())
}

fn decode_ticket(bytes: &[u8]) -> Result<Ticket, HandshakeError> {
    fn read(bytes: &[u8]) -> Result<Ticket, ReadError> {
        let mut r = BitReader::new(bytes);

        let expires_at = Timestamp::from_nanos(r.read_u64()?);
        let token_id = r.read_u64()?;
        let client_id = r.read_u64()?;
        let has_session = r.read_bool()?;
        let session_id = r.read_u64()?;
        let client_to_server = read_key(&mut r)?;
        let server_to_client = read_key(&mut r)?;

        let n = r.read_range(0, MAX_USER_DATA as u32)? as usize;
        r.align()?;
        let payload = r.peek_bytes(n).ok_or(ReadError::Eof)?;
        r.skip_bytes(n)?;
        let user_data = UserData::from_slice(payload).ok_or(ReadError::OutOfRange)?;

        Ok(Ticket {
            expires_at,
            token_id,
            client_id,
            session: has_session.then_some(SessionId(session_id)),
            keys: Keys { client_to_server, server_to_client },
            user_data,
        })
    }
    read(bytes).map_err(|_| HandshakeError::Malformed)
}

/// Layout: issued_at, address family, address, port, ticket.
fn encode_cookie(now: Timestamp, addr: SocketAddr, ticket: &Ticket) -> Result<Blob<MAX_COOKIE>, WriteError> {
    let mut data = [0u8; MAX_COOKIE];
    data[0..8].copy_from_slice(&now.as_nanos().to_le_bytes());

    let mut len = 9;
    match addr.ip() {
        IpAddr::V4(ip) => {
            data[8] = 4;
            data[len..len + 4].copy_from_slice(&ip.octets());
            len += 4;
        }
        IpAddr::V6(ip) => {
            data[8] = 6;
            data[len..len + 16].copy_from_slice(&ip.octets());
            len += 16;
        }
    }

    data[len..len + 2].copy_from_slice(&addr.port().to_le_bytes());
    len += 2;

    let plain = data[len..len + MAX_TICKET]
        .as_mut_array()
        .ok_or(WriteError::OutOfRange)?;

    len += encode_ticket(ticket, plain)?;

    Ok(Blob { data, len })
}

fn decode_cookie(bytes: &[u8]) -> Result<Cookie, HandshakeError> {
    let slice = |from: usize, to: usize| bytes.get(from..to).ok_or(HandshakeError::Malformed);

    let issued = u64::from_le_bytes(slice(0, 8)?.try_into().expect("checked length"));

    let (ip, mut at): (IpAddr, usize) = match *bytes.get(8).ok_or(HandshakeError::Malformed)? {
        4 => {
            let octets: [u8; 4] = slice(9, 13)?.try_into().expect("checked length");
            (IpAddr::V4(Ipv4Addr::from(octets)), 13)
        }
        6 => {
            let octets: [u8; 16] = slice(9, 25)?.try_into().expect("checked length");
            (IpAddr::V6(Ipv6Addr::from(octets)), 25)
        }
        _ => return Err(HandshakeError::Malformed),
    };

    let port = u16::from_le_bytes(slice(at, at + 2)?.try_into().expect("checked length"));
    at += 2;

    let ticket = decode_ticket(bytes.get(at..).ok_or(HandshakeError::Malformed)?)?;

    Ok(Cookie {
        issued_at: Timestamp::from_nanos(issued),
        addr: SocketAddr::new(ip, port),
        ticket,
    })
}

#[inline]
fn write_key(w: &mut BitWriter, key: &Key) -> Result<(), WriteError> {
    for byte in key {
        w.write_bits(*byte as u32, 8)?
    }
    Ok(())
}

#[inline]
fn read_key(r: &mut BitReader) -> Result<Key, ReadError> {
    let mut key = [0u8; 32];
    for byte in key.iter_mut() {
        *byte = r.read_bits(8)? as u8;
    }
    Ok(key)
}
