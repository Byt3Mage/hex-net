//! Establishing a connection without allocating for unverified senders.
//!
//! Two round trips. The server allocates nothing until a client has proven it
//! receives at the address it claims, and every handshake packet is padded so a
//! reply is never larger than the request.

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use crate::{
    bits::{BitReader, BitWriter, ReadError, WriteError},
    crypto::{self, Key, Keys, MAX_BLOB, NONCE_LEN},
    fixed::FixedVec,
    shard::{SHARD_BITS, Shard, ShardCount, ShardId},
    time::Timestamp,
    wire::{ClientNonce, HANDSHAKE_LEN, PROTOCOL_ID, ServerNonce, handshake_blob},
};

/// How long a client has to return a cookie.
pub const COOKIE_LIFETIME: Duration = Duration::from_secs(10);

/// How long a disconnected player's session stays resumable.
pub const RESUME_GRACE: Duration = Duration::from_secs(45);

/// Resume tickets outlive the grace period, so one issued just before a drop is
/// still usable.
pub const RESUME_TICKET_LIFETIME: Duration = Duration::from_secs(180);

pub const MAX_USER_DATA: usize = 256;

/// Worst-case plaintext sizes.
pub const MAX_TICKET: usize = MAX_USER_DATA + 128;
pub const MAX_COOKIE: usize = MAX_TICKET + 56;

const _: () = {
    // A change to MAX_USER_DATA fails the build rather than truncating a ticket
    // at runtime. The ticket's fixed part is 90 bytes. A cookie prefixes at
    // most 27 for an IPv6 address with its family tag and port, then both
    // sides' nonces and the ticket's identity. Sealed, it gains a nonce and a
    assert!(MAX_TICKET >= (MAX_USER_DATA + 90));
    assert!(MAX_COOKIE >= (MAX_TICKET + 27 + ClientNonce::LEN + ServerNonce::LEN + TicketId::LEN));
    assert!(MAX_BLOB >= (MAX_COOKIE + NONCE_LEN + crypto::TAG_LEN + 1));
};

/// An encrypted ticket as it travels. It is opaque to the client, presented
/// unmodified. The same type carries a backend-issued connect ticket and a
/// server-issued resume ticket, which differ only in who sealed them.
pub type EncryptedTicket = FixedVec<u8, MAX_BLOB>;

pub type UserData = FixedVec<u8, MAX_USER_DATA>;

/// A player's presence in the world, outliving any single connection.
/// The low `SHARD_BITS` name the shard holding it, so a ticket resuming it can
/// be sent to that shard without anyone looking the session up.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub u64);

impl SessionId {
    /// The session numbered `sequence` among those `shard` creates.
    #[inline]
    pub const fn new(sequence: u64, shard: ShardId) -> SessionId {
        SessionId((sequence << SHARD_BITS) | (shard.to_byte() as u64))
    }

    /// The shard holding this session.
    #[inline]
    pub const fn shard(self) -> ShardId {
        ShardId::from_byte((self.0 & ((1 << SHARD_BITS) - 1)) as u8)
    }
}

/// A sealed ticket's identity from the random nonce it was sealed under.
///
/// Every sealing draws a fresh one, so two sealed tickets never share an
/// identity, whatever their contents. That is what lets a ticket be spent
/// exactly once without the backend having to number its tickets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TicketId(pub [u8; NONCE_LEN]);

impl TicketId {
    pub const LEN: usize = NONCE_LEN;

    pub fn of_request(packet: &[u8]) -> Option<Self> {
        let blob = handshake_blob(packet)?;
        let nonce = blob.get(..Self::LEN)?;
        Some(Self(nonce.try_into().ok()?))
    }
}

/// The client's credential: sealed by the backend for a new player, or by this
/// server for a resuming one. Opaque to the client.
#[derive(Debug, Clone, Copy)]
pub struct Ticket {
    pub expires_at: Timestamp,
    pub client_id: u64,
    /// `None` for a new player; `Some` names the session being resumed.
    pub session: Option<SessionId>,
    pub keys: Keys,
    /// Passed through to the game untouched.
    pub user_data: UserData,
}

impl Ticket {
    /// The part of ticket policy any shard can judge.
    #[inline]
    pub fn check_expiry(&self, now: Timestamp) -> Result<(), HandshakeError> {
        if now > self.expires_at {
            return Err(HandshakeError::Expired);
        }
        Ok(())
    }
}

/// A cookie's contents, once opened.
#[derive(Clone, Copy)]
pub struct Cookie {
    /// The shard that must complete this handshake. Travels in the clear
    /// ahead of the sealed cookie, so it can be routed on, and is
    /// authenticated with it, so it cannot be redirected.
    pub home: ShardId,
    pub issued_at: Timestamp,
    /// The address the cookie was issued to. A response from anywhere else is
    /// rejected, which is what proves the client receives where it claims.
    pub addr: SocketAddr,
    /// The nonce the client's request carried. Sealed here, so the server
    /// derives the connection's keys from what the client actually sent.
    pub nonce: ClientNonce,
    /// The nonce the server chose for the challenge carrying this cookie.
    /// Sealed here, so the server derives the connection's keys from what it
    /// chose, whatever the cleartext copy arrived as.
    pub server_nonce: ServerNonce,
    /// Which sealed ticket the request presented, so the response spends that
    /// one and no other.
    pub ticket_id: TicketId,
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
    /// Already produced a connection. A ticket is good for one.
    Spent,
    Malformed,
}

/// Sealing and opening of tickets and cookies.
///
/// Stateless apart from two keys and the size of the group it serves.
/// Expiry, session liveness, grace periods and admission are the endpoint's
/// decisions, since it holds the state they depend on; this type answers only
/// whether bytes are authentic, and which shard they belong to.
pub struct Acceptor {
    /// Shared with the backend that issues tickets for new players.
    backend_key: Key,
    /// Known only to this server's shards. Seals cookies and resume tickets.
    server_key: Key,
    shards: ShardCount,
}

impl Acceptor {
    /// An acceptor for an endpoint alone on its address, with a server key of
    /// its own.
    pub fn new(backend_key: Key) -> Self {
        Self {
            backend_key,
            server_key: crypto::generate_key(),
            shards: ShardCount::ONE,
        }
    }
    /// An acceptor for one member of a group, sharing the group's server key
    /// so any member can open what any other sealed.
    pub fn for_shard(backend_key: Key, shard: &Shard) -> Self {
        Self {
            backend_key,
            server_key: *shard.server_key(),
            shards: shard.count(),
        }
    }

    /// The shard that must complete a handshake presenting `ticket`, or `None`
    /// when the session it names cannot exist in this group.
    #[inline]
    pub fn home(&self, ticket: &Ticket, ticket_id: TicketId) -> Option<ShardId> {
        self.shards.home(ticket.session, ticket_id)
    }

    /// Decrypts a ticket from a connection request, encrypted by either the backend or
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
    /// behind the byte naming the shard that must open it.
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt_cookie(
        &self,
        now: Timestamp,
        addr: SocketAddr,
        nonce: ClientNonce,
        server_nonce: ServerNonce,
        ticket_id: TicketId,
        ticket: &Ticket,
        out: &mut [u8],
    ) -> Result<usize, HandshakeError> {
        let home = self.home(ticket, ticket_id).ok_or(HandshakeError::NoSession)?;
        let (first, sealed) = out.split_first_mut().ok_or(HandshakeError::Malformed)?;
        let mut plain = [0u8; MAX_COOKIE];
        let len = encode_cookie(now, addr, nonce, server_nonce, ticket_id, ticket, &mut plain)
            .map_err(|_| HandshakeError::Malformed)?;
        let sealed_len = crypto::encrypt_blob(&self.server_key, &plain[..len], &cookie_aad(home), sealed)
            .map_err(|_| HandshakeError::Malformed)?;

        *first = home.to_byte();
        Ok(1 + sealed_len)
    }

    /// Opens a cookie returned in a challenge response.
    pub fn decrypt_cookie(&self, packet: &[u8]) -> Result<Cookie, HandshakeError> {
        if packet.len() < HANDSHAKE_LEN {
            return Err(HandshakeError::Undersized);
        }
        let blob = handshake_blob(packet).ok_or(HandshakeError::Malformed)?;
        let (&home, sealed) = blob.split_first().ok_or(HandshakeError::Malformed)?;
        let home = ShardId::from_byte(home);

        let mut plain = [0u8; MAX_COOKIE];
        let len = crypto::decrypt_blob(&self.server_key, sealed, &cookie_aad(home), &mut plain)
            .map_err(|_| HandshakeError::BadAuth)?;

        decode_cookie(home, &plain[..len])
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

/// Associated data for a sealed cookie: the protocol, and the shard it is
/// addressed to, so the cleartext routing byte cannot be altered.
fn cookie_aad(home: ShardId) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[..8].copy_from_slice(&PROTOCOL_ID.to_le_bytes());
    aad[8] = home.to_byte();
    aad
}

/// Seals a ticket. The backend calls this after authenticating a player; the
/// sealed bytes go to the client, which presents them unmodified.
pub fn encrypt_ticket(key: &Key, ticket: &Ticket, out: &mut [u8]) -> Result<usize, HandshakeError> {
    let mut plain = [0u8; MAX_TICKET];
    let len = encode_ticket(ticket, &mut plain).map_err(|_| HandshakeError::Malformed)?;
    let aad = PROTOCOL_ID.to_le_bytes();
    crypto::encrypt_blob(key, &plain[..len], &aad, out).map_err(|_| HandshakeError::Malformed)
}

/// Returns the length written. `out` must be at least MAX_TICKET bytes.
fn encode_ticket(t: &Ticket, out: &mut [u8; MAX_TICKET]) -> Result<usize, WriteError> {
    let mut w = BitWriter::new(out);

    w.write_u64(t.expires_at.as_nanos())?;
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
            client_id,
            session: has_session.then_some(SessionId(session_id)),
            keys: Keys { client_to_server, server_to_client },
            user_data,
        })
    }
    read(bytes).map_err(|_| HandshakeError::Malformed)
}

/// Layout: `[issued_at | address family | address | port | client nonce | server nonce | ticket_id | ticket]`
fn encode_cookie(
    now: Timestamp,
    addr: SocketAddr,
    nonce: ClientNonce,
    server_nonce: ServerNonce,
    ticket_id: TicketId,
    ticket: &Ticket,
    out: &mut [u8; MAX_COOKIE],
) -> Result<usize, WriteError> {
    out[0..8].copy_from_slice(&now.as_nanos().to_le_bytes());

    let mut at = match addr.ip() {
        IpAddr::V4(ip) => {
            out[8] = 4;
            out[9..13].copy_from_slice(&ip.octets());
            13
        }
        IpAddr::V6(ip) => {
            out[8] = 6;
            out[9..25].copy_from_slice(&ip.octets());
            25
        }
    };

    out[at..at + 2].copy_from_slice(&addr.port().to_le_bytes());
    at += 2;

    out[at..at + ClientNonce::LEN].copy_from_slice(&nonce.0.to_le_bytes());
    at += ClientNonce::LEN;

    out[at..at + ServerNonce::LEN].copy_from_slice(&server_nonce.0.to_le_bytes());
    at += ServerNonce::LEN;

    out[at..at + TicketId::LEN].copy_from_slice(&ticket_id.0);
    at += TicketId::LEN;

    let plain = out[at..at + MAX_TICKET].as_mut_array().ok_or(WriteError::OutOfRange)?;
    at += encode_ticket(ticket, plain)?;

    Ok(at)
}

fn decode_cookie(home: ShardId, bytes: &[u8]) -> Result<Cookie, HandshakeError> {
    let slice = |range| bytes.get(range).ok_or(HandshakeError::Malformed);
    let issued = u64::from_le_bytes(slice(0..8)?.try_into().expect("checked length"));

    let (ip, mut at) = match *bytes.get(8).ok_or(HandshakeError::Malformed)? {
        4 => {
            let octets: [u8; 4] = slice(9..13)?.try_into().expect("checked length");
            (IpAddr::from(octets), 13)
        }
        6 => {
            let octets: [u8; 16] = slice(9..25)?.try_into().expect("checked length");
            (IpAddr::from(octets), 25)
        }
        _ => return Err(HandshakeError::Malformed),
    };

    let port = u16::from_le_bytes(slice(at..at + 2)?.try_into().expect("checked length"));
    at += 2;

    let nonce = u64::from_le_bytes(slice(at..at + ClientNonce::LEN)?.try_into().expect("checked length"));
    at += ClientNonce::LEN;

    let server_nonce = u64::from_le_bytes(slice(at..at + ServerNonce::LEN)?.try_into().expect("checked length"));
    at += ServerNonce::LEN;

    let ticket_id = slice(at..at + TicketId::LEN)?.try_into().expect("checked length");
    at += TicketId::LEN;

    let ticket = decode_ticket(slice(at..bytes.len())?)?;

    Ok(Cookie {
        home,
        issued_at: Timestamp::from_nanos(issued),
        addr: SocketAddr::new(ip, port),
        nonce: ClientNonce(nonce),
        server_nonce: ServerNonce(server_nonce),
        ticket_id: TicketId(ticket_id),
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
