//! Packet layout: a cleartext header, then an encrypted payload of frames.

use crate::{
    bits::{BitReader, BitWriter, ReadError, WriteError},
    seq::WireSequence,
};

pub use crate::crypto::TAG_LEN;

/// Largest datagram sent. Stays under the common 1500-byte path MTU after IPv6
/// and UDP headers with room for tunnels, so no router fragments it.
pub const MAX_DATAGRAM: usize = 1200;

/// Handshake packets are padded to this length, so a reply is never larger than
/// the packet that prompted it.
pub const HANDSHAKE_LEN: usize = 1200;

/// Game and wire-protocol revision. Used as AEAD associated data when sealing
/// tickets and cookies, so a mismatch fails authentication.
pub const PROTOCOL_ID: u64 = 0x_4E45_544C_4942_0001;

/// Offset of the blob inside a handshake packet: kind and length.
pub const HANDSHAKE_BODY_OFFSET: usize = 3;

/// Chosen at random by a client for each connection attempt, and carried by
/// every request that attempt sends, retries included.
///
/// Both sides mix it into the connection's keys, which is what ties a
/// connection to the handshake that created it rather than merely to the
/// session keys, which a backend might hand out more than once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClientNonce(pub u64);

impl ClientNonce {
    pub const LEN: usize = 8;

    /// A fresh nonce from the operating system's generator.
    pub fn random() -> ClientNonce {
        let mut bytes = [0u8; Self::LEN];
        getrandom::fill(&mut bytes).expect("OS randomness unavailable");
        ClientNonce(u64::from_le_bytes(bytes))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketKind {
    /// Encrypted, carrying frames. Everything after the handshake.
    Payload = 0,
    /// A ticket, from a new or resuming client. Cleartext, padded.
    Request = 1,
    /// The server's cookie. Cleartext, padded.
    Challenge = 2,
    /// The cookie echoed back. Cleartext, padded.
    Response = 3,
}

impl PacketKind {
    #[inline]
    fn from_bits(bits: u8) -> Option<PacketKind> {
        match bits {
            0 => Some(PacketKind::Payload),
            1 => Some(PacketKind::Request),
            2 => Some(PacketKind::Challenge),
            3 => Some(PacketKind::Response),
            _ => None,
        }
    }

    /// Reads the kind from a raw first byte, for routing before the header is
    /// parsed.
    #[inline]
    pub fn from_byte(byte: u8) -> Option<PacketKind> {
        Self::from_bits(byte & flags::KIND_MASK)
    }
}

/// Server-assigned, unique per connection.
///
/// Survives NAT rebinding, and forms half of every AEAD nonce, so it must not
/// be reused while a session's keys are live.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId(pub u32);

mod flags {
    pub const KIND_MASK: u8 = 0b0000_0011;
    pub const ACK: u8 = 0b0000_0100;
    pub const ACK_BITS: u8 = 0b000_1000;
    /// Must be zero, so future versions can define them and older builds reject
    /// rather than misread packets that use them.
    pub const RESERVED: u8 = 0b1111_0000;
}

/// Cleartext header of a payload packet, authenticated as AEAD associated data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: PacketKind,
    pub conn_id: ConnectionId,
    pub sequence: WireSequence,
    /// Newest sequence received from the peer.
    pub ack: Option<WireSequence>,
    /// How long the peer held this acknowledgement, in 250us units, so the
    /// sender can subtract its tick delay from the RTT sample.
    pub ack_delay: u8,
    /// Bit i set means (ack - 1 - i) was received.
    pub ack_bits: u32,
}

impl Header {
    pub const MAX_LEN: usize = 14;

    /// Writes the header. The bytes written become the AEAD associated data.
    pub fn encode(&self, out: &mut [u8; MAX_DATAGRAM]) -> usize {
        const { assert!(Self::MAX_LEN < MAX_DATAGRAM) };

        // encode packet kind
        let mut flags = self.kind as u8;

        // encode connection id
        out[1..5].copy_from_slice(&self.conn_id.0.to_le_bytes());
        let mut at = 5;

        // encode wire sequence
        out[at..at + 2].copy_from_slice(&self.sequence.0.to_le_bytes());
        at += 2;

        if let Some(ack) = self.ack {
            flags |= flags::ACK;

            // encode ack
            out[at..at + 2].copy_from_slice(&ack.0.to_le_bytes());
            at += 2;

            // encode ack delay
            out[at] = self.ack_delay;
            at += 1;

            // encode ackbits
            if self.ack_bits != 0 {
                flags |= flags::ACK_BITS;

                out[at..at + 4].copy_from_slice(&self.ack_bits.to_le_bytes());
                at += 4;
            }
        }

        // write flags now.
        out[0] = flags;

        // total length used
        at
    }

    /// Parses a header from untrusted bytes. Every failure is an error.
    pub fn decode(input: &[u8]) -> Result<(Header, usize), ReadError> {
        let &first = input.first().ok_or(ReadError::Eof)?;
        if (first & flags::RESERVED) != 0 {
            return Err(ReadError::OutOfRange);
        }

        let kind = PacketKind::from_bits(first & flags::KIND_MASK).ok_or(ReadError::OutOfRange)?;
        let conn_id = ConnectionId(u32::from_le_bytes(read_array(input, 1)?));

        let mut at = 5;

        let sequence = WireSequence(u16::from_le_bytes(read_array(input, at)?));
        at += 2;

        let mut ack = None;
        let mut ack_delay = 0;
        let mut ack_bits = 0;
        if (first & flags::ACK) != 0 {
            ack = Some(WireSequence(u16::from_le_bytes(read_array(input, at)?)));
            at += 2;

            ack_delay = *input.get(at).ok_or(ReadError::Eof)?;
            at += 1;

            if (first & flags::ACK_BITS) != 0 {
                ack_bits = u32::from_le_bytes(read_array(input, at)?);
                at += 4;
            }
        } else if (first & flags::ACK_BITS) != 0 {
            // History without an acknowledgement has no meaning.
            return Err(ReadError::OutOfRange);
        }

        Ok((Header { kind, conn_id, sequence, ack, ack_delay, ack_bits }, at))
    }
}

/// Builds a handshake packet: kind, length, blob, zero padding.
pub fn encode_handshake(kind: PacketKind, blob: &[u8], out: &mut [u8]) -> Result<usize, WriteError> {
    let end = HANDSHAKE_BODY_OFFSET + blob.len();
    if (out.len() < HANDSHAKE_LEN) || (end > HANDSHAKE_LEN) {
        return Err(WriteError::Overflow);
    }
    out[0] = kind as u8;
    out[1..3].copy_from_slice(&(blob.len() as u16).to_le_bytes());
    out[HANDSHAKE_BODY_OFFSET..end].copy_from_slice(blob);
    out[end..HANDSHAKE_LEN].fill(0);
    Ok(HANDSHAKE_LEN)
}

/// The blob inside a handshake packet.
pub fn handshake_blob(packet: &[u8]) -> Option<&[u8]> {
    let len = u16::from_le_bytes(packet.get(1..3)?.try_into().ok()?) as usize;
    packet.get(HANDSHAKE_BODY_OFFSET..HANDSHAKE_BODY_OFFSET + len)
}

/// Frames a request (ticket, the attempt's nonce, padding).
///
/// The nonce rides in the clear. Tampering with it only makes the keys the
/// two sides derive disagree, so the handshake fails. It cannot make either
/// side accept a connection it did not ask for.
pub fn encode_request(ticket: &[u8], nonce: ClientNonce, out: &mut [u8]) -> Result<usize, WriteError> {
    let at = HANDSHAKE_BODY_OFFSET + ticket.len();
    if (at + ClientNonce::LEN) > HANDSHAKE_LEN {
        return Err(WriteError::Overflow);
    }
    let len = encode_handshake(PacketKind::Request, ticket, out)?;
    out[at..(at + ClientNonce::LEN)].copy_from_slice(&nonce.0.to_le_bytes());
    Ok(len)
}

/// The nonce a request carries after its ticket.
pub fn request_nonce(packet: &[u8]) -> Option<ClientNonce> {
    let at = HANDSHAKE_BODY_OFFSET + handshake_blob(packet)?.len();
    let bytes = packet.get(at..(at + ClientNonce::LEN))?;
    Some(ClientNonce(u64::from_le_bytes(bytes.try_into().ok()?)))
}

#[inline]
fn read_array<const N: usize>(input: &[u8], at: usize) -> Result<[u8; N], ReadError> {
    let end = at + N;
    if end > input.len() {
        return Err(ReadError::Eof);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&input[at..end]);
    Ok(out)
}

/// Contents of an encrypted payload, written bit-packed in priority order until
/// the packet is full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    /// Fills the rest of the packet. Always last.
    Padding = 0,
    /// Keepalive, close, path validation, resume ticket delivery.
    Control = 1,
    TimeSync = 2,
    /// One whole message on a channel.
    Message = 3,
    /// One piece of a message too large for a packet.
    Fragment = 4,
    Replication = 5,
}

impl FrameKind {
    pub const BITS: u32 = 3;

    #[inline]
    pub fn from_bits(bits: u32) -> Option<FrameKind> {
        match bits {
            0 => Some(FrameKind::Padding),
            1 => Some(FrameKind::Control),
            2 => Some(FrameKind::TimeSync),
            3 => Some(FrameKind::Message),
            4 => Some(FrameKind::Fragment),
            5 => Some(FrameKind::Replication),
            _ => None,
        }
    }

    #[inline]
    pub fn write(self, w: &mut BitWriter) -> Result<(), WriteError> {
        w.write_bits(self as u32, Self::BITS)
    }

    #[inline]
    pub fn read(r: &mut BitReader) -> Result<FrameKind, ReadError> {
        FrameKind::from_bits(r.read_bits(Self::BITS)?).ok_or(ReadError::OutOfRange)
    }
}

/// Contents of a Control frame.
///
/// One numbering shared by both directions, since both sides must agree on the
/// bits. Each role accepts only the subset it can legitimately receive; a frame
/// only the opposite side sends is a protocol violation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ControlKind {
    /// Empty. Makes a keepalive ack-eliciting, so it yields an RTT sample and
    /// confirms the path still carries traffic. Either direction.
    Ping = 0,
    /// Carries a CloseReason. Either direction.
    Close = 1,
    /// Server to client: prove you receive at this address by echoing the token.
    PathChallenge = 2,
    /// Client to server: the echo.
    PathResponse = 3,
    /// Server to client: a sealed ticket for resuming this session.
    ResumeTicket = 4,
    /// Server to client: this connection is established. Carries nothing; the
    /// fact that it decrypted is the proof.
    Accepted = 5,
}

impl ControlKind {
    pub const BITS: u32 = 3;

    #[inline]
    pub fn from_bits(bits: u32) -> Option<ControlKind> {
        match bits {
            0 => Some(ControlKind::Ping),
            1 => Some(ControlKind::Close),
            2 => Some(ControlKind::PathChallenge),
            3 => Some(ControlKind::PathResponse),
            4 => Some(ControlKind::ResumeTicket),
            5 => Some(ControlKind::Accepted),
            _ => None,
        }
    }

    #[inline]
    pub fn write(self, w: &mut BitWriter) -> Result<(), WriteError> {
        w.write_bits(self as u32, Self::BITS)
    }

    #[inline]
    pub fn read(r: &mut BitReader) -> Result<ControlKind, ReadError> {
        ControlKind::from_bits(r.read_bits(Self::BITS)?).ok_or(ReadError::OutOfRange)
    }
}
