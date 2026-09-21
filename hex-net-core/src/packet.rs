//! The cryptographic and sequencing layer of a connection.

use core::range::Range;

use crate::{
    crypto::{Cipher, CryptoError, Key, TAG_LEN},
    seq::{ReceiveWindow, Sequence, WindowError, WireSequence},
    time::Timestamp,
    wire::{ConnectionId, Header, MAX_DATAGRAM, PacketKind},
};

/// A sealed datagram: the sequence it went out under and its length.
///
/// Only `encrypt` builds one, so the sequence is the one actually used for
/// the nonce and the length is bounded by `MAX_DATAGRAM`.
#[derive(Clone, Copy, Debug)]
pub struct Sealed {
    sequence: Sequence,
    len: u16,
}

impl Sealed {
    #[inline]
    pub fn sequence(&self) -> Sequence {
        self.sequence
    }

    /// Datagram length in bytes, header and tag included.
    #[inline]
    pub fn datagram_len(&self) -> u16 {
        self.len
    }
}
/// What the outgoing header reports about received traffic.
#[derive(Clone, Copy, Debug)]
pub struct AckState {
    /// Newest ack-eliciting sequence received.
    pub newest: Sequence,
    /// Bit i set means (newest - 1 - i) was received.
    pub bits: u32,
    /// When `newest` arrived, so the header can report how long it was held.
    pub received_at: Timestamp,
}

/// A claim on the next outgoing sequence.
///
/// `encrypt` consumes it, so the sequence written into the header and the one
/// used for the nonce are necessarily the same. Dropping it unused leaves the
/// counter untouched, which is what an abandoned packet needs.
pub struct SequenceTicket(Sequence);

impl SequenceTicket {
    #[inline]
    pub fn sequence(&self) -> Sequence {
        self.0
    }
}

/// A datagram-sized buffer.
///
/// Sizing it in the type removes the length check every entry point would
/// otherwise need, and lets `begin` hand out a body range that provably fits.
pub type Packet = [u8; MAX_DATAGRAM];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecryptError {
    /// The header did not parse, or was not a payload packet.
    Malformed,
    Replay(WindowError),
    Unauthenticated,
}

/// A decrypted packet.
#[derive(Clone, Debug)]
pub struct Decrypted {
    pub sequence: Sequence,
    pub header: Header,
    /// Byte range of the plaintext body within the caller's buffer.
    pub body: Range<usize>,
}

/// Holds both ciphers, the send counter, and the two receive windows.
///
/// A received sequence is checked against the window before decryption and
/// committed only after it authenticates. A send sequence is consumed only when
/// a packet is actually sealed, so an abandoned packet leaves no gap.
pub struct PacketCrypto {
    tx: Cipher,
    rx: Cipher,
    next_sequence: Sequence,
    /// Every received sequence. Guards against replay and reusing a
    /// nonce, so it must record packets of every kind.
    replay: ReceiveWindow,
    /// Received sequences that should be acknowledged.
    ///
    /// Separate from the replay window because a peer does not acknowledge
    /// packets that carry only acknowledgements, and so does not track them.
    acked: ReceiveWindow,
    /// When `acked`'s newest entry arrived. The reported delay must describe
    /// the packet the acknowledgement names, not whichever arrived first.
    newest_acked_at: Timestamp,
}

impl PacketCrypto {
    /// `conn_id` forms half of every nonce, so a resumed session may reuse its
    /// keys under a newly assigned id.
    pub fn new(conn_id: ConnectionId, tx_key: &Key, rx_key: &Key) -> Self {
        Self {
            tx: Cipher::new(tx_key, conn_id.0),
            rx: Cipher::new(rx_key, conn_id.0),
            next_sequence: Sequence::FIRST,
            replay: ReceiveWindow::default(),
            acked: ReceiveWindow::default(),
            newest_acked_at: Timestamp::ZERO,
        }
    }

    #[inline]
    pub fn next_sequence(&self) -> SequenceTicket {
        SequenceTicket(self.next_sequence)
    }

    /// What the outgoing header should acknowledge, or `None` before any
    /// ack-eliciting packet has arrived.
    #[inline]
    pub fn ack_state(&self) -> Option<AckState> {
        Some(AckState {
            newest: self.acked.newest()?,
            bits: self.acked.ack_bits(),
            received_at: self.newest_acked_at,
        })
    }

    /// Records a received packet as worth acknowledging. Called once the frames
    /// have been read and the packet is known to carry more than acknowledgements.
    #[inline]
    pub fn record_eliciting(&mut self, sequence: Sequence, now: Timestamp) {
        if self.acked.newest().is_none_or(|n| sequence > n) {
            self.newest_acked_at = now;
        }
        self.acked.insert(sequence);
    }

    /// Writes `header` and returns the writable body range, which excludes the
    /// space `encrypt` needs for the tag.
    pub fn begin(&self, header: &Header, buf: &mut Packet) -> core::ops::Range<usize> {
        header.encode(buf)..(MAX_DATAGRAM - TAG_LEN)
    }

    /// Parses, checks, and decrypts one datagram in place.
    ///
    /// The sequence reaches the replay window only once the packet has
    /// authenticated: committing earlier would let one forged packet claiming a
    /// far-future sequence advance the window past all genuine traffic.
    pub fn decrypt(&mut self, buf: &mut Packet, len: usize) -> Result<Decrypted, DecryptError> {
        let (header, header_len) = Header::decode(&buf[..len]).map_err(|_| DecryptError::Malformed)?;
        if header.kind != PacketKind::Payload {
            return Err(DecryptError::Malformed);
        }

        let sequence = Sequence::resolve(self.replay.newest(), header.sequence).ok_or(DecryptError::Malformed)?;
        self.replay.check(sequence).map_err(DecryptError::Replay)?;

        let body_len = self
            .rx
            .decrypt(sequence.get(), buf, header_len, len)
            .map_err(|_: CryptoError| DecryptError::Unauthenticated)?;

        self.replay.insert(sequence);

        Ok(Decrypted {
            sequence,
            header,
            body: (header_len..(header_len + body_len)).into(),
        })
    }

    /// Encrypts the body in place and appends the tag, consuming `ticket` and
    /// with it the sequence number.
    pub fn encrypt(
        &mut self,
        ticket: SequenceTicket,
        buf: &mut Packet,
        header_len: usize,
        body_end: usize,
    ) -> Result<Sealed, CryptoError> {
        const { assert!(MAX_DATAGRAM <= (u16::MAX as usize)) };
        let len = self.tx.encrypt(ticket.0.get(), buf, header_len, body_end)?;
        self.next_sequence = ticket.0.next();
        Ok(Sealed { sequence: ticket.0, len: len as u16 })
    }

    /// Resolves a peer's acknowledgement, rejecting anything ahead of our own
    /// counter: a peer cannot acknowledge a packet that was never sent.
    pub fn resolve_ack(&self, wire: WireSequence) -> Option<Sequence> {
        let newest_sent = self.next_sequence.checked_sub(1)?;
        Sequence::resolve(Some(newest_sent), wire).filter(|&ack| ack <= newest_sent)
    }
}
