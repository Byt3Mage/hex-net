//! The cryptographic and sequencing layer of a connection.

use core::range::Range;

use crate::crypto::{Cipher, CryptoError, Key, TAG_LEN};
use crate::seq::{self, ReceiveWindow, Sequence, WindowError, WireSequence};
use crate::wire::{ConnectionId, Header, MAX_DATAGRAM, PacketKind};

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
    /// Every received sequence. Guards against replay and against reusing a
    /// nonce, so it must record packets of every kind.
    replay: ReceiveWindow,
    /// Received sequences worth acknowledging.
    ///
    /// Separate from the replay window because a peer does not acknowledge
    /// packets that carry only acknowledgements, and so does not track them.
    /// Reporting one as the newest received would name a packet the peer has no
    /// record of, which costs it every round-trip sample.
    acked: ReceiveWindow,
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
        }
    }

    #[inline]
    pub fn next_sequence(&self) -> Sequence {
        self.next_sequence
    }

    /// The newest sequence worth acknowledging, for the outgoing header.
    #[inline]
    pub fn newest_acknowledged(&self) -> Sequence {
        self.acked.newest()
    }

    #[inline]
    pub fn ack_bits(&self) -> u32 {
        self.acked.ack_bits()
    }

    /// Records a received packet as worth acknowledging. Called once the frames
    /// have been read and the packet is known to carry more than acknowledgements.
    #[inline]
    pub fn record_eliciting(&mut self, sequence: Sequence) {
        self.acked.insert(sequence);
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

        let sequence = seq::reconstruct(self.replay.newest(), header.sequence).ok_or(DecryptError::Malformed)?;
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

    /// Writes `header` and returns the writable body range, which excludes the
    /// space `seal` needs for the tag.
    pub fn begin(&self, header: &Header, buf: &mut [u8; MAX_DATAGRAM]) -> Option<Range<usize>> {
        let header_len = header.encode(buf).ok()?;
        Some((header_len..(MAX_DATAGRAM - TAG_LEN)).into())
    }

    /// Encrypts the body in place and appends the tag, consuming the sequence
    /// number. Returns the sequence the packet carried and the datagram length.
    pub fn encrypt(
        &mut self,
        buf: &mut Packet,
        header_len: usize,
        body_end: usize,
    ) -> Result<(Sequence, usize), CryptoError> {
        let sequence = self.next_sequence;
        let len = self.tx.encrypt(sequence.get(), buf, header_len, body_end)?;
        self.next_sequence = sequence.next();
        Ok((sequence, len))
    }

    /// Resolves a peer's acknowledgement, rejecting anything ahead of our own
    /// counter: a peer cannot acknowledge a packet that was never sent.
    pub fn resolve_ack(&self, wire: WireSequence) -> Option<Sequence> {
        let newest_sent = self.next_sequence.saturating_sub(1);
        let ack = seq::reconstruct(newest_sent, wire)?;
        (ack <= newest_sent).then_some(ack)
    }
}
