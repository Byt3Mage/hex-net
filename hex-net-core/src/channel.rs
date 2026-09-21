//! Delivery guarantees, chosen per message.
//!
//! Each channel is independent: a retransmit on one never holds up another, so
//! head-of-line blocking applies only where a channel asked for it.

use crate::{
    arena::{Arena, MessageRef},
    bits::{BitReader, BitWriter, ReadError, WriteError, bits_required},
    fixed::FixedVec,
    seq::{self, WireSequence},
    wire::FrameKind,
};

/// Width of a message id on the wire.
const MESSAGE_ID_BITS: u32 = 16;

/// Bits in a message frame's fields: kind, channel, id, and length.
const MESSAGE_FRAME_BITS: u32 =
    FrameKind::BITS + bits_required((MAX_CHANNELS - 1) as u32) + MESSAGE_ID_BITS + bits_required(MAX_MESSAGE as u32);

/// Worst-case bytes a message frame adds to its payload. Its fields plus up to
/// seven bits of alignment before the payload, since a frame can start
/// anywhere within a byte.
pub const MESSAGE_FRAME_OVERHEAD: usize = (MESSAGE_FRAME_BITS as usize + 7).div_ceil(8);

/// Largest message carried whole. Longer payloads are fragmented before
/// reaching a channel.
pub const MAX_MESSAGE: usize = 1024;

/// Channels a connection may have. Both peers must agree on the set and its
/// order, since a channel travels as its index.
pub const MAX_CHANNELS: usize = 8;

/// Payload storage per direction, in 64-byte blocks.
///
/// Sized by bytes outstanding (bandwidth x round trip) with headroom for
/// the application to queue ahead. 4 KB against a 2 KB working set.
const ARENA_BLOCKS: usize = 64;

/// Unacknowledged messages tracked across all channels.
///
/// The receive side's hold list matches this, and both directions use equal
/// arenas, so a peer cannot have more outstanding than we can hold. That makes
/// the hold list's capacity a consequence of the send window rather than a
/// guess, and means it cannot overflow.
const MAX_PENDING: usize = 64;

/// Out-of-order messages held across all channels.
const MAX_HELD: usize = MAX_PENDING;

/// Messages recorded per packet. A packet reaching this cap simply carries
/// fewer; the remainder goes in the next one.
const MAX_MESSAGES_PER_PACKET: usize = 8;

/// Called with each delivered message, during the call that received it.
///
/// The payload borrows the packet buffer it arrived in, so no storage is
/// involved on the common path.
pub type OnMessage<'a> = &'a mut dyn FnMut(u8, &[u8]);

/// A message's position within its channel.
///
/// Distinct from a packet sequence: one message can travel in several packets
/// across retransmits, and each channel numbers its own.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct MessageId(u32);

impl MessageId {
    pub const FIRST: MessageId = MessageId(0);

    #[inline]
    pub const fn get(self) -> u32 {
        self.0
    }

    #[inline]
    pub fn next(self) -> MessageId {
        MessageId(self.0.wrapping_add(1))
    }

    #[inline]
    pub const fn to_wire(self) -> WireSequence {
        WireSequence(self.0 as u16)
    }

    /// Resolved against a reference both sides track, as packet sequences are.
    #[inline]
    pub fn from_wire(reference: MessageId, wire: WireSequence) -> Option<MessageId> {
        let full = seq::reconstruct(u64::from(reference.0), wire)?;
        u32::try_from(full).ok().map(MessageId)
    }

    /// How far ahead of `earlier` this is, treating both as a wrapping counter.
    #[inline]
    fn distance_from(self, earlier: MessageId) -> i64 {
        (self.0.wrapping_sub(earlier.0) as i32) as i64
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ChannelKind {
    /// Arrives or does not; delivered in the order received.
    Unreliable,
    /// Arrives or does not; anything older than the newest seen is discarded.
    /// The right choice for continuously changing state, where a lost update is
    /// superseded rather than resent.
    UnreliableSequenced,
    /// Always arrives; delivered in the order received.
    ReliableUnordered,
    /// Always arrives, in order. A gap holds later messages until it fills.
    ReliableOrdered,
}

impl ChannelKind {
    #[inline]
    const fn is_reliable(self) -> bool {
        matches!(self, ChannelKind::ReliableUnordered | ChannelKind::ReliableOrdered)
    }

    /// Whether messages carry an id. Unreliable messages are never resent and
    /// never acknowledged, so they need no identity.
    #[inline]
    const fn needs_id(self) -> bool {
        !matches!(self, ChannelKind::Unreliable)
    }
}

/// The channel set a connection uses.
///
/// Both peers must build the same one in the same order, since a channel travels
/// as its index.
#[derive(Clone, Copy)]
pub struct ChannelSet {
    set: [ChannelKind; MAX_CHANNELS],
    len: usize,
}

impl ChannelSet {
    pub const fn new<const N: usize>(kinds: [ChannelKind; N]) -> Self {
        const { assert!(N <= MAX_CHANNELS, "too many channels") };

        let mut set = [ChannelKind::Unreliable; MAX_CHANNELS];
        let mut i = 0;

        while i < N {
            set[i] = kinds[i];
            i += 1;
        }

        Self { set, len: N }
    }

    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub const fn kind(&self, channel: u8) -> Option<ChannelKind> {
        let i = channel as usize;
        if i < self.len { Some(self.set[i]) } else { None }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// Longer than MAX_MESSAGE. Fragment it first.
    TooLarge,
    /// No channel at that index.
    NoSuchChannel,
    /// The pending list or the arena is full: the application is producing
    /// faster than the connection can drain.
    WouldBlock,
}

#[derive(Clone, Copy, Default)]
struct Pending {
    channel: u8,
    id: MessageId,
    message: MessageRef,
    /// Set while the message rides in a packet whose fate is unknown. Cleared on
    /// loss so it is written again.
    in_flight: bool,
}

#[derive(Clone, Copy, Default)]
struct Held {
    channel: u8,
    id: MessageId,
    message: MessageRef,
}

/// Per-channel receive state.
///
/// A struct rather than an enum: the variants' fields are small, and a struct
/// keeps every channel the same size regardless of kind.
#[derive(Clone, Copy, Default)]
struct ReceiverState {
    /// Sequenced: the newest id delivered.
    newest: MessageId,
    has_newest: bool,
    /// Unordered: which recent ids were delivered. A reliable message is resent
    /// until acknowledged and an acknowledgement can itself be lost, so the same
    /// message genuinely arrives more than once.
    seen_newest: MessageId,
    seen_mask: u64,
    seen_started: bool,
    /// Ordered: the next id that may be delivered.
    expected: MessageId,
}

impl ReceiverState {
    /// Whether an id is new to the unordered duplicate set. Ids older than the
    /// window count as seen: a message that old has been delivered and
    /// acknowledged many times over.
    fn accept_unordered(&mut self, id: MessageId) -> bool {
        if !self.seen_started {
            self.seen_started = true;
            self.seen_newest = id;
            self.seen_mask = 1;
            return true;
        }

        let distance = id.distance_from(self.seen_newest);
        if distance > 0 {
            let shift = distance as u64;
            self.seen_mask = if shift >= 64 { 0 } else { self.seen_mask << shift };
            self.seen_mask |= 1;
            self.seen_newest = id;
            return true;
        }

        let offset = (-distance) as u64;
        if offset >= 64 {
            return false;
        }
        if (self.seen_mask & (1 << offset)) != 0 {
            return false;
        }
        self.seen_mask |= 1 << offset;
        true
    }
}

/// One message written into the packet in progress.
/// Unreliable messages are dropped when the packet commits.
/// Reliable ones stay until acknowledged.
#[derive(Clone, Copy, Default)]
pub struct Written {
    channel: u8,
    id: MessageId,
    reliable: bool,
}

/// Which messages rode in the packet being built.
pub type PacketMessages = FixedVec<Written, MAX_MESSAGES_PER_PACKET>;

/// Identifies one reliable message awaiting its packet's fate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MessageKey {
    channel: u8,
    id: MessageId,
}

/// The reliable messages a sent packet carried. This is what the delivery ledger
/// stores with the packet and hands back when its fate is known. Unreliable
/// messages never appear here, instead released when the packet commits.
pub type PacketRecord = FixedVec<MessageKey, MAX_MESSAGES_PER_PACKET>;

/// What a channel decided about an arriving message.
enum Accepted {
    /// Deliver it now.
    Deliver,
    /// Hold it; it is ahead of the gap.
    Hold,
    /// A duplicate, or a sequenced message superseded by a newer one.
    Discard,
}

/// One connection's channels.
///
/// The transport calls in at four points: when a received packet's frames are
/// read, when an outgoing packet is being filled, when a packet's fate is
/// known, and when the application sends.
pub struct Channels {
    set: ChannelSet,

    next_ids: [MessageId; MAX_CHANNELS],
    receivers: [ReceiverState; MAX_CHANNELS],

    /// Unacknowledged and unsent messages, oldest first, tagged with channel.
    pending: FixedVec<Pending, MAX_PENDING>,
    /// Messages ahead of their channel's expected id.
    held: FixedVec<Held, MAX_HELD>,

    send_arena: Arena<ARENA_BLOCKS>,
    /// Only ordered holds copy inbound payloads; everything else is delivered as
    /// a borrow of the packet buffer.
    recv_arena: Arena<ARENA_BLOCKS>,

    dropped_inbound: u64,
}

impl Channels {
    pub fn new(set: ChannelSet) -> Self {
        Self {
            set,
            next_ids: [MessageId::FIRST; MAX_CHANNELS],
            receivers: [ReceiverState::default(); MAX_CHANNELS],
            pending: FixedVec::new(),
            held: FixedVec::new(),
            send_arena: Arena::new(),
            recv_arena: Arena::new(),
            dropped_inbound: 0,
        }
    }

    /// Inbound messages dropped because hold storage was full. Always zero in
    /// practice: the peer cannot have more outstanding than the hold can take.
    #[inline]
    pub fn dropped_inbound(&self) -> u64 {
        self.dropped_inbound
    }

    #[inline]
    fn kind(&self, channel: u8) -> Option<ChannelKind> {
        self.set.kind(channel)
    }

    /// Queues a message.
    ///
    /// `WouldBlock` means the connection cannot currently carry more. Either the
    /// peer has stopped acknowledging, or the application is outpacing the send
    /// budget.
    pub fn send(&mut self, channel: u8, payload: &[u8]) -> Result<(), SendError> {
        if payload.len() > MAX_MESSAGE {
            return Err(SendError::TooLarge);
        }
        if self.kind(channel).is_none() {
            return Err(SendError::NoSuchChannel);
        }
        if self.pending.is_full() {
            return Err(SendError::WouldBlock);
        }

        let message = self.send_arena.store(payload).ok_or(SendError::WouldBlock)?;
        let id = self.next_ids[channel as usize];

        if !self.pending.push(Pending { channel, id, message, in_flight: false }) {
            self.send_arena.release(message);
            return Err(SendError::WouldBlock);
        }
        self.next_ids[channel as usize] = id.next();
        Ok(())
    }

    pub(crate) fn read_message(&mut self, r: &mut BitReader, on_message: OnMessage) -> Result<(), ReadError> {
        let channel = r.read_range(0, (MAX_CHANNELS - 1) as u32)? as u8;
        let kind = self.kind(channel).ok_or(ReadError::OutOfRange)?;

        let id = if kind.needs_id() {
            let wire = WireSequence(r.read_bits(MESSAGE_ID_BITS)? as u16);
            let reference = self.reference(channel, kind);
            MessageId::from_wire(reference, wire).ok_or(ReadError::OutOfRange)?
        } else {
            MessageId::FIRST
        };

        let len = r.read_range(0, MAX_MESSAGE as u32)? as usize;
        r.align()?;

        // Borrowed from the packet buffer, not copied: the common path stores
        // nothing at all.
        let payload = r.peek_bytes(len).ok_or(ReadError::Eof)?;
        r.skip_bytes(len)?;

        match self.classify(channel, kind, id) {
            Accepted::Discard => {}
            Accepted::Deliver => {
                on_message(channel, payload);
                self.flush_ordered(channel, on_message);
            }
            Accepted::Hold => {
                if self.held.is_full() {
                    // Unreachable while both peers use equal arenas and pending
                    // limits, since the peer cannot have this many outstanding.
                    self.dropped_inbound += 1;
                    return Ok(());
                }
                let Some(message) = self.recv_arena.store(payload) else {
                    self.dropped_inbound += 1;
                    return Ok(());
                };
                let _ = self.held.push(Held { channel, id, message });
            }
        }
        Ok(())
    }

    /// The reference an incoming wire id is resolved against.
    fn reference(&self, channel: u8, kind: ChannelKind) -> MessageId {
        let state = &self.receivers[channel as usize];
        match kind {
            ChannelKind::Unreliable => MessageId::FIRST,
            ChannelKind::UnreliableSequenced => state.newest,
            ChannelKind::ReliableUnordered => state.seen_newest,
            ChannelKind::ReliableOrdered => state.expected,
        }
    }

    /// Decides what a channel does with an arriving id, advancing the receiver's
    /// own state.
    fn classify(&mut self, channel: u8, kind: ChannelKind, id: MessageId) -> Accepted {
        let state = &mut self.receivers[channel as usize];

        match kind {
            ChannelKind::Unreliable => Accepted::Deliver,

            ChannelKind::UnreliableSequenced => {
                // Older than what was delivered: a newer update has superseded
                // it, so it carries nothing useful.
                if state.has_newest && (id.distance_from(state.newest) <= 0) {
                    return Accepted::Discard;
                }
                state.newest = id;
                state.has_newest = true;
                Accepted::Deliver
            }

            ChannelKind::ReliableUnordered => {
                if state.accept_unordered(id) {
                    Accepted::Deliver
                } else {
                    Accepted::Discard
                }
            }

            ChannelKind::ReliableOrdered => {
                let distance = id.distance_from(state.expected);
                if distance < 0 {
                    // Already delivered; the peer resent it because our
                    // acknowledgement was lost.
                    Accepted::Discard
                } else if distance == 0 {
                    state.expected = state.expected.next();
                    Accepted::Deliver
                } else if self.held.iter().any(|e| (e.channel == channel) && (e.id == id)) {
                    Accepted::Discard
                } else {
                    Accepted::Hold
                }
            }
        }
    }

    /// Delivers held messages that the last delivery unblocked.
    fn flush_ordered(&mut self, channel: u8, on_message: OnMessage) {
        let mut staging = [0u8; MAX_MESSAGE];

        loop {
            let wanted = self.receivers[channel as usize].expected;
            let Some(at) = self
                .held
                .iter()
                .position(|e| (e.channel == channel) && (e.id == wanted))
            else {
                return;
            };

            let Some(entry) = self.held.remove(at) else { return };
            self.receivers[channel as usize].expected = wanted.next();

            // Held messages outlived their packet, so this is the one inbound
            // path that copies.
            if let Some(len) = self.recv_arena.load(entry.message, &mut staging) {
                on_message(channel, &staging[..len]);
            }
            self.recv_arena.release(entry.message);
        }
    }

    /// Fills the remaining space, using at most `limit` bytes of the datagram's
    /// allowance. Returns whether anything was written.
    ///
    /// Channels are visited in configured order, so their order is a priority
    /// declaration.
    pub fn write_frames(&mut self, w: &mut BitWriter, staged: &mut PacketMessages, limit: usize) -> bool {
        let start_bits = w.bits_written();
        let mut wrote = false;

        'channels: for channel in 0..(self.set.len() as u8) {
            let Some(kind) = self.kind(channel) else { continue };

            loop {
                if staged.is_full() {
                    break 'channels;
                }
                if (w.bits_written() - start_bits).div_ceil(8) >= limit {
                    break 'channels;
                }

                let Some(pending) = self.pending.iter_mut().find(|m| (m.channel == channel) && !m.in_flight) else {
                    break;
                };

                let checkpoint = w.checkpoint();
                let ok = FrameKind::Message.write(w).is_ok()
                    && write_message_frame(w, kind, *pending, &self.send_arena).is_ok();

                if !ok {
                    // Out of packet space. A later channel may hold something smaller that fits.
                    w.rollback(checkpoint);
                    break;
                }

                // Fit the packet, but would exceed the allowance, which applies
                // to the datagram as a whole.
                if (w.bits_written() - start_bits).div_ceil(8) > limit {
                    w.rollback(checkpoint);
                    break 'channels;
                }

                pending.in_flight = true;
                let _ = staged.push(Written {
                    channel,
                    id: pending.id,
                    reliable: kind.is_reliable(),
                });
                wrote = true;
            }
        }

        wrote
    }

    /// The packet was sent. Unreliable messages are released and reliable
    /// ones are returned as the record the delivery ledger keeps for the
    /// packet.
    pub fn on_packet_sent(&mut self, staged: PacketMessages) -> PacketRecord {
        let mut record = PacketRecord::new();

        staged.iter().for_each(|msg| {
            if msg.reliable {
                let _ = record.push(MessageKey { channel: msg.channel, id: msg.id });
            } else {
                self.release_pending(msg.channel, msg.id);
            }
        });

        record
    }

    /// The packet was not sent: staged messages return to the send queues.
    ///
    /// Without this they would stay marked in flight under a sequence the peer
    /// never sees, so no acknowledgement or loss would ever arrive for them
    /// and they would stall permanently.
    pub fn on_packet_aborted(&mut self, staged: PacketMessages) {
        staged.iter().for_each(|msg| self.mark_lost(msg.channel, msg.id));
    }

    /// The packet carrying `record` was acknowledged
    pub fn on_acked(&mut self, record: PacketRecord) {
        record.iter().for_each(|key| self.release_pending(key.channel, key.id));
    }

    /// The packet carrying `record` was lost
    pub fn on_lost(&mut self, record: PacketRecord) {
        record.iter().for_each(|key| self.mark_lost(key.channel, key.id));
    }

    /// Marks up to `max` of the oldest unacknowledged messages as unsent, so
    /// the next packet carries them again.
    ///
    /// Used for probes: a packet that has to go out anyway is worth more
    /// carrying the data whose acknowledgement is being waited on, since the
    /// reply then completes those messages rather than merely revealing that
    /// an earlier packet was lost. The originals stay tracked; whichever copy
    /// arrives first is the one that counts, and the receiver discards the
    /// other.
    pub fn requeue_oldest(&mut self, max: usize) -> usize {
        let mut requeued = 0;
        for pending in self.pending.iter_mut() {
            if requeued == max {
                break;
            }
            if pending.in_flight {
                pending.in_flight = false;
                requeued += 1;
            }
        }
        requeued
    }

    /// Messages queued to send or awaiting their packet's outcome. Zero once
    /// everything sent has been acknowledged.
    #[inline]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Payload length of the message the next packet tries first, if one is
    /// waiting to be sent.
    ///
    /// `write_frames` visits channels in configured order, oldest message
    /// first, and a message that does not fit the allowance ends the attempt.
    /// So this message's size alone decides when sending can resume.
    pub fn next_unsent_len(&self) -> Option<usize> {
        (0..(self.set.len() as u8)).find_map(|channel| {
            self.pending
                .iter()
                .find(|m| (m.channel == channel) && !m.in_flight)
                .map(|m| m.message.len())
        })
    }

    /// Removes a message from the send queue and frees its storage. Used when a
    /// reliable message is acknowledged and when an unreliable one's packet
    /// commits. In both cases the message has no further outcome.
    fn release_pending(&mut self, channel: u8, id: MessageId) {
        let Some(at) = self.pending.iter().position(|m| (m.channel == channel) && (m.id == id)) else {
            return;
        };
        if let Some(outbound) = self.pending.remove(at) {
            self.send_arena.release(outbound.message);
        }
    }

    /// A lost message returns to the queue and goes out in a new packet under a
    /// new packet sequence; retransmitting the original would repeat its AEAD
    /// nonce.
    fn mark_lost(&mut self, channel: u8, id: MessageId) {
        if let Some(outbound) = self.pending.iter_mut().find(|m| (m.channel == channel) && (m.id == id)) {
            outbound.in_flight = false;
        }
    }
}

/// Writes one message frame. The frame kind has already been written.
fn write_message_frame<const N: usize>(
    w: &mut BitWriter,
    kind: ChannelKind,
    pending: Pending,
    arena: &Arena<N>,
) -> Result<(), WriteError> {
    w.write_range(pending.channel as u32, 0, (MAX_CHANNELS - 1) as u32)?;
    if kind.needs_id() {
        w.write_bits(u32::from(pending.id.to_wire().0), MESSAGE_ID_BITS)?;
    }
    w.write_range(pending.message.len() as u32, 0, MAX_MESSAGE as u32)?;
    // Byte-aligned so the payload copies as blocks rather than bit by bit. The
    // cost is under a byte of padding per message.
    w.align()?;
    arena.chunks(pending.message).try_for_each(|c| w.write_bytes(c))
}
