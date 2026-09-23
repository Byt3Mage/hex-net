//! Everything the transport is tuned by, in one place.
//!
//! Three kinds of value are defined here:
//! - [BudgetConfig]: What one side chooses for itself
//! - [MaxAckDelay]: What both sides must agree on
//! - [Liveness]: How long a connection may be silent before it is considered gone

use crate::{
    channel::{MAX_MESSAGE, MESSAGE_FRAME_OVERHEAD},
    time::Span,
    wire::{Header, MAX_DATAGRAM, TAG_LEN},
};

/// Wire resolution of the acknowledgement delay field: the unit a header
/// reports a held acknowledgement in.
pub const ACK_DELAY_UNIT: Span = Span::from_micros(250);

/// Slowest send rate offered, in bytes a second. Below this a connection could
/// not carry one maximum-size message per round trip, and the timers built on
/// the rate stop being meaningful.
pub const MIN_RATE: u32 = 2000;

/// Smallest packet size a connection may be capped at: enough for a full
/// message, its frame, a header and a tag. A smaller cap would stall any
/// message that could not be split.
pub const MIN_PACKET: usize = Header::MAX_LEN + TAG_LEN + MESSAGE_FRAME_OVERHEAD + MAX_MESSAGE;

/// One side's send allowance: the rate it refills at and the largest datagram
/// it will build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetConfig {
    rate: u32,
    max_packet: u16,
}

impl BudgetConfig {
    pub const DEFAULT: BudgetConfig = match BudgetConfig::new(8000, MAX_DATAGRAM) {
        Some(config) => config,
        None => panic!("the default budget violates its own bounds"),
    };

    /// `None` for a rate below `MIN_RATE`, or a packet cap that could not carry
    /// a whole message or exceeds what the wire allows.
    pub const fn new(rate: u32, max_packet: usize) -> Option<BudgetConfig> {
        const { assert!(MIN_PACKET <= MAX_DATAGRAM, "a full message must fit one datagram") };
        const { assert!(MAX_DATAGRAM <= u16::MAX as usize) };
        if rate < MIN_RATE || max_packet < MIN_PACKET || max_packet > MAX_DATAGRAM {
            return None;
        }
        Some(BudgetConfig { rate, max_packet: max_packet as u16 })
    }

    #[inline]
    pub const fn rate(self) -> u32 {
        self.rate
    }

    #[inline]
    pub const fn max_packet(self) -> usize {
        self.max_packet as usize
    }
}

/// Longest a receiver holds an acknowledgement waiting for a packet to ride on.
///
/// Bounded by what the header's delay field can express, whose top value is
/// reserved for "unknown", so an acknowledgement sent on its deadline always
/// reports a measured delay and yields a round-trip sample.
///
/// Both sides must use the same value: each holds its own acknowledgements
/// this long, and each allows for the peer holding them this long before it
/// decides the tail of its flight is unanswered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxAckDelay(Span);

impl MaxAckDelay {
    /// The longest delay a header can report, since the field's top value
    /// means "longer than this".
    pub const LIMIT: Span = Span::from_nanos(ACK_DELAY_UNIT.as_nanos() * ((u8::MAX as u64) - 1));

    /// Every packet worth acknowledging is acknowledged by the next transmit,
    /// whether or not anything else is going out.
    pub const IMMEDIATE: MaxAckDelay = MaxAckDelay(Span::ZERO);

    pub const DEFAULT: MaxAckDelay = match MaxAckDelay::new(Span::from_millis(25)) {
        Some(delay) => delay,
        None => panic!("the default acknowledgement delay exceeds the header's range"),
    };

    /// `None` when `delay` is longer than a header can report, which would make
    /// the delay it costs invisible to the peer's round-trip estimate.
    pub const fn new(delay: Span) -> Option<MaxAckDelay> {
        if delay.as_nanos() > Self::LIMIT.as_nanos() { None } else { Some(MaxAckDelay(delay)) }
    }

    #[inline]
    pub const fn get(self) -> Span {
        self.0
    }
}

/// How a connection proves it is still there, and how long it may go unproven.
///
/// The two are one type because only their relation is meaningful: a keepalive
/// interval at or above the idle timeout would let a connection time out while
/// waiting to send the packet that would have saved it. That pairing cannot be
/// built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Liveness {
    idle_timeout: Span,
    keepalive: Span,
}

impl Liveness {
    /// Two keepalives fit inside the idle timeout, so one lost keepalive does
    /// not end a connection.
    const MIN_KEEPALIVES_PER_TIMEOUT: u64 = 2;

    pub const DEFAULT: Liveness = match Liveness::new(Span::from_secs(10), Span::from_secs(1)) {
        Some(liveness) => liveness,
        None => panic!("the default liveness violates its own bounds"),
    };

    /// `None` unless a keepalive is nonzero and at least twice as frequent as
    /// the timeout it defends against.
    pub const fn new(idle_timeout: Span, keepalive: Span) -> Option<Liveness> {
        if keepalive.is_zero() {
            return None;
        }
        if keepalive.as_nanos().saturating_mul(Self::MIN_KEEPALIVES_PER_TIMEOUT) > idle_timeout.as_nanos() {
            return None;
        }
        Some(Liveness { idle_timeout, keepalive })
    }

    /// No packet received for this long and the connection is dead.
    #[inline]
    pub const fn idle_timeout(self) -> Span {
        self.idle_timeout
    }

    /// Longest a connection stays silent: a keepalive goes out this long after
    /// the last packet the peer would acknowledge, which also holds a NAT
    /// mapping open.
    #[inline]
    pub const fn keepalive(self) -> Span {
        self.keepalive
    }
}

/// How one side of a connection behaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportConfig {
    pub budget: BudgetConfig,
    pub max_ack_delay: MaxAckDelay,
    pub liveness: Liveness,
}

impl TransportConfig {
    pub const DEFAULT: TransportConfig = TransportConfig {
        budget: BudgetConfig::DEFAULT,
        max_ack_delay: MaxAckDelay::DEFAULT,
        liveness: Liveness::DEFAULT,
    };

    /// A configuration built from parts, each already validated by its own
    /// constructor.
    pub const fn new(budget: BudgetConfig, max_ack_delay: MaxAckDelay, liveness: Liveness) -> TransportConfig {
        TransportConfig { budget, max_ack_delay, liveness }
    }

    #[inline]
    pub const fn with_budget(self, budget: BudgetConfig) -> TransportConfig {
        TransportConfig { budget, ..self }
    }

    #[inline]
    pub const fn with_max_ack_delay(self, max_ack_delay: MaxAckDelay) -> TransportConfig {
        TransportConfig { max_ack_delay, ..self }
    }

    #[inline]
    pub const fn with_liveness(self, liveness: Liveness) -> TransportConfig {
        TransportConfig { liveness, ..self }
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}
