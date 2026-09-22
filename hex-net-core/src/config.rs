//! What a connection is configured with: the send budget, which each side
//! chooses for itself, and the acknowledgement delay, which both sides must
//! share.

use std::time::Duration;

use crate::{ack::ACK_DELAY_UNIT, budget::BudgetConfig};

/// Longest a receiver holds an acknowledgement waiting for a packet to ride on.
///
/// Bounded by what the header's delay field can express, whose top value is
/// reserved for "unknown", so an acknowledgement sent on its deadline always
/// reports a measured delay and yields an RTT sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxAckDelay(Duration);

impl MaxAckDelay {
    /// The longest delay the header can report.
    pub const LIMIT: Duration = Duration::from_nanos((ACK_DELAY_UNIT.as_nanos() as u64) * ((u8::MAX as u64) - 1));

    /// Every packet worth acknowledging is acknowledged by the next transmit,
    /// whether or not anything else is going out.
    pub const IMMEDIATE: MaxAckDelay = MaxAckDelay(Duration::ZERO);

    pub const DEFAULT: MaxAckDelay = match MaxAckDelay::new(Duration::from_millis(25)) {
        Some(delay) => delay,
        None => panic!("the default acknowledgement delay exceeds the header's range"),
    };

    /// `None` when `delay` is longer than the header can report.
    pub const fn new(delay: Duration) -> Option<MaxAckDelay> {
        if delay.as_nanos() > Self::LIMIT.as_nanos() { None } else { Some(MaxAckDelay(delay)) }
    }

    #[inline]
    pub const fn get(self) -> Duration {
        self.0
    }
}

/// How one side of a connection behaves.
///
/// `max_ack_delay` must be the same on both sides: each holds its own
/// acknowledgements that long, and allows for the peer holding them that long
/// before it probes. `budget` is each side's own choice.
#[derive(Clone, Copy, Debug)]
pub struct TransportConfig {
    pub budget: BudgetConfig,
    pub max_ack_delay: MaxAckDelay,
}

impl TransportConfig {
    pub const DEFAULT: TransportConfig = TransportConfig {
        budget: BudgetConfig::DEFAULT,
        max_ack_delay: MaxAckDelay::DEFAULT,
    };
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}
