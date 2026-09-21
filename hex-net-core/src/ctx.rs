use crate::{stats::Counters, time::Timestamp};

/// Per-pass state threaded through the transport.
///
/// Constructed once per service pass by the driver, so every connection
/// touched in that pass shares one clock reading and one set of counters.
pub struct Ctx<'a> {
    /// The instant this pass is running at, or a datagram's kernel receive
    /// timestamp when one is available.
    pub now: Timestamp,
    pub counters: &'a mut Counters,
}

impl<'a> Ctx<'a> {
    #[inline]
    pub fn new(now: Timestamp, counters: &'a mut Counters) -> Self {
        Self { now, counters }
    }
}
