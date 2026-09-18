//! Counters and latency histograms.
//!
//! Recording is a shift, an index, and an increment, so measurement does not
//! perturb what is measured.

use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(usize)]
pub enum Counter {
    DatagramsReceived,
    DatagramsSent,
    BytesReceived,
    BytesSent,
    SendFailures,

    PacketsTooShort,
    PacketsMalformed,
    PacketsDuplicate,
    PacketsTooOld,
    PacketsUnknownConnection,
    DecryptFailures,

    PacketsAcked,
    PacketsLost,
    /// Declared lost, then acknowledged. A sustained rate means the reorder
    /// threshold or loss timer is too tight and bandwidth is going to
    /// needless retransmission.
    PacketsSpuriouslyLost,

    ConnectionsRejectedFull,
    /// Refused by the per-address or global handshake limiter.
    HandshakesRateLimited,

    MessagesSent,
    MessagesReceived,
    /// Inbound messages dropped because storage was full.
    MessagesDropped,

    TicksRun,
    TicksOverBudget,
}

impl Counter {
    pub const COUNT: usize = (Counter::TicksOverBudget as usize) + 1;

    pub const ALL: [Counter; Counter::COUNT] = {
        use Counter::*;
        [
            DatagramsReceived,
            DatagramsSent,
            BytesReceived,
            BytesSent,
            SendFailures,
            PacketsTooShort,
            PacketsMalformed,
            PacketsDuplicate,
            PacketsTooOld,
            PacketsUnknownConnection,
            DecryptFailures,
            PacketsAcked,
            PacketsLost,
            PacketsSpuriouslyLost,
            ConnectionsRejectedFull,
            HandshakesRateLimited,
            MessagesSent,
            MessagesReceived,
            MessagesDropped,
            TicksRun,
            TicksOverBudget,
        ]
    };

    pub const fn name(self) -> &'static str {
        use Counter::*;
        match self {
            DatagramsReceived => "datagrams_received",
            DatagramsSent => "datagrams_sent",
            BytesReceived => "bytes_received",
            BytesSent => "bytes_sent",
            SendFailures => "send_failures",
            PacketsTooShort => "packets_too_short",
            PacketsMalformed => "packets_malformed",
            PacketsDuplicate => "packets_duplicate",
            PacketsTooOld => "packets_too_old",
            PacketsUnknownConnection => "packets_unknown_connection",
            DecryptFailures => "decrypt_failures",
            PacketsAcked => "packets_acked",
            PacketsLost => "packets_lost",
            PacketsSpuriouslyLost => "packets_spuriously_lost",
            ConnectionsRejectedFull => "connections_rejected_full",
            HandshakesRateLimited => "handshakes_rate_limited",
            MessagesSent => "messages_sent",
            MessagesReceived => "messages_received",
            MessagesDropped => "messages_dropped",
            TicksRun => "ticks_run",
            TicksOverBudget => "ticks_over_budget",
        }
    }
}

/// Totals, indexed by enum. One set per thread, merged to read: a shared
/// atomic counter would bounce a cache line between cores on every packet.
#[derive(Clone, Debug)]
pub struct Counters {
    values: [u64; Counter::COUNT],
}

impl Default for Counters {
    fn default() -> Self {
        Self::new()
    }
}

impl Counters {
    pub const fn new() -> Self {
        Self { values: [0; Counter::COUNT] }
    }

    #[inline]
    pub fn add(&mut self, counter: Counter, n: u64) {
        self.values[counter as usize] = self.values[counter as usize].wrapping_add(n);
    }

    #[inline]
    pub fn inc(&mut self, counter: Counter) {
        self.add(counter, 1);
    }

    #[inline]
    pub fn get(&self, counter: Counter) -> u64 {
        self.values[counter as usize]
    }

    pub fn merge(&mut self, other: &Counters) {
        for (slot, value) in self.values.iter_mut().zip(other.values.iter()) {
            *slot = slot.wrapping_add(*value);
        }
    }

    /// Totals since `previous`, for per-second reporting.
    pub fn delta_since(&self, previous: &Counters) -> Counters {
        let mut out = Counters::new();
        for (i, slot) in out.values.iter_mut().enumerate() {
            *slot = self.values[i].wrapping_sub(previous.values[i]);
        }
        out
    }

    pub fn iter(&self) -> impl Iterator<Item = (Counter, u64)> + '_ {
        Counter::ALL.iter().map(move |&c| (c, self.get(c)))
    }
}

const SUBBUCKET_BITS: u32 = 4;
/// Buckets per doubling of value.
const SUBBUCKETS: usize = 1 << SUBBUCKET_BITS;
const MAJOR_BUCKETS: usize = 64 - (SUBBUCKET_BITS as usize);
const BUCKETS: usize = MAJOR_BUCKETS * SUBBUCKETS;

/// Log-linear histogram covering the whole u64 range with about six percent
/// worst-case bucket error.
///
/// Percentiles rather than averages: an average tick time hides the one tick
/// in a hundred that players actually feel.
#[derive(Clone)]
pub struct Histogram {
    buckets: [u32; BUCKETS],
    count: u64,
    sum: u64,
    min: u64,
    max: u64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

impl Histogram {
    pub const fn new() -> Self {
        Self {
            buckets: [0; BUCKETS],
            count: 0,
            sum: 0,
            min: u64::MAX,
            max: 0,
        }
    }

    #[inline]
    pub fn record(&mut self, value: u64) {
        let index = Self::bucket_of(value);
        self.buckets[index] = self.buckets[index].saturating_add(1);
        self.count += 1;
        self.sum = self.sum.saturating_add(value);
        self.min = self.min.min(value);
        self.max = self.max.max(value);
    }

    #[inline]
    pub fn record_duration(&mut self, d: Duration) {
        self.record(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
    }

    /// Values below sixteen get an exact bucket each; above that, sixteen
    /// buckets per doubling.
    #[inline]
    fn bucket_of(value: u64) -> usize {
        if value < (SUBBUCKETS as u64) {
            return value as usize;
        }
        let magnitude = (63 - value.leading_zeros()) as usize;
        let shift = magnitude - (SUBBUCKET_BITS as usize);
        let sub = ((value >> shift) as usize) & (SUBBUCKETS - 1);
        (((magnitude - (SUBBUCKET_BITS as usize)) + 1) * SUBBUCKETS) + sub
    }

    /// Lowest value landing in this bucket.
    fn bucket_start(index: usize) -> u64 {
        if index < SUBBUCKETS {
            return index as u64;
        }
        let major = (index / SUBBUCKETS) - 1;
        let sub = index % SUBBUCKETS;
        ((SUBBUCKETS + sub) as u64) << (major as u32)
    }

    #[inline]
    pub fn count(&self) -> u64 {
        self.count
    }

    #[inline]
    pub fn min(&self) -> u64 {
        if self.count == 0 { 0 } else { self.min }
    }

    #[inline]
    pub fn max(&self) -> u64 {
        self.max
    }

    #[inline]
    pub fn mean(&self) -> f64 {
        if self.count == 0 { 0.0 } else { (self.sum as f64) / (self.count as f64) }
    }

    /// Value at quantile `q`, reported as the bucket's lower bound so the
    /// figure is never an overstatement.
    pub fn quantile(&self, q: f64) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let q = q.clamp(0.0, 1.0);
        let target = ((self.count as f64) * q).ceil().max(1.0) as u64;

        let mut seen = 0u64;
        for (index, &n) in self.buckets.iter().enumerate() {
            seen += n as u64;
            if seen >= target {
                return Self::bucket_start(index).max(self.min);
            }
        }
        self.max
    }

    /// Exact: merged percentiles match recording every sample in one place.
    pub fn merge(&mut self, other: &Histogram) {
        for (slot, n) in self.buckets.iter_mut().zip(other.buckets.iter()) {
            *slot = slot.saturating_add(*n);
        }
        self.count += other.count;
        self.sum = self.sum.saturating_add(other.sum);
        self.min = self.min.min(other.min);
        self.max = self.max.max(other.max);
    }

    pub fn reset(&mut self) {
        *self = Histogram::new();
    }

    pub fn summary_micros(&self) -> String {
        format!(
            "n={} min={:.1} p50={:.1} p99={:.1} p999={:.1} max={:.1}",
            self.count,
            (self.min() as f64) / 1000.0,
            (self.quantile(0.50) as f64) / 1000.0,
            (self.quantile(0.99) as f64) / 1000.0,
            (self.quantile(0.999) as f64) / 1000.0,
            (self.max as f64) / 1000.0,
        )
    }
}
