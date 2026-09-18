use std::time::Duration;

/// How a simulated link behaves. Per-direction, so the uplink and downlink
/// can be different, just like real connections.
#[derive(Clone, Copy, Debug)]
pub struct LinkConfig {
    /// One-way delay before jitter.
    pub latency: Duration,
    /// Random delay added on top, uniform in [0, jitter].
    pub jitter: Duration,
    /// Chance a packet is dropped, 0.0 to 1.0.
    pub loss: f32,
    /// Chance a packet is delivered twice. Real networks do this.
    pub duplication: f32,
    /// Chance a packet's delivery time is pushed back, reordering it behind
    /// later packets.
    pub reorder: f32,
    /// Extra delay applied when a packet is chosen for reordering.
    pub reorder_delay: Duration,
    /// Bytes per second, or None for unlimited.
    pub bandwidth: Option<u32>,
    /// Packets in flight before the link starts dropping. Models a router
    /// queue: once full, new packets are discarded rather than queued.
    pub capacity: usize,
}

impl LinkConfig {
    /// A link that does nothing: instant, lossless. The baseline for tests
    /// that care about protocol logic rather than network behaviour.
    pub const PERFECT: LinkConfig = LinkConfig {
        latency: Duration::ZERO,
        jitter: Duration::ZERO,
        loss: 0.0,
        duplication: 0.0,
        reorder: 0.0,
        reorder_delay: Duration::ZERO,
        bandwidth: None,
        capacity: 4096,
    };

    /// Wired broadband: low latency, negligible loss.
    pub const GOOD: LinkConfig = LinkConfig {
        latency: Duration::from_millis(15),
        jitter: Duration::from_millis(3),
        loss: 0.001,
        duplication: 0.0,
        reorder: 0.001,
        reorder_delay: Duration::from_millis(20),
        bandwidth: None,
        capacity: 4096,
    };

    /// Mobile or congested wifi. This is the one worth testing against most:
    /// it is unpleasant but entirely ordinary for real players.
    pub const POOR: LinkConfig = LinkConfig {
        latency: Duration::from_millis(80),
        jitter: Duration::from_millis(40),
        loss: 0.05,
        duplication: 0.005,
        reorder: 0.02,
        reorder_delay: Duration::from_millis(60),
        bandwidth: Some(256_000),
        capacity: 256,
    };

    /// Deliberately hostile. Nothing should break; things may be slow.
    pub const AWFUL: LinkConfig = LinkConfig {
        latency: Duration::from_millis(200),
        jitter: Duration::from_millis(150),
        loss: 0.30,
        duplication: 0.02,
        reorder: 0.10,
        reorder_delay: Duration::from_millis(200),
        bandwidth: Some(64_000),
        capacity: 64,
    };
}

/// Deterministic PRNG. Seeded per run, so a failing test replays exactly.
/// xorshift64*: fast, adequate for shaping traffic, not for anything
/// security-related.
#[derive(Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        // Zero is a fixed point of xorshift; avoid it.
        Self(seed | 1)
    }

    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform in [0, 1).
    #[inline]
    pub fn next_f32(&mut self) -> f32 {
        // Top 24 bits: exactly the mantissa width of f32, so every value is
        // representable and the distribution has no gaps.
        ((self.next_u64() >> 40) as f32) / ((1u32 << 24) as f32)
    }

    #[inline]
    pub fn chance(&mut self, probability: f32) -> bool {
        (probability > 0.0) && (self.next_f32() < probability)
    }

    /// Uniform in [0, max].
    #[inline]
    pub fn duration_up_to(&mut self, max: Duration) -> Duration {
        if max.is_zero() {
            return Duration::ZERO;
        }
        let nanos = max.as_nanos() as u64;
        Duration::from_nanos(self.next_u64() % (nanos + 1))
    }
}
