//! Randomized round-trip and robustness tests for the bit reader and writer.

use crate::bits::{BitReader, BitWriter, ReadError, WriteError, bits_required};

/// xorshift64*, seeded per test so a failure replays exactly.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// One operation, replayed identically against the writer and the reader.
#[derive(Debug, Clone)]
enum Op {
    Bits(u32, u32),
    Bool(bool),
    Range(u32, u32, u32),
    RangeI32(i32, i32, i32),
    Align,
    /// Aligns first, so the run is byte-aligned as write_bytes requires.
    Bytes(Vec<u8>),
}

fn random_op(r: &mut Rng, allow_bytes: bool) -> Op {
    let choice = r.below(if allow_bytes { 6 } else { 5 });
    match choice {
        0 => {
            let bits = r.below(33) as u32;
            let value = if bits == 0 { 0 } else { (r.next() as u32) & (((1u64 << bits) - 1) as u32) };
            Op::Bits(value, bits)
        }
        1 => Op::Bool(r.below(2) == 1),
        2 => {
            let min = (r.next() as u32) >> r.below(32);
            let max = min.saturating_add((r.next() as u32) >> r.below(32));
            let span = (max - min).saturating_add(1);
            let value = min + ((r.next() as u32) % span.max(1));
            Op::Range(value.min(max), min, max)
        }
        3 => {
            let min = (r.next() as i32) >> r.below(32);
            let width = (r.next() as u32) >> r.below(32);
            let max = ((min as i64) + (width as i64)).min(i32::MAX as i64) as i32;
            let span = ((max as i64) - (min as i64) + 1).max(1) as u64;
            let value = ((min as i64) + ((r.next() % span) as i64)) as i32;
            Op::RangeI32(value.min(max), min, max)
        }
        4 => Op::Align,
        _ => {
            let len = r.below(40) as usize;
            Op::Bytes((0..len).map(|_| r.next() as u8).collect())
        }
    }
}

fn write_op(w: &mut BitWriter, op: &Op) -> Result<(), WriteError> {
    match op {
        Op::Bits(value, bits) => w.write_bits(*value, *bits),
        Op::Bool(value) => w.write_bool(*value),
        Op::Range(value, min, max) => w.write_range(*value, *min, *max),
        Op::RangeI32(value, min, max) => w.write_range_i32(*value, *min, *max),
        Op::Align => w.align(),
        Op::Bytes(bytes) => {
            // A byte run needs alignment; both must fit or neither is written.
            let at = w.checkpoint();
            let pad = (8 - ((w.bits_written() % 8) as u32)) % 8;
            if (((pad as usize) + (bytes.len() * 8)) > w.bits_remaining())
                || w.align().is_err()
                || w.write_bytes(bytes).is_err()
            {
                w.rollback(at);
                return Err(WriteError::Overflow);
            }
            Ok(())
        }
    }
}

fn check_op(r: &mut BitReader, op: &Op) {
    match op {
        Op::Bits(value, bits) => assert_eq!(r.read_bits(*bits), Ok(*value)),
        Op::Bool(value) => assert_eq!(r.read_bool(), Ok(*value)),
        Op::Range(value, min, max) => assert_eq!(r.read_range(*min, *max), Ok(*value)),
        Op::RangeI32(value, min, max) => assert_eq!(r.read_range_i32(*min, *max), Ok(*value)),
        Op::Align => assert_eq!(r.align(), Ok(())),
        Op::Bytes(bytes) => {
            r.align().expect("alignment padding must be present");
            let seen = r.peek_bytes(bytes.len()).expect("payload must be present");
            assert_eq!(seen, &bytes[..]);
            r.skip_bytes(bytes.len()).expect("payload must be skippable");
        }
    }
}

#[test]
fn roundtrip_mixed_operations() {
    let mut rng = Rng::new(0x9E37_79B9_7F4A_7C15);

    for _ in 0..20_000 {
        let capacity = rng.below(96) as usize;
        // Pre-filled with garbage: nothing may depend on the buffer being zero.
        let mut buffer = vec![0xA5u8; capacity];
        let mut w = BitWriter::new(&mut buffer);
        let mut kept: Vec<Op> = Vec::new();

        for _ in 0..rng.below(40) {
            let op = random_op(&mut rng, true);
            let before = w.bits_remaining();
            match write_op(&mut w, &op) {
                Ok(()) => kept.push(op),
                Err(_) => assert_eq!(w.bits_remaining(), before, "a failed write must consume nothing"),
            }
        }

        let len = w.finish();
        let mut r = BitReader::new(&buffer[..len]);
        for op in &kept {
            check_op(&mut r, op);
        }
        assert!(r.bits_remaining() < 8, "only padding may remain");
    }
}

#[test]
fn rollback_across_byte_runs() {
    let mut rng = Rng::new(0xDEAD_BEEF_CAFE_F00D);

    for _ in 0..20_000 {
        let capacity = rng.below(96) as usize;
        let mut buffer = vec![0x5Au8; capacity];
        let mut w = BitWriter::new(&mut buffer);
        let mut kept: Vec<Op> = Vec::new();

        for _ in 0..rng.below(30) {
            // A speculative group, half of which is rolled back.
            let checkpoint = w.checkpoint();
            let keep_from = kept.len();
            let mut aborted = false;

            for _ in 0..(1 + rng.below(4)) {
                let op = random_op(&mut rng, true);
                if write_op(&mut w, &op).is_err() {
                    aborted = true;
                    break;
                }
                kept.push(op);
            }

            if aborted || (rng.below(2) == 0) {
                w.rollback(checkpoint);
                kept.truncate(keep_from);
            }
        }

        let len = w.finish();
        let mut r = BitReader::new(&buffer[..len]);
        for op in &kept {
            check_op(&mut r, op);
        }
        assert!(r.bits_remaining() < 8);
    }
}

#[test]
fn byte_runs_at_every_bit_offset() {
    // A run starting at each of the eight offsets within a word, and at each
    // word position, so the flush-and-reload path is exercised at every phase.
    for lead_bits in 0..64u32 {
        for run_len in 0..=9usize {
            let payload: Vec<u8> = (0..run_len).map(|i| (i as u8).wrapping_mul(37)).collect();
            let mut buffer = [0xFFu8; 64];
            let mut w = BitWriter::new(&mut buffer);

            for _ in 0..lead_bits {
                w.write_bits(1, 1).unwrap();
            }
            w.align().unwrap();
            w.write_bytes(&payload).unwrap();
            // Bits after the run must land correctly on top of the reloaded tail.
            w.write_bits(0b1011, 4).unwrap();
            w.write_bits(0x2F, 6).unwrap();

            let len = w.finish();
            let mut r = BitReader::new(&buffer[..len]);

            for _ in 0..lead_bits {
                assert_eq!(r.read_bits(1), Ok(1));
            }
            r.align().unwrap();
            assert_eq!(r.peek_bytes(run_len), Some(&payload[..]));
            r.skip_bytes(run_len).unwrap();
            assert_eq!(r.read_bits(4), Ok(0b1011));
            assert_eq!(r.read_bits(6), Ok(0x2F));
        }
    }
}

#[test]
fn byte_run_then_rollback_then_rewrite() {
    // The case the flush-and-reload bookkeeping is most likely to get wrong:
    // rolling back to a point before a byte run, then writing different data.
    for lead_bits in 0..40u32 {
        let mut buffer = [0x33u8; 64];
        let mut w = BitWriter::new(&mut buffer);

        for _ in 0..lead_bits {
            w.write_bits(1, 1).unwrap();
        }
        let checkpoint = w.checkpoint();

        w.align().unwrap();
        w.write_bytes(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01]).unwrap();
        w.write_bits(0x3F, 6).unwrap();

        w.rollback(checkpoint);

        w.write_bits(0b101, 3).unwrap();
        w.align().unwrap();
        w.write_bytes(&[0x11, 0x22]).unwrap();
        w.write_bits(0x1234, 16).unwrap();

        let len = w.finish();
        let mut r = BitReader::new(&buffer[..len]);

        for _ in 0..lead_bits {
            assert_eq!(r.read_bits(1), Ok(1));
        }
        assert_eq!(r.read_bits(3), Ok(0b101));
        r.align().unwrap();
        assert_eq!(r.peek_bytes(2), Some(&[0x11u8, 0x22][..]));
        r.skip_bytes(2).unwrap();
        assert_eq!(r.read_bits(16), Ok(0x1234));
    }
}

#[test]
fn bulk_and_per_byte_paths_agree() {
    // A byte run must produce the same stream as writing each byte through
    // write_bits, and peek_bytes must yield the same values as reading eight
    // bits at a time.
    let mut rng = Rng::new(0x0123_4567_89AB_CDEF);

    for _ in 0..5_000 {
        let lead_bits = rng.below(17) as u32;
        let lead_value = (rng.next() as u32) & (((1u64 << lead_bits) - 1) as u32);
        let payload: Vec<u8> = (0..rng.below(50)).map(|_| rng.next() as u8).collect();

        let mut bulk = [0u8; 128];
        let bulk_len = {
            let mut w = BitWriter::new(&mut bulk);
            w.write_bits(lead_value, lead_bits).unwrap();
            w.align().unwrap();
            w.write_bytes(&payload).unwrap();
            w.finish()
        };

        let mut stepped = [0u8; 128];
        let stepped_len = {
            let mut w = BitWriter::new(&mut stepped);
            w.write_bits(lead_value, lead_bits).unwrap();
            w.align().unwrap();
            for byte in &payload {
                w.write_bits(*byte as u32, 8).unwrap();
            }
            w.finish()
        };

        assert_eq!(bulk_len, stepped_len, "the two writers must agree on length");
        assert_eq!(&bulk[..bulk_len], &stepped[..stepped_len], "and on bytes");

        // Both read paths over the same buffer.
        let mut peeking = BitReader::new(&bulk[..bulk_len]);
        peeking.read_bits(lead_bits).unwrap();
        peeking.align().unwrap();
        let peeked = peeking.peek_bytes(payload.len()).unwrap().to_vec();
        peeking.skip_bytes(payload.len()).unwrap();

        let mut reading = BitReader::new(&bulk[..bulk_len]);
        reading.read_bits(lead_bits).unwrap();
        reading.align().unwrap();
        let read: Vec<u8> = (0..payload.len())
            .map(|_| reading.read_bits(8).unwrap() as u8)
            .collect();

        assert_eq!(peeked, payload);
        assert_eq!(read, payload);
        assert_eq!(
            peeking.bits_read(),
            reading.bits_read(),
            "skip_bytes must advance as far as the equivalent reads"
        );
    }
}

#[test]
fn reader_never_panics_on_garbage() {
    let mut rng = Rng::new(0xFEED_FACE_D00D_1234);

    for _ in 0..50_000 {
        let len = rng.below(48) as usize;
        let buffer: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let mut r = BitReader::new(&buffer);

        for _ in 0..30 {
            match rng.below(6) {
                0 => {
                    let _ = r.read_bits(rng.below(33) as u32);
                }
                1 => {
                    let _ = r.read_bool();
                }
                2 => {
                    let min = (rng.next() as u32) >> 4;
                    let max = min.saturating_add((rng.next() as u32) >> 4);
                    let _ = r.read_range(min, max);
                }
                3 => {
                    let _ = r.align();
                }
                4 => {
                    let _ = r.peek_bytes(rng.below(64) as usize);
                }
                _ => {
                    let _ = r.skip_bytes(rng.below(64) as usize);
                }
            }
        }
    }
}

#[test]
fn write_bytes_rejects_an_overlong_run() {
    let mut buffer = [0u8; 8];
    let mut w = BitWriter::new(&mut buffer);

    w.write_bits(0xFF, 8).unwrap();
    let before = w.bits_remaining();

    assert_eq!(w.write_bytes(&[0u8; 8]), Err(WriteError::Overflow));
    assert_eq!(w.bits_remaining(), before, "a rejected run consumes nothing");

    w.write_bytes(&[1, 2, 3, 4, 5, 6, 7]).unwrap();
    assert_eq!(w.bits_remaining(), 0);
}

#[test]
fn peek_bytes_refuses_unaligned_and_overlong() {
    let buffer = [0xAAu8; 4];
    let mut r = BitReader::new(&buffer);

    r.read_bits(3).unwrap();
    assert_eq!(r.peek_bytes(1), None, "unaligned peek must refuse");

    r.align().unwrap();
    assert_eq!(r.peek_bytes(3), Some(&buffer[1..4]));
    assert_eq!(r.peek_bytes(4), None, "a peek past the end must refuse");
    assert_eq!(r.skip_bytes(4), Err(ReadError::Eof));
}

#[test]
fn range_rejects_values_the_bit_width_allows() {
    // Range 0..=4 needs three bits, which can encode 7. A hand-crafted packet
    // can contain that; the reader must not hand it back.
    let mut buffer = [0u8; 4];
    let mut w = BitWriter::new(&mut buffer);
    w.write_bits(7, 3).unwrap();
    let len = w.finish();

    assert_eq!(
        BitReader::new(&buffer[..len]).read_range(0, 4),
        Err(ReadError::OutOfRange)
    );
}

#[test]
fn write_range_rejects_out_of_range_values() {
    let mut buffer = [0u8; 4];
    let mut w = BitWriter::new(&mut buffer);

    assert_eq!(w.write_range(101, 0, 100), Err(WriteError::OutOfRange));
    assert_eq!(w.write_range(4, 5, 9), Err(WriteError::OutOfRange));
    assert_eq!(w.bits_remaining(), 32, "rejected writes consume nothing");
}

#[test]
fn signed_ranges_round_trip_at_the_extremes() {
    let bounds = [
        i32::MIN,
        i32::MIN + 1,
        -1000,
        -17,
        -1,
        0,
        1,
        15,
        1000,
        i32::MAX - 1,
        i32::MAX,
    ];

    for &min in &bounds {
        for &max in &bounds {
            if min > max {
                continue;
            }
            for &value in &bounds {
                let mut buffer = [0u8; 8];
                let mut w = BitWriter::new(&mut buffer);
                let result = w.write_range_i32(value, min, max);

                if (min <= value) && (value <= max) {
                    result.unwrap();
                    let len = w.finish();
                    assert_eq!(BitReader::new(&buffer[..len]).read_range_i32(min, max), Ok(value));
                } else {
                    assert_eq!(result, Err(WriteError::OutOfRange));
                }
            }
        }
    }
}

#[test]
fn bits_required_matches_the_highest_set_bit() {
    assert_eq!(bits_required(0), 0);
    assert_eq!(bits_required(1), 1);
    assert_eq!(bits_required(4), 3);
    assert_eq!(bits_required(100), 7);
    assert_eq!(bits_required(255), 8);
    assert_eq!(bits_required(256), 9);
    assert_eq!(bits_required(u32::MAX), 32);
}
