//! Bit-level serialization.
//!
//! The writer packs values into the fewest bits they need. The reader is the
//! only code that parses attacker-controlled data: it bounds-checks every
//! read, returns errors rather than panicking, and rejects values outside
//! their declared range.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteError {
    /// Not enough space left in the buffer.
    Overflow,
    /// The value lies outside the range it was declared with.
    OutOfRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    /// Fewer bits remain than the read requires.
    Eof,
    /// The decoded value lies outside its declared range.
    OutOfRange,
}

/// A position in the bit stream, for undoing a partial write.
#[derive(Debug, Clone, Copy)]
pub struct Checkpoint(usize);

/// Bits needed to represent any value from 0 to `range` inclusive.
#[inline]
pub const fn bits_required(range: u32) -> u32 {
    32 - range.leading_zeros()
}

/// Appends values to a caller-provided buffer.
///
/// Bits are packed least-significant first, and complete 32-bit words are
/// flushed little-endian, so stream bit k always lands at byte k / 8.
pub struct BitWriter<'a> {
    buf: &'a mut [u8],
    /// Bits not yet flushed, occupying the low `scratch_bits` positions.
    /// Everything above them is zero, which is what makes the OR in
    /// `write_bits` act as placement rather than merging.
    scratch: u64,
    /// Always below 32 between calls.
    scratch_bits: u32,
    /// Byte offset the pending word will flush to.
    word_index: usize,
    bits_written: usize,
}

impl<'a> BitWriter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            scratch: 0,
            scratch_bits: 0,
            word_index: 0,
            bits_written: 0,
        }
    }

    #[inline]
    pub fn bits_remaining(&self) -> usize {
        (self.buf.len() * 8) - self.bits_written
    }

    #[inline]
    pub fn bits_written(&self) -> usize {
        self.bits_written
    }

    /// Writes the low `bits` of `value`. A failed write consumes nothing.
    #[inline]
    pub fn write_bits(&mut self, value: u32, bits: u32) -> Result<(), WriteError> {
        debug_assert!(bits <= 32);
        if (bits as usize) > self.bits_remaining() {
            return Err(WriteError::Overflow);
        }

        // Masking in u64 keeps bits == 32 correct, where a u32 shift would
        // overflow.
        let value = (value as u64) & ((1u64 << bits) - 1);
        self.scratch |= value << self.scratch_bits;
        self.scratch_bits += bits;
        self.bits_written += bits as usize;

        // At most one flush is ever needed: fewer than 32 bits were pending
        // and at most 32 were added.
        if self.scratch_bits >= 32 {
            let word = (self.scratch as u32).to_le_bytes();
            self.buf[self.word_index..(self.word_index + 4)].copy_from_slice(&word);
            self.scratch >>= 32;
            self.scratch_bits -= 32;
            self.word_index += 4;
        }
        Ok(())
    }

    #[inline]
    pub fn write_bool(&mut self, value: bool) -> Result<(), WriteError> {
        self.write_bits(value as u32, 1)
    }

    #[inline]
    pub fn write_u64(&mut self, value: u64) -> Result<(), WriteError> {
        self.write_bits(value as u32, 32)?;
        self.write_bits((value >> 32) as u32, 32)?;
        Ok(())
    }

    /// Writes `value` as an offset from `min`, sized to the width of the
    /// range. The range itself is not transmitted, so the reader must supply
    /// the same bounds.
    #[inline]
    pub fn write_range(&mut self, value: u32, min: u32, max: u32) -> Result<(), WriteError> {
        debug_assert!(min <= max);
        let range = max - min;
        // Wrapping subtraction makes a value below `min` exceed `range`, so one
        // comparison covers both bounds.
        let offset = value.wrapping_sub(min);
        if offset > range {
            return Err(WriteError::OutOfRange);
        }
        self.write_bits(offset, bits_required(range))
    }

    /// Signed form of `write_range`. Two's complement makes the offset
    /// arithmetic identical once both bounds are read as unsigned.
    #[inline]
    pub fn write_range_i32(&mut self, value: i32, min: i32, max: i32) -> Result<(), WriteError> {
        debug_assert!(min <= max);
        let range = (max as u32).wrapping_sub(min as u32);
        let offset = (value as u32).wrapping_sub(min as u32);
        if offset > range {
            return Err(WriteError::OutOfRange);
        }
        self.write_bits(offset, bits_required(range))
    }

    /// Pads with zeros to the next byte boundary.
    pub fn align(&mut self) -> Result<(), WriteError> {
        let pad = (8 - ((self.bits_written % 8) as u32)) % 8;
        self.write_bits(0, pad)
    }

    /// Copies whole bytes at the current position, which must be byte-aligned.
    ///
    /// Moves the payload as a block rather than eight bits at a time, which is
    /// what makes large messages and fragments cheap to write.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), WriteError> {
        debug_assert_eq!(self.bits_written % 8, 0, "write_bytes requires alignment");
        if (bytes.len() * 8) > self.bits_remaining() {
            return Err(WriteError::Overflow);
        }
        if bytes.is_empty() {
            return Ok(());
        }

        // Commit the pending partial word so the buffer is current up to this
        // position, then write past it directly.
        self.flush_partial();
        let at = self.bits_written / 8;
        self.buf[at..(at + bytes.len())].copy_from_slice(bytes);
        self.bits_written += bytes.len() * 8;

        // Rebuild the writer's position from the new bit offset. A run ending
        // mid-word leaves bytes the next flush would overwrite, so they are
        // pulled back into scratch.
        self.word_index = (self.bits_written / 32) * 4;
        self.scratch_bits = (self.bits_written % 32) as u32;
        self.scratch = 0;
        if self.scratch_bits != 0 {
            let mut word = [0u8; 4];
            let take = (self.buf.len() - self.word_index).min(4);
            word[..take].copy_from_slice(&self.buf[self.word_index..(self.word_index + take)]);
            self.scratch = (u32::from_le_bytes(word) as u64) & ((1u64 << self.scratch_bits) - 1);
        }
        Ok(())
    }

    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint(self.bits_written)
    }

    /// Discards everything written after `cp`.
    ///
    /// Only the bit position is stored: every full word is flushed as soon as
    /// it completes, so the position determines the rest of the writer state.
    pub fn rollback(&mut self, cp: Checkpoint) {
        let pos = cp.0;
        assert!(pos <= self.bits_written, "checkpoint is ahead of the writer");

        let word_index = (pos / 32) * 4;
        let scratch_bits = (pos % 32) as u32;

        if word_index < self.word_index {
            let mut word = [0u8; 4];
            let take = (self.buf.len() - word_index).min(4);
            word[..take].copy_from_slice(&self.buf[word_index..(word_index + take)]);
            self.scratch = u32::from_le_bytes(word) as u64;
        }

        // Restores the invariant that everything above the pending bits is zero.
        self.scratch &= (1u64 << scratch_bits) - 1;
        self.scratch_bits = scratch_bits;
        self.word_index = word_index;
        self.bits_written = pos;
    }

    /// Writes the pending partial word without consuming the writer.
    fn flush_partial(&mut self) {
        let tail_bytes = (self.scratch_bits as usize).div_ceil(8);
        if tail_bytes == 0 {
            return;
        }
        let tail = (self.scratch as u32).to_le_bytes();
        self.buf[self.word_index..self.word_index + tail_bytes].copy_from_slice(&tail[..tail_bytes]);
    }

    /// Flushes the trailing partial word. Returns the length in bytes.
    pub fn finish(mut self) -> usize {
        self.flush_partial();
        self.bits_written.div_ceil(8)
    }
}

/// Reads values written by `BitWriter`. Every failure is an error.
pub struct BitReader<'a> {
    buffer: &'a [u8],
    scratch: u64,
    scratch_bits: u32,
    byte_index: usize,
    bits_read: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self {
            buffer,
            scratch: 0,
            scratch_bits: 0,
            byte_index: 0,
            bits_read: 0,
        }
    }

    #[inline]
    pub fn bits_remaining(&self) -> usize {
        (self.buffer.len() * 8) - self.bits_read
    }

    #[inline]
    pub fn bits_read(&self) -> usize {
        self.bits_read
    }

    #[inline]
    pub fn read_bits(&mut self, bits: u32) -> Result<u32, ReadError> {
        debug_assert!(bits <= 32);
        if (bits as usize) > self.bits_remaining() {
            return Err(ReadError::Eof);
        }

        while self.scratch_bits < bits {
            if (self.byte_index + 4) <= self.buffer.len() {
                let mut word = [0u8; 4];
                word.copy_from_slice(&self.buffer[self.byte_index..(self.byte_index + 4)]);
                self.scratch |= (u32::from_le_bytes(word) as u64) << self.scratch_bits;
                self.scratch_bits += 32;
                self.byte_index += 4;
            } else {
                // Packet lengths are not multiples of four, so the tail is taken
                // a byte at a time.
                self.scratch |= (self.buffer[self.byte_index] as u64) << self.scratch_bits;
                self.scratch_bits += 8;
                self.byte_index += 1;
            }
        }

        let value = (self.scratch & ((1u64 << bits) - 1)) as u32;
        self.scratch >>= bits;
        self.scratch_bits -= bits;
        self.bits_read += bits as usize;
        Ok(value)
    }

    #[inline]
    pub fn read_bool(&mut self) -> Result<bool, ReadError> {
        Ok(self.read_bits(1)? != 0)
    }

    #[inline]
    pub fn read_u64(&mut self) -> Result<u64, ReadError> {
        let lo = self.read_bits(32)? as u64;
        let hi = self.read_bits(32)? as u64;
        Ok(lo | (hi << 32))
    }

    /// Reads a value written by `write_range`.
    ///
    /// A field's bit width can encode values above its range, so the decoded
    /// offset is checked before it reaches anything that treats it as an index
    /// or a discriminant.
    #[inline]
    pub fn read_range(&mut self, min: u32, max: u32) -> Result<u32, ReadError> {
        let range = max - min;
        let offset = self.read_bits(bits_required(range))?;
        if offset > range {
            return Err(ReadError::OutOfRange);
        }
        Ok(min + offset)
    }

    #[inline]
    pub fn read_range_i32(&mut self, min: i32, max: i32) -> Result<i32, ReadError> {
        let range = (max as u32).wrapping_sub(min as u32);
        let offset = self.read_bits(bits_required(range))?;
        if offset > range {
            return Err(ReadError::OutOfRange);
        }
        Ok((min as u32).wrapping_add(offset) as i32)
    }

    pub fn align(&mut self) -> Result<(), ReadError> {
        let pad = (8 - ((self.bits_read % 8) as u32)) % 8;
        self.read_bits(pad).map(|_| ())
    }

    /// Borrows `len` bytes at the current position without copying or
    /// advancing. The position must be byte-aligned.
    ///
    /// Lets a message be handed to the application as a slice of the packet
    /// buffer it arrived in, with no intermediate storage.
    pub fn peek_bytes(&self, len: usize) -> Option<&'a [u8]> {
        if !self.bits_read.is_multiple_of(8) {
            return None;
        }
        let at = self.bits_read / 8;
        self.buffer.get(at..(at + len))
    }

    /// Advances past bytes taken with `peek_bytes`.
    pub fn skip_bytes(&mut self, len: usize) -> Result<(), ReadError> {
        if (len * 8) > self.bits_remaining() {
            return Err(ReadError::Eof);
        }
        self.bits_read += len * 8;
        self.byte_index = self.bits_read / 8;
        self.scratch = 0;
        self.scratch_bits = 0;
        Ok(())
    }
}
