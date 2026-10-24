//! 32 bit rANS implementation.
//!
//! Speedwise it is similar to the arithmetic encoders despite
//! having to reverse the symbols on encoding. The advantage of rANS is that it can be written
//! into a buffer in parallel, which can be useful for multiplexing multiple streams into a single buffer.
use std::{
    collections::VecDeque,
    io::{Read, Result, Write},
    num::{NonZeroU8, NonZeroU32},
};

use bytemuck::cast_slice;

use crate::{
    traits::{CabacReader, CabacWriter},
    vp8::VP8Context,
};

trait WriteU16 {
    fn write_u16(&mut self, value: u16);
}

impl WriteU16 for VecDeque<u16> {
    fn write_u16(&mut self, value: u16) {
        self.push_front(u16::to_le(value));
    }
}

/// reads a u16 from the reader in little endian format
#[inline]
fn read_u16(r: &mut impl Read) -> Result<u16> {
    let mut b = [0; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}

/// Rans32State is a 32 bit rANS state.
/// The SCALE_BITS is the number of bits of resolution needed.
#[derive(Clone, Copy)]
struct Rans32State<const SCALE_BITS: u32>(u32);

impl<const SCALE_BITS: u32> std::fmt::Debug for Rans32State<SCALE_BITS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

const RANS_WORD_L: u32 = 1 << 16; // Lower bound of our normalization interval

impl<const SCALE_BITS: u32> Rans32State<SCALE_BITS> {
    #[inline]
    fn new_encoder() -> Self {
        Rans32State(RANS_WORD_L)
    }

    /// Initializes a rANS decoder.
    #[inline]
    fn new_decoder(source: &mut impl Read) -> Result<Self> {
        Ok(Rans32State(
            u32::from(read_u16(source)?) | (u32::from(read_u16(source)?) << 16),
        ))
    }

    /// Flushes the rANS encoder.
    #[inline]
    fn enc_flush(&mut self, buffer: &mut impl WriteU16) {
        let x = self.0;

        buffer.write_u16((x >> 16) as u16);
        buffer.write_u16((x >> 0) as u16);
    }

    // Returns the current cumulative frequency.
    #[inline]
    fn dec_get(&self) -> u32 {
        self.0 & ((1u32 << SCALE_BITS) - 1)
    }

    // Advances in the bit stream by "popping" a single symbol.
    #[inline]
    fn dec_advance(&mut self, source: &mut impl Read, start: u32, freq: NonZeroU32) -> Result<()> {
        let mask = (1u32 << SCALE_BITS) - 1;

        // s, x = D(x)
        let mut x = self.0;
        x = freq.get() * (x >> SCALE_BITS) + (x & mask) - start;

        // Renormalize
        if x < RANS_WORD_L {
            x = (x << 16) | u32::from(read_u16(source)?);
            debug_assert!(x >= RANS_WORD_L);
        }

        self.0 = x;
        Ok(())
    }

    /// Encodes a single symbol
    #[inline]
    fn encode(&mut self, output: &mut impl WriteU16, start: u32, freq: NonZeroU32) {
        let mut x = self.0;
        let x_max = ((RANS_WORD_L >> SCALE_BITS) << 16) * u32::from(freq);

        if x >= x_max {
            output.write_u16(x as u16);
            x >>= 16;
            debug_assert!(x < x_max);
        }

        self.0 = (x / freq) << SCALE_BITS | (x % freq) + start;
    }

    /// Encodes 2 symbols in parallel
    #[inline]
    fn encode_2(
        output: &mut impl WriteU16,
        v: [(&mut Rans32State<SCALE_BITS>, u32, NonZeroU32); 2],
    ) {
        let freq0 = v[0].2;
        let freq1 = v[1].2;

        let start0 = v[0].1;
        let start1 = v[1].1;

        let mut x0 = v[0].0.0;
        let mut x1 = v[1].0.0;
        let x_max_0 = ((RANS_WORD_L >> SCALE_BITS) << 16) * u32::from(freq0);
        let x_max_1 = ((RANS_WORD_L >> SCALE_BITS) << 16) * u32::from(freq1);

        if x0 >= x_max_0 {
            output.write_u16(x0 as u16);
            x0 >>= 16;
        }
        if x1 >= x_max_1 {
            output.write_u16(x1 as u16);
            x1 >>= 16;
        }

        v[0].0.0 = (x0 / freq0) << SCALE_BITS | (x0 % freq0) + start0;
        v[1].0.0 = (x1 / freq1) << SCALE_BITS | (x1 % freq1) + start1;
    }
}

#[derive(Copy, Clone)]
struct Symbol {
    bit: bool,
    prob: NonZeroU8,
}

impl Default for Symbol {
    fn default() -> Self {
        Symbol {
            bit: false,
            prob: NonZeroU8::new(128).unwrap(),
        }
    }
}

const STACK_SIZE: usize = 16386;

pub struct RansWriter32<W> {
    upstream_writer: W,
    symbol_buffer: Box<[Symbol; STACK_SIZE]>,
    symbol_buffer_stack: usize,
}

impl<W: Write> RansWriter32<W> {
    pub fn new(writer: W) -> Self {
        RansWriter32 {
            upstream_writer: writer,
            symbol_buffer: Box::new([Symbol::default(); STACK_SIZE]),
            symbol_buffer_stack: STACK_SIZE,
        }
    }

    #[cold]
    fn flush(&mut self) -> Result<()> {
        let mut rans0 = Rans32State::<8>::new_encoder();
        let mut rans1 = Rans32State::<8>::new_encoder();

        let mut write_buffer: VecDeque<u16> = VecDeque::new();

        assert!(self.symbol_buffer_stack < STACK_SIZE);

        let mut i = self.symbol_buffer_stack;
        let odd = i & 1 != 0;

        // if we had an odd number of bits, then we need to encode the first one,
        // and then swap the rans states so that we can encode the rest aligned
        if odd {
            let s0 = self.symbol_buffer[i];
            let (start, freq) = start_freq(s0.bit, s0.prob);
            rans0.encode(&mut write_buffer, start, freq);
            i += 1;

            std::mem::swap(&mut rans0, &mut rans1);
        }

        while i < STACK_SIZE {
            let s0 = self.symbol_buffer[i];
            let (start0, freq0) = start_freq(s0.bit, s0.prob);
            let s1 = self.symbol_buffer[i + 1];
            let (start1, freq1) = start_freq(s1.bit, s1.prob);

            Rans32State::<8>::encode_2(
                &mut write_buffer,
                [(&mut rans0, start0, freq0), (&mut rans1, start1, freq1)],
            );
            i += 2;
        }

        rans0.enc_flush(&mut write_buffer);
        rans1.enc_flush(&mut write_buffer);

        let slices = write_buffer.as_slices();

        self.upstream_writer.write_all(cast_slice(&slices.0))?;
        self.upstream_writer.write_all(cast_slice(&slices.1))?;

        self.symbol_buffer_stack = STACK_SIZE;
        Ok(())
    }
}

impl<W: Write> CabacWriter<VP8Context> for RansWriter32<W> {
    fn put(&mut self, bit: bool, branch: &mut VP8Context) -> Result<()> {
        let prob = branch.get_probability();
        let b = branch.record_and_update_bit(bit);

        if self.symbol_buffer_stack == 0 {
            self.flush()?;
        }

        *branch = b;
        self.symbol_buffer_stack -= 1;
        self.symbol_buffer[self.symbol_buffer_stack] = Symbol { bit, prob };
        Ok(())
    }

    fn put_bypass(&mut self, bit: bool) -> Result<()> {
        if self.symbol_buffer_stack == 0 {
            self.flush()?;
        }

        self.symbol_buffer_stack -= 1;
        self.symbol_buffer[self.symbol_buffer_stack] = Symbol {
            bit,
            prob: NonZeroU8::new(128).unwrap(),
        };
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        self.flush()
    }
}

#[inline]
fn start_freq(bit: bool, prob: NonZeroU8) -> (u32, NonZeroU32) {
    if bit {
        (
            prob.get() as u32,
            NonZeroU32::new(256 - u32::from(prob.get())).unwrap(),
        )
    } else {
        (0, NonZeroU32::from(prob))
    }
}

/// implements two parallel RANS readers that alternate
pub struct RansReader32<R> {
    rans0: Rans32State<8>,
    rans1: Rans32State<8>,
    upstream_reader: R,
    bits_read: usize,
}

impl<R: Read> RansReader32<R> {
    pub fn new(mut reader: R) -> Result<Self> {
        let rans0 = Rans32State::new_decoder(&mut reader)?;
        let rans1 = Rans32State::new_decoder(&mut reader)?;
        Ok(RansReader32 {
            rans0,
            rans1,
            upstream_reader: reader,
            bits_read: 0,
        })
    }

    /// sees if we read enough bits to reset the stream to avoid the reverse buffers
    /// from growing too large
    pub fn check_reset_stream(&mut self) -> Result<()> {
        if self.bits_read == STACK_SIZE {
            self.bits_read = 0;
            self.rans0 = Rans32State::new_decoder(&mut self.upstream_reader)?;
            self.rans1 = Rans32State::new_decoder(&mut self.upstream_reader)?;
        }
        self.bits_read += 1;
        Ok(())
    }
}

impl<R: Read> CabacReader<VP8Context> for RansReader32<R> {
    /// reads a bit and then swaps the rans states
    fn get(&mut self, branch: &mut VP8Context) -> Result<bool> {
        self.check_reset_stream()?;

        let mut local_state = self.rans0;
        self.rans0 = self.rans1;

        let prob = branch.get_probability();

        let cumulative_freq = local_state.dec_get();

        let bit = cumulative_freq >= u32::from(prob.get());

        let b = branch.record_and_update_bit(bit);
        let (start, freq) = start_freq(bit, prob);
        local_state.dec_advance(&mut self.upstream_reader, start, freq)?;

        *branch = b;
        self.rans1 = local_state;
        Ok(bit)
    }

    /// reads a bit without updating the probability
    fn get_bypass(&mut self) -> Result<bool> {
        self.check_reset_stream()?;

        let mut local_state = self.rans0;
        self.rans0 = self.rans1;

        let start = local_state.0 & 0x80;

        local_state.dec_advance(
            &mut self.upstream_reader,
            start,
            NonZeroU32::new(128).unwrap(),
        )?;

        self.rans1 = local_state;
        Ok(start != 0)
    }
}
