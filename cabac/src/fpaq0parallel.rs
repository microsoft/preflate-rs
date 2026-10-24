//! Special version of FPaq0 that allows for parallel encoding and decoding.
//!
//! There is some overhead on the encoding side since we need to track the future output byte
//! locations so that the reader can read them back without any
//! special signalling.
//!
//! Original algorithm developed by Matt Mahoney <https://mattmahoney.net/dc/fpaq0.cpp>
//!
//! I like this implementation since it has no carry processing compared to other arithmetic encoders and the bytes
//! align exactly with reads and writes. This makes it especially suitable for this kind of parallel encoding and decoding.
//!
//! As long as you exactly match your puts and gets, you can even put bytes in the middle of the stream, as long
//! as you read them back in the same order.
//!
//! This gives you many of the advantages of rANS decoding without the need to do everything in reverse, and also
//! the encoding doesn't require any divide/mod ops like rANS does. It does require a bit more memory with the future
//! buffer, but as long as the use of the contexts is fairly balanced, it should be a good tradeoff. ie don't do this:
//!
//!  for i in 0..100000 {
//!   context1.put(bit, &mut output);
//!  }
//!  context2.put(bit,&mut output);
//!
//! Parallelization implements the idea from:
//! P. G. Howard, "Interleaving entropy codes," Proceedings. Compression and Complexity of SEQUENCES 1997
//!  (Cat. No.97TB100171), Salerno, Italy, 1997, pp. 45-55, doi: 10.1109/SEQUEN.1997.666902.

#[cfg(feature = "simd")]
use wide::u32x4;

use crate::vp8::VP8Context;

use std::{
    collections::VecDeque,
    io::{Read, Result, Write},
};

/// This holds the output and stitches together the future output in the right
/// order so that the reader can read it back without any special signalling.
///
/// This is implementation doesn't work well  if the encoders are not very well balanced
/// since it does a linear search to find the right location to write the byte.
///
/// However, in balanced cases this is faster than the bookkeeping required to avoid the
/// linear search.
pub struct ParallelEncoderOutput<W> {
    /// the next id of the encoder that is attached to this output. Each encoder
    /// gets a unique id so that we can keep track of the future output of that encoder.
    next_id: u8,

    /// the future output that cannot yet be written because the next byte hasn't been
    /// decided on.
    future_output: VecDeque<u16>,

    /// the writer that we flush to once we have decided on the next byte
    output: W,
}

impl<W: Write> ParallelEncoderOutput<W> {
    pub fn new(output: W) -> Self {
        ParallelEncoderOutput {
            next_id: 0,
            future_output: VecDeque::new(),
            output,
        }
    }

    /// writes a byte to the steam in its reserved location. If repush is true, it will
    /// reserve a new location for the next byte.
    ///
    /// Don't inline this because otherwise the compiler will not be able to use
    /// as many registers in the hot loop.
    #[cold]
    fn flush_byte<const REPUSH: bool>(&mut self, byte: u8, id: u8) -> Result<()> {
        let slices = self.future_output.as_mut_slices();
        assert!(!slices.0.is_empty());

        let mut first_iter = slices.0.iter_mut();

        if *first_iter.next().unwrap() == id as u16 {
            // if the first item is the one we are looking for, then we can write it
            // together along with the rest of the output that has been decided.
            let _ = self.future_output.pop_front().unwrap();
            if REPUSH {
                self.future_output.push_back(id as u16);
            }

            self.output.write_all(&[byte])?;

            while let Some(&x) = self.future_output.front() {
                if (x & 0x100) == 0 {
                    break;
                }
                let _ = self.future_output.pop_front();

                self.output.write_all(&[x as u8])?;
            }
        } else {
            // otherwise we need to find a location to write the byte in the future
            // and then push a new location at the end of the stack

            while let Some(v) = first_iter.next() {
                if *v == id as u16 {
                    *v = byte as u16 | 0x100;
                    if REPUSH {
                        self.future_output.push_back(id as u16);
                    }
                    return Ok(());
                }
            }

            for v in slices.1 {
                if *v == id as u16 {
                    *v = byte as u16 | 0x100;

                    if REPUSH {
                        self.future_output.push_back(id as u16);
                    }
                    return Ok(());
                }
            }

            panic!("id not found in future output");
        }

        Ok(())
    }

    /// writes a byte to the output stream in such a position that it can be
    /// read back by the decoder without any special signalling as long
    /// as it is done in the same order as it was written
    pub fn write_bypass_byte(&mut self, byte: u8) -> Result<()> {
        if self.future_output.is_empty() {
            self.output.write_all(&[byte])?;
        } else {
            self.future_output.push_back(byte as u16 | 0x100);
        }

        Ok(())
    }
}

/// This encoder writes whole bits and can be used to write bits to the stream where probability doesn't help.
pub struct BypassBitEncoder {
    id: u8,
    b: u8,
    bits_written: usize,
}

impl BypassBitEncoder {
    pub fn new<W: Write>(output: &mut ParallelEncoderOutput<W>) -> Self {
        assert!(output.next_id < 255, "too many encoders on the same output");
        let id = output.next_id;
        output.next_id += 1;

        output.future_output.push_back(id as u16);

        BypassBitEncoder {
            id,
            b: 0,
            bits_written: 0,
        }
    }

    /// writes a bit to the stream
    pub fn put<W: Write>(
        &mut self,
        bit: bool,
        writer: &mut ParallelEncoderOutput<W>,
    ) -> Result<()> {
        if self.bits_written == 8 {
            writer.flush_byte::<true>(self.b, self.id)?;
            self.b = 0;
            self.bits_written = 0;
        }

        self.b |= (bit as u8) << self.bits_written;
        self.bits_written += 1;

        Ok(())
    }

    /// flushes any remaining bits
    pub fn finish<W: Write>(&mut self, writer: &mut ParallelEncoderOutput<W>) -> Result<()> {
        writer.flush_byte::<false>(self.b, self.id)?;

        Ok(())
    }
}

/// counterpart to BypassBitEncoder that reads the bits back
pub struct BypassBitDecoder {
    b: u8,
    bits_left: usize,
}

impl BypassBitDecoder {
    pub fn new(reader: &mut impl Read) -> Result<Self> {
        let mut buf = [0u8];
        reader.read_exact(&mut buf)?;

        Ok(BypassBitDecoder {
            b: buf[0],
            bits_left: 8,
        })
    }

    /// reads a bit from the stream
    pub fn get<R: Read>(&mut self, reader: &mut R) -> Result<bool> {
        if self.bits_left == 0 {
            let mut buf = [0u8];
            reader.read_exact(&mut buf)?;
            self.b = buf[0];
            self.bits_left = 8;
        }

        let bit = (self.b & 1) != 0;
        self.b >>= 1;
        self.bits_left -= 1;

        Ok(bit)
    }
}

/// Encodes a bitstream using a context aware binary arithmetic encoder. Multiple encoders can be used
/// on the same bitstream and the bits will be interleaved in such a way that they can be read back
/// without any special signalling.
pub struct Fpaq0EncoderParallel {
    xl: u32,
    xr: u32,
    id: u8,
}

impl std::fmt::Debug for Fpaq0EncoderParallel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Fpaq0Encoder {{ xl: {:x}, xr: {:x} }}", self.xl, self.xr)
    }
}

impl Fpaq0EncoderParallel {
    /// creates new encoder and attaches it to the output stream
    pub fn new<W: Write>(output: &mut ParallelEncoderOutput<W>) -> Self {
        // we flush 4 bytes at the beginning to make sure that we can read the first four bytes when the
        // encoder starts
        assert!(output.next_id < 255, "too many encoders on the same output");
        let id = output.next_id;
        output.next_id += 1;

        for _i in 0..4 {
            output.future_output.push_back(id as u16);
        }

        Fpaq0EncoderParallel {
            xl: 0,
            xr: 0xffff_ffff,
            id,
        }
    }

    fn flush_bits<W: Write>(
        &mut self,
        writer: &mut ParallelEncoderOutput<W>,
        xl: &mut u32,
        xr: &mut u32,
    ) -> Result<()> {
        while 0 == ((*xl ^ *xr) & 0xFF00_0000) {
            let byte = (*xr >> 24) as u8;

            writer.flush_byte::<true>(byte, self.id)?;

            *xl <<= 8;
            *xr = (*xr << 8) | 0x0000_00FF;
        }
        Ok(())
    }

    /// puts bit into the stream given a certain probability context
    pub fn put<W: Write>(
        &mut self,
        bit: bool,
        branch: &mut VP8Context,
        writer: &mut ParallelEncoderOutput<W>,
    ) -> Result<()> {
        let mut xl = self.xl;
        let mut xr = self.xr;

        let xm = xl + ((xr - xl) >> 8) * u32::from(branch.get_probability().get());

        // left/lower part of the interval corresponds to zero

        if !bit {
            xr = xm;
        } else {
            xl = xm + 1;
        }

        let b = branch.record_and_update_bit(bit);

        self.flush_bits(writer, &mut xl, &mut xr)?;

        *branch = b;
        self.xl = xl;
        self.xr = xr;
        Ok(())
    }

    /// flushes any outstanding bits into the stream
    pub fn finish<W: Write>(&mut self, writer: &mut ParallelEncoderOutput<W>) -> Result<()> {
        let mut byte = (self.xr >> 24) as u8;

        for _ in 0..4 {
            writer.flush_byte::<false>(byte, self.id)?;
            byte = 0;
        }

        Ok(())
    }
}

/// Decodes a byte stream encoded by Fpaq0EncoderParallel
pub struct Fpaq0DecoderParallel {
    xl: u32,
    xr: u32,
    x: u32,
}

impl std::fmt::Debug for Fpaq0DecoderParallel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Fpaq0Decoder {{ xl: {:x}, xr: {:x}, x: {:x} }}",
            self.xl, self.xr, self.x
        )
    }
}

impl Fpaq0DecoderParallel {
    pub fn new(reader: &mut impl Read) -> Result<Self> {
        let mut x: u32 = 0;
        for _ in 0..4 {
            let mut b = [0u8];
            let _ = reader.read_exact(&mut b)?;

            x = (x << 8) | u32::from(b[0]);
        }

        Ok(Fpaq0DecoderParallel {
            xl: 0,
            xr: 0xffff_ffff,
            x,
        })
    }

    fn fill_bits(&mut self, xl: &mut u32, xr: &mut u32, reader: &mut impl Read) -> Result<()> {
        while 0 == ((*xl ^ *xr) & 0xFF00_0000) {
            *xl <<= 8;
            *xr = (*xr << 8) | 0x0000_00FF;

            let mut b = [0u8];
            let _ = reader.read_exact(&mut b)?;

            self.x = (self.x << 8) | u32::from(b[0]);
        }
        Ok(())
    }

    /// reads a bit from the stream given a certain probability context
    pub fn get(&mut self, cur_ctx: &mut VP8Context, reader: &mut impl Read) -> Result<bool> {
        let mut xl = self.xl;
        let mut xr = self.xr;

        let xm = xl + ((xr - xl) >> 8) * u32::from(cur_ctx.get_probability().get());
        let mut bit = true;
        if self.x <= xm {
            bit = false;
            xr = xm;
        } else {
            xl = xm + 1;
        }

        let c = cur_ctx.record_and_update_bit(bit);

        self.fill_bits(&mut xl, &mut xr, reader)?;

        *cur_ctx = c;
        self.xl = xl;
        self.xr = xr;

        Ok(bit)
    }
}

/// Decodes a byte stream encoded by Fpaq0EncoderParallel
#[cfg(feature = "simd")]
pub struct Fpaq0DecoderParallelSimd {
    xl: u32x4,
    xr: u32x4,
    x: u32x4,
}

#[cfg(feature = "simd")]
impl std::fmt::Debug for Fpaq0DecoderParallelSimd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Fpaq0Decoder {{ xl: {:x}, xr: {:x}, x: {:x} }}",
            self.xl, self.xr, self.x
        )
    }
}

#[cfg(feature = "simd")]
fn bitmask(x: u32x4) -> u32 {
    let x: wide::i32x4 = bytemuck::cast(x);
    x.move_mask() as u32
}

#[cfg(feature = "simd")]
impl Fpaq0DecoderParallelSimd {
    pub fn new(reader: &mut impl Read) -> Result<Self> {
        let mut x = [0u32; 4];
        for i in 0..4 {
            for _ in 0..4 {
                let mut b = [0u8];
                let _ = reader.read_exact(&mut b)?;

                x[i] = (x[i] << 8) | u32::from(b[0]);
            }
        }

        Ok(Fpaq0DecoderParallelSimd {
            xl: u32x4::splat(0),
            xr: u32x4::splat(0xffff_ffff),
            x: u32x4::from(x),
        })
    }

    #[inline]
    fn fill_bits(
        &mut self,
        xlw: &mut u32x4,
        xrw: &mut u32x4,
        reader: &mut impl Read,
    ) -> Result<()> {
        let c = (*xlw ^ *xrw).cmp_gt(u32x4::splat(0x00FF_FFFF));
        let bm = bitmask(c);
        if bm == 15 {
            return Ok(());
        }

        for i in 0..4 {
            if bm & (1 << i) != 0 {
                continue;
            }

            let mut xl = xlw.as_array_ref()[i];
            let mut xr = xrw.as_array_ref()[i];
            let mut x = self.x.as_array_ref()[i];

            loop {
                if (xl ^ xr) > 0x00FF_FFFF {
                    break;
                }

                xl <<= 8;
                xr = (xr << 8) | 0x0000_00FF;

                let mut b = [0u8];
                let _ = reader.read_exact(&mut b)?;

                x = (x << 8) | u32::from(b[0]);
            }

            xlw.as_array_mut()[i] = xl;
            xrw.as_array_mut()[i] = xr;
            self.x.as_array_mut()[i] = x;
        }
        Ok(())
    }

    /// reads a bit from the stream given a certain probability context
    #[inline(always)]
    pub fn get(&mut self, cur_ctx: &mut [VP8Context; 4], reader: &mut impl Read) -> Result<u32> {
        let xm: u32x4 = self.xl
            + ((self.xr - self.xl) >> 8)
                * u32x4::from([
                    u32::from(cur_ctx[0].get_probability().get()),
                    u32::from(cur_ctx[1].get_probability().get()),
                    u32::from(cur_ctx[2].get_probability().get()),
                    u32::from(cur_ctx[3].get_probability().get()),
                ]);

        let cmp = xm.cmp_lt(self.x);

        let mut xrw = cmp.blend(self.xr, xm);
        let mut xlw = cmp.blend(xm + 1, self.xl);

        VP8Context::record_and_update_bit_wide(cur_ctx, cmp);

        let bitmask = bitmask(cmp);

        self.fill_bits(&mut xlw, &mut xrw, reader)?;

        self.xl = xlw;
        self.xr = xrw;

        Ok(bitmask)
    }
}

#[test]
fn bypass_byte() {
    use byteorder::ReadBytesExt;

    let mut outputbuffer = Vec::new();
    let mut output = ParallelEncoderOutput::new(&mut outputbuffer);

    {
        let mut context = VP8Context::default();

        let mut encoder = Fpaq0EncoderParallel::new(&mut output);
        for i in 0i32..1024 {
            if i > 10 && i < 20 {
                output.write_bypass_byte(i as u8).unwrap();
            }
            encoder
                .put((i % 47) != 0, &mut context, &mut output)
                .unwrap();
        }

        encoder.finish(&mut output).unwrap();
        assert!(output.future_output.is_empty());
    }

    {
        let mut context = VP8Context::default();
        let mut reader = std::io::Cursor::new(&outputbuffer);

        let mut decoder = Fpaq0DecoderParallel::new(&mut reader).unwrap();
        for i in 0..1024i32 {
            if i > 10 && i < 20 {
                assert_eq!(reader.read_u8().unwrap(), i as u8);
            }
            assert_eq!(
                decoder.get(&mut context, &mut reader).unwrap(),
                (i % 47) != 0
            );
        }
    }
}

#[test]
fn bypass_encoder() {
    let mut outputbuffer = Vec::new();
    let mut output = ParallelEncoderOutput::new(&mut outputbuffer);

    let mut encoder = BypassBitEncoder::new(&mut output);

    for i in 0..999 {
        encoder.put(i % 3 == 0, &mut output).unwrap();
    }

    encoder.finish(&mut output).unwrap();

    let mut reader = std::io::Cursor::new(&outputbuffer);

    let mut decoder = BypassBitDecoder::new(&mut reader).unwrap();

    for i in 0..999 {
        assert_eq!(decoder.get(&mut reader).unwrap(), i % 3 == 0);
    }
}

#[test]
fn bypass_dual() {
    let mut output = ParallelEncoderOutput::new(Vec::new());
    {
        let mut context1 = VP8Context::default();
        let mut context2 = VP8Context::default();
        let mut context3 = VP8Context::default();

        let mut encoder1 = Fpaq0EncoderParallel::new(&mut output);
        let mut encoder2 = Fpaq0EncoderParallel::new(&mut output);
        let mut encoder3 = Fpaq0EncoderParallel::new(&mut output);
        let mut encoder4 = BypassBitEncoder::new(&mut output);

        for i in 0i32..1024 {
            encoder1
                .put((i % 47) != 0, &mut context1, &mut output)
                .unwrap();
            encoder2
                .put(i % 3 != 0, &mut context2, &mut output)
                .unwrap();
            encoder3
                .put(i % 5 != 0, &mut context3, &mut output)
                .unwrap();
            encoder4.put(i % 7 != 0, &mut output).unwrap();
        }

        encoder1.finish(&mut output).unwrap();
        encoder2.finish(&mut output).unwrap();
        encoder3.finish(&mut output).unwrap();
        encoder4.finish(&mut output).unwrap();

        // nothing should be left to write
        assert!(output.future_output.is_empty());
    }

    {
        let mut context1 = VP8Context::default();
        let mut context2 = VP8Context::default();
        let mut context3 = VP8Context::default();

        let mut reader = std::io::Cursor::new(&output.output);

        let mut decoder1 = Fpaq0DecoderParallel::new(&mut reader).unwrap();
        let mut decoder2 = Fpaq0DecoderParallel::new(&mut reader).unwrap();
        let mut decoder3 = Fpaq0DecoderParallel::new(&mut reader).unwrap();
        let mut decoder4 = BypassBitDecoder::new(&mut reader).unwrap();

        for i in 0..1024 {
            assert_eq!(
                decoder1.get(&mut context1, &mut reader).unwrap(),
                (i % 47) != 0
            );
            assert_eq!(
                decoder2.get(&mut context2, &mut reader).unwrap(),
                (i % 3) != 0
            );
            assert_eq!(
                decoder3.get(&mut context3, &mut reader).unwrap(),
                (i % 5) != 0
            );
            assert_eq!(decoder4.get(&mut reader).unwrap(), (i % 7) != 0, "i:{}", i);
        }
    }
}

#[cfg(feature = "simd")]
#[test]
fn simd_test() {
    let mut output = ParallelEncoderOutput::new(Vec::new());
    {
        let mut context = [
            VP8Context::default(),
            VP8Context::default(),
            VP8Context::default(),
            VP8Context::default(),
        ];
        let mut encoders = [
            Fpaq0EncoderParallel::new(&mut output),
            Fpaq0EncoderParallel::new(&mut output),
            Fpaq0EncoderParallel::new(&mut output),
            Fpaq0EncoderParallel::new(&mut output),
        ];

        for i in 0i32..10240 {
            encoders[0]
                .put((i % 47) != 0, &mut context[0], &mut output)
                .unwrap();
            encoders[1]
                .put(i % 3 != 0, &mut context[1], &mut output)
                .unwrap();
            encoders[2]
                .put(i % 5 != 0, &mut context[2], &mut output)
                .unwrap();
            encoders[3]
                .put(i % 7 != 0, &mut context[3], &mut output)
                .unwrap();
        }

        for i in 0..4 {
            encoders[i].finish(&mut output).unwrap();
        }

        // nothing should be left to write
        assert!(output.future_output.is_empty());
    }

    {
        let mut context = [
            VP8Context::default(),
            VP8Context::default(),
            VP8Context::default(),
            VP8Context::default(),
        ];

        let mut reader = std::io::Cursor::new(&output.output);

        let mut decoder = Fpaq0DecoderParallelSimd::new(&mut reader).unwrap();

        for i in 0..10240 {
            let bits = decoder.get(&mut context, &mut reader).unwrap();

            assert_eq!(bits & 1 != 0, (i % 47) != 0);
            assert_eq!(bits & 2 != 0, (i % 3) != 0);
            assert_eq!(bits & 4 != 0, (i % 5) != 0);
            assert_eq!(bits & 8 != 0, (i % 7) != 0);
        }
    }
}
