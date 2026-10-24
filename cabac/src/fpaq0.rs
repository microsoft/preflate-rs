//! Implementation of the FPAQ0 algorithm.
//!
//! This arithmetic encoder has an advange over other arithmetic encoders since it *does not require carry propagation*, which
//! simplifies the output, and also means that the output can be written byte by byte, and even written in
//! parallel (i.e. multiple threads writing to the same output buffer) with some minor modifications (see fpaq0parallel).
//!
//! The history of this algorithm is a bit complicated. The method for reducing range to avoid carry is was original
//! described by:
//!
//! F. Rubin, "Arithmetic Stream Coding Using Fixed Precision Registers",
//! IEEE Trans. Information Theory IT-25 (6) (1979), p. 672 - 675
//!
//! This was then rediscovered by Ilia Muraviev and Matt Mahoney in <https://mattmahoney.net/dc/fpaq0.cpp>
use crate::{
    traits::{CabacReader, CabacWriter},
    vp8::VP8Context,
};
use std::io::{Read, Result, Write};

/// Implementation of a binary arithmetic decoder based on the FPAQ0 algorithm.
pub struct Fpaq0Decoder<R> {
    inner_reader: R,
    xl: u32,
    xr: u32,
    x: u32,
}

impl<R: Read> Fpaq0Decoder<R> {
    pub fn new(mut reader: R) -> Result<Self> {
        let mut x: u32 = 0;
        for _ in 0..4 {
            let mut b = [0u8];
            let _ = reader.read(&mut b)?;

            x = (x << 8) | u32::from(b[0]);
        }

        Ok(Fpaq0Decoder {
            inner_reader: reader,
            xl: 0,
            xr: 0xffff_ffff,
            x,
        })
    }

    fn fill_bits(
        xl: &mut u32,
        xr: &mut u32,
        x: &mut u32,
        inner_reader: &mut impl Read,
    ) -> Result<()> {
        while 0 == ((*xl ^ *xr) & 0xFF00_0000) {
            *xl <<= 8;
            *xr = (*xr << 8) | 0x0000_00FF;

            let mut b = [0u8];
            let _ = inner_reader.read_exact(&mut b)?;

            *x = (*x << 8) | u32::from(b[0]);
        }
        Ok(())
    }
}

impl<R: Read> CabacReader<VP8Context> for Fpaq0Decoder<R> {
    fn get_bypass(&mut self) -> Result<bool> {
        let mut xl = self.xl;
        let mut xr = self.xr;

        let xm = xl + (((xr - xl) & 0xffffff00) >> 1);
        let mut bit = true;
        if self.x <= xm {
            bit = false;
            xr = xm;
        } else {
            xl = xm + 1;
        }

        Self::fill_bits(&mut xl, &mut xr, &mut self.x, &mut self.inner_reader)?;

        self.xl = xl;
        self.xr = xr;

        Ok(bit)
    }

    fn get(&mut self, cur_ctx: &mut VP8Context) -> Result<bool> {
        let mut xl = self.xl;
        let mut xr = self.xr;
        let mut x = self.x;

        let xm = xl + ((xr - xl) >> 8) * u32::from(cur_ctx.get_probability().get());

        let mut bit = true;
        if x <= xm {
            xr = xm;
            bit = false;
        } else {
            xl = xm + 1;
        }

        let b = cur_ctx.record_and_update_bit(bit);

        Self::fill_bits(&mut xl, &mut xr, &mut x, &mut self.inner_reader)?;

        *cur_ctx = b;
        self.xl = xl;
        self.xr = xr;
        self.x = x;

        Ok(bit)
    }
}

pub struct Fpaq0Encoder<W> {
    inner_writer: W,
    xl: u32,
    xr: u32,
}

/// Implementation of a binary arithmetic decoder based on the FPAQ0 algorithm.
impl<W: Write> Fpaq0Encoder<W> {
    pub fn new(writer: W) -> Self {
        Fpaq0Encoder {
            inner_writer: writer,
            xl: 0,
            xr: 0xffff_ffff,
        }
    }

    fn flush_bits(xl: &mut u32, xr: &mut u32, inner_writer: &mut impl Write) -> Result<()> {
        while 0 == ((*xl ^ *xr) & 0xFF00_0000) {
            let byte = (*xr >> 24) as u8;
            inner_writer.write_all(&[byte])?;
            *xl <<= 8;
            *xr = (*xr << 8) | 0x0000_00FF;
        }
        Ok(())
    }
}

impl<W: Write> CabacWriter<VP8Context> for Fpaq0Encoder<W> {
    fn put(&mut self, bit: bool, branch: &mut VP8Context) -> Result<()> {
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

        Self::flush_bits(&mut xl, &mut xr, &mut self.inner_writer)?;

        self.xl = xl;
        self.xr = xr;
        *branch = b;

        Ok(())
    }

    fn put_bypass(&mut self, bit: bool) -> Result<()> {
        let mut xl = self.xl;
        let mut xr = self.xr;

        let xm = xl + (((xr - xl) & 0xffffff00) >> 1);

        // left/lower part of the interval corresponds to zero

        if !bit {
            xr = xm;
        } else {
            xl = xm + 1;
        }

        Self::flush_bits(&mut xl, &mut xr, &mut self.inner_writer)?;

        self.xl = xl;
        self.xr = xr;

        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        let byte = (self.xr >> 24) as u8;
        self.inner_writer.write_all(&[byte])?;
        self.inner_writer.write_all(&[0, 0, 0])
    }
}
