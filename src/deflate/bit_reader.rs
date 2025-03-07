/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use std::io::{Error, ErrorKind, Read, Result};

use byteorder::ReadBytesExt;

pub trait ReadBits {
    fn get(&mut self, cbit: u32) -> Result<u32>;
}

/// BitReader reads a variable number of bits from a byte stream.
pub struct BitReader<R: Read> {
    bits_read: u32,
    bit_count: u32,
    bytes_read: u32,
    inner: R,
}

impl<R: Read> BitReader<R> {
    pub fn new(inner: R) -> Self {
        BitReader {
            bits_read: 0,
            bit_count: 0,
            bytes_read: 0,
            inner: inner,
        }
    }

    #[allow(dead_code)]
    pub fn get_inner_mut(&mut self) -> &mut R {
        &mut self.inner
    }
}

impl<R: Read> BitReader<R> {
    pub fn bytes_read(&self) -> u32 {
        self.bytes_read
    }
    pub fn bits_left(&self) -> u32 {
        self.bit_count
    }

    /// reads the bits until the next byte boundary
    pub fn read_padding_bits(&mut self) -> u8 {
        let cbit = self.bit_count & 7;

        let wret = self.bits_read & ((1 << cbit) - 1);

        self.bits_read >>= cbit;
        self.bit_count -= cbit;

        wret as u8
    }

    pub fn read_byte(&mut self) -> Result<u8> {
        debug_assert!(self.bit_count == 0, "BitReader Error: Attempt to read bytes without first calling FlushBufferToByteBoundary");

        let result = self.inner.read_u8()?;

        self.bytes_read += 1;

        Ok(result)
    }
}

impl<R: Read> ReadBits for BitReader<R> {
    /// Read cbit bits from the input stream return
    /// Only supports read of 1 to 32 bits.
    fn get(&mut self, cbit: u32) -> Result<u32> {
        if cbit == 0 {
            return Ok(0);
        }

        if cbit > 24 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "BitReader Error: Attempt to read more than 24 bits",
            ));
        }

        while self.bit_count < cbit {
            let b = self.inner.read_u8()? as u32;

            self.bits_read |= b << self.bit_count;
            self.bit_count += 8;
            self.bytes_read += 1;
        }

        let wret = self.bits_read & ((1 << cbit) - 1);

        self.bits_read >>= cbit;
        self.bit_count -= cbit;

        Ok(wret)
    }
}
