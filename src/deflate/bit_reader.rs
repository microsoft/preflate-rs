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
pub struct BitReader<R> {
    binary_reader: R,
    bits_read: u32,
    bit_count: u32,
}

impl<R: Read> ReadBits for BitReader<R> {
    fn get(&mut self, cbit: u32) -> Result<u32> {
        BitReader::get(self, cbit)
    }
}

impl<R: Read> BitReader<R> {
    pub fn new(binary_reader: R) -> Self {
        BitReader {
            binary_reader,
            bits_read: 0,
            bit_count: 0,
        }
    }

    pub fn bits_left(&self) -> u32 {
        self.bit_count
    }

    pub fn read_byte(&mut self) -> Result<u8> {
        assert!(self.bit_count == 0, "BitReader Error: Attempt to read bytes without first calling FlushBufferToByteBoundary");

        let result = self.binary_reader.read_u8()?;
        Ok(result)
    }

    /// Read cbit bits from the input stream return
    /// Only supports read of 1 to 32 bits.
    pub fn get(&mut self, cbit: u32) -> Result<u32> {
        let mut wret: u32 = 0;

        if cbit == 0 {
            return Ok(wret);
        }

        if cbit > 32 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "BitReader Error: Attempt to read more than 32 bits",
            ));
        }

        while self.bit_count < cbit {
            let b = self.binary_reader.read_u8()? as u32;
            self.bits_read |= b << self.bit_count;
            self.bit_count += 8;
        }

        wret = self.bits_read & ((1 << cbit) - 1);

        self.bits_read >>= cbit;
        self.bit_count -= cbit;

        Ok(wret)
    }
}
