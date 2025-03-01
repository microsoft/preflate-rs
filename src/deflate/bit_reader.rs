/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use std::io::{Error, ErrorKind, Read, Result, Seek};

use byteorder::ReadBytesExt;

pub trait ReadBits {
    fn get(&mut self, cbit: u32) -> Result<u32>;
}

/// BitReader reads a variable number of bits from a byte stream.
pub struct BitReader<R: Read + Seek> {
    binary_reader: R,
    bits_read: u32,
    bit_count: u32,
}

impl<R: Read + Seek> ReadBits for BitReader<R> {
    fn get(&mut self, cbit: u32) -> Result<u32> {
        BitReader::get(self, cbit)
    }
}

impl<R: Read + Seek> BitReader<R> {
    pub fn new(binary_reader: R) -> Self {
        BitReader {
            binary_reader,
            bits_read: 0,
            bit_count: 0,
        }
    }

    /// runs a function that reads from the bit stream and rolls back if an error ocurrs. This
    /// is useful if we have complicated parsing code that needs to abort if the buffer is not yet full.
    #[inline(always)]
    pub fn run_with_rollback<
        ROK,
        RERR,
        F: FnOnce(&mut BitReader<R>) -> core::result::Result<ROK, RERR>,
    >(
        &mut self,
        f: F,
    ) -> core::result::Result<ROK, RERR> {
        let prev_pos = self
            .binary_reader
            .seek(std::io::SeekFrom::Current(0))
            .unwrap();
        let prev_bits_read = self.bits_read;
        let prev_bit_count = self.bit_count;

        let r = f(self);
        match r {
            Ok(result) => {
                return Ok(result);
            }
            Err(e) => {
                self.binary_reader
                    .seek(std::io::SeekFrom::Start(prev_pos))
                    .unwrap();
                self.bits_read = prev_bits_read;
                self.bit_count = prev_bit_count;
                return Err(e);
            }
        }
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
