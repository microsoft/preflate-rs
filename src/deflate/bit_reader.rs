/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use std::io::{Error, ErrorKind, Read, Result, Seek};

use byteorder::ReadBytesExt;

pub trait ReadBits {
    fn get(&mut self, cbit: u32) -> Result<u32>;
    fn read_padding_bits(&mut self) -> u8;
    fn read_byte(&mut self) -> Result<u8>;
    fn bits_left(&self) -> u32;
}

/// BitReader reads a variable number of bits from a byte stream.
pub struct BitReader {
    bits_read: u32,
    bit_count: u32,
}

pub struct BitReaderWrapper<'a, R: Read> {
    bit_reader: &'a mut BitReader,
    byte_reader: &'a mut R,
}

impl<R: Read> BitReaderWrapper<'_, R> {
    pub fn new<'a>(
        bit_reader: &'a mut BitReader,
        byte_reader: &'a mut R,
    ) -> BitReaderWrapper<'a, R> {
        BitReaderWrapper {
            bit_reader,
            byte_reader,
        }
    }
}

impl<R: Read> ReadBits for BitReaderWrapper<'_, R> {
    fn get(&mut self, cbit: u32) -> Result<u32> {
        BitReader::get(self.bit_reader, cbit, self.byte_reader)
    }

    fn read_padding_bits(&mut self) -> u8 {
        self.bit_reader.read_padding_bits()
    }

    fn read_byte(&mut self) -> Result<u8> {
        self.bit_reader.read_byte(self.byte_reader)
    }

    fn bits_left(&self) -> u32 {
        self.bit_reader.bits_left()
    }
}

impl BitReader {
    pub fn new() -> Self {
        BitReader {
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
        R: Read + Seek,
        F: FnOnce(&mut BitReaderWrapper<R>) -> core::result::Result<ROK, RERR>,
    >(
        &mut self,
        byte_reader: &mut R,
        f: F,
    ) -> core::result::Result<ROK, RERR> {
        let prev_pos = byte_reader.seek(std::io::SeekFrom::Current(0)).unwrap();
        let prev_bits_read = self.bits_read;
        let prev_bit_count = self.bit_count;

        let r = f(&mut BitReaderWrapper::new(self, byte_reader));
        match r {
            Ok(result) => {
                return Ok(result);
            }
            Err(e) => {
                byte_reader
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

    pub fn read_byte(&mut self, byte_reader: &mut impl Read) -> Result<u8> {
        debug_assert!(self.bit_count == 0, "BitReader Error: Attempt to read bytes without first calling FlushBufferToByteBoundary");

        let result = byte_reader.read_u8()?;

        Ok(result)
    }

    /// Read cbit bits from the input stream return
    /// Only supports read of 1 to 32 bits.
    pub fn get(&mut self, cbit: u32, byte_reader: &mut impl Read) -> Result<u32> {
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
            let b = byte_reader.read_u8()? as u32;

            self.bits_read |= b << self.bit_count;
            self.bit_count += 8;
        }

        wret = self.bits_read & ((1 << cbit) - 1);

        self.bits_read >>= cbit;
        self.bit_count -= cbit;

        Ok(wret)
    }
}
