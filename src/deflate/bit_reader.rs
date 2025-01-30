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

    /// Clear out the buffer and reset the position to the byte after the "current" position. Tricky since we may have more than 8 bits buffered.
    pub fn flush_buffer_to_byte_boundary(&mut self) {
        self.bit_count = 0;
    }

    pub fn bit_position_in_current_byte(&self) -> u32 {
        8 - self.bit_count
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
        let mut cbits_added = 0;

        if cbit == 0 {
            return Ok(wret);
        }

        if cbit > 32 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "BitReader Error: Attempt to read more than 32 bits",
            ));
        }

        while cbits_added < cbit {
            let cbits_needed = cbit - cbits_added;

            // Ensure the buffer is has at least 1 bit in it.
            if self.bit_count == 0 {
                self.bits_read = self.binary_reader.read_u8()? as u32;
                self.bit_count = 8;
            }

            // Calc number of bits we can take from the buffer
            let cbits_from_buffer = std::cmp::min(cbits_needed, self.bit_count);

            // make room in return buffer for bits and insert them in the buffer
            wret |= (self.bits_read & !(u32::MAX << cbits_from_buffer)) << cbits_added;

            // Update the buffer state to reflect the bits that have been read
            self.bits_read >>= cbits_from_buffer;
            self.bit_count -= cbits_from_buffer;

            // Update the running count of bits added so far.
            cbits_added += cbits_from_buffer;
        }

        Ok(wret)
    }
}
