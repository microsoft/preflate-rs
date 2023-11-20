/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use std::io::{Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};

pub trait ReadBits {
    fn get(&mut self, cbit: u32) -> anyhow::Result<u32>;
}

pub struct ZipBitReader<'a, R> {
    binary_reader: &'a mut R,
    max_readable_bytes: i64, // Data can be read up to and including this position. Use to detect corruption. If negative no checking is done
    count_of_bits_in_buffer: u32, // Number of bits in m_returnValueBuffer
    return_value_buffer: u64, // Buffer used to assemble bits for the caller
}

impl<'a, R: Read + Seek> ReadBits for ZipBitReader<'_, R> {
    fn get(&mut self, cbit: u32) -> anyhow::Result<u32> {
        ZipBitReader::get(self, cbit)
    }
}

impl<'a, R: Read + Seek> ZipBitReader<'a, R> {
    pub fn new(binary_reader: &'a mut R, max_readable_bytes: i64) -> Self {
        ZipBitReader {
            binary_reader,
            max_readable_bytes,
            count_of_bits_in_buffer: 0,
            return_value_buffer: 0,
        }
    }

    /// Call to Ensure the buffer populated with at least 1 bit from the current
    fn ensure_buffer(&mut self) -> anyhow::Result<()> {
        if self.count_of_bits_in_buffer == 0 {
            if self.max_readable_bytes >= 8 {
                self.return_value_buffer = self.binary_reader.read_u64::<LittleEndian>()?;
                self.count_of_bits_in_buffer = 64;
                self.max_readable_bytes -= 8;
                return Ok(());
            }

            if self.max_readable_bytes >= 4 {
                self.return_value_buffer = self.binary_reader.read_u32::<LittleEndian>()? as u64;
                self.count_of_bits_in_buffer = 32;
                self.max_readable_bytes -= 4;
                return Ok(());
            }

            if self.max_readable_bytes >= 2 {
                self.return_value_buffer = self.binary_reader.read_u16::<LittleEndian>()? as u64;
                self.count_of_bits_in_buffer = 16;
                self.max_readable_bytes -= 2;
                return Ok(());
            }

            if self.max_readable_bytes == 0 {
                return Err(anyhow::Error::msg(
                    "BitReader Error: Attempt to read past end of range",
                ));
            }

            self.max_readable_bytes -= 1;
            self.return_value_buffer = self.binary_reader.read_u8()? as u64;
            self.count_of_bits_in_buffer = 8;
        }

        Ok(())
    }

    /// Clear out the buffer and reset the position to the byte after the "current" position. Tricky since we may have more than 8 bits buffered.
    pub fn flush_buffer_to_byte_boundary(&mut self) -> anyhow::Result<()> {
        if self.count_of_bits_in_buffer == 0 {
            // BaseStream is at the correct Position nothing to do in this case
            return Ok(());
        }

        // Reset the BaseStream Position to the next whole byte boundary based on current stream position and number of bits in the buffer
        // if the number of bits left is from 1-7 we are positioned correctly
        // if the number of bits left is from 8-15 we want to back up 1 byte
        // if the number of bits left is from 16 - 23 we wantto back up 2 bytes
        // if the number of bits left si from 24 - 31 we want to back up 3 bytes
        let number_of_bytes_to_seek_back = self.count_of_bits_in_buffer / 8;
        self.binary_reader.seek(SeekFrom::Current(
            -(number_of_bytes_to_seek_back as i32) as i64,
        ))?;
        self.max_readable_bytes += number_of_bytes_to_seek_back as i64;
        self.count_of_bits_in_buffer = 0;

        Ok(())
    }

    pub fn bit_position_in_current_byte(&self) -> u32 {
        8 - (self.count_of_bits_in_buffer % 8)
    }

    pub fn read_byte(&mut self) -> anyhow::Result<u8> {
        if self.count_of_bits_in_buffer != 0 {
            return Err(anyhow::Error::msg("BitReader Error: Attempt to read bytes without first calling FlushBufferToByteBoundary"));
        }

        self.max_readable_bytes -= 1;
        let result = self.binary_reader.read_u8()?;
        Ok(result)
    }

    /// Read cbit bits from the input stream return
    /// Only supports read of 1 to 32 bits.
    pub fn get(&mut self, cbit: u32) -> anyhow::Result<u32> {
        let mut wret: u32 = 0;
        let mut cbits_added = 0;

        if cbit == 0 {
            return Ok(wret);
        }

        if cbit > 32 {
            return Err(anyhow::Error::msg(
                "BitReader Error: Attempt to read more than 32 bits",
            ));
        }

        while cbits_added < cbit {
            let cbits_needed = cbit - cbits_added;

            // Ensure the buffer is has at least 1 bit in it.
            if self.count_of_bits_in_buffer == 0 {
                self.ensure_buffer()?;
            }

            // Calc number of bits we can take from the buffer
            let cbits_from_buffer = std::cmp::min(cbits_needed, self.count_of_bits_in_buffer);

            // make room in return buffer for bits and insert them in the buffer
            wret |= ((self.return_value_buffer & !(u64::MAX << cbits_from_buffer)) << cbits_added)
                as u32;
            // Update the buffer state to reflect the bits that have been read
            self.return_value_buffer >>= cbits_from_buffer;
            self.count_of_bits_in_buffer -= cbits_from_buffer;

            // Update the running count of bits added so far.
            cbits_added += cbits_from_buffer;
        }

        Ok(wret)
    }
}
