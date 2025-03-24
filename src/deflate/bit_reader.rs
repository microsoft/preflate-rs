/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use std::io::{BufRead, Error, Result};

use byteorder::ReadBytesExt;

pub trait ReadBits {
    fn get(&mut self, cbit: u32, reader: &mut impl BufRead) -> Result<u32>;
    fn peek_byte(&self) -> u8;
    fn bits_left(&self) -> u32;
    fn consume(&mut self, cbit: u32);
}

/// BitReader reads a variable number of bits from a byte stream.
#[derive(Debug, Clone)]
pub struct BitReader {
    bits: u64,
    bits_left: u32,
    read_ahead: u32,
}

impl BitReader {
    pub fn new() -> Self {
        BitReader {
            bits: 0,
            bits_left: 0,
            read_ahead: 0,
        }
    }

    /// reads the bits until the next byte boundary
    pub fn read_padding_bits(&mut self) -> u8 {
        let cbit = self.bits_left & 7;

        let wret = self.bits & ((1 << cbit) - 1);

        self.bits >>= cbit;
        self.bits_left -= cbit;

        wret as u8
    }

    pub fn consume_read(&mut self, reader: &mut impl BufRead) {
        while self.bits_left >= 8 && self.read_ahead > 0 {
            self.bits_left -= 8;
            self.read_ahead -= 1;
        }

        self.bits = self.bits & ((1 << self.bits_left) - 1);

        if self.read_ahead > 0 {
            reader.consume(self.read_ahead as usize);
            self.read_ahead = 0;
        }
    }

    #[cold]
    fn fill_register(
        &mut self,
        cbit: u32,
        reader: &mut impl BufRead,
        mask: u64,
    ) -> std::result::Result<u32, Error> {
        reader.consume(self.read_ahead as usize);
        self.read_ahead = 0;

        let buffer = reader.fill_buf()?;
        if buffer.len() > 8 {
            let mut i = 0;
            while self.bits_left <= 56 {
                let b = buffer[i] as u64;

                self.bits |= b << self.bits_left;
                self.bits_left += 8;
                i += 1;
            }

            self.read_ahead = i as u32;

            let w = self.bits & mask;
            self.bits >>= cbit;
            self.bits_left -= cbit;

            return Ok(w as u32);
        }

        while self.bits_left < cbit {
            let b = reader.read_u8()? as u64;

            self.bits |= b << self.bits_left;
            self.bits_left += 8;
        }

        let wret = self.bits & ((1 << cbit) - 1);

        self.bits >>= cbit;
        self.bits_left -= cbit;

        Ok(wret as u32)
    }
}

impl ReadBits for BitReader {
    fn bits_left(&self) -> u32 {
        self.bits_left & 7
    }

    fn consume(&mut self, cbit: u32) {
        self.bits >>= cbit;
        self.bits_left -= cbit;
    }

    fn peek_byte(&self) -> u8 {
        self.bits as u8
    }

    /// Read cbit bits from the input stream return
    /// Only supports read of 1 to 32 bits.
    #[inline]
    fn get(&mut self, cbit: u32, reader: &mut impl BufRead) -> Result<u32> {
        let mask = (1u64 << cbit) - 1;

        if cbit < self.bits_left {
            let wret = self.bits & mask;

            self.bits >>= cbit;
            self.bits_left -= cbit;

            return Ok(wret as u32);
        }

        self.fill_register(cbit, reader, mask)
    }
}
