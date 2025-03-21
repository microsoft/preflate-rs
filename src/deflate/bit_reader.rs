/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use std::io::{Error, ErrorKind, Read, Result};

use byteorder::ReadBytesExt;

pub trait ReadBits {
    fn get(&mut self, cbit: u32, reader: &mut impl Read) -> Result<u32>;
}

/// BitReader reads a variable number of bits from a byte stream.
#[derive(Debug, Clone)]
pub struct BitReader {
    bits: u32,
    bits_left: u32,
}

impl BitReader {
    pub fn new() -> Self {
        BitReader {
            bits: 0,
            bits_left: 0,
        }
    }

    pub fn bits_left(&self) -> u32 {
        self.bits_left
    }

    /// reads the bits until the next byte boundary
    pub fn read_padding_bits(&mut self) -> u8 {
        let cbit = self.bits_left & 7;

        let wret = self.bits & ((1 << cbit) - 1);

        self.bits >>= cbit;
        self.bits_left -= cbit;

        wret as u8
    }

    pub fn read_byte(&mut self, reader: &mut impl Read) -> Result<u8> {
        debug_assert!(self.bits_left == 0);
        let r = reader.read_u8()?;
        Ok(r)
    }
}

impl ReadBits for BitReader {
    /// Read cbit bits from the input stream return
    /// Only supports read of 1 to 32 bits.
    fn get(&mut self, cbit: u32, reader: &mut impl Read) -> Result<u32> {
        if cbit == 0 {
            return Ok(0);
        }

        if cbit > 24 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "BitReader Error: Attempt to read more than 24 bits",
            ));
        }

        while self.bits_left < cbit {
            let b = reader.read_u8()? as u32;

            self.bits |= b << self.bits_left;
            self.bits_left += 8;
        }

        let wret = self.bits & ((1 << cbit) - 1);

        self.bits >>= cbit;
        self.bits_left -= cbit;

        Ok(wret)
    }
}
