/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use std::{
    collections::VecDeque,
    io::{Cursor, Error, ErrorKind, Read, Result, Seek, SeekFrom},
};

use byteorder::ReadBytesExt;

pub trait ReadBits {
    fn get(&mut self, cbit: u32) -> Result<u32>;
    fn read_padding_bits(&mut self) -> u8;
    fn read_byte(&mut self) -> Result<u8>;
    fn bits_left(&self) -> u32;
}

pub trait ScopedRead: Read {
    fn read_at_position(&self, position: usize) -> Result<u8>;
    fn truncate(&mut self, position: usize);
}

impl ScopedRead for VecDeque<u8> {
    fn read_at_position(&self, position: usize) -> Result<u8> {
        if position >= self.len() {
            return Err(Error::new(ErrorKind::UnexpectedEof, "Unexpected EOF"));
        }
        Ok(self[position])
    }

    fn truncate(&mut self, position: usize) {
        self.drain(0..position);
    }
}

impl<T: AsRef<[u8]>> ScopedRead for Cursor<T> {
    fn read_at_position(&self, position: usize) -> Result<u8> {
        let read_pos = self.position() as usize + position;
        if read_pos >= self.get_ref().as_ref().len() {
            return Err(Error::new(ErrorKind::UnexpectedEof, "Unexpected EOF"));
        }

        Ok(self.get_ref().as_ref()[read_pos])
    }

    fn truncate(&mut self, position: usize) {
        self.seek(SeekFrom::Current(position as i64)).unwrap();
    }
}

/// BitReader reads a variable number of bits from a byte stream.
pub struct BitReader<R: Read> {
    bits_read: u32,
    bit_count: u32,
    bytes_read: u64,
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

    pub fn get_inner_mut(&mut self) -> &mut R {
        &mut self.inner
    }
}

impl<R: Read> BitReader<R> {
    pub fn position(&self) -> u64 {
        self.bytes_read
    }
}

impl<R: Read> ReadBits for BitReader<R> {
    fn bits_left(&self) -> u32 {
        self.bit_count
    }

    /// reads the bits until the next byte boundary
    fn read_padding_bits(&mut self) -> u8 {
        let cbit = self.bit_count & 7;

        let wret = self.bits_read & ((1 << cbit) - 1);

        self.bits_read >>= cbit;
        self.bit_count -= cbit;

        wret as u8
    }

    fn read_byte(&mut self) -> Result<u8> {
        debug_assert!(self.bit_count == 0, "BitReader Error: Attempt to read bytes without first calling FlushBufferToByteBoundary");

        let result = self.inner.read_u8()?;

        self.bytes_read += 1;

        Ok(result)
    }

    /// Read cbit bits from the input stream return
    /// Only supports read of 1 to 32 bits.
    fn get(&mut self, cbit: u32) -> Result<u32> {
        if cbit == 0 {
            return Ok(0);
        }

        if cbit > 32 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "BitReader Error: Attempt to read more than 32 bits",
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

pub struct BitReaderWrapper<'a, R: Read> {
    bit_reader: &'a mut BitReader<R>,
    position: usize,
}

impl<R: ScopedRead> ReadBits for BitReaderWrapper<'_, R> {
    fn get(&mut self, cbit: u32) -> Result<u32> {
        if cbit == 0 {
            return Ok(0);
        }

        if cbit > 32 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "BitReader Error: Attempt to read more than 32 bits",
            ));
        }

        while self.bit_reader.bit_count < cbit {
            let b = self.bit_reader.inner.read_at_position(self.position)? as u32;
            self.position += 1;

            self.bit_reader.bits_read |= b << self.bit_reader.bit_count;
            self.bit_reader.bit_count += 8;
        }

        let wret = self.bit_reader.bits_read & ((1 << cbit) - 1);

        self.bit_reader.bits_read >>= cbit;
        self.bit_reader.bit_count -= cbit;

        Ok(wret)
    }

    fn read_padding_bits(&mut self) -> u8 {
        self.bit_reader.read_padding_bits()
    }

    fn read_byte(&mut self) -> Result<u8> {
        let b = self.bit_reader.inner.read_at_position(self.position)?;
        self.position += 1;
        Ok(b)
    }

    fn bits_left(&self) -> u32 {
        self.bit_reader.bits_left()
    }
}

impl<R: ScopedRead> BitReader<R> {
    pub fn scoped_read<
        'a,
        T,
        E,
        F: FnOnce(&mut BitReaderWrapper<R>) -> core::result::Result<T, E>,
    >(
        &'a mut self,
        f: F,
    ) -> core::result::Result<T, E> {
        let saved_bit_count = self.bit_count;
        let saved_bits_read = self.bits_read;

        let mut w = BitReaderWrapper {
            bit_reader: self,
            position: 0,
        };
        let r = f(&mut w);
        let inner_pos = w.position;
        if r.is_ok() {
            self.inner.truncate(inner_pos);
            self.bytes_read += inner_pos as u64;
        } else {
            // revert back to original without changes
            self.bit_count = saved_bit_count;
            self.bits_read = saved_bits_read;
        }

        r
    }
}
