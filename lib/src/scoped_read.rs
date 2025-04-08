use std::{
    collections::VecDeque,
    io::{Cursor, Error, ErrorKind, Read, Result, SeekFrom},
};

use crate::PreflateError;

pub trait ScopedRead: Read
where
    Self: Sized,
{
    fn peek(&self, position: usize) -> Result<u8>;
    fn advance(&mut self, amount: usize);

    fn scoped_read<
        'a,
        T,
        F: FnOnce(&mut ScopedReaderWrapper<Self>) -> core::result::Result<T, PreflateError>,
    >(
        &'a mut self,
        f: F,
    ) -> core::result::Result<T, PreflateError> {
        let mut w = ScopedReaderWrapper {
            inner: self,
            position: 0,
        };
        let r = f(&mut w);
        let inner_pos = w.position;
        match r {
            Ok(t) => {
                self.advance(inner_pos);
                Ok(t)
            }
            Err(e) => Err(e),
        }
    }
}

impl ScopedRead for VecDeque<u8> {
    fn peek(&self, position: usize) -> Result<u8> {
        if position >= self.len() {
            return Err(Error::new(ErrorKind::UnexpectedEof, "Unexpected EOF"));
        }
        Ok(self[position])
    }

    fn advance(&mut self, position: usize) {
        self.drain(0..position);
    }
}

impl<T: AsRef<[u8]>> ScopedRead for Cursor<T> {
    fn peek(&self, position: usize) -> Result<u8> {
        let read_pos = self.position() as usize + position;
        if read_pos >= self.get_ref().as_ref().len() {
            return Err(Error::new(ErrorKind::UnexpectedEof, "Unexpected EOF"));
        }

        Ok(self.get_ref().as_ref()[read_pos])
    }

    fn advance(&mut self, position: usize) {
        std::io::Seek::seek(self, SeekFrom::Current(position as i64)).unwrap();
    }
}

pub struct ScopedReaderWrapper<'a, R: ScopedRead> {
    inner: &'a mut R,
    position: usize,
}

impl<T: ScopedRead> Read for ScopedReaderWrapper<'_, T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut i = 0;
        while i < buf.len() {
            buf[i] = self.inner.peek(self.position)?;
            self.position += 1;
            i += 1;
        }

        Ok(i)
    }
}
