use std::{
    collections::VecDeque,
    io::{Cursor, Error, ErrorKind, Read, Result, SeekFrom},
};

pub trait ScopedRead: Read {
    fn peek(&self, position: usize) -> Result<u8>;
    fn advance(&mut self, amount: usize);
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
