use std::{
    collections::VecDeque,
    io::{BufRead, Read, Write},
};

use crate::Result;

/// writes the pending output to the writer
pub fn write_dequeue(
    pending_output: &mut VecDeque<u8>,
    writer: &mut impl Write,
    max_output_write: usize,
) -> Result<usize> {
    if pending_output.len() > 0 {
        let slices = pending_output.as_mut_slices();

        let mut amount_written = 0;
        let len = slices.0.len().min(max_output_write);
        writer.write_all(&slices.0[..len])?;
        amount_written += len;

        if amount_written < max_output_write {
            let len = slices.1.len().min(max_output_write - amount_written);
            writer.write_all(&slices.1[..len])?;
            amount_written += len;
        }

        pending_output.drain(..amount_written);
        Ok(amount_written)
    } else {
        Ok(0)
    }
}

/// A BufRead implementation that reads at most `limit` bytes from the underlying reader.
pub struct TakeReader<T> {
    inner: T,
    amount_left: usize,
}

impl<T> TakeReader<T> {
    pub fn new(inner: T, limit: usize) -> Self {
        TakeReader {
            inner,
            amount_left: limit,
        }
    }
}

impl<T: BufRead + Read> BufRead for TakeReader<T> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        let buf = self.inner.fill_buf()?;
        Ok(&buf[..buf.len().min(self.amount_left)])
    }

    fn consume(&mut self, amt: usize) {
        self.amount_left -= amt;
        self.inner.consume(amt);
    }
}

impl<T: Read> Read for TakeReader<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = buf.len().min(self.amount_left);
        let read = self.inner.read(&mut buf[..len])?;
        self.amount_left -= read;
        Ok(read)
    }
}

#[allow(dead_code)]
#[cfg(test)]
pub fn write_file(filename: &str, data: &[u8]) {
    let filename = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("samples")
        .join(filename);

    let mut writecomp = std::fs::File::create(filename).unwrap();
    std::io::Write::write_all(&mut writecomp, data).unwrap();
}

#[cfg(test)]
pub fn read_file(filename: &str) -> Vec<u8> {
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

    let filename = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("samples")
        .join(filename);
    println!("reading {0}", filename.to_str().unwrap());
    let mut f = File::open(filename).unwrap();

    let mut content = Vec::new();
    f.read_to_end(&mut content).unwrap();

    content
}

/// handy function to compare two arrays, and print the first mismatch. Useful for debugging.
#[cfg(test)]
#[track_caller]
pub fn assert_eq_array<T: PartialEq + std::fmt::Debug>(a: &[T], b: &[T]) {
    use core::panic;

    if a.len() != b.len() {
        for i in 0..std::cmp::min(a.len(), b.len()) {
            assert_eq!(
                a[i],
                b[i],
                "length mismatch {},{} and first mismatch at offset {}",
                a.len(),
                b.len(),
                i
            );
        }
        panic!(
            "length mismatch {} and {}, but common prefix identical",
            a.len(),
            b.len()
        );
    } else {
        for i in 0..a.len() {
            assert_eq!(
                a[i],
                b[i],
                "length identical {}, but first mismatch at offset {}",
                a.len(),
                i
            );
        }
    }
}

#[cfg(test)]
#[track_caller]
pub fn assert_block_eq(
    a: &crate::deflate::deflate_token::DeflateTokenBlock,
    b: &crate::deflate::deflate_token::DeflateTokenBlock,
) {
    use crate::deflate::deflate_token::DeflateTokenBlockType;

    if a == b {
        return;
    }

    if std::mem::discriminant(&a.block_type) != std::mem::discriminant(&b.block_type) {
        panic!("block type mismatch {:?} {:?}", a.block_type, b.block_type);
    }

    match (&a.block_type, &b.block_type) {
        (
            DeflateTokenBlockType::Huffman {
                tokens: ta,
                huffman_type: ha,
            },
            DeflateTokenBlockType::Huffman {
                tokens: tb,
                huffman_type: hb,
            },
        ) => {
            assert_eq_array(&ta, &tb);
            assert_eq!(ha, hb);
        }
        (
            DeflateTokenBlockType::Stored { uncompressed: ua },
            DeflateTokenBlockType::Stored { uncompressed: ub },
        ) => {
            assert_eq_array(&ua, &ub);
        }
        _ => {
            panic!("unexpected block type");
        }
    }
    assert_eq!(a.last, b.last, "last flag mismatch");
}

#[cfg(test)]
pub fn test_on_all_deflate_files(f: impl Fn(&[u8])) {
    use std::io::Read;

    let searchpath = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("samples");

    for entry in std::fs::read_dir(searchpath).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.extension().is_some() && path.extension().unwrap() == "deflate" {
            println!("Testing {:?}", path);

            let mut file = std::fs::File::open(&path).unwrap();
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer).unwrap();

            f(&buffer);
        }
    }
}
