use std::{
    collections::VecDeque,
    io::{BufRead, Read, Write},
};

use preflate_rs::Result;

use crate::ProcessBuffer;

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

struct LimitedOutputWriter<'a> {
    amount_written: usize,
    output_buffer: &'a mut [u8],
    extra_queue: &'a mut VecDeque<u8>,
}

impl Write for LimitedOutputWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let amount_for_output = buf
            .len()
            .min(self.output_buffer.len() - self.amount_written);

        self.output_buffer[self.amount_written..self.amount_written + amount_for_output]
            .copy_from_slice(&buf[..amount_for_output]);
        self.amount_written += amount_for_output;

        if amount_for_output < buf.len() {
            self.extra_queue.extend(&buf[amount_for_output..]);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // nothing to do since we don't buffer anything
        Ok(())
    }
}

/// Processes input data, writing output to the output buffer and any extra to the output_extra queue.
///
/// This is necessary because in the unmanaged wrapper we cannot expand the buffer that was given to us,
/// so we have to write as much as we can to the output buffer and then queue up any extra data for next time.
///
/// This avoids adding complexity to every ProcessBuffer implementation to handle the case where there is too
/// much output to fit in the output buffer.
pub fn process_limited_buffer(
    process: &mut impl ProcessBuffer,
    input: &[u8],
    input_complete: bool,
    output_buffer: &mut [u8],
    output_extra: &mut VecDeque<u8>,
) -> Result<(bool, usize)> {
    // first write any extra data we have pending from last time
    let mut amount_written = 0;
    while amount_written < output_buffer.len() && output_extra.len() > 0 {
        amount_written += output_extra
            .read(&mut output_buffer[amount_written..])
            .unwrap();
    }

    // now call process buffer with the remaining space
    let mut w = LimitedOutputWriter {
        amount_written,
        output_buffer,
        extra_queue: output_extra,
    };
    process.process_buffer(input, input_complete, &mut w)?;

    Ok((w.extra_queue.len() == 0, w.amount_written))
}

#[test]
fn test_process_limited_buffer() {
    let mut p = crate::container_processor::NopProcessBuffer {};

    let input = b"Hello, world!";
    let mut output = [0u8; 5];
    let mut extra = VecDeque::new();

    // first call should write "Hello" and queue up the rest
    let (complete, written) =
        process_limited_buffer(&mut p, input, true, &mut output, &mut extra).unwrap();
    assert!(!complete);
    assert_eq!(written, 5);
    assert_eq!(&output, b"Hello");
    assert_eq!(extra.len(), 8); // ", world!"

    // second call with no input should write the queued data
    let (complete, written) =
        process_limited_buffer(&mut p, &[], true, &mut output, &mut extra).unwrap();
    assert!(!complete);
    assert_eq!(written, 5);
    assert_eq!(&output, b", wor");
    assert_eq!(extra.len(), 3); // "ld!"

    // third call with no input should write the remaining queued data
    let (complete, written) =
        process_limited_buffer(&mut p, &[], true, &mut output, &mut extra).unwrap();
    assert!(complete);
    assert_eq!(written, 3);
    assert_eq!(&output[..3], b"ld!");
    assert_eq!(extra.len(), 0);

    // fourth call with no input should do nothing
    let (complete, written) =
        process_limited_buffer(&mut p, &[], true, &mut output, &mut extra).unwrap();
    assert!(complete);
    assert_eq!(written, 0);
    assert_eq!(extra.len(), 0);

    // now test with input that fits in the buffer
    let input = b"Hi!";
    let (complete, written) =
        process_limited_buffer(&mut p, input, true, &mut output, &mut extra).unwrap();
    assert!(complete);
    assert_eq!(written, 3);
    assert_eq!(&output[..3], b"Hi!");
    assert_eq!(extra.len(), 0);
}
