use std::io::{BufRead, Read};

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
