use std::{collections::VecDeque, io::Write};

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

#[allow(dead_code)]
#[cfg(test)]
pub fn write_file(filename: &str, data: &[u8]) {
    let mut writecomp = std::fs::File::create(filename).unwrap();
    std::io::Write::write_all(&mut writecomp, data).unwrap();
}

#[cfg(test)]
pub fn read_file(filename: &str) -> Vec<u8> {
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

    let filename = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("samples")
        .join(filename);
    println!("reading {0}", filename.to_str().unwrap());
    let mut f = File::open(filename).unwrap();

    let mut content = Vec::new();
    f.read_to_end(&mut content).unwrap();

    content
}
