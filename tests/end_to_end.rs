/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

use flate2::{read::ZlibEncoder, Compression};
use preflate_rs::{decompress_deflate_stream, recompress_deflate_stream};

#[cfg(test)]
pub fn read_file(filename: &str) -> Vec<u8> {
    let filename = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("samples")
        .join(filename);
    println!("reading {0}", filename.to_str().unwrap());
    let mut f = File::open(filename).unwrap();

    let mut content = Vec::new();
    f.read_to_end(&mut content).unwrap();

    content
}

#[test]
fn end_to_end_compressed() {
    for i in 0..9 {
        let compressed_data = read_file(&format!("compressed_miniz_oxide_level{}.bin", i));

        verifyresult(&compressed_data);
    }
}

#[test]
fn test_wrong() {
    test_file("sample1.bin");
}

fn verifyresult(compressed_data: &[u8]) {
    let result = decompress_deflate_stream(compressed_data, true).unwrap();
    let recomp = recompress_deflate_stream(&result.plain_text, &result.cabac_encoded).unwrap();
    assert_eq!(compressed_data, recomp);
}

fn test_file(filename: &str) {
    let v = read_file(filename);

    // Zlib compression with different compression levels
    for level in 0..10 {
        println!("zlib level: {}", level);

        let mut output = Vec::new();
        output.resize(v.len() + 1000, 0);

        let mut output_size = output.len() as libz_sys::uLongf;

        unsafe {
            let err = libz_sys::compress2(
                output.as_mut_ptr(),
                &mut output_size,
                v.as_ptr(),
                v.len() as libz_sys::uLongf,
                level,
            );

            output.set_len(output_size as usize);
            println!("output size: {}, err = {}", output.len(), err);
        }

        let minusheader = &output[2..output.len() - 4];

        verifyresult(minusheader);
    }

    // Zlib compression with different compression levels
    for level in 0..10 {
        println!("Flate2 level: {}", level);
        let mut zlib_encoder: ZlibEncoder<Cursor<&Vec<u8>>> =
            ZlibEncoder::new(Cursor::new(&v), Compression::new(level));
        let mut output = Vec::new();
        zlib_encoder.read_to_end(&mut output).unwrap();

        // skip header and final crc
        let minusheader = &output[2..output.len() - 4];

        verifyresult(minusheader);
    }
}
