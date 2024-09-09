/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::{mem, ptr};

use libdeflate_sys::{libdeflate_alloc_compressor, libdeflate_deflate_compress};
use preflate_rs::{
    compress_zstd, decompress_deflate_stream, decompress_zstd, recompress_deflate_stream,
};

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
        let compressed_data = read_file(&format!("compressed_flate2_level{}.deflate", i));
        verifyresult(&compressed_data);

        let compressed_data = read_file(&format!("compressed_zlib_level{}.deflate", i));
        verifyresult(&compressed_data);
    }
}

#[test]
fn test_matchnotfound() {
    test_file("sample3.bin");
}

#[test]
fn test_pptxplaintext() {
    test_file("pptxplaintext.bin");
}

#[test]
fn test_nomatch() {
    test_file("sample2.bin");
}

#[test]
fn test_sample1() {
    test_file("sample1.bin");
}

#[test]
fn test_samplezip() {
    test_container("samplezip.zip");
}

#[test]
fn test_docx() {
    test_container("samplepptx.pptx");
}

fn test_container(filename: &str) {
    let v = read_file(filename);
    let c = compress_zstd(&v).unwrap();

    let r = decompress_zstd(&c, 1024 * 1024 * 128).unwrap();
    assert!(v == r);

    println!(
        "file {} original size: {}, compressed size: {} (plaintext={})",
        filename,
        v.len(),
        c.len(),
        r.len()
    );
}

#[test]
fn libzng() {
    let level = 1;

    let v = read_file("pptxplaintext.bin");
    println!("zlibng level: {}", level);

    let output = libngzsys_compress(&v, level);

    let minusheader = &output[2..output.len() - 4];

    // write to file
    //let mut f = File::create(format!("c:\\temp\\compressed_zlib_level{}.bin", level)).unwrap();
    //.write_all(minusheader).unwrap();

    verifyresult(minusheader);
}

fn verifyresult(compressed_data: &[u8]) {
    let result = decompress_deflate_stream(compressed_data, true).unwrap();
    let recomp =
        recompress_deflate_stream(&result.plain_text, &result.prediction_corrections).unwrap();

    println!(
        "compressed size: {}, cabac: {}",
        compressed_data.len(),
        result.prediction_corrections.len()
    );
    println!("parameters: {:?}", result.parameters);

    assert_eq!(compressed_data, recomp);
}

fn test_file(filename: &str) {
    let v = read_file(filename);

    // Zlib compression with different compression levels
    for level in 1..=9 {
        println!("zlib level: {}", level);

        let output = libzsys_compress(&v, level, Strategy::Default);

        let minusheader = &output[2..output.len() - 4];

        // write to file
        //let mut f = File::create(format!("c:\\temp\\compressed_zlib_level{}.bin", level)).unwrap();
        //.write_all(minusheader).unwrap();

        verifyresult(minusheader);
    }

    for s in [Strategy::HuffmanOnly, Strategy::Rle, Strategy::Fixed].iter() {
        println!("zlib level: strategy {:?}", s);

        let output = libzsys_compress(&v, 1, *s);

        let minusheader = &output[2..output.len() - 4];

        // write to file
        //let mut f = File::create(format!("c:\\temp\\compressed_zlib_level{}.bin", level)).unwrap();
        //.write_all(minusheader).unwrap();

        verifyresult(minusheader);
    }

    for level in 0..=9 {
        println!("libdeflate level: {}", level);
        let output = libdeflate_compress(&v, level);

        // write to file
        /*let mut f = File::create(format!(
            "c:\\temp\\compressed_libdeflate_level{}.deflate",
            level
        ))
        .unwrap();
        f.write_all(&output).unwrap();*/

        verifyresult(&output);
    }

    // Zlibng compression with different compression levels
    for level in 1..=4 {
        println!("zlibng level: {}", level);

        let output = libngzsys_compress(&v, level);

        let minusheader = &output[2..output.len() - 4];

        // write to file
        /*let mut f = File::create(format!(
            "c:\\temp\\compressed_zlibng_level{}.deflate",
            level
        ))
        .unwrap();
        f.write_all(minusheader).unwrap();*/

        verifyresult(minusheader);
    }

    for level in 0..=9 {
        println!("miniz_oxide level: {}", level);
        let output = miniz_oxide::deflate::compress_to_vec(&v, level);
        verifyresult(&output);
    }
}

#[derive(Debug, Copy, Clone)]
enum Strategy {
    Default,
    HuffmanOnly,
    Rle,
    Fixed,
}

fn libzsys_compress(input_data: &[u8], level: i32, strategy: Strategy) -> Vec<u8> {
    let mut output = Vec::new();
    use libz_sys::*;
    unsafe {
        let mut z_stream = z_stream {
            next_in: input_data.as_ptr() as *mut _,
            avail_in: input_data.len() as u32,
            next_out: ptr::null_mut(),
            avail_out: 0,
            total_in: 0,
            total_out: 0,
            msg: std::ptr::null_mut(),
            state: std::ptr::null_mut(),
            zalloc: mem::transmute(ptr::null::<u8>()),
            zfree: mem::transmute(ptr::null::<u8>()),
            opaque: ptr::null_mut(),
            data_type: 0,
            adler: 0,
            reserved: 0,
        };

        // Additional options for deflateInit2_
        let window_bits = 15; // Default window size
        let mem_level = 8; // Default memory level
        let version = zlibVersion(); // Use the zlib version defined in the library
        let stream_size = std::mem::size_of::<z_stream>() as i32;

        // Initialize the zlib stream for compression with deflateInit2_

        assert_eq!(
            deflateInit2_(
                &mut z_stream,
                level,
                Z_DEFLATED,
                window_bits,
                mem_level,
                match strategy {
                    Strategy::Default => Z_DEFAULT_STRATEGY,
                    Strategy::HuffmanOnly => Z_HUFFMAN_ONLY,
                    Strategy::Rle => Z_RLE,
                    Strategy::Fixed => Z_FIXED,
                },
                version,
                stream_size
            ),
            Z_OK
        );

        output.resize(input_data.len() + 1000, 0);

        z_stream.next_out = output.as_mut_ptr() as *mut _;
        z_stream.avail_out = output.len() as u32;

        assert_eq!(Z_STREAM_END, deflate(&mut z_stream, Z_FINISH));
        output.set_len(z_stream.total_out as usize);

        assert_eq!(Z_OK, deflateEnd(&mut z_stream));
    }
    output
}

fn libdeflate_compress(in_data: &[u8], level: i32) -> Vec<u8> {
    unsafe {
        let mut out_data = vec![0; in_data.len() + 1000];

        let compressor = libdeflate_alloc_compressor(level);
        let sz = libdeflate_deflate_compress(
            compressor,
            in_data.as_ptr() as *const core::ffi::c_void,
            in_data.len(),
            out_data.as_mut_ptr() as *mut core::ffi::c_void,
            out_data.len(),
        );

        assert_ne!(sz, 0);
        out_data.resize(sz, 0);
        out_data
    }
}

fn libngzsys_compress(input_data: &[u8], level: i32) -> Vec<u8> {
    let mut output = Vec::new();
    use libz_ng_sys::{
        deflate, deflateEnd, deflateInit2_, z_stream, zlibVersion, Z_DEFAULT_STRATEGY, Z_DEFLATED,
        Z_FINISH, Z_OK, Z_STREAM_END,
    };
    unsafe {
        let mut z_stream = z_stream {
            next_in: input_data.as_ptr() as *mut _,
            avail_in: input_data.len() as u32,
            next_out: ptr::null_mut(),
            avail_out: 0,
            total_in: 0,
            total_out: 0,
            msg: std::ptr::null_mut(),
            state: std::ptr::null_mut(),
            zalloc: mem::transmute(ptr::null::<u8>()),
            zfree: mem::transmute(ptr::null::<u8>()),
            opaque: ptr::null_mut(),
            data_type: 0,
            adler: 0,
            reserved: 0,
        };

        // Additional options for deflateInit2_
        let window_bits = 15; // Default window size
        let mem_level = 8; // Default memory level
        let version = zlibVersion(); // Use the zlib version defined in the library
        let stream_size = std::mem::size_of::<z_stream>() as i32;

        // Initialize the zlib stream for compression with deflateInit2_

        assert_eq!(
            deflateInit2_(
                &mut z_stream,
                level,
                Z_DEFLATED,
                window_bits,
                mem_level,
                Z_DEFAULT_STRATEGY,
                version,
                stream_size
            ),
            Z_OK
        );

        output.resize(input_data.len() + 1000, 0);

        z_stream.next_out = output.as_mut_ptr() as *mut _;
        z_stream.avail_out = output.len() as u32;

        assert_eq!(Z_STREAM_END, deflate(&mut z_stream, Z_FINISH));
        output.set_len(z_stream.total_out as usize);

        assert_eq!(Z_OK, deflateEnd(&mut z_stream));
    }
    output
}
