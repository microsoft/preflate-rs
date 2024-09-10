/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

mod bit_helper;
mod bit_reader;
mod bit_writer;
mod cabac_codec;
mod complevel_estimator;
mod deflate_reader;
mod deflate_writer;
mod hash_algorithm;
mod hash_chain;
mod hash_chain_holder;
mod huffman_calc;
mod huffman_encoding;
mod huffman_helper;
mod idat_parse;
mod preflate_constants;
pub mod preflate_container;
pub mod preflate_error;
mod preflate_input;
mod preflate_parameter_estimator;
mod preflate_parse_config;
mod preflate_stream_info;
mod preflate_token;
mod process;
mod scan_deflate;
mod skip_length_estimator;
mod statistical_codec;
mod token_predictor;
mod tree_predictor;

use preflate_container::{expand_zlib_chunks, recreated_zlib_chunks};
use preflate_error::PreflateError;
use std::{io::Cursor, panic::catch_unwind};

/// C ABI interface for compressing Zip file, exposed from DLL.
#[no_mangle]
pub unsafe extern "C" fn WrapperCompressZip(
    input_buffer: *const u8,
    input_buffer_size: u64,
    output_buffer: *mut u8,
    output_buffer_size: u64,
    result_size: *mut u64,
) -> i32 {
    match catch_unwind(|| {
        let input_buffer = std::slice::from_raw_parts(input_buffer, input_buffer_size as usize);
        let output_buffer =
            std::slice::from_raw_parts_mut(output_buffer, output_buffer_size as usize);

        let plain_text = expand_zlib_chunks(&input_buffer)?;

        *result_size = zstd::bulk::compress_to_buffer(&plain_text, output_buffer, 9)? as u64;

        Result::<(), PreflateError>::Ok(())
    }) {
        Ok(x) => {
            if let Err(_) = x {
                return -1;
            }
            return 0;
        }
        Err(_) => {
            return -2;
        }
    }
}

/// C ABI interface for decompressing Zip, exposed from DLL
#[no_mangle]
pub unsafe extern "C" fn WrapperDecompressZip(
    input_buffer: *const u8,
    input_buffer_size: u64,
    output_buffer: *mut u8,
    output_buffer_size: u64,
    result_size: *mut u64,
) -> i32 {
    match catch_unwind(|| {
        let input = std::slice::from_raw_parts(input_buffer, input_buffer_size as usize);
        let output = std::slice::from_raw_parts_mut(output_buffer, output_buffer_size as usize);

        let compressed_data =
            zstd::bulk::decompress(input, 1024 * 1024 * 128).map_err(PreflateError::ZstdError)?;

        let mut source = Cursor::new(&compressed_data);
        let mut destination = Cursor::new(output);

        recreated_zlib_chunks(&mut source, &mut destination)?;
        *result_size = destination.position();

        Result::<(), PreflateError>::Ok(())
    }) {
        Ok(x) => {
            if let Err(_) = x {
                return -1;
            }
            return 0;
        }
        Err(_) => {
            return -2;
        }
    }
}

#[test]
fn extern_interface() {
    use crate::process::read_file;
    let input = read_file("samplezip.zip");

    let mut compressed = Vec::new();

    compressed.resize(input.len() + 10000, 0);

    let mut result_size: u64 = 0;

    unsafe {
        let retval = WrapperCompressZip(
            input[..].as_ptr(),
            input.len() as u64,
            compressed[..].as_mut_ptr(),
            compressed.len() as u64,
            (&mut result_size) as *mut u64,
        );

        assert_eq!(retval, 0);
    }

    let mut original = Vec::new();
    original.resize(input.len() + 10000, 0);

    let mut original_size: u64 = 0;
    unsafe {
        let retval = WrapperDecompressZip(
            compressed[..].as_ptr(),
            result_size,
            original[..].as_mut_ptr(),
            original.len() as u64,
            (&mut original_size) as *mut u64,
        );

        assert_eq!(retval, 0);
    }
    assert_eq!(input.len() as u64, original_size);
    assert_eq!(input[..], original[..(original_size as usize)]);
}
