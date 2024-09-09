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
mod preflate_container;
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

use anyhow::{self};
use cabac::vp8::{VP8Reader, VP8Writer};
use preflate_container::{expand_zlib_chunks, recreated_zlib_chunks};
use preflate_error::PreflateError;
use preflate_parameter_estimator::{estimate_preflate_parameters, PreflateParameters};
use process::parse_deflate;
use std::{io::Cursor, panic::catch_unwind};

use crate::{
    cabac_codec::{PredictionDecoderCabac, PredictionEncoderCabac},
    process::{decode_mispredictions, encode_mispredictions},
    statistical_codec::PredictionEncoder,
};

/// result of decompress_deflate_stream
pub struct DecompressResult {
    /// the plaintext that was decompressed from the stream
    pub plain_text: Vec<u8>,

    /// the extra data that is needed to reconstruct the deflate stream exactly as it was written
    pub prediction_corrections: Vec<u8>,

    /// the number of bytes that were processed from the compressed stream (this will be exactly the
    /// data that will be recreated using the cabac_encoded data)
    pub compressed_size: usize,

    /// the parameters that were used to compress the stream (informational)
    pub parameters: PreflateParameters,
}

impl core::fmt::Debug for DecompressResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DecompressResult {{ plain_text: {}, prediction_corrections: {}, compressed_size: {} }}", self.plain_text.len(), self.prediction_corrections.len(), self.compressed_size)
    }
}

/// decompresses a deflate stream and returns the plaintext and cabac_encoded data that can be used to reconstruct it
pub fn decompress_deflate_stream(
    compressed_data: &[u8],
    verify: bool,
) -> Result<DecompressResult, PreflateError> {
    let mut cabac_encoded = Vec::new();

    let mut cabac_encoder =
        PredictionEncoderCabac::new(VP8Writer::new(&mut cabac_encoded).unwrap());

    let contents = parse_deflate(compressed_data, 0)?;

    //process::write_file("c:\\temp\\lastop.deflate", compressed_data);
    //process::write_file("c:\\temp\\lastop.bin", contents.plain_text.as_slice());

    let params = estimate_preflate_parameters(&contents.plain_text, &contents.blocks)
        .map_err(|e| PreflateError::AnalyzeFailed(e))?;

    //println!("params: {:?}", params);

    params.write(&mut cabac_encoder);
    encode_mispredictions(&contents, &params, &mut cabac_encoder)?;

    cabac_encoder.finish();

    if verify {
        let mut cabac_decoder =
            PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(&cabac_encoded)).unwrap());

        let reread_params = PreflateParameters::read(&mut cabac_decoder)
            .map_err(|e| PreflateError::InvalidPredictionData(e))?;
        assert_eq!(params, reread_params);

        let (recompressed, _recreated_blocks) =
            decode_mispredictions(&reread_params, &contents.plain_text, &mut cabac_decoder)?;

        if recompressed[..] != compressed_data[..contents.compressed_size] {
            return Err(PreflateError::Mismatch(anyhow::anyhow!(
                "recompressed data does not match original"
            )));
        }
    }

    Ok(DecompressResult {
        plain_text: contents.plain_text,
        prediction_corrections: cabac_encoded,
        compressed_size: contents.compressed_size,
        parameters: params,
    })
}

/// recompresses a deflate stream using the cabac_encoded data that was returned from decompress_deflate_stream
pub fn recompress_deflate_stream(
    plain_text: &[u8],
    prediction_corrections: &[u8],
) -> Result<Vec<u8>, PreflateError> {
    let mut cabac_decoder =
        PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(&prediction_corrections)).unwrap());

    let params = PreflateParameters::read(&mut cabac_decoder)
        .map_err(|e| PreflateError::InvalidPredictionData(e))?;
    let (recompressed, _recreated_blocks) =
        decode_mispredictions(&params, plain_text, &mut cabac_decoder)?;
    Ok(recompressed)
}

/// decompresses a deflate stream and returns the plaintext and cabac_encoded data that can be used to reconstruct it
/// This version uses DebugWriter and DebugReader, which are slower but can be used to debug the cabac encoding errors.
#[cfg(test)]
pub fn decompress_deflate_stream_assert(
    compressed_data: &[u8],
    verify: bool,
) -> Result<DecompressResult, PreflateError> {
    use cabac::debug::{DebugReader, DebugWriter};

    let mut cabac_encoded = Vec::new();

    let mut cabac_encoder =
        PredictionEncoderCabac::new(DebugWriter::new(&mut cabac_encoded).unwrap());

    let contents = parse_deflate(compressed_data, 0)?;

    let params = estimate_preflate_parameters(&contents.plain_text, &contents.blocks)
        .map_err(|e| PreflateError::AnalyzeFailed(e))?;

    params.write(&mut cabac_encoder);
    encode_mispredictions(&contents, &params, &mut cabac_encoder)?;

    assert_eq!(contents.compressed_size, compressed_data.len());
    cabac_encoder.finish();

    if verify {
        let mut cabac_decoder =
            PredictionDecoderCabac::new(DebugReader::new(Cursor::new(&cabac_encoded)).unwrap());

        let params = PreflateParameters::read(&mut cabac_decoder)
            .map_err(|e| PreflateError::InvalidPredictionData(e))?;
        let (recompressed, _recreated_blocks) =
            decode_mispredictions(&params, &contents.plain_text, &mut cabac_decoder)?;

        if recompressed[..] != compressed_data[..] {
            return Err(PreflateError::Mismatch(anyhow::anyhow!(
                "recompressed data does not match original"
            )));
        }
    }

    Ok(DecompressResult {
        plain_text: contents.plain_text,
        prediction_corrections: cabac_encoded,
        compressed_size: contents.compressed_size,
        parameters: params,
    })
}

/// recompresses a deflate stream using the cabac_encoded data that was returned from decompress_deflate_stream
/// This version uses DebugWriter and DebugReader, which are slower and don't compress but can be used to debug the cabac encoding errors.
#[cfg(test)]
pub fn recompress_deflate_stream_assert(
    plain_text: &[u8],
    prediction_corrections: &[u8],
) -> Result<Vec<u8>, PreflateError> {
    use cabac::debug::DebugReader;

    let mut cabac_decoder = PredictionDecoderCabac::new(
        DebugReader::new(Cursor::new(&prediction_corrections)).unwrap(),
    );

    let params = PreflateParameters::read(&mut cabac_decoder)
        .map_err(|e| PreflateError::InvalidPredictionData(e))?;

    let (recompressed, _recreated_blocks) =
        decode_mispredictions(&params, plain_text, &mut cabac_decoder)?;
    Ok(recompressed)
}

/// expands the Zlib compressed streams in the data and then recompresses the result
/// with Zstd with the maximum level.
pub fn compress_zstd(zlib_compressed_data: &[u8]) -> Result<Vec<u8>, PreflateError> {
    let plain_text = expand_zlib_chunks(&zlib_compressed_data)
        .map_err(|_| PreflateError::InvalidCompressedWrapper)?;
    zstd::bulk::compress(&plain_text, 9).map_err(|e| PreflateError::ZstdError(e))
}

/// decompresses the Zstd compressed data and then recompresses the result back
/// to the original Zlib compressed streams.
pub fn decompress_zstd(compressed_data: &[u8], capacity: usize) -> Result<Vec<u8>, PreflateError> {
    let compressed_data = zstd::bulk::decompress(compressed_data, capacity)
        .map_err(|e| PreflateError::ZstdError(e))?;

    let mut result = Vec::new();
    recreated_zlib_chunks(&mut Cursor::new(compressed_data), &mut result)?;
    Ok(result)
}

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

        let compressed_data = zstd::bulk::decompress(input, 1024 * 1024 * 128)
            .map_err(|e| PreflateError::ZstdError(e))?;

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

#[test]
fn verify_zip_compress() {
    use crate::process::read_file;
    let v = read_file("samplezip.zip");

    let expanded = expand_zlib_chunks(&v).unwrap();

    let mut recompressed = Vec::new();
    recreated_zlib_chunks(&mut Cursor::new(expanded), &mut recompressed).unwrap();

    assert!(v == recompressed);
}

#[test]
fn verify_roundtrip_zlib() {
    for i in 0..9 {
        verify_file(&format!("compressed_zlib_level{}.deflate", i));
    }
}

#[test]
fn verify_roundtrip_flate2() {
    for i in 0..9 {
        verify_file(&format!("compressed_flate2_level{}.deflate", i));
    }
}

#[test]
fn verify_roundtrip_libdeflate() {
    for i in 0..9 {
        verify_file(&format!("compressed_libdeflate_level{}.deflate", i));
    }
}

#[cfg(test)]
fn verify_file(filename: &str) {
    use crate::process::read_file;
    let v = read_file(filename);

    let r = decompress_deflate_stream(&v, true).unwrap();
    let recompressed = recompress_deflate_stream(&r.plain_text, &r.prediction_corrections).unwrap();
    assert!(v == recompressed);
}

#[test]
fn verify_zip_compress_zstd() {
    use crate::process::read_file;
    let v = read_file("samplezip.zip");

    let compressed = compress_zstd(&v).unwrap();

    let recreated = decompress_zstd(&compressed, 256 * 1024 * 1024).unwrap();

    assert!(v == recreated);
    println!(
        "original zip = {} bytes, recompressed zip = {} bytes",
        v.len(),
        compressed.len()
    );
}

#[test]
fn verify_roundtrip_assert() {
    use crate::process::read_file;

    let v = read_file("compressed_zlib_level1.deflate");

    let r = decompress_deflate_stream_assert(&v, true).unwrap();
    let recompressed =
        recompress_deflate_stream_assert(&r.plain_text, &r.prediction_corrections).unwrap();
    assert!(v == recompressed);
}
