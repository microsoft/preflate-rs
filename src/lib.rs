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
mod huffman_calc;
mod huffman_encoding;
mod huffman_helper;
mod predictor_state;
mod preflate_constants;
pub mod preflate_error;
mod preflate_input;
mod preflate_parameter_estimator;
mod preflate_parse_config;
mod preflate_stream_info;
mod preflate_token;
mod process;
mod scan_deflate;
mod statistical_codec;
mod token_predictor;
mod tree_predictor;

use anyhow::{self};
use cabac::vp8::{VP8Reader, VP8Writer};
use preflate_error::PreflateError;
use preflate_parameter_estimator::{estimate_preflate_parameters, PreflateParameters};
use process::parse_deflate;
use scan_deflate::search_for_deflate_streams;
use std::io::Cursor;

use crate::{
    cabac_codec::{PredictionDecoderCabac, PredictionEncoderCabac},
    process::{decode_mispredictions, encode_mispredictions},
    statistical_codec::PredictionEncoder,
};

const COMPRESSED_WRAPPER_VERSION_1: u8 = 1;

/// result of decompress_deflate_stream
pub struct DecompressResult {
    /// the plaintext that was decompressed from the stream
    pub plain_text: Vec<u8>,

    /// the extra data that is needed to reconstruct the deflate stream exactly as it was written
    pub prediction_corrections: Vec<u8>,

    /// the number of bytes that were processed from the compressed stream (this will be exactly the
    /// data that will be recreated using the cabac_encoded data)
    pub compressed_size: usize,

    /// the parameters that were used to compress the stream
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

    /*
    let mut writecomp = File::create("c:\\temp\\lastop.deflate").unwrap();
    writecomp.write_all(compressed_data).unwrap();

    let mut writeplaintext = File::create("c:\\temp\\lastop.bin").unwrap();
    writeplaintext.write_all(&contents.plain_text).unwrap();
    */

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

fn append_with_length(dst: &mut Vec<u8>, src: &[u8]) {
    dst.extend_from_slice(&(src.len() as u32).to_le_bytes());
    dst.extend_from_slice(src);
}

fn read_segment_with_length<'a>(
    src: &'a [u8],
    index: &mut usize,
) -> Result<&'a [u8], PreflateError> {
    if src.len() < *index + 4 {
        return Err(PreflateError::InvalidCompressedWrapper);
    }

    let len = u32::from_le_bytes(src[*index..*index + 4].try_into().unwrap()) as usize;
    *index += 4;

    if src.len() < *index + len {
        return Err(PreflateError::InvalidCompressedWrapper);
    }

    let result = &src[*index..*index + len];
    *index += len;

    Ok(result)
}

/// scans for deflate streams in a zlib compressed file, decompresses the streams and
/// returns an uncompressed file that can then be recompressed using a better algorithm.
/// This can then be passed back into recreated_zlib_chunks to recreate the exact original file.
pub fn expand_zlib_chunks(compressed_data: &[u8]) -> Vec<u8> {
    let mut locations_found = Vec::new();

    search_for_deflate_streams(compressed_data, &mut locations_found);

    let mut plain_text = Vec::new();
    plain_text.push(COMPRESSED_WRAPPER_VERSION_1); // version 1 of format. Definitely will improved.

    let mut prev: Option<scan_deflate::DeflateStreamLocation> = None;
    for loc in locations_found {
        //println!("loc: {:?}", loc);

        if let Some(prev) = prev {
            append_with_length(
                &mut plain_text,
                &compressed_data[prev.start + prev.data.compressed_size..loc.start],
            );
        } else {
            append_with_length(&mut plain_text, &compressed_data[0..loc.start]);
        }

        append_with_length(&mut plain_text, &loc.data.prediction_corrections);
        append_with_length(&mut plain_text, &loc.data.plain_text);
        prev = Some(loc);
    }

    // append the last chunk
    if let Some(prev) = prev {
        append_with_length(
            &mut plain_text,
            &compressed_data[prev.start + prev.data.compressed_size..],
        );
    }

    plain_text
}

/// takes a binary chunk of data that was created by expand_zlib_chunks and recompresses it back to its
/// original form.
pub fn recreated_zlib_chunks(compressed_data: &[u8]) -> Result<Vec<u8>, PreflateError> {
    let mut result = Vec::new();
    let mut index = 0;

    if compressed_data.len() < 5 {
        return Err(PreflateError::InvalidCompressedWrapper);
    }

    if compressed_data[0] != COMPRESSED_WRAPPER_VERSION_1 {
        return Err(PreflateError::InvalidCompressedWrapper);
    }
    index += 1;

    while index != compressed_data.len() {
        let segment = read_segment_with_length(compressed_data, &mut index)?;
        result.extend_from_slice(segment);

        if index == compressed_data.len() {
            // reached end of file
            break;
        }

        let corrections = read_segment_with_length(compressed_data, &mut index)?;
        let plain_text = read_segment_with_length(compressed_data, &mut index)?;
        let recompressed = recompress_deflate_stream(plain_text, corrections)?;
        result.extend_from_slice(&recompressed);
    }

    Ok(result)
}

/// expands the Zlib compressed streams in the data and then recompresses the result
/// with Zstd with the maximum level.
pub fn compress_zstd(zlib_compressed_data: &[u8]) -> Vec<u8> {
    let plain_text = expand_zlib_chunks(&zlib_compressed_data);
    zstd::bulk::compress(&plain_text, 9).unwrap()
}

/// decompresses the Zstd compressed data and then recompresses the result back
/// to the original Zlib compressed streams.
pub fn decompress_zstd(compressed_data: &[u8], capacity: usize) -> Result<Vec<u8>, PreflateError> {
    let compressed_data = zstd::bulk::decompress(compressed_data, capacity)
        .map_err(|e| PreflateError::ZstdError(e))?;

    recreated_zlib_chunks(&compressed_data)
}

#[test]
fn verify_zip_compress() {
    use crate::process::read_file;
    let v = read_file("samplezip.zip");

    let expanded = expand_zlib_chunks(&v);

    let recompressed = recreated_zlib_chunks(&expanded).unwrap();

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

    let compressed = compress_zstd(&v);

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
