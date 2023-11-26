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
mod statistical_codec;
mod token_predictor;
mod tree_predictor;

use anyhow::{self};
use cabac::{
    debug::{DebugReader, DebugWriter},
    vp8::{VP8Reader, VP8Writer},
};
use preflate_error::PreflateError;
use preflate_parameter_estimator::{estimate_preflate_parameters, PreflateParameters};
use process::parse_deflate;
use std::io::Cursor;

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
}

/// decompresses a deflate stream and returns the plaintext and cabac_encoded data that can be used to reconstruct it
pub fn decompress_deflate_stream(
    compressed_data: &[u8],
    verify: bool,
) -> Result<DecompressResult, PreflateError> {
    let mut cabac_encoded = Vec::new();

    let mut cabac_encoder =
        PredictionEncoderCabac::new(VP8Writer::new(&mut cabac_encoded).unwrap());

    let contents = parse_deflate(compressed_data, 1)?;

    let params = estimate_preflate_parameters(&contents.plain_text, &contents.blocks);

    params.write(&mut cabac_encoder);
    encode_mispredictions(&contents, &params, &mut cabac_encoder)?;

    cabac_encoder.finish();

    if verify {
        let mut cabac_decoder =
            PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(&cabac_encoded)).unwrap());

        let reread_params = PreflateParameters::read(&mut cabac_decoder);
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
    })
}

/// recompresses a deflate stream using the cabac_encoded data that was returned from decompress_deflate_stream
pub fn recompress_deflate_stream(
    plain_text: &[u8],
    cabac_encoded: &[u8],
) -> Result<Vec<u8>, PreflateError> {
    let mut cabac_decoder =
        PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(&cabac_encoded)).unwrap());

    let params = PreflateParameters::read(&mut cabac_decoder);
    let (recompressed, _recreated_blocks) =
        decode_mispredictions(&params, plain_text, &mut cabac_decoder)?;
    Ok(recompressed)
}

/// decompresses a deflate stream and returns the plaintext and cabac_encoded data that can be used to reconstruct it
/// This version uses DebugWriter and DebugReader, which are slower but can be used to debug the cabac encoding errors.
pub fn decompress_deflate_stream_assert(
    compressed_data: &[u8],
    verify: bool,
) -> Result<DecompressResult, PreflateError> {
    let mut cabac_encoded = Vec::new();

    let mut cabac_encoder =
        PredictionEncoderCabac::new(DebugWriter::new(&mut cabac_encoded).unwrap());

    let contents = parse_deflate(compressed_data, 1)?;

    let params = estimate_preflate_parameters(&contents.plain_text, &contents.blocks);

    params.write(&mut cabac_encoder);
    encode_mispredictions(&contents, &params, &mut cabac_encoder)?;

    assert_eq!(contents.compressed_size, compressed_data.len());
    cabac_encoder.finish();

    if verify {
        let mut cabac_decoder =
            PredictionDecoderCabac::new(DebugReader::new(Cursor::new(&cabac_encoded)).unwrap());

        let params = PreflateParameters::read(&mut cabac_decoder);
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
    })
}

/// recompresses a deflate stream using the cabac_encoded data that was returned from decompress_deflate_stream
/// This version uses DebugWriter and DebugReader, which are slower and don't compress but can be used to debug the cabac encoding errors.
pub fn recompress_deflate_stream_assert(
    plain_text: &[u8],
    cabac_encoded: &[u8],
) -> Result<Vec<u8>, PreflateError> {
    let mut cabac_decoder =
        PredictionDecoderCabac::new(DebugReader::new(Cursor::new(&cabac_encoded)).unwrap());

    let params = PreflateParameters::read(&mut cabac_decoder);

    let (recompressed, _recreated_blocks) =
        decode_mispredictions(&params, plain_text, &mut cabac_decoder)?;
    Ok(recompressed)
}

#[test]
fn verify_roundtrip() {
    use crate::process::read_file;
    
    let v = read_file("compressed_zlib_level1.deflate");

    let r = decompress_deflate_stream(&v, true).unwrap();
    let recompressed = recompress_deflate_stream(&r.plain_text, &r.prediction_corrections).unwrap();
    assert_eq!(v, recompressed);
}

#[test]
fn verify_roundtrip_assert() {
    use crate::process::read_file;

    let v = read_file("compressed_zlib_level1.deflate");

    let r = decompress_deflate_stream_assert(&v, true).unwrap();
    let recompressed =
        recompress_deflate_stream_assert(&r.plain_text, &r.prediction_corrections).unwrap();
    assert_eq!(v, recompressed);
}
