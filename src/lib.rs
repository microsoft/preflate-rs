mod bit_helper;
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
mod zip_bit_reader;

use anyhow::{self};
use cabac::vp8::{VP8Reader, VP8Writer};
use preflate_error::PreflateError;
use std::io::Cursor;

use crate::{
    cabac_codec::{PredictionDecoderCabac, PredictionEncoderCabac},
    process::{read_deflate, write_deflate},
    statistical_codec::PredictionEncoder,
};

pub struct DecompressResult {
    pub plain_text: Vec<u8>,
    pub cabac_encoded: Vec<u8>,
    pub compressed_processed: usize,
}

pub fn decompress_deflate_stream(
    compressed_data: &[u8],
    verify: bool,
) -> Result<DecompressResult, PreflateError> {
    let mut cabac_encoded = Vec::new();

    let mut cabac_encoder =
        PredictionEncoderCabac::new(VP8Writer::new(&mut cabac_encoded).unwrap());
    let (compressed_processed, _params, plain_text, _original_blocks) =
        read_deflate(compressed_data, &mut cabac_encoder, 0)?;

    assert_eq!(compressed_processed, compressed_data.len());
    cabac_encoder.finish();

    if verify {
        let mut cabac_decoder =
            PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(&cabac_encoded)).unwrap());
        let (recompressed, _recreated_blocks) = write_deflate(&plain_text, &mut cabac_decoder)?;

        if recompressed[..] != compressed_data[..] {
            return Err(PreflateError::Mismatch(anyhow::anyhow!(
                "recompressed data does not match original"
            )));
        }
    }

    Ok(DecompressResult {
        plain_text,
        cabac_encoded,
        compressed_processed,
    })
}

pub fn recompress_deflate_stream(
    plain_text: &[u8],
    cabac_encoded: &[u8],
) -> Result<Vec<u8>, PreflateError> {
    let mut cabac_decoder =
        PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(&cabac_encoded)).unwrap());
    let (recompressed, _recreated_blocks) = write_deflate(&plain_text, &mut cabac_decoder)?;
    Ok(recompressed)
}
