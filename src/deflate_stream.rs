/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use std::io::Cursor;

use bitcode::{Decode, Encode};
use cabac::vp8::{VP8Reader, VP8Writer};

use crate::{
    cabac_codec::{PredictionDecoderCabac, PredictionEncoderCabac},
    deflate::{
        deflate_reader::{parse_deflate, DeflateParserState},
        deflate_token::DeflateTokenBlock,
        deflate_writer::DeflateWriter,
    },
    estimator::preflate_parameter_estimator::PreflateParameters,
    preflate_error::{AddContext, ExitCode, PreflateError},
    preflate_input::{PlainText, PreflateInput},
    statistical_codec::PredictionEncoder,
    token_predictor::TokenPredictor,
    Result,
};

/// the data required to reconstruct the deflate stream exactly the way that it was
#[derive(Encode, Decode)]
pub struct ReconstructionData {
    pub parameters: PreflateParameters,
    pub corrections: Vec<u8>,
}

impl ReconstructionData {
    pub fn read(data: &[u8]) -> Result<Self> {
        bitcode::decode(data).map_err(|e| {
            PreflateError::new(
                ExitCode::InvalidCompressedWrapper,
                format!("{:?}", e).as_str(),
            )
        })
    }
}

#[derive(Debug)]
pub struct DeflateContinueState {
    pub predictor: TokenPredictor,
    pub last: bool,
    pub plain_text: PlainText,
}

/// result of decompress_deflate_stream
pub struct DecompressResult {
    /// the plaintext that was decompressed from the stream
    pub plain_text: PlainText,

    /// the extra data that is needed to reconstruct the deflate stream exactly as it was written
    pub corrections: Vec<u8>,

    /// the number of bytes that were processed from the compressed stream (this will be exactly the
    /// data that will be recreated using the cabac_encoded data)
    pub compressed_size: usize,

    /// the parameters that were used to compress the stream (informational)
    pub parameters: Option<PreflateParameters>,

    pub continue_state: Option<DeflateContinueState>,
}

impl core::fmt::Debug for DecompressResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DecompressResult {{ plain_text: {}, prediction_corrections: {}, compressed_size: {} }}", self.plain_text.text().len(), self.corrections.len(), self.compressed_size)
    }
}

/// decompresses a deflate stream and returns the plaintext and cabac_encoded data that can be used to reconstruct it
pub fn decompress_deflate_stream(
    previous_state: Option<DeflateContinueState>,
    compressed_data: &[u8],
    verify: bool,
    _loglevel: u32,
) -> Result<DecompressResult> {
    let mut cabac_encoded = Vec::new();

    let mut cabac_encoder =
        PredictionEncoderCabac::new(VP8Writer::new(&mut cabac_encoded).unwrap());

    if let Some(mut state) = previous_state {
        let mut plain_text = state.plain_text;

        let mut contents = parse_deflate(
            DeflateParserState::ContinueStaticBlock { last: state.last },
            compressed_data,
            &mut plain_text,
        )?;

        let mut input = PreflateInput::new(&plain_text);

        predict_blocks(
            &contents.blocks,
            &mut state.predictor,
            &mut cabac_encoder,
            &mut input,
            false,
        )?;

        cabac_encoder.finish();

        // todo verify continue state

        Ok(DecompressResult {
            plain_text: plain_text.clone(),
            corrections: cabac_encoded,
            compressed_size: contents.compressed_size,
            parameters: None,
            continue_state: match &mut contents.state {
                DeflateParserState::ContinueStaticBlock { last, .. } => {
                    Some(DeflateContinueState {
                        predictor: state.predictor,
                        last: *last,
                        plain_text: plain_text,
                    })
                }
                _ => None,
            },
        })
    } else {
        let mut plain_text = PlainText::new();
        let mut contents = parse_deflate(
            DeflateParserState::StartBlock,
            compressed_data,
            &mut plain_text,
        )?;

        let params =
            PreflateParameters::estimate_preflate_parameters(&contents, &plain_text).context()?;

        let mut input = PreflateInput::new(&plain_text);

        let mut token_predictor = TokenPredictor::new(&params.predictor);

        predict_blocks(
            &contents.blocks,
            &mut token_predictor,
            &mut cabac_encoder,
            &mut input,
            false,
        )?;

        cabac_encoder.finish();

        let reconstruction_data = bitcode::encode(&ReconstructionData {
            parameters: params,
            corrections: cabac_encoded,
        });

        if verify {
            let r = ReconstructionData::read(&reconstruction_data)?;

            assert_eq!(r.parameters, params);

            let recompressed = recompress_deflate_stream_pred(
                &plain_text,
                &r.corrections,
                &mut TokenPredictor::new(&r.parameters.predictor),
                false,
            )?;

            if recompressed[..] != compressed_data[..contents.compressed_size] {
                return Err(PreflateError::new(
                    ExitCode::RoundtripMismatch,
                    "recompressed data does not match original",
                ));
            }
        }

        Ok(DecompressResult {
            plain_text: plain_text.clone(),
            corrections: reconstruction_data,
            compressed_size: contents.compressed_size,
            parameters: Some(params),
            continue_state: match &mut contents.state {
                DeflateParserState::ContinueStaticBlock { last, .. } => {
                    Some(DeflateContinueState {
                        predictor: token_predictor,
                        last: *last,
                        plain_text: plain_text,
                    })
                }
                _ => None,
            },
        })
    }
}

/// recompresses a deflate stream using the cabac_encoded data that was returned from decompress_deflate_stream
pub fn recompress_deflate_stream(
    plain_text: &PlainText,
    prediction_corrections: &[u8],
) -> Result<Vec<u8>> {
    let r = ReconstructionData::read(prediction_corrections)?;

    recompress_deflate_stream_pred(
        plain_text,
        &r.corrections,
        &mut TokenPredictor::new(&r.parameters.predictor),
        false,
    )
}

pub fn recompress_deflate_stream_pred(
    plain_text: &PlainText,
    corrections: &[u8],
    predictor: &mut TokenPredictor,
    partial: bool,
) -> Result<Vec<u8>> {
    let mut cabac_decoder =
        PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(corrections)).unwrap());
    let mut input = PreflateInput::new(plain_text);
    let mut deflate_writer = DeflateWriter::new();
    loop {
        let (end, block) = predictor.recreate_block(&mut cabac_decoder, &mut input, partial)?;

        deflate_writer.encode_block(&block)?;

        if end {
            break;
        }
    }
    deflate_writer.flush();
    Ok(deflate_writer.detach_output())
}

/// takes a deflate compressed stream, analyzes it, decoompresses it, and records
/// any differences in the encoder codec
#[cfg(test)]
fn encode_mispredictions(
    deflate: &crate::deflate::deflate_reader::DeflateContents,
    plain_text: &PlainText,
    params: &PreflateParameters,
    encoder: &mut impl PredictionEncoder,
    partial: bool,
) -> Result<()> {
    let mut input = PreflateInput::new(plain_text);

    let mut token_predictor = TokenPredictor::new(&params.predictor);

    predict_blocks(
        &deflate.blocks,
        &mut token_predictor,
        encoder,
        &mut input,
        partial,
    )?;

    Ok(())
}

fn predict_blocks(
    blocks: &[DeflateTokenBlock],
    token_predictor: &mut TokenPredictor,
    encoder: &mut impl PredictionEncoder,
    input: &mut PreflateInput,
    partial: bool,
) -> Result<()> {
    for i in 0..blocks.len() {
        token_predictor.predict_block(&blocks[i], encoder, input, partial)?;
    }
    assert!(input.remaining() == 0);
    Ok(())
}

#[cfg(test)]
fn decode_mispredictions(
    params: &PreflateParameters,
    input: &mut PreflateInput,
    decoder: &mut impl crate::statistical_codec::PredictionDecoder,
    partial: bool,
) -> Result<(Vec<u8>, Vec<DeflateTokenBlock>)> {
    let mut deflate_writer: DeflateWriter = DeflateWriter::new();
    let mut predictor = TokenPredictor::new(&params.predictor);

    let output_blocks =
        recreate_blocks(&mut predictor, decoder, &mut deflate_writer, input, partial)?;

    deflate_writer.flush();

    Ok((deflate_writer.detach_output(), output_blocks))
}

#[cfg(test)]
#[inline(never)]
fn recreate_blocks<D: crate::statistical_codec::PredictionDecoder>(
    token_predictor: &mut TokenPredictor,
    decoder: &mut D,
    deflate_writer: &mut DeflateWriter,
    input: &mut PreflateInput,
    partial: bool,
) -> Result<Vec<DeflateTokenBlock>> {
    let mut output_blocks = Vec::new();
    loop {
        let (stop, block) = token_predictor.recreate_block(decoder, input, partial)?;

        deflate_writer.encode_block(&block)?;

        output_blocks.push(block);
        if stop {
            break;
        }
    }
    Ok(output_blocks)
}

/// decompresses a deflate stream and returns the plaintext and cabac_encoded data that can be used to reconstruct it
/// This version uses DebugWriter and DebugReader, which are slower but can be used to debug the cabac encoding errors.
#[cfg(test)]
fn decompress_deflate_stream_assert(
    compressed_data: &[u8],
    verify: bool,
) -> Result<DecompressResult> {
    use crate::deflate::deflate_reader::parse_deflate_whole;
    use cabac::debug::{DebugReader, DebugWriter};

    use crate::preflate_error::AddContext;

    let mut cabac_encoded = Vec::new();

    let mut cabac_encoder =
        PredictionEncoderCabac::new(DebugWriter::new(&mut cabac_encoded).unwrap());

    let (contents, plain_text) = parse_deflate_whole(compressed_data)?;

    let params =
        PreflateParameters::estimate_preflate_parameters(&contents, &plain_text).context()?;

    encode_mispredictions(&contents, &plain_text, &params, &mut cabac_encoder, false)?;
    assert_eq!(contents.compressed_size, compressed_data.len());
    cabac_encoder.finish();

    let reconstruction_data = bitcode::encode(&ReconstructionData {
        parameters: params,
        corrections: cabac_encoded,
    });

    if verify {
        let r = ReconstructionData::read(&reconstruction_data)?;

        let mut cabac_decoder =
            PredictionDecoderCabac::new(DebugReader::new(Cursor::new(&r.corrections)).unwrap());

        let params = r.parameters;
        let mut input = PreflateInput::new(&plain_text);
        let (recompressed, _recreated_blocks) =
            decode_mispredictions(&params, &mut input, &mut cabac_decoder, false)?;

        if recompressed[..] != compressed_data[..] {
            return Err(PreflateError::new(
                ExitCode::RoundtripMismatch,
                "recompressed data does not match original",
            ));
        }
    }

    Ok(DecompressResult {
        plain_text,
        corrections: reconstruction_data,
        compressed_size: contents.compressed_size,
        parameters: Some(params),
        continue_state: None,
    })
}

#[test]
fn verify_roundtrip_assert() {
    use crate::utils::read_file;

    let v = read_file("compressed_zlib_level1.deflate");

    let r = decompress_deflate_stream_assert(&v, true).unwrap();
    let recompressed = recompress_deflate_stream_assert(&r.plain_text, &r.corrections).unwrap();
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
    use crate::utils::read_file;
    let v = read_file(filename);

    let r = decompress_deflate_stream(None, &v, true, 1).unwrap();
    let recompressed = recompress_deflate_stream(&r.plain_text, &r.corrections).unwrap();
    assert!(v == recompressed);
}

/// recompresses a deflate stream using the cabac_encoded data that was returned from decompress_deflate_stream
/// This version uses DebugWriter and DebugReader, which are slower and don't compress but can be used to debug the cabac encoding errors.
#[cfg(test)]
fn recompress_deflate_stream_assert(
    plain_text: &PlainText,
    prediction_corrections: &[u8],
) -> Result<Vec<u8>> {
    use cabac::debug::DebugReader;

    let r = ReconstructionData::read(prediction_corrections)?;

    let mut cabac_decoder =
        PredictionDecoderCabac::new(DebugReader::new(Cursor::new(&r.corrections)).unwrap());

    let mut input = PreflateInput::new(plain_text);
    let (recompressed, _recreated_blocks) =
        decode_mispredictions(&r.parameters, &mut input, &mut cabac_decoder, false)?;
    Ok(recompressed)
}

#[cfg(test)]
fn analyze_compressed_data_fast(
    compressed_data: &[u8],
    header_crc32: Option<u32>,
    uncompressed_size: &mut u64,
) {
    use crate::{
        cabac_codec::{PredictionDecoderCabac, PredictionEncoderCabac},
        deflate::deflate_reader::parse_deflate_whole,
    };
    use std::io::Cursor;

    use cabac::vp8::{VP8Reader, VP8Writer};

    let mut buffer = Vec::new();

    let mut cabac_encoder = PredictionEncoderCabac::new(VP8Writer::new(&mut buffer).unwrap());

    let (contents, plain_text) = parse_deflate_whole(compressed_data).unwrap();

    let params = PreflateParameters::estimate_preflate_parameters(&contents, &plain_text).unwrap();

    println!("params: {:?}", params);

    encode_mispredictions(&contents, &plain_text, &params, &mut cabac_encoder, false).unwrap();

    if let Some(crc) = header_crc32 {
        let result_crc = crc32fast::hash(&plain_text.text());
        assert_eq!(result_crc, crc);
    }

    assert_eq!(contents.compressed_size, compressed_data.len());

    cabac_encoder.finish();

    cabac_encoder.print();

    println!("buffer size: {}", buffer.len());

    let mut cabac_decoder =
        PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(&buffer)).unwrap());

    let mut input = PreflateInput::new(&plain_text);

    let (recompressed, _recreated_blocks) =
        decode_mispredictions(&params, &mut input, &mut cabac_decoder, false).unwrap();

    assert!(recompressed[..] == compressed_data[..]);

    *uncompressed_size = plain_text.text().len() as u64;
}

#[cfg(test)]
fn analyze_compressed_data_verify(
    compressed_data: &[u8],
    header_crc32: Option<u32>,
    _deflate_info_dump_level: i32,
    uncompressed_size: &mut u64,
) {
    use crate::{
        cabac_codec::{PredictionDecoderCabac, PredictionEncoderCabac},
        deflate::{deflate_reader::parse_deflate_whole, deflate_token::DeflateTokenBlockType},
        statistical_codec::{VerifyPredictionDecoder, VerifyPredictionEncoder},
        utils::assert_eq_array,
    };
    use cabac::debug::{DebugReader, DebugWriter};
    use std::io::Cursor;

    let mut buffer = Vec::new();

    let cabac_encoder = PredictionEncoderCabac::new(DebugWriter::new(&mut buffer).unwrap());
    let debug_encoder = VerifyPredictionEncoder::new();

    let mut combined_encoder = (debug_encoder, cabac_encoder);

    let (contents, plain_text) = parse_deflate_whole(compressed_data).unwrap();

    let params = PreflateParameters::estimate_preflate_parameters(&contents, &plain_text).unwrap();

    println!("params: {:?}", params);

    encode_mispredictions(
        &contents,
        &plain_text,
        &params,
        &mut combined_encoder,
        false,
    )
    .unwrap();

    assert_eq!(contents.compressed_size, compressed_data.len());

    combined_encoder.finish();

    combined_encoder.0.print();

    let actions = combined_encoder.0.actions();

    println!("buffer size: {}", buffer.len());

    let debug_decoder = VerifyPredictionDecoder::new(actions);
    let cabac_decoder =
        PredictionDecoderCabac::new(DebugReader::new(Cursor::new(&buffer)).unwrap());

    let mut combined_decoder = (debug_decoder, cabac_decoder);
    let mut input = PreflateInput::new(&plain_text);

    let (recompressed, recreated_blocks) =
        decode_mispredictions(&params, &mut input, &mut combined_decoder, false).unwrap();

    assert_eq!(contents.blocks.len(), recreated_blocks.len());
    contents
        .blocks
        .iter()
        .zip(recreated_blocks)
        .enumerate()
        .for_each(|(index, (a, b))| match (&a.block_type, &b.block_type) {
            (
                DeflateTokenBlockType::Stored {
                    uncompressed: a,
                    head_padding_bits: b,
                },
                DeflateTokenBlockType::Stored {
                    uncompressed: c,
                    head_padding_bits: d,
                },
            ) => {
                assert_eq!(a, c, "uncompressed data differs {index}");
                assert_eq!(b, d, "padding bits differ {index}");
            }
            (
                DeflateTokenBlockType::Huffman {
                    tokens: t1,
                    huffman_type: h1,
                    tail_padding_bits: p1,
                    partial: part1,
                },
                DeflateTokenBlockType::Huffman {
                    tokens: t2,
                    huffman_type: h2,
                    tail_padding_bits: p2,
                    partial: part2,
                },
            ) => {
                assert_eq_array(t1, t2);
                assert_eq!(h1, h2, "huffman type differs {index}");
                assert_eq!(p1, p2, "padding bits differ {index}");
                assert_eq!(part1, part2, "partial differ {index}");
            }
            _ => panic!("block type differs {index}"),
        });

    assert_eq!(
        recompressed.len(),
        compressed_data.len(),
        "re-compressed version should be same (length)"
    );
    assert!(
        &recompressed[..] == compressed_data,
        "re-compressed version should be same (content)"
    );

    let result_crc = crc32fast::hash(&plain_text.text());

    if let Some(crc) = header_crc32 {
        assert_eq!(crc, result_crc, "crc mismatch");
    }

    *uncompressed_size = plain_text.text().len() as u64;
}

#[cfg(test)]
fn do_analyze(crc: Option<u32>, compressed_data: &[u8], verify: bool) {
    let mut uncompressed_size = 0;

    if verify {
        analyze_compressed_data_verify(compressed_data, crc, 1, &mut uncompressed_size);
    } else {
        analyze_compressed_data_fast(compressed_data, crc, &mut uncompressed_size);
    }
}

/// verify that levels 1-6 of zlib are compressed without any correction data
///
/// Future work: figure out why level 7 and above are not perfect
#[test]
fn verify_zlib_perfect_compression() {
    use crate::deflate::deflate_reader::parse_deflate_whole;
    use crate::utils::read_file;

    for i in 1..6 {
        println!("iteration {}", i);
        let compressed_data: &[u8] =
            &read_file(format!("compressed_zlib_level{i}.deflate").as_str());

        let compressed_data = compressed_data;

        let (contents, plain_text) = parse_deflate_whole(compressed_data).unwrap();

        let params =
            PreflateParameters::estimate_preflate_parameters(&contents, &plain_text).unwrap();

        println!("params: {:?}", params);

        // this "encoder" just asserts if anything gets passed to it
        let mut verify_encoder = crate::statistical_codec::AssertDefaultOnlyEncoder {};
        encode_mispredictions(&contents, &plain_text, &params, &mut verify_encoder, false).unwrap();

        println!("params buffer length {}", bitcode::encode(&params).len());
    }
}

#[test]
fn verify_longmatch() {
    use crate::utils::read_file;
    do_analyze(
        None,
        &read_file("compressed_flate2_level1_longmatch.deflate"),
        false,
    );
}

#[test]
fn verify_zlibng() {
    use crate::utils::read_file;

    do_analyze(None, &read_file("compressed_zlibng_level1.deflate"), false);
}

#[test]
fn verify_miniz() {
    use crate::utils::read_file;

    do_analyze(
        None,
        &read_file("compressed_minizoxide_level1.deflate"),
        false,
    );
}

// this is the deflate stream extracted out of the
#[test]
fn verify_png_deflate() {
    use crate::utils::read_file;
    do_analyze(None, &read_file("treegdi.extract.deflate"), false);
}
