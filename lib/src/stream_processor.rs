/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

//! Responsible for performing preflate and recreation on a chunk by chunk basis

use std::io::{BufRead, Cursor};

use bitcode::{Decode, Encode};
use cabac::vp8::{VP8Reader, VP8Writer};

use crate::{
    cabac_codec::{PredictionDecoderCabac, PredictionEncoderCabac},
    deflate::{
        deflate_reader::DeflateParser, deflate_token::DeflateTokenBlock,
        deflate_writer::DeflateWriter,
    },
    estimator::preflate_parameter_estimator::{
        estimate_preflate_parameters, TokenPredictorParameters,
    },
    preflate_error::{AddContext, ExitCode, PreflateError},
    preflate_input::{PlainText, PreflateInput},
    statistical_codec::{CodecCorrection, PredictionDecoder, PredictionEncoder},
    token_predictor::TokenPredictor,
    Result,
};

/// the data required to reconstruct the deflate stream exactly the way that it was
#[derive(Encode, Decode)]
struct ReconstructionData {
    pub parameters: TokenPredictorParameters,
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

/// Result of a call to PreflateStreamProcessor::decompress
pub struct PreflateStreamChunkResult {
    /// the extra data that is needed to reconstruct the deflate stream exactly as it was written
    pub corrections: Vec<u8>,

    /// the number of bytes that were processed from the compressed stream (this will be exactly the
    /// data that will be recreated using the cabac_encoded data)
    pub compressed_size: usize,

    /// the parameters that were used to compress the stream. Only returned for the first
    /// chunk that is passed in.
    pub parameters: Option<TokenPredictorParameters>,

    pub blocks: Vec<DeflateTokenBlock>,
}

/// Takes a stream of deflate compressed data removes the deflate compression, recording the data
/// that can be used to reconstruct it along with the plain-text.
#[derive(Debug)]
pub struct PreflateStreamProcessor {
    predictor: Option<TokenPredictor>,
    validator: Option<RecreateStreamProcessor>,
    parser: DeflateParser,
}

impl PreflateStreamProcessor {
    /// Creates a new PreflateStreamProcessor
    /// plain_text_limit: the maximum size of the plain text that will decompressed to memory
    /// verify: if true, the decompressed data will be recompressed and compared to the original as it is run
    pub fn new(plain_text_limit: usize, verify: bool) -> Self {
        Self {
            predictor: None,
            parser: DeflateParser::new(plain_text_limit),
            validator: if verify {
                Some(RecreateStreamProcessor::new())
            } else {
                None
            },
        }
    }

    pub fn is_done(&self) -> bool {
        self.parser.is_done()
    }

    pub fn plain_text(&self) -> &PlainText {
        &self.parser.plain_text()
    }

    pub fn shrink_to_dictionary(&mut self) {
        self.parser.shrink_to_dictionary();
    }

    pub fn detach_plain_text(self) -> PlainText {
        self.parser.detach_plain_text()
    }

    /// decompresses a deflate stream and returns the plaintext and cabac_encoded data that can be used to reconstruct it
    pub fn decompress(
        &mut self,
        compressed_data: &[u8],
        _loglevel: u32,
    ) -> Result<PreflateStreamChunkResult> {
        let contents = self.parser.parse(compressed_data)?;

        let mut cabac_encoded = Vec::new();

        let mut cabac_encoder =
            PredictionEncoderCabac::new(VP8Writer::new(&mut cabac_encoded).unwrap());

        if let Some(predictor) = &mut self.predictor {
            let mut input = PreflateInput::new(&self.parser.plain_text());

            // we are missing the last couple hashes in the dictionary since we didn't
            // have the full plaintext yet.
            predictor.add_missing_previous_hash(&input);

            predict_blocks(&contents.blocks, predictor, &mut cabac_encoder, &mut input)?;

            cabac_encoder.finish();

            if let Some(validator) = &mut self.validator {
                let (recompressed, _rec_blocks) = validator.recompress(
                    &mut Cursor::new(self.parser.plain_text().text()),
                    &cabac_encoded,
                )?;

                #[cfg(test)]
                for i in 0..contents.blocks.len() {
                    crate::utils::assert_block_eq(&contents.blocks[i], &_rec_blocks[i]);
                }

                // we should always succeed here in test code
                #[cfg(test)]
                crate::utils::assert_eq_array(
                    &recompressed,
                    &compressed_data[..contents.compressed_size],
                );

                if recompressed[..] != compressed_data[..contents.compressed_size] {
                    return Err(PreflateError::new(
                        ExitCode::RoundtripMismatch,
                        "recompressed data does not match original",
                    ));
                }
            }

            Ok(PreflateStreamChunkResult {
                corrections: cabac_encoded,
                compressed_size: contents.compressed_size,
                parameters: None,
                blocks: contents.blocks,
            })
        } else {
            let params =
                estimate_preflate_parameters(&contents, &self.parser.plain_text()).context()?;

            let mut input = PreflateInput::new(&self.parser.plain_text());

            let mut token_predictor = TokenPredictor::new(&params);

            predict_blocks(
                &contents.blocks,
                &mut token_predictor,
                &mut cabac_encoder,
                &mut input,
            )?;

            cabac_encoder.finish();

            let reconstruction_data = bitcode::encode(&ReconstructionData {
                parameters: params,
                corrections: cabac_encoded,
            });

            self.predictor = Some(token_predictor);

            if let Some(validator) = &mut self.validator {
                let (recompressed, _rec_blocks) = validator.recompress(
                    &mut Cursor::new(self.parser.plain_text().text()),
                    &reconstruction_data,
                )?;

                #[cfg(test)]
                for i in 0..contents.blocks.len() {
                    crate::utils::assert_block_eq(&contents.blocks[i], &_rec_blocks[i]);
                }

                // we should always succeed here in test code
                #[cfg(test)]
                crate::utils::assert_eq_array(
                    &recompressed,
                    &compressed_data[..contents.compressed_size],
                );

                if recompressed[..] != compressed_data[..contents.compressed_size] {
                    return Err(PreflateError::new(
                        ExitCode::RoundtripMismatch,
                        "recompressed data does not match original",
                    ));
                }
            }

            Ok(PreflateStreamChunkResult {
                corrections: reconstruction_data,
                compressed_size: contents.compressed_size,
                parameters: Some(params),
                blocks: contents.blocks,
            })
        }
    }
}

/// Decompresses a deflate stream and returns the plaintext and diff data that can be used to reconstruct it
/// via recreate_whole_deflate_stream
pub fn preflate_whole_deflate_stream(
    compressed_data: &[u8],
    verify: bool,
    loglevel: u32,
    plain_text_limit: usize,
) -> Result<(PreflateStreamChunkResult, PlainText)> {
    let mut state = PreflateStreamProcessor::new(plain_text_limit, verify);
    let r = state.decompress(compressed_data, loglevel)?;

    Ok((r, state.parser.detach_plain_text()))
}

/// recreates the original deflate stream, piece-by-piece
#[derive(Debug)]
pub struct RecreateStreamProcessor {
    predictor: Option<TokenPredictor>,
    writer: DeflateWriter,
    plain_text: PlainText,
}

impl RecreateStreamProcessor {
    pub fn new() -> Self {
        Self {
            predictor: None,
            writer: DeflateWriter::new(),
            plain_text: PlainText::new(),
        }
    }

    pub fn recompress(
        &mut self,
        plain_text: &mut impl BufRead,
        corrections: &[u8],
    ) -> Result<(Vec<u8>, Vec<DeflateTokenBlock>)> {
        loop {
            let buf = plain_text.fill_buf().context()?;
            let buf_len = buf.len();
            if buf_len == 0 {
                break;
            }

            self.plain_text.append(&buf);

            plain_text.consume(buf_len);
        }

        let mut input = PreflateInput::new(&self.plain_text);

        if let Some(predictor) = &mut self.predictor {
            let mut cabac_decoder =
                PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(corrections)).unwrap());

            predictor.add_missing_previous_hash(&input);

            let blocks =
                recreate_blocks(predictor, &mut cabac_decoder, &mut self.writer, &mut input)
                    .context()?;

            self.plain_text.shrink_to_dictionary();

            self.writer.flush();

            Ok((self.writer.detach_output(), blocks))
        } else {
            let r = ReconstructionData::read(corrections)?;

            let mut predictor = TokenPredictor::new(&r.parameters);

            let mut cabac_decoder =
                PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(r.corrections)).unwrap());

            let blocks = recreate_blocks(
                &mut predictor,
                &mut cabac_decoder,
                &mut self.writer,
                &mut input,
            )
            .context()?;

            self.predictor = Some(predictor);

            self.plain_text.shrink_to_dictionary();

            self.writer.flush();

            Ok((self.writer.detach_output(), blocks))
        }
    }
}

/// recompresses a deflate stream using the cabac_encoded data that was returned from decompress_deflate_stream
pub fn recreate_whole_deflate_stream(
    plain_text: &[u8],
    prediction_corrections: &[u8],
) -> Result<Vec<u8>> {
    let mut state = RecreateStreamProcessor::new();

    let (recompressed, _) =
        state.recompress(&mut Cursor::new(&plain_text), prediction_corrections)?;

    Ok(recompressed)
}

/// takes a deflate compressed stream, analyzes it, decoompresses it, and records
/// any differences in the encoder codec
#[cfg(test)]
fn encode_mispredictions(
    deflate: &crate::deflate::deflate_reader::DeflateContents,
    plain_text: &PlainText,
    params: &TokenPredictorParameters,
    encoder: &mut impl PredictionEncoder,
) -> Result<()> {
    let mut input = PreflateInput::new(plain_text);

    let mut token_predictor = TokenPredictor::new(&params);

    predict_blocks(&deflate.blocks, &mut token_predictor, encoder, &mut input)?;

    Ok(())
}

fn predict_blocks(
    blocks: &[DeflateTokenBlock],
    token_predictor: &mut TokenPredictor,
    encoder: &mut impl PredictionEncoder,
    input: &mut PreflateInput,
) -> Result<()> {
    for i in 0..blocks.len() {
        token_predictor.predict_block(&blocks[i], encoder, input, i == blocks.len() - 1)?;
        // end of stream normally is the last block
        encoder.encode_correction_bool(
            CodecCorrection::EndOfChunk,
            i == blocks.len() - 1,
            input.remaining() == 0,
        );
    }
    assert!(input.remaining() == 0);
    Ok(())
}

#[cfg(test)]
fn decode_mispredictions(
    params: &TokenPredictorParameters,
    input: &mut PreflateInput,
    decoder: &mut impl crate::statistical_codec::PredictionDecoder,
) -> Result<(Vec<u8>, Vec<DeflateTokenBlock>)> {
    let mut deflate_writer: DeflateWriter = DeflateWriter::new();
    let mut predictor = TokenPredictor::new(&params);

    let output_blocks = recreate_blocks(&mut predictor, decoder, &mut deflate_writer, input)?;

    deflate_writer.flush();

    Ok((deflate_writer.detach_output(), output_blocks))
}

fn recreate_blocks<D: PredictionDecoder>(
    token_predictor: &mut TokenPredictor,
    decoder: &mut D,
    deflate_writer: &mut DeflateWriter,
    input: &mut PreflateInput,
) -> Result<Vec<DeflateTokenBlock>> {
    let mut output_blocks = Vec::new();
    loop {
        let block = token_predictor.recreate_block(decoder, input)?;

        deflate_writer.encode_block(&block)?;

        output_blocks.push(block);

        // end of stream normally is the last block
        let last =
            decoder.decode_correction_bool(CodecCorrection::EndOfChunk, input.remaining() == 0);

        if last {
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
) -> Result<(PreflateStreamChunkResult, PlainText)> {
    use crate::deflate::deflate_reader::parse_deflate_whole;
    use cabac::debug::{DebugReader, DebugWriter};

    use crate::preflate_error::AddContext;

    let mut cabac_encoded = Vec::new();

    let mut cabac_encoder =
        PredictionEncoderCabac::new(DebugWriter::new(&mut cabac_encoded).unwrap());

    let (contents, plain_text) = parse_deflate_whole(compressed_data)?;

    let params = estimate_preflate_parameters(&contents, &plain_text).context()?;

    encode_mispredictions(&contents, &plain_text, &params, &mut cabac_encoder)?;
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
            decode_mispredictions(&params, &mut input, &mut cabac_decoder)?;

        if recompressed[..] != compressed_data[..] {
            return Err(PreflateError::new(
                ExitCode::RoundtripMismatch,
                "recompressed data does not match original",
            ));
        }
    }

    Ok((
        PreflateStreamChunkResult {
            corrections: reconstruction_data,
            compressed_size: contents.compressed_size,
            parameters: Some(params),
            blocks: contents.blocks,
        },
        plain_text,
    ))
}

#[test]
fn verify_roundtrip_assert() {
    use crate::utils::read_file;

    let v = read_file("compressed_zlib_level1.deflate");

    let (r, plain_text) = decompress_deflate_stream_assert(&v, true).unwrap();
    let recompressed = recompress_deflate_stream_assert(&plain_text, &r.corrections).unwrap();
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

    let (r, plain_text) = preflate_whole_deflate_stream(&v, true, 1, usize::MAX).unwrap();
    let recompressed = recreate_whole_deflate_stream(plain_text.text(), &r.corrections).unwrap();
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
        decode_mispredictions(&r.parameters, &mut input, &mut cabac_decoder)?;
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

    let params = estimate_preflate_parameters(&contents, &plain_text).unwrap();

    println!("params: {:?}", params);

    encode_mispredictions(&contents, &plain_text, &params, &mut cabac_encoder).unwrap();

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
        decode_mispredictions(&params, &mut input, &mut cabac_decoder).unwrap();

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

    let params = estimate_preflate_parameters(&contents, &plain_text).unwrap();

    println!("params: {:?}", params);

    encode_mispredictions(&contents, &plain_text, &params, &mut combined_encoder).unwrap();

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
        decode_mispredictions(&params, &mut input, &mut combined_decoder).unwrap();

    assert_eq!(contents.blocks.len(), recreated_blocks.len());
    contents
        .blocks
        .iter()
        .zip(recreated_blocks)
        .enumerate()
        .for_each(|(index, (a, b))| match (&a.block_type, &b.block_type) {
            (
                DeflateTokenBlockType::Stored { uncompressed: a },
                DeflateTokenBlockType::Stored { uncompressed: c },
            ) => {
                assert_eq!(a, c, "uncompressed data differs {index}");
            }
            (
                DeflateTokenBlockType::Huffman {
                    tokens: t1,
                    huffman_type: h1,
                },
                DeflateTokenBlockType::Huffman {
                    tokens: t2,
                    huffman_type: h2,
                },
            ) => {
                assert_eq_array(t1, t2);
                assert_eq!(h1, h2, "huffman type differs {index}");
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
fn do_analyze(crc: Option<u32>, compressed_data: &[u8]) {
    let mut uncompressed_size = 0;

    analyze_compressed_data_verify(compressed_data, crc, 1, &mut uncompressed_size);
    analyze_compressed_data_fast(compressed_data, crc, &mut uncompressed_size);
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

        let params = estimate_preflate_parameters(&contents, &plain_text).unwrap();

        println!("params: {:?}", params);

        // this "encoder" just asserts if anything gets passed to it
        let mut verify_encoder = crate::statistical_codec::AssertDefaultOnlyEncoder {};
        encode_mispredictions(&contents, &plain_text, &params, &mut verify_encoder).unwrap();

        println!("params buffer length {}", bitcode::encode(&params).len());
    }
}

#[test]
fn verify_longmatch() {
    use crate::utils::read_file;
    do_analyze(
        None,
        &read_file("compressed_flate2_level1_longmatch.deflate"),
    );
}

#[test]
fn verify_zlibng() {
    use crate::utils::read_file;

    do_analyze(None, &read_file("compressed_zlibng_level1.deflate"));
}

#[test]
fn verify_miniz() {
    use crate::utils::read_file;

    do_analyze(None, &read_file("compressed_minizoxide_level1.deflate"));
}

/// this is the deflate stream extracted out of the png file (minus the idat wrapper)
#[test]
fn verify_png_deflate() {
    use crate::utils::read_file;
    do_analyze(None, &read_file("treegdi.extract.deflate"));
}

#[cfg(test)]
pub fn analyze_compressed_data_verify_incremental(compressed_data: &[u8], plain_text_limit: usize) {
    use crate::{deflate::deflate_reader::parse_deflate_whole, utils::assert_eq_array};

    let (original_con, _) = parse_deflate_whole(compressed_data).unwrap();

    let mut start_offset = 0;
    let mut end_offset = compressed_data.len().min(100001);

    let mut stream = PreflateStreamProcessor::new(plain_text_limit, true);

    let mut plain_text_offset = 0;

    let mut expanded_contents = Vec::new();
    while !stream.is_done() {
        let result = stream.decompress(&compressed_data[start_offset..end_offset], 1);
        match result {
            Ok(r) => {
                println!(
                    "chunk cmp_start={} cmp_size={} blocks={} pt_off={}({})",
                    start_offset,
                    r.compressed_size,
                    r.blocks.len(),
                    plain_text_offset,
                    stream.plain_text().len()
                );
                start_offset += r.compressed_size;
                end_offset = (start_offset + 10001).min(compressed_data.len());

                plain_text_offset += stream.plain_text().len();
                expanded_contents.push((r.corrections, stream.plain_text().text().to_vec()));

                stream.shrink_to_dictionary();
            }
            Err(e) => {
                if e.exit_code() == ExitCode::PredictionFailure {
                    println!("Prediction failure for {:?} not great, but some corner cases where the initial estimator isn't totaly right", e);
                    return;
                }
                assert_eq!(
                    e.exit_code(),
                    ExitCode::ShortRead,
                    "unexpected error {:?}",
                    e
                );
                end_offset = (end_offset + 10001).min(compressed_data.len());
            }
        }
    }

    // now reconstruct the data and make sure it is identical
    let mut recompressed = Vec::new();
    let mut reconstructed_blocks = Vec::new();

    let mut reconstruct = RecreateStreamProcessor::new();
    for i in 0..expanded_contents.len() {
        let (mut r, mut b) = reconstruct
            .recompress(
                &mut Cursor::new(&expanded_contents[i].1),
                &expanded_contents[i].0,
            )
            .unwrap();

        println!(
            "reconstruct block offset={} blocks={} pt={}",
            i,
            b.len(),
            expanded_contents[i].1.len()
        );

        recompressed.append(&mut r);
        reconstructed_blocks.append(&mut b);
    }

    //assert_eq!(original_con.blocks.len(), reconstructed_blocks.len());
    for i in 0..original_con.blocks.len() {
        println!("block {}", i);
        crate::utils::assert_block_eq(&original_con.blocks[i], &reconstructed_blocks[i]);
    }

    assert_eq_array(compressed_data, &recompressed);
}

#[test]
fn verify_plain_text_limit() {
    analyze_compressed_data_verify_incremental(
        &crate::utils::read_file("compressed_zlib_level3.deflate"),
        1 * 1024 * 1024,
    );
}

/// test partial reading reading
#[test]
fn verify_partial_blocks() {
    for i in 0..=9 {
        analyze_compressed_data_verify_incremental(
            &crate::utils::read_file(&format!("compressed_zlib_level{}.deflate", i)),
            usize::MAX,
        );
    }
}
