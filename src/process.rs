/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use std::io::Cursor;

use crate::{
    deflate_reader::DeflateReader,
    deflate_writer::DeflateWriter,
    preflate_error::PreflateError,
    preflate_input::PreflateInput,
    preflate_parameter_estimator::PreflateParameters,
    preflate_token::PreflateTokenBlock,
    statistical_codec::{
        CodecCorrection, CodecMisprediction, PredictionDecoder, PredictionEncoder,
    },
    token_predictor::TokenPredictor,
};

/// takes a deflate compressed stream, analyzes it, decoompresses it, and records
/// any differences in the encoder codec
pub fn encode_mispredictions(
    deflate: &DeflateContents,
    params: &PreflateParameters,
    encoder: &mut impl PredictionEncoder,
) -> Result<(), PreflateError> {
    predict_blocks(
        &deflate.blocks,
        TokenPredictor::new(PreflateInput::new(&deflate.plain_text), &params.predictor),
        encoder,
    )?;

    encoder.encode_misprediction(CodecMisprediction::EOFMisprediction, false);

    encoder.encode_correction(CodecCorrection::NonZeroPadding, deflate.eof_padding.into());

    Ok(())
}

pub struct DeflateContents {
    pub compressed_size: usize,
    pub plain_text: Vec<u8>,
    pub blocks: Vec<PreflateTokenBlock>,
    pub eof_padding: u8,
}

pub fn parse_deflate(
    compressed_data: &[u8],
    deflate_info_dump_level: u32,
) -> Result<DeflateContents, PreflateError> {
    let mut input_stream = Cursor::new(compressed_data);
    let mut block_decoder = DeflateReader::new(&mut input_stream);
    let mut blocks = Vec::new();
    let mut last = false;
    while !last {
        let block = block_decoder.read_block(&mut last)?;

        if deflate_info_dump_level > 0 {
            // Log information about this deflate compressed block
            match &block {
                PreflateTokenBlock::Stored {
                    uncompressed,
                    padding_bits,
                } => {
                    println!(
                        "Block: stored, uncompressed={} padding_bits={}",
                        uncompressed.len(),
                        padding_bits
                    );
                }
                PreflateTokenBlock::StaticHuff { tokens, .. } => {
                    println!("StaticBlock: tokens={}", tokens.len());
                }

                PreflateTokenBlock::DynamicHuff { tokens, .. } => {
                    println!("DynamicBlock: tokens={}", tokens.len());
                }
            }
        }

        blocks.push(block);
    }
    let eof_padding = block_decoder.read_eof_padding();
    let plain_text = block_decoder.move_plain_text();
    let compressed_size = input_stream.position() as usize;

    /*// write to file
     let mut f = std::fs::File::create("c:\\temp\\treegdi.deflate")
    .unwrap();
    std::io::Write::write_all(&mut f, &compressed_data[0..compressed_size]).unwrap();*/

    Ok(DeflateContents {
        compressed_size,
        plain_text,
        blocks,
        eof_padding,
    })
}

fn predict_blocks(
    blocks: &[PreflateTokenBlock],
    mut token_predictor_in: TokenPredictor,
    encoder: &mut impl PredictionEncoder,
) -> Result<(), PreflateError> {
    for i in 0..blocks.len() {
        if token_predictor_in.input_eof() {
            encoder.encode_misprediction(CodecMisprediction::EOFMisprediction, true);
        }

        token_predictor_in.predict_block(&blocks[i], encoder, i == blocks.len() - 1)?;
    }
    assert!(token_predictor_in.input_eof());
    Ok(())
}

pub fn decode_mispredictions(
    params: &PreflateParameters,
    plain_text: PreflateInput,
    decoder: &mut impl PredictionDecoder,
) -> Result<(Vec<u8>, Vec<PreflateTokenBlock>), PreflateError> {
    let mut deflate_writer: DeflateWriter = DeflateWriter::new();

    let output_blocks = recreate_blocks(
        TokenPredictor::new(plain_text, &params.predictor),
        decoder,
        &mut deflate_writer,
    )?;

    // flush the last byte, which may be incomplete and normally
    // padded with zeros, but maybe not
    let padding = decoder.decode_correction(CodecCorrection::NonZeroPadding) as u8;
    deflate_writer.flush_with_padding(padding);

    Ok((deflate_writer.detach_output(), output_blocks))
}

#[inline(never)]
fn recreate_blocks<D: PredictionDecoder>(
    mut token_predictor: TokenPredictor,
    decoder: &mut D,
    deflate_writer: &mut DeflateWriter,
) -> Result<Vec<PreflateTokenBlock>, PreflateError> {
    let mut output_blocks = Vec::new();
    let mut is_eof = token_predictor.input_eof()
        && !decoder.decode_misprediction(CodecMisprediction::EOFMisprediction);
    while !is_eof {
        let block = token_predictor.recreate_block(decoder)?;

        is_eof = token_predictor.input_eof()
            && !decoder.decode_misprediction(CodecMisprediction::EOFMisprediction);

        deflate_writer.encode_block(&block, is_eof)?;

        output_blocks.push(block);
    }
    Ok(output_blocks)
}

#[allow(dead_code)]
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

#[cfg(test)]
fn analyze_compressed_data_fast(
    compressed_data: &[u8],
    header_crc32: Option<u32>,
    uncompressed_size: &mut u64,
) {
    use crate::cabac_codec::{PredictionDecoderCabac, PredictionEncoderCabac};
    use crate::preflate_parameter_estimator::estimate_preflate_parameters;

    use cabac::vp8::{VP8Reader, VP8Writer};

    let mut buffer = Vec::new();

    let mut cabac_encoder = PredictionEncoderCabac::new(VP8Writer::new(&mut buffer).unwrap());

    let contents = parse_deflate(compressed_data, 1).unwrap();

    let params = estimate_preflate_parameters(&contents.plain_text, &contents.blocks).unwrap();

    println!("params: {:?}", params);

    params.write(&mut cabac_encoder);
    encode_mispredictions(&contents, &params, &mut cabac_encoder).unwrap();

    if let Some(crc) = header_crc32 {
        let result_crc = crc32fast::hash(&contents.plain_text);
        assert_eq!(result_crc, crc);
    }

    assert_eq!(contents.compressed_size, compressed_data.len());

    cabac_encoder.finish();

    cabac_encoder.print();

    println!("buffer size: {}", buffer.len());

    let mut cabac_decoder =
        PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(&buffer)).unwrap());

    let params = PreflateParameters::read(&mut cabac_decoder).unwrap();

    let (recompressed, _recreated_blocks) = decode_mispredictions(
        &params,
        PreflateInput::new(&contents.plain_text),
        &mut cabac_decoder,
    )
    .unwrap();

    assert!(recompressed[..] == compressed_data[..]);

    *uncompressed_size = contents.plain_text.len() as u64;
}

#[cfg(test)]
fn analyze_compressed_data_verify(
    compressed_data: &[u8],
    header_crc32: Option<u32>,
    _deflate_info_dump_level: i32,
    uncompressed_size: &mut u64,
) {
    use crate::preflate_parameter_estimator::estimate_preflate_parameters;
    use crate::{
        cabac_codec::{PredictionDecoderCabac, PredictionEncoderCabac},
        statistical_codec::{VerifyPredictionDecoder, VerifyPredictionEncoder},
    };
    use cabac::debug::{DebugReader, DebugWriter};

    fn compare<T: PartialEq + std::fmt::Debug>(a: &[T], b: &[T], str: &str) {
        if a.len() != b.len() {
            panic!("lengths differ {}", str);
        }

        for i in 0..a.len() {
            if a[i] != b[i] {
                panic!("index {} differs ({:?},{:?}) {}", i, a[i], b[i], str);
            }
        }
    }

    let mut buffer = Vec::new();

    let cabac_encoder = PredictionEncoderCabac::new(DebugWriter::new(&mut buffer).unwrap());
    let debug_encoder = VerifyPredictionEncoder::new();

    let mut combined_encoder = (debug_encoder, cabac_encoder);

    let contents = parse_deflate(compressed_data, 1).unwrap();

    let params = estimate_preflate_parameters(&contents.plain_text, &contents.blocks).unwrap();

    println!("params: {:?}", params);

    params.write(&mut combined_encoder);
    encode_mispredictions(&contents, &params, &mut combined_encoder).unwrap();

    assert_eq!(contents.compressed_size, compressed_data.len());

    combined_encoder.finish();

    combined_encoder.0.print();

    let actions = combined_encoder.0.actions();

    println!("buffer size: {}", buffer.len());

    let debug_decoder = VerifyPredictionDecoder::new(actions);
    let cabac_decoder =
        PredictionDecoderCabac::new(DebugReader::new(Cursor::new(&buffer)).unwrap());

    let mut combined_decoder = (debug_decoder, cabac_decoder);

    let params_reread = PreflateParameters::read(&mut combined_decoder).unwrap();
    assert_eq!(params, params_reread);

    let (recompressed, recreated_blocks) = decode_mispredictions(
        &params_reread,
        PreflateInput::new(&contents.plain_text),
        &mut combined_decoder,
    )
    .unwrap();

    assert_eq!(contents.blocks.len(), recreated_blocks.len());
    contents
        .blocks
        .iter()
        .zip(recreated_blocks)
        .enumerate()
        .for_each(|(index, (a, b))| match (a, &b) {
            (
                PreflateTokenBlock::Stored {
                    uncompressed: a,
                    padding_bits: b,
                },
                PreflateTokenBlock::Stored {
                    uncompressed: c,
                    padding_bits: d,
                },
            ) => {
                assert_eq!(a, c, "uncompressed data differs {index}");
                assert_eq!(b, d, "padding bits differ {index}");
            }
            (
                PreflateTokenBlock::StaticHuff {
                    tokens: t1,
                    incomplete: i1,
                },
                PreflateTokenBlock::StaticHuff {
                    tokens: t2,
                    incomplete: i2,
                },
            ) => {
                compare(t1, t2, &format!("tokens differ {index}"));
                assert_eq!(i1, i2, "incomplete flag differs {index}");
            }
            (
                PreflateTokenBlock::DynamicHuff {
                    tokens: t1,
                    huffman_encoding: h1,
                },
                PreflateTokenBlock::DynamicHuff {
                    tokens: t2,
                    huffman_encoding: h2,
                },
            ) => {
                compare(t1, t2, &format!("tokens differ {index}"));
                assert_eq!(h1, h2, "huffman_encoding differs {index}");
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

    let result_crc = crc32fast::hash(&contents.plain_text);

    if let Some(crc) = header_crc32 {
        assert_eq!(crc, result_crc, "crc mismatch");
    }

    *uncompressed_size = contents.plain_text.len() as u64;
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

#[test]
fn verify_longmatch() {
    do_analyze(
        None,
        &read_file("compressed_flate2_level1_longmatch.deflate"),
        true,
    );
}

#[test]
fn verify_zlibng() {
    do_analyze(None, &read_file("compressed_zlibng_level1.deflate"), false);
}
