/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use bitcode::{Decode, Encode};

use crate::{
    deflate::{
        deflate_reader::DeflateContents, deflate_token::DeflateTokenBlock,
        deflate_writer::DeflateWriter,
    },
    estimator::preflate_parameter_estimator::PreflateParameters,
    preflate_error::{ExitCode, PreflateError},
    preflate_input::PreflateInput,
    statistical_codec::{CodecCorrection, PredictionDecoder, PredictionEncoder},
    token_predictor::TokenPredictor,
};

/// the data required to reconstruct the deflate stream exactly the way that it was
#[derive(Encode, Decode)]
pub struct ReconstructionData {
    pub parameters: PreflateParameters,
    pub corrections: Vec<u8>,
}

impl ReconstructionData {
    pub fn read(data: &[u8]) -> Result<Self, PreflateError> {
        bitcode::decode(data).map_err(|e| {
            PreflateError::new(
                ExitCode::InvalidCompressedWrapper,
                format!("{:?}", e).as_str(),
            )
        })
    }
}

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

    Ok(())
}

fn predict_blocks(
    blocks: &[DeflateTokenBlock],
    mut token_predictor_in: TokenPredictor,
    encoder: &mut impl PredictionEncoder,
) -> Result<(), PreflateError> {
    for i in 0..blocks.len() {
        token_predictor_in.predict_block(&blocks[i], encoder)?;
    }
    assert!(token_predictor_in.input_eof());
    Ok(())
}

pub fn decode_mispredictions(
    params: &PreflateParameters,
    plain_text: PreflateInput,
    decoder: &mut impl PredictionDecoder,
) -> Result<(Vec<u8>, Vec<DeflateTokenBlock>), PreflateError> {
    let mut deflate_writer: DeflateWriter = DeflateWriter::new();

    let output_blocks = recreate_blocks(
        TokenPredictor::new(plain_text, &params.predictor),
        decoder,
        &mut deflate_writer,
    )?;

    deflate_writer.flush();

    Ok((deflate_writer.detach_output(), output_blocks))
}

#[inline(never)]
fn recreate_blocks<D: PredictionDecoder>(
    mut token_predictor: TokenPredictor,
    decoder: &mut D,
    deflate_writer: &mut DeflateWriter,
) -> Result<Vec<DeflateTokenBlock>, PreflateError> {
    let mut output_blocks = Vec::new();
    loop {
        let block = token_predictor.recreate_block(decoder)?;

        deflate_writer.encode_block(&block)?;

        let last = block.last;
        output_blocks.push(block);
        if last {
            break;
        }
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
    use crate::{
        cabac_codec::{PredictionDecoderCabac, PredictionEncoderCabac},
        deflate::deflate_reader::parse_deflate,
    };
    use std::io::Cursor;

    use cabac::vp8::{VP8Reader, VP8Writer};

    let mut buffer = Vec::new();

    let mut cabac_encoder = PredictionEncoderCabac::new(VP8Writer::new(&mut buffer).unwrap());

    let contents = parse_deflate(compressed_data, 1).unwrap();

    let params = PreflateParameters::estimate_preflate_parameters(&contents).unwrap();

    println!("params: {:?}", params);

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
    use crate::{
        cabac_codec::{PredictionDecoderCabac, PredictionEncoderCabac},
        deflate::{deflate_reader::parse_deflate, deflate_token::DeflateTokenBlockType},
        statistical_codec::{VerifyPredictionDecoder, VerifyPredictionEncoder},
    };
    use cabac::debug::{DebugReader, DebugWriter};
    use std::io::Cursor;

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

    let params = PreflateParameters::estimate_preflate_parameters(&contents).unwrap();

    println!("params: {:?}", params);

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

    let (recompressed, recreated_blocks) = decode_mispredictions(
        &params,
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
        .for_each(|(index, (a, b))| match (&a.block_type, &b.block_type) {
            (
                DeflateTokenBlockType::Stored {
                    uncompressed: a,
                    padding_bits: b,
                },
                DeflateTokenBlockType::Stored {
                    uncompressed: c,
                    padding_bits: d,
                },
            ) => {
                assert_eq!(a, c, "uncompressed data differs {index}");
                assert_eq!(b, d, "padding bits differ {index}");
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
                compare(t1, t2, &format!("tokens differ {index}"));
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

/// verify that levels 1-6 of zlib are compressed without any correction data
///
/// Future work: figure out why level 7 and above are not perfect
#[test]
fn verify_zlib_perfect_compression() {
    use crate::deflate::deflate_reader::parse_deflate;

    for i in 1..6 {
        println!("iteration {}", i);
        let compressed_data: &[u8] =
            &read_file(format!("compressed_zlib_level{i}.deflate").as_str());

        let compressed_data = compressed_data;

        let contents = parse_deflate(compressed_data, 1).unwrap();

        let params = PreflateParameters::estimate_preflate_parameters(&contents).unwrap();

        println!("params: {:?}", params);

        // this "encoder" just asserts if anything gets passed to it
        let mut verify_encoder = crate::statistical_codec::AssertDefaultOnlyEncoder {};
        encode_mispredictions(&contents, &params, &mut verify_encoder).unwrap();

        println!("params buffer length {}", bitcode::encode(&params).len());
    }
}

#[test]
fn verify_longmatch() {
    do_analyze(
        None,
        &read_file("compressed_flate2_level1_longmatch.deflate"),
        false,
    );
}

#[test]
fn verify_zlibng() {
    do_analyze(None, &read_file("compressed_zlibng_level1.deflate"), false);
}

#[test]
fn verify_miniz() {
    do_analyze(
        None,
        &read_file("compressed_minizoxide_level1.deflate"),
        false,
    );
}

// this is the deflate stream extracted out of the
#[test]
fn verify_png_deflate() {
    do_analyze(None, &read_file("treegdi.extract.deflate"), false);
}
