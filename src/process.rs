/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use std::io::Cursor;

use crate::{
    deflate_reader::DeflateReader,
    deflate_writer::DeflateWriter,
    huffman_calc::HufftreeBitCalc,
    preflate_error::PreflateError,
    preflate_parameter_estimator::PreflateParameters,
    preflate_token::{BlockType, PreflateTokenBlock},
    statistical_codec::{
        CodecCorrection, CodecMisprediction, PredictionDecoder, PredictionEncoder,
    },
    token_predictor::TokenPredictor,
    tree_predictor::{predict_tree_for_block, recreate_tree_for_block},
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
        TokenPredictor::new(&deflate.plain_text, &params.predictor),
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
        let block = block_decoder
            .read_block(&mut last)
            .map_err(|e| PreflateError::ReadBlock(blocks.len(), e))?;

        if deflate_info_dump_level > 0 {
            // Log information about this deflate compressed block
            println!("Block: tokens={}", block.tokens.len());
        }

        blocks.push(block);
    }
    let eof_padding = block_decoder.read_eof_padding();
    let plain_text = block_decoder.move_plain_text();
    let compressed_size = input_stream.position() as usize;
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

        token_predictor_in
            .predict_block(&blocks[i], encoder, i == blocks.len() - 1)
            .map_err(|e| PreflateError::PredictBlock(i, e))?;

        if blocks[i].block_type == BlockType::DynamicHuff {
            predict_tree_for_block(
                &blocks[i].huffman_encoding,
                &blocks[i].freq,
                encoder,
                HufftreeBitCalc::Zlib,
            )
            .map_err(|e| PreflateError::PredictTree(i, e))?;
        }
    }
    assert!(token_predictor_in.input_eof());
    Ok(())
}

pub fn decode_mispredictions(
    params: &PreflateParameters,
    plain_text: &[u8],
    decoder: &mut impl PredictionDecoder,
) -> Result<(Vec<u8>, Vec<PreflateTokenBlock>), PreflateError> {
    let mut deflate_writer: DeflateWriter<'_> = DeflateWriter::new(plain_text);

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

fn recreate_blocks<D: PredictionDecoder>(
    mut token_predictor: TokenPredictor,
    decoder: &mut D,
    deflate_writer: &mut DeflateWriter,
) -> Result<Vec<PreflateTokenBlock>, PreflateError> {
    let mut output_blocks = Vec::new();
    let mut is_eof = token_predictor.input_eof()
        && !decoder.decode_misprediction(CodecMisprediction::EOFMisprediction);
    while !is_eof {
        let mut block = token_predictor
            .recreate_block(decoder)
            .map_err(|e| PreflateError::RecreateBlock(output_blocks.len(), e))?;

        if block.block_type == BlockType::DynamicHuff {
            block.huffman_encoding =
                recreate_tree_for_block(&block.freq, decoder, HufftreeBitCalc::Zlib)
                    .map_err(|e| PreflateError::RecreateTree(output_blocks.len(), e))?;
        }

        is_eof = token_predictor.input_eof()
            && !decoder.decode_misprediction(CodecMisprediction::EOFMisprediction);

        deflate_writer
            .encode_block(&block, is_eof)
            .map_err(|e| PreflateError::EncodeBlock(output_blocks.len(), e))?;

        output_blocks.push(block);
    }
    Ok(output_blocks)
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

    let (recompressed, _recreated_blocks) =
        decode_mispredictions(&params, &contents.plain_text, &mut cabac_decoder).unwrap();

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

    fn compare<T: PartialEq + std::fmt::Debug>(a: &[T], b: &[T]) {
        if a.len() != b.len() {
            panic!("lengths differ");
        }

        for i in 0..a.len() {
            if a[i] != b[i] {
                panic!("index {} differs ({:?},{:?})", i, a[i], b[i]);
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

    let (recompressed, recreated_blocks) =
        decode_mispredictions(&params_reread, &contents.plain_text, &mut combined_decoder).unwrap();

    assert_eq!(contents.blocks.len(), recreated_blocks.len());
    contents
        .blocks
        .iter()
        .zip(recreated_blocks)
        .enumerate()
        .for_each(|(index, (a, b))| {
            assert_eq!(a.block_type, b.block_type, "block type differs {index}");
            //assert_eq!(a.uncompressed_len, b.uncompressed_len);
            assert_eq!(
                a.padding_bits, b.padding_bits,
                "padding bits differ {index}"
            );
            compare(&a.tokens, &b.tokens);
            assert_eq!(
                a.tokens.len(),
                b.tokens.len(),
                "token length differs {index}"
            );
            assert!(a.tokens == b.tokens, "tokens differ {index}");
            assert_eq!(
                a.freq.literal_codes, b.freq.literal_codes,
                "literal code freq differ {index}"
            );
            assert_eq!(
                a.freq.distance_codes, b.freq.distance_codes,
                "distance code freq differ {index}"
            );
            assert_eq!(
                a.huffman_encoding, b.huffman_encoding,
                "huffman_encoding differs {index}"
            );
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
        false,
    );
}

#[test]
#[ignore = "doesn't work yet due to excessive hash chain length"]
fn test_treepngdeflate() {
    use crate::hash_algorithm::{HashImplementation, RandomVectorHash};
    use crate::hash_chain::HashChain;
    use crate::hash_chain::UPDATE_MODE_ALL;

    let compressed_data: &[u8] = &read_file("treepng.deflate");

    let contents = parse_deflate(compressed_data, 1).unwrap();

    let mut input = crate::preflate_input::PreflateInput::new(&contents.plain_text);
    let mut chain = RandomVectorHash::new_hash_chain(RandomVectorHash {});

    let r = RandomVectorHash::default();

    let h = r.get_hash(&contents.plain_text);

    println!("hashx: {:?}", h);

    let mut maxdepth = 0;

    for b in &contents.blocks {
        for i in 0..b.tokens.len() {
            let t = &b.tokens[i];
            match t {
                crate::preflate_token::PreflateToken::Literal => {
                    chain.update_hash::<true, UPDATE_MODE_ALL>(1, &input);
                    input.advance(1);
                }
                crate::preflate_token::PreflateToken::Reference(r) => {
                    let depth = chain.match_depth(&r, 32768, &input);
                    if depth > 5 {
                        println!("reference: {:?}", r);

                        println!("back: {:?}", &input.cur_chars(-82)[0..82]);

                        println!(
                            "depth: {}, {}, {:?}",
                            depth,
                            input.pos(),
                            &input.cur_chars(0)[0..16]
                        );
                        chain.match_depth(&r, 32768, &input);
                        return;
                    }

                    chain.update_hash::<true, UPDATE_MODE_ALL>(r.len(), &input);

                    input.advance(r.len());
                }
            }
        }
    }

    //do_analyze(None, &read_file("treepng.deflate"), true);
}

#[test]
#[ignore = "doesn't work yet due to excessive hash chain length"]
fn test_tree_paintnet() {
    do_analyze(None, &read_file("tree.paintnet.deflate"), true);
}

#[test]
#[ignore = "doesn't work yet due to excessive hash chain length"]
fn test_tree_treepng() {
    do_analyze(None, &read_file("treepng.deflate"), true);
}

// test binary deflate generated by MS Office
#[test]
fn verify_docx() {
    do_analyze(None, &read_file("dump571.deflate"), true);
}

// test binary deflate generated by starcontrol
#[test]
fn verify_savegame() {
    do_analyze(None, &read_file("savegame.deflate"), false);
}

#[test]
fn verify_zlib_compressed_3() {
    let i = 1;
    let v = read_file(&format!("compressed_zlib_level{}.deflate", i));

    //let minusheader = &v[2..v.len() - 4];
    //let crc = Some(u32::from_le_bytes([v[v.len() - 4], v[v.len() - 3], v[v.len() - 2], v[v.len() - 1]]));

    do_analyze(None, &v, true);
}

#[test]
fn verify_zlib_compressed() {
    for i in 0..9 {
        let v = read_file(&format!("compressed_zlib_level{}.deflate", i));

        //let minusheader = &v[2..v.len() - 4];
        //let crc = Some(u32::from_le_bytes([v[v.len() - 4], v[v.len() - 3], v[v.len() - 2], v[v.len() - 1]]));

        do_analyze(None, &v, true);
        do_analyze(None, &v, false);
    }
}

/// with the right parameters, Zlib compressed data should be recreated perfectly
#[test]
fn verify_zlib_compressed_perfect() {
    use crate::{
        hash_algorithm::HashAlgorithm,
        preflate_parameter_estimator::PreflateHuffStrategy,
        preflate_parameter_estimator::PreflateStrategy,
        preflate_parse_config::{FAST_PREFLATE_PARSER_SETTINGS, SLOW_PREFLATE_PARSER_SETTINGS},
        statistical_codec::{AssertDefaultOnlyDecoder, AssertDefaultOnlyEncoder},
    };

    for i in 1..=9 {
        println!();
        println!("testing zlib level {}", i);

        let v = read_file(&format!("compressed_zlib_level{}.deflate", i));

        let config;
        let add_policy;
        let max_dist_3_matches;
        let max_lazy;
        if i < 4 {
            config = &FAST_PREFLATE_PARSER_SETTINGS[i as usize - 1];
            add_policy = crate::hash_chain::DictionaryAddPolicy::AddFirst(config.max_lazy as u16);
            max_dist_3_matches = 32768;
            max_lazy = 0;
        } else {
            config = &SLOW_PREFLATE_PARSER_SETTINGS[i as usize - 4];
            add_policy = crate::hash_chain::DictionaryAddPolicy::AddAll;
            max_dist_3_matches = 4096;
            max_lazy = config.max_lazy;
        }

        let params = PreflateParameters {
            huff_strategy: PreflateHuffStrategy::Dynamic,
            predictor: crate::token_predictor::TokenPredictorParameters {
                strategy: PreflateStrategy::Default,
                window_bits: 15,
                very_far_matches_detected: false,
                matches_to_start_detected: false,
                nice_length: config.nice_length,
                add_policy,
                max_token_count: 16383,
                zlib_compatible: true,
                max_dist_3_matches,
                good_length: config.good_length,
                max_lazy: max_lazy,
                max_chain: config.max_chain,
                min_len: 3,
                hash_algorithm: HashAlgorithm::Zlib {
                    hash_shift: 5,
                    hash_mask: 0x7fff,
                },
            },
        };

        let contents = parse_deflate(&v, 1).unwrap();

        // assert that we don't get any mispredictions on known good zlib compressed data
        let mut cabac_encoder = AssertDefaultOnlyEncoder {};
        encode_mispredictions(&contents, &params, &mut cabac_encoder).unwrap();

        let mut cabac_decoder = AssertDefaultOnlyDecoder {};
        decode_mispredictions(&params, &contents.plain_text, &mut cabac_decoder).unwrap();
    }
}

#[test]
fn verify_miniz1_compressed_perfect() {
    use crate::{
        cabac_codec::{PredictionDecoderCabac, PredictionEncoderCabac},
        hash_algorithm::HashAlgorithm,
        preflate_parameter_estimator::{PreflateHuffStrategy, PreflateStrategy},
    };
    use cabac::vp8::{VP8Reader, VP8Writer};

    let v = read_file("compressed_flate2_level1.deflate");

    let contents = parse_deflate(&v, 1).unwrap();

    let mut buffer = Vec::new();
    let mut cabac_encoder = PredictionEncoderCabac::new(VP8Writer::new(&mut buffer).unwrap());

    let params = PreflateParameters {
        predictor: crate::token_predictor::TokenPredictorParameters {
            strategy: PreflateStrategy::Default,
            window_bits: 15,
            very_far_matches_detected: false,
            matches_to_start_detected: false,
            nice_length: 258,
            add_policy: crate::hash_chain::DictionaryAddPolicy::AddFirst(0),
            max_token_count: 16383,
            zlib_compatible: true,
            max_dist_3_matches: 8192,
            good_length: 258,
            max_lazy: 0,
            max_chain: 2,
            min_len: 3,
            hash_algorithm: HashAlgorithm::MiniZFast,
        },
        huff_strategy: PreflateHuffStrategy::Dynamic,
    };

    encode_mispredictions(&contents, &params, &mut cabac_encoder).unwrap();

    cabac_encoder.finish();

    cabac_encoder.print();

    let mut cabac_decoder =
        PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(&buffer)).unwrap());

    decode_mispredictions(&params, &contents.plain_text, &mut cabac_decoder).unwrap();
}

#[test]
fn verify_miniz_compressed_1() {
    let v = read_file(&format!("compressed_flate2_level1.deflate"));

    //let minusheader = &v[2..v.len() - 4];
    //let crc = Some(u32::from_le_bytes([v[v.len() - 4], v[v.len() - 3], v[v.len() - 2], v[v.len() - 1]]));

    do_analyze(None, &v, false);
}

#[test]
fn verify_libdeflate_compressed() {
    for i in 0..9 {
        let filename = format!("compressed_libdeflate_level{}.deflate", i);
        let v = read_file(&filename);

        //let minusheader = &v[2..v.len() - 4];
        //let crc = Some(u32::from_le_bytes([v[v.len() - 4], v[v.len() - 3], v[v.len() - 2], v[v.len() - 1]]));

        do_analyze(None, &v, true);
    }
}

#[test]
fn verify_miniz_compressed() {
    for i in 0..9 {
        let filename = format!("compressed_flate2_level{}.deflate", i);
        println!();
        println!("loading {}", filename);
        let v = read_file(&filename);

        //let minusheader = &v[2..v.len() - 4];
        //let crc = Some(u32::from_le_bytes([v[v.len() - 4], v[v.len() - 3], v[v.len() - 2], v[v.len() - 1]]));

        do_analyze(None, &v, true);
        do_analyze(None, &v, false);
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub fn zlibcompress(v: &[u8], level: i32) -> Vec<u8> {
    let mut output = Vec::new();
    output.resize(v.len() + 1000, 0);

    let mut output_size = output.len() as libz_sys::uLongf;

    unsafe {
        let err = libz_sys::compress2(
            output.as_mut_ptr(),
            &mut output_size,
            v.as_ptr(),
            v.len() as libz_sys::uLongf,
            level,
        );

        assert_eq!(err, 0, "shouldn't fail zlib compression");

        output.set_len(output_size as usize);
    }
    output
}
