/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use std::ops::RangeInclusive;

use crate::{
    cabac_codec::{decode_difference, encode_difference},
    deflate::deflate_constants::{CODETREE_CODE_COUNT, NONLEN_CODE_COUNT, TREE_CODE_ORDER_TABLE},
    deflate::deflate_token::TokenFrequency,
    deflate::{
        huffman_calc::{HufftreeBitCalc, calc_bit_lengths},
        huffman_encoding::{HuffmanOriginalEncoding, TreeCodeType},
    },
    preflate_error::{ExitCode, Result, err_exit_code},
    statistical_codec::{CodecCorrection, PredictionDecoder, PredictionEncoder},
};

/// Largest literal/length count the 5-bit HLIT header field can express (257 + 31).
const MAX_HLIT_CODE_COUNT: u32 = 288;

pub fn predict_tree_for_block<D: PredictionEncoder>(
    huffman_encoding: &HuffmanOriginalEncoding,
    freq: &TokenFrequency,
    encoder: &mut D,
    huffcalc: HufftreeBitCalc,
) -> Result<()> {
    encoder.encode_verify_state("tree", 0);

    // bit_lengths is a vector of huffman code sizes for literals followed by length codes
    // first predict the size of the literal tree
    let mut bit_lengths = calc_bit_lengths(huffcalc, &freq.literal_codes, 15);

    /*
    let (ao, bo) = huffman_encoding.get_literal_distance_lengths();
     bit_lengths.iter().zip(ao.iter()).enumerate().for_each(|(i, (&a, &b))| {
         assert_eq!(a, b, "i{i} bit_lengths: {:?} ao: {:?}", bit_lengths, ao);
     });
     assert_eq!(bit_lengths[..], ao[..]);
    */

    encoder.encode_correction_diff(
        CodecCorrection::LiteralCountCorrection,
        huffman_encoding.num_literals as u32,
        bit_lengths.len() as u32,
    );

    // resize to the actual size
    bit_lengths.resize(huffman_encoding.num_literals, 0);

    // now predict the size of the distance tree
    let mut distance_code_lengths = calc_bit_lengths(huffcalc, &freq.distance_codes, 15);
    //assert_eq!(distance_code_lengths[..], bo[..]);

    encoder.encode_correction_diff(
        CodecCorrection::DistanceCountCorrection,
        huffman_encoding.num_dist as u32,
        distance_code_lengths.len() as u32,
    );

    // resize to the actual size
    distance_code_lengths.resize(huffman_encoding.num_dist, 0);

    bit_lengths.append(&mut distance_code_lengths);

    // now predict each length code
    predict_ld_trees(encoder, &bit_lengths, huffman_encoding.lengths.as_slice())?;

    // final step, we need to construct the second level huffman tree that is used
    // to store the bit lengths of the huffman tree we just created
    let codetree_freq = calc_codetree_freq(&huffman_encoding.lengths);

    let mut tc_code_tree = calc_bit_lengths(huffcalc, &codetree_freq, 7);

    let tc_code_tree_len = calc_tc_lengths_without_trailing_zeros(&tc_code_tree);

    encoder.encode_correction_diff(
        CodecCorrection::TreeCodeBitLengthCorrection,
        huffman_encoding.num_code_lengths as u32,
        tc_code_tree_len as u32,
    );

    // resize so that when we walk through in TREE_CODE_ORDER_TABLE order, we
    // don't go out of range.
    tc_code_tree.resize(CODETREE_CODE_COUNT, 0);

    for i in 0..huffman_encoding.num_code_lengths {
        let predicted_bl = tc_code_tree[TREE_CODE_ORDER_TABLE[i]];
        encoder.encode_correction(
            CodecCorrection::TreeCodeBitLengthCorrection,
            encode_difference(
                predicted_bl.into(),
                huffman_encoding.code_lengths[TREE_CODE_ORDER_TABLE[i]].into(),
            ),
        );
    }

    Ok(())
}

pub fn recreate_tree_for_block<D: PredictionDecoder>(
    freq: &TokenFrequency,
    codec: &mut D,
    huffcalc: HufftreeBitCalc,
) -> Result<HuffmanOriginalEncoding> {
    codec.decode_verify_state("tree", 0);

    let mut result: HuffmanOriginalEncoding = Default::default();

    let mut bit_lengths = calc_bit_lengths(huffcalc, &freq.literal_codes, 15);

    // the 5-bit HLIT field allows up to 288 codes, which the parser accepts and the writer re-emits
    let literal_count = decode_tree_correction(
        codec,
        CodecCorrection::LiteralCountCorrection,
        bit_lengths.len() as u32,
        NONLEN_CODE_COUNT as u32..=MAX_HLIT_CODE_COUNT,
    )?;
    bit_lengths.resize(literal_count as usize, 0);

    result.num_literals = bit_lengths.len();

    let mut distance_code_lengths = calc_bit_lengths(huffcalc, &freq.distance_codes, 15);

    let distance_count = decode_tree_correction(
        codec,
        CodecCorrection::DistanceCountCorrection,
        distance_code_lengths.len() as u32,
        1..=32,
    )?;
    distance_code_lengths.resize(distance_count as usize, 0);

    result.num_dist = distance_code_lengths.len();

    // frequences are encoded as appended together as a single vector
    bit_lengths.append(&mut distance_code_lengths);

    result.lengths = reconstruct_ld_trees(codec, &bit_lengths)?;

    let bl_freqs = calc_codetree_freq(&result.lengths);

    let mut tc_code_tree = calc_bit_lengths(huffcalc, &bl_freqs, 7);

    let mut tc_code_tree_len = calc_tc_lengths_without_trailing_zeros(&tc_code_tree);

    tc_code_tree_len = decode_tree_correction(
        codec,
        CodecCorrection::TreeCodeBitLengthCorrection,
        tc_code_tree_len as u32,
        4..=CODETREE_CODE_COUNT as u32,
    )? as usize;

    result.num_code_lengths = tc_code_tree_len;

    // resize so that when we walk through in TREE_CODE_ORDER_TABLE order, we
    // don't go out of range.
    tc_code_tree.resize(CODETREE_CODE_COUNT, 0);

    for i in 0..tc_code_tree_len {
        result.code_lengths[TREE_CODE_ORDER_TABLE[i]] = decode_tree_correction(
            codec,
            CodecCorrection::TreeCodeBitLengthCorrection,
            tc_code_tree[TREE_CODE_ORDER_TABLE[i]].into(),
            0..=7,
        )? as u8;
    }

    Ok(result)
}

fn decode_tree_correction<D: PredictionDecoder>(
    decoder: &mut D,
    correction: CodecCorrection,
    predicted: u32,
    bounds: RangeInclusive<u32>,
) -> Result<u32> {
    let value = decode_difference(predicted, decoder.decode_correction(correction)?)?;
    match value {
        value if bounds.contains(&value) => Ok(value),
        _ => err_exit_code(
            ExitCode::InvalidPredictionData,
            format!("Invalid Huffman tree correction: {correction:?}"),
        ),
    }
}

/// since treecodes are encoded in a different order (see TREE_CODE_ORDER_TABLE) in
/// order to optimize the chance of removing trailing zeros, we need to calculate
/// the effective encoding size of the length codes
fn calc_tc_lengths_without_trailing_zeros(bit_lengths: &[u8]) -> usize {
    let mut len = bit_lengths.len();
    // remove trailing zeros
    while len > 4 && bit_lengths[TREE_CODE_ORDER_TABLE[len - 1]] == 0 {
        len -= 1;
    }

    len
}

fn predict_ld_trees<D: PredictionEncoder>(
    encoder: &mut D,
    predicted_bit_len: &[u8],
    actual_target_codes: &[(TreeCodeType, u8)],
) -> Result<()> {
    encoder.encode_verify_state("predict_ld_trees", 0);

    let mut symbols = predicted_bit_len;
    let mut prev_code = None;

    assert_eq!(
        actual_target_codes
            .iter()
            .map(|&(a, b)| if a == TreeCodeType::Code {
                1
            } else {
                b as usize
            })
            .sum::<usize>(),
        predicted_bit_len.len(),
        "target_codes RLE encoding should sum to the same length as sym_bit_len"
    );

    for &(target_tree_code_type, target_tree_code_data) in actual_target_codes.iter() {
        if symbols.is_empty() {
            return err_exit_code(ExitCode::InvalidDeflate, "Reconstruction failed");
        }

        let predicted_tree_code_type: TreeCodeType = predict_code_type(symbols, prev_code);

        prev_code = Some(symbols[0]);

        encoder.encode_correction(
            CodecCorrection::LDTypeCorrection,
            encode_difference(
                predicted_tree_code_type as u32,
                target_tree_code_type as u32,
            ),
        );

        let predicted_tree_code_data = predict_code_data(symbols, target_tree_code_type);

        if target_tree_code_type != TreeCodeType::Code {
            encoder.encode_correction(
                CodecCorrection::RepeatCountCorrection,
                encode_difference(
                    predicted_tree_code_data.into(),
                    target_tree_code_data.into(),
                ),
            );
        } else {
            encoder.encode_correction(
                CodecCorrection::LDBitLengthCorrection,
                encode_difference(
                    predicted_tree_code_data.into(),
                    target_tree_code_data.into(),
                ),
            );
        }

        if target_tree_code_type == TreeCodeType::Code {
            symbols = &symbols[1..];
        } else {
            symbols = &symbols[target_tree_code_data as usize..];
        }
    }

    Ok(())
}

fn reconstruct_ld_trees<D: PredictionDecoder>(
    decoder: &mut D,
    sym_bit_len: &[u8],
) -> Result<Vec<(TreeCodeType, u8)>> {
    decoder.decode_verify_state("predict_ld_trees", 0);

    let mut symbols = sym_bit_len;
    let mut prev_code = None;
    let mut result: Vec<(TreeCodeType, u8)> = Vec::new();

    while !symbols.is_empty() {
        let predicted_tree_code_type = predict_code_type(symbols, prev_code);
        prev_code = Some(symbols[0]);

        let predicted_tree_code_type_u32 = decode_tree_correction(
            decoder,
            CodecCorrection::LDTypeCorrection,
            predicted_tree_code_type as u32,
            0..=18,
        )?;

        const TC_CODE: u32 = TreeCodeType::Code as u32;
        const TC_REPEAT: u32 = TreeCodeType::Repeat as u32;
        const TC_ZERO_SHORT: u32 = TreeCodeType::ZeroShort as u32;
        const TC_ZERO_LONG: u32 = TreeCodeType::ZeroLong as u32;

        let predicted_tree_code_type = match predicted_tree_code_type_u32 {
            TC_CODE => TreeCodeType::Code,
            TC_REPEAT => TreeCodeType::Repeat,
            TC_ZERO_SHORT => TreeCodeType::ZeroShort,
            TC_ZERO_LONG => TreeCodeType::ZeroLong,
            _ => return err_exit_code(ExitCode::RecompressFailed, "Reconstruction failed"),
        };

        let predicted_tree_code_data = predict_code_data(symbols, predicted_tree_code_type);
        let (correction, bounds) = match predicted_tree_code_type {
            TreeCodeType::Code => (CodecCorrection::LDBitLengthCorrection, 0..=15),
            // a leading repeat is accepted by the parser and repeats a length of 0
            TreeCodeType::Repeat => (CodecCorrection::RepeatCountCorrection, 3..=6),
            TreeCodeType::ZeroShort => (CodecCorrection::RepeatCountCorrection, 3..=10),
            TreeCodeType::ZeroLong => (CodecCorrection::RepeatCountCorrection, 11..=138),
        };
        let predicted_tree_code_data =
            decode_tree_correction(decoder, correction, predicted_tree_code_data.into(), bounds)?
                as u8;
        if predicted_tree_code_type != TreeCodeType::Code
            && predicted_tree_code_data as usize > symbols.len()
        {
            return err_exit_code(
                ExitCode::InvalidPredictionData,
                "Huffman repeat exceeds remaining symbols",
            );
        }

        result.push((predicted_tree_code_type, predicted_tree_code_data));

        if predicted_tree_code_type == TreeCodeType::Code {
            symbols = &symbols[1..];
        } else {
            symbols = &symbols[predicted_tree_code_data as usize..];
        }
    }

    Ok(result)
}

/// calculates the treecode frequence for the given block, which is used to
/// to calculate the huffman tree for encoding the treecodes themselves
fn calc_codetree_freq(codes: &[(TreeCodeType, u8)]) -> [u16; CODETREE_CODE_COUNT] {
    let mut bl_freqs = [0u16; CODETREE_CODE_COUNT];

    for (code, data) in codes.iter() {
        match code {
            TreeCodeType::Code => {
                bl_freqs[*data as usize] += 1;
            }
            TreeCodeType::Repeat => {
                bl_freqs[16] += 1;
            }
            TreeCodeType::ZeroShort => {
                bl_freqs[17] += 1;
            }
            TreeCodeType::ZeroLong => {
                bl_freqs[18] += 1;
            }
        }
    }

    bl_freqs
}

fn predict_code_type(sym_bit_len: &[u8], previous_code: Option<u8>) -> TreeCodeType {
    let code = sym_bit_len[0];
    if code == 0 {
        let mut curlen = 1;
        let max_cur_len = std::cmp::min(sym_bit_len.len(), 11);
        while curlen < max_cur_len && sym_bit_len[curlen] == 0 {
            curlen += 1;
        }
        if curlen >= 11 {
            TreeCodeType::ZeroLong
        } else if curlen >= 3 {
            TreeCodeType::ZeroShort
        } else {
            TreeCodeType::Code
        }
    } else if let Some(code) = previous_code {
        let mut curlen = 0;
        while curlen < sym_bit_len.len() && sym_bit_len[curlen] == code {
            curlen += 1;
        }
        if curlen >= 3 {
            TreeCodeType::Repeat
        } else {
            TreeCodeType::Code
        }
    } else {
        TreeCodeType::Code
    }
}

fn predict_code_data(sym_bit_len: &[u8], code_type: TreeCodeType) -> u8 {
    let code = sym_bit_len[0];
    match code_type {
        TreeCodeType::Code => code,
        TreeCodeType::Repeat => {
            let mut curlen = 3;
            let max_cur_len = std::cmp::min(sym_bit_len.len(), 6);
            while curlen < max_cur_len && sym_bit_len[curlen] == code {
                curlen += 1;
            }
            curlen as u8
        }
        TreeCodeType::ZeroShort | TreeCodeType::ZeroLong => {
            let mut curlen = if code_type == TreeCodeType::ZeroShort {
                3
            } else {
                11
            };
            let max_cur_len = std::cmp::min(
                sym_bit_len.len(),
                if code_type == TreeCodeType::ZeroShort {
                    10
                } else {
                    138
                },
            );
            while curlen < max_cur_len && sym_bit_len[curlen] == 0 {
                curlen += 1;
            }
            curlen as u8
        }
    }
}

#[test]
fn encode_roundtrip_perfect() {
    use crate::statistical_codec::AssertDefaultOnlyDecoder;
    use crate::statistical_codec::VerifyPredictionEncoder;

    for huffcalc in [HufftreeBitCalc::Miniz, HufftreeBitCalc::Zlib] {
        let mut freq = TokenFrequency::default();
        freq.literal_codes[0] = 100;
        freq.literal_codes[1] = 50;
        freq.literal_codes[2] = 25;

        freq.distance_codes[0] = 100;
        freq.distance_codes[1] = 50;
        freq.distance_codes[2] = 25;

        let mut empty_decoder = AssertDefaultOnlyDecoder {};
        let regenerated_header =
            recreate_tree_for_block(&freq, &mut empty_decoder, huffcalc).unwrap();

        assert_eq!(regenerated_header.num_literals, 257);
        assert_eq!(regenerated_header.num_dist, 3);
        assert_eq!(regenerated_header.lengths[0], (TreeCodeType::Code, 1));
        assert_eq!(regenerated_header.lengths[1], (TreeCodeType::Code, 2));
        assert_eq!(regenerated_header.lengths[2], (TreeCodeType::Code, 3));

        let mut empty_encoder = VerifyPredictionEncoder::default();
        predict_tree_for_block(&regenerated_header, &freq, &mut empty_encoder, huffcalc).unwrap();
        assert_eq!(empty_encoder.count_nondefault_actions(), 0);
    }
}

#[test]
fn encode_perfect_encoding() {
    use crate::deflate::deflate_constants::LITLEN_CODE_COUNT;
    use crate::statistical_codec::{AssertDefaultOnlyDecoder, VerifyPredictionEncoder};

    let mut freq = TokenFrequency::default();
    // fill with random frequencies
    let mut v: u16 = 10;
    freq.literal_codes[..LITLEN_CODE_COUNT].fill_with(|| {
        v = v.wrapping_add(997);
        v
    });
    freq.distance_codes.fill_with(|| {
        v = v.wrapping_add(997);
        v
    });

    // use the default encoder the says that everything is ok
    let mut default_only_decoder = AssertDefaultOnlyDecoder {};
    let default_encoding =
        recreate_tree_for_block(&freq, &mut default_only_decoder, HufftreeBitCalc::Zlib).unwrap();

    // now predict the encoding using the default encoding and it should be perfect
    let mut empty_encoder = VerifyPredictionEncoder::default();
    predict_tree_for_block(
        &default_encoding,
        &freq,
        &mut empty_encoder,
        HufftreeBitCalc::Zlib,
    )
    .unwrap();
    assert_eq!(empty_encoder.count_nondefault_actions(), 0);
}

#[test]
fn encode_tree_roundtrip() {
    use crate::statistical_codec::{VerifyPredictionDecoder, VerifyPredictionEncoder};

    let mut freq = TokenFrequency::default();
    freq.literal_codes[0] = 100;
    freq.literal_codes[1] = 50;
    freq.literal_codes[2] = 25;

    freq.distance_codes[0] = 100;
    freq.distance_codes[1] = 50;
    freq.distance_codes[2] = 25;

    let huff_origin = HuffmanOriginalEncoding {
        lengths: vec![
            (TreeCodeType::Code, 4),
            (TreeCodeType::Code, 4),
            (TreeCodeType::Code, 4),
            (TreeCodeType::ZeroLong, 138),
            (TreeCodeType::ZeroLong, 115),
            (TreeCodeType::Code, 3),
            (TreeCodeType::Code, 1),
            (TreeCodeType::Code, 2),
            (TreeCodeType::Code, 2),
        ],
        code_lengths: [0, 3, 2, 3, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        num_literals: 257,
        num_dist: 3,
        num_code_lengths: 19,
    };

    let mut encoder = VerifyPredictionEncoder::default();

    predict_tree_for_block(&huff_origin, &freq, &mut encoder, HufftreeBitCalc::Zlib).unwrap();

    let mut decoder = VerifyPredictionDecoder::new(encoder.actions());

    let regenerated_header =
        recreate_tree_for_block(&freq, &mut decoder, HufftreeBitCalc::Zlib).unwrap();

    assert_eq!(huff_origin, regenerated_header);
}

/// test that we can reconstruct the tree from the predicted bit lengths where
/// the predicted lengths are totally wrong
#[test]
fn encode_totally_different_tree() {
    use crate::statistical_codec::{VerifyPredictionDecoder, VerifyPredictionEncoder};
    use TreeCodeType::*;

    #[rustfmt::skip]
    let predicted_bit_len = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 6, 6, 5, 7, 7, 8,
        0, 0, 0, 8, 0, 8, 0, 8, 0, 7, 6, 7, 7, 0, 0, 0, 8, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 7, 0,
        0, 8, 7, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 7, 5, 6, 4, 6, 7, 7, 5, 8, 8, 6, 5, 5, 5, 5,
        0, 5, 5, 4, 7, 7, 7, 7, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 4, 6, 6, 6, 7, 8, 6, 0, 8, 0, 7,
        0, 7, 7, 7, 6, 6, 7, 8, 8, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 7, 7, 4, 4, 3, 3,
        2, 3, 3, 7, 6, 6, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    #[rustfmt::skip]
    let actual_target_codes  =
        [(Code, 14), (Repeat, 6), (Code, 14), (Code, 14), (Code, 12), (Code, 6), (Code, 14),
        (Repeat, 6), (Repeat, 6), (Repeat, 6), (Code, 13), (Code, 14), (Code, 6), (Code, 14),
        (Code, 10), (Code, 12), (Code, 14), (Code, 14), (Code, 13), (Code, 10), (Code, 8), (Code, 9),
        (Code, 11), (Code, 10), (Code, 7), (Code, 8), (Code, 7), (Code, 9), (Code, 8), (Code, 8),
        (Code, 8), (Code, 9), (Code, 8), (Code, 9), (Code, 10), (Code, 9), (Code, 8), (Code, 9),
        (Code, 9), (Code, 8), (Code, 9), (Code, 10), (Code, 8), (Code, 14), (Code, 14), (Code, 8),
        (Code, 9), (Code, 8), (Code, 9), (Code, 8), (Code, 9), (Code, 10), (Code, 11), (Code, 8),
        (Code, 11), (Code, 14), (Code, 9), (Code, 10), (Code, 9), (Code, 10), (Code, 9), (Code, 12),
        (Code, 9), (Code, 9), (Code, 9), (Code, 10), (Code, 12), (Code, 11), (Code, 14), (Code, 14),
        (Code, 12), (Code, 11), (Code, 14), (Code, 11), (Code, 14), (Code, 14), (Code, 14), (Code, 6),
        (Code, 7), (Code, 7), (Code, 7), (Code, 6), (Code, 8), (Code, 8), (Code, 7), (Code, 6),
        (Code, 12), (Code, 9), (Code, 6), (Code, 7), (Code, 7), (Code, 6), (Code, 7), (Code, 13),
        (Code, 6), (Code, 6), (Code, 6), (Code, 7), (Code, 8), (Code, 8), (Code, 9), (Code, 8),
        (Code, 11), (Code, 13), (Code, 12), (Code, 13), (Code, 13), (Code, 14), (Repeat, 6),
        (Repeat, 6), (Repeat, 6), (Repeat, 6), (Repeat, 6), (Repeat, 6), (Repeat, 6), (Repeat, 6),
        (Repeat, 6), (Repeat, 6), (Repeat, 6), (Repeat, 6), (Repeat, 6), (Repeat, 6), (Repeat, 6),
        (Repeat, 6), (Repeat, 6), (Repeat, 6), (Repeat, 6), (Code, 14), (Code, 13), (Code, 13),
        (Code, 13), (Code, 14), (Code, 13), (Code, 14), (Code, 13), (Code, 14), (Code, 13),
        (Code, 14), (Repeat, 4), (Code, 4), (Code, 3), (Code, 4), (Code, 4), (Code, 4), (Code, 5),
        (Repeat, 4), (Code, 6), (Code, 6), (Code, 5), (Code, 6), (Code, 7), (Code, 8), (Code, 8),
        (Code, 9), (Code, 10), (Code, 9), (Code, 10), (Code, 12), (Code, 11), (Code, 12), (Code, 14),
        (Code, 14), (Code, 14), (Code, 12), (Code, 11), (Code, 6), (Code, 10), (Code, 11), (Code, 11),
        (Code, 9), (Code, 8), (Code, 8), (Code, 8), (Code, 7), (Code, 7), (Code, 5), (Code, 6),
        (Code, 4), (Code, 5), (Code, 4), (Code, 5), (Code, 4), (Code, 5), (Code, 4), (Repeat, 6),
        (Code, 5), (Code, 4), (Code, 5), (Code, 5), (Code, 5)];

    let mut encoder = VerifyPredictionEncoder::default();

    predict_ld_trees(&mut encoder, &predicted_bit_len, &actual_target_codes).unwrap();

    let mut decoder = VerifyPredictionDecoder::new(encoder.actions());

    let regenerated_header = reconstruct_ld_trees(&mut decoder, &predicted_bit_len).unwrap();

    assert_eq!(actual_target_codes, regenerated_header.as_slice());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::statistical_codec::{
        AssertDefaultOnlyDecoder, CodecAction, VerifyPredictionDecoder, VerifyPredictionEncoder,
    };

    #[test]
    fn maximum_header_counts_roundtrip() {
        let mut lengths = vec![(TreeCodeType::Code, 8); 226];
        lengths.extend_from_slice(&[(TreeCodeType::Code, 9); 60]);
        lengths.extend_from_slice(&[(TreeCodeType::Code, 0); 2]);
        lengths.extend_from_slice(&[(TreeCodeType::Code, 5); 32]);
        let mut code_lengths = [0; CODETREE_CODE_COUNT];
        code_lengths[0] = 3;
        code_lengths[5] = 3;
        code_lengths[8] = 1;
        code_lengths[9] = 2;
        let tree = HuffmanOriginalEncoding {
            lengths,
            code_lengths,
            num_literals: 288,
            num_dist: 32,
            num_code_lengths: 19,
        };
        let freq = TokenFrequency::default();
        let mut encoder = VerifyPredictionEncoder::default();
        predict_tree_for_block(&tree, &freq, &mut encoder, HufftreeBitCalc::Zlib).unwrap();
        let recreated = recreate_tree_for_block(
            &freq,
            &mut VerifyPredictionDecoder::new(encoder.actions()),
            HufftreeBitCalc::Zlib,
        )
        .unwrap();
        assert_eq!(tree, recreated);
    }

    fn reject_tree_correction(correction: CodecCorrection, occurrence: usize, value: u32) {
        let mut freq = TokenFrequency::default();
        freq.literal_codes[0] = 100;
        freq.literal_codes[1] = 50;
        freq.literal_codes[2] = 25;
        freq.distance_codes[..3].copy_from_slice(&[100, 50, 25]);
        let tree = recreate_tree_for_block(
            &freq,
            &mut AssertDefaultOnlyDecoder {},
            HufftreeBitCalc::Zlib,
        )
        .unwrap();
        let mut encoder = VerifyPredictionEncoder::default();
        predict_tree_for_block(&tree, &freq, &mut encoder, HufftreeBitCalc::Zlib).unwrap();
        let mut actions = encoder.actions();
        let action = actions
            .iter_mut()
            .filter_map(|action| match action {
                CodecAction::Correction(c, value) if *c == correction => Some(value),
                _ => None,
            })
            .nth(occurrence)
            .unwrap();
        *action = value;
        let error = recreate_tree_for_block(
            &freq,
            &mut VerifyPredictionDecoder::new(actions),
            HufftreeBitCalc::Zlib,
        )
        .unwrap_err();
        assert_eq!(error.exit_code(), ExitCode::InvalidPredictionData);
    }

    #[test]
    fn reject_invalid_tree_counts() {
        for value in [0, 256, 289, 65_536] {
            reject_tree_correction(
                CodecCorrection::LiteralCountCorrection,
                0,
                encode_difference(257, value),
            );
        }
        for value in [0, 33, 65_536] {
            reject_tree_correction(
                CodecCorrection::DistanceCountCorrection,
                0,
                encode_difference(3, value),
            );
        }
        for correction in [
            CodecCorrection::LiteralCountCorrection,
            CodecCorrection::DistanceCountCorrection,
            CodecCorrection::TreeCodeBitLengthCorrection,
        ] {
            for value in [u32::MAX - 1, u32::MAX] {
                reject_tree_correction(correction, 0, value);
            }
        }
        // These corrections decrease by 19 or increase by 20, independently of
        // the predicted count, and so are always outside the header's 4..=19.
        for value in [38, 41] {
            reject_tree_correction(CodecCorrection::TreeCodeBitLengthCorrection, 0, value);
        }
        reject_tree_correction(CodecCorrection::TreeCodeBitLengthCorrection, 1, 17);
    }

    #[test]
    fn reject_invalid_tree_symbols() {
        for (code_type, value, count, prefix) in [
            (TreeCodeType::Code, 16, 20, false),
            (TreeCodeType::Code, 256, 20, false),
            (TreeCodeType::Repeat, 0, 20, true),
            (TreeCodeType::Repeat, 7, 20, true),
            (TreeCodeType::Repeat, 3, 3, true),
            (TreeCodeType::ZeroShort, 0, 20, false),
            (TreeCodeType::ZeroShort, 2, 20, false),
            (TreeCodeType::ZeroShort, 11, 20, false),
            (TreeCodeType::ZeroShort, 10, 3, false),
            (TreeCodeType::ZeroLong, 0, 20, false),
            (TreeCodeType::ZeroLong, 10, 20, false),
            (TreeCodeType::ZeroLong, 139, 200, false),
            (TreeCodeType::ZeroLong, 138, 20, false),
            (TreeCodeType::ZeroLong, 256, 300, false),
        ] {
            let symbols = vec![1; count];
            let mut encoder = VerifyPredictionEncoder::default();
            encoder.encode_verify_state("predict_ld_trees", 0);
            let remaining = if prefix {
                encoder.encode_correction(CodecCorrection::LDTypeCorrection, 0);
                encoder.encode_correction(CodecCorrection::LDBitLengthCorrection, 0);
                &symbols[1..]
            } else {
                &symbols[..]
            };
            encoder.encode_correction_diff(
                CodecCorrection::LDTypeCorrection,
                code_type as u32,
                predict_code_type(remaining, prefix.then_some(1)) as u32,
            );
            encoder.encode_correction_diff(
                if code_type == TreeCodeType::Code {
                    CodecCorrection::LDBitLengthCorrection
                } else {
                    CodecCorrection::RepeatCountCorrection
                },
                value,
                predict_code_data(remaining, code_type).into(),
            );
            let error = reconstruct_ld_trees(
                &mut VerifyPredictionDecoder::new(encoder.actions()),
                &symbols,
            )
            .unwrap_err();
            assert_eq!(error.exit_code(), ExitCode::InvalidPredictionData);
        }
    }
}
