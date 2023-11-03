use std::{cmp::Ordering, collections::BinaryHeap, f32::consts::E, os::windows::fs::symlink_dir};

use crate::{
    huffman_decoder::{HuffmanOriginalEncoding, TreeCodeType},
    huffman_helper::calc_bit_lengths,
    preflate_constants::{
        quantize_distance, quantize_length, CODETREE_CODE_COUNT, DIST_CODE_COUNT,
        LITLENDIST_CODE_COUNT, LITLEN_CODE_COUNT, NONLEN_CODE_COUNT, TREE_CODE_ORDER_TABLE,
    },
    preflate_input::PreflateInput,
    preflate_statistical_codec::{PreflatePredictionDecoder, PreflatePredictionEncoder},
    preflate_statistical_model::PreflateStatisticsCounter,
    preflate_token::{BlockType, PreflateTokenBlock},
};

pub fn decode_tree_for_block(
    block: &PreflateTokenBlock,
    codec: &mut PreflatePredictionDecoder,
) -> anyhow::Result<HuffmanOriginalEncoding> {
    let mut result: HuffmanOriginalEncoding = Default::default();

    assert!(block.block_type == BlockType::DynamicHuff);

    let mut bit_lengths = [0u8; LITLENDIST_CODE_COUNT as usize];
    let mut predicted_l_tree_size = build_l_bit_lengths(&mut bit_lengths, &block.literal_codes);

    if codec.decode_literal_count_misprediction() {
        predicted_l_tree_size = codec.decode_value(5) as usize + NONLEN_CODE_COUNT;
    }

    result.num_literals = predicted_l_tree_size;

    let mut predicted_d_tree_size = build_d_bit_lengths(
        &mut bit_lengths[predicted_l_tree_size as usize..],
        &block.distance_codes,
    );

    if codec.decode_distance_count_misprediction() {
        predicted_d_tree_size = codec.decode_value(5) as usize;
    }

    result.num_dist = predicted_d_tree_size;

    let tree_codes = reconstruct_ld_trees(codec, &bit_lengths)?;

    let bl_freqs = calc_codetree_freq(&tree_codes);

    let mut simple_code_tree = [0u8; CODETREE_CODE_COUNT as usize];
    let mut predicted_c_tree_size = build_tc_bit_lengths(&mut simple_code_tree, &bl_freqs);
    if codec.decode_tree_code_count_misprediction() {
        predicted_c_tree_size = codec.decode_value(4) as usize + 4;
    }
    //block.ncode = predicted_c_tree_size as u16;

    let mut shuffled_code_tree = [0u8; CODETREE_CODE_COUNT as usize];
    for i in 0..predicted_c_tree_size {
        let predicted_bl = simple_code_tree[TREE_CODE_ORDER_TABLE[i] as usize];
        shuffled_code_tree[i as usize] = codec.decode_tree_code_bit_length_correction(predicted_bl);
    }

    /*block
            .tree_codes
            .reserve(predicted_c_tree_size as usize + target_code_size);
        block
            .tree_codes
            .extend_from_slice(&shuffled_code_tree[..predicted_c_tree_size as usize]);
        block
            .tree_codes
            .extend_from_slice(&compressed_ld_trees[..target_code_size as usize]);
    */
    Ok(result)
}

fn build_l_bit_lengths(bit_lengths: &mut [u8], lcodes: &[u16]) -> usize {
    calc_bit_lengths(bit_lengths, lcodes, LITLEN_CODE_COUNT as usize, 15)
}

fn build_d_bit_lengths(bit_lengths: &mut [u8], dcodes: &[u16]) -> usize {
    calc_bit_lengths(bit_lengths, dcodes, DIST_CODE_COUNT as usize, 15)
}

fn build_tc_bit_lengths(
    bit_lengths: &mut [u8; CODETREE_CODE_COUNT],
    bl_freqs: &[u16; CODETREE_CODE_COUNT],
) -> usize {
    let mut predicted_c_tree_size = CODETREE_CODE_COUNT;
    let mut simple_code_tree_copy = [0; CODETREE_CODE_COUNT];
    calc_bit_lengths(&mut simple_code_tree_copy, bl_freqs, CODETREE_CODE_COUNT, 7);

    while predicted_c_tree_size > 4
        && simple_code_tree_copy[TREE_CODE_ORDER_TABLE[predicted_c_tree_size - 1] as usize] == 0
    {
        predicted_c_tree_size -= 1;
    }

    predicted_c_tree_size
}

fn predict_ld_trees(
    encoder: &mut PreflatePredictionEncoder,
    sym_bit_len: &[u8],
    target_codes: &[(TreeCodeType, u8)],
) -> anyhow::Result<()> {
    let mut symbols = sym_bit_len;
    let mut prev_code = None;

    for (target_tree_code_type, target_tree_code_data) in target_codes.iter() {
        if symbols.len() == 0 {
            return Err(anyhow::anyhow!("Reconstruction failed"));
        }

        let predicted_tree_code_type = predict_code_type(symbols, prev_code);

        prev_code = Some(symbols[0]);

        encoder.encode_ld_type_correction(predicted_tree_code_type, *target_tree_code_type);

        let predicted_tree_code_data = predict_code_data(symbols, *target_tree_code_type);

        if *target_tree_code_type != TreeCodeType::Code {
            encoder.encode_repeat_count_correction(
                predicted_tree_code_data,
                *target_tree_code_data,
                *target_tree_code_type,
            );
        } else {
            encoder
                .encode_ld_bit_length_correction(predicted_tree_code_data, *target_tree_code_data);
        }

        if *target_tree_code_type == TreeCodeType::Code {
            symbols = &symbols[1..];
        } else {
            symbols = &symbols[*target_tree_code_data as usize..];
        }
    }

    Ok(())
}

fn reconstruct_ld_trees(
    codec: &mut PreflatePredictionDecoder,
    sym_bit_len: &[u8],
) -> anyhow::Result<Vec<(TreeCodeType, u8)>> {
    let mut symbols = sym_bit_len;
    let mut prev_code = None;
    let mut result: Vec<(TreeCodeType, u8)> = Vec::new();

    while symbols.len() > 0 {
        let predicted_tree_code_type = predict_code_type(symbols, prev_code);
        prev_code = Some(symbols[0]);

        let predicted_tree_code_type = codec.decode_ld_type_correction(predicted_tree_code_type);

        let mut predicted_tree_code_data = predict_code_data(symbols, predicted_tree_code_type);

        if predicted_tree_code_type != TreeCodeType::Code {
            predicted_tree_code_data = codec
                .decode_repeat_count_correction(predicted_tree_code_data, predicted_tree_code_type);
        } else {
            predicted_tree_code_data =
                codec.decode_ld_bit_length_correction(predicted_tree_code_data);
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

fn collect_token_statistics(
    plain_text: &[u8],
    block: &PreflateTokenBlock,
) -> (
    [u32; LITLEN_CODE_COUNT as usize],
    [u32; DIST_CODE_COUNT as usize],
    u32,
    u32,
) {
    let mut input = PreflateInput::new(plain_text);

    let mut Lcodes = [0; LITLEN_CODE_COUNT as usize];
    let mut Dcodes = [0; DIST_CODE_COUNT as usize];
    let mut Lcount = 0;
    let mut Dcount = 0;

    for token in &block.tokens {
        if token.len() == 1 {
            Lcodes[input.cur_char(0) as usize] += 1;
            Lcount += 1;
            input.advance(1);
        } else {
            Lcodes[(NONLEN_CODE_COUNT + quantize_length(token.len())) as usize] += 1;
            Lcount += 1;
            Dcodes[quantize_distance(token.dist()) as usize] += 1;
            Dcount += 1;
            input.advance(token.len());
        }
    }
    Lcodes[256] = 1;

    (Lcodes, Dcodes, Lcount, Dcount)
}

pub fn encode_tree_for_block(
    block: &PreflateTokenBlock,
    huffman_encoding: &HuffmanOriginalEncoding,
    encoder: &mut PreflatePredictionEncoder,
) -> anyhow::Result<()> {
    if block.block_type != BlockType::DynamicHuff {
        return Ok(());
    }

    let mut bit_lengths = vec![0; LITLENDIST_CODE_COUNT as usize];
    let mut predicted_l_tree_size = build_l_bit_lengths(&mut bit_lengths, &block.literal_codes);

    encoder
        .encode_literal_count_misprediction(predicted_l_tree_size != huffman_encoding.num_literals);
    if predicted_l_tree_size != huffman_encoding.num_literals {
        encoder.encode_value(huffman_encoding.num_literals as u32, 7);
    }

    predicted_l_tree_size = huffman_encoding.num_literals;

    let mut predicted_d_tree_size = build_d_bit_lengths(
        &mut bit_lengths[predicted_l_tree_size as usize..],
        &block.distance_codes,
    );

    encoder
        .encode_tree_code_count_misprediction(predicted_d_tree_size != huffman_encoding.num_dist);
    if predicted_d_tree_size != huffman_encoding.num_dist {
        encoder.encode_value(huffman_encoding.num_dist as u32, 5);
    }

    predicted_d_tree_size = huffman_encoding.num_dist;

    predict_ld_trees(encoder, &bit_lengths, huffman_encoding.lengths.as_slice())?;

    let freq = calc_codetree_freq(&huffman_encoding.lengths);

    Ok(())
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
        while curlen < max_cur_len && sym_bit_len[curlen as usize] == 0 {
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
            while curlen < max_cur_len && sym_bit_len[curlen as usize] == code {
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
            while curlen < max_cur_len && sym_bit_len[curlen as usize] == 0 {
                curlen += 1;
            }
            curlen as u8
        }
    }
}
