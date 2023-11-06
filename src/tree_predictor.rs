use crate::{
    huffman_helper::calc_bit_lengths,
    huffman_table::{HuffmanOriginalEncoding, TreeCodeType},
    preflate_constants::{
        CODETREE_CODE_COUNT, DIST_CODE_COUNT, LITLENDIST_CODE_COUNT, LITLEN_CODE_COUNT,
        NONLEN_CODE_COUNT, TREE_CODE_ORDER_TABLE,
    },
    preflate_token::TokenFrequency,
    statistical_codec::{
        AssertEmptyEncoder, EmptyDecoder, PredictionDecoder, PredictionEncoder,
        PreflatePredictionEncoder,
    },
};

pub fn predict_tree_for_block<D: PredictionEncoder>(
    huffman_encoding: &HuffmanOriginalEncoding,
    freq: &TokenFrequency,
    encoder: &mut D,
) -> anyhow::Result<()> {
    // bit_lengths is a vector of huffman code sizes for literals followed by length codes
    let mut bit_lengths = vec![0; LITLENDIST_CODE_COUNT as usize];

    // first predict the size of the literal tree
    let mut predicted_l_tree_size = build_l_bit_lengths(&mut bit_lengths, &freq.literal_codes);

    encoder
        .encode_literal_count_misprediction(predicted_l_tree_size != huffman_encoding.num_literals);

    // if incorrect, include the actual size
    if predicted_l_tree_size != huffman_encoding.num_literals {
        encoder.encode_value(huffman_encoding.num_literals as u16, 7);
        predicted_l_tree_size = huffman_encoding.num_literals;
    }

    // now predict the size of the distance tree
    let predicted_d_tree_size = build_d_bit_lengths(
        &mut bit_lengths[predicted_l_tree_size as usize..],
        &freq.distance_codes,
    );

    encoder.encode_distance_count_misprediction(predicted_d_tree_size != huffman_encoding.num_dist);

    // if incorrect, include the actual size
    if predicted_d_tree_size != huffman_encoding.num_dist {
        encoder.encode_value(huffman_encoding.num_dist as u16, 5);
    }

    // now predict each length code
    predict_ld_trees(encoder, &bit_lengths, huffman_encoding.lengths.as_slice())?;

    // final step, we need to construct the second level huffman tree that is used
    // to store the bit lengths of the huffman tree we just created
    let codetree_freq = calc_codetree_freq(&huffman_encoding.lengths);

    let mut tc_code_tree = [0u8; CODETREE_CODE_COUNT as usize];
    let predicted_c_tree_size = build_tc_bit_lengths(&mut tc_code_tree, &codetree_freq);

    if predicted_c_tree_size != huffman_encoding.code_lengths.len() {
        encoder.encode_tree_code_count_misprediction(true);
        encoder.encode_value(huffman_encoding.code_lengths.len() as u16 - 4, 4);
    } else {
        encoder.encode_tree_code_count_misprediction(false);
    }

    for i in 0..huffman_encoding.code_lengths.len() {
        let predicted_bl = tc_code_tree[i];
        encoder.encode_tree_code_bit_length_correction(
            predicted_bl,
            huffman_encoding.code_lengths[i] as u8,
        );
    }

    Ok(())
}

pub fn recreate_tree_for_block<D: PredictionDecoder>(
    freq: &TokenFrequency,
    codec: &mut D,
) -> anyhow::Result<HuffmanOriginalEncoding> {
    let mut result: HuffmanOriginalEncoding = Default::default();

    let mut bit_lengths = [0u8; LITLENDIST_CODE_COUNT as usize];
    let mut predicted_l_tree_size = build_l_bit_lengths(&mut bit_lengths, &freq.literal_codes);

    if codec.decode_literal_count_misprediction() {
        predicted_l_tree_size = codec.decode_value(7) as usize + NONLEN_CODE_COUNT;
    }

    result.num_literals = predicted_l_tree_size;

    let mut predicted_d_tree_size = build_d_bit_lengths(
        &mut bit_lengths[predicted_l_tree_size as usize..],
        &freq.distance_codes,
    );

    if codec.decode_distance_count_misprediction() {
        predicted_d_tree_size = codec.decode_value(5) as usize;
    }

    result.num_dist = predicted_d_tree_size;

    result.lengths = reconstruct_ld_trees(codec, &bit_lengths)?;

    let bl_freqs = calc_codetree_freq(&result.lengths);

    let mut simple_code_tree = [0u8; CODETREE_CODE_COUNT as usize];
    let mut predicted_c_tree_size = build_tc_bit_lengths(&mut simple_code_tree, &bl_freqs);

    if codec.decode_tree_code_count_misprediction() {
        predicted_c_tree_size = codec.decode_value(4) as usize + 4;
    }

    for i in 0..predicted_c_tree_size {
        result
            .code_lengths
            .push(codec.decode_tree_code_bit_length_correction(simple_code_tree[i]));
    }

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
    calc_bit_lengths(bit_lengths, bl_freqs, CODETREE_CODE_COUNT, 7);

    while predicted_c_tree_size > 4
        && bit_lengths[TREE_CODE_ORDER_TABLE[predicted_c_tree_size - 1] as usize] == 0
    {
        predicted_c_tree_size -= 1;
    }

    predicted_c_tree_size
}

fn predict_ld_trees<D: PredictionEncoder>(
    encoder: &mut D,
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

fn reconstruct_ld_trees<D: PredictionDecoder>(
    codec: &mut D,
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

#[test]
fn encode_roundtrip_perfect() {
    let mut freq = TokenFrequency::default();
    freq.literal_codes[0] = 100;
    freq.literal_codes[1] = 50;
    freq.literal_codes[2] = 25;

    freq.distance_codes[0] = 100;
    freq.distance_codes[1] = 50;
    freq.distance_codes[2] = 25;

    let mut empty_decoder = EmptyDecoder {};
    let regenerated_header = recreate_tree_for_block(&freq, &mut empty_decoder).unwrap();

    assert_eq!(regenerated_header.num_literals, 257);
    assert_eq!(regenerated_header.num_dist, 3);
    assert_eq!(regenerated_header.lengths[0], (TreeCodeType::Code, 1));
    assert_eq!(regenerated_header.lengths[1], (TreeCodeType::Code, 2));
    assert_eq!(regenerated_header.lengths[2], (TreeCodeType::Code, 3));

    let mut empty_encoder = AssertEmptyEncoder {};
    predict_tree_for_block(&regenerated_header, &freq, &mut empty_encoder).unwrap();

    println!("regenerated_header: {:?}", regenerated_header);
}

#[test]
fn encode_tree_roundtrip() {
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
            (TreeCodeType::ZeroLong, 56),
        ],
        code_lengths: vec![0, 3, 2, 3, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        num_literals: 257,
        num_dist: 4,
    };

    let mut encoder = PreflatePredictionEncoder::default();

    predict_tree_for_block(&huff_origin, &freq, &mut encoder).unwrap();

    let mut decoder = encoder.make_decoder();

    let regenerated_header = recreate_tree_for_block(&freq, &mut decoder).unwrap();

    assert_eq!(huff_origin, regenerated_header);
}
