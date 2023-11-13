use crate::{
    bit_helper::DebugHash,
    huffman_calc::calc_minzoxide::calc_bit_lengths,
    huffman_encoding::{HuffmanOriginalEncoding, TreeCodeType},
    preflate_constants::{CODETREE_CODE_COUNT, NONLEN_CODE_COUNT, TREE_CODE_ORDER_TABLE},
    preflate_token::TokenFrequency,
    statistical_codec::{PredictionDecoder, PredictionEncoder},
};

pub fn predict_tree_for_block<D: PredictionEncoder>(
    huffman_encoding: &HuffmanOriginalEncoding,
    freq: &TokenFrequency,
    encoder: &mut D,
) -> anyhow::Result<()> {
    encoder.encode_verify_state("tree", DebugHash::default());

    // bit_lengths is a vector of huffman code sizes for literals followed by length codes
    // first predict the size of the literal tree
    let mut bit_lengths = calc_bit_lengths(&freq.literal_codes, 15);

    encoder.encode_literal_count_misprediction(bit_lengths.len() != huffman_encoding.num_literals);

    // if incorrect, include the actual size
    if bit_lengths.len() != huffman_encoding.num_literals {
        encoder.encode_value(huffman_encoding.num_literals as u16 - 257, 5);

        bit_lengths.resize(huffman_encoding.num_literals as usize, 0);
    }

    // now predict the size of the distance tree
    let mut distance_code_lengths = calc_bit_lengths(&freq.distance_codes, 15);

    encoder.encode_distance_count_misprediction(
        distance_code_lengths.len() != huffman_encoding.num_dist,
    );

    // if incorrect, include the actual size
    if distance_code_lengths.len() != huffman_encoding.num_dist {
        encoder.encode_value(huffman_encoding.num_dist as u16 - 1, 5);

        distance_code_lengths.resize(huffman_encoding.num_dist as usize, 0);
    }

    bit_lengths.append(&mut distance_code_lengths);

    // now predict each length code
    predict_ld_trees(encoder, &bit_lengths, huffman_encoding.lengths.as_slice())?;

    // final step, we need to construct the second level huffman tree that is used
    // to store the bit lengths of the huffman tree we just created
    let codetree_freq = calc_codetree_freq(&huffman_encoding.lengths);

    let mut tc_code_tree = calc_bit_lengths(&codetree_freq, 7);

    let tc_code_tree_len = calc_tc_lengths_without_trailing_zeros(&tc_code_tree);

    if tc_code_tree_len != huffman_encoding.num_code_lengths {
        encoder.encode_tree_code_count_misprediction(true);
        encoder.encode_value(huffman_encoding.num_code_lengths as u16 - 4, 4);
    } else {
        encoder.encode_tree_code_count_misprediction(false);
    }

    // resize so that when we walk through in TREE_CODE_ORDER_TABLE order, we
    // don't go out of range.
    tc_code_tree.resize(CODETREE_CODE_COUNT, 0);

    for i in 0..huffman_encoding.num_code_lengths {
        let predicted_bl = tc_code_tree[TREE_CODE_ORDER_TABLE[i]];
        encoder.encode_tree_code_bit_length_correction(
            predicted_bl,
            huffman_encoding.code_lengths[TREE_CODE_ORDER_TABLE[i]] as u8,
        );
    }

    Ok(())
}

pub fn recreate_tree_for_block<D: PredictionDecoder>(
    freq: &TokenFrequency,
    codec: &mut D,
) -> anyhow::Result<HuffmanOriginalEncoding> {
    codec.decode_verify_state("tree", DebugHash::default());

    let mut result: HuffmanOriginalEncoding = Default::default();

    let mut bit_lengths = calc_bit_lengths(&freq.literal_codes, 15);

    if codec.decode_literal_count_misprediction() {
        let corrected_num_literals = codec.decode_value(5) as usize + NONLEN_CODE_COUNT;
        bit_lengths.resize(corrected_num_literals, 0);
    }

    result.num_literals = bit_lengths.len();

    let mut distance_code_lengths = calc_bit_lengths(&freq.distance_codes, 15);

    if codec.decode_distance_count_misprediction() {
        let corrected_num_distance = codec.decode_value(5) as usize + 1;
        bit_lengths.resize(corrected_num_distance, 0);
    }

    result.num_dist = distance_code_lengths.len();

    // frequences are encoded as appended together as a single vector
    bit_lengths.append(&mut distance_code_lengths);

    result.lengths = reconstruct_ld_trees(codec, &bit_lengths)?;

    let bl_freqs = calc_codetree_freq(&result.lengths);

    let mut tc_code_tree = calc_bit_lengths(&bl_freqs, 7);

    let mut tc_code_tree_len = calc_tc_lengths_without_trailing_zeros(&tc_code_tree);

    if codec.decode_tree_code_count_misprediction() {
        tc_code_tree_len = codec.decode_value(4) as usize + 4;
    }

    result.num_code_lengths = tc_code_tree_len;

    // resize so that when we walk through in TREE_CODE_ORDER_TABLE order, we
    // don't go out of range.
    tc_code_tree.resize(CODETREE_CODE_COUNT, 0);

    for i in 0..tc_code_tree_len {
        result.code_lengths[TREE_CODE_ORDER_TABLE[i]] =
            codec.decode_tree_code_bit_length_correction(tc_code_tree[TREE_CODE_ORDER_TABLE[i]]);
    }

    Ok(result)
}

/// since treecodes are encoded in a different order (see TREE_CODE_ORDER_TABLE) in
/// order to optimize the chance of removing trailing zeros, we need to calculate
/// the effective encoding size of the length codes
fn calc_tc_lengths_without_trailing_zeros(bit_lengths: &[u8]) -> usize {
    let mut len = bit_lengths.len();
    // remove trailing zeros
    while len > 4 && bit_lengths[TREE_CODE_ORDER_TABLE[len - 1] as usize] == 0 {
        len -= 1;
    }

    len
}

fn predict_ld_trees<D: PredictionEncoder>(
    encoder: &mut D,
    predicted_bit_len: &[u8],
    actual_target_codes: &[(TreeCodeType, u8)],
) -> anyhow::Result<()> {
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
        if symbols.len() == 0 {
            return Err(anyhow::anyhow!("Reconstruction failed"));
        }

        let predicted_tree_code_type: TreeCodeType = predict_code_type(symbols, prev_code);

        prev_code = Some(symbols[0]);

        encoder.encode_ld_type_correction(predicted_tree_code_type, target_tree_code_type);

        let predicted_tree_code_data = predict_code_data(symbols, target_tree_code_type);

        if target_tree_code_type != TreeCodeType::Code {
            encoder.encode_repeat_count_correction(
                predicted_tree_code_data,
                target_tree_code_data,
                target_tree_code_type,
            );
        } else {
            encoder
                .encode_ld_bit_length_correction(predicted_tree_code_data, target_tree_code_data);
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
) -> anyhow::Result<Vec<(TreeCodeType, u8)>> {
    let mut symbols = sym_bit_len;
    let mut prev_code = None;
    let mut result: Vec<(TreeCodeType, u8)> = Vec::new();

    while symbols.len() > 0 {
        let predicted_tree_code_type = predict_code_type(symbols, prev_code);
        prev_code = Some(symbols[0]);

        let predicted_tree_code_type = decoder.decode_ld_type_correction(predicted_tree_code_type);

        let mut predicted_tree_code_data = predict_code_data(symbols, predicted_tree_code_type);

        if predicted_tree_code_type != TreeCodeType::Code {
            predicted_tree_code_data = decoder
                .decode_repeat_count_correction(predicted_tree_code_data, predicted_tree_code_type);
        } else {
            predicted_tree_code_data =
                decoder.decode_ld_bit_length_correction(predicted_tree_code_data);
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
    use crate::statistical_codec::PreflatePredictionDecoder;

    let mut freq = TokenFrequency::default();
    freq.literal_codes[0] = 100;
    freq.literal_codes[1] = 50;
    freq.literal_codes[2] = 25;

    freq.distance_codes[0] = 100;
    freq.distance_codes[1] = 50;
    freq.distance_codes[2] = 25;

    let mut empty_decoder = PreflatePredictionDecoder::default_decoder();
    let regenerated_header = recreate_tree_for_block(&freq, &mut empty_decoder).unwrap();

    println!("regenerated_header: {:?}", regenerated_header);

    assert_eq!(regenerated_header.num_literals, 257);
    assert_eq!(regenerated_header.num_dist, 3);
    assert_eq!(regenerated_header.lengths[0], (TreeCodeType::Code, 1));
    assert_eq!(regenerated_header.lengths[1], (TreeCodeType::Code, 2));
    assert_eq!(regenerated_header.lengths[2], (TreeCodeType::Code, 3));

    let mut empty_encoder = crate::statistical_codec::PreflatePredictionEncoder::default();
    predict_tree_for_block(&regenerated_header, &freq, &mut empty_encoder).unwrap();
    assert_eq!(empty_encoder.count_nondefault_actions(), 0);

    println!("regenerated_header: {:?}", regenerated_header);
}

#[test]
fn encode_perfect_encoding() {
    use crate::statistical_codec::PreflatePredictionDecoder;

    let mut freq = TokenFrequency::default();
    // fill with random frequencies
    let mut v: u16 = 10;
    freq.literal_codes.fill_with(|| {
        v = v.wrapping_add(997);
        v
    });
    freq.distance_codes.fill_with(|| {
        v = v.wrapping_add(997);
        v
    });

    // use the default encoder the says that everything is ok
    let default_encoding =
        recreate_tree_for_block(&freq, &mut PreflatePredictionDecoder::default_decoder()).unwrap();

    // now predict the encoding using the default encoding and it should be perfect
    let mut empty_encoder = crate::statistical_codec::PreflatePredictionEncoder::default();
    predict_tree_for_block(&default_encoding, &freq, &mut empty_encoder).unwrap();
    assert_eq!(empty_encoder.count_nondefault_actions(), 0);
}

#[test]
fn encode_tree_roundtrip() {
    use crate::statistical_codec::PreflatePredictionEncoder;

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

    let mut encoder = PreflatePredictionEncoder::default();

    predict_tree_for_block(&huff_origin, &freq, &mut encoder).unwrap();

    let mut decoder = encoder.make_decoder();

    let regenerated_header = recreate_tree_for_block(&freq, &mut decoder).unwrap();

    assert_eq!(huff_origin, regenerated_header);
}