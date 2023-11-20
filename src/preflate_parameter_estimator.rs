/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::{
    bit_helper::bit_length,
    complevel_estimator::estimate_preflate_comp_level,
    preflate_constants,
    preflate_parse_config::*,
    preflate_stream_info::{extract_preflate_info, PreflateStreamInfo},
    preflate_token::PreflateTokenBlock,
    statistical_codec::{PredictionDecoder, PredictionEncoder},
};

#[derive(Debug, Copy, Clone)]
pub enum PreflateStrategy {
    PreflateDefault,
    PreflateRleOnly,
    PreflateHuffOnly,
    PreflateStore,
}

#[derive(Debug, Copy, Clone)]
pub enum PreflateHuffStrategy {
    PreflateHuffDynamic,
    PreflateHuffMixed,
    PreflateHuffStatic,
}

#[derive(Debug, Copy, Clone)]
pub struct PreflateParameters {
    pub strategy: PreflateStrategy,
    pub huff_strategy: PreflateHuffStrategy,
    pub zlib_compatible: bool,
    pub window_bits: u32,
    pub mem_level: u32,
    pub far_len3_matches_detected: bool,
    pub very_far_matches_detected: bool,
    pub matches_to_start_detected: bool,
    pub log2_of_max_chain_depth_m1: u32,
    pub is_fast_compressor: bool,
    pub good_length: u32,
    pub max_lazy: u32,
    pub nice_length: u32,
    pub max_chain: u32,
}

impl PreflateParameters {
    pub fn read<D: PredictionDecoder>(decoder: &mut D) -> Self {
        let strategy = decoder.decode_value(4);
        let huff_strategy = decoder.decode_value(4);
        let zlib_compatible = decoder.decode_value(1) != 0;
        let window_bits = decoder.decode_value(8);
        let mem_level = decoder.decode_value(8);
        let far_len3_matches_detected = decoder.decode_value(1) != 0;
        let very_far_matches_detected = decoder.decode_value(1) != 0;
        let matches_to_start_detected = decoder.decode_value(1) != 0;
        let log2_of_max_chain_depth_m1 = decoder.decode_value(16);
        let is_fast_compressor = decoder.decode_value(1) != 0;
        let good_length = decoder.decode_value(16);
        let max_lazy = decoder.decode_value(16);
        let nice_length = decoder.decode_value(16);
        let max_chain = decoder.decode_value(16);

        PreflateParameters {
            strategy: match strategy {
                0 => PreflateStrategy::PreflateDefault,
                1 => PreflateStrategy::PreflateRleOnly,
                2 => PreflateStrategy::PreflateHuffOnly,
                3 => PreflateStrategy::PreflateStore,
                _ => panic!("invalid strategy"),
            },
            huff_strategy: match huff_strategy {
                0 => PreflateHuffStrategy::PreflateHuffDynamic,
                1 => PreflateHuffStrategy::PreflateHuffMixed,
                2 => PreflateHuffStrategy::PreflateHuffStatic,
                _ => panic!("invalid huff strategy"),
            },
            zlib_compatible,
            window_bits: window_bits.into(),
            mem_level: mem_level.into(),
            far_len3_matches_detected,
            very_far_matches_detected,
            matches_to_start_detected,
            log2_of_max_chain_depth_m1: log2_of_max_chain_depth_m1.into(),
            is_fast_compressor,
            good_length: good_length.into(),
            max_lazy: max_lazy.into(),
            nice_length: nice_length.into(),
            max_chain: max_chain.into(),
        }
    }

    pub fn write<E: PredictionEncoder>(&self, encoder: &mut E) {
        encoder.encode_value(self.strategy as u16, 4);
        encoder.encode_value(self.huff_strategy as u16, 4);
        encoder.encode_value(self.zlib_compatible as u16, 1);
        encoder.encode_value(self.window_bits as u16, 8);
        encoder.encode_value(self.mem_level as u16, 8);
        encoder.encode_value(self.far_len3_matches_detected as u16, 1);
        encoder.encode_value(self.very_far_matches_detected as u16, 1);
        encoder.encode_value(self.matches_to_start_detected as u16, 1);
        encoder.encode_value(self.log2_of_max_chain_depth_m1 as u16, 16);
        encoder.encode_value(self.is_fast_compressor as u16, 1);
        encoder.encode_value(self.good_length as u16, 16);
        encoder.encode_value(self.max_lazy as u16, 16);
        encoder.encode_value(self.nice_length as u16, 16);
        encoder.encode_value(self.max_chain as u16, 16);
    }
}

fn estimate_preflate_mem_level(max_block_size_: u32) -> u32 {
    let mut max_block_size = max_block_size_;
    let mut mbits = 0;
    while max_block_size > 0 {
        mbits += 1;
        max_block_size >>= 1;
    }
    mbits = std::cmp::min(std::cmp::max(mbits, 7), 15);
    mbits - 6
}

pub fn estimate_preflate_window_bits(max_dist_: u32) -> u32 {
    let mut max_dist = max_dist_;
    max_dist += preflate_constants::MIN_LOOKAHEAD as u32;
    let wbits = bit_length(max_dist - 1);
    std::cmp::min(std::cmp::max(wbits, 9), 15)
}

pub fn estimate_preflate_strategy(info: &PreflateStreamInfo) -> PreflateStrategy {
    if info.count_stored_blocks == info.count_blocks {
        return PreflateStrategy::PreflateStore;
    }
    if info.count_huff_blocks == info.count_blocks {
        return PreflateStrategy::PreflateHuffOnly;
    }
    if info.count_rle_blocks == info.count_blocks {
        return PreflateStrategy::PreflateRleOnly;
    }
    return PreflateStrategy::PreflateDefault;
}

pub fn estimate_preflate_huff_strategy(info: &PreflateStreamInfo) -> PreflateHuffStrategy {
    if info.count_static_huff_tree_blocks == info.count_blocks {
        return PreflateHuffStrategy::PreflateHuffStatic;
    }
    if info.count_static_huff_tree_blocks == 0 {
        return PreflateHuffStrategy::PreflateHuffDynamic;
    }
    return PreflateHuffStrategy::PreflateHuffMixed;
}

pub fn estimate_preflate_parameters(
    unpacked_output: &[u8],
    blocks: &Vec<PreflateTokenBlock>,
) -> PreflateParameters {
    let info = extract_preflate_info(blocks);

    let window_bits = estimate_preflate_window_bits(info.max_dist);
    let mem_level = estimate_preflate_mem_level(info.max_tokens_per_block);

    let cl = estimate_preflate_comp_level(
        window_bits.into(),
        mem_level.into(),
        unpacked_output,
        blocks,
        false,
    );

    let config;
    let comp_level = cl.recommended_compression_level;
    let is_fast_compressor;

    if comp_level >= 1 && comp_level <= 3 {
        is_fast_compressor = true;
        config = &FAST_PREFLATE_PARSER_SETTINGS[(comp_level - 1) as usize]
    } else {
        is_fast_compressor = false;
        config = &SLOW_PREFLATE_PARSER_SETTINGS[if comp_level >= 4 && comp_level <= 9 {
            (comp_level - 4) as usize
        } else {
            5
        }]
    }

    PreflateParameters {
        window_bits,
        mem_level,
        strategy: estimate_preflate_strategy(&info),
        huff_strategy: estimate_preflate_huff_strategy(&info),
        zlib_compatible: cl.zlib_compatible,
        far_len3_matches_detected: cl.far_len_3_matches,
        very_far_matches_detected: cl.very_far_matches,
        matches_to_start_detected: cl.match_to_start,
        log2_of_max_chain_depth_m1: if cl.max_chain_depth == 0 {
            0
        } else {
            bit_length(cl.max_chain_depth as u32 - 1)
        },
        is_fast_compressor,
        good_length: config.good_length,
        max_lazy: config.max_lazy,
        nice_length: config.nice_length,
        max_chain: config.max_chain,
    }
}
