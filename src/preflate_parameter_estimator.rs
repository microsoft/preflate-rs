/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::{
    bit_helper::bit_length,
    complevel_estimator::estimate_preflate_comp_level,
    preflate_constants::{self},
    preflate_stream_info::{extract_preflate_info, PreflateStreamInfo},
    preflate_token::PreflateTokenBlock,
    statistical_codec::{PredictionDecoder, PredictionEncoder},
};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PreflateStrategy {
    Default,
    RleOnly,
    HuffOnly,
    Store,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PreflateHuffStrategy {
    Dynamic,
    Mixed,
    Static,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct PreflateParameters {
    pub strategy: PreflateStrategy,
    pub huff_strategy: PreflateHuffStrategy,
    pub zlib_compatible: bool,
    pub window_bits: u32,
    pub hash_shift: u32,
    pub hash_mask: u16,
    pub max_token_count: u16,
    pub max_dist_3_matches: u16,
    pub very_far_matches_detected: bool,
    pub matches_to_start_detected: bool,
    pub log2_of_max_chain_depth_m1: u32,
    pub is_fast_compressor: bool,
    pub good_length: u32,
    pub max_lazy: u32,
    pub nice_length: u32,
    pub max_chain: u32,
    pub hash_algorithm: u16,
}

impl PreflateParameters {
    pub fn read<D: PredictionDecoder>(decoder: &mut D) -> Self {
        let strategy = decoder.decode_value(4);
        let huff_strategy = decoder.decode_value(4);
        let zlib_compatible = decoder.decode_value(1) != 0;
        let window_bits = decoder.decode_value(8);
        let hash_shift = decoder.decode_value(8);
        let hash_mask = decoder.decode_value(16);
        let max_token_count = decoder.decode_value(16);
        let max_dist_3_matches = decoder.decode_value(16);
        let very_far_matches_detected = decoder.decode_value(1) != 0;
        let matches_to_start_detected = decoder.decode_value(1) != 0;
        let log2_of_max_chain_depth_m1 = decoder.decode_value(16);
        let is_fast_compressor = decoder.decode_value(1) != 0;
        let good_length = decoder.decode_value(16);
        let max_lazy = decoder.decode_value(16);
        let nice_length = decoder.decode_value(16);
        let max_chain = decoder.decode_value(16);
        let hash_algorithm = decoder.decode_value(16);

        PreflateParameters {
            strategy: match strategy {
                0 => PreflateStrategy::Default,
                1 => PreflateStrategy::RleOnly,
                2 => PreflateStrategy::HuffOnly,
                3 => PreflateStrategy::Store,
                _ => panic!("invalid strategy"),
            },
            huff_strategy: match huff_strategy {
                0 => PreflateHuffStrategy::Dynamic,
                1 => PreflateHuffStrategy::Mixed,
                2 => PreflateHuffStrategy::Static,
                _ => panic!("invalid huff strategy"),
            },
            zlib_compatible,
            window_bits: window_bits.into(),
            hash_shift: hash_shift.into(),
            hash_mask: hash_mask,
            max_token_count: max_token_count,
            max_dist_3_matches,
            very_far_matches_detected,
            matches_to_start_detected,
            log2_of_max_chain_depth_m1: log2_of_max_chain_depth_m1.into(),
            is_fast_compressor,
            good_length: good_length.into(),
            max_lazy: max_lazy.into(),
            nice_length: nice_length.into(),
            max_chain: max_chain.into(),
            hash_algorithm,
        }
    }

    pub fn write<E: PredictionEncoder>(&self, encoder: &mut E) {
        encoder.encode_value(self.strategy as u16, 4);
        encoder.encode_value(self.huff_strategy as u16, 4);
        encoder.encode_value(u16::try_from(self.zlib_compatible).unwrap(), 1);
        encoder.encode_value(u16::try_from(self.window_bits).unwrap(), 8);
        encoder.encode_value(u16::try_from(self.hash_shift).unwrap(), 8);
        encoder.encode_value(u16::try_from(self.hash_mask).unwrap(), 16);
        encoder.encode_value(u16::try_from(self.max_token_count).unwrap(), 16);
        encoder.encode_value(u16::try_from(self.max_dist_3_matches).unwrap(), 16);
        encoder.encode_value(u16::try_from(self.very_far_matches_detected).unwrap(), 1);
        encoder.encode_value(u16::try_from(self.matches_to_start_detected).unwrap(), 1);
        encoder.encode_value(u16::try_from(self.log2_of_max_chain_depth_m1).unwrap(), 16);
        encoder.encode_value(u16::try_from(self.is_fast_compressor).unwrap(), 1);
        encoder.encode_value(u16::try_from(self.good_length).unwrap(), 16);
        encoder.encode_value(u16::try_from(self.max_lazy).unwrap(), 16);
        encoder.encode_value(u16::try_from(self.nice_length).unwrap(), 16);
        encoder.encode_value(u16::try_from(self.max_chain).unwrap(), 16);
        encoder.encode_value(u16::try_from(self.hash_algorithm).unwrap(), 16);
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
    max_dist += preflate_constants::MIN_LOOKAHEAD;
    let wbits = bit_length(max_dist - 1);
    std::cmp::min(std::cmp::max(wbits, 9), 15)
}

pub fn estimate_preflate_strategy(info: &PreflateStreamInfo) -> PreflateStrategy {
    if info.count_stored_blocks == info.count_blocks {
        return PreflateStrategy::Store;
    }
    if info.count_huff_blocks == info.count_blocks {
        return PreflateStrategy::HuffOnly;
    }
    if info.count_rle_blocks == info.count_blocks {
        return PreflateStrategy::RleOnly;
    }
    PreflateStrategy::Default
}

pub fn estimate_preflate_huff_strategy(info: &PreflateStreamInfo) -> PreflateHuffStrategy {
    if info.count_static_huff_tree_blocks == info.count_blocks {
        return PreflateHuffStrategy::Static;
    }
    if info.count_static_huff_tree_blocks == 0 {
        return PreflateHuffStrategy::Dynamic;
    }
    PreflateHuffStrategy::Mixed
}

pub fn estimate_preflate_parameters(
    unpacked_output: &[u8],
    blocks: &Vec<PreflateTokenBlock>,
) -> PreflateParameters {
    let info = extract_preflate_info(blocks);

    let window_bits = estimate_preflate_window_bits(info.max_dist);
    let mem_level = estimate_preflate_mem_level(info.max_tokens_per_block);

    //let hash_shift = 5;
    //let hash_mask = 32767;

    let max_token_count = (1 << (6 + mem_level)) - 1;

    let cl = estimate_preflate_comp_level(window_bits, mem_level, unpacked_output, blocks);

    let hash_shift = cl.hash_shift;
    let hash_mask = cl.hash_mask;

    PreflateParameters {
        window_bits,
        hash_shift,
        hash_mask,
        max_token_count,
        strategy: estimate_preflate_strategy(&info),
        huff_strategy: estimate_preflate_huff_strategy(&info),
        zlib_compatible: cl.zlib_compatible,
        max_dist_3_matches: cl.max_dist_3_matches,
        very_far_matches_detected: cl.very_far_matches,
        matches_to_start_detected: cl.match_to_start,
        log2_of_max_chain_depth_m1: if cl.max_chain_depth == 0 {
            0
        } else {
            bit_length(cl.max_chain_depth as u32 - 1)
        },
        is_fast_compressor: cl.fast_compressor,
        good_length: cl.good_length,
        max_lazy: cl.max_lazy,
        nice_length: cl.nice_length,
        max_chain: cl.max_chain,
        hash_algorithm: cl.hash_algorithm,
    }
}
