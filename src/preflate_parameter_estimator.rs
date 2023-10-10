use crate::{
    bit_helper::bit_length,
    preflate_complevel_estimator::estimate_preflate_comp_level,
    preflate_constants,
    preflate_parse_config::*,
    preflate_stream_info::{extract_preflate_info, PreflateStreamInfo},
    preflate_token::PreflateTokenBlock,
};

pub enum PreflateStrategy {
    PREFLATE_DEFAULT,
    PREFLATE_RLE_ONLY,
    PREFLATE_HUFF_ONLY,
    PREFLATE_STORE,
}

pub enum PreflateHuffStrategy {
    PREFLATE_HUFF_DYNAMIC,
    PREFLATE_HUFF_MIXED,
    PREFLATE_HUFF_STATIC,
}

pub struct PreflateParameters {
    pub strategy: PreflateStrategy,
    pub huff_strategy: PreflateHuffStrategy,
    pub zlib_compatible: bool,
    pub window_bits: u32,
    pub mem_level: u32,
    pub comp_level: u32,
    pub far_len3_matches_detected: bool,
    pub very_far_matches_detected: bool,
    pub matches_to_start_detected: bool,
    pub log2_of_max_chain_depth_m1: u32,
}

impl PreflateParameters {
    pub fn is_fast_compressor(&self) -> bool {
        self.comp_level >= 1 && self.comp_level <= 3
    }

    pub fn is_slow_compressor(&self) -> bool {
        self.comp_level >= 4 && self.comp_level <= 9
    }

    pub fn config(&self) -> &PreflateParserConfig {
        if self.is_fast_compressor() {
            &FAST_PREFLATE_PARSER_SETTINGS[(self.comp_level - 1) as usize]
        } else {
            &SLOW_PREFLATE_PARSER_SETTINGS[if self.is_slow_compressor() {
                (self.comp_level - 4) as usize
            } else {
                5
            }]
        }
    }
}

pub fn estimate_preflate_mem_level(max_block_size_: u32) -> u32 {
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
        return PreflateStrategy::PREFLATE_STORE;
    }
    if info.count_huff_blocks == info.count_blocks {
        return PreflateStrategy::PREFLATE_HUFF_ONLY;
    }
    if info.count_rle_blocks == info.count_blocks {
        return PreflateStrategy::PREFLATE_RLE_ONLY;
    }
    return PreflateStrategy::PREFLATE_DEFAULT;
}

pub fn estimate_preflate_huff_strategy(info: &PreflateStreamInfo) -> PreflateHuffStrategy {
    if info.count_static_huff_tree_blocks == info.count_blocks {
        return PreflateHuffStrategy::PREFLATE_HUFF_STATIC;
    }
    if info.count_static_huff_tree_blocks == 0 {
        return PreflateHuffStrategy::PREFLATE_HUFF_DYNAMIC;
    }
    return PreflateHuffStrategy::PREFLATE_HUFF_MIXED;
}

pub fn estimate_preflate_parameters(
    unpacked_output: &Vec<u8>,
    off0: u32,
    blocks: &Vec<PreflateTokenBlock>,
) -> PreflateParameters {
    let info = extract_preflate_info(blocks);

    let mut result = PreflateParameters {
        window_bits: estimate_preflate_window_bits(info.max_dist),
        mem_level: estimate_preflate_mem_level(info.max_tokens_per_block),
        strategy: estimate_preflate_strategy(&info),
        huff_strategy: estimate_preflate_huff_strategy(&info),
        zlib_compatible: false,
        far_len3_matches_detected: false,
        very_far_matches_detected: false,
        matches_to_start_detected: false,
        log2_of_max_chain_depth_m1: 0,
        comp_level: 0,
    };

    let cl = estimate_preflate_comp_level(
        result.window_bits.into(),
        result.mem_level.into(),
        unpacked_output,
        off0,
        blocks,
        false,
    );

    result.comp_level = cl.recommended_compression_level;
    result.zlib_compatible = cl.zlib_compatible;
    result.far_len3_matches_detected = cl.far_len_3_matches;
    result.very_far_matches_detected = cl.very_far_matches;
    result.matches_to_start_detected = cl.match_to_start;
    result.log2_of_max_chain_depth_m1 = if cl.max_chain_depth == 0 {
        0
    } else {
        bit_length(cl.max_chain_depth as u32 - 1)
    };
    result
}
