/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use bitcode::{Decode, Encode};

use crate::{
    bit_helper::bit_length,
    deflate::{deflate_constants, deflate_reader::DeflateContents},
    estimator::{add_policy_estimator::DictionaryAddPolicy, preflate_parse_config::MatchingType},
    hash_algorithm::HashAlgorithm,
    preflate_error::Result,
    preflate_input::PlainText,
    token_predictor::TokenPredictorParameters,
};

use super::{
    add_policy_estimator::estimate_add_policy,
    complevel_estimator::estimate_preflate_comp_level,
    preflate_stream_info::{extract_preflate_info, PreflateStreamInfo},
};

#[derive(Encode, Decode, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum PreflateStrategy {
    Default,
    RleOnly,
    HuffOnly,
    Store,
}

#[derive(Encode, Decode, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum PreflateHuffStrategy {
    Dynamic,
    Mixed,
    Static,
}

#[derive(Encode, Decode, Debug, Copy, Clone, Eq, PartialEq)]
pub struct PreflateParameters {
    pub huff_strategy: PreflateHuffStrategy,

    pub predictor: TokenPredictorParameters,
}

impl PreflateParameters {
    /// From the plain text and the preflate blocks, estimate the preflate parameters
    pub fn estimate_preflate_parameters(
        deflate_contents: &DeflateContents,
        plain_text: &PlainText,
    ) -> Result<Self> {
        let info = extract_preflate_info(&deflate_contents.blocks);

        let preflate_strategy = estimate_preflate_strategy(&info);
        let huff_strategy = estimate_preflate_huff_strategy(&info);

        if preflate_strategy == PreflateStrategy::Store
            || preflate_strategy == PreflateStrategy::HuffOnly
        {
            // No dictionary used
            return Ok(PreflateParameters {
                predictor: TokenPredictorParameters {
                    window_bits: 0,
                    very_far_matches_detected: false,
                    matches_to_start_detected: false,
                    strategy: preflate_strategy,
                    nice_length: 0,
                    add_policy: DictionaryAddPolicy::AddAll,
                    max_token_count: 16386,
                    zlib_compatible: true,
                    max_dist_3_matches: 0,
                    matching_type: MatchingType::Greedy,
                    max_chain: 0,
                    min_len: 0,
                    hash_algorithm: HashAlgorithm::None,
                },
                huff_strategy,
            });
        }

        let window_bits = estimate_preflate_window_bits(info.max_dist);
        let mem_level = estimate_preflate_mem_level(info.max_tokens_per_block);
        let add_policy = estimate_add_policy(&deflate_contents.blocks);

        //let hash_shift = 5;
        //let hash_mask = 32767;

        let max_token_count = (1 << (6 + mem_level)) - 1;

        let cl = estimate_preflate_comp_level(
            window_bits,
            mem_level,
            info.min_len,
            deflate_contents,
            plain_text,
            add_policy,
        )?;

        let zlib_compatible = !info.matches_to_start_detected
            && !cl.very_far_matches_detected
            && (info.max_dist_3_matches < 4096 || add_policy != DictionaryAddPolicy::AddAll);

        Ok(PreflateParameters {
            predictor: TokenPredictorParameters {
                window_bits,
                very_far_matches_detected: cl.very_far_matches_detected,
                matches_to_start_detected: info.matches_to_start_detected,
                strategy: estimate_preflate_strategy(&info),
                nice_length: cl.nice_length,
                add_policy: add_policy,
                max_token_count,
                zlib_compatible,
                max_dist_3_matches: info.max_dist_3_matches,
                matching_type: cl.match_type,
                max_chain: cl.max_chain,
                min_len: info.min_len,
                hash_algorithm: cl.hash_algorithm,
            },
            huff_strategy: estimate_preflate_huff_strategy(&info),
        })
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

fn estimate_preflate_window_bits(max_dist_: u32) -> u32 {
    let mut max_dist = max_dist_;
    max_dist += deflate_constants::MIN_LOOKAHEAD;
    let wbits = bit_length(max_dist - 1);
    std::cmp::min(std::cmp::max(wbits, 9), 15)
}

fn estimate_preflate_strategy(info: &PreflateStreamInfo) -> PreflateStrategy {
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

fn estimate_preflate_huff_strategy(info: &PreflateStreamInfo) -> PreflateHuffStrategy {
    if info.count_static_huff_tree_blocks == info.count_blocks {
        return PreflateHuffStrategy::Static;
    }
    if info.count_static_huff_tree_blocks == 0 {
        return PreflateHuffStrategy::Dynamic;
    }
    PreflateHuffStrategy::Mixed
}

#[test]
fn verify_zlib_recognition() {
    use crate::{
        deflate::deflate_reader::parse_deflate_whole,
        estimator::preflate_parse_config::{
            SLOW_PREFLATE_PARSER_SETTINGS, ZLIB_PREFLATE_PARSER_SETTINGS,
        },
        utils::read_file,
    };

    for i in 0..=9 {
        let v = read_file(&format!("compressed_zlib_level{}.deflate", i));
        let (contents, plain_text) = parse_deflate_whole(&v).unwrap();

        let params =
            PreflateParameters::estimate_preflate_parameters(&contents, &plain_text).unwrap();

        assert_eq!(params.predictor.zlib_compatible, true);
        if i == 0 {
            assert_eq!(params.predictor.strategy, PreflateStrategy::Store);
        } else if i >= 1 && i < 4 {
            let config = &ZLIB_PREFLATE_PARSER_SETTINGS[i as usize - 1];
            assert!(
                params.predictor.max_chain <= config.max_chain,
                "max_chain mismatch {} should be <= {}",
                params.predictor.max_chain,
                config.max_chain
            );
            assert_eq!(params.predictor.matching_type, config.match_type);
            assert_eq!(params.predictor.add_policy, config.dictionary_add_policy);
            assert_eq!(params.predictor.nice_length, config.nice_length);
            assert_eq!(params.predictor.strategy, PreflateStrategy::Default);
        } else if i >= 4 {
            let config = &SLOW_PREFLATE_PARSER_SETTINGS[i as usize - 4];
            assert!(
                params.predictor.max_chain <= config.max_chain,
                "max_chain mismatch {} should be <= {}",
                params.predictor.max_chain,
                config.max_chain
            );
            assert_eq!(params.predictor.matching_type, config.match_type);
            assert_eq!(params.predictor.add_policy, config.dictionary_add_policy);
            assert_eq!(params.predictor.nice_length, config.nice_length);
            assert_eq!(params.predictor.strategy, PreflateStrategy::Default);
        }
    }
}

#[test]
fn verify_miniz_recognition() {
    use crate::deflate::deflate_reader::parse_deflate_whole;
    use crate::utils::read_file;

    for i in 0..=9 {
        let v = read_file(&format!("compressed_flate2_level{}.deflate", i));
        let (contents, plain_text) = parse_deflate_whole(&v).unwrap();

        let params =
            PreflateParameters::estimate_preflate_parameters(&contents, &plain_text).unwrap();

        if i == 0 {
            assert_eq!(params.predictor.strategy, PreflateStrategy::Store);
        } else if i == 1 {
            println!("{:?}", params);
        } else {
            println!("{:?}", params);
        }
    }
}

#[test]
fn verify_zlibng_recognition() {
    use crate::deflate::deflate_reader::parse_deflate_whole;
    use crate::utils::read_file;

    for i in 1..=2 {
        let v = read_file(&format!("compressed_zlibng_level{}.deflate", i));
        let (contents, plain_text) = parse_deflate_whole(&v).unwrap();

        let params =
            PreflateParameters::estimate_preflate_parameters(&contents, &plain_text).unwrap();

        if i == 0 {
            assert_eq!(params.predictor.strategy, PreflateStrategy::Store);
        } else if i == 1 {
            println!("{:?}", params);
        } else {
            println!("{:?}", params);
        }
    }
}
