/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::{
    bit_helper::bit_length,
    estimator::{add_policy_estimator::DictionaryAddPolicy, preflate_parse_config::MatchingType},
    hash_algorithm::HashAlgorithm,
    preflate_constants::{self},
    preflate_error::{ExitCode, Result},
    preflate_token::PreflateTokenBlock,
    statistical_codec::{PredictionDecoder, PredictionEncoder},
    token_predictor::TokenPredictorParameters,
    PreflateError,
};

use super::{
    add_policy_estimator::estimate_add_policy,
    complevel_estimator::estimate_preflate_comp_level,
    preflate_stream_info::{extract_preflate_info, PreflateStreamInfo},
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
    pub huff_strategy: PreflateHuffStrategy,

    pub predictor: TokenPredictorParameters,
}

const FILE_VERSION: u16 = 1;

impl PreflateParameters {
    pub fn read(decoder: &mut impl PredictionDecoder) -> core::result::Result<Self, PreflateError> {
        assert_eq!(FILE_VERSION, decoder.decode_value(8));
        let strategy = decoder.decode_value(4);
        let huff_strategy = decoder.decode_value(4);
        let zlib_compatible = decoder.decode_value(1) != 0;
        let window_bits = decoder.decode_value(8);
        let hash_algorithm = HashAlgorithm::from_u16(decoder.decode_value(16));

        let max_token_count = decoder.decode_value(16);
        let max_dist_3_matches = decoder.decode_value(16);
        let very_far_matches_detected = decoder.decode_value(1) != 0;
        let matches_to_start_detected = decoder.decode_value(1) != 0;
        let good_length = decoder.decode_value(16);
        let max_lazy = decoder.decode_value(16);
        let nice_length = decoder.decode_value(16);
        let max_chain = decoder.decode_value(16);
        let min_len = decoder.decode_value(16);

        let add_policy = match decoder.decode_value(3) {
            0 => DictionaryAddPolicy::AddAll,
            1 => DictionaryAddPolicy::AddFirst(decoder.decode_value(8)),
            2 => DictionaryAddPolicy::AddFirstAndLast(decoder.decode_value(8)),
            3 => DictionaryAddPolicy::AddFirstExcept4kBoundary,
            4 => DictionaryAddPolicy::AddFirstWith32KBoundary,
            _ => {
                return Err(PreflateError::new(
                    ExitCode::InvalidParameterHeader,
                    "invalid add policy",
                ))
            }
        };

        const STRATEGY_DEFAULT: u16 = PreflateStrategy::Default as u16;
        const STRATEGY_RLE_ONLY: u16 = PreflateStrategy::RleOnly as u16;
        const STRATEGY_HUFF_ONLY: u16 = PreflateStrategy::HuffOnly as u16;
        const STRATEGY_STORE: u16 = PreflateStrategy::Store as u16;

        const HUFF_STRATEGY_DYNAMIC: u16 = PreflateHuffStrategy::Dynamic as u16;
        const HUFF_STRATEGY_MIXED: u16 = PreflateHuffStrategy::Mixed as u16;
        const HUFF_STRATEGY_STATIC: u16 = PreflateHuffStrategy::Static as u16;

        Ok(PreflateParameters {
            predictor: TokenPredictorParameters {
                strategy: match strategy {
                    STRATEGY_DEFAULT => PreflateStrategy::Default,
                    STRATEGY_RLE_ONLY => PreflateStrategy::RleOnly,
                    STRATEGY_HUFF_ONLY => PreflateStrategy::HuffOnly,
                    STRATEGY_STORE => PreflateStrategy::Store,
                    _ => {
                        return Err(PreflateError::new(
                            ExitCode::InvalidParameterHeader,
                            "invalid strategy",
                        ))
                    }
                },
                window_bits: window_bits.into(),
                very_far_matches_detected,
                matches_to_start_detected,
                nice_length: nice_length.into(),
                add_policy,
                max_token_count,
                zlib_compatible,
                max_dist_3_matches,
                matching_type: if max_lazy > 0 {
                    MatchingType::Lazy {
                        good_length,
                        max_lazy,
                    }
                } else {
                    MatchingType::Greedy
                },
                max_chain: max_chain.into(),
                min_len: min_len.into(),
                hash_algorithm: match hash_algorithm {
                    Some(h) => h,
                    None => {
                        return Err(PreflateError::new(
                            ExitCode::InvalidParameterHeader,
                            "invalid hash algorithm",
                        ))
                    }
                },
            },
            huff_strategy: match huff_strategy {
                HUFF_STRATEGY_DYNAMIC => PreflateHuffStrategy::Dynamic,
                HUFF_STRATEGY_MIXED => PreflateHuffStrategy::Mixed,
                HUFF_STRATEGY_STATIC => PreflateHuffStrategy::Static,
                _ => {
                    return Err(PreflateError::new(
                        ExitCode::InvalidParameterHeader,
                        "invalid huff strategy",
                    ))
                }
            },
        })
    }

    pub fn write<E: PredictionEncoder>(&self, encoder: &mut E) {
        encoder.encode_value(FILE_VERSION, 8);
        encoder.encode_value(self.predictor.strategy as u16, 4);
        encoder.encode_value(self.huff_strategy as u16, 4);
        encoder.encode_value(u16::from(self.predictor.zlib_compatible), 1);
        encoder.encode_value(u16::try_from(self.predictor.window_bits).unwrap(), 8);

        encoder.encode_value(self.predictor.hash_algorithm.to_u16(), 16);

        encoder.encode_value(self.predictor.max_token_count, 16);
        encoder.encode_value(self.predictor.max_dist_3_matches, 16);
        encoder.encode_value(u16::from(self.predictor.very_far_matches_detected), 1);
        encoder.encode_value(u16::from(self.predictor.matches_to_start_detected), 1);

        let good_length;
        let max_lazy;
        match self.predictor.matching_type {
            MatchingType::Greedy => {
                good_length = 0;
                max_lazy = 0;
            }
            MatchingType::Lazy {
                good_length: gl,
                max_lazy: ml,
            } => {
                good_length = gl;
                max_lazy = ml;
            }
        }

        encoder.encode_value(good_length, 16);
        encoder.encode_value(max_lazy, 16);
        encoder.encode_value(u16::try_from(self.predictor.nice_length).unwrap(), 16);
        encoder.encode_value(u16::try_from(self.predictor.max_chain).unwrap(), 16);
        encoder.encode_value(u16::try_from(self.predictor.min_len).unwrap(), 16);

        match self.predictor.add_policy {
            DictionaryAddPolicy::AddAll => encoder.encode_value(0, 3),
            DictionaryAddPolicy::AddFirst(v) => {
                encoder.encode_value(1, 3);
                encoder.encode_value(v as u16, 8);
            }
            DictionaryAddPolicy::AddFirstAndLast(v) => {
                encoder.encode_value(2, 3);
                encoder.encode_value(v as u16, 8);
            }
            DictionaryAddPolicy::AddFirstExcept4kBoundary => {
                encoder.encode_value(3, 3);
            }
            DictionaryAddPolicy::AddFirstWith32KBoundary => {
                encoder.encode_value(4, 3);
            }
        }
    }

    /// From the plain text and the preflate blocks, estimate the preflate parameters
    pub fn estimate_preflate_parameters(
        plain_text: &[u8],
        blocks: &Vec<PreflateTokenBlock>,
    ) -> Result<Self> {
        let info = extract_preflate_info(blocks);

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
        let add_policy = estimate_add_policy(blocks);

        //let hash_shift = 5;
        //let hash_mask = 32767;

        let max_token_count = (1 << (6 + mem_level)) - 1;

        let cl = estimate_preflate_comp_level(
            window_bits,
            mem_level,
            info.min_len,
            plain_text,
            add_policy,
            blocks,
        )?;

        Ok(PreflateParameters {
            predictor: TokenPredictorParameters {
                window_bits,
                very_far_matches_detected: cl.very_far_matches_detected,
                matches_to_start_detected: cl.matches_to_start_detected,
                strategy: estimate_preflate_strategy(&info),
                nice_length: cl.nice_length,
                add_policy: cl.add_policy,
                max_token_count,
                zlib_compatible: cl.zlib_compatible,
                max_dist_3_matches: cl.max_dist_3_matches,
                matching_type: cl.match_type,
                max_chain: cl.max_chain,
                min_len: cl.min_len,
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
    max_dist += preflate_constants::MIN_LOOKAHEAD;
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
        estimator::preflate_parse_config::{
            SLOW_PREFLATE_PARSER_SETTINGS, ZLIB_PREFLATE_PARSER_SETTINGS,
        },
        process::{parse_deflate, read_file},
    };

    for i in 0..=9 {
        let v = read_file(&format!("compressed_zlib_level{}.deflate", i));
        let contents = parse_deflate(&v, 1).unwrap();

        let params = PreflateParameters::estimate_preflate_parameters(
            &contents.plain_text,
            &contents.blocks,
        )
        .unwrap();

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
    use crate::process::{parse_deflate, read_file};

    for i in 0..=9 {
        let v = read_file(&format!("compressed_flate2_level{}.deflate", i));
        let contents = parse_deflate(&v, 1).unwrap();

        let params = PreflateParameters::estimate_preflate_parameters(
            &contents.plain_text,
            &contents.blocks,
        )
        .unwrap();

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
    use crate::process::{parse_deflate, read_file};

    for i in 1..=2 {
        let v = read_file(&format!("compressed_zlibng_level{}.deflate", i));
        let contents = parse_deflate(&v, 1).unwrap();

        let params = PreflateParameters::estimate_preflate_parameters(
            &contents.plain_text,
            &contents.blocks,
        )
        .unwrap();

        if i == 0 {
            assert_eq!(params.predictor.strategy, PreflateStrategy::Store);
        } else if i == 1 {
            println!("{:?}", params);
        } else {
            println!("{:?}", params);
        }
    }
}
