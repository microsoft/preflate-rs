/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use anyhow::Result;

use crate::{
    add_policy_estimator::estimate_add_policy,
    bit_helper::bit_length,
    complevel_estimator::estimate_preflate_comp_level,
    hash_algorithm::HashAlgorithm,
    hash_chain::DictionaryAddPolicy,
    preflate_constants::{self},
    preflate_parse_config::MatchingType,
    preflate_stream_info::{extract_preflate_info, PreflateStreamInfo},
    preflate_token::PreflateTokenBlock,
    statistical_codec::{PredictionDecoder, PredictionEncoder},
    token_predictor::TokenPredictorParameters,
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

const HASH_ALGORITHM_NONE: u16 = 0;
const HASH_ALGORITHM_ZLIB: u16 = 1;
const HASH_ALGORITHM_MINIZ_FAST: u16 = 2;
const HASH_ALGORITHM_LIBDEFLATE4: u16 = 3;
const HASH_ALGORITHM_LIBDEFLATE4_FAST: u16 = 4;
const HASH_ALGORITHM_ZLIBNG: u16 = 5;
const HASH_ALGORITHM_RANDOMVECTOR: u16 = 6;
const HASH_ALGORITHM_CRC32C: u16 = 7;

impl PreflateParameters {
    pub fn read(decoder: &mut impl PredictionDecoder) -> Result<Self> {
        assert_eq!(FILE_VERSION, decoder.decode_value(8));
        let strategy = decoder.decode_value(4);
        let huff_strategy = decoder.decode_value(4);
        let zlib_compatible = decoder.decode_value(1) != 0;
        let window_bits = decoder.decode_value(8);
        let hash_algorithm = decoder.decode_value(4);

        let hash_shift;
        let hash_mask;
        if hash_algorithm == HASH_ALGORITHM_ZLIB {
            hash_shift = decoder.decode_value(8);
            hash_mask = decoder.decode_value(16);
        } else {
            hash_shift = 0;
            hash_mask = 0;
        }

        let max_token_count = decoder.decode_value(16);
        let max_dist_3_matches = decoder.decode_value(16);
        let very_far_matches_detected = decoder.decode_value(1) != 0;
        let matches_to_start_detected = decoder.decode_value(1) != 0;
        let good_length = decoder.decode_value(16);
        let max_lazy = decoder.decode_value(16);
        let nice_length = decoder.decode_value(16);
        let max_chain = decoder.decode_value(16);
        let min_len = decoder.decode_value(16);

        let add_policy = match decoder.decode_value(2) {
            0 => DictionaryAddPolicy::AddAll,
            1 => DictionaryAddPolicy::AddFirst(decoder.decode_value(8)),
            2 => DictionaryAddPolicy::AddFirstAndLast(decoder.decode_value(8)),
            3 => DictionaryAddPolicy::AddFirstExcept4kBoundary,
            _ => panic!("invalid add policy"),
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
                    _ => panic!("invalid strategy"),
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
                    HASH_ALGORITHM_NONE => HashAlgorithm::None,
                    HASH_ALGORITHM_ZLIB => HashAlgorithm::Zlib {
                        hash_shift: hash_shift.into(),
                        hash_mask,
                    },
                    HASH_ALGORITHM_MINIZ_FAST => HashAlgorithm::MiniZFast,
                    HASH_ALGORITHM_LIBDEFLATE4 => HashAlgorithm::Libdeflate4,
                    HASH_ALGORITHM_LIBDEFLATE4_FAST => HashAlgorithm::Libdeflate4Fast,
                    HASH_ALGORITHM_ZLIBNG => HashAlgorithm::ZlibNG,
                    HASH_ALGORITHM_RANDOMVECTOR => HashAlgorithm::RandomVector,
                    HASH_ALGORITHM_CRC32C => HashAlgorithm::Crc32cHash,
                    _ => panic!("invalid hash algorithm"),
                },
            },
            huff_strategy: match huff_strategy {
                HUFF_STRATEGY_DYNAMIC => PreflateHuffStrategy::Dynamic,
                HUFF_STRATEGY_MIXED => PreflateHuffStrategy::Mixed,
                HUFF_STRATEGY_STATIC => PreflateHuffStrategy::Static,
                _ => panic!("invalid huff strategy"),
            },
        })
    }

    pub fn write<E: PredictionEncoder>(&self, encoder: &mut E) {
        encoder.encode_value(FILE_VERSION, 8);
        encoder.encode_value(self.predictor.strategy as u16, 4);
        encoder.encode_value(self.huff_strategy as u16, 4);
        encoder.encode_value(u16::from(self.predictor.zlib_compatible), 1);
        encoder.encode_value(u16::try_from(self.predictor.window_bits).unwrap(), 8);

        match self.predictor.hash_algorithm {
            HashAlgorithm::None => {
                encoder.encode_value(HASH_ALGORITHM_NONE, 4);
            }
            HashAlgorithm::Zlib {
                hash_shift,
                hash_mask,
            } => {
                encoder.encode_value(HASH_ALGORITHM_ZLIB, 4);
                encoder.encode_value(u16::try_from(hash_shift).unwrap(), 8);
                encoder.encode_value(hash_mask, 16);
            }
            HashAlgorithm::MiniZFast => {
                encoder.encode_value(HASH_ALGORITHM_MINIZ_FAST, 4);
            }
            HashAlgorithm::Libdeflate4Fast => {
                encoder.encode_value(HASH_ALGORITHM_LIBDEFLATE4, 4);
            }
            HashAlgorithm::Libdeflate4 => {
                encoder.encode_value(HASH_ALGORITHM_LIBDEFLATE4, 4);
            }
            HashAlgorithm::ZlibNG => {
                encoder.encode_value(HASH_ALGORITHM_ZLIBNG, 4);
            }
            HashAlgorithm::RandomVector => {
                encoder.encode_value(HASH_ALGORITHM_RANDOMVECTOR, 4);
            }
            HashAlgorithm::Crc32cHash => {
                encoder.encode_value(HASH_ALGORITHM_CRC32C, 4);
            }
        }

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
            DictionaryAddPolicy::AddAll => encoder.encode_value(0, 2),
            DictionaryAddPolicy::AddFirst(v) => {
                encoder.encode_value(1, 2);
                encoder.encode_value(v as u16, 8);
            }
            DictionaryAddPolicy::AddFirstAndLast(v) => {
                encoder.encode_value(2, 2);
                encoder.encode_value(v as u16, 8);
            }
            DictionaryAddPolicy::AddFirstExcept4kBoundary => {
                encoder.encode_value(3, 2);
            }
        }
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
) -> anyhow::Result<PreflateParameters> {
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
        unpacked_output,
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

#[test]
fn verify_zlib_recognition() {
    use crate::{
        preflate_parse_config::{SLOW_PREFLATE_PARSER_SETTINGS, ZLIB_PREFLATE_PARSER_SETTINGS},
        process::{parse_deflate, read_file},
    };

    for i in 0..=9 {
        let v = read_file(&format!("compressed_zlib_level{}.deflate", i));
        let contents = parse_deflate(&v, 1).unwrap();

        let params = estimate_preflate_parameters(&contents.plain_text, &contents.blocks).unwrap();

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

        let params = estimate_preflate_parameters(&contents.plain_text, &contents.blocks).unwrap();

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

        let params = estimate_preflate_parameters(&contents.plain_text, &contents.blocks).unwrap();

        if i == 0 {
            assert_eq!(params.predictor.strategy, PreflateStrategy::Store);
        } else if i == 1 {
            println!("{:?}", params);
        } else {
            println!("{:?}", params);
        }
    }
}
