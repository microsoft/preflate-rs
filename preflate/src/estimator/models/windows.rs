//! Windows DEFLATE recognition and candidate profile construction.
//! Couples table hashing and search budgets with observed token-buffer limits;
//! runtime lazy matching and buffer-edge decisions live in `compressors::windows`.

use crate::reconstruction_parameters::{ChainParser, LazyLookaheadSettings, LazyMinimum};
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
use crate::{
    compressors::windows::HASH,
    estimator::preflate_stream_info::PreflateStreamInfo,
    hash_algorithm::HashAlgorithm,
    parameters::{DictionaryAddPolicy, LazyBehavior},
    reconstruction_parameters::ReconstructionParameters,
};

const LAZY_MAX_CHAIN: u32 = 100;

pub fn alternatives(
    parameters: ReconstructionParameters,
    info: &PreflateStreamInfo,
) -> [Option<ReconstructionParameters>; 3] {
    [
        shallow_greedy_alternative(parameters, info),
        alternative(parameters, info),
        partial_slow_alternative(parameters, info),
    ]
}

pub fn without_three_byte_references(
    parameters: ReconstructionParameters,
    info: &PreflateStreamInfo,
) -> Option<ReconstructionParameters> {
    if info.min_len <= 3
        || !matches!(
            parameters.hash_algorithm(),
            HashAlgorithm::Libdeflate4Fast | HashAlgorithm::ZlibNG | HashAlgorithm::Crc32cHash
        )
    {
        return None;
    }
    // A different hash's chain rank cannot constrain this coupled hypothesis.
    full_buffer_lazy(parameters, info, 258)
}
pub fn alternative(
    parameters: ReconstructionParameters,
    info: &PreflateStreamInfo,
) -> Option<ReconstructionParameters> {
    if parameters.hash_algorithm() != HASH
        || parameters.budget().expect("dictionary candidate").max_chain > LAZY_MAX_CHAIN
    {
        return None;
    }
    full_buffer_lazy(parameters, info, 128)
}

fn full_buffer_lazy(
    parameters: ReconstructionParameters,
    info: &PreflateStreamInfo,
    max_lazy: u16,
) -> Option<ReconstructionParameters> {
    if parameters
        .dictionary()
        .expect("dictionary candidate")
        .insertion
        != DictionaryAddPolicy::AddAll
        || !matches!(parameters.chain_parser(), Some(ChainParser::Lazy { .. }))
        || info.max_tokens_per_block < 64
        || !info.max_tokens_per_block.is_power_of_two()
    {
        return None;
    }
    Some({
        let mut canonical_configuration = parameters;
        canonical_configuration.replace_chain_parser(ChainParser::WindowsLazy {
            max_lazy,
            short_match_cutoff: canonical_configuration.behavior.short_match_cutoff(),
        });
        canonical_configuration.set_estimated_hash(HASH);
        canonical_configuration
            .chain_common_mut()
            .expect("chain candidate")
            .search
            .nice_length = 258;
        canonical_configuration
            .budget_mut()
            .expect("dictionary candidate")
            .max_chain = LAZY_MAX_CHAIN;

        canonical_configuration.max_token_count = u16::try_from(info.max_tokens_per_block).ok()?;
        canonical_configuration
    })
}

pub fn partial_slow_alternative(
    parameters: ReconstructionParameters,
    info: &PreflateStreamInfo,
) -> Option<ReconstructionParameters> {
    if parameters.hash_algorithm() != HASH
        || parameters
            .dictionary()
            .expect("dictionary candidate")
            .insertion
            != DictionaryAddPolicy::AddAll
        || parameters.budget().expect("dictionary candidate").max_chain != LAZY_MAX_CHAIN
        || !matches!(
            parameters.chain_parser(),
            Some(ChainParser::Lazy {
                lookahead: LazyLookaheadSettings {
                    behavior: LazyBehavior::RecomputeAfterLiteral,
                    ..
                },
                minimum: LazyMinimum::Three { .. },
                ..
            })
        )
        || info.min_len != 3
        || info.max_dist_3_matches > crate::compressors::zlib::SHORT_MATCH_CUTOFF
        || info.max_tokens_per_block < 64
        || info.max_tokens_per_block >= u32::from(parameters.max_token_count)
    {
        return None;
    }
    Some({
        let mut canonical_configuration = parameters;
        canonical_configuration.replace_chain_parser(ChainParser::WindowsLazy {
            max_lazy: 258,
            short_match_cutoff: canonical_configuration.behavior.short_match_cutoff(),
        });
        canonical_configuration.behavior.set_full_window(true);
        canonical_configuration
            .chain_common_mut()
            .expect("chain candidate")
            .search
            .nice_length = 258;

        canonical_configuration
    })
}

// This identifies a table-hash candidate, not the Windows-specific parser behavior.
pub fn table_hash_alternative(
    parameters: ReconstructionParameters,
    info: &PreflateStreamInfo,
) -> Option<ReconstructionParameters> {
    if parameters.hash_algorithm() != HashAlgorithm::Libdeflate4
        || !matches!(
            parameters.chain_parser(),
            Some(ChainParser::LibdeflateLazy { .. })
        )
        || parameters
            .dictionary()
            .expect("dictionary candidate")
            .insertion
            != DictionaryAddPolicy::AddAll
        || info.min_len != 3
        || info.max_dist_3_matches > crate::compressors::zlib::SHORT_MATCH_CUTOFF
    {
        return None;
    }
    Some({
        let mut canonical_configuration = parameters;
        canonical_configuration.replace_chain_parser(ChainParser::Lazy {
            lookahead: LazyLookaheadSettings {
                max_lazy: 16,
                behavior: LazyBehavior::RecomputeAfterLiteral,
            },
            minimum: LazyMinimum::Three {
                short_match_cutoff: canonical_configuration.behavior.short_match_cutoff(),
            },
        });
        canonical_configuration.set_estimated_hash(HASH);
        canonical_configuration
            .chain_common_mut()
            .expect("chain candidate")
            .search
            .nice_length = 128;
        canonical_configuration
            .budget_mut()
            .expect("dictionary candidate")
            .max_chain = 128;
        canonical_configuration
            .behavior
            .set_short_match_cutoff(crate::compressors::zlib::SHORT_MATCH_CUTOFF);

        canonical_configuration
    })
}

pub fn shallow_greedy_alternative(
    parameters: ReconstructionParameters,
    info: &PreflateStreamInfo,
) -> Option<ReconstructionParameters> {
    if parameters.hash_algorithm() != HASH
        || parameters
            .dictionary()
            .expect("dictionary candidate")
            .insertion
            != DictionaryAddPolicy::AddAll
        || parameters.budget().expect("dictionary candidate").max_chain == 0
        || parameters.budget().expect("dictionary candidate").max_chain > 8
        || !matches!(
            parameters.chain_parser(),
            Some(ChainParser::Lazy {
                lookahead: LazyLookaheadSettings {
                    max_lazy: 0..=4,
                    ..
                },
                minimum: LazyMinimum::Three { .. },
                ..
            })
        )
        || info.min_len != 3
        || info.max_dist_3_matches > crate::compressors::zlib::SHORT_MATCH_CUTOFF
        || info.max_tokens_per_block < 64
    {
        return None;
    }
    Some({
        let mut canonical_configuration = parameters;
        canonical_configuration.replace_chain_parser(ChainParser::WindowsLazy {
            max_lazy: 0,
            short_match_cutoff: canonical_configuration.behavior.short_match_cutoff(),
        });
        canonical_configuration
            .chain_common_mut()
            .expect("chain candidate")
            .search
            .nice_length = 258;

        canonical_configuration.max_token_count = if info.max_tokens_per_block.is_power_of_two() {
            u16::try_from(info.max_tokens_per_block).ok()?
        } else {
            parameters.max_token_count
        };
        canonical_configuration
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameters::tests::MatchingType;

    #[test]
    fn table_hash_alternative_requires_compatible_observed_short_references() {
        let base = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_short_match_cutoff(8192);
            canonical_configuration.set_matching_type(MatchingType::LibdeflateLazy {
                two_positions: true,
            });
            canonical_configuration
        };
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
        info.min_len = 3;
        info.max_dist_3_matches = 4096;
        let candidate = table_hash_alternative(base, &info).unwrap();
        assert_eq!(candidate.hash_algorithm(), HASH);
        assert_eq!(candidate.max_dist_3_matches(), 4096);
        assert_eq!(candidate.max_token_count, base.max_token_count);
        assert_eq!(
            candidate.matches_to_start_detected(),
            base.matches_to_start_detected()
        );
        for incompatible in [
            {
                let mut canonical_configuration = base;
                canonical_configuration.set_hash_algorithm(HASH);
                canonical_configuration
            },
            {
                let mut canonical_configuration = base;
                canonical_configuration.set_matching_type(MatchingType::Greedy);
                canonical_configuration
            },
            {
                let mut canonical_configuration = base;
                canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(6));
                canonical_configuration
            },
        ] {
            assert!(table_hash_alternative(incompatible, &info).is_none());
        }
        info.max_dist_3_matches = 4097;
        assert!(table_hash_alternative(base, &info).is_none());
        info.max_dist_3_matches = 0;
        info.min_len = 6;
        assert!(table_hash_alternative(base, &info).is_none());
    }

    #[test]
    fn no_short_match_profile_keeps_hash_parser_and_budget_coupled() {
        let base = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4Fast);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_nice_length(128);
            canonical_configuration.set_max_chain(99);
            canonical_configuration.set_short_match_cutoff(0);
            canonical_configuration.set_matching_type(MatchingType::Lazy {
                max_lazy: 16,
                filtered_matching: false,
                behavior: LazyBehavior::RecomputeAfterLiteral,
            });
            canonical_configuration.max_token_count = 32767;
            canonical_configuration
        };
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
        info.max_tokens_per_block = 16384;
        for minimum in [4, 5, 6, 258] {
            info.min_len = minimum;
            for hash in [
                HashAlgorithm::Libdeflate4Fast,
                HashAlgorithm::ZlibNG,
                HashAlgorithm::Crc32cHash,
            ] {
                for depth in [1, 99, 100, 4096] {
                    let candidate = without_three_byte_references(
                        {
                            let mut canonical_configuration = base;
                            canonical_configuration.set_hash_algorithm(hash);
                            canonical_configuration.set_max_chain(depth);
                            canonical_configuration
                        },
                        &info,
                    )
                    .unwrap();
                    assert_eq!(candidate, {
                        let mut canonical_configuration = base;
                        canonical_configuration.set_hash_algorithm(HASH);
                        canonical_configuration.set_nice_length(258);
                        canonical_configuration.set_max_chain(100);
                        canonical_configuration
                            .set_matching_type(MatchingType::WindowsLazy { max_lazy: 258 });
                        canonical_configuration.max_token_count = 16384;
                        canonical_configuration
                    });
                }
            }
        }
        for minimum in [0, 3] {
            info.min_len = minimum;
            assert!(without_three_byte_references(base, &info).is_none());
        }
        info.min_len = 5;
        for incompatible in [
            {
                let mut canonical_configuration = base;
                canonical_configuration.set_hash_algorithm(HASH);
                canonical_configuration
            },
            {
                let mut canonical_configuration = base;
                canonical_configuration.set_hash_algorithm(crate::compressors::zlib::DEFAULT_HASH);
                canonical_configuration
            },
            {
                let mut canonical_configuration = base;
                canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4Fast15);
                canonical_configuration
            },
            {
                let mut canonical_configuration = base;
                canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(4));
                canonical_configuration
            },
            {
                let mut canonical_configuration = base;
                canonical_configuration.set_matching_type(MatchingType::Greedy);
                canonical_configuration
            },
            {
                let mut canonical_configuration = base;
                canonical_configuration.set_matching_type(MatchingType::LibdeflateLazy {
                    two_positions: true,
                });
                canonical_configuration
            },
        ] {
            assert!(without_three_byte_references(incompatible, &info).is_none());
        }
        for capacity in [0, 63, 16383, 16385, 65536] {
            info.max_tokens_per_block = capacity;
            assert!(without_three_byte_references(base, &info).is_none());
        }
    }

    #[test]
    fn partial_slow_alternative_keeps_the_unobserved_buffer_capacity() {
        let parameters = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(HASH);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_max_chain(100);
            canonical_configuration.set_short_match_cutoff(4000);
            canonical_configuration.set_matching_type(MatchingType::Lazy {
                max_lazy: 16,
                filtered_matching: false,
                behavior: LazyBehavior::RecomputeAfterLiteral,
            });
            canonical_configuration.max_token_count = 8191;
            canonical_configuration
        };
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
        info.min_len = 3;
        info.max_dist_3_matches = 4000;
        info.max_tokens_per_block = 6494;
        let result = partial_slow_alternative(parameters, &info).unwrap();
        assert_eq!(result.max_token_count, 8191);
        assert_eq!(result.max_dist_3_matches(), parameters.max_dist_3_matches());
        assert_eq!(
            result.matching_type(),
            MatchingType::WindowsLazy { max_lazy: 258 }
        );
        assert!(result.very_far_matches_detected());
        for count in [0, 63, 8191, 8192] {
            info.max_tokens_per_block = count;
            assert!(partial_slow_alternative(parameters, &info).is_none());
        }
        info.max_tokens_per_block = 6494;
        info.max_dist_3_matches = 4097;
        assert!(partial_slow_alternative(parameters, &info).is_none());
    }

    #[test]
    fn shallow_greedy_alternative_preserves_observed_search_depth() {
        let base = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(HASH);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_nice_length(16);
            canonical_configuration.set_max_chain(5);
            canonical_configuration.set_matching_type(MatchingType::Lazy {
                max_lazy: 4,
                filtered_matching: false,
                behavior: LazyBehavior::Zlib { good_length: 4 },
            });
            canonical_configuration
        };
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
        info.min_len = 3;
        info.max_dist_3_matches = 4096;
        info.max_tokens_per_block = 128;
        let expected = {
            let mut canonical_configuration = base;
            canonical_configuration.set_nice_length(258);
            canonical_configuration.set_matching_type(MatchingType::WindowsLazy { max_lazy: 0 });
            canonical_configuration.max_token_count = 128;
            canonical_configuration
        };
        assert_eq!(shallow_greedy_alternative(base, &info), Some(expected));
        info.max_tokens_per_block = 100;
        assert_eq!(
            shallow_greedy_alternative(base, &info)
                .unwrap()
                .max_token_count,
            base.max_token_count
        );
        for depth in [0, 9, 100] {
            assert!(
                shallow_greedy_alternative(
                    {
                        let mut canonical_configuration = base;
                        canonical_configuration.set_max_chain(depth);
                        canonical_configuration
                    },
                    &info
                )
                .is_none()
            );
        }
        info.min_len = 4;
        assert!(shallow_greedy_alternative(base, &info).is_none());
        info.min_len = 3;
        info.max_dist_3_matches = 4097;
        assert!(shallow_greedy_alternative(base, &info).is_none());
    }

    #[test]
    fn lazy_alternative_requires_table_hash_and_a_full_token_buffer() {
        let parameters = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(HASH);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_max_chain(100);
            canonical_configuration.set_matching_type(MatchingType::Lazy {
                max_lazy: 16,
                filtered_matching: false,
                behavior: LazyBehavior::RecomputeAfterLiteral,
            });
            canonical_configuration
        };
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
        for count in [0, 63, 16383, 16385, 65536] {
            info.max_tokens_per_block = count;
            assert!(alternative(parameters, &info).is_none());
        }
        info.max_tokens_per_block = 16384;
        let candidate = alternative(parameters, &info).unwrap();
        assert_eq!(candidate.max_token_count, 16384);
        assert_eq!(
            candidate.matching_type(),
            MatchingType::WindowsLazy { max_lazy: 128 }
        );
        for incompatible in [
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_hash_algorithm(HashAlgorithm::MiniZFast);
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(4));
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_matching_type(MatchingType::Greedy);
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_max_chain(101);
                canonical_configuration
            },
        ] {
            assert!(alternative(incompatible, &info).is_none());
        }
    }
}
