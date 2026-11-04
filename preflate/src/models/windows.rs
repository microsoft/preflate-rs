/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use crate::{
    estimator::PreflateStreamInfo,
    hash_algorithm::HashAlgorithm,
    hash_chain_holder::HashChainHolder,
    parameters::{DictionaryAddPolicy, LazyBehavior, MatchingType, TokenPredictorParameters},
    preflate_input::PreflateInput,
};

// Windows DEFLATE uses fixed table-XOR hashing rather than zlib's rotating hash.
pub(crate) const HASH: HashAlgorithm = HashAlgorithm::RandomVector;
pub(crate) const TRAILING_LITERALS: u32 = 2;
const LAZY_MAX_CHAIN: u32 = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Profile(pub(super) TokenPredictorParameters);

impl Profile {
    pub(super) fn parameters(self) -> TokenPredictorParameters {
        self.0
    }

    pub(super) fn parameters_mut(&mut self) -> &mut TokenPredictorParameters {
        &mut self.0
    }

    pub(super) fn alternatives(
        parameters: TokenPredictorParameters,
        info: &PreflateStreamInfo,
    ) -> [Option<Self>; 3] {
        [
            shallow_greedy_alternative(parameters, info).map(Self),
            alternative(parameters, info).map(Self),
            partial_slow_alternative(parameters, info).map(Self),
        ]
    }

    pub(super) fn without_three_byte_references(
        parameters: TokenPredictorParameters,
        info: &PreflateStreamInfo,
    ) -> Option<Self> {
        if info.min_len <= 3
            || !matches!(
                parameters.hash_algorithm,
                HashAlgorithm::Libdeflate4Fast | HashAlgorithm::ZlibNG | HashAlgorithm::Crc32cHash
            )
        {
            return None;
        }
        // A different hash's chain rank cannot constrain this coupled hypothesis.
        full_buffer_lazy(parameters, info, 258).map(Self)
    }
}

pub(crate) fn alternative(
    parameters: TokenPredictorParameters,
    info: &PreflateStreamInfo,
) -> Option<TokenPredictorParameters> {
    if parameters.hash_algorithm != HASH || parameters.max_chain > LAZY_MAX_CHAIN {
        return None;
    }
    full_buffer_lazy(parameters, info, 128)
}

fn full_buffer_lazy(
    parameters: TokenPredictorParameters,
    info: &PreflateStreamInfo,
    max_lazy: u16,
) -> Option<TokenPredictorParameters> {
    if parameters.add_policy != DictionaryAddPolicy::AddAll
        || !matches!(parameters.matching_type, MatchingType::Lazy { .. })
        || info.max_tokens_per_block < 64
        || !info.max_tokens_per_block.is_power_of_two()
    {
        return None;
    }
    Some(TokenPredictorParameters {
        hash_algorithm: HASH,
        matching_type: MatchingType::WindowsLazy { max_lazy },
        nice_length: 258,
        max_chain: LAZY_MAX_CHAIN,
        max_token_count: u16::try_from(info.max_tokens_per_block).ok()?,
        ..parameters
    })
}

pub(crate) fn partial_slow_alternative(
    parameters: TokenPredictorParameters,
    info: &PreflateStreamInfo,
) -> Option<TokenPredictorParameters> {
    if parameters.hash_algorithm != HASH
        || parameters.add_policy != DictionaryAddPolicy::AddAll
        || parameters.max_chain != LAZY_MAX_CHAIN
        || !matches!(
            parameters.matching_type,
            MatchingType::Lazy {
                filtered_matching: false,
                behavior: LazyBehavior::RecomputeAfterLiteral,
                ..
            }
        )
        || info.min_len != 3
        || info.max_dist_3_matches > super::zlib::SHORT_MATCH_CUTOFF
        || info.max_tokens_per_block < 64
        || info.max_tokens_per_block >= u32::from(parameters.max_token_count)
    {
        return None;
    }
    Some(TokenPredictorParameters {
        matching_type: MatchingType::WindowsLazy { max_lazy: 258 },
        nice_length: 258,
        very_far_matches_detected: true,
        ..parameters
    })
}

// This identifies a table-hash candidate, not the Windows-specific parser behavior.
pub(super) fn table_hash_alternative(
    parameters: TokenPredictorParameters,
    info: &PreflateStreamInfo,
) -> Option<TokenPredictorParameters> {
    if parameters.hash_algorithm != HashAlgorithm::Libdeflate4
        || !matches!(
            parameters.matching_type,
            MatchingType::LibdeflateLazy { .. }
        )
        || parameters.add_policy != DictionaryAddPolicy::AddAll
        || info.min_len != 3
        || info.max_dist_3_matches > super::zlib::SHORT_MATCH_CUTOFF
    {
        return None;
    }
    Some(TokenPredictorParameters {
        hash_algorithm: HASH,
        matching_type: MatchingType::Lazy {
            max_lazy: 16,
            filtered_matching: false,
            behavior: LazyBehavior::RecomputeAfterLiteral,
        },
        nice_length: 128,
        max_chain: 128,
        max_dist_3_matches: super::zlib::SHORT_MATCH_CUTOFF,
        ..parameters
    })
}

#[inline(always)]
pub(crate) fn literal_at_buffer_edge(
    token_count: u32,
    capacity: u32,
    has_pending_reference: bool,
) -> bool {
    token_count + 1 == capacity && !has_pending_reference
}

pub(crate) fn shallow_greedy_alternative(
    parameters: TokenPredictorParameters,
    info: &PreflateStreamInfo,
) -> Option<TokenPredictorParameters> {
    if parameters.hash_algorithm != HASH
        || parameters.add_policy != DictionaryAddPolicy::AddAll
        || parameters.max_chain == 0
        || parameters.max_chain > 8
        || !matches!(
            parameters.matching_type,
            MatchingType::Lazy {
                max_lazy: 0..=4,
                filtered_matching: false,
                ..
            }
        )
        || info.min_len != 3
        || info.max_dist_3_matches > super::zlib::SHORT_MATCH_CUTOFF
        || info.max_tokens_per_block < 64
    {
        return None;
    }
    Some(TokenPredictorParameters {
        matching_type: MatchingType::WindowsLazy { max_lazy: 0 },
        nice_length: 258,
        max_token_count: if info.max_tokens_per_block.is_power_of_two() {
            u16::try_from(info.max_tokens_per_block).ok()?
        } else {
            parameters.max_token_count
        },
        ..parameters
    })
}

pub(crate) fn predict_lazy(
    input: &PreflateInput,
    state: &dyn HashChainHolder,
    current: crate::deflate::deflate_token::DeflateTokenReference,
    max_lazy: u16,
    budget: crate::reconstruction_parameters::SearchBudget,
) -> super::MatchPrediction {
    // Keep the deferred reference as a token-buffer marker; prediction searches again.
    super::zlib::predict_lazy(
        input,
        state,
        current,
        crate::reconstruction_parameters::LazyLookaheadSettings {
            max_lazy,
            behavior: LazyBehavior::Zlib { good_length: 258 },
        },
        budget,
    )
}

#[test]
fn buffer_edge_literal_requires_an_unused_deferred_match_slot() {
    for (count, capacity, pending, expected) in [
        (0, 128, false, false),
        (126, 128, false, false),
        (127, 128, false, true),
        (127, 128, true, false),
        (128, 128, false, false),
        (0, 1, false, true),
    ] {
        assert_eq!(
            literal_at_buffer_edge(count, capacity, pending),
            expected,
            "count={count}, capacity={capacity}, pending={pending}"
        );
    }
}

#[test]
fn table_hash_alternative_requires_compatible_observed_short_references() {
    let base = TokenPredictorParameters {
        hash_algorithm: HashAlgorithm::Libdeflate4,
        matching_type: MatchingType::LibdeflateLazy {
            two_positions: true,
        },
        add_policy: DictionaryAddPolicy::AddAll,
        max_dist_3_matches: 8192,
        ..crate::token_predictor::zlib_level_1_params()
    };
    let mut info = crate::estimator::extract_preflate_info(&[]);
    info.min_len = 3;
    info.max_dist_3_matches = 4096;
    let candidate = table_hash_alternative(base, &info).unwrap();
    assert_eq!(candidate.hash_algorithm, HASH);
    assert_eq!(candidate.max_dist_3_matches, 4096);
    assert_eq!(candidate.max_token_count, base.max_token_count);
    assert_eq!(
        candidate.matches_to_start_detected,
        base.matches_to_start_detected
    );
    for incompatible in [
        TokenPredictorParameters {
            hash_algorithm: HASH,
            ..base
        },
        TokenPredictorParameters {
            matching_type: MatchingType::Greedy,
            ..base
        },
        TokenPredictorParameters {
            add_policy: DictionaryAddPolicy::AddFirst(6),
            ..base
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
    let base = TokenPredictorParameters {
        hash_algorithm: HashAlgorithm::Libdeflate4Fast,
        add_policy: DictionaryAddPolicy::AddAll,
        matching_type: MatchingType::Lazy {
            max_lazy: 16,
            filtered_matching: false,
            behavior: LazyBehavior::RecomputeAfterLiteral,
        },
        nice_length: 128,
        max_chain: 99,
        max_token_count: 32767,
        max_dist_3_matches: 0,
        ..crate::token_predictor::zlib_level_1_params()
    };
    let mut info = crate::estimator::extract_preflate_info(&[]);
    info.max_tokens_per_block = 16384;
    for minimum in [4, 5, 6, 258] {
        info.min_len = minimum;
        for hash in [
            HashAlgorithm::Libdeflate4Fast,
            HashAlgorithm::ZlibNG,
            HashAlgorithm::Crc32cHash,
        ] {
            for depth in [1, 99, 100, 4096] {
                let candidate = Profile::without_three_byte_references(
                    TokenPredictorParameters {
                        hash_algorithm: hash,
                        max_chain: depth,
                        ..base
                    },
                    &info,
                )
                .unwrap();
                let candidate = candidate.parameters();
                assert_eq!(
                    candidate,
                    TokenPredictorParameters {
                        hash_algorithm: HASH,
                        matching_type: MatchingType::WindowsLazy { max_lazy: 258 },
                        nice_length: 258,
                        max_chain: 100,
                        max_token_count: 16384,
                        ..base
                    }
                );
            }
        }
    }
    for minimum in [0, 3] {
        info.min_len = minimum;
        assert!(Profile::without_three_byte_references(base, &info).is_none());
    }
    info.min_len = 5;
    for incompatible in [
        TokenPredictorParameters {
            hash_algorithm: HASH,
            ..base
        },
        TokenPredictorParameters {
            hash_algorithm: super::zlib::DEFAULT_HASH,
            ..base
        },
        TokenPredictorParameters {
            hash_algorithm: HashAlgorithm::Libdeflate4Fast15,
            ..base
        },
        TokenPredictorParameters {
            add_policy: DictionaryAddPolicy::AddFirst(4),
            ..base
        },
        TokenPredictorParameters {
            matching_type: MatchingType::Greedy,
            ..base
        },
        TokenPredictorParameters {
            matching_type: MatchingType::LibdeflateLazy {
                two_positions: true,
            },
            ..base
        },
    ] {
        assert!(Profile::without_three_byte_references(incompatible, &info).is_none());
    }
    for capacity in [0, 63, 16383, 16385, 65536] {
        info.max_tokens_per_block = capacity;
        assert!(Profile::without_three_byte_references(base, &info).is_none());
    }
}

#[test]
fn partial_slow_alternative_keeps_the_unobserved_buffer_capacity() {
    let parameters = TokenPredictorParameters {
        hash_algorithm: HASH,
        add_policy: DictionaryAddPolicy::AddAll,
        matching_type: MatchingType::Lazy {
            max_lazy: 16,
            filtered_matching: false,
            behavior: LazyBehavior::RecomputeAfterLiteral,
        },
        max_chain: 100,
        max_token_count: 8191,
        max_dist_3_matches: 4000,
        ..crate::token_predictor::zlib_level_1_params()
    };
    let mut info = crate::estimator::extract_preflate_info(&[]);
    info.min_len = 3;
    info.max_dist_3_matches = 4000;
    info.max_tokens_per_block = 6494;
    let result = partial_slow_alternative(parameters, &info).unwrap();
    assert_eq!(result.max_token_count, 8191);
    assert_eq!(result.max_dist_3_matches, parameters.max_dist_3_matches);
    assert_eq!(
        result.matching_type,
        MatchingType::WindowsLazy { max_lazy: 258 }
    );
    assert!(result.very_far_matches_detected);
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
    let base = TokenPredictorParameters {
        hash_algorithm: HASH,
        add_policy: DictionaryAddPolicy::AddAll,
        matching_type: MatchingType::Lazy {
            max_lazy: 4,
            filtered_matching: false,
            behavior: LazyBehavior::Zlib { good_length: 4 },
        },
        nice_length: 16,
        max_chain: 5,
        ..crate::token_predictor::zlib_level_1_params()
    };
    let mut info = crate::estimator::extract_preflate_info(&[]);
    info.min_len = 3;
    info.max_dist_3_matches = 4096;
    info.max_tokens_per_block = 128;
    let expected = TokenPredictorParameters {
        matching_type: MatchingType::WindowsLazy { max_lazy: 0 },
        nice_length: 258,
        max_token_count: 128,
        ..base
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
                TokenPredictorParameters {
                    max_chain: depth,
                    ..base
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
    let parameters = TokenPredictorParameters {
        hash_algorithm: HASH,
        add_policy: DictionaryAddPolicy::AddAll,
        matching_type: MatchingType::Lazy {
            max_lazy: 16,
            filtered_matching: false,
            behavior: LazyBehavior::RecomputeAfterLiteral,
        },
        max_chain: 100,
        ..crate::token_predictor::zlib_level_1_params()
    };
    let mut info = crate::estimator::extract_preflate_info(&[]);
    for count in [0, 63, 16383, 16385, 65536] {
        info.max_tokens_per_block = count;
        assert!(alternative(parameters, &info).is_none());
    }
    info.max_tokens_per_block = 16384;
    let candidate = alternative(parameters, &info).unwrap();
    assert_eq!(candidate.max_token_count, 16384);
    assert_eq!(
        candidate.matching_type,
        MatchingType::WindowsLazy { max_lazy: 128 }
    );
    for incompatible in [
        TokenPredictorParameters {
            hash_algorithm: HashAlgorithm::MiniZFast,
            ..parameters
        },
        TokenPredictorParameters {
            add_policy: DictionaryAddPolicy::AddFirst(4),
            ..parameters
        },
        TokenPredictorParameters {
            matching_type: MatchingType::Greedy,
            ..parameters
        },
        TokenPredictorParameters {
            max_chain: 101,
            ..parameters
        },
    ] {
        assert!(alternative(incompatible, &info).is_none());
    }
}
