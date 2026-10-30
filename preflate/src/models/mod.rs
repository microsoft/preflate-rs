/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Family policy and parsing behavior shared by estimation and reconstruction.
//! A hash signature alone does not establish a compressor or parser identity.

pub(crate) mod chromium;
pub(crate) mod generic;
pub(crate) mod libdeflate;
pub(crate) mod miniz;
pub(crate) mod windows;
pub(crate) mod zlib;
pub(crate) mod zlib_ng;

use crate::hash_algorithm::HashAlgorithm;

use crate::estimator::{
    CandidateEvidence, ParserEvidencePolicy, PreflateStreamInfo,
    add_policy_estimator::DictionaryAddPolicy,
    preflate_parameter_estimator::TokenPredictorParameters,
};

pub(crate) enum MatchPrediction {
    Reference,
    Literal {
        pending_reference: Option<crate::deflate::deflate_token::DeflateTokenReference>,
        pending_literals: u8,
    },
}

pub(crate) fn block_minimum_match_length(
    parameters: &TokenPredictorParameters,
    filtered_matching: bool,
    bytes: &[u8],
) -> u32 {
    use crate::estimator::preflate_parse_config::MatchingType;
    if parameters.matching_type == MatchingType::LibdeflateGreedy
        || filtered_matching
            && matches!(
                parameters.matching_type,
                MatchingType::LibdeflateLazy { .. }
            )
    {
        libdeflate::minimum_match_length(bytes, parameters.max_chain.saturating_sub(1))
    } else if filtered_matching
        && matches!(
            parameters.matching_type,
            MatchingType::Lazy {
                filtered_matching: true,
                ..
            }
        )
    {
        zlib::FILTERED_MIN_MATCH_LENGTH
    } else {
        crate::deflate::deflate_constants::MIN_MATCH
    }
}

pub(crate) fn candidate_hashes(
    mem_level: u32,
    info: &PreflateStreamInfo,
    add_policy: DictionaryAddPolicy,
) -> impl Iterator<Item = HashAlgorithm> {
    let primary = if info.min_len == 3 {
        [miniz::FAST_HASH, libdeflate::CHAIN_HASH, windows::HASH]
    } else {
        let [multiplicative, crc] = zlib_ng::HASHES;
        [libdeflate::fast_hash(add_policy), multiplicative, crc]
    };
    let mut alternates = zlib::candidate_hashes(mem_level);
    chromium::substitute_candidate(&mut alternates, &info.chromium_short_matches);
    primary.into_iter().chain(alternates.into_iter().flatten())
}

pub(crate) fn chain_add_policy(
    hash: HashAlgorithm,
    policy: DictionaryAddPolicy,
    longest_match: u32,
) -> DictionaryAddPolicy {
    chromium::add_policy(
        hash,
        libdeflate::chain_add_policy(hash, policy, longest_match),
        longest_match,
    )
}

pub(crate) fn evidence_policy(hash: HashAlgorithm) -> ParserEvidencePolicy {
    match hash {
        HashAlgorithm::Libdeflate4 => libdeflate::evidence_policy(),
        _ => ParserEvidencePolicy::default(),
    }
}

pub(crate) fn fingerprint(
    parameters: TokenPredictorParameters,
    evidence: &CandidateEvidence,
) -> Option<TokenPredictorParameters> {
    match evidence.hash_algorithm {
        HashAlgorithm::Zlib { .. } => miniz::fingerprint(parameters, evidence),
        HashAlgorithm::Libdeflate4
        | HashAlgorithm::Libdeflate4Fast
        | HashAlgorithm::Libdeflate4Fast15 => libdeflate::fingerprint(parameters, evidence),
        _ => None,
    }
}

#[test]
fn candidate_order_and_duplicate_suppression_preserve_ambiguous_searches() {
    use crate::estimator::extract_preflate_info;

    for (memory_level, expected_zlib) in [
        (
            1,
            vec![
                HashAlgorithm::Zlib {
                    hash_mask: 255,
                    hash_shift: 3,
                },
                HashAlgorithm::Zlib {
                    hash_mask: 32767,
                    hash_shift: 5,
                },
                HashAlgorithm::Zlib {
                    hash_mask: 2047,
                    hash_shift: 4,
                },
            ],
        ),
        (
            4,
            vec![
                HashAlgorithm::Zlib {
                    hash_mask: 2047,
                    hash_shift: 4,
                },
                HashAlgorithm::Zlib {
                    hash_mask: 32767,
                    hash_shift: 5,
                },
            ],
        ),
        (
            8,
            vec![
                HashAlgorithm::Zlib {
                    hash_mask: 32767,
                    hash_shift: 5,
                },
                HashAlgorithm::Zlib {
                    hash_mask: 2047,
                    hash_shift: 4,
                },
            ],
        ),
    ] {
        for minimum in [3, 4] {
            for insertion in [
                DictionaryAddPolicy::AddAll,
                DictionaryAddPolicy::AddFirst(4),
            ] {
                let mut info = extract_preflate_info(&[]);
                info.min_len = minimum;
                let mut expected = if minimum == 3 {
                    vec![
                        HashAlgorithm::MiniZFast,
                        HashAlgorithm::Libdeflate4,
                        HashAlgorithm::RandomVector,
                    ]
                } else {
                    vec![
                        if insertion == DictionaryAddPolicy::AddAll {
                            HashAlgorithm::Libdeflate4Fast15
                        } else {
                            HashAlgorithm::Libdeflate4Fast
                        },
                        HashAlgorithm::ZlibNG,
                        HashAlgorithm::Crc32cHash,
                    ]
                };
                expected.extend_from_slice(&expected_zlib);
                assert_eq!(
                    candidate_hashes(memory_level, &info, insertion).collect::<Vec<_>>(),
                    expected,
                    "memory={memory_level}, minimum={minimum}, insertion={insertion:?}"
                );
            }
        }
    }
}
