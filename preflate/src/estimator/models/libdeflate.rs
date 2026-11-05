//! Libdeflate recognition and complete greedy/lazy candidate settings.
//!
//! The chained matcher combines a four-byte primary chain with a three-byte
//! secondary candidate. Greedy and lazy parsers differ in minimum-match rules,
//! equal-length distance preferences, and the number of lookahead positions.
//!
//! Observed hashes, insertion cutoffs, and parser evidence select compatible
//! settings without changing the existing search-depth bounds. Runtime minimum
//! lengths, lookahead decisions, and search restrictions live in
//! `compressors::libdeflate` and consume only those executable settings.

use crate::reconstruction_parameters::ChainParser;
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
use crate::{
    compressors::libdeflate::CHAIN_HASH,
    estimator::{
        complevel_estimator::CandidateEvidence,
        depth_estimator::DistancePolicy,
        evidence_policy::ParserEvidencePolicy,
        initial_estimate::InitialEstimate,
        parser_estimator::{InsertionConstraint, ParserInference},
        preflate_stream_info::PreflateStreamInfo,
    },
    hash_algorithm::HashAlgorithm,
    parameters::DictionaryAddPolicy,
    reconstruction_parameters::ReconstructionParameters,
};

pub fn chain_add_policy(
    hash: HashAlgorithm,
    add_policy: DictionaryAddPolicy,
    longest_match: u32,
) -> DictionaryAddPolicy {
    if hash == CHAIN_HASH
        && InsertionConstraint::observe(add_policy, longest_match)
            == InsertionConstraint::Unresolved
    {
        DictionaryAddPolicy::AddAll
    } else {
        add_policy
    }
}

pub fn primary_chain_evidence(
    mut evidence: CandidateEvidence,
    info: &PreflateStreamInfo,
    add_policy: DictionaryAddPolicy,
) -> CandidateEvidence {
    // Both models share the complete 16-bit primary chain. With no three-byte
    // references, reuse its depth and allow for the chained model's secondary slot.
    // Require a block reaching the native soft limit, not just a compatible hash.
    if evidence.hash_algorithm == HashAlgorithm::Libdeflate4Fast
        && chain_add_policy(CHAIN_HASH, add_policy, info.max_len) == DictionaryAddPolicy::AddAll
        && info.min_len > 3
        && (300000..=304999).contains(&info.max_huffman_block_bytes)
        && (3..=600).contains(&evidence.required_chain)
    {
        evidence.hash_algorithm = CHAIN_HASH;
        evidence.required_chain += 1;
        evidence.distance_policy = DistancePolicy::FullWindow;
    }
    evidence
}

pub fn fast_hash(add_policy: DictionaryAddPolicy) -> HashAlgorithm {
    if add_policy == DictionaryAddPolicy::AddAll {
        HashAlgorithm::Libdeflate4Fast15
    } else {
        HashAlgorithm::Libdeflate4Fast
    }
}

pub fn evidence_policy() -> ParserEvidencePolicy {
    // Greedy parsing can raise its block-local minimum to nine.
    ParserEvidencePolicy::with_deferred_match_floor(9)
}

pub fn prefer_fingerprint(hash: HashAlgorithm) -> bool {
    // A 16-bit bucket is a subset of its 15-bit bucket; depth alone favors the wrong one.
    hash == HashAlgorithm::Libdeflate4Fast15
}

pub fn fingerprint(initial: &InitialEstimate<'_>) -> Option<ReconstructionParameters> {
    let evidence = &initial.evidence;
    let (parser, nice_length, max_chain, window_bits, full_window) = match evidence.hash_algorithm {
        HashAlgorithm::Libdeflate4
            if evidence.parser == ParserInference::Greedy && evidence.required_chain <= 17 =>
        {
            let nice_length = match evidence.required_chain {
                0..=7 => 10,
                8..=13 => 14,
                _ => 30,
            };
            (
                ChainParser::LibdeflateGreedy {
                    short_match_cutoff: 4096,
                },
                nice_length,
                evidence.required_chain,
                15,
                false,
            )
        }
        HashAlgorithm::Libdeflate4 if evidence.required_chain <= 601 => {
            let (depth, nice, two_positions) = match evidence.required_chain {
                0..=17 => (16, 30, false),
                18..=36 => (35, 65, false),
                37..=101 => (100, 130, false),
                102..=301 => (300, 258, true),
                _ => (600, 258, true),
            };
            (
                ChainParser::LibdeflateLazy {
                    two_positions,
                    short_match_cutoff: 8192,
                },
                nice,
                depth + 1,
                15,
                true,
            )
        }
        HashAlgorithm::Libdeflate4Fast if evidence.required_chain <= 2 => (
            ChainParser::Greedy {
                short_match_cutoff: initial.info.max_dist_3_matches,
            },
            32,
            evidence.required_chain,
            initial.window_bits,
            false,
        ),
        HashAlgorithm::Libdeflate4Fast15 => (
            ChainParser::Greedy {
                short_match_cutoff: initial.info.max_dist_3_matches,
            },
            32,
            2,
            15,
            false,
        ),
        _ => return None,
    };
    let mut parameters = initial.chain_parameters(parser, nice_length, max_chain);
    parameters
        .dictionary_mut()
        .expect("dictionary candidate")
        .window_bits = window_bits;
    if full_window {
        parameters.behavior.set_full_window(true);
    }
    Some(parameters)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameters::tests::MatchingType;

    #[test]
    fn primary_chain_reuse_preserves_fast_and_incompatible_candidates() {
        use crate::estimator::preflate_stream_info::tests::extract_preflate_info;

        let original = CandidateEvidence {
            hash_algorithm: HashAlgorithm::Libdeflate4Fast,
            required_chain: 100,
            distance_policy: DistancePolicy::ZlibWindow,
            parser: ParserInference::Unresolved,
            shallow_miniz_greedy: false,
            minimum_nice_length: 0,
        };
        for (hash, depth, minimum, bytes, insertion, expected) in [
            (
                HashAlgorithm::Libdeflate4Fast,
                100,
                5,
                304999,
                DictionaryAddPolicy::AddAll,
                true,
            ),
            (
                HashAlgorithm::Libdeflate4Fast,
                600,
                4,
                300000,
                DictionaryAddPolicy::AddAll,
                true,
            ),
            (
                HashAlgorithm::Libdeflate4Fast,
                2,
                5,
                300000,
                DictionaryAddPolicy::AddAll,
                false,
            ),
            (
                HashAlgorithm::Libdeflate4Fast15,
                2,
                5,
                300000,
                DictionaryAddPolicy::AddAll,
                false,
            ),
            (
                HashAlgorithm::Libdeflate4Fast,
                100,
                3,
                300000,
                DictionaryAddPolicy::AddAll,
                false,
            ),
            (
                HashAlgorithm::Libdeflate4Fast,
                100,
                5,
                305000,
                DictionaryAddPolicy::AddAll,
                false,
            ),
            (
                HashAlgorithm::Libdeflate4Fast,
                100,
                5,
                300000,
                DictionaryAddPolicy::AddFirst(4),
                false,
            ),
            (
                HashAlgorithm::Libdeflate4Fast,
                601,
                5,
                300000,
                DictionaryAddPolicy::AddAll,
                false,
            ),
        ] {
            let mut info = extract_preflate_info(&[]);
            info.min_len = minimum;
            info.max_len = 258;
            info.max_huffman_block_bytes = bytes;
            let evidence = CandidateEvidence {
                hash_algorithm: hash,
                required_chain: depth,
                ..original
            };
            let selected = primary_chain_evidence(evidence, &info, insertion);
            assert_eq!(
                selected.hash_algorithm,
                if expected { CHAIN_HASH } else { hash }
            );
            assert_eq!(selected.required_chain, depth + u32::from(expected));
            assert_eq!(
                selected.distance_policy,
                if expected {
                    DistancePolicy::FullWindow
                } else {
                    DistancePolicy::ZlibWindow
                }
            );
            assert_eq!(selected.parser, evidence.parser);
        }
    }

    #[test]
    fn chained_insertion_normalizes_only_an_unobserved_cutoff() {
        for (hash, policy, maximum, expected) in [
            (
                CHAIN_HASH,
                DictionaryAddPolicy::AddFirst(100),
                100,
                DictionaryAddPolicy::AddAll,
            ),
            (
                CHAIN_HASH,
                DictionaryAddPolicy::AddFirst(99),
                100,
                DictionaryAddPolicy::AddFirst(99),
            ),
            (
                HashAlgorithm::Libdeflate4Fast,
                DictionaryAddPolicy::AddFirst(100),
                100,
                DictionaryAddPolicy::AddFirst(100),
            ),
            (
                CHAIN_HASH,
                DictionaryAddPolicy::AddFirstAndLast(100),
                100,
                DictionaryAddPolicy::AddFirstAndLast(100),
            ),
        ] {
            assert_eq!(chain_add_policy(hash, policy, maximum), expected);
        }
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
        info.min_len = 5;
        info.max_len = 100;
        let evidence = CandidateEvidence {
            hash_algorithm: HashAlgorithm::Libdeflate4Fast,
            required_chain: 100,
            distance_policy: DistancePolicy::ZlibWindow,
            parser: ParserInference::Unresolved,
            shallow_miniz_greedy: false,
            minimum_nice_length: 0,
        };
        for (bytes, hash) in [
            (299999, HashAlgorithm::Libdeflate4Fast),
            (300000, CHAIN_HASH),
        ] {
            info.max_huffman_block_bytes = bytes;
            assert_eq!(
                primary_chain_evidence(evidence, &info, DictionaryAddPolicy::AddFirst(100))
                    .hash_algorithm,
                hash
            );
        }
    }

    #[test]
    fn verify_libdeflate_greedy_recognition() {
        use crate::{
            deflate::deflate_reader::tests::parse_deflate_whole,
            estimator::preflate_parameter_estimator::tests::estimate_preflate_parameters,
            utils::read_file,
        };

        for (level, nice_length) in [(2, 10), (3, 14), (4, 30)] {
            let compressed = read_file(&format!("compressed_libdeflate_level{level}.deflate"));
            let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
            let parameters = estimate_preflate_parameters(&contents, &plain).unwrap();
            assert_eq!(parameters.hash_algorithm(), HashAlgorithm::Libdeflate4);
            assert_eq!(parameters.matching_type(), MatchingType::LibdeflateGreedy);
            assert_eq!(parameters.nice_length(), nice_length);
        }
        let compressed = read_file("compressed_libdeflate_level5.deflate");
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        let parameters = estimate_preflate_parameters(&contents, &plain).unwrap();
        assert_eq!(
            parameters.matching_type(),
            MatchingType::LibdeflateLazy {
                two_positions: false
            }
        );
    }
}
