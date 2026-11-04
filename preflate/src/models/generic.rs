/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use super::zlib;
use crate::{
    deflate::deflate_token::DeflateTokenReference, hash_chain_holder::prefix_compare,
    preflate_input::PreflateInput,
};
use crate::{
    estimator::{CandidateEvidence, InsertionConstraint, ParserInference},
    parameters::{DictionaryAddPolicy, MatchingType, TokenPredictorParameters},
};

#[derive(Default)]
pub(crate) struct GreedyNiceObservations {
    samples: u16,
    contradictions: [u16; 3],
    next_position: u32,
}

impl GreedyNiceObservations {
    pub(crate) fn minimum(&self) -> u16 {
        [8, 16, 32]
            .into_iter()
            .zip(self.contradictions)
            .filter_map(|(limit, count)| (count >= 4).then_some(limit + 1))
            .max()
            .unwrap_or(0)
    }

    pub(crate) fn observe(
        &mut self,
        policy: DictionaryAddPolicy,
        input: &PreflateInput,
        reference: DeflateTokenReference,
        depth: u32,
        head: u16,
    ) {
        if self.samples >= 256
            || input.pos() < self.next_position
            || reference.len() <= 8
            || depth == 0
            || !matches!(policy, DictionaryAddPolicy::AddFirst(0..=6))
            || self.minimum() > 32
        {
            return;
        }
        let distance = u32::from((input.pos() as u16).wrapping_sub(head));
        if head == 0 || distance == 0 || distance >= reference.dist() {
            return;
        }
        self.samples += 1;
        let stride = (input.pos() + input.remaining()).div_ceil(256);
        self.next_position = input.pos().saturating_add(stride.max(1));
        let limit = reference.len().min(33);
        let length = prefix_compare(
            input.cur_chars(0),
            input.cur_chars(-(distance as i32)),
            limit,
        );
        // A fast early exit at this newer head cannot reach the actual reference.
        if length < limit || reference.len() > limit {
            for (cutoff, count) in [8, 16, 32].into_iter().zip(&mut self.contradictions) {
                *count += u16::from(length >= cutoff);
            }
        }
    }
}

pub(crate) fn alternatives(
    parameters: TokenPredictorParameters,
) -> [Option<TokenPredictorParameters>; 2] {
    let noncanonical_greedy = matches!(
        parameters.hash_algorithm,
        crate::hash_algorithm::HashAlgorithm::Zlib { .. }
            | crate::hash_algorithm::HashAlgorithm::RandomVector
    ) && parameters.matching_type == MatchingType::Greedy
        && matches!(parameters.add_policy, DictionaryAddPolicy::AddFirst(limit) if limit > 6);
    let table_lazy = parameters.hash_algorithm == super::windows::HASH
        && parameters.add_policy == DictionaryAddPolicy::AddAll
        && matches!(parameters.matching_type, MatchingType::Lazy { .. });
    let slow = &zlib::SLOW_PREFLATE_PARSER_SETTINGS[2];
    let lazy = (noncanonical_greedy || table_lazy).then_some(TokenPredictorParameters {
        matching_type: slow.match_type,
        nice_length: slow.nice_length,
        max_chain: slow.max_chain,
        ..parameters
    });
    let fast = &zlib::ZLIB_PREFLATE_PARSER_SETTINGS[0];
    let insertion = (parameters.hash_algorithm == super::windows::HASH
        && parameters.add_policy == DictionaryAddPolicy::AddFirstAndLast(0))
    .then_some(TokenPredictorParameters {
        matching_type: fast.match_type,
        add_policy: fast.dictionary_add_policy,
        nice_length: fast.nice_length,
        max_chain: fast.max_chain,
        ..parameters
    });
    [insertion, lazy]
}

pub(crate) fn slow_alternative(
    parameters: TokenPredictorParameters,
) -> Option<TokenPredictorParameters> {
    if parameters.max_token_count >= 8191
        || !(parameters.add_policy == DictionaryAddPolicy::AddAll
            || matches!(parameters.add_policy, DictionaryAddPolicy::AddFirst(limit) if limit > 6))
        || !matches!(
            parameters.hash_algorithm,
            crate::hash_algorithm::HashAlgorithm::Zlib { .. }
                | crate::hash_algorithm::HashAlgorithm::RandomVector
        )
        || !matches!(
            parameters.matching_type,
            MatchingType::Lazy { .. } | MatchingType::Greedy
        )
        || parameters.nice_length >= 258
    {
        return None;
    }
    let slow = &zlib::SLOW_PREFLATE_PARSER_SETTINGS[5];
    Some(TokenPredictorParameters {
        matching_type: slow.match_type,
        nice_length: slow.nice_length,
        max_chain: slow.max_chain,
        add_policy: DictionaryAddPolicy::AddAll,
        ..parameters
    })
}

pub(crate) fn resolve_matching_policy(
    current: MatchingType,
    insertion: InsertionConstraint,
    inference: ParserInference,
) -> MatchingType {
    if current == MatchingType::Greedy
        && insertion == InsertionConstraint::Unresolved
        && let ParserInference::Lazy {
            longest_deferred_match,
        } = inference
    {
        return zlib::SLOW_PREFLATE_PARSER_SETTINGS
            .iter()
            .map(|config| config.match_type)
            .find(|policy| {
                matches!(policy, MatchingType::Lazy { max_lazy, .. }
                    if *max_lazy > longest_deferred_match)
            })
            .unwrap_or(current);
    }
    current
}

pub(crate) fn apply_defaults(
    mut parameters: TokenPredictorParameters,
    evidence: &CandidateEvidence,
    compatible: bool,
    observed_min_len: u32,
) -> TokenPredictorParameters {
    // Full-insertion lazy tuples stay coupled; partial insertion also constrains fast defaults.
    if let Some(config) = zlib::parser_settings(parameters.add_policy)
        .iter()
        .find(|config| evidence.required_chain <= config.max_chain)
    {
        parameters.matching_type = config.match_type;
        if matches!(config.match_type, MatchingType::Lazy { .. }) {
            parameters.nice_length = config.nice_length;
        }
    }
    if parameters.matching_type == MatchingType::Greedy
        && let Some(nice_length) = super::zlib_ng::greedy_nice_length(&parameters)
            .filter(|&nice| nice >= u32::from(evidence.minimum_nice_length))
            .or_else(|| zlib::greedy_nice_length(&parameters, evidence.minimum_nice_length))
    {
        parameters.nice_length = nice_length;
    }
    zlib::project_lazy_behavior(parameters, compatible, observed_min_len)
}

#[test]
fn greedy_nice_observations_require_repeated_improvements_and_are_bounded() {
    use crate::preflate_input::PlainText;

    let make_input = |head_length: usize| {
        let pattern = b"abcdefghijklmnopqrstuvwxyz0123456789ABCD";
        let mut bytes = vec![b'@'];
        bytes.extend(pattern);
        bytes.push(b'!');
        let head = bytes.len() as u16;
        bytes.extend(&pattern[..head_length]);
        bytes.push(b'$');
        let position = bytes.len() as u32;
        bytes.extend(pattern);
        (PlainText::new_with_data(bytes), position, head)
    };
    let (plain, position, head) = make_input(32);
    let mut input = PreflateInput::new(&plain);
    input.advance(position);
    let reference = DeflateTokenReference::new(40, position - 1);
    let mut observations = GreedyNiceObservations::default();
    for _ in 0..3 {
        observations.next_position = 0;
        observations.observe(DictionaryAddPolicy::AddFirst(4), &input, reference, 1, head);
        assert_eq!(observations.minimum(), 0);
    }
    observations.next_position = 0;
    observations.observe(DictionaryAddPolicy::AddFirst(4), &input, reference, 1, head);
    assert_eq!(observations.minimum(), 33);
    for (policy, depth, candidate_head) in [
        (DictionaryAddPolicy::AddAll, 1, head),
        (DictionaryAddPolicy::AddFirstAndLast(4), 1, head),
        (DictionaryAddPolicy::AddFirstWith32KBoundary, 1, head),
        (DictionaryAddPolicy::AddFirst(4), 0, head),
        (DictionaryAddPolicy::AddFirst(4), 1, 0),
        (DictionaryAddPolicy::AddFirst(4), 1, 1),
    ] {
        let mut observations = GreedyNiceObservations::default();
        for _ in 0..4 {
            observations.next_position = 0;
            observations.observe(policy, &input, reference, depth, candidate_head);
        }
        assert_eq!(observations.minimum(), 0);
    }
    let (short_plain, short_position, short_head) = make_input(7);
    let mut short_input = PreflateInput::new(&short_plain);
    short_input.advance(short_position);
    let mut observations = GreedyNiceObservations::default();
    for _ in 0..4 {
        observations.observe(
            DictionaryAddPolicy::AddFirst(4),
            &short_input,
            DeflateTokenReference::new(40, short_position - 1),
            1,
            short_head,
        );
    }
    assert_eq!(observations.samples, 1);
    for _ in 0..512 {
        observations.next_position = 0;
        observations.observe(
            DictionaryAddPolicy::AddFirst(4),
            &short_input,
            DeflateTokenReference::new(40, short_position - 1),
            1,
            short_head,
        );
    }
    assert_eq!(observations.samples, 256);
    for _ in 0..4 {
        observations.next_position = 0;
        observations.observe(DictionaryAddPolicy::AddFirst(4), &input, reference, 1, head);
    }
    assert_eq!(observations.minimum(), 0);
}

#[test]
fn repeated_head_contradictions_reject_short_fast_nice_defaults() {
    use crate::{estimator::DistancePolicy, hash_algorithm::HashAlgorithm};
    for (minimum, expected) in [(0, 8), (9, 16), (17, 32), (33, 255)] {
        let parameters = TokenPredictorParameters {
            hash_algorithm: HashAlgorithm::RandomVector,
            add_policy: DictionaryAddPolicy::AddFirst(4),
            nice_length: 255,
            max_chain: 4,
            ..crate::token_predictor::zlib_level_1_params()
        };
        let evidence = CandidateEvidence {
            hash_algorithm: parameters.hash_algorithm,
            required_chain: 4,
            distance_policy: DistancePolicy::ZlibWindow,
            parser: ParserInference::Unresolved,
            shallow_miniz_greedy: false,
            minimum_nice_length: minimum,
        };
        assert_eq!(
            apply_defaults(parameters, &evidence, true, 3).nice_length,
            expected
        );
    }
}

#[test]
fn fast_nice_defaults_reconcile_insertion_and_required_chain_bounds() {
    use crate::{estimator::DistancePolicy, hash_algorithm::HashAlgorithm};

    for hash_algorithm in [
        HashAlgorithm::Zlib {
            hash_mask: 16383,
            hash_shift: 5,
        },
        HashAlgorithm::RandomVector,
        HashAlgorithm::Libdeflate4,
    ] {
        for (limit, required_chain, expected) in [
            (4, 16, 32),
            (4, 4, 8),
            (4, 8, 16),
            (5, 1, 16),
            (6, 2, 32),
            (7, 4, 255),
            (4, 64, 255),
        ] {
            let parameters = TokenPredictorParameters {
                hash_algorithm,
                add_policy: DictionaryAddPolicy::AddFirst(limit),
                nice_length: 255,
                max_chain: required_chain,
                ..crate::token_predictor::zlib_level_1_params()
            };
            let evidence = CandidateEvidence {
                hash_algorithm,
                required_chain,
                distance_policy: DistancePolicy::ZlibWindow,
                parser: ParserInference::Unresolved,
                shallow_miniz_greedy: false,
                minimum_nice_length: 0,
            };
            let actual = apply_defaults(parameters, &evidence, true, 3);
            assert_eq!(actual.nice_length, expected, "{parameters:?}");
            assert_eq!(actual.max_chain, parameters.max_chain);
            assert_eq!(actual.add_policy, parameters.add_policy);
            assert_eq!(actual.hash_algorithm, parameters.hash_algorithm);
        }
    }
}

#[test]
fn nonclassic_insertion_keeps_family_defaults_or_an_independent_nice_limit() {
    use crate::{estimator::DistancePolicy, hash_algorithm::HashAlgorithm};
    for (hash_algorithm, add_policy, nice_length) in [
        (zlib::DEFAULT_HASH, DictionaryAddPolicy::AddFirst(7), 255),
        (
            HashAlgorithm::Crc32cHash,
            DictionaryAddPolicy::AddFirstAndLast(4),
            8,
        ),
        (
            HashAlgorithm::ZlibNG,
            DictionaryAddPolicy::AddFirstAndLast(96),
            16,
        ),
        (
            HashAlgorithm::Crc32cHash,
            DictionaryAddPolicy::AddFirstAndLast(191),
            32,
        ),
        (
            HashAlgorithm::Crc32cHash,
            DictionaryAddPolicy::AddFirstAndLast(190),
            32,
        ),
        (
            HashAlgorithm::ZlibNG,
            DictionaryAddPolicy::AddFirstAndLast(5),
            16,
        ),
        (
            HashAlgorithm::Libdeflate4,
            DictionaryAddPolicy::AddFirstAndLast(7),
            255,
        ),
        (
            HashAlgorithm::RandomVector,
            DictionaryAddPolicy::AddFirstExcept4kBoundary,
            255,
        ),
    ] {
        for required_chain in [1, 2, 4, 8, 32, 128, 4096] {
            let parameters = TokenPredictorParameters {
                hash_algorithm,
                add_policy,
                max_chain: required_chain,
                nice_length: 255,
                ..crate::token_predictor::zlib_level_1_params()
            };
            let evidence = CandidateEvidence {
                hash_algorithm,
                required_chain,
                distance_policy: DistancePolicy::ZlibWindow,
                parser: ParserInference::Unresolved,
                shallow_miniz_greedy: false,
                minimum_nice_length: 0,
            };
            let actual = apply_defaults(parameters, &evidence, true, 3);
            assert_eq!(actual.matching_type, MatchingType::Greedy);
            assert_eq!(actual.max_chain, required_chain);
            assert_eq!(actual.nice_length, nice_length, "{parameters:?}");
        }
    }
}

#[test]
fn slow_alternative_preserves_hash_and_rejects_strong_or_incompatible_profiles() {
    let base = TokenPredictorParameters {
        add_policy: DictionaryAddPolicy::AddAll,
        matching_type: zlib::SLOW_PREFLATE_PARSER_SETTINGS[3].match_type,
        nice_length: 128,
        max_token_count: 2047,
        ..crate::token_predictor::zlib_level_1_params()
    };
    let result = slow_alternative(base).unwrap();
    assert_eq!(result.hash_algorithm, base.hash_algorithm);
    assert_eq!(result.max_dist_3_matches, base.max_dist_3_matches);
    assert_eq!(
        result.matching_type,
        zlib::SLOW_PREFLATE_PARSER_SETTINGS[5].match_type
    );
    assert_eq!(result.max_chain, 4096);
    for incompatible in [
        TokenPredictorParameters {
            max_token_count: 8191,
            ..base
        },
        TokenPredictorParameters {
            nice_length: 258,
            ..base
        },
        TokenPredictorParameters {
            matching_type: MatchingType::MiniZ {
                max_probes: 3,
                greedy: true,
            },
            ..base
        },
        TokenPredictorParameters {
            hash_algorithm: crate::hash_algorithm::HashAlgorithm::Libdeflate4,
            ..base
        },
        TokenPredictorParameters {
            add_policy: DictionaryAddPolicy::AddFirst(4),
            ..base
        },
    ] {
        assert!(slow_alternative(incompatible).is_none());
    }
}

#[test]
fn ambiguous_parser_alternatives_preserve_insertion_evidence() {
    let base = crate::token_predictor::zlib_level_1_params();
    for limit in [4, 5, 6] {
        assert_eq!(
            alternatives(TokenPredictorParameters {
                add_policy: DictionaryAddPolicy::AddFirst(limit),
                ..base
            }),
            [None, None]
        );
    }

    assert_eq!(
        alternatives(TokenPredictorParameters {
            hash_algorithm: crate::hash_algorithm::HashAlgorithm::Libdeflate4Fast,
            add_policy: DictionaryAddPolicy::AddFirst(116),
            ..base
        }),
        [None, None]
    );
    let slow = &zlib::SLOW_PREFLATE_PARSER_SETTINGS[2];
    for limit in [7, 61, 120] {
        let parameters = TokenPredictorParameters {
            add_policy: DictionaryAddPolicy::AddFirst(limit),
            max_dist_3_matches: 4048,
            ..base
        };
        assert_eq!(
            alternatives(parameters),
            [
                None,
                Some(TokenPredictorParameters {
                    matching_type: slow.match_type,
                    nice_length: slow.nice_length,
                    max_chain: slow.max_chain,
                    ..parameters
                })
            ]
        );
    }
    let parameters = TokenPredictorParameters {
        hash_algorithm: super::windows::HASH,
        add_policy: DictionaryAddPolicy::AddFirstAndLast(0),
        ..base
    };
    assert_eq!(
        alternatives(parameters),
        [
            Some(TokenPredictorParameters {
                matching_type: MatchingType::Greedy,
                add_policy: DictionaryAddPolicy::AddFirst(4),
                nice_length: 8,
                max_chain: 4,
                ..parameters
            }),
            None
        ]
    );
}
