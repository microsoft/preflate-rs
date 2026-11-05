//! Default settings and parser refinements for streams without a decisive family fingerprint.
//! Uses insertion and search evidence to propose conservative compressor behavior.

use crate::reconstruction_parameters::{ChainParser, LazyLookaheadSettings, LazyMinimum};
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use super::{zlib, zlib_ng};
use crate::{
    deflate::deflate_token::DeflateTokenReference, hash_chain_holder::prefix_compare,
    preflate_input::PreflateInput,
};
use crate::{
    estimator::{
        initial_estimate::InitialEstimate,
        parser_estimator::{InsertionConstraint, ParserInference},
        preflate_stream_info::PreflateStreamInfo,
    },
    hash_algorithm::HashAlgorithm,
    parameters::{DictionaryAddPolicy, LazyBehavior},
    reconstruction_parameters::ReconstructionParameters,
};

pub fn primary_only_greedy(
    parameters: ReconstructionParameters,
    info: &PreflateStreamInfo,
) -> Option<ReconstructionParameters> {
    if !parameters.behavior.uses_general_distances()
        || parameters.hash_algorithm() != HashAlgorithm::Libdeflate4Fast
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
        || info.min_len < 4
        || info.reference_count < 64
        || parameters.max_token_count < 1023
        || !(u32::from(parameters.max_token_count) + 1).is_power_of_two()
        || info.max_tokens_per_block != u32::from(parameters.max_token_count)
    {
        return None;
    }
    let bounded_window = info.ends_with_final_block
        && !info.matches_to_start_detected
        && info.max_dist
            <= (1
                << parameters
                    .dictionary()
                    .expect("dictionary candidate")
                    .window_bits)
                - crate::deflate::deflate_constants::MIN_LOOKAHEAD;
    Some({
        let mut canonical_configuration = parameters;
        canonical_configuration.replace_chain_parser(ChainParser::Greedy {
            short_match_cutoff: canonical_configuration.behavior.short_match_cutoff(),
        });
        canonical_configuration
            .behavior
            .set_full_window(parameters.behavior.uses_full_window() && !bounded_window);

        canonical_configuration
    })
}

#[derive(Default)]
pub struct GreedyNiceObservations {
    samples: u16,
    contradictions: [u16; 3],
    next_position: u32,
}

impl GreedyNiceObservations {
    pub fn minimum(&self) -> u16 {
        [8, 16, 32]
            .into_iter()
            .zip(self.contradictions)
            .filter_map(|(limit, count)| (count >= 4).then_some(limit + 1))
            .max()
            .unwrap_or(0)
    }

    pub fn observe(
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

pub fn alternatives(parameters: ReconstructionParameters) -> [Option<ReconstructionParameters>; 2] {
    let noncanonical_greedy = matches!(
        parameters.hash_algorithm(),
        crate::hash_algorithm::HashAlgorithm::Zlib { .. }
            | crate::hash_algorithm::HashAlgorithm::RandomVector
    ) && matches!(
        parameters.chain_parser(),
        Some(ChainParser::Greedy { .. })
    ) && matches!(parameters.dictionary().expect("dictionary candidate").insertion, DictionaryAddPolicy::AddFirst(limit) if limit > 6);
    let table_lazy = parameters.hash_algorithm() == crate::compressors::windows::HASH
        && parameters
            .dictionary()
            .expect("dictionary candidate")
            .insertion
            == DictionaryAddPolicy::AddAll
        && matches!(parameters.chain_parser(), Some(ChainParser::Lazy { .. }));
    let slow = &zlib::SLOW_PREFLATE_PARSER_SETTINGS[2];
    let lazy = (noncanonical_greedy || table_lazy).then(|| {
        let mut canonical_configuration = parameters;
        canonical_configuration.replace_chain_parser(
            slow.parser
                .with_cutoff(canonical_configuration.behavior.short_match_cutoff()),
        );
        canonical_configuration
            .chain_common_mut()
            .expect("chain candidate")
            .search
            .nice_length = slow.nice_length;
        canonical_configuration
            .budget_mut()
            .expect("dictionary candidate")
            .max_chain = slow.max_chain;

        canonical_configuration
    });
    let fast = &zlib::ZLIB_PREFLATE_PARSER_SETTINGS[0];
    let insertion = (parameters.hash_algorithm() == crate::compressors::windows::HASH
        && parameters
            .dictionary()
            .expect("dictionary candidate")
            .insertion
            == DictionaryAddPolicy::AddFirstAndLast(0))
    .then(|| {
        let mut canonical_configuration = parameters;
        canonical_configuration.replace_chain_parser(
            fast.parser
                .with_cutoff(canonical_configuration.behavior.short_match_cutoff()),
        );
        canonical_configuration
            .dictionary_mut()
            .expect("dictionary candidate")
            .insertion = fast.dictionary_add_policy;
        canonical_configuration
            .chain_common_mut()
            .expect("chain candidate")
            .search
            .nice_length = fast.nice_length;
        canonical_configuration
            .budget_mut()
            .expect("dictionary candidate")
            .max_chain = fast.max_chain;

        canonical_configuration
    });
    [insertion, lazy]
}

pub fn slow_alternative(parameters: ReconstructionParameters) -> Option<ReconstructionParameters> {
    if parameters.max_token_count >= 8191
        || !(parameters
            .dictionary()
            .expect("dictionary candidate")
            .insertion
            == DictionaryAddPolicy::AddAll
            || matches!(parameters.dictionary().expect("dictionary candidate").insertion, DictionaryAddPolicy::AddFirst(limit) if limit > 6))
        || !matches!(
            parameters.hash_algorithm(),
            crate::hash_algorithm::HashAlgorithm::Zlib { .. }
                | crate::hash_algorithm::HashAlgorithm::RandomVector
        )
        || !matches!(
            parameters.chain_parser(),
            Some(ChainParser::Lazy { .. } | ChainParser::Greedy { .. })
        )
        || parameters
            .chain_common()
            .expect("chain candidate")
            .search
            .nice_length
            >= 258
    {
        return None;
    }
    let slow = &zlib::SLOW_PREFLATE_PARSER_SETTINGS[5];
    Some({
        let mut canonical_configuration = parameters;
        canonical_configuration.replace_chain_parser(
            slow.parser
                .with_cutoff(canonical_configuration.behavior.short_match_cutoff()),
        );
        canonical_configuration
            .dictionary_mut()
            .expect("dictionary candidate")
            .insertion = DictionaryAddPolicy::AddAll;
        canonical_configuration
            .chain_common_mut()
            .expect("chain candidate")
            .search
            .nice_length = slow.nice_length;
        canonical_configuration
            .budget_mut()
            .expect("dictionary candidate")
            .max_chain = slow.max_chain;

        canonical_configuration
    })
}

pub fn resolve_matching_policy(
    current: ChainParser,
    insertion: InsertionConstraint,
    inference: ParserInference,
) -> ChainParser {
    if matches!(current, ChainParser::Greedy { .. })
        && insertion == InsertionConstraint::Unresolved
        && let ParserInference::Lazy {
            longest_deferred_match,
        } = inference
    {
        return zlib::SLOW_PREFLATE_PARSER_SETTINGS
            .iter()
            .map(|config| {
                config.parser.with_cutoff(match current {
                    ChainParser::Greedy { short_match_cutoff } => short_match_cutoff,
                    _ => unreachable!(),
                })
            })
            .find(|policy| {
                matches!(policy, ChainParser::Lazy { lookahead, .. }
                    if lookahead.max_lazy > longest_deferred_match)
            })
            .unwrap_or(current);
    }
    current
}

pub fn candidate(initial: &InitialEstimate<'_>, compatible: bool) -> ReconstructionParameters {
    let evidence = &initial.evidence;
    let short_match_cutoff = initial.info.max_dist_3_matches;
    let config = zlib::parser_settings(initial.insertion)
        .iter()
        .find(|config| evidence.required_chain <= config.max_chain);
    let parser = config.map_or(ChainParser::Greedy { short_match_cutoff }, |config| {
        config.parser.with_cutoff(short_match_cutoff)
    });
    let mut nice_length = if evidence.required_chain == 1 {
        u32::from(u8::MAX)
    } else {
        initial.info.max_len.max(u32::from(u8::MAX))
    };
    // Full-insertion lazy tuples stay coupled; partial insertion also constrains fast defaults.
    if let Some(config) = config
        && matches!(config.parser, ChainParser::Lazy { .. })
    {
        nice_length = config.nice_length;
    }
    if matches!(parser, ChainParser::Greedy { .. })
        && let Some(fast_nice_length) = zlib_ng::greedy_nice_length(initial)
            .filter(|&nice| nice >= u32::from(evidence.minimum_nice_length))
            .or_else(|| zlib::greedy_nice_length(initial))
    {
        nice_length = fast_nice_length;
    }
    zlib::project_lazy_behavior(
        initial.chain_parameters(parser, nice_length, evidence.required_chain),
        compatible,
        initial.info.min_len,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::estimator::test_support::initial_stream_info;
    use crate::estimator::{
        complevel_estimator::CandidateEvidence, depth_estimator::DistancePolicy,
    };

    use crate::parameters::{PreflateStrategy, tests::MatchingType};

    #[test]
    fn primary_only_greedy_preserves_evidence_and_requires_an_unrecognized_parser() {
        let parameters = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4Fast);
            canonical_configuration.set_full_window(true);
            canonical_configuration.set_matching_type(MatchingType::Lazy {
                max_lazy: 128,
                filtered_matching: false,
                behavior: LazyBehavior::RecomputeAfterLiteral,
            });
            canonical_configuration.max_token_count = 4095;
            canonical_configuration
        };
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
        info.min_len = 4;
        info.reference_count = 64;
        info.max_tokens_per_block = 4095;
        info.max_dist = 32506;
        info.ends_with_final_block = true;
        assert_eq!(
            primary_only_greedy(parameters, &info),
            Some({
                let mut canonical_configuration = parameters;
                canonical_configuration.set_full_window(false);
                canonical_configuration.set_matching_type(MatchingType::Greedy);
                canonical_configuration
            })
        );
        for rejected in [
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4);
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4Fast15);
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_matching_type(MatchingType::LibdeflateLazy {
                    two_positions: true,
                });
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_matching_type(MatchingType::Greedy);
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_matching_type(MatchingType::Lazy {
                    max_lazy: 128,
                    filtered_matching: true,
                    behavior: LazyBehavior::RecomputeAfterLiteral,
                });
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_matching_type(MatchingType::Lazy {
                    max_lazy: 128,
                    filtered_matching: false,
                    behavior: LazyBehavior::Zlib { good_length: 8 },
                });
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.max_token_count = 1000;
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_strategy(PreflateStrategy::RleOnly);
                canonical_configuration
            },
        ] {
            assert!(primary_only_greedy(rejected, &info).is_none());
        }
        info.min_len = 3;
        assert!(primary_only_greedy(parameters, &info).is_none());
        info.min_len = 4;
        info.reference_count = 63;
        assert!(primary_only_greedy(parameters, &info).is_none());
        info.reference_count = 64;
        info.max_tokens_per_block = 4094;
        assert!(primary_only_greedy(parameters, &info).is_none());
        info.max_tokens_per_block = 4095;
        for (complete, starts, distance) in [
            (false, false, 32506),
            (true, true, 32506),
            (true, false, 32507),
        ] {
            info.ends_with_final_block = complete;
            info.matches_to_start_detected = starts;
            info.max_dist = distance;
            assert!(
                primary_only_greedy(parameters, &info)
                    .unwrap()
                    .very_far_matches_detected()
            );
        }
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
        let mut info = initial_stream_info();
        info.max_len = 255;
        info.max_dist_3_matches = 32488;
        for (minimum, expected) in [(0, 8), (9, 16), (17, 32), (33, 255)] {
            let evidence = CandidateEvidence {
                hash_algorithm: HashAlgorithm::RandomVector,
                required_chain: 4,
                distance_policy: DistancePolicy::ZlibWindow,
                parser: ParserInference::Unresolved,
                shallow_miniz_greedy: false,
                minimum_nice_length: minimum,
            };
            let mut initial = InitialEstimate::test_fixture(&info, evidence);
            initial.insertion = DictionaryAddPolicy::AddFirst(4);
            assert_eq!(candidate(&initial, true).nice_length(), expected);
        }
    }

    #[test]
    fn fast_nice_defaults_reconcile_insertion_and_required_chain_bounds() {
        let mut info = initial_stream_info();
        info.max_len = 255;
        info.max_dist_3_matches = 32488;
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
                let evidence = CandidateEvidence {
                    hash_algorithm,
                    required_chain,
                    distance_policy: DistancePolicy::ZlibWindow,
                    parser: ParserInference::Unresolved,
                    shallow_miniz_greedy: false,
                    minimum_nice_length: 0,
                };
                let mut initial = InitialEstimate::test_fixture(&info, evidence);
                initial.insertion = DictionaryAddPolicy::AddFirst(limit);
                let actual = candidate(&initial, true);
                assert_eq!(
                    actual.nice_length(),
                    expected,
                    "{hash_algorithm:?}, limit={limit}, depth={required_chain}"
                );
                assert_eq!(actual.max_chain(), required_chain);
                assert_eq!(actual.add_policy(), initial.insertion);
                assert_eq!(actual.hash_algorithm(), hash_algorithm);
            }
        }
    }

    #[test]
    fn nonclassic_insertion_keeps_family_defaults_or_an_independent_nice_limit() {
        let mut info = initial_stream_info();
        info.max_len = 255;
        info.max_dist_3_matches = 32488;
        for (hash_algorithm, add_policy, nice_length) in [
            (
                crate::compressors::zlib::DEFAULT_HASH,
                DictionaryAddPolicy::AddFirst(7),
                255,
            ),
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
                let evidence = CandidateEvidence {
                    hash_algorithm,
                    required_chain,
                    distance_policy: DistancePolicy::ZlibWindow,
                    parser: ParserInference::Unresolved,
                    shallow_miniz_greedy: false,
                    minimum_nice_length: 0,
                };
                let mut initial = InitialEstimate::test_fixture(&info, evidence);
                initial.insertion = add_policy;
                let actual = candidate(&initial, true);
                assert_eq!(actual.matching_type(), MatchingType::Greedy);
                assert_eq!(actual.max_chain(), required_chain);
                assert_eq!(
                    actual.nice_length(),
                    nice_length,
                    "{hash_algorithm:?}, policy={add_policy:?}, depth={required_chain}"
                );
            }
        }
    }

    #[test]
    fn slow_alternative_preserves_hash_and_rejects_strong_or_incompatible_profiles() {
        let base = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_nice_length(128);
            canonical_configuration.set_matching_type(
                zlib::SLOW_PREFLATE_PARSER_SETTINGS[3]
                    .parser
                    .matching_type(),
            );
            canonical_configuration.max_token_count = 2047;
            canonical_configuration
        };
        let result = slow_alternative(base).unwrap();
        assert_eq!(result.hash_algorithm(), base.hash_algorithm());
        assert_eq!(result.max_dist_3_matches(), base.max_dist_3_matches());
        assert_eq!(
            result.matching_type(),
            zlib::SLOW_PREFLATE_PARSER_SETTINGS[5]
                .parser
                .matching_type()
        );
        assert_eq!(result.max_chain(), 4096);
        for incompatible in [
            {
                let mut canonical_configuration = base;
                canonical_configuration.max_token_count = 8191;
                canonical_configuration
            },
            {
                let mut canonical_configuration = base;
                canonical_configuration.set_nice_length(258);
                canonical_configuration
            },
            {
                let mut canonical_configuration = base;
                canonical_configuration.set_matching_type(MatchingType::MiniZ {
                    max_probes: 3,
                    greedy: true,
                });
                canonical_configuration
            },
            {
                let mut canonical_configuration = base;
                canonical_configuration
                    .set_hash_algorithm(crate::hash_algorithm::HashAlgorithm::Libdeflate4);
                canonical_configuration
            },
            {
                let mut canonical_configuration = base;
                canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(4));
                canonical_configuration
            },
        ] {
            assert!(slow_alternative(incompatible).is_none());
        }
    }

    #[test]
    fn ambiguous_parser_alternatives_preserve_insertion_evidence() {
        let base = crate::token_predictor::tests::zlib_level_1_params();
        for limit in [4, 5, 6] {
            assert_eq!(
                alternatives({
                    let mut canonical_configuration = base;
                    canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(limit));
                    canonical_configuration
                }),
                [None, None]
            );
        }

        assert_eq!(
            alternatives({
                let mut canonical_configuration = base;
                canonical_configuration
                    .set_hash_algorithm(crate::hash_algorithm::HashAlgorithm::Libdeflate4Fast);
                canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(116));
                canonical_configuration
            }),
            [None, None]
        );
        let slow = &zlib::SLOW_PREFLATE_PARSER_SETTINGS[2];
        for limit in [7, 61, 120] {
            let parameters = {
                let mut canonical_configuration = base;
                canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(limit));
                canonical_configuration.set_short_match_cutoff(4048);
                canonical_configuration
            };
            assert_eq!(
                alternatives(parameters),
                [
                    None,
                    Some({
                        let mut canonical_configuration = parameters;
                        canonical_configuration.set_nice_length(slow.nice_length);
                        canonical_configuration.set_max_chain(slow.max_chain);
                        canonical_configuration.set_matching_type(slow.parser.matching_type());
                        canonical_configuration
                    })
                ]
            );
        }
        let parameters = {
            let mut canonical_configuration = base;
            canonical_configuration.set_hash_algorithm(crate::compressors::windows::HASH);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirstAndLast(0));
            canonical_configuration
        };
        assert_eq!(
            alternatives(parameters),
            [
                Some({
                    let mut canonical_configuration = parameters;
                    canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(4));
                    canonical_configuration.set_nice_length(8);
                    canonical_configuration.set_max_chain(4);
                    canonical_configuration.set_matching_type(MatchingType::Greedy);
                    canonical_configuration
                }),
                None
            ]
        );
    }
}
