/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use super::{
    add_policy_estimator::DictionaryAddPolicy,
    complevel_estimator::CandidateEvidence,
    parser_estimator::{InsertionConstraint, ParserInference},
    preflate_parameter_estimator::TokenPredictorParameters,
};

use crate::models;
pub(crate) use crate::models::zlib::compatible as zlib_compatible;

#[derive(Clone, Copy)]
pub(crate) struct ParserContext {
    pub zlib_compatible: bool,
    pub observed_min_len: u32,
}

/// Evidence may adjust defaults, but not a fingerprint or an accepted prefix trial.
/// Prefix validation establishes a bounded token fit, not full-stream optimality.
pub(crate) enum ParameterEstimate {
    Inferred {
        parameters: TokenPredictorParameters,
        parser: ParserContext,
    },
    Fingerprinted(TokenPredictorParameters),
    PrefixValidated(TokenPredictorParameters),
}

impl ParameterEstimate {
    pub fn parameters(&self) -> TokenPredictorParameters {
        match self {
            Self::Inferred { parameters, .. }
            | Self::Fingerprinted(parameters)
            | Self::PrefixValidated(parameters) => *parameters,
        }
    }

    pub fn resolve_parser(
        self,
        inference: ParserInference,
        longest_match: u32,
    ) -> TokenPredictorParameters {
        match self {
            Self::Fingerprinted(parameters) | Self::PrefixValidated(parameters) => parameters,
            Self::Inferred { parameters, parser } => TokenPredictorParameters {
                matching_type: models::generic::resolve_matching_policy(
                    parameters.matching_type,
                    InsertionConstraint::observe(parameters.add_policy, longest_match),
                    inference,
                ),
                ..parameters
            }
            .with_lazy_behavior(parser.zlib_compatible, parser.observed_min_len),
        }
    }
}

/// Apply coupled search settings only after the depth walk has finished.
pub(super) fn select_compressor_profile(
    parameters: TokenPredictorParameters,
    evidence: &CandidateEvidence,
    observed_min_len: u32,
) -> ParameterEstimate {
    if let Some(parameters) = models::chromium::profile(parameters, evidence) {
        return ParameterEstimate::Fingerprinted(parameters);
    }
    let parser = ParserContext {
        zlib_compatible: zlib_compatible(&parameters),
        observed_min_len,
    };
    let parameters = models::generic::apply_defaults(
        parameters,
        evidence,
        parser.zlib_compatible,
        observed_min_len,
    );

    if parameters.add_policy != DictionaryAddPolicy::AddAll || parser.zlib_compatible {
        return ParameterEstimate::Inferred { parameters, parser };
    }

    match models::fingerprint(parameters, evidence) {
        Some(parameters) => ParameterEstimate::Fingerprinted(parameters),
        None => ParameterEstimate::Inferred { parameters, parser },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::estimator::depth_estimator::DistancePolicy;
    use crate::{
        estimator::preflate_parse_config::{
            MatchingType, SLOW_PREFLATE_PARSER_SETTINGS, ZLIB_PREFLATE_PARSER_SETTINGS,
        },
        hash_algorithm::HashAlgorithm,
    };

    fn parameters(evidence: &CandidateEvidence) -> TokenPredictorParameters {
        TokenPredictorParameters {
            add_policy: DictionaryAddPolicy::AddAll,
            window_bits: 9,
            nice_length: 258,
            max_chain: evidence.required_chain,
            matching_type: MatchingType::Greedy,
            hash_algorithm: evidence.hash_algorithm,
            very_far_matches_detected: evidence.distance_policy == DistancePolicy::FullWindow,
            max_dist_3_matches: 3,
            ..crate::token_predictor::zlib_level_1_params()
        }
    }

    #[test]
    fn zlib_distance_boundary_is_inclusive() {
        let mut parameters = crate::token_predictor::zlib_level_1_params();
        parameters.add_policy = DictionaryAddPolicy::AddAll;
        for (distance, expected) in [(0, true), (4095, true), (4096, true), (4097, false)] {
            parameters.max_dist_3_matches = distance;
            assert_eq!(
                zlib_compatible(&parameters),
                expected,
                "distance={distance}"
            );
            assert!(!zlib_compatible(&TokenPredictorParameters {
                very_far_matches_detected: true,
                ..parameters
            }));
            // Fast zlib does not use the lazy parser's TOO_FAR rejection.
            assert!(zlib_compatible(&TokenPredictorParameters {
                add_policy: DictionaryAddPolicy::AddFirst(4),
                ..parameters
            }));
        }
        parameters.max_dist_3_matches = 4096;
        parameters.matches_to_start_detected = true;
        assert!(!zlib_compatible(&parameters));
    }

    #[test]
    fn generic_profile_defaults_preserve_observed_search_budget() {
        for required_chain in 1..=4096 {
            let evidence = CandidateEvidence {
                hash_algorithm: HashAlgorithm::Zlib {
                    hash_mask: 32767,
                    hash_shift: 5,
                },
                required_chain,
                distance_policy: DistancePolicy::ZlibWindow,
                parser: ParserInference::Unresolved,
            };
            for add_policy in [
                DictionaryAddPolicy::AddAll,
                DictionaryAddPolicy::AddFirst(4),
                DictionaryAddPolicy::AddFirstAndLast(4),
                DictionaryAddPolicy::AddFirstWith32KBoundary,
                DictionaryAddPolicy::AddFirstExcept4kBoundary,
            ] {
                let base = TokenPredictorParameters {
                    add_policy,
                    ..parameters(&evidence)
                };
                let settings = if add_policy == DictionaryAddPolicy::AddAll {
                    &SLOW_PREFLATE_PARSER_SETTINGS[..]
                } else {
                    &ZLIB_PREFLATE_PARSER_SETTINGS[..]
                };
                let config = settings
                    .iter()
                    .find(|config| required_chain <= config.max_chain);
                let expected = TokenPredictorParameters {
                    matching_type: config.map_or(MatchingType::Greedy, |config| config.match_type),
                    nice_length: config.map_or(258, |config| config.nice_length),
                    ..base
                };
                let selection = select_compressor_profile(base, &evidence, 3);
                assert!(matches!(selection, ParameterEstimate::Inferred { .. }));
                assert_eq!(selection.parameters(), expected);
            }
        }
    }

    #[test]
    fn libdeflate_profiles_keep_coupled_settings_at_depth_boundaries() {
        for (required_chain, greedy, matching, nice, budget, window, short_distance) in [
            (1, true, MatchingType::LibdeflateGreedy, 10, 1, 15, 4096),
            (7, true, MatchingType::LibdeflateGreedy, 10, 7, 15, 4096),
            (8, true, MatchingType::LibdeflateGreedy, 14, 8, 15, 4096),
            (13, true, MatchingType::LibdeflateGreedy, 14, 13, 15, 4096),
            (14, true, MatchingType::LibdeflateGreedy, 30, 14, 15, 4096),
            (17, true, MatchingType::LibdeflateGreedy, 30, 17, 15, 4096),
            (
                1,
                false,
                MatchingType::LibdeflateLazy {
                    two_positions: false,
                },
                30,
                17,
                15,
                8192,
            ),
            (
                17,
                false,
                MatchingType::LibdeflateLazy {
                    two_positions: false,
                },
                30,
                17,
                15,
                8192,
            ),
            (
                18,
                true,
                MatchingType::LibdeflateLazy {
                    two_positions: false,
                },
                65,
                36,
                15,
                8192,
            ),
            (
                36,
                false,
                MatchingType::LibdeflateLazy {
                    two_positions: false,
                },
                65,
                36,
                15,
                8192,
            ),
            (
                37,
                false,
                MatchingType::LibdeflateLazy {
                    two_positions: false,
                },
                130,
                101,
                15,
                8192,
            ),
            (
                101,
                false,
                MatchingType::LibdeflateLazy {
                    two_positions: false,
                },
                130,
                101,
                15,
                8192,
            ),
            (
                102,
                false,
                MatchingType::LibdeflateLazy {
                    two_positions: true,
                },
                258,
                301,
                15,
                8192,
            ),
            (
                301,
                false,
                MatchingType::LibdeflateLazy {
                    two_positions: true,
                },
                258,
                301,
                15,
                8192,
            ),
            (
                302,
                false,
                MatchingType::LibdeflateLazy {
                    two_positions: true,
                },
                258,
                601,
                15,
                8192,
            ),
            (
                601,
                false,
                MatchingType::LibdeflateLazy {
                    two_positions: true,
                },
                258,
                601,
                15,
                8192,
            ),
        ] {
            let evidence = CandidateEvidence {
                hash_algorithm: HashAlgorithm::Libdeflate4,
                required_chain,
                distance_policy: DistancePolicy::FullWindow,
                parser: if greedy {
                    ParserInference::Greedy
                } else {
                    ParserInference::Unresolved
                },
            };
            let base = parameters(&evidence);
            let selection = select_compressor_profile(base, &evidence, 3);
            assert!(matches!(selection, ParameterEstimate::Fingerprinted(_)));
            assert_eq!(
                selection.parameters(),
                TokenPredictorParameters {
                    matching_type: matching,
                    nice_length: nice,
                    max_chain: budget,
                    window_bits: window,
                    max_dist_3_matches: short_distance,
                    ..base
                }
            );
        }
    }

    #[test]
    fn miniz_and_fast_profiles_preserve_their_own_budgets() {
        for (required_chain, greedy, probes) in [
            (1, true, 6),
            (6, true, 6),
            (7, true, 32),
            (33, true, 32),
            (1, false, 16),
            (18, false, 16),
            (19, false, 32),
            (34, false, 128),
            (151, false, 256),
            (1500, false, 1500),
        ] {
            let evidence = CandidateEvidence {
                hash_algorithm: HashAlgorithm::Zlib {
                    hash_mask: 32767,
                    hash_shift: 5,
                },
                required_chain,
                distance_policy: DistancePolicy::ZlibWindow,
                parser: if greedy {
                    ParserInference::Greedy
                } else {
                    ParserInference::Unresolved
                },
            };
            let base = TokenPredictorParameters {
                max_dist_3_matches: 4097,
                ..parameters(&evidence)
            };
            let selection = select_compressor_profile(base, &evidence, 3);
            assert!(matches!(selection, ParameterEstimate::Fingerprinted(_)));
            assert_eq!(
                selection.parameters(),
                TokenPredictorParameters {
                    matching_type: MatchingType::MiniZ {
                        max_probes: probes,
                        greedy
                    },
                    nice_length: 258,
                    max_chain: u32::from(probes).div_ceil(3) * 3,
                    window_bits: 15,
                    ..base
                }
            );
        }
        for hash in [
            HashAlgorithm::Libdeflate4Fast,
            HashAlgorithm::Libdeflate4Fast15,
        ] {
            let evidence = CandidateEvidence {
                hash_algorithm: hash,
                required_chain: 1,
                distance_policy: DistancePolicy::FullWindow,
                parser: ParserInference::Unresolved,
            };
            let base = parameters(&evidence);
            let fastest = hash == HashAlgorithm::Libdeflate4Fast15;
            let selection = select_compressor_profile(base, &evidence, 3);
            assert!(matches!(selection, ParameterEstimate::Fingerprinted(_)));
            assert_eq!(
                selection.parameters(),
                TokenPredictorParameters {
                    matching_type: MatchingType::Greedy,
                    nice_length: 32,
                    max_chain: if fastest { 2 } else { 1 },
                    window_bits: if fastest { 15 } else { 9 },
                    ..base
                }
            );
        }
    }
}
