/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

//! Candidate ordering, compressor-profile selection, and parser-policy resolution.
//!
//! Family models interpret observations and propose complete settings. This
//! coordinator orders and deduplicates hash candidates, assigns the bounded
//! refinement slots, and keeps each model hypothesis beside its configuration.
//! Selection provenance protects fingerprinted and prefix-validated choices
//! while allowing inferred defaults to follow stronger parser evidence.

use super::{
    complevel_estimator::CandidateEvidence,
    depth_estimator::HashTableDepthEstimator,
    estimation_result::EstimationResult,
    evidence_policy::ParserEvidencePolicy,
    initial_estimate::InitialEstimate,
    models::{self, chromium, generic, libdeflate, miniz, windows, zlib, zlib_ng},
    parser_estimator::{InsertionConstraint, ParserInference},
    preflate_stream_info::PreflateStreamInfo,
};
use crate::{
    hash_algorithm::HashAlgorithm, parameters::DictionaryAddPolicy,
    reconstruction_parameters::ReconstructionParameters,
};

impl ReconstructionParameters {
    pub(crate) fn with_lazy_behavior(self, compatible: bool, observed_min_len: u32) -> Self {
        models::zlib::project_lazy_behavior(self, compatible, observed_min_len)
    }
}

#[derive(Clone, Copy)]
pub struct ParserContext {
    pub zlib_compatible: bool,
    pub observed_min_len: u32,
}

/// Evidence may adjust defaults, but not a fingerprint or an accepted prefix trial.
/// Prefix validation establishes a bounded token fit, not full-stream optimality.
pub struct ParameterEstimate {
    pub profile: EstimationResult,
    pub provenance: EstimateProvenance,
}

pub enum EstimateProvenance {
    Inferred(ParserContext),
    Fingerprinted,
    PrefixValidated,
}

impl ParameterEstimate {
    pub fn parameters(&self) -> ReconstructionParameters {
        self.profile.reconstruction
    }

    pub fn resolve_profile(
        self,
        inference: ParserInference,
        longest_match: u32,
    ) -> EstimationResult {
        match self.provenance {
            EstimateProvenance::Fingerprinted | EstimateProvenance::PrefixValidated => self.profile,
            EstimateProvenance::Inferred(parser) => {
                let mut parameters = self.profile.reconstruction;
                if let Some(current) = parameters.chain_parser() {
                    parameters.replace_chain_parser(models::generic::resolve_matching_policy(
                        current,
                        InsertionConstraint::observe(
                            parameters
                                .dictionary()
                                .expect("dictionary candidate")
                                .insertion,
                            longest_match,
                        ),
                        inference,
                    ));
                }
                inferred_profile(
                    parameters.with_lazy_behavior(parser.zlib_compatible, parser.observed_min_len),
                )
            }
        }
    }
}

/// A model hypothesis, not a claim that its producer has been identified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressorProfile {
    Zlib,
    ZlibNg,
    #[serde(rename = "miniz")]
    MiniZ,
    Libdeflate,
    Windows,
    Chromium,
    Custom,
}

impl CompressorProfile {
    pub fn with_parameters(self, reconstruction: ReconstructionParameters) -> EstimationResult {
        EstimationResult::new(self, reconstruction)
    }
}

pub fn select_compressor_profile(initial: &InitialEstimate<'_>) -> ParameterEstimate {
    if let Some(profile) = chromium::profile(initial) {
        return ParameterEstimate {
            profile: CompressorProfile::Chromium.with_parameters(profile),
            provenance: EstimateProvenance::Fingerprinted,
        };
    }
    let parser = ParserContext {
        zlib_compatible: zlib::compatible_initial(initial),
        observed_min_len: initial.info.min_len,
    };
    if initial.insertion == DictionaryAddPolicy::AddAll && !parser.zlib_compatible {
        let fingerprint = miniz::fingerprint(initial)
            .map(|parameters| CompressorProfile::MiniZ.with_parameters(parameters))
            .or_else(|| {
                libdeflate::fingerprint(initial)
                    .map(|parameters| CompressorProfile::Libdeflate.with_parameters(parameters))
            });
        if let Some(profile) = fingerprint {
            return ParameterEstimate {
                profile,
                provenance: EstimateProvenance::Fingerprinted,
            };
        }
    }
    let parameters = generic::candidate(initial, parser.zlib_compatible);
    ParameterEstimate {
        profile: inferred_profile(parameters),
        provenance: EstimateProvenance::Inferred(parser),
    }
}

pub fn preferred_depth_candidate<'a>(
    candidates: &'a [Box<dyn HashTableDepthEstimator>],
    add_policy: DictionaryAddPolicy,
    info: &PreflateStreamInfo,
) -> Option<&'a dyn HashTableDepthEstimator> {
    let prefer_miniz_hash = miniz::prefer_rotating_hash(
        add_policy,
        info,
        candidates
            .iter()
            .any(|candidate| miniz::vetoes_rotating_hash(candidate.hash_algorithm())),
    );
    candidates
        .iter()
        .find(|candidate| {
            libdeflate::prefer_fingerprint(candidate.hash_algorithm())
                || info.chromium_short_matches.supports_chromium()
                    && matches!(candidate.hash_algorithm(), HashAlgorithm::Chromium { .. })
                || prefer_miniz_hash
                    && candidate.hash_algorithm() == crate::compressors::zlib::DEFAULT_HASH
        })
        .map(|candidate| candidate.as_ref())
}

pub fn profile_alternatives(
    parameters: ReconstructionParameters,
    info: &PreflateStreamInfo,
    zlib_candidates: &[CandidateEvidence],
) -> [Option<EstimationResult>; 11] {
    let [insertion, lazy] = generic::alternatives(parameters);
    let [windows_greedy, windows_lazy, windows_partial] = windows::alternatives(parameters, info);
    let [chromium_fast, chromium_lazy] = chromium::alternatives(parameters, info);
    let insertion = zlib::table_hash_fast(parameters, info, zlib_candidates)
        .map(|parameters| CompressorProfile::Zlib.with_parameters(parameters))
        .or_else(|| {
            insertion.map(|parameters| CompressorProfile::Custom.with_parameters(parameters))
        });
    let lazy = zlib::table_hash_slow(parameters, info, zlib_candidates)
        .or_else(|| zlib::noncanonical_insertion(parameters, info))
        .map(|parameters| CompressorProfile::Zlib.with_parameters(parameters))
        .or_else(|| {
            lazy.and_then(|candidate| {
                if candidate == parameters {
                    // Reuse the redundant slot when the shorter zlib prefix was ambiguous.
                    zlib::memory_hash_alternative(parameters, info)
                        .map(|parameters| CompressorProfile::Zlib.with_parameters(parameters))
                } else {
                    Some(CompressorProfile::Custom.with_parameters(candidate))
                }
            })
            .or_else(|| {
                zlib::filtered_hash(parameters, info)
                    .map(|parameters| CompressorProfile::Zlib.with_parameters(parameters))
            })
        })
        .or_else(|| {
            zlib::ambiguous_fast_hash(parameters, info)
                .map(|parameters| CompressorProfile::Zlib.with_parameters(parameters))
        })
        .or_else(|| {
            generic::primary_only_greedy(parameters, info)
                .map(|parameters| CompressorProfile::Custom.with_parameters(parameters))
        });
    [
        miniz::shallow_alternative(parameters, info)
            .map(|parameters| CompressorProfile::MiniZ.with_parameters(parameters)),
        windows_greedy.map(|parameters| CompressorProfile::Windows.with_parameters(parameters)),
        windows_lazy.map(|parameters| CompressorProfile::Windows.with_parameters(parameters)),
        windows_partial.map(|parameters| CompressorProfile::Windows.with_parameters(parameters)),
        insertion,
        lazy,
        chromium_fast.map(|parameters| CompressorProfile::Chromium.with_parameters(parameters)),
        chromium_lazy.map(|parameters| CompressorProfile::Chromium.with_parameters(parameters)),
        zlib::flush(parameters, info)
            .map(|parameters| CompressorProfile::Zlib.with_parameters(parameters)),
        generic::slow_alternative(parameters)
            .map(|parameters| CompressorProfile::Custom.with_parameters(parameters)),
        windows::without_three_byte_references(parameters, info)
            .map(|parameters| CompressorProfile::Windows.with_parameters(parameters))
            .or_else(|| {
                windows::table_hash_alternative(parameters, info)
                    .map(|parameters| CompressorProfile::Custom.with_parameters(parameters))
            }),
    ]
}

pub fn candidate_hashes(
    mem_level: u32,
    info: &PreflateStreamInfo,
    add_policy: DictionaryAddPolicy,
) -> impl Iterator<Item = HashAlgorithm> {
    let primary = if info.min_len == 3 {
        [
            miniz::FAST_HASH,
            crate::compressors::libdeflate::CHAIN_HASH,
            crate::compressors::windows::HASH,
        ]
    } else {
        let [multiplicative, crc] = zlib_ng::HASHES;
        [libdeflate::fast_hash(add_policy), multiplicative, crc]
    };
    let mut alternates = zlib::candidate_hashes(mem_level);
    if let Some(chromium) = chromium::hash_candidate(&info.chromium_short_matches) {
        // Preserve the memory candidate; replace small first, then default.
        if alternates.small.is_some() {
            alternates.small = Some(chromium);
        } else if alternates.default.is_some() {
            alternates.default = Some(chromium);
        }
    }
    const HASH_CANDIDATE_BUDGET: usize = 7;
    let proposed = [
        Some(primary[0]),
        Some(primary[1]),
        Some(primary[2]),
        Some(alternates.memory),
        alternates.default,
        alternates.small,
        zlib::adjacent_memory_hash(info, add_policy),
    ];
    let mut candidates = [None; HASH_CANDIDATE_BUDGET];
    let mut count = 0;
    for hash in proposed.into_iter().flatten() {
        if !candidates[..count].contains(&Some(hash)) {
            candidates[count] = Some(hash);
            count += 1;
        }
    }
    candidates.into_iter().flatten()
}

pub fn chain_add_policy(
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

pub fn evidence_policy(hash: HashAlgorithm) -> ParserEvidencePolicy {
    match hash {
        HashAlgorithm::Libdeflate4 => libdeflate::evidence_policy(),
        _ => ParserEvidencePolicy::default(),
    }
}

fn inferred_profile(parameters: ReconstructionParameters) -> EstimationResult {
    zlib_ng::inferred(parameters).map_or(
        CompressorProfile::Custom.with_parameters(parameters),
        |parameters| CompressorProfile::ZlibNg.with_parameters(parameters),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compressors::{
            windows::HASH as WINDOWS_HASH,
            zlib::{DEFAULT_HASH, SHORT_MATCH_CUTOFF},
        },
        estimator::{
            depth_estimator::DistancePolicy,
            models::zlib::{
                SLOW_PREFLATE_PARSER_SETTINGS, ZLIB_PREFLATE_PARSER_SETTINGS,
                compatible as zlib_compatible,
            },
            test_support::initial_stream_info,
        },
        hash_algorithm::HashAlgorithm,
        parameters::{DictionaryAddPolicy, tests::MatchingType},
        reconstruction_parameters::BehaviorSettings,
        token_predictor::tests::zlib_level_1_params,
    };

    fn stream_info() -> PreflateStreamInfo {
        let mut info = initial_stream_info();
        info.max_dist_3_matches = 3;
        info
    }

    fn initial(info: &PreflateStreamInfo, evidence: CandidateEvidence) -> InitialEstimate<'_> {
        InitialEstimate {
            window_bits: 9,
            ..InitialEstimate::test_fixture(info, evidence)
        }
    }

    fn parameters(evidence: &CandidateEvidence) -> ReconstructionParameters {
        {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(evidence.hash_algorithm);
            canonical_configuration
                .set_full_window(evidence.distance_policy == DistancePolicy::FullWindow);
            canonical_configuration.set_window_bits(9);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_nice_length(if evidence.required_chain == 1 {
                255
            } else {
                258
            });
            canonical_configuration.set_max_chain(evidence.required_chain);
            canonical_configuration.set_short_match_cutoff(3);
            canonical_configuration.set_matching_type(MatchingType::Greedy);
            canonical_configuration
        }
    }

    #[test]
    fn zlib_distance_boundary_is_inclusive() {
        let mut parameters = crate::token_predictor::tests::zlib_level_1_params();
        parameters.set_insertion(DictionaryAddPolicy::AddAll);
        for (distance, expected) in [(0, true), (4095, true), (4096, true), (4097, false)] {
            parameters.set_short_match_cutoff(distance);
            assert_eq!(
                zlib_compatible(&parameters),
                expected,
                "distance={distance}"
            );
            assert!(!zlib_compatible(&{
                let mut canonical_configuration = parameters;
                canonical_configuration.set_full_window(true);
                canonical_configuration
            }));
            // Fast zlib does not use the lazy parser's TOO_FAR rejection.
            assert!(zlib_compatible(&{
                let mut canonical_configuration = parameters;
                canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(4));
                canonical_configuration
            }));
        }
        parameters.set_short_match_cutoff(4096);
        parameters.set_matches_to_start(true);
        assert!(!zlib_compatible(&parameters));
    }

    #[test]
    fn generic_profile_defaults_preserve_budgets_and_family_settings() {
        let info = stream_info();
        for required_chain in 1..=4096 {
            let evidence = CandidateEvidence {
                hash_algorithm: HashAlgorithm::Zlib {
                    hash_mask: 32767,
                    hash_shift: 5,
                },
                required_chain,
                distance_policy: DistancePolicy::ZlibWindow,
                parser: ParserInference::Unresolved,
                shallow_miniz_greedy: false,
                minimum_nice_length: 0,
            };
            for add_policy in [
                DictionaryAddPolicy::AddAll,
                DictionaryAddPolicy::AddFirst(4),
                DictionaryAddPolicy::AddFirstAndLast(4),
                DictionaryAddPolicy::AddFirstWith32KBoundary,
                DictionaryAddPolicy::AddFirstExcept4kBoundary,
            ] {
                let base = {
                    let mut canonical_configuration = parameters(&evidence);
                    canonical_configuration.set_insertion(add_policy);
                    canonical_configuration
                };
                let settings = if add_policy == DictionaryAddPolicy::AddAll {
                    &SLOW_PREFLATE_PARSER_SETTINGS[..]
                } else {
                    &ZLIB_PREFLATE_PARSER_SETTINGS[..]
                };
                let config = settings
                    .iter()
                    .find(|config| required_chain <= config.max_chain);
                let expected = {
                    let mut canonical_configuration = base;
                    canonical_configuration.set_nice_length(
                        config
                            .filter(|config| {
                                matches!(config.parser.matching_type(), MatchingType::Lazy { .. })
                                    || matches!(
                                        add_policy,
                                        DictionaryAddPolicy::AddFirst(4)
                                            | DictionaryAddPolicy::AddFirstAndLast(4)
                                            | DictionaryAddPolicy::AddFirstWith32KBoundary
                                    )
                            })
                            .map_or(base.nice_length(), |config| config.nice_length),
                    );
                    canonical_configuration.set_matching_type(
                        config.map_or(MatchingType::Greedy, |config| config.parser.matching_type()),
                    );
                    canonical_configuration
                };
                let mut initial = initial(&info, evidence);
                initial.insertion = add_policy;
                let selection = select_compressor_profile(&initial);
                assert!(matches!(
                    selection.provenance,
                    EstimateProvenance::Inferred(_)
                ));
                assert_eq!(selection.parameters(), expected);
            }
        }
    }

    #[test]
    fn libdeflate_profiles_keep_coupled_settings_at_depth_boundaries() {
        let info = stream_info();
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
                shallow_miniz_greedy: false,
                minimum_nice_length: 0,
                parser: if greedy {
                    ParserInference::Greedy
                } else {
                    ParserInference::Unresolved
                },
            };
            let base = parameters(&evidence);
            let selection = select_compressor_profile(&initial(&info, evidence));
            assert!(matches!(
                selection.provenance,
                EstimateProvenance::Fingerprinted
            ));
            assert_eq!(selection.parameters(), {
                let mut canonical_configuration = base;
                canonical_configuration.set_window_bits(window);
                canonical_configuration.set_nice_length(nice);
                canonical_configuration.set_max_chain(budget);
                canonical_configuration.set_short_match_cutoff(short_distance);
                canonical_configuration.set_matching_type(matching);
                canonical_configuration
            });
        }
    }

    #[test]
    fn miniz_and_fast_profiles_preserve_their_own_budgets() {
        let mut info = stream_info();
        info.max_dist_3_matches = 4097;
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
                shallow_miniz_greedy: false,
                minimum_nice_length: 0,
                parser: if greedy {
                    ParserInference::Greedy
                } else {
                    ParserInference::Unresolved
                },
            };
            let base = {
                let mut canonical_configuration = parameters(&evidence);
                canonical_configuration.set_short_match_cutoff(4097);
                canonical_configuration
            };
            let selection = select_compressor_profile(&initial(&info, evidence));
            assert!(matches!(
                selection.provenance,
                EstimateProvenance::Fingerprinted
            ));
            assert_eq!(selection.parameters(), {
                let mut canonical_configuration = base;
                canonical_configuration.set_window_bits(15);
                canonical_configuration.set_nice_length(258);
                canonical_configuration.set_max_chain(u32::from(probes).div_ceil(3) * 3);
                canonical_configuration.set_matching_type(MatchingType::MiniZ {
                    max_probes: probes,
                    greedy,
                });
                canonical_configuration
            });
        }
        let info = stream_info();
        for hash in [
            HashAlgorithm::Libdeflate4Fast,
            HashAlgorithm::Libdeflate4Fast15,
        ] {
            let evidence = CandidateEvidence {
                hash_algorithm: hash,
                required_chain: 1,
                distance_policy: DistancePolicy::FullWindow,
                parser: ParserInference::Unresolved,
                shallow_miniz_greedy: false,
                minimum_nice_length: 0,
            };
            let base = parameters(&evidence);
            let fastest = hash == HashAlgorithm::Libdeflate4Fast15;
            let selection = select_compressor_profile(&initial(&info, evidence));
            assert!(matches!(
                selection.provenance,
                EstimateProvenance::Fingerprinted
            ));
            assert_eq!(selection.parameters(), {
                let mut canonical_configuration = base;
                canonical_configuration.set_window_bits(if fastest { 15 } else { 9 });
                canonical_configuration.set_nice_length(32);
                canonical_configuration.set_max_chain(if fastest { 2 } else { 1 });
                canonical_configuration.set_matching_type(MatchingType::Greedy);
                canonical_configuration
            });
        }
    }

    #[test]
    fn protected_provenance_preserves_the_complete_profile() {
        let profile = CompressorProfile::Custom
            .with_parameters(crate::token_predictor::tests::zlib_level_1_params());
        for provenance in [
            EstimateProvenance::Fingerprinted,
            EstimateProvenance::PrefixValidated,
        ] {
            let estimate = ParameterEstimate {
                profile,
                provenance,
            };
            assert_eq!(estimate.parameters(), profile.reconstruction);
            assert_eq!(
                estimate.resolve_profile(
                    ParserInference::Lazy {
                        longest_deferred_match: 7,
                    },
                    4,
                ),
                profile
            );
        }
    }

    #[test]
    fn memory_hash_reuses_only_an_identical_generic_lazy_slot() {
        let settings = &zlib::SLOW_PREFLATE_PARSER_SETTINGS[2];
        let baseline = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(crate::compressors::windows::HASH);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_nice_length(settings.nice_length);
            canonical_configuration.set_max_chain(settings.max_chain);
            canonical_configuration
                .set_short_match_cutoff(crate::compressors::zlib::SHORT_MATCH_CUTOFF);
            canonical_configuration.set_matching_type(settings.parser.matching_type());
            canonical_configuration.max_token_count = 2047;
            canonical_configuration
        };
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
        info.max_tokens_per_block = 2047;
        let candidates = profile_alternatives(baseline, &info, &[]);
        assert_eq!(candidates.len(), 11);
        assert_eq!(
            candidates[5],
            zlib::memory_hash_alternative(baseline, &info)
                .map(|parameters| CompressorProfile::Zlib.with_parameters(parameters))
        );
        assert!(matches!(
            candidates[5],
            Some(EstimationResult {
                model: CompressorProfile::Zlib,
                ..
            })
        ));
        for parameters in [
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_max_chain(32);
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_nice_length(258);
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_matching_type(
                    crate::parameters::tests::MatchingType::Lazy {
                        max_lazy: 16,
                        filtered_matching: false,
                        behavior: crate::parameters::LazyBehavior::RecomputeAfterLiteral,
                    },
                );
                canonical_configuration
            },
        ] {
            assert_eq!(
                profile_alternatives(parameters, &info, &[])[5],
                generic::alternatives(parameters)[1]
                    .map(|parameters| CompressorProfile::Custom.with_parameters(parameters))
            );
        }
    }

    #[test]
    fn filtered_hash_reuses_an_empty_generic_lazy_slot() {
        let settings = &zlib::SLOW_PREFLATE_PARSER_SETTINGS[2];
        let baseline = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4Fast);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_nice_length(settings.nice_length);
            canonical_configuration.set_max_chain(126);
            canonical_configuration.set_short_match_cutoff(0);
            canonical_configuration.set_matching_type(settings.parser.matching_type());
            canonical_configuration.max_token_count = 16383;
            canonical_configuration
        };
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
        info.min_len = 6;
        info.max_tokens_per_block = u32::from(baseline.max_token_count);
        assert_eq!(generic::alternatives(baseline)[1], None);
        let candidates = profile_alternatives(baseline, &info, &[]);
        assert_eq!(candidates.len(), 11);
        assert_eq!(
            candidates[5],
            zlib::filtered_hash(baseline, &info)
                .map(|parameters| CompressorProfile::Zlib.with_parameters(parameters)),
        );
        assert!(matches!(
            candidates[5],
            Some(EstimationResult {
                model: CompressorProfile::Zlib,
                ..
            })
        ));
        info.min_len = 5;
        assert_eq!(profile_alternatives(baseline, &info, &[])[5], None);
    }

    #[test]
    fn noncanonical_insertion_reuses_the_generic_lazy_slot() {
        let parameters = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(147));
            canonical_configuration
        };
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
        info.min_len = 3;
        info.max_tokens_per_block = 12288;
        let candidates = profile_alternatives(parameters, &info, &[]);
        assert_eq!(candidates.len(), 11);
        assert_eq!(
            candidates[5],
            zlib::noncanonical_insertion(parameters, &info)
                .map(|parameters| CompressorProfile::Zlib.with_parameters(parameters))
        );
    }

    #[test]
    fn shared_hash_observations_do_not_imply_a_family() {
        let mut info = initial_stream_info();
        info.max_len = 8;
        let mut evidence = CandidateEvidence {
            hash_algorithm: DEFAULT_HASH,
            required_chain: 3,
            distance_policy: DistancePolicy::ZlibWindow,
            parser: ParserInference::Unresolved,
            shallow_miniz_greedy: false,
            minimum_nice_length: 0,
        };
        assert!(matches!(
            select_compressor_profile(&InitialEstimate::test_fixture(&info, evidence)),
            ParameterEstimate {
                profile: EstimationResult {
                    model: CompressorProfile::Custom,
                    ..
                },
                provenance: EstimateProvenance::Inferred(_),
            }
        ));
        info.max_dist_3_matches += 1;
        assert!(matches!(
            select_compressor_profile(&InitialEstimate::test_fixture(&info, evidence)),
            ParameterEstimate {
                profile: EstimationResult {
                    model: CompressorProfile::MiniZ,
                    ..
                },
                provenance: EstimateProvenance::Fingerprinted,
            }
        ));
        evidence.hash_algorithm = WINDOWS_HASH;
        info.max_dist_3_matches = SHORT_MATCH_CUTOFF;
        assert!(matches!(
            select_compressor_profile(&InitialEstimate::test_fixture(&info, evidence)),
            ParameterEstimate {
                profile: EstimationResult {
                    model: CompressorProfile::Custom,
                    ..
                },
                provenance: EstimateProvenance::Inferred(_),
            }
        ));
    }

    #[test]
    fn inferred_family_candidates_remain_refinable_and_fingerprints_remain_protected() {
        let mut info = initial_stream_info();
        info.max_len = 8;
        info.max_dist_3_matches = 32488;
        let evidence = CandidateEvidence {
            hash_algorithm: HashAlgorithm::Crc32cHash,
            required_chain: 3,
            distance_policy: DistancePolicy::ZlibWindow,
            parser: ParserInference::Unresolved,
            shallow_miniz_greedy: false,
            minimum_nice_length: 0,
        };
        let mut initial = InitialEstimate::test_fixture(&info, evidence);
        initial.insertion = DictionaryAddPolicy::AddFirstAndLast(4);
        let selected = select_compressor_profile(&initial);
        assert!(matches!(
            selected,
            ParameterEstimate {
                profile: EstimationResult {
                    model: CompressorProfile::ZlibNg,
                    ..
                },
                provenance: EstimateProvenance::Inferred(_),
            }
        ));
        let resolved = selected.resolve_profile(
            ParserInference::Lazy {
                longest_deferred_match: 7,
            },
            3,
        );
        assert!(matches!(
            resolved,
            EstimationResult {
                model: CompressorProfile::ZlibNg,
                ..
            }
        ));
        assert!(matches!(
            resolved.reconstruction.matching_type(),
            MatchingType::Greedy
        ));
        let parameters = {
            let mut parameters = zlib_level_1_params();
            parameters.set_hash_algorithm(HashAlgorithm::Crc32cHash);
            parameters.set_insertion(DictionaryAddPolicy::AddFirstAndLast(4));
            parameters
        };
        let unresolved = inferred_profile({
            let mut canonical_configuration = parameters;
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(4));
            canonical_configuration
        });
        assert!(matches!(
            unresolved,
            EstimationResult {
                model: CompressorProfile::Custom,
                ..
            }
        ));
        let resolved = ParameterEstimate {
            profile: unresolved,
            provenance: EstimateProvenance::Inferred(ParserContext {
                zlib_compatible: true,
                observed_min_len: 3,
            }),
        }
        .resolve_profile(
            ParserInference::Lazy {
                longest_deferred_match: 7,
            },
            3,
        );
        assert!(matches!(
            resolved.reconstruction.matching_type(),
            MatchingType::Lazy { .. }
        ));

        let evidence = CandidateEvidence {
            hash_algorithm: HashAlgorithm::Chromium { hash_mask: 0x7fff },
            ..evidence
        };
        let mut initial = InitialEstimate::test_fixture(&info, evidence);
        initial.insertion = DictionaryAddPolicy::AddFirst(4);
        let selected = select_compressor_profile(&initial);
        assert!(matches!(
            selected,
            ParameterEstimate {
                profile: EstimationResult {
                    model: CompressorProfile::Chromium,
                    ..
                },
                provenance: EstimateProvenance::Fingerprinted,
            }
        ));
        let expected = selected.parameters();
        let resolved = selected.resolve_profile(
            ParserInference::Lazy {
                longest_deferred_match: 7,
            },
            3,
        );
        assert_eq!(resolved.reconstruction, expected);
        assert!(matches!(
            resolved,
            EstimationResult {
                model: CompressorProfile::Chromium,
                ..
            }
        ));
    }

    #[test]
    fn uncovered_miniz_probe_budgets_keep_the_generic_fallback_protected() {
        let mut info = stream_info();
        info.max_dist_3_matches = 8191;
        for (required_chain, parser) in [
            (34, ParserInference::Greedy),
            (1501, ParserInference::Unresolved),
        ] {
            let evidence = CandidateEvidence {
                hash_algorithm: DEFAULT_HASH,
                required_chain,
                distance_policy: DistancePolicy::ZlibWindow,
                parser,
                shallow_miniz_greedy: false,
                minimum_nice_length: 0,
            };
            let initial = initial(&info, evidence);
            let mut expected = generic::candidate(&initial, false);
            expected.chain_common_mut().unwrap().search.nice_length = 258;
            let selected = select_compressor_profile(&initial);
            assert_eq!(selected.profile.model, CompressorProfile::MiniZ);
            assert!(matches!(
                selected.provenance,
                EstimateProvenance::Fingerprinted
            ));
            assert_eq!(selected.parameters(), expected);
            assert_eq!(
                selected.parameters().budget().unwrap().max_chain,
                required_chain
            );
            assert!(matches!(
                selected.parameters().behavior,
                BehaviorSettings::Chain { .. }
            ));
            let resolved = selected.resolve_profile(
                ParserInference::Lazy {
                    longest_deferred_match: 7,
                },
                258,
            );
            assert_eq!(resolved.reconstruction, expected);
        }
    }

    #[test]
    fn family_partitioning_preserves_the_other_refinement_slots() {
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
        info.min_len = 3;
        info.max_tokens_per_block = 128;
        for distance in [0, 4096, 4097, 8191] {
            info.max_dist_3_matches = distance;
            for hash in [
                crate::compressors::zlib::DEFAULT_HASH,
                crate::compressors::windows::HASH,
                crate::compressors::libdeflate::CHAIN_HASH,
                HashAlgorithm::Chromium { hash_mask: 0x7fff },
            ] {
                for insertion in [
                    DictionaryAddPolicy::AddAll,
                    DictionaryAddPolicy::AddFirst(32),
                    DictionaryAddPolicy::AddFirstAndLast(0),
                ] {
                    for max_chain in [3, 100, 128] {
                        let parameters = {
                            let mut canonical_configuration =
                                crate::token_predictor::tests::zlib_level_1_params();
                            canonical_configuration.set_hash_algorithm(hash);
                            canonical_configuration.set_insertion(insertion);
                            canonical_configuration.set_max_chain(max_chain);
                            canonical_configuration.set_matching_type(
                                zlib::SLOW_PREFLATE_PARSER_SETTINGS[0]
                                    .parser
                                    .matching_type(),
                            );
                            canonical_configuration.max_token_count = 1023;
                            canonical_configuration
                        };
                        let [insertion, lazy] = generic::alternatives(parameters);
                        let [fast_chromium, slow_chromium] =
                            chromium::alternatives(parameters, &info);
                        let expected = [
                            miniz::shallow_alternative(parameters, &info),
                            windows::shallow_greedy_alternative(parameters, &info),
                            windows::alternative(parameters, &info),
                            windows::partial_slow_alternative(parameters, &info),
                            insertion,
                            zlib::noncanonical_insertion(parameters, &info)
                                .map(|parameters| {
                                    CompressorProfile::Zlib.with_parameters(parameters)
                                })
                                .map(|profile| profile.reconstruction)
                                .or(lazy),
                            fast_chromium,
                            slow_chromium,
                            zlib::flush_alternative(parameters, &info),
                            generic::slow_alternative(parameters),
                            windows::table_hash_alternative(parameters, &info),
                        ];
                        assert_eq!(
                            profile_alternatives(parameters, &info, &[])
                                .map(|candidate| candidate.map(|result| result.reconstruction)),
                            expected
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn table_hash_only_refinement_retains_custom_profile_identity() {
        let parameters = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(crate::compressors::libdeflate::CHAIN_HASH);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_matching_type(
                crate::parameters::tests::MatchingType::LibdeflateLazy {
                    two_positions: true,
                },
            );
            canonical_configuration
        };
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
        info.min_len = 3;
        info.max_dist_3_matches = 4096;
        let candidate = profile_alternatives(parameters, &info, &[])[10].unwrap();
        assert!(matches!(
            candidate,
            EstimationResult {
                model: CompressorProfile::Custom,
                ..
            }
        ));
        let parameters = candidate.reconstruction;
        assert_eq!(
            parameters.hash_algorithm(),
            crate::compressors::windows::HASH
        );
        assert!(matches!(
            parameters.matching_type(),
            crate::parameters::tests::MatchingType::Lazy { .. }
        ));
    }

    #[test]
    fn no_short_match_profile_reuses_the_table_hash_refinement_slot() {
        let parameters = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4Fast);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_max_chain(4096);
            canonical_configuration.set_matching_type(
                zlib::SLOW_PREFLATE_PARSER_SETTINGS[0]
                    .parser
                    .matching_type(),
            );
            canonical_configuration
        };
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
        info.min_len = 5;
        info.max_tokens_per_block = 16384;
        let alternatives = profile_alternatives(parameters, &info, &[]);
        assert_eq!(alternatives.len(), 11);
        assert!(windows::table_hash_alternative(parameters, &info).is_none());
        assert!(matches!(
            alternatives[10],
            Some(EstimationResult {
                model: CompressorProfile::Windows,
                ..
            })
        ));
        assert_eq!(alternatives[10].unwrap().reconstruction, {
            let mut canonical_configuration = parameters;
            canonical_configuration.set_hash_algorithm(crate::compressors::windows::HASH);
            canonical_configuration.set_nice_length(258);
            canonical_configuration.set_max_chain(100);
            canonical_configuration.set_matching_type(
                crate::parameters::tests::MatchingType::WindowsLazy { max_lazy: 258 },
            );
            canonical_configuration.max_token_count = 16384;
            canonical_configuration
        });
    }

    #[test]
    fn complete_estimation_retains_family_profiles() {
        use crate::{
            deflate::deflate_reader::tests::parse_deflate_whole,
            estimator::preflate_parameter_estimator::estimate_preflate_profile,
        };
        let profile = |name| {
            let compressed = crate::utils::read_file(name);
            let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
            estimate_preflate_profile(&contents, &plain).unwrap()
        };
        assert!(matches!(
            profile("compressed_flate2_level2.deflate"),
            candidate if candidate.model == CompressorProfile::MiniZ && matches!(candidate.reconstruction.matching_type(),
                crate::parameters::tests::MatchingType::MiniZ { greedy: true, .. })
        ));
        assert!(matches!(
            profile("compressed_flate2_level6.deflate"),
            candidate if candidate.model == CompressorProfile::MiniZ && matches!(candidate.reconstruction.matching_type(),
                crate::parameters::tests::MatchingType::MiniZ { greedy: false, .. })
        ));
        assert!(matches!(
            profile("compressed_libdeflate_level2.deflate"),
            candidate if candidate.model == CompressorProfile::Libdeflate && candidate.reconstruction.matching_type() == crate::parameters::tests::MatchingType::LibdeflateGreedy
        ));
        assert!(matches!(
            profile("compressed_libdeflate_level5.deflate"),
            candidate if candidate.model == CompressorProfile::Libdeflate && matches!(candidate.reconstruction.matching_type(),
                crate::parameters::tests::MatchingType::LibdeflateLazy { .. })
        ));
        assert!(matches!(
            profile("compressed_chromium_level1.deflate"),
            candidate if candidate.model == CompressorProfile::Chromium && candidate.reconstruction.matching_type() == crate::parameters::tests::MatchingType::Greedy
        ));
        assert!(matches!(
            profile("compressed_chromium_level6.deflate"),
            candidate if candidate.model == CompressorProfile::Chromium && matches!(candidate.reconstruction.matching_type(),
                crate::parameters::tests::MatchingType::Lazy { .. })
        ));
        assert!(matches!(
            profile("compressed_zlibng_level1.deflate"),
            candidate if candidate.model == CompressorProfile::ZlibNg && candidate.reconstruction.hash_algorithm() == HashAlgorithm::Crc32cHash
        ));
    }

    #[test]
    fn hash_candidate_budget_and_confidence_preserve_existing_order() {
        for memory_level in 1..=9 {
            let memory = crate::compressors::zlib::memory_hash(memory_level);
            let mut expected_zlib = vec![memory];
            for hash in [
                crate::compressors::zlib::DEFAULT_HASH,
                crate::compressors::zlib::memory_hash(4),
            ] {
                if !expected_zlib.contains(&hash) {
                    expected_zlib.push(hash);
                }
            }
            for minimum in [3, 4, 6] {
                for insertion in [
                    DictionaryAddPolicy::AddAll,
                    DictionaryAddPolicy::AddFirst(4),
                ] {
                    let mut info =
                        crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
                    info.min_len = minimum;
                    let primary = if minimum == 3 {
                        [
                            miniz::FAST_HASH,
                            crate::compressors::libdeflate::CHAIN_HASH,
                            crate::compressors::windows::HASH,
                        ]
                    } else {
                        let [multiplicative, crc] = zlib_ng::HASHES;
                        [libdeflate::fast_hash(insertion), multiplicative, crc]
                    };
                    let expected: Vec<_> = primary
                        .into_iter()
                        .chain(expected_zlib.iter().copied())
                        .collect();
                    for supported in [false, true] {
                        info.max_tokens_per_block = (1 << (memory_level + 6)) - 1;
                        info.max_unflushed_tokens_per_block = if supported {
                            info.max_tokens_per_block
                        } else {
                            0
                        };
                        assert_eq!(
                            zlib::supported_memory_hash(&info),
                            supported.then_some(memory)
                        );
                        let mut expected = expected.clone();
                        if let Some(adjacent) = zlib::adjacent_memory_hash(&info, insertion)
                            && !expected.contains(&adjacent)
                        {
                            expected.push(adjacent);
                        }
                        let actual: Vec<_> =
                            candidate_hashes(memory_level, &info, insertion).collect();
                        assert_eq!(actual, expected);
                        assert!(actual.len() <= 7);
                        for (index, hash) in actual.iter().enumerate() {
                            assert!(!actual[..index].contains(hash));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn candidate_order_and_duplicate_suppression_preserve_ambiguous_searches() {
        use crate::estimator::preflate_stream_info::tests::extract_preflate_info;

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
            for minimum in [3, 4, 5, 6] {
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

    impl ParameterEstimate {
        pub fn resolve_parser(
            self,
            inference: ParserInference,
            longest_match: u32,
        ) -> ReconstructionParameters {
            self.resolve_profile(inference, longest_match)
                .reconstruction
        }
    }
}
