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

use crate::{
    estimator::{
        CandidateEvidence, HashTableDepthEstimator, ParameterEstimate, ParserContext,
        ParserEvidencePolicy, PreflateStreamInfo,
    },
    parameters::{DictionaryAddPolicy, TokenPredictorParameters},
};

/// A family-owned model candidate, not a claim that its producer has been identified.
/// Custom profiles retain combinations that do not establish a known family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompressorProfile {
    Zlib(zlib::Profile),
    ZlibNg(zlib_ng::Profile),
    MiniZ(miniz::Profile),
    Libdeflate(libdeflate::Profile),
    Windows(windows::Profile),
    Chromium(chromium::Profile),
    Custom(TokenPredictorParameters),
}

impl CompressorProfile {
    pub(crate) fn parameters(self) -> TokenPredictorParameters {
        match self {
            Self::Zlib(profile) => profile.parameters(),
            Self::ZlibNg(profile) => profile.parameters(),
            Self::MiniZ(profile) => profile.parameters(),
            Self::Libdeflate(profile) => profile.parameters(),
            Self::Windows(profile) => profile.parameters(),
            Self::Chromium(profile) => profile.parameters(),
            Self::Custom(parameters) => parameters,
        }
    }

    fn parameters_mut(&mut self) -> &mut TokenPredictorParameters {
        match self {
            Self::Zlib(profile) => profile.parameters_mut(),
            Self::ZlibNg(profile) => profile.parameters_mut(),
            Self::MiniZ(profile) => profile.parameters_mut(),
            Self::Libdeflate(profile) => profile.parameters_mut(),
            Self::Windows(profile) => profile.parameters_mut(),
            Self::Chromium(profile) => profile.parameters_mut(),
            Self::Custom(parameters) => parameters,
        }
    }

    pub(crate) fn inferred(parameters: TokenPredictorParameters) -> Self {
        zlib_ng::Profile::inferred(parameters).map_or(Self::Custom(parameters), Self::ZlibNg)
    }

    pub(crate) fn refine_short_match_policy(&mut self, info: &PreflateStreamInfo, rejections: u16) {
        zlib::refine_short_match_policy(self.parameters_mut(), info, rejections);
    }

    pub(crate) fn canonicalize_unobserved_insertion(&mut self, longest_match: u32) {
        let parameters = self.parameters_mut();
        if matches!(parameters.add_policy,
            DictionaryAddPolicy::AddFirst(limit) | DictionaryAddPolicy::AddFirstAndLast(limit)
                if u32::from(limit) >= longest_match)
        {
            parameters.add_policy = DictionaryAddPolicy::AddAll;
        }
    }

    pub(crate) fn canonicalize_first_only_insertion(&mut self, plaintext_bytes: u32) {
        let parameters = self.parameters_mut();
        if parameters.add_policy == DictionaryAddPolicy::AddFirst(0)
            && plaintext_bytes <= zlib_ng::SLIDE_POINT
        {
            // No later token can observe an insertion at the slide point.
            parameters.add_policy = DictionaryAddPolicy::AddFirstWith32KBoundary;
        }
    }

    pub(crate) fn canonical_token_limit(self, bounds: (u32, u32)) -> u16 {
        let original = self.parameters().max_token_count;
        debug_assert!(bounds.0 <= u32::from(original) && u32::from(original) <= bounds.1);
        let maximum = if original <= u16::from(u8::MAX) {
            u16::from(u8::MAX)
        } else {
            u16::MAX
        };
        // Share a small buffer on tiny streams without inflating decoder reservations.
        [1023, 2047, 4095, 8191, 16383, 32767, 65535, 511, 255, 127]
            .into_iter()
            .find(|&limit| {
                limit <= maximum && bounds.0 <= u32::from(limit) && u32::from(limit) <= bounds.1
            })
            .unwrap_or(original)
    }
}

pub(crate) fn select_profile(
    parameters: TokenPredictorParameters,
    evidence: &CandidateEvidence,
    observed_min_len: u32,
) -> ParameterEstimate {
    if let Some(profile) = chromium::Profile::fingerprint(parameters, evidence) {
        return ParameterEstimate::Fingerprinted(CompressorProfile::Chromium(profile));
    }
    let parser = ParserContext {
        zlib_compatible: zlib::compatible(&parameters),
        observed_min_len,
    };
    let parameters = generic::apply_defaults(
        parameters,
        evidence,
        parser.zlib_compatible,
        observed_min_len,
    );
    if parameters.add_policy == DictionaryAddPolicy::AddAll && !parser.zlib_compatible {
        let fingerprint = miniz::Profile::fingerprint(parameters, evidence)
            .map(CompressorProfile::MiniZ)
            .or_else(|| {
                libdeflate::Profile::fingerprint(parameters, evidence)
                    .map(CompressorProfile::Libdeflate)
            });
        if let Some(profile) = fingerprint {
            return ParameterEstimate::Fingerprinted(profile);
        }
    }
    ParameterEstimate::Inferred {
        profile: CompressorProfile::inferred(parameters),
        parser,
    }
}

pub(crate) fn preferred_depth_candidate<'a>(
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
                || prefer_miniz_hash && candidate.hash_algorithm() == zlib::DEFAULT_HASH
        })
        .map(|candidate| candidate.as_ref())
}

pub(crate) fn profile_alternatives(
    parameters: TokenPredictorParameters,
    info: &PreflateStreamInfo,
) -> [Option<CompressorProfile>; 11] {
    let [insertion, lazy] = generic::alternatives(parameters);
    let [windows_greedy, windows_lazy, windows_partial] =
        windows::Profile::alternatives(parameters, info);
    let [chromium_fast, chromium_lazy] = chromium::Profile::alternatives(parameters, info);
    let lazy = zlib::Profile::noncanonical_insertion(parameters, info)
        .map(CompressorProfile::Zlib)
        .or_else(|| {
            lazy.and_then(|candidate| {
                if candidate == parameters {
                    // Reuse the redundant slot when the shorter zlib prefix was ambiguous.
                    zlib::Profile::memory_hash(parameters, info).map(CompressorProfile::Zlib)
                } else {
                    Some(CompressorProfile::Custom(candidate))
                }
            })
            .or_else(|| zlib::Profile::filtered_hash(parameters, info).map(CompressorProfile::Zlib))
        })
        .or_else(|| {
            zlib::Profile::ambiguous_fast_hash(parameters, info).map(CompressorProfile::Zlib)
        });
    [
        miniz::Profile::shallow(parameters, info).map(CompressorProfile::MiniZ),
        windows_greedy.map(CompressorProfile::Windows),
        windows_lazy.map(CompressorProfile::Windows),
        windows_partial.map(CompressorProfile::Windows),
        insertion.map(CompressorProfile::Custom),
        lazy,
        chromium_fast.map(CompressorProfile::Chromium),
        chromium_lazy.map(CompressorProfile::Chromium),
        zlib::Profile::flush(parameters, info).map(CompressorProfile::Zlib),
        generic::slow_alternative(parameters).map(CompressorProfile::Custom),
        windows::Profile::without_three_byte_references(parameters, info)
            .map(CompressorProfile::Windows)
            .or_else(|| {
                windows::table_hash_alternative(parameters, info).map(CompressorProfile::Custom)
            }),
    ]
}

#[inline(always)]
pub(crate) fn hash_window_distance_limits(
    hash: HashAlgorithm,
    normal_prediction: bool,
    window: u32,
    history: u32,
) -> (u32, u32) {
    if normal_prediction && matches!(hash, HashAlgorithm::Chromium { .. }) {
        chromium::distance_limits(window, history)
    } else {
        zlib::distance_limits(window, history)
    }
}

#[test]
fn profile_parameter_reads_preserve_every_variant() {
    let parameters = crate::token_predictor::zlib_level_1_params();
    for mut profile in [
        CompressorProfile::Zlib(zlib::Profile(parameters)),
        CompressorProfile::ZlibNg(zlib_ng::Profile(parameters)),
        CompressorProfile::MiniZ(miniz::Profile(parameters)),
        CompressorProfile::Libdeflate(libdeflate::Profile(parameters)),
        CompressorProfile::Windows(windows::Profile(parameters)),
        CompressorProfile::Chromium(chromium::Profile(parameters)),
        CompressorProfile::Custom(parameters),
    ] {
        let original = profile;
        assert_eq!(profile.parameters(), parameters);
        assert_eq!(profile, original);
        profile.parameters_mut().nice_length = 42;
        assert_eq!(
            profile.parameters(),
            TokenPredictorParameters {
                nice_length: 42,
                ..parameters
            }
        );
    }
}

#[test]
fn first_only_canonicalization_requires_an_unobservable_slide_insertion() {
    let parameters = TokenPredictorParameters {
        add_policy: DictionaryAddPolicy::AddFirst(0),
        ..crate::token_predictor::zlib_level_1_params()
    };
    for (bytes, expected) in [
        (0, DictionaryAddPolicy::AddFirstWith32KBoundary),
        (
            zlib_ng::SLIDE_POINT,
            DictionaryAddPolicy::AddFirstWith32KBoundary,
        ),
        (zlib_ng::SLIDE_POINT + 1, DictionaryAddPolicy::AddFirst(0)),
    ] {
        let mut profile = CompressorProfile::Custom(parameters);
        profile.canonicalize_first_only_insertion(bytes);
        assert!(matches!(profile, CompressorProfile::Custom(_)));
        assert_eq!(profile.parameters().add_policy, expected);
        assert!(profile.parameters().serialized_size() <= parameters.serialized_size());
    }
}

#[test]
fn memory_hash_reuses_only_an_identical_generic_lazy_slot() {
    let settings = &zlib::SLOW_PREFLATE_PARSER_SETTINGS[2];
    let baseline = TokenPredictorParameters {
        hash_algorithm: windows::HASH,
        add_policy: DictionaryAddPolicy::AddAll,
        matching_type: settings.match_type,
        nice_length: settings.nice_length,
        max_chain: settings.max_chain,
        max_token_count: 2047,
        max_dist_3_matches: zlib::SHORT_MATCH_CUTOFF,
        ..crate::token_predictor::zlib_level_1_params()
    };
    let mut info = crate::estimator::extract_preflate_info(&[]);
    info.max_tokens_per_block = 2047;
    let candidates = profile_alternatives(baseline, &info);
    assert_eq!(candidates.len(), 11);
    assert_eq!(
        candidates[5],
        zlib::Profile::memory_hash(baseline, &info).map(CompressorProfile::Zlib)
    );
    assert!(matches!(candidates[5], Some(CompressorProfile::Zlib(_))));
    for parameters in [
        TokenPredictorParameters {
            max_chain: 32,
            ..baseline
        },
        TokenPredictorParameters {
            nice_length: 258,
            ..baseline
        },
        TokenPredictorParameters {
            matching_type: crate::parameters::MatchingType::Lazy {
                max_lazy: 16,
                filtered_matching: false,
                behavior: crate::parameters::LazyBehavior::RecomputeAfterLiteral,
            },
            ..baseline
        },
    ] {
        assert_eq!(
            profile_alternatives(parameters, &info)[5],
            generic::alternatives(parameters)[1].map(CompressorProfile::Custom)
        );
    }
}

#[test]
fn filtered_hash_reuses_an_empty_generic_lazy_slot() {
    let settings = &zlib::SLOW_PREFLATE_PARSER_SETTINGS[2];
    let baseline = TokenPredictorParameters {
        hash_algorithm: HashAlgorithm::Libdeflate4Fast,
        add_policy: DictionaryAddPolicy::AddAll,
        matching_type: settings.match_type,
        nice_length: settings.nice_length,
        max_chain: 126,
        max_token_count: 16383,
        max_dist_3_matches: 0,
        ..crate::token_predictor::zlib_level_1_params()
    };
    let mut info = crate::estimator::extract_preflate_info(&[]);
    info.min_len = 6;
    info.max_tokens_per_block = u32::from(baseline.max_token_count);
    assert_eq!(generic::alternatives(baseline)[1], None);
    let candidates = profile_alternatives(baseline, &info);
    assert_eq!(candidates.len(), 11);
    assert_eq!(
        candidates[5],
        zlib::Profile::filtered_hash(baseline, &info).map(CompressorProfile::Zlib),
    );
    assert!(matches!(candidates[5], Some(CompressorProfile::Zlib(_))));
    info.min_len = 5;
    assert_eq!(profile_alternatives(baseline, &info)[5], None);
}

#[test]
fn noncanonical_insertion_reuses_the_generic_lazy_slot() {
    let parameters = TokenPredictorParameters {
        hash_algorithm: HashAlgorithm::Libdeflate4,
        add_policy: DictionaryAddPolicy::AddFirst(147),
        ..crate::token_predictor::zlib_level_1_params()
    };
    let mut info = crate::estimator::extract_preflate_info(&[]);
    info.min_len = 3;
    info.max_tokens_per_block = 12288;
    let candidates = profile_alternatives(parameters, &info);
    assert_eq!(candidates.len(), 11);
    assert_eq!(
        candidates[5],
        zlib::Profile::noncanonical_insertion(parameters, &info).map(CompressorProfile::Zlib)
    );
}

pub(crate) enum MatchPrediction {
    Reference,
    Literal {
        pending_reference: Option<crate::deflate::deflate_token::DeflateTokenReference>,
        pending_literals: u8,
    },
}

pub(crate) fn block_minimum_match_length(
    parameters: &crate::reconstruction_parameters::BehaviorSettings,
    filtered_matching: bool,
    bytes: &[u8],
) -> u32 {
    use {
        crate::reconstruction_parameters::BehaviorSettings,
        crate::reconstruction_parameters::LazyMinimum,
    };
    match parameters {
        BehaviorSettings::LibdeflateGreedy(settings) => libdeflate::minimum_match_length(
            bytes,
            settings.common.search.budget.max_chain.saturating_sub(1),
        ),
        BehaviorSettings::LibdeflateLazy(settings) if filtered_matching => {
            libdeflate::minimum_match_length(
                bytes,
                settings.common.search.budget.max_chain.saturating_sub(1),
            )
        }
        BehaviorSettings::Lazy(settings)
            if filtered_matching && matches!(settings.minimum, LazyMinimum::FilteredSix) =>
        {
            zlib::FILTERED_MIN_MATCH_LENGTH
        }
        BehaviorSettings::NoDictionary { strategy: _ }
        | BehaviorSettings::Greedy(_)
        | BehaviorSettings::MiniZ(_)
        | BehaviorSettings::WindowsLazy(_)
        | BehaviorSettings::LibdeflateLazy(_)
        | BehaviorSettings::Lazy(_) => crate::deflate::deflate_constants::MIN_MATCH,
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

#[test]
fn hash_window_dispatch_keeps_family_limits_out_of_correction_recovery() {
    let chromium = HashAlgorithm::Chromium { hash_mask: 0x7fff };
    assert_eq!(
        hash_window_distance_limits(chromium, true, 32768, 65536),
        (32506, 32505)
    );
    for (hash, normal_prediction) in [
        (chromium, false),
        (zlib::DEFAULT_HASH, true),
        (zlib::DEFAULT_HASH, false),
        (windows::HASH, true),
        (HashAlgorithm::Crc32cHash, true),
        (libdeflate::CHAIN_HASH, true),
    ] {
        assert_eq!(
            hash_window_distance_limits(hash, normal_prediction, 32768, 65536),
            (32507, 32506),
            "hash={hash:?}, normal={normal_prediction}"
        );
        assert_eq!(
            hash_window_distance_limits(hash, normal_prediction, 512, 100),
            (100, 100)
        );
    }
}

#[test]
fn unobserved_insertion_limits_preserve_family_and_active_overrides() {
    let parameters = crate::token_predictor::zlib_level_1_params();
    for (policy, maximum, expected) in [
        (
            DictionaryAddPolicy::AddFirst(4),
            4,
            DictionaryAddPolicy::AddAll,
        ),
        (
            DictionaryAddPolicy::AddFirstAndLast(4),
            4,
            DictionaryAddPolicy::AddAll,
        ),
        (
            DictionaryAddPolicy::AddFirst(4),
            5,
            DictionaryAddPolicy::AddFirst(4),
        ),
        (
            DictionaryAddPolicy::AddFirstAndLast(4),
            5,
            DictionaryAddPolicy::AddFirstAndLast(4),
        ),
        (
            DictionaryAddPolicy::AddFirstExcept4kBoundary,
            4,
            DictionaryAddPolicy::AddFirstExcept4kBoundary,
        ),
        (
            DictionaryAddPolicy::AddFirstWith32KBoundary,
            4,
            DictionaryAddPolicy::AddFirstWith32KBoundary,
        ),
    ] {
        let parameters = TokenPredictorParameters {
            add_policy: policy,
            ..parameters
        };
        let mut profile = CompressorProfile::Zlib(zlib::Profile(parameters));
        profile.canonicalize_unobserved_insertion(maximum);
        assert!(matches!(profile, CompressorProfile::Zlib(_)));
        assert_eq!(profile.parameters().add_policy, expected);
        assert!(profile.parameters().serialized_size() <= parameters.serialized_size());
    }
}

#[test]
fn canonical_token_limits_preserve_bounds_width_and_idempotence() {
    let mut parameters = crate::token_predictor::zlib_level_1_params();
    for original in 0..=u16::MAX {
        parameters.max_token_count = original;
        let size = parameters.serialized_size();
        for bounds in [
            (0, u32::from(u16::MAX)),
            (u32::from(original), u32::from(original)),
            (u32::from(original / 2), u32::from(original)),
        ] {
            let limit = CompressorProfile::Custom(parameters).canonical_token_limit(bounds);
            assert!((bounds.0..=bounds.1).contains(&u32::from(limit)));
            let canonical = TokenPredictorParameters {
                max_token_count: limit,
                ..parameters
            };
            assert!(canonical.serialized_size() <= size);
            assert_eq!(
                CompressorProfile::Custom(canonical).canonical_token_limit(bounds),
                limit
            );
        }
    }
}

#[test]
fn shared_hash_observations_do_not_imply_a_family() {
    use crate::estimator::{DistancePolicy, ParserInference};

    let mut parameters = crate::token_predictor::zlib_level_1_params();
    parameters.add_policy = DictionaryAddPolicy::AddAll;
    parameters.max_dist_3_matches = zlib::SHORT_MATCH_CUTOFF;
    let mut evidence = CandidateEvidence {
        hash_algorithm: parameters.hash_algorithm,
        required_chain: 3,
        distance_policy: DistancePolicy::ZlibWindow,
        parser: ParserInference::Unresolved,
        shallow_miniz_greedy: false,
        minimum_nice_length: 0,
    };
    assert!(matches!(
        select_profile(parameters, &evidence, 3),
        ParameterEstimate::Inferred {
            profile: CompressorProfile::Custom(_),
            ..
        }
    ));
    parameters.max_dist_3_matches += 1;
    assert!(matches!(
        select_profile(parameters, &evidence, 3),
        ParameterEstimate::Fingerprinted(CompressorProfile::MiniZ(_))
    ));
    parameters.hash_algorithm = windows::HASH;
    evidence.hash_algorithm = windows::HASH;
    parameters.max_dist_3_matches = zlib::SHORT_MATCH_CUTOFF;
    assert!(matches!(
        select_profile(parameters, &evidence, 3),
        ParameterEstimate::Inferred {
            profile: CompressorProfile::Custom(_),
            ..
        }
    ));
}

#[test]
fn inferred_family_candidates_remain_refinable_and_fingerprints_remain_protected() {
    use crate::{
        estimator::{DistancePolicy, ParserInference},
        parameters::MatchingType,
    };

    let parameters = TokenPredictorParameters {
        hash_algorithm: HashAlgorithm::Crc32cHash,
        add_policy: DictionaryAddPolicy::AddFirstAndLast(4),
        ..crate::token_predictor::zlib_level_1_params()
    };
    let evidence = CandidateEvidence {
        hash_algorithm: parameters.hash_algorithm,
        required_chain: 3,
        distance_policy: DistancePolicy::ZlibWindow,
        parser: ParserInference::Unresolved,
        shallow_miniz_greedy: false,
        minimum_nice_length: 0,
    };
    let selected = select_profile(parameters, &evidence, 3);
    assert!(matches!(
        selected,
        ParameterEstimate::Inferred {
            profile: CompressorProfile::ZlibNg(_),
            ..
        }
    ));
    let resolved = selected.resolve_profile(
        ParserInference::Lazy {
            longest_deferred_match: 7,
        },
        3,
    );
    assert!(matches!(resolved, CompressorProfile::ZlibNg(_)));
    assert!(matches!(
        resolved.parameters().matching_type,
        MatchingType::Greedy
    ));
    let unresolved = CompressorProfile::inferred(TokenPredictorParameters {
        add_policy: DictionaryAddPolicy::AddFirst(4),
        ..parameters
    });
    assert!(matches!(unresolved, CompressorProfile::Custom(_)));
    let resolved = ParameterEstimate::Inferred {
        profile: unresolved,
        parser: ParserContext {
            zlib_compatible: true,
            observed_min_len: 3,
        },
    }
    .resolve_profile(
        ParserInference::Lazy {
            longest_deferred_match: 7,
        },
        3,
    );
    assert!(matches!(
        resolved.parameters().matching_type,
        MatchingType::Lazy { .. }
    ));

    let parameters = TokenPredictorParameters {
        hash_algorithm: HashAlgorithm::Chromium { hash_mask: 0x7fff },
        add_policy: DictionaryAddPolicy::AddFirst(4),
        ..parameters
    };
    let evidence = CandidateEvidence {
        hash_algorithm: parameters.hash_algorithm,
        ..evidence
    };
    let selected = select_profile(parameters, &evidence, 3);
    assert!(matches!(
        selected,
        ParameterEstimate::Fingerprinted(CompressorProfile::Chromium(_))
    ));
    let expected = selected.parameters();
    let resolved = selected.resolve_profile(
        ParserInference::Lazy {
            longest_deferred_match: 7,
        },
        3,
    );
    assert_eq!(resolved.parameters(), expected);
    assert!(matches!(resolved, CompressorProfile::Chromium(_)));
}

#[test]
fn family_partitioning_preserves_the_other_refinement_slots() {
    let mut info = crate::estimator::extract_preflate_info(&[]);
    info.min_len = 3;
    info.max_tokens_per_block = 128;
    for distance in [0, 4096, 4097, 8191] {
        info.max_dist_3_matches = distance;
        for hash in [
            zlib::DEFAULT_HASH,
            windows::HASH,
            libdeflate::CHAIN_HASH,
            HashAlgorithm::Chromium { hash_mask: 0x7fff },
        ] {
            for insertion in [
                DictionaryAddPolicy::AddAll,
                DictionaryAddPolicy::AddFirst(32),
                DictionaryAddPolicy::AddFirstAndLast(0),
            ] {
                for max_chain in [3, 100, 128] {
                    let parameters = TokenPredictorParameters {
                        hash_algorithm: hash,
                        add_policy: insertion,
                        max_chain,
                        matching_type: zlib::SLOW_PREFLATE_PARSER_SETTINGS[0].match_type,
                        max_token_count: 1023,
                        ..crate::token_predictor::zlib_level_1_params()
                    };
                    let [insertion, lazy] = generic::alternatives(parameters);
                    let [fast_chromium, slow_chromium] = chromium::alternatives(parameters, &info);
                    let expected = [
                        miniz::shallow_alternative(parameters, &info),
                        windows::shallow_greedy_alternative(parameters, &info),
                        windows::alternative(parameters, &info),
                        windows::partial_slow_alternative(parameters, &info),
                        insertion,
                        zlib::Profile::noncanonical_insertion(parameters, &info)
                            .map(CompressorProfile::Zlib)
                            .map(|profile| profile.parameters())
                            .or(lazy),
                        fast_chromium,
                        slow_chromium,
                        zlib::flush_alternative(parameters, &info),
                        generic::slow_alternative(parameters),
                        windows::table_hash_alternative(parameters, &info),
                    ];
                    assert_eq!(
                        profile_alternatives(parameters, &info)
                            .map(|candidate| candidate.map(CompressorProfile::parameters)),
                        expected
                    );
                }
            }
        }
    }
}

#[test]
fn table_hash_only_refinement_retains_custom_profile_identity() {
    let parameters = TokenPredictorParameters {
        hash_algorithm: libdeflate::CHAIN_HASH,
        add_policy: DictionaryAddPolicy::AddAll,
        matching_type: crate::parameters::MatchingType::LibdeflateLazy {
            two_positions: true,
        },
        ..crate::token_predictor::zlib_level_1_params()
    };
    let mut info = crate::estimator::extract_preflate_info(&[]);
    info.min_len = 3;
    info.max_dist_3_matches = 4096;
    let candidate = profile_alternatives(parameters, &info)[10].unwrap();
    assert!(matches!(candidate, CompressorProfile::Custom(_)));
    let parameters = candidate.parameters();
    assert_eq!(parameters.hash_algorithm, windows::HASH);
    assert!(matches!(
        parameters.matching_type,
        crate::parameters::MatchingType::Lazy { .. }
    ));
}

#[test]
fn no_short_match_profile_reuses_the_table_hash_refinement_slot() {
    let parameters = TokenPredictorParameters {
        hash_algorithm: HashAlgorithm::Libdeflate4Fast,
        add_policy: DictionaryAddPolicy::AddAll,
        matching_type: zlib::SLOW_PREFLATE_PARSER_SETTINGS[0].match_type,
        max_chain: 4096,
        ..crate::token_predictor::zlib_level_1_params()
    };
    let mut info = crate::estimator::extract_preflate_info(&[]);
    info.min_len = 5;
    info.max_tokens_per_block = 16384;
    let alternatives = profile_alternatives(parameters, &info);
    assert_eq!(alternatives.len(), 11);
    assert!(windows::table_hash_alternative(parameters, &info).is_none());
    assert!(matches!(
        alternatives[10],
        Some(CompressorProfile::Windows(_))
    ));
    assert_eq!(
        alternatives[10].unwrap().parameters(),
        TokenPredictorParameters {
            hash_algorithm: windows::HASH,
            matching_type: crate::parameters::MatchingType::WindowsLazy { max_lazy: 258 },
            nice_length: 258,
            max_chain: 100,
            max_token_count: 16384,
            ..parameters
        }
    );
}

#[test]
fn complete_estimation_retains_family_profiles() {
    use {
        crate::deflate::deflate_reader::parse_deflate_whole,
        crate::estimator::preflate_parameter_estimator::estimate_preflate_profile,
    };
    let profile = |name| {
        let compressed = crate::utils::read_file(name);
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        estimate_preflate_profile(&contents, &plain).unwrap()
    };
    assert!(matches!(
        profile("compressed_flate2_level2.deflate"),
        CompressorProfile::MiniZ(candidate) if matches!(candidate.parameters().matching_type,
            crate::MatchingType::MiniZ { greedy: true, .. })
    ));
    assert!(matches!(
        profile("compressed_flate2_level6.deflate"),
        CompressorProfile::MiniZ(candidate) if matches!(candidate.parameters().matching_type,
            crate::MatchingType::MiniZ { greedy: false, .. })
    ));
    assert!(matches!(
        profile("compressed_libdeflate_level2.deflate"),
        CompressorProfile::Libdeflate(candidate) if candidate.parameters().matching_type == crate::MatchingType::LibdeflateGreedy
    ));
    assert!(matches!(
        profile("compressed_libdeflate_level5.deflate"),
        CompressorProfile::Libdeflate(candidate) if matches!(candidate.parameters().matching_type,
            crate::MatchingType::LibdeflateLazy { .. })
    ));
    assert!(matches!(
        profile("compressed_chromium_level1.deflate"),
        CompressorProfile::Chromium(candidate) if candidate.parameters().matching_type == crate::MatchingType::Greedy
    ));
    assert!(matches!(
        profile("compressed_chromium_level6.deflate"),
        CompressorProfile::Chromium(candidate) if matches!(candidate.parameters().matching_type,
            crate::MatchingType::Lazy { .. })
    ));
    assert!(matches!(
        profile("compressed_zlibng_level1.deflate"),
        CompressorProfile::ZlibNg(candidate) if candidate.parameters().hash_algorithm == HashAlgorithm::Crc32cHash
    ));
}

#[test]
fn hash_candidate_budget_and_confidence_preserve_existing_order() {
    for memory_level in 1..=9 {
        let memory = zlib::memory_hash(memory_level);
        let mut expected_zlib = vec![memory];
        for hash in [zlib::DEFAULT_HASH, zlib::memory_hash(4)] {
            if !expected_zlib.contains(&hash) {
                expected_zlib.push(hash);
            }
        }
        for minimum in [3, 4, 6] {
            for insertion in [
                DictionaryAddPolicy::AddAll,
                DictionaryAddPolicy::AddFirst(4),
            ] {
                let mut info = crate::estimator::extract_preflate_info(&[]);
                info.min_len = minimum;
                let primary = if minimum == 3 {
                    [miniz::FAST_HASH, libdeflate::CHAIN_HASH, windows::HASH]
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
                    let actual: Vec<_> = candidate_hashes(memory_level, &info, insertion).collect();
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

impl DictionaryAddPolicy {
    /// Updates the hash based on the dictionary add policy
    #[inline(always)]
    pub fn update_hash<U: FnMut(&[u8], u32, u32)>(
        self,
        input: &[u8],
        pos: u32,
        length: u32,
        mut update_fn: U,
    ) {
        if length == 1 {
            match self {
                DictionaryAddPolicy::AddFirstExcept4kBoundary => {
                    if !miniz::cross_4k_boundary(pos) {
                        update_fn(input, pos, 1);
                    }
                }
                _ => {
                    update_fn(input, pos, 1);
                }
            }
        } else {
            match self {
                DictionaryAddPolicy::AddAll => update_fn(input, pos, length),
                DictionaryAddPolicy::AddFirst(limit) => {
                    if length <= u32::from(limit) {
                        update_fn(input, pos, length);
                    } else {
                        update_fn(input, pos, 1);
                    }
                }
                DictionaryAddPolicy::AddFirstAndLast(limit) => {
                    if length <= u32::from(limit) {
                        update_fn(input, pos, length);
                    } else {
                        update_fn(input, pos, 1);
                        update_fn(&input[length as usize - 1..], pos + length - 1, 1);
                    }
                }
                DictionaryAddPolicy::AddFirstExcept4kBoundary => {
                    if !miniz::cross_4k_boundary(pos) {
                        update_fn(input, pos, 1);
                    }
                }
                DictionaryAddPolicy::AddFirstWith32KBoundary => {
                    update_fn(input, pos, 1);
                    if zlib_ng::is_at_32k_boundary(length, pos) {
                        update_fn(&input[length as usize - 1..], pos + length - 1, 1);
                    }
                }
            }
        }
    }
}
