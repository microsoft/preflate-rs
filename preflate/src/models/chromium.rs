/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use crate::{
    deflate::deflate_constants::MIN_LOOKAHEAD,
    estimator::{CandidateEvidence, InsertionConstraint, ParserInference, PreflateStreamInfo},
    hash_algorithm::HashAlgorithm,
    parameters::{DictionaryAddPolicy, TokenPredictorParameters},
    preflate_input::PlainText,
};

#[derive(Default, Debug)]
pub(crate) struct ShortMatchEvidence {
    sampled: u8,
    high_bit_aliases: u8,
    incompatible: bool,
}

impl ShortMatchEvidence {
    pub(crate) fn observe(&mut self, plain: &PlainText, position: u32, distance: u32) {
        if self.sampled >= 64 {
            return;
        }
        self.sampled += 1;
        let Some(&current) = plain.text().get(position as usize + 3) else {
            return;
        };
        let source = i64::from(position) + 3 - i64::from(distance);
        let previous = if source >= 0 {
            plain.text().get(source as usize)
        } else {
            plain
                .prefix()
                .len()
                .checked_sub((-source) as usize)
                .and_then(|index| plain.prefix().get(index))
        };
        if let Some(&previous) = previous {
            match current ^ previous {
                0 => {}
                0x80 => self.high_bit_aliases += 1,
                _ => self.incompatible = true,
            }
        }
    }

    pub(crate) fn supports_chromium(&self) -> bool {
        self.high_bit_aliases >= 16 && !self.incompatible
    }
}

pub(crate) fn hash_candidate(evidence: &ShortMatchEvidence) -> Option<HashAlgorithm> {
    evidence
        .supports_chromium()
        .then_some(HashAlgorithm::Chromium { hash_mask: 0x7fff })
}

pub(crate) fn add_policy(
    hash: HashAlgorithm,
    policy: DictionaryAddPolicy,
    longest_match: u32,
) -> DictionaryAddPolicy {
    if matches!(hash, HashAlgorithm::Chromium { .. })
        && InsertionConstraint::observe(policy, longest_match) == InsertionConstraint::Unresolved
    {
        DictionaryAddPolicy::AddAll
    } else {
        depth_add_policy(hash, policy)
    }
}

pub(crate) fn depth_add_policy(
    hash: HashAlgorithm,
    policy: DictionaryAddPolicy,
) -> DictionaryAddPolicy {
    if matches!(hash, HashAlgorithm::Chromium { .. })
        && matches!(policy, DictionaryAddPolicy::AddFirst(limit) if limit > 6)
    {
        // Native fast levels insert fully only through lengths 4, 5 or 6.
        DictionaryAddPolicy::AddAll
    } else {
        policy
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Profile(pub(super) TokenPredictorParameters);

impl Profile {
    pub(super) fn parameters(self) -> TokenPredictorParameters {
        self.0
    }

    pub(super) fn parameters_mut(&mut self) -> &mut TokenPredictorParameters {
        &mut self.0
    }

    pub(super) fn fingerprint(
        parameters: TokenPredictorParameters,
        evidence: &CandidateEvidence,
    ) -> Option<Self> {
        profile(parameters, evidence).map(Self)
    }

    pub(super) fn alternatives(
        parameters: TokenPredictorParameters,
        info: &PreflateStreamInfo,
    ) -> [Option<Self>; 2] {
        let [fast, lazy] = alternatives(parameters, info);
        [fast.map(Self), lazy.map(Self)]
    }
}

pub(crate) fn alternatives(
    parameters: TokenPredictorParameters,
    info: &PreflateStreamInfo,
) -> [Option<TokenPredictorParameters>; 2] {
    if info.chromium_short_matches.incompatible
        || info.matches_to_start_detected
        || info.max_dist > 32768 - MIN_LOOKAHEAD
    {
        return [None, None];
    }
    let fast = &super::zlib::ZLIB_PREFLATE_PARSER_SETTINGS[match parameters.add_policy {
        DictionaryAddPolicy::AddFirst(5) => 1,
        DictionaryAddPolicy::AddFirst(6) => 2,
        _ => 0,
    }];
    let slow = &super::zlib::SLOW_PREFLATE_PARSER_SETTINGS[2];
    [fast, slow].map(|config| {
        let is_slow = config.dictionary_add_policy == DictionaryAddPolicy::AddAll;
        if is_slow && info.max_dist_3_matches > super::zlib::SHORT_MATCH_CUTOFF {
            return None;
        }
        Some(TokenPredictorParameters {
            hash_algorithm: HashAlgorithm::Chromium { hash_mask: 0x7fff },
            matching_type: config.match_type,
            add_policy: config.dictionary_add_policy,
            nice_length: config.nice_length,
            max_chain: config.max_chain,
            window_bits: 15,
            very_far_matches_detected: false,
            max_dist_3_matches: if info.short_reference_count == 0 {
                0
            } else if is_slow {
                super::zlib::SHORT_MATCH_CUTOFF
            } else {
                32768
            },
            ..parameters
        })
    })
}

pub(crate) fn profile(
    mut parameters: TokenPredictorParameters,
    evidence: &CandidateEvidence,
) -> Option<TokenPredictorParameters> {
    if !matches!(parameters.hash_algorithm, HashAlgorithm::Chromium { .. })
        || evidence.distance_policy != crate::estimator::DistancePolicy::ZlibWindow
        || parameters.matches_to_start_detected
    {
        return None;
    }
    let settings = super::zlib::parser_settings(parameters.add_policy);
    let config = settings.iter().find(|config| {
        evidence.required_chain <= config.max_chain
            && match (evidence.parser, config.match_type) {
                (
                    ParserInference::Lazy {
                        longest_deferred_match,
                    },
                    crate::parameters::MatchingType::Lazy { max_lazy, .. },
                ) => max_lazy > longest_deferred_match,
                _ => true,
            }
    })?;
    parameters.matching_type = config.match_type;
    parameters.nice_length = config.nice_length;
    parameters.max_chain = config.max_chain;
    parameters.max_dist_3_matches = if parameters.add_policy == DictionaryAddPolicy::AddAll {
        super::zlib::SHORT_MATCH_CUTOFF
    } else {
        32768
    };
    Some(parameters)
}

#[inline(always)]
pub(crate) fn distance_limits(window: u32, history: u32) -> (u32, u32) {
    let maximum = window - MIN_LOOKAHEAD;
    (history.min(maximum), history.min(maximum - 1))
}

#[test]
fn chromium_oldest_source_is_inclusive_only_at_the_head() {
    assert_eq!(distance_limits(32768, 65536), (32506, 32505));
    assert_eq!(distance_limits(512, 100), (100, 100));
}

#[test]
fn recognition_requires_repeated_compatible_short_references_and_is_bounded() {
    let plain = PlainText::new_with_data(b"@abc0abc\xb0abc1".to_vec());
    let mut evidence = ShortMatchEvidence::default();
    for _ in 0..15 {
        evidence.observe(&plain, 5, 4);
    }
    assert!(!evidence.supports_chromium());
    evidence.observe(&plain, 5, 4);
    assert!(evidence.supports_chromium());
    evidence.observe(&plain, 9, 8);
    assert!(!evidence.supports_chromium());
    for _ in 0..100 {
        evidence.observe(&plain, 5, 4);
    }
    assert_eq!(evidence.sampled, 64);
    assert!(!evidence.supports_chromium());
    let mut prefix = PlainText::new_with_data(b"@abc0".to_vec());
    prefix.shrink_to_dictionary();
    prefix.append(b"abc\xb0");
    let mut evidence = ShortMatchEvidence::default();
    for _ in 0..16 {
        evidence.observe(&prefix, 0, 4);
    }
    assert!(evidence.supports_chromium());
    evidence.observe(&prefix, 1, 4);
    assert!(evidence.supports_chromium());
}

#[test]
fn recognition_reuses_an_optional_candidate_and_preserves_the_memory_level_hash() {
    for memory_level in 1..=9 {
        let mut info = crate::estimator::extract_preflate_info(&[]);
        info.min_len = 3;
        let original = super::candidate_hashes(memory_level, &info, DictionaryAddPolicy::AddAll)
            .collect::<Vec<_>>();
        let evidence = ShortMatchEvidence {
            sampled: 16,
            high_bit_aliases: 16,
            incompatible: false,
        };
        info.chromium_short_matches = evidence;
        let hashes = super::candidate_hashes(memory_level, &info, DictionaryAddPolicy::AddAll)
            .collect::<Vec<_>>();
        let mut expected = original.clone();
        *expected.last_mut().unwrap() = HashAlgorithm::Chromium { hash_mask: 0x7fff };
        assert_eq!(hashes, expected);
        assert!(hashes.contains(&super::zlib::memory_hash(memory_level)));
        assert_eq!(hashes.len(), original.len());
        assert_eq!(
            hashes
                .iter()
                .filter(|hash| matches!(hash, HashAlgorithm::Chromium { .. }))
                .count(),
            1
        );
    }
}

#[test]
fn fallback_admits_missing_aliases_but_rejects_contradictory_evidence() {
    let parameters = crate::token_predictor::zlib_level_1_params();
    let mut info = crate::estimator::extract_preflate_info(&[]);
    assert!(alternatives(parameters, &info).iter().all(Option::is_some));
    info.chromium_short_matches = ShortMatchEvidence {
        sampled: 1,
        high_bit_aliases: 1,
        incompatible: false,
    };
    assert!(alternatives(parameters, &info).iter().all(Option::is_some));
    info.chromium_short_matches.incompatible = true;
    assert_eq!(alternatives(parameters, &info), [None, None]);
}
