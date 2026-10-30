/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use crate::{
    deflate::deflate_constants::MIN_LOOKAHEAD,
    estimator::{
        CandidateEvidence, InsertionConstraint, ParserInference,
        add_policy_estimator::DictionaryAddPolicy,
        preflate_parameter_estimator::TokenPredictorParameters,
    },
    hash_algorithm::HashAlgorithm,
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

pub(crate) fn substitute_candidate(
    hashes: &mut [Option<HashAlgorithm>; 3],
    evidence: &ShortMatchEvidence,
) {
    if evidence.supports_chromium()
        && let Some(slot) = hashes.iter_mut().skip(1).rfind(|slot| slot.is_some())
    {
        // Keep the memory-level hash and reuse an optional alternate's existing budget.
        *slot = Some(HashAlgorithm::Chromium { hash_mask: 0x7fff });
    }
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
                    crate::estimator::preflate_parse_config::MatchingType::Lazy {
                        max_lazy, ..
                    },
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
pub(crate) fn distance_limits(
    algorithm: HashAlgorithm,
    normal_prediction: bool,
    window: u32,
    history: u32,
) -> (u32, u32) {
    if normal_prediction && matches!(algorithm, HashAlgorithm::Chromium { .. }) {
        let maximum = window - MIN_LOOKAHEAD;
        (history.min(maximum), history.min(maximum - 1))
    } else {
        super::zlib::distance_limits(window, history)
    }
}

#[test]
fn chromium_oldest_source_is_inclusive_only_at_the_head() {
    let hash = HashAlgorithm::Chromium { hash_mask: 0x7fff };
    assert_eq!(distance_limits(hash, true, 32768, 65536), (32506, 32505));
    assert_eq!(distance_limits(hash, true, 512, 100), (100, 100));
    assert_eq!(distance_limits(hash, false, 32768, 65536), (32507, 32506));
    assert_eq!(
        distance_limits(super::zlib::DEFAULT_HASH, true, 32768, 65536),
        (32507, 32506)
    );
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
        let original = super::zlib::candidate_hashes(memory_level);
        let mut hashes = original;
        substitute_candidate(&mut hashes, &ShortMatchEvidence::default());
        assert_eq!(hashes, original);
        let evidence = ShortMatchEvidence {
            sampled: 16,
            high_bit_aliases: 16,
            incompatible: false,
        };
        substitute_candidate(&mut hashes, &evidence);
        assert_eq!(hashes[0], original[0]);
        assert_eq!(
            hashes.iter().flatten().count(),
            original.iter().flatten().count()
        );
        assert_eq!(
            hashes
                .iter()
                .flatten()
                .filter(|hash| matches!(hash, HashAlgorithm::Chromium { .. }))
                .count(),
            1
        );
    }
}
