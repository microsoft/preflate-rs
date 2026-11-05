/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Chromium zlib hash recognition and compatible profile construction.
//! Uses short-reference alias evidence to select compatible hash and parser settings.

use crate::{
    deflate::deflate_constants::MIN_LOOKAHEAD,
    estimator::{
        initial_estimate::InitialEstimate,
        parser_estimator::{InsertionConstraint, ParserInference},
        preflate_stream_info::PreflateStreamInfo,
    },
    hash_algorithm::HashAlgorithm,
    parameters::DictionaryAddPolicy,
    preflate_input::PlainText,
    reconstruction_parameters::ReconstructionParameters,
};

#[derive(Default, Debug)]
pub struct ShortMatchEvidence {
    sampled: u8,
    high_bit_aliases: u8,
    incompatible: bool,
}

impl ShortMatchEvidence {
    pub fn observe(&mut self, plain: &PlainText, position: u32, distance: u32) {
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

    pub fn supports_chromium(&self) -> bool {
        self.high_bit_aliases >= 16 && !self.incompatible
    }
}

pub fn hash_candidate(evidence: &ShortMatchEvidence) -> Option<HashAlgorithm> {
    evidence
        .supports_chromium()
        .then_some(HashAlgorithm::Chromium { hash_mask: 0x7fff })
}

pub fn add_policy(
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

pub fn depth_add_policy(hash: HashAlgorithm, policy: DictionaryAddPolicy) -> DictionaryAddPolicy {
    if matches!(hash, HashAlgorithm::Chromium { .. })
        && matches!(policy, DictionaryAddPolicy::AddFirst(limit) if limit > 6)
    {
        // Native fast levels insert fully only through lengths 4, 5 or 6.
        DictionaryAddPolicy::AddAll
    } else {
        policy
    }
}

pub fn alternatives(
    parameters: ReconstructionParameters,
    info: &PreflateStreamInfo,
) -> [Option<ReconstructionParameters>; 2] {
    if info.chromium_short_matches.incompatible
        || info.matches_to_start_detected
        || info.max_dist > 32768 - MIN_LOOKAHEAD
    {
        return [None, None];
    }
    let fast = &super::zlib::ZLIB_PREFLATE_PARSER_SETTINGS[match parameters
        .dictionary()
        .expect("dictionary candidate")
        .insertion
    {
        DictionaryAddPolicy::AddFirst(5) => 1,
        DictionaryAddPolicy::AddFirst(6) => 2,
        _ => 0,
    }];
    let slow = &super::zlib::SLOW_PREFLATE_PARSER_SETTINGS[2];
    [fast, slow].map(|config| {
        let is_slow = config.dictionary_add_policy == DictionaryAddPolicy::AddAll;
        if is_slow && info.max_dist_3_matches > crate::compressors::zlib::SHORT_MATCH_CUTOFF {
            return None;
        }
        use crate::reconstruction_parameters::{
            BehaviorSettings, ChainDistancePolicy, ChainMatchSettings, ChainSettings,
            DictionaryIndex, DictionarySettings, HashFunction, InputTailPolicy,
            MiniZDistancePolicy, SearchBudget, WindowBounds,
        };
        let distance = match parameters.behavior {
            BehaviorSettings::Chain { common, .. } => common.distance,
            BehaviorSettings::MiniZ { common, .. } => match common.distance {
                MiniZDistancePolicy::Disabled => ChainDistancePolicy::Disabled,
                MiniZDistancePolicy::Enabled(history) => ChainDistancePolicy::Window {
                    history,
                    bounds: WindowBounds::Lookahead,
                },
            },
            BehaviorSettings::NoDictionary { .. } => unreachable!("dictionary candidate"),
        };
        let short_match_cutoff = if info.short_reference_count == 0 {
            0
        } else if is_slow {
            crate::compressors::zlib::SHORT_MATCH_CUTOFF
        } else {
            32768
        };
        Some(ReconstructionParameters {
            behavior: BehaviorSettings::Chain {
                common: ChainMatchSettings {
                    dictionary: DictionarySettings {
                        index: DictionaryIndex::Chain {
                            hash: HashFunction::Chromium { hash_mask: 0x7fff },
                        },
                        window_bits: 15,
                        insertion: config.dictionary_add_policy,
                    },
                    distance: match distance {
                        ChainDistancePolicy::Window { history, .. } => {
                            ChainDistancePolicy::Window {
                                history,
                                bounds: WindowBounds::LookaheadMinusOne,
                            }
                        }
                        other => other,
                    },
                    search: ChainSettings {
                        input_tail: InputTailPolicy::HashMinimum,
                        budget: SearchBudget {
                            max_chain: config.max_chain,
                        },
                        nice_length: config.nice_length,
                    },
                },
                parser: config.parser.with_cutoff(short_match_cutoff),
            },
            ..parameters
        })
    })
}

pub fn profile(initial: &InitialEstimate<'_>) -> Option<ReconstructionParameters> {
    let evidence = &initial.evidence;
    if !matches!(evidence.hash_algorithm, HashAlgorithm::Chromium { .. })
        || evidence.distance_policy != crate::estimator::depth_estimator::DistancePolicy::ZlibWindow
        || initial.permits_position_zero()
    {
        return None;
    }
    let settings = super::zlib::parser_settings(initial.insertion);
    let config = settings.iter().find(|config| {
        evidence.required_chain <= config.max_chain
            && match (evidence.parser, config.parser) {
                (
                    ParserInference::Lazy {
                        longest_deferred_match,
                    },
                    crate::reconstruction_parameters::ChainParser::Lazy { lookahead, .. },
                ) => lookahead.max_lazy > longest_deferred_match,
                _ => true,
            }
    })?;
    let short_match_cutoff = if initial.insertion == DictionaryAddPolicy::AddAll {
        crate::compressors::zlib::SHORT_MATCH_CUTOFF
    } else {
        32768
    };
    Some(initial.chain_parameters(
        config.parser.with_cutoff(short_match_cutoff),
        config.nice_length,
        config.max_chain,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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
            let mut info =
                crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
            info.min_len = 3;
            let original = crate::estimator::compressor_profile::candidate_hashes(
                memory_level,
                &info,
                DictionaryAddPolicy::AddAll,
            )
            .collect::<Vec<_>>();
            let evidence = ShortMatchEvidence {
                sampled: 16,
                high_bit_aliases: 16,
                incompatible: false,
            };
            info.chromium_short_matches = evidence;
            let hashes = crate::estimator::compressor_profile::candidate_hashes(
                memory_level,
                &info,
                DictionaryAddPolicy::AddAll,
            )
            .collect::<Vec<_>>();
            let mut expected = original.clone();
            *expected.last_mut().unwrap() = HashAlgorithm::Chromium { hash_mask: 0x7fff };
            assert_eq!(hashes, expected);
            assert!(hashes.contains(&crate::compressors::zlib::memory_hash(memory_level)));
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
        let parameters = crate::token_predictor::tests::zlib_level_1_params();
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
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
}
