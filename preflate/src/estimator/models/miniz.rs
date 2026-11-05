//! MiniZ recognition from insertion patterns and bounded matching evidence.
//!
//! The normal parser shares zlib's rotating hash but searches candidate suffixes
//! in probe groups and can use greedy or lazy token decisions. Its probe budget
//! and chain-link conventions therefore differ from an ordinary zlib search,
//! even when both streams have the same hash signature.
//!
//! The fastest parser uses a separate hash and skips insertion near 4 KiB
//! boundaries. Recognition combines these insertion patterns with repeated
//! matching evidence rather than treating a shallow chain as sufficient proof.

/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use super::{generic, zlib};
use crate::{
    compressors::{
        miniz::maximum_distance,
        zlib::{DEFAULT_HASH, SHORT_MATCH_CUTOFF},
    },
    deflate::deflate_token::DeflateTokenReference,
    estimator::{
        initial_estimate::InitialEstimate, parser_estimator::ParserInference,
        preflate_stream_info::PreflateStreamInfo,
    },
    hash_algorithm::HashAlgorithm,
    parameters::DictionaryAddPolicy,
    preflate_input::PreflateInput,
    reconstruction_parameters::{
        BehaviorSettings, ChainDistancePolicy, DictionaryIndex, DictionarySettings,
        InputTailPolicy, MiniZDistancePolicy, MiniZMatchSettings, MiniZSearchSettings,
        ReconstructionParameters, SearchBudget, SourceHistorySettings,
    },
};

pub const FAST_HASH: HashAlgorithm = HashAlgorithm::MiniZFast;

#[derive(Default)]
pub struct ShallowGreedyObservations {
    invalid: bool,
    comparisons: u16,
    skipped_better: u16,
}

impl ShallowGreedyObservations {
    pub fn active(&self) -> bool {
        !self.invalid
    }

    pub fn detected(&self) -> bool {
        !self.invalid && self.skipped_better >= 4
    }

    fn distance(input: &PreflateInput, head: u16) -> Option<u32> {
        let distance = u32::from((input.pos() as u16).wrapping_sub(head));
        (head != 0
            && distance != 0
            && distance <= maximum_distance(32768, input.bytes_before(), 258))
        .then_some(distance)
    }

    pub fn observe_reference(
        &mut self,
        input: &PreflateInput,
        reference: DeflateTokenReference,
        depth: u32,
        heads: [u16; 2],
    ) {
        if self.invalid {
            return;
        }
        if depth > 2
            || (reference.len() == 3 && reference.dist() >= 8192)
            || reference.dist() == input.pos() & 32767
        {
            self.invalid = true;
            return;
        }
        // The estimator's chunk tail need not be the native compressor's input tail.
        if input.remaining() < 258 {
            return;
        }
        let current = input.cur_chars(0);
        for &head in heads.iter().take(depth as usize) {
            let Some(distance) = Self::distance(input, head) else {
                self.invalid = true;
                return;
            };
            if input.cur_chars(-(distance as i32))[1..3] == current[1..3] {
                self.invalid = true;
                return;
            }
        }
        let source = input.cur_chars(-(reference.dist() as i32));
        if reference.dist() > maximum_distance(32768, input.bytes_before(), 258)
            || (reference.len() < 258
                && source[reference.len() as usize] == current[reference.len() as usize])
        {
            self.invalid = true;
            return;
        }
        if depth == 0 && reference.len() < 258 && self.comparisons < 256 {
            let Some(distance) = Self::distance(input, heads[1]) else {
                return;
            };
            if distance == input.pos() & 32767 {
                return;
            }
            self.comparisons += 1;
            let length = reference.len() as usize + 1;
            if input.cur_chars(-(distance as i32))[..length] == current[..length] {
                // A second probe group would improve this actual first-group match.
                self.skipped_better += 1;
            }
        }
    }

    pub fn observe_literal(&mut self, input: &PreflateInput, heads: [u16; 2]) {
        if self.invalid || input.remaining() < 258 {
            return;
        }
        let current = input.cur_chars(0);
        for head in heads {
            let Some(distance) = Self::distance(input, head) else {
                return;
            };
            let source = input.cur_chars(-(distance as i32));
            if source[1..3] == current[1..3] {
                if source[..2] == current[..2]
                    && distance != input.pos() & 32767
                    && (distance < 8192 || source[3] == current[3])
                {
                    self.invalid = true;
                }
                return;
            }
        }
    }
}

pub fn prefer_rotating_hash(
    add_policy: DictionaryAddPolicy,
    info: &PreflateStreamInfo,
    has_libdeflate_chain: bool,
) -> bool {
    add_policy == DictionaryAddPolicy::AddAll
        && info.max_dist_3_matches > SHORT_MATCH_CUTOFF
        && !info.matches_to_start_detected
        && !has_libdeflate_chain
}

pub fn vetoes_rotating_hash(hash: HashAlgorithm) -> bool {
    hash == crate::compressors::libdeflate::CHAIN_HASH
}

pub fn shallow_alternative(
    parameters: ReconstructionParameters,
    info: &PreflateStreamInfo,
) -> Option<ReconstructionParameters> {
    if info.min_len != 3
        || !(4097..8192).contains(&info.max_dist_3_matches)
        || info.matches_to_start_detected
        || matches!(
            parameters.behavior,
            BehaviorSettings::MiniZ {
                common: MiniZMatchSettings {
                    search: MiniZSearchSettings { max_probes: 3, .. },
                    ..
                },
                greedy: true,
                ..
            }
        )
    {
        return None;
    }
    let mut dictionary = *parameters.dictionary().expect("dictionary candidate");
    dictionary.index = DictionaryIndex::from_algorithm(DEFAULT_HASH).expect("dictionary hash");
    dictionary.window_bits = 15;
    dictionary.insertion = DictionaryAddPolicy::AddAll;
    let distance = match parameters.behavior {
        BehaviorSettings::Chain { common, .. }
            if common.distance == ChainDistancePolicy::Disabled =>
        {
            MiniZDistancePolicy::Disabled
        }
        BehaviorSettings::MiniZ { common, .. }
            if common.distance == MiniZDistancePolicy::Disabled =>
        {
            MiniZDistancePolicy::Disabled
        }
        _ => MiniZDistancePolicy::Enabled(SourceHistorySettings {
            matches_to_start: parameters.behavior.permits_position_zero(),
        }),
    };
    Some(ReconstructionParameters {
        behavior: parser_behavior(
            dictionary,
            distance,
            SearchBudget { max_chain: 3 },
            3,
            true,
            8191,
        ),
        ..parameters
    })
}

pub fn fingerprint(initial: &InitialEstimate<'_>) -> Option<ReconstructionParameters> {
    let evidence = &initial.evidence;
    if evidence.hash_algorithm != DEFAULT_HASH
        || initial.info.max_dist_3_matches <= SHORT_MATCH_CUTOFF
    {
        return None;
    }
    let shallow = evidence.shallow_miniz_greedy
        && evidence.required_chain <= 3
        && !matches!(evidence.parser, ParserInference::Lazy { .. })
        && initial.insertion == DictionaryAddPolicy::AddAll
        && !initial.permits_position_zero();
    let greedy = shallow || evidence.parser == ParserInference::Greedy;
    let profiles: &[u16] = if greedy {
        if shallow { &[3] } else { &[6, 32] }
    } else {
        &[16, 32, 128, 256, 512, 768, 1500]
    };
    if let Some(&max_probes) = profiles
        .iter()
        .find(|&&probes| u32::from(probes).div_ceil(3) * 3 >= evidence.required_chain)
    {
        let mut dictionary = initial.dictionary();
        dictionary.window_bits = 15;
        return Some(initial.parameters(parser_behavior(
            dictionary,
            MiniZDistancePolicy::Enabled(initial.source_history()),
            SearchBudget {
                max_chain: u32::from(max_probes).div_ceil(3) * 3,
            },
            max_probes,
            greedy,
            if shallow {
                8191
            } else {
                initial.info.max_dist_3_matches
            },
        )));
    }
    let mut parameters = generic::candidate(initial, zlib::compatible_initial(initial));
    parameters
        .chain_common_mut()
        .expect("chain candidate")
        .search
        .nice_length = 258;
    Some(parameters)
}

fn parser_behavior(
    dictionary: DictionarySettings,
    distance: MiniZDistancePolicy,
    budget: SearchBudget,
    max_probes: u16,
    greedy: bool,
    short_match_cutoff: u32,
) -> BehaviorSettings {
    BehaviorSettings::MiniZ {
        common: MiniZMatchSettings {
            dictionary,
            distance,
            search: MiniZSearchSettings {
                input_tail: if dictionary.index.into_algorithm() == HashAlgorithm::Libdeflate4Fast15
                {
                    InputTailPolicy::AtLeastFiveBytes
                } else {
                    InputTailPolicy::HashMinimum
                },
                max_probes,
                budget,
            },
        },
        greedy,
        short_match_cutoff,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::estimator::test_support::initial_stream_info;
    use crate::estimator::{
        complevel_estimator::CandidateEvidence, depth_estimator::DistancePolicy,
    };

    use crate::parameters::PreflateStrategy;
    use crate::parameters::tests::MatchingType;

    #[test]
    fn initial_and_refinement_paths_share_complete_miniz_settings() {
        let mut info = initial_stream_info();
        info.max_dist_3_matches = 8191;
        let evidence = CandidateEvidence {
            hash_algorithm: DEFAULT_HASH,
            required_chain: 3,
            distance_policy: DistancePolicy::ZlibWindow,
            parser: ParserInference::Unresolved,
            shallow_miniz_greedy: true,
            minimum_nice_length: 0,
        };
        for strategy in [PreflateStrategy::Default, PreflateStrategy::RleOnly] {
            let mut initial = InitialEstimate::test_fixture(&info, evidence);
            initial.strategy = strategy;
            let expected = fingerprint(&initial).unwrap();
            let mut base = generic::candidate(&initial, zlib::compatible_initial(&initial));
            let refined = shallow_alternative(base, &info).unwrap();
            assert_eq!(refined, expected);

            base.chain_common_mut().unwrap().distance = ChainDistancePolicy::Disabled;
            let disabled = shallow_alternative(base, &info).unwrap();
            let mut expected_disabled = expected;
            let BehaviorSettings::MiniZ { common, .. } = &mut expected_disabled.behavior else {
                panic!("MiniZ fingerprint expected");
            };
            common.distance = MiniZDistancePolicy::Disabled;
            assert_eq!(disabled, expected_disabled);
        }
    }

    #[test]
    fn shallow_greedy_observations_require_repeated_skipped_improvements() {
        let mut bytes = vec![b'!'; 4096];
        bytes[80..85].copy_from_slice(b"abcYZ");
        bytes[100..105].copy_from_slice(b"abcXZ");
        bytes[1024..1029].copy_from_slice(b"abcYQ");
        let plain = crate::preflate_input::PlainText::new_with_data(bytes);
        let mut input = PreflateInput::new(&plain);
        input.advance(1024);
        let reference = DeflateTokenReference::new(3, 924);
        let mut observations = ShallowGreedyObservations::default();
        assert!(!observations.detected());
        for count in 1..=4 {
            observations.observe_reference(&input, reference, 0, [100, 80]);
            assert_eq!(observations.detected(), count >= 4);
        }
        assert_eq!(observations.skipped_better, 4);
        observations.observe_literal(&input, [100, 80]);
        assert!(!observations.active());
        assert!(!observations.detected());
    }

    #[test]
    fn shallow_greedy_observations_reject_inconsistent_references() {
        let mut bytes = vec![b'!'; 4096];
        bytes[40..45].copy_from_slice(b"AbcWZ");
        bytes[80..85].copy_from_slice(b"abcYZ");
        bytes[100..105].copy_from_slice(b"abcXZ");
        bytes[1024..1029].copy_from_slice(b"abcYQ");
        let plain = crate::preflate_input::PlainText::new_with_data(bytes);
        let mut input = PreflateInput::new(&plain);
        input.advance(1024);
        for (length, distance, depth, heads) in [
            (3, 924, 3, [100, 80]),
            (3, 944, 0, [80, 100]),
            (4, 944, 1, [100, 80]),
            (4, 944, 1, [40, 80]),
            (4, 944, 1, [0, 80]),
            (4, 1024, 0, [0, 80]),
        ] {
            let mut observations = ShallowGreedyObservations::default();
            observations.observe_reference(
                &input,
                DeflateTokenReference::new(length, distance),
                depth,
                heads,
            );
            assert!(
                !observations.active(),
                "{length} {distance} {depth} {heads:?}"
            );
        }
        let mut observations = ShallowGreedyObservations::default();
        observations.observe_reference(&input, DeflateTokenReference::new(4, 944), 1, [20, 80]);
        assert!(observations.active());
    }

    #[test]
    fn shallow_greedy_observations_bound_comparisons_and_ignore_uncertain_tails() {
        let mut bytes = vec![b'!'; 4096];
        bytes[80..85].copy_from_slice(b"abcYZ");
        bytes[100..105].copy_from_slice(b"abcXZ");
        bytes[1024..1029].copy_from_slice(b"abcYQ");
        let plain = crate::preflate_input::PlainText::new_with_data(bytes.clone());
        let mut input = PreflateInput::new(&plain);
        input.advance(1024);
        let reference = DeflateTokenReference::new(3, 924);
        let mut observations = ShallowGreedyObservations::default();
        for _ in 0..300 {
            observations.observe_reference(&input, reference, 0, [100, 80]);
        }
        assert_eq!(observations.comparisons, 256);
        assert_eq!(observations.skipped_better, 256);
        bytes.truncate(1024 + 257);
        let tail = crate::preflate_input::PlainText::new_with_data(bytes);
        let mut input = PreflateInput::new(&tail);
        input.advance(1024);
        observations.observe_literal(&input, [100, 80]);
        observations.observe_reference(&input, reference, 0, [100, 80]);
        assert!(observations.detected());
        assert_eq!(observations.comparisons, 256);
        // A native three-byte distance exclusion applies even at the chunk tail.
        observations.observe_reference(&input, DeflateTokenReference::new(3, 8192), 0, [100, 80]);
        assert!(!observations.detected());
    }

    #[test]
    fn shallow_alternative_does_not_require_a_winning_hash_or_full_insertion_estimate() {
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
        info.min_len = 3;
        info.max_dist_3_matches = 8191;
        let base = crate::token_predictor::tests::zlib_level_1_params();
        for add_policy in [
            DictionaryAddPolicy::AddAll,
            DictionaryAddPolicy::AddFirst(72),
            DictionaryAddPolicy::AddFirst(120),
        ] {
            let parameters = {
                let mut canonical_configuration = base;
                canonical_configuration
                    .set_hash_algorithm(crate::compressors::libdeflate::CHAIN_HASH);
                canonical_configuration.set_insertion(add_policy);
                canonical_configuration
            };
            let alternative = shallow_alternative(parameters, &info).unwrap();
            assert_eq!(
                alternative.hash_algorithm(),
                crate::compressors::zlib::DEFAULT_HASH
            );
            assert_eq!(alternative.add_policy(), DictionaryAddPolicy::AddAll);
            assert_eq!(
                alternative.matching_type(),
                MatchingType::MiniZ {
                    max_probes: 3,
                    greedy: true,
                }
            );
            assert_eq!(alternative.max_chain(), 3);
            assert_eq!(alternative.nice_length(), 258);
            assert_eq!(alternative.max_dist_3_matches(), 8191);
        }
        for distance in [0, 4096, 8192] {
            info.max_dist_3_matches = distance;
            assert!(shallow_alternative(base, &info).is_none());
        }
        info.max_dist_3_matches = 8191;
        info.matches_to_start_detected = true;
        assert!(shallow_alternative(base, &info).is_none());
    }

    #[test]
    fn shallow_fingerprint_requires_specific_evidence_and_preserves_lazy_veto() {
        let mut info = initial_stream_info();
        info.max_dist_3_matches = 8191;
        for (supported, depth, parser, shallow) in [
            (false, 3, ParserInference::Unresolved, false),
            (true, 3, ParserInference::Unresolved, true),
            (true, 3, ParserInference::Greedy, true),
            (true, 4, ParserInference::Unresolved, false),
            (
                true,
                3,
                ParserInference::Lazy {
                    longest_deferred_match: 6,
                },
                false,
            ),
        ] {
            let evidence = CandidateEvidence {
                hash_algorithm: DEFAULT_HASH,
                required_chain: depth,
                distance_policy: DistancePolicy::ZlibWindow,
                parser,
                shallow_miniz_greedy: supported,
                minimum_nice_length: 0,
            };
            assert_eq!(
                fingerprint(&InitialEstimate::test_fixture(&info, evidence))
                    .unwrap()
                    .matching_type()
                    == (MatchingType::MiniZ {
                        max_probes: 3,
                        greedy: true,
                    }),
                shallow,
            );
        }
    }

    #[test]
    fn verify_miniz_recognition() {
        use crate::{
            deflate::deflate_reader::tests::parse_deflate_whole,
            estimator::preflate_parameter_estimator::tests::estimate_preflate_parameters,
            parameters::PreflateStrategy, utils::read_file,
        };

        for level in 0..=9 {
            let compressed = read_file(&format!("compressed_flate2_level{level}.deflate"));
            let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
            let parameters = estimate_preflate_parameters(&contents, &plain).unwrap();
            if level == 0 {
                assert_eq!(parameters.strategy(), PreflateStrategy::Store);
            } else if level >= 2 {
                let probes = [6, 32, 16, 32, 128, 256, 512, 768][level - 2];
                assert_eq!(
                    parameters.matching_type(),
                    MatchingType::MiniZ {
                        max_probes: probes,
                        greedy: level <= 3,
                    }
                );
                assert_eq!(parameters.window_bits(), 15);
                assert_eq!(parameters.max_chain(), u32::from(probes).div_ceil(3) * 3);
            }
        }
    }
}
