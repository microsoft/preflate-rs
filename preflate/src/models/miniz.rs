/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use super::{libdeflate, zlib};
use crate::{
    deflate::deflate_token::DeflateTokenReference,
    estimator::{CandidateEvidence, ParserInference, PreflateStreamInfo},
    hash_algorithm::HashAlgorithm,
    hash_chain_holder::{HashChainHolder, MatchResult, prefix_compare, read_u16_le},
    parameters::{DictionaryAddPolicy, MatchingType, TokenPredictorParameters},
    preflate_input::PreflateInput,
};

use super::MatchPrediction;

#[inline(always)]
pub(crate) fn cross_4k_boundary(pos: u32) -> bool {
    (pos & 4095) >= 4093
}

#[inline(always)]
pub(crate) fn maximum_distance(window: u32, history: u32, available: u32) -> u32 {
    history.min(window.saturating_sub(available))
}

#[inline(always)]
pub(crate) fn is_zero_chain_link(position: u32, distance: u32) -> bool {
    // Normal miniz chains reserve zero in their wrapping 16-bit position links.
    position.wrapping_sub(distance) & 65535 == 0
}

#[inline(always)]
pub(crate) fn probe_limit(
    depth: u32,
    search: crate::reconstruction_parameters::MiniZSearchSettings,
) -> u32 {
    if depth > search.budget.max_chain {
        depth
    } else {
        u32::from(search.max_probes)
    }
}

#[inline(always)]
pub(crate) fn predict_token(
    input: &PreflateInput,
    state: &dyn HashChainHolder,
    current: DeflateTokenReference,
    greedy: bool,
    budget: crate::reconstruction_parameters::SearchBudget,
) -> MatchPrediction {
    if current.dist() == input.pos() & 32767 {
        return MatchPrediction::Literal {
            pending_reference: None,
            pending_literals: 0,
        };
    }
    if !greedy
        && current.len() < 128
        && input.remaining() > current.len()
        && let MatchResult::Success(next) =
            state.match_token_1(current.len(), budget.max_chain, input)
        && next.len() > current.len()
        && !(next.len() == 3 && next.dist() >= 8192)
        && next.dist() != (input.pos() + 1) & 32767
    {
        return MatchPrediction::Literal {
            pending_reference: Some(next),
            pending_literals: 0,
        };
    }
    MatchPrediction::Reference
}

#[inline]
pub(crate) fn match_chain<const OFFSET: u32>(
    input: &PreflateInput<'_>,
    max_len: u32,
    max_dist: u32,
    max_probes: u32,
    mut best_len: u32,
    mut iter: impl Iterator<Item = u32>,
) -> MatchResult {
    let bytes = input.cur_chars(OFFSET as i32);
    let probes = if best_len < 32 {
        max_probes
    } else {
        max_probes >> 2
    };
    // The first suffix hit consumes its three-probe group even when the prefix fails.
    let mut groups = probes.div_ceil(3);
    let mut best = MatchResult::NoMoreMatchesFound;
    while groups > 0 {
        groups -= 1;
        let suffix = read_u16_le(bytes, (best_len - 1) as usize);
        let mut candidate = None;
        for _ in 0..3 {
            let Some(dist) = iter.next() else { return best };
            if dist > max_dist {
                return best;
            }
            let source = input.cur_chars(OFFSET as i32 - dist as i32);
            if read_u16_le(source, (best_len - 1) as usize) == suffix {
                candidate = Some((dist, source));
                break;
            }
        }
        if let Some((dist, source)) = candidate {
            if read_u16_le(source, 0) != read_u16_le(bytes, 0) {
                continue;
            }
            let length = prefix_compare(source, bytes, max_len);
            if length > best_len {
                best_len = length;
                best = MatchResult::Success(DeflateTokenReference::new(length, dist));
                if length == max_len {
                    return best;
                }
            }
        }
    }
    best
}

pub(crate) const FAST_HASH: HashAlgorithm = HashAlgorithm::MiniZFast;

#[derive(Default)]
pub(crate) struct ShallowGreedyObservations {
    invalid: bool,
    comparisons: u16,
    skipped_better: u16,
}

impl ShallowGreedyObservations {
    pub(crate) fn active(&self) -> bool {
        !self.invalid
    }

    pub(crate) fn detected(&self) -> bool {
        !self.invalid && self.skipped_better >= 4
    }

    fn distance(input: &PreflateInput, head: u16) -> Option<u32> {
        let distance = u32::from((input.pos() as u16).wrapping_sub(head));
        (head != 0
            && distance != 0
            && distance <= maximum_distance(32768, input.bytes_before(), 258))
        .then_some(distance)
    }

    pub(crate) fn observe_reference(
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

    pub(crate) fn observe_literal(&mut self, input: &PreflateInput, heads: [u16; 2]) {
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
        fingerprint(parameters, evidence).map(Self)
    }

    pub(super) fn shallow(
        parameters: TokenPredictorParameters,
        info: &PreflateStreamInfo,
    ) -> Option<Self> {
        shallow_alternative(parameters, info).map(Self)
    }
}

pub(crate) fn prefer_rotating_hash(
    add_policy: DictionaryAddPolicy,
    info: &PreflateStreamInfo,
    has_libdeflate_chain: bool,
) -> bool {
    add_policy == DictionaryAddPolicy::AddAll
        && info.max_dist_3_matches > zlib::SHORT_MATCH_CUTOFF
        && !info.matches_to_start_detected
        && !has_libdeflate_chain
}

pub(crate) fn vetoes_rotating_hash(hash: HashAlgorithm) -> bool {
    hash == libdeflate::CHAIN_HASH
}

pub(crate) fn shallow_alternative(
    parameters: TokenPredictorParameters,
    info: &PreflateStreamInfo,
) -> Option<TokenPredictorParameters> {
    if info.min_len != 3
        || !(4097..8192).contains(&info.max_dist_3_matches)
        || info.matches_to_start_detected
        || parameters.matching_type
            == (MatchingType::MiniZ {
                max_probes: 3,
                greedy: true,
            })
    {
        return None;
    }
    Some(TokenPredictorParameters {
        hash_algorithm: zlib::DEFAULT_HASH,
        matching_type: MatchingType::MiniZ {
            max_probes: 3,
            greedy: true,
        },
        add_policy: DictionaryAddPolicy::AddAll,
        window_bits: 15,
        nice_length: 258,
        max_chain: 3,
        max_dist_3_matches: 8191,
        ..parameters
    })
}

#[test]
fn shallow_alternative_does_not_require_a_winning_hash_or_full_insertion_estimate() {
    let mut info = crate::estimator::extract_preflate_info(&[]);
    info.min_len = 3;
    info.max_dist_3_matches = 8191;
    let base = crate::token_predictor::zlib_level_1_params();
    for add_policy in [
        DictionaryAddPolicy::AddAll,
        DictionaryAddPolicy::AddFirst(72),
        DictionaryAddPolicy::AddFirst(120),
    ] {
        let parameters = TokenPredictorParameters {
            hash_algorithm: libdeflate::CHAIN_HASH,
            add_policy,
            ..base
        };
        let alternative = shallow_alternative(parameters, &info).unwrap();
        assert_eq!(alternative.hash_algorithm, zlib::DEFAULT_HASH);
        assert_eq!(alternative.add_policy, DictionaryAddPolicy::AddAll);
        assert_eq!(
            alternative.matching_type,
            MatchingType::MiniZ {
                max_probes: 3,
                greedy: true,
            }
        );
        assert_eq!(alternative.max_chain, 3);
        assert_eq!(alternative.nice_length, 258);
        assert_eq!(alternative.max_dist_3_matches, 8191);
    }
    for distance in [0, 4096, 8192] {
        info.max_dist_3_matches = distance;
        assert!(shallow_alternative(base, &info).is_none());
    }
    info.max_dist_3_matches = 8191;
    info.matches_to_start_detected = true;
    assert!(shallow_alternative(base, &info).is_none());
}

pub(crate) fn fingerprint(
    mut parameters: TokenPredictorParameters,
    evidence: &CandidateEvidence,
) -> Option<TokenPredictorParameters> {
    if evidence.hash_algorithm != zlib::DEFAULT_HASH
        || parameters.max_dist_3_matches <= zlib::SHORT_MATCH_CUTOFF
    {
        return None;
    }
    let shallow = evidence.shallow_miniz_greedy
        && evidence.required_chain <= 3
        && !matches!(evidence.parser, ParserInference::Lazy { .. })
        && parameters.add_policy == DictionaryAddPolicy::AddAll
        && !parameters.matches_to_start_detected;
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
        parameters.matching_type = MatchingType::MiniZ { max_probes, greedy };
        parameters.max_chain = u32::from(max_probes).div_ceil(3) * 3;
        parameters.window_bits = 15;
        if shallow {
            parameters.max_dist_3_matches = 8191;
        }
    }
    parameters.nice_length = 258;
    Some(parameters)
}

#[test]
fn shallow_fingerprint_requires_specific_evidence_and_preserves_lazy_veto() {
    use crate::estimator::DistancePolicy;
    let parameters = TokenPredictorParameters {
        add_policy: DictionaryAddPolicy::AddAll,
        matches_to_start_detected: false,
        max_dist_3_matches: 8191,
        ..crate::token_predictor::zlib_level_1_params()
    };
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
            hash_algorithm: zlib::DEFAULT_HASH,
            required_chain: depth,
            distance_policy: DistancePolicy::ZlibWindow,
            parser,
            shallow_miniz_greedy: supported,
            minimum_nice_length: 0,
        };
        assert_eq!(
            fingerprint(parameters, &evidence).unwrap().matching_type
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
        deflate::deflate_reader::parse_deflate_whole,
        estimator::preflate_parameter_estimator::estimate_preflate_parameters,
        parameters::PreflateStrategy, utils::read_file,
    };

    for level in 0..=9 {
        let compressed = read_file(&format!("compressed_flate2_level{level}.deflate"));
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        let parameters = estimate_preflate_parameters(&contents, &plain).unwrap();
        if level == 0 {
            assert_eq!(parameters.strategy, PreflateStrategy::Store);
        } else if level >= 2 {
            let probes = [6, 32, 16, 32, 128, 256, 512, 768][level - 2];
            assert_eq!(
                parameters.matching_type,
                MatchingType::MiniZ {
                    max_probes: probes,
                    greedy: level <= 3,
                }
            );
            assert_eq!(parameters.window_bits, 15);
            assert_eq!(parameters.max_chain, u32::from(probes).div_ceil(3) * 3);
        }
    }
}

#[test]
fn fast_insertion_skips_only_the_final_three_positions_of_each_4k_region() {
    let bytes = [b'a'; 8];
    for base in [0, 4096, 32768] {
        let mut inserted = Vec::new();
        for offset in 4092..=4096 {
            DictionaryAddPolicy::AddFirstExcept4kBoundary.update_hash(
                &bytes,
                base + offset,
                1,
                |_, position, length| inserted.push((position, length)),
            );
        }
        assert_eq!(inserted, [(base + 4092, 1), (base + 4096, 1)]);
    }
}
