/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use crate::{
    deflate::{deflate_constants::MIN_MATCH, deflate_token::DeflateTokenReference},
    estimator::{
        CandidateEvidence, DistancePolicy, InsertionConstraint, ParserEvidencePolicy,
        ParserInference, PreflateStreamInfo, add_policy_estimator::DictionaryAddPolicy,
        preflate_parameter_estimator::TokenPredictorParameters,
        preflate_parse_config::MatchingType,
    },
    hash_algorithm::HashAlgorithm,
    hash_chain_holder::{HashChainHolder, MatchResult},
    preflate_input::PreflateInput,
};

use super::MatchPrediction;

pub(crate) struct SearchRestrictions {
    pub minimum_input: u32,
    pub window_edge_exclusion: u32,
}

#[inline(always)]
pub(crate) fn search_restrictions(
    hash: HashAlgorithm,
    matching: MatchingType,
) -> SearchRestrictions {
    let restricted = hash == HashAlgorithm::Libdeflate4Fast15
        || (hash == HashAlgorithm::Libdeflate4 && matching == MatchingType::LibdeflateGreedy);
    SearchRestrictions {
        minimum_input: if restricted { 5 } else { 0 },
        window_edge_exclusion: u32::from(
            restricted
                || hash == CHAIN_HASH && matches!(matching, MatchingType::LibdeflateLazy { .. }),
        ),
    }
}

#[inline(always)]
pub(crate) fn skip_secondary(hash: HashAlgorithm, offset: u32, previous_length: u32) -> bool {
    offset == 0 && previous_length >= 3 && hash == HashAlgorithm::Libdeflate4
}

#[inline(always)]
pub(crate) fn initial_search_length(matching: MatchingType, minimum: u32) -> u32 {
    if matches!(
        matching,
        MatchingType::LibdeflateGreedy | MatchingType::LibdeflateLazy { .. }
    ) {
        minimum - 1
    } else {
        0
    }
}

pub(crate) fn minimum_match_length(bytes: &[u8], depth: u32) -> u32 {
    if bytes.len() < 512 {
        return MIN_MATCH;
    }
    let mut seen = [false; 256];
    let mut distinct = 0;
    for &byte in bytes.iter().take(4096) {
        if !seen[usize::from(byte)] {
            seen[usize::from(byte)] = true;
            distinct += 1;
            if distinct >= 80 {
                return MIN_MATCH;
            }
        }
    }
    minimum_for_alphabet(distinct, depth)
}

fn minimum_for_alphabet(distinct: u32, depth: u32) -> u32 {
    let length = match distinct {
        0..=5 => 9,
        6..=7 => 8,
        8..=9 => 7,
        10..=15 => 6,
        16..=44 => 5,
        45..=79 => 4,
        _ => 3,
    };
    let cap = match depth {
        0..=4 => 4,
        5..=9 => 5,
        10..=15 => 7,
        _ => 9,
    };
    length.min(cap)
}

pub(crate) struct LazyMinimum {
    block_start: u32,
    next_recalculation: u32,
}

impl LazyMinimum {
    pub(crate) fn new(position: u32, remaining: u32) -> Self {
        Self {
            block_start: position,
            next_recalculation: position + remaining.min(10000),
        }
    }

    pub(crate) fn update(
        &mut self,
        position: u32,
        end: u32,
        literal_frequencies: &[u16],
        depth: u32,
    ) -> Option<u32> {
        if position < self.next_recalculation || position == end {
            return None;
        }
        let total: u32 = literal_frequencies
            .iter()
            .map(|&count| u32::from(count))
            .sum();
        let cutoff = total >> 10;
        let distinct = literal_frequencies
            .iter()
            .filter(|&&count| u32::from(count) > cutoff)
            .count() as u32;
        self.next_recalculation += (end - self.next_recalculation).min(position - self.block_start);
        Some(minimum_for_alphabet(distinct, depth))
    }
}

#[inline(always)]
pub(crate) fn prefer_match(
    current: DeflateTokenReference,
    next: DeflateTokenReference,
    literal_cost: i32,
) -> bool {
    next.len() >= current.len()
        && 4 * (next.len() as i32 - current.len() as i32) + current.dist().ilog2() as i32
            - next.dist().ilog2() as i32
            > literal_cost
}

#[inline(always)]
pub(crate) fn predict_lazy(
    input: &PreflateInput,
    state: &dyn HashChainHolder,
    current: DeflateTokenReference,
    nice_length: u32,
    max_chain: u32,
    two_positions: bool,
) -> MatchPrediction {
    if current.len() < nice_length && input.remaining() > current.len() {
        let depth = max_chain.saturating_sub(1);
        if let MatchResult::Success(next) =
            state.match_token_1(current.len() - 1, (depth >> 1).max(1), input)
        {
            if prefer_match(current, next, 2) {
                return MatchPrediction::Literal {
                    pending_reference: Some(next),
                    pending_literals: 0,
                };
            }
        }
        if two_positions && input.remaining() > current.len() + 1 {
            if let MatchResult::Success(next) =
                state.match_token_2(current.len() - 1, (depth >> 2).max(1), input)
            {
                if prefer_match(current, next, 6) {
                    return MatchPrediction::Literal {
                        pending_reference: Some(next),
                        pending_literals: 1,
                    };
                }
            }
        }
    }
    MatchPrediction::Reference
}

pub(crate) const CHAIN_HASH: HashAlgorithm = HashAlgorithm::Libdeflate4;

pub(crate) fn chain_add_policy(
    hash: HashAlgorithm,
    add_policy: DictionaryAddPolicy,
    longest_match: u32,
) -> DictionaryAddPolicy {
    if hash == CHAIN_HASH
        && InsertionConstraint::observe(add_policy, longest_match)
            == InsertionConstraint::Unresolved
    {
        DictionaryAddPolicy::AddAll
    } else {
        add_policy
    }
}

pub(crate) fn primary_chain_evidence(
    mut evidence: CandidateEvidence,
    info: &PreflateStreamInfo,
    add_policy: DictionaryAddPolicy,
) -> CandidateEvidence {
    // Both models share the complete 16-bit primary chain. With no three-byte
    // references, reuse its depth and allow for the chained model's secondary slot.
    // Require a block reaching the native soft limit, not just a compatible hash.
    if evidence.hash_algorithm == HashAlgorithm::Libdeflate4Fast
        && chain_add_policy(CHAIN_HASH, add_policy, info.max_len) == DictionaryAddPolicy::AddAll
        && info.min_len > 3
        && (300000..=304999).contains(&info.max_huffman_block_bytes)
        && (3..=600).contains(&evidence.required_chain)
    {
        evidence.hash_algorithm = CHAIN_HASH;
        evidence.required_chain += 1;
        evidence.distance_policy = DistancePolicy::FullWindow;
    }
    evidence
}

pub(crate) fn fast_hash(add_policy: DictionaryAddPolicy) -> HashAlgorithm {
    if add_policy == DictionaryAddPolicy::AddAll {
        HashAlgorithm::Libdeflate4Fast15
    } else {
        HashAlgorithm::Libdeflate4Fast
    }
}

#[test]
fn primary_chain_reuse_preserves_fast_and_incompatible_candidates() {
    use crate::estimator::extract_preflate_info;

    let original = CandidateEvidence {
        hash_algorithm: HashAlgorithm::Libdeflate4Fast,
        required_chain: 100,
        distance_policy: DistancePolicy::ZlibWindow,
        parser: ParserInference::Unresolved,
    };
    for (hash, depth, minimum, bytes, insertion, expected) in [
        (
            HashAlgorithm::Libdeflate4Fast,
            100,
            5,
            304999,
            DictionaryAddPolicy::AddAll,
            true,
        ),
        (
            HashAlgorithm::Libdeflate4Fast,
            600,
            4,
            300000,
            DictionaryAddPolicy::AddAll,
            true,
        ),
        (
            HashAlgorithm::Libdeflate4Fast,
            2,
            5,
            300000,
            DictionaryAddPolicy::AddAll,
            false,
        ),
        (
            HashAlgorithm::Libdeflate4Fast15,
            2,
            5,
            300000,
            DictionaryAddPolicy::AddAll,
            false,
        ),
        (
            HashAlgorithm::Libdeflate4Fast,
            100,
            3,
            300000,
            DictionaryAddPolicy::AddAll,
            false,
        ),
        (
            HashAlgorithm::Libdeflate4Fast,
            100,
            5,
            305000,
            DictionaryAddPolicy::AddAll,
            false,
        ),
        (
            HashAlgorithm::Libdeflate4Fast,
            100,
            5,
            300000,
            DictionaryAddPolicy::AddFirst(4),
            false,
        ),
        (
            HashAlgorithm::Libdeflate4Fast,
            601,
            5,
            300000,
            DictionaryAddPolicy::AddAll,
            false,
        ),
    ] {
        let mut info = extract_preflate_info(&[]);
        info.min_len = minimum;
        info.max_len = 258;
        info.max_huffman_block_bytes = bytes;
        let evidence = CandidateEvidence {
            hash_algorithm: hash,
            required_chain: depth,
            ..original
        };
        let selected = primary_chain_evidence(evidence, &info, insertion);
        assert_eq!(
            selected.hash_algorithm,
            if expected { CHAIN_HASH } else { hash }
        );
        assert_eq!(selected.required_chain, depth + u32::from(expected));
        assert_eq!(
            selected.distance_policy,
            if expected {
                DistancePolicy::FullWindow
            } else {
                DistancePolicy::ZlibWindow
            }
        );
        assert_eq!(selected.parser, evidence.parser);
    }
}

#[test]
fn chained_insertion_normalizes_only_an_unobserved_cutoff() {
    for (hash, policy, maximum, expected) in [
        (
            CHAIN_HASH,
            DictionaryAddPolicy::AddFirst(100),
            100,
            DictionaryAddPolicy::AddAll,
        ),
        (
            CHAIN_HASH,
            DictionaryAddPolicy::AddFirst(99),
            100,
            DictionaryAddPolicy::AddFirst(99),
        ),
        (
            HashAlgorithm::Libdeflate4Fast,
            DictionaryAddPolicy::AddFirst(100),
            100,
            DictionaryAddPolicy::AddFirst(100),
        ),
        (
            CHAIN_HASH,
            DictionaryAddPolicy::AddFirstAndLast(100),
            100,
            DictionaryAddPolicy::AddFirstAndLast(100),
        ),
    ] {
        assert_eq!(chain_add_policy(hash, policy, maximum), expected);
    }
    let mut info = crate::estimator::extract_preflate_info(&[]);
    info.min_len = 5;
    info.max_len = 100;
    let evidence = CandidateEvidence {
        hash_algorithm: HashAlgorithm::Libdeflate4Fast,
        required_chain: 100,
        distance_policy: DistancePolicy::ZlibWindow,
        parser: ParserInference::Unresolved,
    };
    for (bytes, hash) in [
        (299999, HashAlgorithm::Libdeflate4Fast),
        (300000, CHAIN_HASH),
    ] {
        info.max_huffman_block_bytes = bytes;
        assert_eq!(
            primary_chain_evidence(evidence, &info, DictionaryAddPolicy::AddFirst(100))
                .hash_algorithm,
            hash
        );
    }
}

pub(crate) fn evidence_policy() -> ParserEvidencePolicy {
    // Greedy parsing can raise its block-local minimum to nine.
    ParserEvidencePolicy::with_deferred_match_floor(9)
}

pub(crate) fn prefer_fingerprint(hash: HashAlgorithm) -> bool {
    // A 16-bit bucket is a subset of its 15-bit bucket; depth alone favors the wrong one.
    hash == HashAlgorithm::Libdeflate4Fast15
}

pub(crate) fn fingerprint(
    mut parameters: TokenPredictorParameters,
    evidence: &CandidateEvidence,
) -> Option<TokenPredictorParameters> {
    match evidence.hash_algorithm {
        HashAlgorithm::Libdeflate4
            if evidence.parser == ParserInference::Greedy && evidence.required_chain <= 17 =>
        {
            parameters.matching_type = MatchingType::LibdeflateGreedy;
            parameters.window_bits = 15;
            parameters.max_dist_3_matches = 4096;
            parameters.nice_length = match evidence.required_chain {
                0..=7 => 10,
                8..=13 => 14,
                _ => 30,
            };
        }
        HashAlgorithm::Libdeflate4 if evidence.required_chain <= 601 => {
            let (depth, nice, two_positions) = match evidence.required_chain {
                0..=17 => (16, 30, false),
                18..=36 => (35, 65, false),
                37..=101 => (100, 130, false),
                102..=301 => (300, 258, true),
                _ => (600, 258, true),
            };
            parameters.matching_type = MatchingType::LibdeflateLazy { two_positions };
            parameters.nice_length = nice;
            parameters.max_chain = depth + 1;
            parameters.window_bits = 15;
            parameters.very_far_matches_detected = true;
            parameters.max_dist_3_matches = 8192;
        }
        HashAlgorithm::Libdeflate4Fast if evidence.required_chain <= 2 => {
            parameters.matching_type = MatchingType::Greedy;
            parameters.nice_length = 32;
        }
        HashAlgorithm::Libdeflate4Fast15 => {
            parameters.matching_type = MatchingType::Greedy;
            parameters.nice_length = 32;
            parameters.max_chain = 2;
            parameters.window_bits = 15;
        }
        _ => return None,
    }
    Some(parameters)
}

#[test]
fn verify_libdeflate_greedy_recognition() {
    use crate::{
        deflate::deflate_reader::parse_deflate_whole,
        estimator::preflate_parameter_estimator::estimate_preflate_parameters, utils::read_file,
    };

    for (level, nice_length) in [(2, 10), (3, 14), (4, 30)] {
        let compressed = read_file(&format!("compressed_libdeflate_level{level}.deflate"));
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        let parameters = estimate_preflate_parameters(&contents, &plain).unwrap();
        assert_eq!(parameters.hash_algorithm, HashAlgorithm::Libdeflate4);
        assert_eq!(parameters.matching_type, MatchingType::LibdeflateGreedy);
        assert_eq!(parameters.nice_length, nice_length);
    }
    let compressed = read_file("compressed_libdeflate_level5.deflate");
    let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
    let parameters = estimate_preflate_parameters(&contents, &plain).unwrap();
    assert_eq!(
        parameters.matching_type,
        MatchingType::LibdeflateLazy {
            two_positions: false
        }
    );
}

#[test]
fn minimum_match_length_is_bounded_and_depth_aware() {
    for (distinct, expected) in [
        (1, 9),
        (5, 9),
        (6, 8),
        (7, 8),
        (8, 7),
        (9, 7),
        (10, 6),
        (15, 6),
        (16, 5),
        (44, 5),
        (45, 4),
        (79, 4),
        (80, 3),
        (256, 3),
    ] {
        let bytes: Vec<_> = (0..4096).map(|i| (i % distinct) as u8).collect();
        assert_eq!(minimum_match_length(&bytes, 16), expected);
        assert_eq!(minimum_match_length(&bytes, 12), expected.min(7));
        assert_eq!(minimum_match_length(&bytes, 6), expected.min(5));
        assert_eq!(minimum_match_length(&bytes, 4), expected.min(4));
        assert_eq!(minimum_match_length(&bytes[..511], 16), 3);
    }
    let mut bytes = vec![b'a'; 4096];
    bytes.extend(0..=255);
    assert_eq!(minimum_match_length(&bytes, 16), 9);
}

#[test]
fn minimum_is_monotonic_and_alphabet_invariant() {
    for length in [511, 512, 4095, 4096, 4352] {
        let mut previous_alphabet = [9; 8];
        for alphabet in 1..=256 {
            let bytes: Vec<_> = (0..length).map(|i| (i % alphabet) as u8).collect();
            let relabeled: Vec<_> = bytes
                .iter()
                .map(|byte| byte.wrapping_mul(129) ^ 0xa5)
                .collect();
            let mut previous_depth = 3;
            for (index, depth) in [0, 4, 5, 9, 10, 15, 16, 600].into_iter().enumerate() {
                let minimum = minimum_match_length(&bytes, depth);
                assert!((3..=9).contains(&minimum));
                assert_eq!(minimum, minimum_match_length(&relabeled, depth));
                assert!(minimum >= previous_depth);
                assert!(minimum <= previous_alphabet[index]);
                previous_depth = minimum;
                previous_alphabet[index] = minimum;
            }
        }
    }
}

#[test]
fn lazy_minimum_uses_literal_frequencies_and_progressive_positions() {
    let mut frequencies = [0; 256];
    frequencies[..80].fill(2);
    let mut minimum = LazyMinimum::new(700, 50000);
    assert_eq!(minimum.update(10699, 50700, &frequencies, 100), None);
    assert_eq!(minimum.update(10700, 50700, &frequencies, 100), Some(3));
    assert_eq!(minimum.next_recalculation, 20700);

    frequencies.fill(1);
    frequencies[0] = 1024;
    assert_eq!(minimum.update(20703, 50700, &frequencies, 100), Some(9));
    assert_eq!(minimum.next_recalculation, 40703);
    assert_eq!(minimum.update(40704, 50700, &frequencies, 4), Some(4));
    assert_eq!(minimum.next_recalculation, 50700);
    assert_eq!(minimum.update(50700, 50700, &frequencies, 100), None);
    assert_eq!(LazyMinimum::new(700, 511).next_recalculation, 1211);
}

#[test]
fn lazy_prefers_a_nearer_equal_length_match() {
    let current = DeflateTokenReference::new(3, 136);
    assert!(prefer_match(current, DeflateTokenReference::new(3, 5), 2));
    assert!(!prefer_match(current, DeflateTokenReference::new(3, 32), 2));
    assert!(!prefer_match(current, DeflateTokenReference::new(3, 5), 6));
    assert!(!prefer_match(
        DeflateTokenReference::new(4, 136),
        DeflateTokenReference::new(3, 1),
        2,
    ));
}
