/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use super::{libdeflate, zlib};
use crate::{
    deflate::deflate_token::DeflateTokenReference,
    estimator::{
        CandidateEvidence, ParserInference, PreflateStreamInfo,
        add_policy_estimator::DictionaryAddPolicy,
        preflate_parameter_estimator::TokenPredictorParameters,
        preflate_parse_config::MatchingType,
    },
    hash_algorithm::HashAlgorithm,
    hash_chain_holder::{HashChainHolder, MatchResult, prefix_compare, read_u16_le},
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
pub(crate) fn probe_limit(depth: u32, normal_budget: u32, max_probes: u16) -> u32 {
    if depth > normal_budget {
        depth
    } else {
        u32::from(max_probes)
    }
}

#[inline(always)]
pub(crate) fn predict_token(
    input: &PreflateInput,
    state: &dyn HashChainHolder,
    current: DeflateTokenReference,
    greedy: bool,
    max_chain: u32,
) -> MatchPrediction {
    if current.dist() == input.pos() & 32767 {
        return MatchPrediction::Literal {
            pending_reference: None,
            pending_literals: 0,
        };
    }
    if !greedy && current.len() < 128 && input.remaining() > current.len() {
        if let MatchResult::Success(next) = state.match_token_1(current.len(), max_chain, input) {
            if next.len() > current.len()
                && !(next.len() == 3 && next.dist() >= 8192)
                && next.dist() != (input.pos() + 1) & 32767
            {
                return MatchPrediction::Literal {
                    pending_reference: Some(next),
                    pending_literals: 0,
                };
            }
        }
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

pub(crate) fn fingerprint(
    mut parameters: TokenPredictorParameters,
    evidence: &CandidateEvidence,
) -> Option<TokenPredictorParameters> {
    if evidence.hash_algorithm != zlib::DEFAULT_HASH
        || parameters.max_dist_3_matches <= zlib::SHORT_MATCH_CUTOFF
    {
        return None;
    }
    let greedy = evidence.parser == ParserInference::Greedy;
    let profiles: &[u16] = if greedy {
        &[6, 32]
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
    }
    parameters.nice_length = 258;
    Some(parameters)
}

#[test]
fn verify_miniz_recognition() {
    use crate::{
        deflate::deflate_reader::parse_deflate_whole,
        estimator::preflate_parameter_estimator::{PreflateStrategy, estimate_preflate_parameters},
        utils::read_file,
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
