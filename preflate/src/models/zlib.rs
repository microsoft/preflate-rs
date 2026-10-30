/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use crate::{
    deflate::{
        deflate_constants::MIN_LOOKAHEAD, deflate_reader::DeflateContents,
        deflate_token::DeflateTokenReference,
    },
    estimator::{
        DepthEstimate, DistancePolicy, HashTableDepthEstimator, InsertionConstraint,
        ParameterEstimate, PreflateStreamInfo,
        add_policy_estimator::DictionaryAddPolicy,
        preflate_parameter_estimator::{TokenPredictorParameters, estimate_preflate_window_bits},
        preflate_parse_config::{LazyBehavior, MatchingType, PreflateParserConfig},
    },
    hash_algorithm::HashAlgorithm,
    hash_chain_holder::{HashChainHolder, MatchResult},
    preflate_input::{PlainText, PreflateInput},
    token_predictor::TokenPredictor,
};

use super::MatchPrediction;

pub(crate) const FILTERED_MIN_MATCH_LENGTH: u32 = 6;

pub(crate) fn sample_short_match_policy(
    add_policy: DictionaryAddPolicy,
    minimum_length: u32,
    maximum_distance: u32,
    plaintext_bytes: usize,
) -> bool {
    matches!(
        add_policy,
        DictionaryAddPolicy::AddAll | DictionaryAddPolicy::AddFirst(_)
    ) && minimum_length == 3
        && (1..=SHORT_MATCH_CUTOFF).contains(&maximum_distance)
        && plaintext_bytes >= 65536
}

pub(crate) fn short_match_rejected(
    input: &PreflateInput,
    distance: u32,
    maximum_distance: u32,
    window_bytes: u32,
) -> bool {
    // Three emitted literals rule out ordinary one-position lazy deferral.
    if input.remaining() < 4
        || distance == 0
        || distance > maximum_distance.min(distance_limits(window_bytes, input.bytes_before()).0)
    {
        return false;
    }
    let current = input.cur_chars(0);
    let previous = input.cur_chars(-(distance as i32));
    current[..3] == previous[..3] && current[3] != previous[3]
}

pub(crate) fn refine_short_match_policy(
    parameters: &mut TokenPredictorParameters,
    info: &PreflateStreamInfo,
    rejections: u16,
) {
    if rejections >= 16
        && info.min_len == 3
        && (1..=SHORT_MATCH_CUTOFF).contains(&info.max_dist_3_matches)
        && info.reference_count >= 4096
        && u64::from(info.short_reference_count) * 512 <= u64::from(info.reference_count)
        && matches!(parameters.hash_algorithm, HashAlgorithm::Zlib { .. })
        && parameters.add_policy == DictionaryAddPolicy::AddAll
        && matches!(
            parameters.matching_type,
            MatchingType::Lazy {
                filtered_matching: false,
                behavior: LazyBehavior::Zlib { .. },
                ..
            }
        )
    {
        parameters.max_dist_3_matches = 0;
    }
}

#[test]
fn short_match_rejection_requires_an_exact_three_byte_head_match_in_window() {
    let plain = PlainText::new_with_data(b"@abc0abc1".to_vec());
    let mut input = PreflateInput::new(&plain);
    input.advance(5);
    assert!(short_match_rejected(&input, 4, 4, 512));
    for (distance, cutoff, window) in [(0, 4, 512), (4, 3, 512), (3, 4, 512)] {
        assert!(!short_match_rejected(&input, distance, cutoff, window));
    }
}

#[test]
fn short_match_policy_requires_sparse_references_and_repeated_contradictions() {
    use crate::deflate::deflate_token::{
        DeflateHuffmanType, DeflateToken, DeflateTokenBlock, DeflateTokenBlockType,
    };
    use crate::estimator::extract_preflate_info;

    let blocks = [DeflateTokenBlock {
        block_type: DeflateTokenBlockType::Huffman {
            tokens: std::iter::once(DeflateToken::Literal(b'a'))
                .chain(std::iter::once(DeflateToken::new_ref(3, 1)))
                .chain(std::iter::repeat_n(DeflateToken::new_ref(6, 1), 4095))
                .collect(),
            huffman_type: DeflateHuffmanType::Static,
        },
        last: true,
    }];
    let info = extract_preflate_info(&blocks);
    let baseline = TokenPredictorParameters {
        matching_type: SLOW_PREFLATE_PARSER_SETTINGS[5].match_type,
        add_policy: DictionaryAddPolicy::AddAll,
        max_dist_3_matches: info.max_dist_3_matches,
        ..crate::token_predictor::zlib_level_1_params()
    };
    for (rejections, expected) in [
        (0, baseline.max_dist_3_matches),
        (15, baseline.max_dist_3_matches),
        (16, 0),
        (256, 0),
    ] {
        let mut candidate = baseline;
        refine_short_match_policy(&mut candidate, &info, rejections);
        assert_eq!(candidate.max_dist_3_matches, expected);
    }
    let mut frequent = extract_preflate_info(&blocks);
    frequent.short_reference_count = frequent.reference_count / 512 + 1;
    let mut candidate = baseline;
    refine_short_match_policy(&mut candidate, &frequent, 256);
    assert_eq!(candidate, baseline);
    for candidate in [
        TokenPredictorParameters {
            matching_type: MatchingType::Greedy,
            ..baseline
        },
        TokenPredictorParameters {
            hash_algorithm: HashAlgorithm::RandomVector,
            ..baseline
        },
        TokenPredictorParameters {
            add_policy: DictionaryAddPolicy::AddFirst(4),
            ..baseline
        },
    ] {
        let mut result = candidate;
        refine_short_match_policy(&mut result, &info, 256);
        assert_eq!(result, candidate);
    }
}

#[derive(Default)]
pub(crate) struct WindowConstraint {
    ceiling: std::cell::Cell<Option<u32>>,
}

impl WindowConstraint {
    pub fn is_enabled(&self) -> bool {
        self.ceiling.get().is_some()
    }

    pub fn enable(&mut self, parameters: &TokenPredictorParameters) {
        if matches!(parameters.hash_algorithm, HashAlgorithm::Zlib { .. })
            && matches!(
                parameters.matching_type,
                MatchingType::Greedy | MatchingType::Lazy { .. }
            )
            && parameters.strategy
                == crate::estimator::preflate_parameter_estimator::PreflateStrategy::Default
            && !parameters.very_far_matches_detected
            && (9..15).contains(&parameters.window_bits)
        {
            self.ceiling.set(Some(32768));
        }
    }

    pub fn exclude(&self, distance: u32, first_hop: bool) {
        if let Some(ceiling) = self.ceiling.get() {
            // Hop zero admits window - MIN_LOOKAHEAD + 1; later hops admit one less.
            let maximum = distance.saturating_add(MIN_LOOKAHEAD - if first_hop { 2 } else { 1 });
            self.ceiling.set(Some(ceiling.min(maximum)));
        }
    }

    pub fn window_bits(&self, original: u32) -> Option<u32> {
        self.ceiling.get().map(|ceiling| {
            debug_assert!(ceiling >= 1 << original);
            if ceiling >= 32768 { 15 } else { original }
        })
    }
}

#[inline(always)]
pub(crate) fn distance_limits(window: u32, history: u32) -> (u32, u32) {
    let maximum = window - MIN_LOOKAHEAD + 1;
    (history.min(maximum), history.min(maximum - 1))
}

#[inline(always)]
pub(crate) fn predict_lazy(
    input: &PreflateInput,
    state: &dyn HashChainHolder,
    current: DeflateTokenReference,
    max_lazy: u16,
    behavior: LazyBehavior,
    max_chain: u32,
) -> MatchPrediction {
    if current.len() < u32::from(max_lazy) && input.remaining() >= current.len() + 2 {
        let mut max_depth = max_chain;
        if let LazyBehavior::Zlib { good_length } = behavior {
            if current.len() >= u32::from(good_length) {
                max_depth >>= 2;
            }
        }
        if let MatchResult::Success(next) = state.match_token_1(current.len(), max_depth, input) {
            if next.len() > current.len() {
                return MatchPrediction::Literal {
                    pending_reference: match behavior {
                        LazyBehavior::Zlib { .. } => Some(next),
                        LazyBehavior::RecomputeAfterLiteral => None,
                    },
                    pending_literals: 0,
                };
            }
        }
    }
    MatchPrediction::Reference
}

pub(crate) const SHORT_MATCH_CUTOFF: u32 = 4096;
pub(crate) const DEFAULT_HASH: HashAlgorithm = HashAlgorithm::Zlib {
    hash_mask: 32767,
    hash_shift: 5,
};

pub(crate) fn candidate_hashes(mem_level: u32) -> [Option<HashAlgorithm>; 3] {
    let bits = mem_level + 7;
    let memory_hash = HashAlgorithm::Zlib {
        hash_mask: ((1u32 << bits) - 1) as u16,
        hash_shift: bits.div_ceil(3),
    };
    let small_hash = HashAlgorithm::Zlib {
        hash_mask: 2047,
        hash_shift: 4,
    };
    [
        Some(memory_hash),
        (DEFAULT_HASH != memory_hash).then_some(DEFAULT_HASH),
        (small_hash != memory_hash).then_some(small_hash),
    ]
}

pub(crate) fn compatible(parameters: &TokenPredictorParameters) -> bool {
    !parameters.matches_to_start_detected
        && !parameters.very_far_matches_detected
        && (parameters.max_dist_3_matches <= SHORT_MATCH_CUTOFF
            || parameters.add_policy != DictionaryAddPolicy::AddAll)
}

pub(crate) fn project_lazy_behavior(
    mut parameters: TokenPredictorParameters,
    compatible: bool,
    observed_min_len: u32,
) -> TokenPredictorParameters {
    if let MatchingType::Lazy {
        filtered_matching,
        behavior,
        ..
    } = &mut parameters.matching_type
    {
        *filtered_matching = observed_min_len >= FILTERED_MIN_MATCH_LENGTH
            && matches!(parameters.hash_algorithm, HashAlgorithm::Zlib { .. });
        if !compatible {
            *behavior = LazyBehavior::RecomputeAfterLiteral;
        }
    }
    parameters
}

pub(crate) fn parser_settings(add_policy: DictionaryAddPolicy) -> &'static [PreflateParserConfig] {
    if add_policy == DictionaryAddPolicy::AddAll {
        &SLOW_PREFLATE_PARSER_SETTINGS
    } else {
        &ZLIB_PREFLATE_PARSER_SETTINGS
    }
}

pub(crate) fn refine_depth_candidate<'a>(
    candidates: &'a [Box<dyn HashTableDepthEstimator>],
    baseline: &'a dyn HashTableDepthEstimator,
    add_policy: DictionaryAddPolicy,
    info: &PreflateStreamInfo,
) -> &'a dyn HashTableDepthEstimator {
    let DictionaryAddPolicy::AddFirst(limit) = add_policy else {
        return baseline;
    };
    if u32::from(limit) >= info.max_len || baseline.parser_evidence().lazy_matches < 4 {
        return baseline;
    }
    let Some(config) = ZLIB_PREFLATE_PARSER_SETTINGS
        .iter()
        .find(|config| config.dictionary_add_policy == add_policy)
    else {
        return baseline;
    };
    candidates
        .iter()
        .find(|candidate| {
            matches!(candidate.hash_algorithm(), HashAlgorithm::Zlib { .. })
                && candidate.max_chain_found() < config.max_chain
                && candidate.parser_evidence().lazy_matches == 0
        })
        .map_or(baseline, |candidate| candidate.as_ref())
}

pub(crate) fn refine_parameters(
    estimate: ParameterEstimate,
    depth: &DepthEstimate,
    info: &PreflateStreamInfo,
    contents: &DeflateContents,
    plain: &PlainText,
) -> ParameterEstimate {
    let parameters = estimate.parameters();
    let ambiguous_insertion = InsertionConstraint::observe(parameters.add_policy, info.max_len)
        == InsertionConstraint::Unresolved;
    if depth.zlib_candidates.is_empty()
        || matches!(
            parameters.hash_algorithm,
            HashAlgorithm::Libdeflate4Fast15 | HashAlgorithm::Chromium { .. }
        )
        || (!ambiguous_insertion
            && info.min_len < 6
            && matches!(parameters.hash_algorithm, HashAlgorithm::Zlib { .. }))
        || info.matches_to_start_detected
        || info.max_dist_3_matches > SHORT_MATCH_CUTOFF
    {
        return estimate;
    }
    let score = |params: &TokenPredictorParameters| {
        TokenPredictor::new(params)
            .score_predictions(&contents.blocks, plain, 1024, 262144)
            .0
    };
    let baseline_score = score(&parameters);
    if baseline_score < 2 {
        return estimate;
    }
    let mut best = parameters;
    let mut best_score = baseline_score;
    for candidate in &depth.zlib_candidates {
        if candidate.distance_policy != DistancePolicy::ZlibWindow {
            continue;
        }
        let inferred = SLOW_PREFLATE_PARSER_SETTINGS
            .iter()
            .position(|settings| settings.max_chain >= candidate.required_chain)
            .unwrap_or(SLOW_PREFLATE_PARSER_SETTINGS.len() - 1);
        for (position, index) in [inferred, 2].into_iter().enumerate() {
            if position == 1 && inferred == 2 {
                continue;
            }
            let settings = &SLOW_PREFLATE_PARSER_SETTINGS[index];
            let trial = TokenPredictorParameters {
                hash_algorithm: candidate.hash_algorithm,
                matching_type: settings.match_type,
                add_policy: DictionaryAddPolicy::AddAll,
                nice_length: settings.nice_length,
                max_chain: settings.max_chain,
                very_far_matches_detected: false,
                window_bits: estimate_preflate_window_bits(info.max_dist),
                max_dist_3_matches: info.max_dist_3_matches,
                ..parameters
            }
            .with_lazy_behavior(true, info.min_len);
            let trial_score = score(&trial);
            if trial_score < best_score {
                best = trial;
                best_score = trial_score;
                if best_score == 0 {
                    return ParameterEstimate::PrefixValidated(best);
                }
            }
        }
    }
    if best_score * 4 <= baseline_score * 3 {
        ParameterEstimate::PrefixValidated(best)
    } else {
        estimate
    }
}

pub const ZLIB_PREFLATE_PARSER_SETTINGS: [PreflateParserConfig; 3] = [
    PreflateParserConfig {
        match_type: MatchingType::Greedy,
        dictionary_add_policy: DictionaryAddPolicy::AddFirst(4),
        nice_length: 8,
        max_chain: 4,
    },
    PreflateParserConfig {
        match_type: MatchingType::Greedy,
        dictionary_add_policy: DictionaryAddPolicy::AddFirst(5),
        nice_length: 16,
        max_chain: 8,
    },
    PreflateParserConfig {
        match_type: MatchingType::Greedy,
        dictionary_add_policy: DictionaryAddPolicy::AddFirst(6),
        nice_length: 32,
        max_chain: 32,
    },
];

pub const SLOW_PREFLATE_PARSER_SETTINGS: [PreflateParserConfig; 6] = [
    PreflateParserConfig {
        match_type: MatchingType::Lazy {
            max_lazy: 4,
            filtered_matching: false,
            behavior: LazyBehavior::Zlib { good_length: 4 },
        },
        dictionary_add_policy: DictionaryAddPolicy::AddAll,
        nice_length: 16,
        max_chain: 16,
    },
    PreflateParserConfig {
        match_type: MatchingType::Lazy {
            max_lazy: 16,
            filtered_matching: false,
            behavior: LazyBehavior::Zlib { good_length: 8 },
        },
        dictionary_add_policy: DictionaryAddPolicy::AddAll,
        nice_length: 32,
        max_chain: 32,
    },
    PreflateParserConfig {
        match_type: MatchingType::Lazy {
            max_lazy: 16,
            filtered_matching: false,
            behavior: LazyBehavior::Zlib { good_length: 8 },
        },
        dictionary_add_policy: DictionaryAddPolicy::AddAll,
        nice_length: 128,
        max_chain: 128,
    },
    PreflateParserConfig {
        match_type: MatchingType::Lazy {
            max_lazy: 32,
            filtered_matching: false,
            behavior: LazyBehavior::Zlib { good_length: 8 },
        },
        dictionary_add_policy: DictionaryAddPolicy::AddAll,
        nice_length: 128,
        max_chain: 256,
    },
    PreflateParserConfig {
        match_type: MatchingType::Lazy {
            max_lazy: 128,
            filtered_matching: false,
            behavior: LazyBehavior::Zlib { good_length: 32 },
        },
        dictionary_add_policy: DictionaryAddPolicy::AddAll,
        nice_length: 258,
        max_chain: 1024,
    },
    PreflateParserConfig {
        match_type: MatchingType::Lazy {
            max_lazy: 258,
            filtered_matching: false,
            behavior: LazyBehavior::Zlib { good_length: 32 },
        },
        dictionary_add_policy: DictionaryAddPolicy::AddAll,
        nice_length: 258,
        max_chain: 4096,
    },
];

#[test]
fn verify_zlib_recognition() {
    use crate::{
        deflate::deflate_reader::parse_deflate_whole,
        estimator::preflate_parameter_estimator::{PreflateStrategy, estimate_preflate_parameters},
        utils::read_file,
    };

    for level in 0..=9 {
        let compressed = read_file(&format!("compressed_zlib_level{level}.deflate"));
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        let parameters = estimate_preflate_parameters(&contents, &plain).unwrap();
        assert!(compatible(&parameters));
        if level == 0 {
            assert_eq!(parameters.strategy, PreflateStrategy::Store);
            continue;
        }
        let config = if level < 4 {
            &ZLIB_PREFLATE_PARSER_SETTINGS[level - 1]
        } else {
            &SLOW_PREFLATE_PARSER_SETTINGS[level - 4]
        };
        assert!(
            parameters.max_chain <= config.max_chain,
            "level {level}: chain {} exceeds {}",
            parameters.max_chain,
            config.max_chain
        );
        assert_eq!(parameters.matching_type, config.match_type);
        assert_eq!(parameters.add_policy, config.dictionary_add_policy);
        assert_eq!(parameters.nice_length, config.nice_length);
        assert_eq!(parameters.strategy, PreflateStrategy::Default);
    }
}
