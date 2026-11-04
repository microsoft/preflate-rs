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
        prediction_scoring::{score_predictions, score_refinement},
        preflate_parameter_estimator::estimate_preflate_window_bits,
    },
    hash_algorithm::HashAlgorithm,
    hash_chain_holder::{HashChainHolder, MatchResult},
    parameters::{
        DictionaryAddPolicy, LazyBehavior, MatchingType, PreflateParserConfig, PreflateStrategy,
        TokenPredictorParameters,
    },
    preflate_input::{PlainText, PreflateInput},
    reconstruction_parameters::{
        ChainDistancePolicy, DictionarySettings, LazyLookaheadSettings, SearchBudget,
    },
};

use super::MatchPrediction;

impl TokenPredictorParameters {
    pub(crate) fn with_lazy_behavior(self, zlib_compatible: bool, observed_min_len: u32) -> Self {
        project_lazy_behavior(self, zlib_compatible, observed_min_len)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Profile(pub(crate) TokenPredictorParameters);

impl Profile {
    pub(super) fn ambiguous_fast_hash(
        parameters: TokenPredictorParameters,
        info: &PreflateStreamInfo,
    ) -> Option<Self> {
        if !matches!(parameters.hash_algorithm, HashAlgorithm::Zlib { .. })
            || parameters.matching_type != MatchingType::Greedy
            || parameters.strategy != PreflateStrategy::Default
        {
            return None;
        }
        let hash_algorithm = adjacent_memory_hash(info, parameters.add_policy)?;
        (hash_algorithm != parameters.hash_algorithm).then_some(Self(TokenPredictorParameters {
            hash_algorithm,
            ..parameters
        }))
    }

    pub(super) fn parameters(self) -> TokenPredictorParameters {
        self.0
    }

    pub(super) fn parameters_mut(&mut self) -> &mut TokenPredictorParameters {
        &mut self.0
    }

    pub(super) fn flush(
        parameters: TokenPredictorParameters,
        info: &PreflateStreamInfo,
    ) -> Option<Self> {
        flush_alternative(parameters, info).map(Self)
    }

    pub(super) fn memory_hash(
        parameters: TokenPredictorParameters,
        info: &PreflateStreamInfo,
    ) -> Option<Self> {
        if parameters.hash_algorithm != super::windows::HASH
            || parameters.add_policy != DictionaryAddPolicy::AddAll
            || !compatible(&parameters)
        {
            return None;
        }
        let capacity = canonical_token_capacity(&parameters, info)?;
        let hash_algorithm = memory_hash(capacity.ilog2() - 6);
        Some(Self(TokenPredictorParameters {
            hash_algorithm,
            ..parameters
        }))
    }

    pub(super) fn filtered_hash(
        parameters: TokenPredictorParameters,
        info: &PreflateStreamInfo,
    ) -> Option<Self> {
        let settings = &SLOW_PREFLATE_PARSER_SETTINGS[2];
        if parameters.hash_algorithm != HashAlgorithm::Libdeflate4Fast
            || parameters.add_policy != DictionaryAddPolicy::AddAll
            || parameters.matching_type != settings.match_type
            || parameters.nice_length != settings.nice_length
            || parameters.max_chain <= SLOW_PREFLATE_PARSER_SETTINGS[1].max_chain
            || parameters.max_chain > settings.max_chain
            || info.min_len < FILTERED_MIN_MATCH_LENGTH
            || !compatible(&parameters)
        {
            return None;
        }
        canonical_token_capacity(&parameters, info)?;
        Some(Self(
            TokenPredictorParameters {
                hash_algorithm: DEFAULT_HASH,
                matching_type: settings.match_type,
                nice_length: settings.nice_length,
                max_chain: settings.max_chain,
                max_dist_3_matches: 0,
                ..parameters
            }
            .with_lazy_behavior(true, info.min_len),
        ))
    }

    pub(super) fn noncanonical_insertion(
        parameters: TokenPredictorParameters,
        info: &PreflateStreamInfo,
    ) -> Option<Self> {
        if !matches!(parameters.add_policy, DictionaryAddPolicy::AddFirst(limit) if limit > 6)
            || !matches!(
                parameters.hash_algorithm,
                HashAlgorithm::Zlib { .. }
                    | HashAlgorithm::RandomVector
                    | HashAlgorithm::Libdeflate4
            )
            || !matches!(
                parameters.matching_type,
                MatchingType::Greedy | MatchingType::Lazy { .. }
            )
            || parameters.strategy != PreflateStrategy::Default
            || parameters.window_bits != 15
            || parameters.matches_to_start_detected
            || info.min_len != 3
            || info.max_tokens_per_block < 64
        {
            return None;
        }
        let settings = &SLOW_PREFLATE_PARSER_SETTINGS[2];
        Some(Self(TokenPredictorParameters {
            hash_algorithm: DEFAULT_HASH,
            add_policy: settings.dictionary_add_policy,
            matching_type: settings.match_type,
            nice_length: settings.nice_length,
            max_chain: settings.max_chain,
            max_dist_3_matches: SHORT_MATCH_CUTOFF,
            very_far_matches_detected: false,
            ..parameters
        }))
    }
}

pub(crate) const FILTERED_MIN_MATCH_LENGTH: u32 = 6;

#[test]
fn noncanonical_insertion_uses_a_complete_coupled_zlib_tuple() {
    let parameters = TokenPredictorParameters {
        hash_algorithm: HashAlgorithm::Libdeflate4,
        add_policy: DictionaryAddPolicy::AddFirst(147),
        max_chain: 3525,
        nice_length: 255,
        max_dist_3_matches: 26306,
        very_far_matches_detected: true,
        max_token_count: 32767,
        ..crate::token_predictor::zlib_level_1_params()
    };
    let mut info = crate::estimator::extract_preflate_info(&[]);
    info.min_len = 3;
    info.max_tokens_per_block = 12288;
    let settings = &SLOW_PREFLATE_PARSER_SETTINGS[2];
    assert_eq!(
        Profile::noncanonical_insertion(parameters, &info),
        Some(Profile(TokenPredictorParameters {
            hash_algorithm: DEFAULT_HASH,
            add_policy: DictionaryAddPolicy::AddAll,
            matching_type: settings.match_type,
            max_chain: 128,
            nice_length: 128,
            max_dist_3_matches: SHORT_MATCH_CUTOFF,
            very_far_matches_detected: false,
            ..parameters
        })),
    );
    for candidate in [
        TokenPredictorParameters {
            add_policy: DictionaryAddPolicy::AddFirst(6),
            ..parameters
        },
        TokenPredictorParameters {
            add_policy: DictionaryAddPolicy::AddAll,
            ..parameters
        },
        TokenPredictorParameters {
            hash_algorithm: HashAlgorithm::Libdeflate4Fast15,
            ..parameters
        },
        TokenPredictorParameters {
            matching_type: MatchingType::LibdeflateLazy {
                two_positions: true,
            },
            ..parameters
        },
        TokenPredictorParameters {
            window_bits: 14,
            ..parameters
        },
        TokenPredictorParameters {
            matches_to_start_detected: true,
            ..parameters
        },
        TokenPredictorParameters {
            strategy: PreflateStrategy::RleOnly,
            ..parameters
        },
    ] {
        assert_eq!(
            Profile::noncanonical_insertion(candidate, &info),
            None,
            "{candidate:?}"
        );
    }
    info.min_len = 4;
    assert_eq!(Profile::noncanonical_insertion(parameters, &info), None);
    info.min_len = 3;
    info.max_tokens_per_block = 63;
    assert_eq!(Profile::noncanonical_insertion(parameters, &info), None);
}

fn canonical_token_capacity(
    parameters: &TokenPredictorParameters,
    info: &PreflateStreamInfo,
) -> Option<u32> {
    let capacity = u32::from(parameters.max_token_count) + 1;
    (info.max_tokens_per_block == u32::from(parameters.max_token_count)
        && (128..=32768).contains(&capacity)
        && capacity.is_power_of_two())
    .then_some(capacity)
}

#[test]
fn filtered_hash_requires_the_coupled_lazy_tuple_and_complete_canonical_buffer() {
    let settings = &SLOW_PREFLATE_PARSER_SETTINGS[2];
    let baseline = TokenPredictorParameters {
        hash_algorithm: HashAlgorithm::Libdeflate4Fast,
        matching_type: settings.match_type,
        nice_length: settings.nice_length,
        max_chain: 126,
        max_dist_3_matches: 0,
        add_policy: DictionaryAddPolicy::AddAll,
        ..crate::token_predictor::zlib_level_1_params()
    };
    let mut info = crate::estimator::extract_preflate_info(&[]);
    for maximum_tokens in [8191, 16383, 32767] {
        let parameters = TokenPredictorParameters {
            max_token_count: maximum_tokens,
            ..baseline
        };
        info.max_tokens_per_block = u32::from(maximum_tokens);
        for minimum in [6, 7, 258] {
            info.min_len = minimum;
            let candidate = Profile::filtered_hash(parameters, &info).unwrap();
            assert_eq!(
                candidate,
                Profile(
                    TokenPredictorParameters {
                        hash_algorithm: DEFAULT_HASH,
                        max_chain: settings.max_chain,
                        ..parameters
                    }
                    .with_lazy_behavior(true, minimum)
                ),
            );
        }
        for minimum in [3, 4, 5] {
            info.min_len = minimum;
            assert_eq!(Profile::filtered_hash(parameters, &info), None);
        }
        info.min_len = 6;
        info.max_tokens_per_block -= 1;
        assert_eq!(Profile::filtered_hash(parameters, &info), None);
    }
    info.min_len = 6;
    for parameters in [
        TokenPredictorParameters {
            hash_algorithm: HashAlgorithm::Libdeflate4Fast15,
            ..baseline
        },
        TokenPredictorParameters {
            hash_algorithm: HashAlgorithm::Libdeflate4,
            ..baseline
        },
        TokenPredictorParameters {
            matching_type: MatchingType::LibdeflateLazy {
                two_positions: true,
            },
            ..baseline
        },
        TokenPredictorParameters {
            matching_type: MatchingType::Greedy,
            ..baseline
        },
        TokenPredictorParameters {
            max_chain: 32,
            ..baseline
        },
        TokenPredictorParameters {
            max_chain: 129,
            ..baseline
        },
        TokenPredictorParameters {
            nice_length: 258,
            ..baseline
        },
        TokenPredictorParameters {
            max_token_count: 2000,
            ..baseline
        },
        TokenPredictorParameters {
            max_token_count: 63,
            ..baseline
        },
        TokenPredictorParameters {
            max_token_count: u16::MAX,
            ..baseline
        },
        TokenPredictorParameters {
            add_policy: DictionaryAddPolicy::AddFirst(4),
            ..baseline
        },
        TokenPredictorParameters {
            matches_to_start_detected: true,
            ..baseline
        },
        TokenPredictorParameters {
            very_far_matches_detected: true,
            ..baseline
        },
        TokenPredictorParameters {
            max_dist_3_matches: SHORT_MATCH_CUTOFF + 1,
            ..baseline
        },
    ] {
        info.max_tokens_per_block = u32::from(parameters.max_token_count);
        assert_eq!(
            Profile::filtered_hash(parameters, &info),
            None,
            "{parameters:?}"
        );
    }
}

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

    pub fn enable(
        &mut self,
        dictionary: &DictionarySettings,
        distance: ChainDistancePolicy,
        eligible_parser: bool,
    ) {
        if matches!(dictionary.hash.into_algorithm(), HashAlgorithm::Zlib { .. })
            && eligible_parser
            && matches!(distance, ChainDistancePolicy::HashWindow(_))
            && (9..15).contains(&dictionary.window_bits)
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

pub(crate) fn supports_deferred_cutoff(parameters: &TokenPredictorParameters) -> bool {
    matches!(
        parameters.hash_algorithm,
        HashAlgorithm::Zlib { .. } | HashAlgorithm::RandomVector
    ) && parameters.add_policy != DictionaryAddPolicy::AddFirstExcept4kBoundary
        && parameters.nice_length >= 4
        && matches!(
            parameters.matching_type,
            MatchingType::Lazy {
                max_lazy: 4..,
                filtered_matching: false,
                behavior: LazyBehavior::Zlib { good_length: 4.. }
                    | LazyBehavior::RecomputeAfterLiteral,
            }
        )
}

#[derive(Clone, Copy)]
pub(crate) struct DeferredCutoff {
    distance: u32,
    position: u32,
    end: u32,
}

impl DeferredCutoff {
    pub(crate) fn new(input: &PreflateInput, distance: u32) -> Option<Self> {
        // Stay before hash-table reshift and exclude prefixed/continuation history.
        (input.pos() < 32768 && input.bytes_before() == input.pos() && input.remaining() >= 5)
            .then_some(Self {
                distance,
                position: input.pos(),
                end: input.total_length(),
            })
    }

    pub(crate) fn upper_bound(self) -> u32 {
        self.distance - 1
    }

    pub(crate) fn resolved_by(self, input: &PreflateInput, found: MatchResult) -> bool {
        // Default chains virtually insert the current literal in OFFSET=1 searches.
        // With identical budgets and nice_length > 3, a fresh result longer than
        // three is also the previous position's lazy result. Its cached and fresh
        // paths therefore converge before making this position's prediction.
        input.pos() == self.position + 1
            && input.total_length() == self.end
            && matches!(found, MatchResult::Success(reference) if reference.len() > 3)
    }
}

#[test]
fn deferred_cutoff_proofs_reject_unsupported_search_policies() {
    let parameters = TokenPredictorParameters {
        matching_type: SLOW_PREFLATE_PARSER_SETTINGS[2].match_type,
        ..crate::token_predictor::zlib_level_1_params()
    };
    assert!(supports_deferred_cutoff(&parameters));
    for parameters in [
        TokenPredictorParameters {
            nice_length: 3,
            ..parameters
        },
        TokenPredictorParameters {
            hash_algorithm: HashAlgorithm::Libdeflate4,
            ..parameters
        },
        TokenPredictorParameters {
            add_policy: DictionaryAddPolicy::AddFirstExcept4kBoundary,
            ..parameters
        },
        TokenPredictorParameters {
            matching_type: MatchingType::Greedy,
            ..parameters
        },
        TokenPredictorParameters {
            matching_type: MatchingType::Lazy {
                max_lazy: 16,
                filtered_matching: false,
                behavior: LazyBehavior::Zlib { good_length: 3 },
            },
            ..parameters
        },
    ] {
        assert!(!supports_deferred_cutoff(&parameters));
    }
    let plain = PlainText::new_with_data(vec![b'a'; 32780]);
    let mut input = PreflateInput::new(&plain);
    input.advance(32767);
    let proof = DeferredCutoff::new(&input, 4).unwrap();
    assert!(!proof.resolved_by(
        &input,
        MatchResult::Success(DeflateTokenReference::new(4, 1))
    ));
    input.advance(1);
    assert!(DeferredCutoff::new(&input, 4).is_none());
    assert!(proof.resolved_by(
        &input,
        MatchResult::Success(DeflateTokenReference::new(4, 1))
    ));
    assert!(!proof.resolved_by(
        &input,
        MatchResult::Success(DeflateTokenReference::new(3, 1))
    ));
    assert!(!proof.resolved_by(&input, MatchResult::NoMoreMatchesFound));
}

#[inline(always)]
pub(crate) fn predict_lazy(
    input: &PreflateInput,
    state: &dyn HashChainHolder,
    current: DeflateTokenReference,
    lookahead: LazyLookaheadSettings,
    budget: SearchBudget,
) -> MatchPrediction {
    if current.len() < u32::from(lookahead.max_lazy) && input.remaining() >= current.len() + 2 {
        let mut max_depth = budget.max_chain;
        if let LazyBehavior::Zlib { good_length } = lookahead.behavior
            && current.len() >= u32::from(good_length)
        {
            max_depth >>= 2;
        }
        if let MatchResult::Success(next) = state.match_token_1(current.len(), max_depth, input)
            && next.len() > current.len()
        {
            return MatchPrediction::Literal {
                pending_reference: match lookahead.behavior {
                    LazyBehavior::Zlib { .. } => Some(next),
                    LazyBehavior::RecomputeAfterLiteral => None,
                },
                pending_literals: 0,
            };
        }
    }
    MatchPrediction::Reference
}

pub(crate) const SHORT_MATCH_CUTOFF: u32 = 4096;
pub(crate) const DEFAULT_HASH: HashAlgorithm = HashAlgorithm::Zlib {
    hash_mask: 32767,
    hash_shift: 5,
};

pub(crate) fn memory_hash(mem_level: u32) -> HashAlgorithm {
    let bits = mem_level + 7;
    HashAlgorithm::Zlib {
        hash_mask: ((1u32 << bits) - 1) as u16,
        hash_shift: bits.div_ceil(3),
    }
}

pub(crate) struct HashCandidates {
    pub memory: HashAlgorithm,
    pub default: Option<HashAlgorithm>,
    pub small: Option<HashAlgorithm>,
}

pub(crate) fn candidate_hashes(mem_level: u32) -> HashCandidates {
    let memory = memory_hash(mem_level);
    let small_hash = HashAlgorithm::Zlib {
        hash_mask: 2047,
        hash_shift: 4,
    };
    HashCandidates {
        memory,
        default: (DEFAULT_HASH != memory).then_some(DEFAULT_HASH),
        small: (small_hash != memory).then_some(small_hash),
    }
}

pub(crate) fn supported_memory_hash(info: &PreflateStreamInfo) -> Option<HashAlgorithm> {
    let tokens = info.max_unflushed_tokens_per_block;
    let capacity = tokens + 1;
    // An ordinary boundary is stronger evidence, not proof of compressor identity.
    (tokens == info.max_tokens_per_block
        && (128..=32768).contains(&capacity)
        && capacity.is_power_of_two())
    .then(|| memory_hash(capacity.ilog2() - 6))
}

pub(crate) fn adjacent_memory_hash(
    info: &PreflateStreamInfo,
    insertion: DictionaryAddPolicy,
) -> Option<HashAlgorithm> {
    if supported_memory_hash(info).is_some()
        || info.min_len != 3
        || info.max_tokens_per_block < 64
        || !matches!(insertion, DictionaryAddPolicy::AddFirst(4..=6))
    {
        return None;
    }
    let bits = (info.max_tokens_per_block.ilog2() + 1).clamp(7, 15);
    // The inferred buffer is only a lower bound when no ordinary boundary supports it.
    (bits < 15).then(|| memory_hash(bits - 6 + 1))
}

#[test]
fn adjacent_hash_requires_ambiguous_fast_capacity_and_preserves_the_search_tuple() {
    let mut info = crate::estimator::extract_preflate_info(&[]);
    info.min_len = 3;
    info.max_tokens_per_block = 3655;
    let parameters = crate::token_predictor::zlib_level_1_params();
    let expected = memory_hash(7);
    assert_eq!(
        adjacent_memory_hash(&info, parameters.add_policy),
        Some(expected)
    );
    assert_eq!(
        Profile::ambiguous_fast_hash(parameters, &info),
        Some(Profile(TokenPredictorParameters {
            hash_algorithm: expected,
            ..parameters
        }))
    );
    for insertion in [
        DictionaryAddPolicy::AddAll,
        DictionaryAddPolicy::AddFirst(0),
        DictionaryAddPolicy::AddFirst(7),
        DictionaryAddPolicy::AddFirstAndLast(4),
    ] {
        assert_eq!(adjacent_memory_hash(&info, insertion), None);
    }
    for candidate in [
        TokenPredictorParameters {
            hash_algorithm: expected,
            ..parameters
        },
        TokenPredictorParameters {
            hash_algorithm: HashAlgorithm::RandomVector,
            ..parameters
        },
        TokenPredictorParameters {
            matching_type: SLOW_PREFLATE_PARSER_SETTINGS[2].match_type,
            ..parameters
        },
        TokenPredictorParameters {
            strategy: PreflateStrategy::RleOnly,
            ..parameters
        },
    ] {
        assert_eq!(Profile::ambiguous_fast_hash(candidate, &info), None);
    }
    info.max_tokens_per_block = 4095;
    info.max_unflushed_tokens_per_block = 4095;
    assert_eq!(adjacent_memory_hash(&info, parameters.add_policy), None);
    info.max_unflushed_tokens_per_block = 0;
    info.max_tokens_per_block = 32767;
    assert_eq!(adjacent_memory_hash(&info, parameters.add_policy), None);
    info.max_tokens_per_block = 63;
    assert_eq!(adjacent_memory_hash(&info, parameters.add_policy), None);
}

#[test]
fn memory_hash_requires_a_full_canonical_buffer_and_zlib_compatible_distances() {
    let baseline = TokenPredictorParameters {
        hash_algorithm: super::windows::HASH,
        add_policy: DictionaryAddPolicy::AddAll,
        max_dist_3_matches: SHORT_MATCH_CUTOFF,
        ..crate::token_predictor::zlib_level_1_params()
    };
    let mut info = crate::estimator::extract_preflate_info(&[]);
    for bits in 7..=15 {
        let parameters = TokenPredictorParameters {
            max_token_count: (1u16 << bits) - 1,
            ..baseline
        };
        info.max_tokens_per_block = u32::from(parameters.max_token_count);
        assert_eq!(
            Profile::memory_hash(parameters, &info),
            Some(Profile(TokenPredictorParameters {
                hash_algorithm: memory_hash(bits - 6),
                ..parameters
            }))
        );
        info.max_tokens_per_block -= 1;
        assert_eq!(Profile::memory_hash(parameters, &info), None);
        info.max_tokens_per_block += 2;
        assert_eq!(Profile::memory_hash(parameters, &info), None);
    }
    for parameters in [
        TokenPredictorParameters {
            max_token_count: 63,
            ..baseline
        },
        TokenPredictorParameters {
            max_token_count: 2000,
            ..baseline
        },
        TokenPredictorParameters {
            max_token_count: u16::MAX,
            ..baseline
        },
        TokenPredictorParameters {
            hash_algorithm: DEFAULT_HASH,
            ..baseline
        },
        TokenPredictorParameters {
            very_far_matches_detected: true,
            ..baseline
        },
        TokenPredictorParameters {
            matches_to_start_detected: true,
            ..baseline
        },
        TokenPredictorParameters {
            max_dist_3_matches: SHORT_MATCH_CUTOFF + 1,
            ..baseline
        },
        TokenPredictorParameters {
            add_policy: DictionaryAddPolicy::AddFirst(4),
            ..baseline
        },
    ] {
        info.max_tokens_per_block = u32::from(parameters.max_token_count);
        assert_eq!(
            Profile::memory_hash(parameters, &info),
            None,
            "{parameters:?}"
        );
    }
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

pub(crate) fn greedy_nice_length(
    parameters: &TokenPredictorParameters,
    minimum_nice_length: u16,
) -> Option<u32> {
    let observed_limit = match parameters.add_policy {
        DictionaryAddPolicy::AddFirst(limit) | DictionaryAddPolicy::AddFirstAndLast(limit) => limit,
        DictionaryAddPolicy::AddFirstWith32KBoundary => 0,
        _ => return None,
    };
    // Both observations are lower bounds, not independent compressor-level identities.
    ZLIB_PREFLATE_PARSER_SETTINGS
        .iter()
        .find(|config| {
            matches!(config.dictionary_add_policy, DictionaryAddPolicy::AddFirst(limit)
                if limit >= observed_limit)
                && config.max_chain >= parameters.max_chain
                && config.nice_length >= u32::from(minimum_nice_length)
        })
        .map(|config| config.nice_length)
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
    let extension_hash = canonical_token_capacity(&parameters, info)
        .map(|capacity| memory_hash(capacity.ilog2() - 6))
        .filter(|&hash| {
            info.min_len == 3
                && depth.zlib_candidates.iter().any(|candidate| {
                    candidate.hash_algorithm == hash
                        && candidate.distance_policy == DistancePolicy::ZlibWindow
                        && candidate.required_chain <= SLOW_PREFLATE_PARSER_SETTINGS[2].max_chain
                })
        });
    let adaptive = contents.compressed_size > 1024
        && extension_hash.is_some()
        && parameters.hash_algorithm == HashAlgorithm::RandomVector
        && parameters.add_policy == DictionaryAddPolicy::AddAll
        && matches!(parameters.matching_type, MatchingType::Lazy { .. });
    let score = |parameters: &TokenPredictorParameters| {
        score_predictions(
            &mut crate::prediction_state::PredictionState::new(parameters),
            &contents.blocks,
            plain,
            1024,
            262144,
        )
        .0
    };
    let mut best = parameters;
    let mut best_score = if adaptive { 0 } else { score(&parameters) };
    let baseline_score = best_score;
    if !adaptive && baseline_score < 2 {
        return estimate;
    }
    let mut candidates = if adaptive {
        vec![parameters]
    } else {
        Vec::new()
    };
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
            if adaptive && !candidates.contains(&trial) {
                candidates.push(trial);
            }
            if !adaptive {
                let trial_score = score(&trial);
                if trial_score < best_score {
                    best = trial;
                    best_score = trial_score;
                    if best_score == 0 {
                        return ParameterEstimate::PrefixValidated(super::CompressorProfile::Zlib(
                            Profile(best),
                        ));
                    }
                }
            }
        }
    }
    if !adaptive {
        return if best_score * 4 <= baseline_score * 3 {
            ParameterEstimate::PrefixValidated(super::CompressorProfile::Zlib(Profile(best)))
        } else {
            estimate
        };
    }
    if candidates.len() < 2 {
        return estimate;
    }
    let extension = candidates
        .iter()
        .enumerate()
        .skip(1)
        .find_map(|(index, candidate)| {
            (Some(candidate.hash_algorithm) == extension_hash
                && candidate.matching_type == SLOW_PREFLATE_PARSER_SETTINGS[2].match_type
                && candidate.max_chain == SLOW_PREFLATE_PARSER_SETTINGS[2].max_chain)
                .then_some(index)
        })
        .expect("surviving memory hash has a level-six candidate");
    let scores = score_refinement(&candidates, &contents.blocks, plain, 1024, extension);
    if scores.tokens == 0 {
        return estimate;
    }
    let errors = if scores.decisive {
        &scores.errors
    } else {
        &scores.prefix_errors
    };
    let (index, &best_score) = errors
        .iter()
        .enumerate()
        .min_by_key(|&(_, errors)| errors)
        .unwrap();
    if index != 0 && errors[0] >= 2 && best_score * 4 <= errors[0] * 3 {
        return ParameterEstimate::PrefixValidated(super::CompressorProfile::Zlib(Profile(
            candidates[index],
        )));
    }
    estimate
}

pub(crate) fn flush_alternative(
    parameters: TokenPredictorParameters,
    info: &PreflateStreamInfo,
) -> Option<TokenPredictorParameters> {
    let hash_algorithm = HashAlgorithm::Zlib {
        hash_mask: 16383,
        hash_shift: 5,
    };
    let known_flush = parameters.hash_algorithm == hash_algorithm
        && parameters.max_chain == 32
        && info.count_stored_blocks != 0;
    let underestimated_memory = matches!(
        parameters.hash_algorithm,
        HashAlgorithm::Zlib { .. } | HashAlgorithm::RandomVector
    ) && parameters.max_token_count < 8191
        && info.min_len == 3
        && !info.matches_to_start_detected
        && info.max_dist_3_matches <= SHORT_MATCH_CUTOFF
        && (parameters.add_policy == DictionaryAddPolicy::AddAll
            || matches!(parameters.add_policy, DictionaryAddPolicy::AddFirst(limit) if limit > 6));
    if !(known_flush && parameters.add_policy == DictionaryAddPolicy::AddAll
        || underestimated_memory)
    {
        return None;
    }
    Some(TokenPredictorParameters {
        matching_type: MatchingType::Lazy {
            max_lazy: 4,
            filtered_matching: false,
            behavior: LazyBehavior::Zlib { good_length: 8 },
        },
        nice_length: 258,
        max_chain: 32,
        add_policy: DictionaryAddPolicy::AddAll,
        hash_algorithm,
        window_bits: if known_flush {
            parameters.window_bits
        } else {
            15
        },
        max_dist_3_matches: if known_flush {
            parameters.max_dist_3_matches
        } else {
            SHORT_MATCH_CUTOFF
        },
        ..parameters
    })
}

#[test]
fn partial_block_hash_alternative_preserves_known_flush_limits() {
    let parameters = TokenPredictorParameters {
        add_policy: DictionaryAddPolicy::AddAll,
        matching_type: SLOW_PREFLATE_PARSER_SETTINGS[3].match_type,
        max_token_count: 4095,
        hash_algorithm: HashAlgorithm::Zlib {
            hash_mask: 8191,
            hash_shift: 5,
        },
        ..crate::token_predictor::zlib_level_1_params()
    };
    let mut info = crate::estimator::extract_preflate_info(&[]);
    info.min_len = 3;
    info.max_dist_3_matches = 3992;
    let result = flush_alternative(parameters, &info).unwrap();
    assert_eq!(
        result.hash_algorithm,
        HashAlgorithm::Zlib {
            hash_mask: 16383,
            hash_shift: 5
        }
    );
    assert_eq!(result.max_chain, 32);
    assert_eq!(result.nice_length, 258);
    assert_eq!(result.max_dist_3_matches, 4096);
    for (minimum, source_zero, short_distance) in
        [(4, false, 3992), (3, true, 3992), (3, false, 4097)]
    {
        info.min_len = minimum;
        info.matches_to_start_detected = source_zero;
        info.max_dist_3_matches = short_distance;
        assert!(flush_alternative(parameters, &info).is_none());
    }
    let known = TokenPredictorParameters {
        hash_algorithm: result.hash_algorithm,
        max_chain: 32,
        window_bits: 14,
        max_dist_3_matches: 4076,
        ..parameters
    };
    info.count_stored_blocks = 1;
    let result = flush_alternative(known, &info).unwrap();
    assert_eq!(result.window_bits, 14);
    assert_eq!(result.max_dist_3_matches, 4076);
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
        estimator::preflate_parameter_estimator::estimate_preflate_parameters,
        parameters::PreflateStrategy, utils::read_file,
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
