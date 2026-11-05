//! Zlib recognition, coupled profile defaults, and evidence-based refinements.
//!
//! Zlib's parser, insertion policy, search budget, and early-exit lengths form
//! coupled level settings. The model combines those defaults with evidence about
//! hash-table size, token-buffer capacity, distances, and flush boundaries.
//!
//! Ambiguous hashes and parser settings can propose bounded replay candidates.
//! Their acceptance uses the estimator's shared scoring policy, while the
//! executable lazy matching and safe cutoff proofs live in `compressors::zlib`.

use crate::reconstruction_parameters::{ChainParser, LazyLookaheadSettings, LazyMinimum};
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use crate::{
    compressors::zlib::{DEFAULT_HASH, FILTERED_MIN_MATCH_LENGTH, SHORT_MATCH_CUTOFF, memory_hash},
    deflate::{deflate_constants::MIN_LOOKAHEAD, deflate_reader::DeflateContents},
    estimator::{
        complevel_estimator::{CandidateEvidence, DepthEstimate},
        compressor_profile::{CompressorProfile, EstimateProvenance, ParameterEstimate},
        depth_estimator::{DistancePolicy, HashTableDepthEstimator},
        initial_estimate::InitialEstimate,
        parser_estimator::InsertionConstraint,
        prediction_scoring::{score_predictions, score_refinement},
        preflate_parameter_estimator::estimate_preflate_window_bits,
        preflate_stream_info::PreflateStreamInfo,
    },
    hash_algorithm::HashAlgorithm,
    parameters::{DictionaryAddPolicy, LazyBehavior, PreflateParserConfig},
    preflate_input::{PlainText, PreflateInput},
    reconstruction_parameters::ReconstructionParameters,
};

fn distance_limits(window: u32, history: u32) -> (u32, u32) {
    let maximum = window - MIN_LOOKAHEAD + 1;
    (history.min(maximum), history.min(maximum - 1))
}

pub fn table_hash_fast(
    parameters: ReconstructionParameters,
    info: &PreflateStreamInfo,
    candidates: &[CandidateEvidence],
) -> Option<ReconstructionParameters> {
    if !table_hash_window_compatible(&parameters, info)
        || !matches!(parameters.chain_parser(), Some(ChainParser::Greedy { .. }))
        || info.max_dist_3_matches <= SHORT_MATCH_CUTOFF
    {
        return None;
    }
    let index = match parameters
        .dictionary()
        .expect("dictionary candidate")
        .insertion
    {
        DictionaryAddPolicy::AddFirst(0..=4) | DictionaryAddPolicy::AddFirstAndLast(0..=3) => 0,
        DictionaryAddPolicy::AddFirst(5) => 1,
        DictionaryAddPolicy::AddFirst(6) => 2,
        _ => return None,
    };
    let settings = &ZLIB_PREFLATE_PARSER_SETTINGS[index];
    let hash_algorithm = canonical_token_capacity(&parameters, info)
        .map(|capacity| memory_hash(capacity.ilog2() - 6))
        .unwrap_or(DEFAULT_HASH);
    supported_table_hash(hash_algorithm, candidates).then_some({
        let mut canonical_configuration = parameters;
        canonical_configuration.replace_chain_parser(
            settings
                .parser
                .with_cutoff(canonical_configuration.behavior.short_match_cutoff()),
        );
        canonical_configuration.set_estimated_hash(hash_algorithm);
        canonical_configuration.behavior.set_full_window(false);
        canonical_configuration
            .dictionary_mut()
            .expect("dictionary candidate")
            .insertion = settings.dictionary_add_policy;
        canonical_configuration
            .chain_common_mut()
            .expect("chain candidate")
            .search
            .nice_length = settings.nice_length;
        canonical_configuration
            .budget_mut()
            .expect("dictionary candidate")
            .max_chain = settings.max_chain;

        canonical_configuration
    })
}

pub fn table_hash_slow(
    parameters: ReconstructionParameters,
    info: &PreflateStreamInfo,
    candidates: &[CandidateEvidence],
) -> Option<ReconstructionParameters> {
    if !table_hash_window_compatible(&parameters, info)
        || info.max_dist_3_matches > SHORT_MATCH_CUTOFF
        || !(parameters
            .dictionary()
            .expect("dictionary candidate")
            .insertion
            == DictionaryAddPolicy::AddAll
            || matches!(parameters.dictionary().expect("dictionary candidate").insertion, DictionaryAddPolicy::AddFirst(limit) if limit > 6))
        || !matches!(
            parameters.chain_parser(),
            Some(
                ChainParser::Greedy { .. }
                    | ChainParser::Lazy {
                        minimum: LazyMinimum::Three { .. },
                        ..
                    }
            )
        )
    {
        return None;
    }
    let capacity = canonical_token_capacity(&parameters, info)?;
    let hash_algorithm = memory_hash(capacity.ilog2() - 6);
    let settings = &SLOW_PREFLATE_PARSER_SETTINGS[2];
    supported_table_hash(hash_algorithm, candidates).then_some({
        let mut canonical_configuration = parameters;
        canonical_configuration.replace_chain_parser(
            settings
                .parser
                .with_cutoff(canonical_configuration.behavior.short_match_cutoff()),
        );
        canonical_configuration.set_estimated_hash(hash_algorithm);
        canonical_configuration.behavior.set_full_window(false);
        canonical_configuration
            .dictionary_mut()
            .expect("dictionary candidate")
            .insertion = settings.dictionary_add_policy;
        canonical_configuration
            .chain_common_mut()
            .expect("chain candidate")
            .search
            .nice_length = settings.nice_length;
        canonical_configuration
            .budget_mut()
            .expect("dictionary candidate")
            .max_chain = settings.max_chain;
        canonical_configuration
            .behavior
            .set_short_match_cutoff(SHORT_MATCH_CUTOFF);

        canonical_configuration
    })
}

fn supported_table_hash(hash: HashAlgorithm, candidates: &[CandidateEvidence]) -> bool {
    candidates.iter().any(|candidate| {
        candidate.hash_algorithm == hash && candidate.distance_policy == DistancePolicy::ZlibWindow
    })
}

pub fn ambiguous_fast_hash(
    parameters: ReconstructionParameters,
    info: &PreflateStreamInfo,
) -> Option<ReconstructionParameters> {
    if !matches!(parameters.hash_algorithm(), HashAlgorithm::Zlib { .. })
        || !matches!(parameters.chain_parser(), Some(ChainParser::Greedy { .. }))
        || !parameters.behavior.uses_general_distances()
    {
        return None;
    }
    let hash_algorithm = adjacent_memory_hash(
        info,
        parameters
            .dictionary()
            .expect("dictionary candidate")
            .insertion,
    )?;
    (hash_algorithm != parameters.hash_algorithm()).then_some({
        let mut canonical_configuration = parameters;
        canonical_configuration.set_estimated_hash(hash_algorithm);
        canonical_configuration
    })
}

pub fn flush(
    parameters: ReconstructionParameters,
    info: &PreflateStreamInfo,
) -> Option<ReconstructionParameters> {
    flush_alternative(parameters, info)
}

pub fn memory_hash_alternative(
    parameters: ReconstructionParameters,
    info: &PreflateStreamInfo,
) -> Option<ReconstructionParameters> {
    if parameters.hash_algorithm() != crate::compressors::windows::HASH
        || parameters
            .dictionary()
            .expect("dictionary candidate")
            .insertion
            != DictionaryAddPolicy::AddAll
        || !compatible(&parameters)
    {
        return None;
    }
    let capacity = canonical_token_capacity(&parameters, info)?;
    let hash_algorithm = memory_hash(capacity.ilog2() - 6);
    Some({
        let mut canonical_configuration = parameters;
        canonical_configuration.set_estimated_hash(hash_algorithm);
        canonical_configuration
    })
}

pub fn filtered_hash(
    parameters: ReconstructionParameters,
    info: &PreflateStreamInfo,
) -> Option<ReconstructionParameters> {
    let settings = &SLOW_PREFLATE_PARSER_SETTINGS[2];
    if parameters.hash_algorithm() != HashAlgorithm::Libdeflate4Fast
        || parameters
            .dictionary()
            .expect("dictionary candidate")
            .insertion
            != DictionaryAddPolicy::AddAll
        || !parameters.has_chain_parser(settings.parser)
        || parameters
            .chain_common()
            .expect("chain candidate")
            .search
            .nice_length
            != settings.nice_length
        || parameters.budget().expect("dictionary candidate").max_chain
            <= SLOW_PREFLATE_PARSER_SETTINGS[1].max_chain
        || parameters.budget().expect("dictionary candidate").max_chain > settings.max_chain
        || info.min_len < FILTERED_MIN_MATCH_LENGTH
        || !compatible(&parameters)
    {
        return None;
    }
    canonical_token_capacity(&parameters, info)?;
    Some(
        {
            let mut canonical_configuration = parameters;
            canonical_configuration.replace_chain_parser(
                settings
                    .parser
                    .with_cutoff(canonical_configuration.behavior.short_match_cutoff()),
            );
            canonical_configuration.set_estimated_hash(DEFAULT_HASH);
            canonical_configuration
                .chain_common_mut()
                .expect("chain candidate")
                .search
                .nice_length = settings.nice_length;
            canonical_configuration
                .budget_mut()
                .expect("dictionary candidate")
                .max_chain = settings.max_chain;
            canonical_configuration.behavior.set_short_match_cutoff(0);

            canonical_configuration
        }
        .with_lazy_behavior(true, info.min_len),
    )
}

pub fn noncanonical_insertion(
    parameters: ReconstructionParameters,
    info: &PreflateStreamInfo,
) -> Option<ReconstructionParameters> {
    if !matches!(parameters.dictionary().expect("dictionary candidate").insertion, DictionaryAddPolicy::AddFirst(limit) if limit > 6)
        || !matches!(
            parameters.hash_algorithm(),
            HashAlgorithm::Zlib { .. } | HashAlgorithm::RandomVector | HashAlgorithm::Libdeflate4
        )
        || !matches!(
            parameters.chain_parser(),
            Some(ChainParser::Greedy { .. } | ChainParser::Lazy { .. })
        )
        || !parameters.behavior.uses_general_distances()
        || parameters
            .dictionary()
            .expect("dictionary candidate")
            .window_bits
            != 15
        || parameters.behavior.permits_position_zero()
        || info.min_len != 3
        || info.max_tokens_per_block < 64
    {
        return None;
    }
    let settings = &SLOW_PREFLATE_PARSER_SETTINGS[2];
    Some({
        let mut canonical_configuration = parameters;
        canonical_configuration.replace_chain_parser(
            settings
                .parser
                .with_cutoff(canonical_configuration.behavior.short_match_cutoff()),
        );
        canonical_configuration.set_estimated_hash(DEFAULT_HASH);
        canonical_configuration.behavior.set_full_window(false);
        canonical_configuration
            .dictionary_mut()
            .expect("dictionary candidate")
            .insertion = settings.dictionary_add_policy;
        canonical_configuration
            .chain_common_mut()
            .expect("chain candidate")
            .search
            .nice_length = settings.nice_length;
        canonical_configuration
            .budget_mut()
            .expect("dictionary candidate")
            .max_chain = settings.max_chain;
        canonical_configuration
            .behavior
            .set_short_match_cutoff(SHORT_MATCH_CUTOFF);

        canonical_configuration
    })
}

fn table_hash_window_compatible(
    parameters: &ReconstructionParameters,
    info: &PreflateStreamInfo,
) -> bool {
    parameters.hash_algorithm() == crate::compressors::windows::HASH
        && parameters.behavior.uses_general_distances()
        && !parameters.behavior.permits_position_zero()
        && !info.matches_to_start_detected
        && info.min_len == 3
        && info.reference_count >= 64
        && info.max_tokens_per_block >= 64
        && info.max_dist
            <= (1
                << parameters
                    .dictionary()
                    .expect("dictionary candidate")
                    .window_bits)
                - MIN_LOOKAHEAD
        && (!parameters.behavior.uses_full_window() || info.ends_with_final_block)
}

fn canonical_token_capacity(
    parameters: &ReconstructionParameters,
    info: &PreflateStreamInfo,
) -> Option<u32> {
    let capacity = u32::from(parameters.max_token_count) + 1;
    (info.max_tokens_per_block == u32::from(parameters.max_token_count)
        && (128..=32768).contains(&capacity)
        && capacity.is_power_of_two())
    .then_some(capacity)
}

pub fn sample_short_match_policy(
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

pub fn short_match_rejected(
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

pub fn refine_short_match_policy(
    parameters: &mut ReconstructionParameters,
    info: &PreflateStreamInfo,
    rejections: u16,
) {
    if rejections >= 16
        && info.min_len == 3
        && (1..=SHORT_MATCH_CUTOFF).contains(&info.max_dist_3_matches)
        && info.reference_count >= 4096
        && u64::from(info.short_reference_count) * 512 <= u64::from(info.reference_count)
        && matches!(parameters.hash_algorithm(), HashAlgorithm::Zlib { .. })
        && parameters
            .dictionary()
            .expect("dictionary candidate")
            .insertion
            == DictionaryAddPolicy::AddAll
        && matches!(
            parameters.chain_parser(),
            Some(ChainParser::Lazy {
                minimum: LazyMinimum::Three { .. },
                lookahead: LazyLookaheadSettings {
                    behavior: LazyBehavior::Zlib { .. },
                    ..
                },
                ..
            })
        )
    {
        parameters.behavior.set_short_match_cutoff(0);
    }
}

pub struct HashCandidates {
    pub memory: HashAlgorithm,
    pub default: Option<HashAlgorithm>,
    pub small: Option<HashAlgorithm>,
}

pub fn candidate_hashes(mem_level: u32) -> HashCandidates {
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

pub fn supported_memory_hash(info: &PreflateStreamInfo) -> Option<HashAlgorithm> {
    let tokens = info.max_unflushed_tokens_per_block;
    let capacity = tokens + 1;
    // An ordinary boundary is stronger evidence, not proof of compressor identity.
    (tokens == info.max_tokens_per_block
        && (128..=32768).contains(&capacity)
        && capacity.is_power_of_two())
    .then(|| memory_hash(capacity.ilog2() - 6))
}

pub fn adjacent_memory_hash(
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

pub fn compatible(parameters: &ReconstructionParameters) -> bool {
    compatible_constraints(
        parameters.behavior.permits_position_zero(),
        parameters.behavior.uses_full_window(),
        parameters.behavior.short_match_cutoff(),
        parameters
            .dictionary()
            .is_some_and(|dictionary| dictionary.insertion == DictionaryAddPolicy::AddAll),
    )
}

pub fn compatible_initial(initial: &InitialEstimate<'_>) -> bool {
    compatible_constraints(
        initial.permits_position_zero(),
        initial.evidence.distance_policy == DistancePolicy::FullWindow,
        initial.info.max_dist_3_matches,
        initial.insertion == DictionaryAddPolicy::AddAll,
    )
}

fn compatible_constraints(
    matches_to_start: bool,
    full_window: bool,
    short_match_cutoff: u32,
    full_insertion: bool,
) -> bool {
    !matches_to_start
        && !full_window
        && (short_match_cutoff <= SHORT_MATCH_CUTOFF || !full_insertion)
}

pub fn project_lazy_behavior(
    mut parameters: ReconstructionParameters,
    compatible: bool,
    observed_min_len: u32,
) -> ReconstructionParameters {
    let filtered = observed_min_len >= FILTERED_MIN_MATCH_LENGTH
        && matches!(parameters.hash_algorithm(), HashAlgorithm::Zlib { .. });
    if let crate::reconstruction_parameters::BehaviorSettings::Chain {
        parser: crate::reconstruction_parameters::ChainParser::Lazy { lookahead, minimum },
        ..
    } = &mut parameters.behavior
    {
        if filtered {
            *minimum = crate::reconstruction_parameters::LazyMinimum::FilteredSix;
        }
        if !compatible {
            lookahead.behavior = LazyBehavior::RecomputeAfterLiteral;
        }
    }
    parameters
}

pub fn parser_settings(add_policy: DictionaryAddPolicy) -> &'static [PreflateParserConfig] {
    if add_policy == DictionaryAddPolicy::AddAll {
        &SLOW_PREFLATE_PARSER_SETTINGS
    } else {
        &ZLIB_PREFLATE_PARSER_SETTINGS
    }
}

pub fn greedy_nice_length(initial: &InitialEstimate<'_>) -> Option<u32> {
    let observed_limit = match initial.insertion {
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
                && config.max_chain >= initial.evidence.required_chain
                && config.nice_length >= u32::from(initial.evidence.minimum_nice_length)
        })
        .map(|config| config.nice_length)
}

pub fn refine_depth_candidate<'a>(
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

pub fn refine_parameters(
    estimate: ParameterEstimate,
    depth: &DepthEstimate,
    info: &PreflateStreamInfo,
    contents: &DeflateContents,
    plain: &PlainText,
) -> ParameterEstimate {
    let parameters = estimate.parameters();
    let ambiguous_insertion = InsertionConstraint::observe(
        parameters
            .dictionary()
            .expect("dictionary candidate")
            .insertion,
        info.max_len,
    ) == InsertionConstraint::Unresolved;
    if depth.zlib_candidates.is_empty()
        || matches!(
            parameters.hash_algorithm(),
            HashAlgorithm::Libdeflate4Fast15 | HashAlgorithm::Chromium { .. }
        )
        || (!ambiguous_insertion
            && info.min_len < 6
            && matches!(parameters.hash_algorithm(), HashAlgorithm::Zlib { .. }))
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
        && parameters.hash_algorithm() == HashAlgorithm::RandomVector
        && parameters
            .dictionary()
            .expect("dictionary candidate")
            .insertion
            == DictionaryAddPolicy::AddAll
        && matches!(parameters.chain_parser(), Some(ChainParser::Lazy { .. }));
    let score = |parameters: &ReconstructionParameters| {
        score_predictions(
            &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                *parameters,
            ),
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
            let trial = {
                let mut canonical_configuration = parameters;
                canonical_configuration.replace_chain_parser(
                    settings
                        .parser
                        .with_cutoff(canonical_configuration.behavior.short_match_cutoff()),
                );
                canonical_configuration.set_estimated_hash(candidate.hash_algorithm);
                canonical_configuration.behavior.set_full_window(false);
                canonical_configuration
                    .dictionary_mut()
                    .expect("dictionary candidate")
                    .window_bits = estimate_preflate_window_bits(info.max_dist);
                canonical_configuration
                    .dictionary_mut()
                    .expect("dictionary candidate")
                    .insertion = DictionaryAddPolicy::AddAll;
                canonical_configuration
                    .chain_common_mut()
                    .expect("chain candidate")
                    .search
                    .nice_length = settings.nice_length;
                canonical_configuration
                    .budget_mut()
                    .expect("dictionary candidate")
                    .max_chain = settings.max_chain;
                canonical_configuration
                    .behavior
                    .set_short_match_cutoff(info.max_dist_3_matches);

                canonical_configuration
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
                        return ParameterEstimate {
                            profile: CompressorProfile::Zlib.with_parameters(best),
                            provenance: EstimateProvenance::PrefixValidated,
                        };
                    }
                }
            }
        }
    }
    if !adaptive {
        return if best_score * 4 <= baseline_score * 3 {
            ParameterEstimate {
                profile: CompressorProfile::Zlib.with_parameters(best),
                provenance: EstimateProvenance::PrefixValidated,
            }
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
            (Some(candidate.hash_algorithm()) == extension_hash
                && candidate.has_chain_parser(SLOW_PREFLATE_PARSER_SETTINGS[2].parser)
                && candidate.budget().expect("dictionary candidate").max_chain
                    == SLOW_PREFLATE_PARSER_SETTINGS[2].max_chain)
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
        return ParameterEstimate {
            profile: CompressorProfile::Zlib.with_parameters(candidates[index]),
            provenance: EstimateProvenance::PrefixValidated,
        };
    }
    estimate
}

pub fn flush_alternative(
    parameters: ReconstructionParameters,
    info: &PreflateStreamInfo,
) -> Option<ReconstructionParameters> {
    let hash_algorithm = HashAlgorithm::Zlib {
        hash_mask: 16383,
        hash_shift: 5,
    };
    let known_flush = parameters.hash_algorithm() == hash_algorithm
        && parameters.budget().expect("dictionary candidate").max_chain == 32
        && info.count_stored_blocks != 0;
    let underestimated_memory = matches!(
        parameters.hash_algorithm(),
        HashAlgorithm::Zlib { .. } | HashAlgorithm::RandomVector
    ) && parameters.max_token_count < 8191
        && info.min_len == 3
        && !info.matches_to_start_detected
        && info.max_dist_3_matches <= SHORT_MATCH_CUTOFF
        && (parameters
            .dictionary()
            .expect("dictionary candidate")
            .insertion
            == DictionaryAddPolicy::AddAll
            || matches!(parameters.dictionary().expect("dictionary candidate").insertion, DictionaryAddPolicy::AddFirst(limit) if limit > 6));
    if !(known_flush
        && parameters
            .dictionary()
            .expect("dictionary candidate")
            .insertion
            == DictionaryAddPolicy::AddAll
        || underestimated_memory)
    {
        return None;
    }
    Some({
        let mut canonical_configuration = parameters;
        canonical_configuration.replace_chain_parser(ChainParser::Lazy {
            lookahead: LazyLookaheadSettings {
                max_lazy: 4,
                behavior: LazyBehavior::Zlib { good_length: 8 },
            },
            minimum: LazyMinimum::Three {
                short_match_cutoff: canonical_configuration.behavior.short_match_cutoff(),
            },
        });
        canonical_configuration.set_estimated_hash(hash_algorithm);
        canonical_configuration
            .dictionary_mut()
            .expect("dictionary candidate")
            .window_bits = if known_flush {
            parameters
                .dictionary()
                .expect("dictionary candidate")
                .window_bits
        } else {
            15
        };
        canonical_configuration
            .dictionary_mut()
            .expect("dictionary candidate")
            .insertion = DictionaryAddPolicy::AddAll;
        canonical_configuration
            .chain_common_mut()
            .expect("chain candidate")
            .search
            .nice_length = 258;
        canonical_configuration
            .budget_mut()
            .expect("dictionary candidate")
            .max_chain = 32;
        canonical_configuration
            .behavior
            .set_short_match_cutoff(if known_flush {
                parameters.behavior.short_match_cutoff()
            } else {
                SHORT_MATCH_CUTOFF
            });

        canonical_configuration
    })
}

pub const ZLIB_PREFLATE_PARSER_SETTINGS: [PreflateParserConfig; 3] = [
    PreflateParserConfig {
        parser: ChainParser::Greedy {
            short_match_cutoff: 0,
        },
        dictionary_add_policy: DictionaryAddPolicy::AddFirst(4),
        nice_length: 8,
        max_chain: 4,
    },
    PreflateParserConfig {
        parser: ChainParser::Greedy {
            short_match_cutoff: 0,
        },
        dictionary_add_policy: DictionaryAddPolicy::AddFirst(5),
        nice_length: 16,
        max_chain: 8,
    },
    PreflateParserConfig {
        parser: ChainParser::Greedy {
            short_match_cutoff: 0,
        },
        dictionary_add_policy: DictionaryAddPolicy::AddFirst(6),
        nice_length: 32,
        max_chain: 32,
    },
];

pub const SLOW_PREFLATE_PARSER_SETTINGS: [PreflateParserConfig; 6] = [
    PreflateParserConfig {
        parser: ChainParser::Lazy {
            lookahead: LazyLookaheadSettings {
                max_lazy: 4,
                behavior: LazyBehavior::Zlib { good_length: 4 },
            },
            minimum: LazyMinimum::Three {
                short_match_cutoff: 0,
            },
        },
        dictionary_add_policy: DictionaryAddPolicy::AddAll,
        nice_length: 16,
        max_chain: 16,
    },
    PreflateParserConfig {
        parser: ChainParser::Lazy {
            lookahead: LazyLookaheadSettings {
                max_lazy: 16,
                behavior: LazyBehavior::Zlib { good_length: 8 },
            },
            minimum: LazyMinimum::Three {
                short_match_cutoff: 0,
            },
        },
        dictionary_add_policy: DictionaryAddPolicy::AddAll,
        nice_length: 32,
        max_chain: 32,
    },
    PreflateParserConfig {
        parser: ChainParser::Lazy {
            lookahead: LazyLookaheadSettings {
                max_lazy: 16,
                behavior: LazyBehavior::Zlib { good_length: 8 },
            },
            minimum: LazyMinimum::Three {
                short_match_cutoff: 0,
            },
        },
        dictionary_add_policy: DictionaryAddPolicy::AddAll,
        nice_length: 128,
        max_chain: 128,
    },
    PreflateParserConfig {
        parser: ChainParser::Lazy {
            lookahead: LazyLookaheadSettings {
                max_lazy: 32,
                behavior: LazyBehavior::Zlib { good_length: 8 },
            },
            minimum: LazyMinimum::Three {
                short_match_cutoff: 0,
            },
        },
        dictionary_add_policy: DictionaryAddPolicy::AddAll,
        nice_length: 128,
        max_chain: 256,
    },
    PreflateParserConfig {
        parser: ChainParser::Lazy {
            lookahead: LazyLookaheadSettings {
                max_lazy: 128,
                behavior: LazyBehavior::Zlib { good_length: 32 },
            },
            minimum: LazyMinimum::Three {
                short_match_cutoff: 0,
            },
        },
        dictionary_add_policy: DictionaryAddPolicy::AddAll,
        nice_length: 258,
        max_chain: 1024,
    },
    PreflateParserConfig {
        parser: ChainParser::Lazy {
            lookahead: LazyLookaheadSettings {
                max_lazy: 258,
                behavior: LazyBehavior::Zlib { good_length: 32 },
            },
            minimum: LazyMinimum::Three {
                short_match_cutoff: 0,
            },
        },
        dictionary_add_policy: DictionaryAddPolicy::AddAll,
        nice_length: 258,
        max_chain: 4096,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    use crate::parameters::{PreflateStrategy, tests::MatchingType};

    #[test]
    fn table_hash_fast_uses_coupled_profiles_without_the_lazy_distance_cutoff() {
        let candidates = table_hash_test_evidence(DEFAULT_HASH);
        let parameters = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(HashAlgorithm::RandomVector);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirstAndLast(0));
            canonical_configuration.set_nice_length(258);
            canonical_configuration.set_max_chain(75);
            canonical_configuration.set_short_match_cutoff(8192);
            canonical_configuration
        };
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
        info.min_len = 3;
        info.reference_count = 64;
        info.max_tokens_per_block = 9414;
        info.max_dist = 8192;
        info.max_dist_3_matches = 8192;
        info.ends_with_final_block = true;
        for (policy, index) in [
            (DictionaryAddPolicy::AddFirstAndLast(0), 0),
            (DictionaryAddPolicy::AddFirstAndLast(3), 0),
            (DictionaryAddPolicy::AddFirst(4), 0),
            (DictionaryAddPolicy::AddFirst(5), 1),
            (DictionaryAddPolicy::AddFirst(6), 2),
        ] {
            let candidate = table_hash_fast(
                {
                    let mut canonical_configuration = parameters;
                    canonical_configuration.set_insertion(policy);
                    canonical_configuration
                },
                &info,
                &candidates,
            )
            .unwrap();
            let settings = &ZLIB_PREFLATE_PARSER_SETTINGS[index];
            assert_eq!(candidate.hash_algorithm(), DEFAULT_HASH);
            assert_eq!(candidate.add_policy(), settings.dictionary_add_policy);
            assert_eq!(candidate.matching_type(), settings.parser.matching_type());
            assert_eq!(candidate.nice_length(), settings.nice_length);
            assert_eq!(candidate.max_chain(), settings.max_chain);
            assert_eq!(
                candidate.max_dist_3_matches(),
                parameters.max_dist_3_matches()
            );
        }
        info.max_dist_3_matches = SHORT_MATCH_CUTOFF;
        assert!(table_hash_fast(parameters, &info, &candidates).is_none());
    }

    fn table_hash_test_evidence(hash_algorithm: HashAlgorithm) -> [CandidateEvidence; 1] {
        [CandidateEvidence {
            hash_algorithm,
            required_chain: 1,
            distance_policy: DistancePolicy::ZlibWindow,
            parser: crate::estimator::parser_estimator::ParserInference::Unresolved,
            shallow_miniz_greedy: false,
            minimum_nice_length: 0,
        }]
    }

    #[test]
    fn table_hash_slow_requires_canonical_memory_and_safe_window_evidence() {
        let candidates = table_hash_test_evidence(memory_hash(5));
        let parameters = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(HashAlgorithm::RandomVector);
            canonical_configuration.set_full_window(true);
            canonical_configuration.set_window_bits(12);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(7));
            canonical_configuration.set_nice_length(255);
            canonical_configuration.set_max_chain(8);
            canonical_configuration.set_short_match_cutoff(3834);
            canonical_configuration.max_token_count = 2047;
            canonical_configuration
        };
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
        info.min_len = 3;
        info.reference_count = 64;
        info.max_tokens_per_block = 2047;
        info.max_dist = 3834;
        info.max_dist_3_matches = 3834;
        info.ends_with_final_block = true;
        assert!(table_hash_slow(parameters, &info, &[]).is_none());
        assert!(
            table_hash_slow(parameters, &info, &table_hash_test_evidence(DEFAULT_HASH)).is_none()
        );
        let candidate = table_hash_slow(parameters, &info, &candidates).unwrap();
        assert_eq!(candidate.hash_algorithm(), memory_hash(5));
        assert_eq!(candidate.window_bits(), 12);
        assert!(!candidate.very_far_matches_detected());
        assert_eq!(candidate.add_policy(), DictionaryAddPolicy::AddAll);
        assert_eq!(
            candidate.matching_type(),
            SLOW_PREFLATE_PARSER_SETTINGS[2].parser.matching_type()
        );
        assert_eq!((candidate.nice_length(), candidate.max_chain()), (128, 128));
        for rejected in [
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_hash_algorithm(DEFAULT_HASH);
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration
                    .set_matching_type(MatchingType::WindowsLazy { max_lazy: 128 });
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_matches_to_start(true);
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_strategy(PreflateStrategy::RleOnly);
                canonical_configuration
            },
        ] {
            assert!(table_hash_slow(rejected, &info, &candidates).is_none());
        }
        for (complete, starts, distance, references, minimum, tokens) in [
            (false, false, 3834, 64, 3, 2047),
            (true, true, 3834, 64, 3, 2047),
            (true, false, 3835, 64, 3, 2047),
            (true, false, 3834, 63, 3, 2047),
            (true, false, 3834, 64, 4, 2047),
            (true, false, 3834, 64, 3, 2046),
        ] {
            info.ends_with_final_block = complete;
            info.matches_to_start_detected = starts;
            info.max_dist = distance;
            info.reference_count = references;
            info.min_len = minimum;
            info.max_tokens_per_block = tokens;
            assert!(table_hash_slow(parameters, &info, &candidates).is_none());
        }
    }

    #[test]
    fn noncanonical_insertion_uses_a_complete_coupled_zlib_tuple() {
        let parameters = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4);
            canonical_configuration.set_full_window(true);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(147));
            canonical_configuration.set_nice_length(255);
            canonical_configuration.set_max_chain(3525);
            canonical_configuration.set_short_match_cutoff(26306);
            canonical_configuration.max_token_count = 32767;
            canonical_configuration
        };
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
        info.min_len = 3;
        info.max_tokens_per_block = 12288;
        let settings = &SLOW_PREFLATE_PARSER_SETTINGS[2];
        assert_eq!(
            noncanonical_insertion(parameters, &info),
            Some({
                let mut canonical_configuration = parameters;
                canonical_configuration.set_hash_algorithm(DEFAULT_HASH);
                canonical_configuration.set_full_window(false);
                canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
                canonical_configuration.set_nice_length(128);
                canonical_configuration.set_max_chain(128);
                canonical_configuration.set_short_match_cutoff(SHORT_MATCH_CUTOFF);
                canonical_configuration.set_matching_type(settings.parser.matching_type());
                canonical_configuration
            }),
        );
        for candidate in [
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(6));
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4Fast15);
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_matching_type(MatchingType::LibdeflateLazy {
                    two_positions: true,
                });
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_window_bits(14);
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_matches_to_start(true);
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_strategy(PreflateStrategy::RleOnly);
                canonical_configuration
            },
        ] {
            assert_eq!(
                noncanonical_insertion(candidate, &info),
                None,
                "{candidate:?}"
            );
        }
        info.min_len = 4;
        assert_eq!(noncanonical_insertion(parameters, &info), None);
        info.min_len = 3;
        info.max_tokens_per_block = 63;
        assert_eq!(noncanonical_insertion(parameters, &info), None);
    }

    #[test]
    fn filtered_hash_requires_the_coupled_lazy_tuple_and_complete_canonical_buffer() {
        let settings = &SLOW_PREFLATE_PARSER_SETTINGS[2];
        let baseline = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4Fast);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_nice_length(settings.nice_length);
            canonical_configuration.set_max_chain(126);
            canonical_configuration.set_short_match_cutoff(0);
            canonical_configuration.set_matching_type(settings.parser.matching_type());
            canonical_configuration
        };
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
        for maximum_tokens in [8191, 16383, 32767] {
            let parameters = {
                let mut canonical_configuration = baseline;
                canonical_configuration.max_token_count = maximum_tokens;
                canonical_configuration
            };
            info.max_tokens_per_block = u32::from(maximum_tokens);
            for minimum in [6, 7, 258] {
                info.min_len = minimum;
                let candidate = filtered_hash(parameters, &info).unwrap();
                assert_eq!(
                    candidate,
                    {
                        let mut canonical_configuration = parameters;
                        canonical_configuration.set_hash_algorithm(DEFAULT_HASH);
                        canonical_configuration.set_max_chain(settings.max_chain);
                        canonical_configuration
                    }
                    .with_lazy_behavior(true, minimum),
                );
            }
            for minimum in [3, 4, 5] {
                info.min_len = minimum;
                assert_eq!(filtered_hash(parameters, &info), None);
            }
            info.min_len = 6;
            info.max_tokens_per_block -= 1;
            assert_eq!(filtered_hash(parameters, &info), None);
        }
        info.min_len = 6;
        for parameters in [
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4Fast15);
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4);
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_matching_type(MatchingType::LibdeflateLazy {
                    two_positions: true,
                });
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_matching_type(MatchingType::Greedy);
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_max_chain(32);
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_max_chain(129);
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_nice_length(258);
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.max_token_count = 2000;
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.max_token_count = 63;
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.max_token_count = u16::MAX;
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(4));
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_matches_to_start(true);
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_full_window(true);
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_short_match_cutoff(SHORT_MATCH_CUTOFF + 1);
                canonical_configuration
            },
        ] {
            info.max_tokens_per_block = u32::from(parameters.max_token_count);
            assert_eq!(filtered_hash(parameters, &info), None, "{parameters:?}");
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
        use crate::estimator::preflate_stream_info::tests::extract_preflate_info;

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
        let baseline = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_short_match_cutoff(info.max_dist_3_matches);
            canonical_configuration
                .set_matching_type(SLOW_PREFLATE_PARSER_SETTINGS[5].parser.matching_type());
            canonical_configuration
        };
        for (rejections, expected) in [
            (0, baseline.max_dist_3_matches()),
            (15, baseline.max_dist_3_matches()),
            (16, 0),
            (256, 0),
        ] {
            let mut candidate = baseline;
            refine_short_match_policy(&mut candidate, &info, rejections);
            assert_eq!(candidate.max_dist_3_matches(), expected);
        }
        let mut frequent = extract_preflate_info(&blocks);
        frequent.short_reference_count = frequent.reference_count / 512 + 1;
        let mut candidate = baseline;
        refine_short_match_policy(&mut candidate, &frequent, 256);
        assert_eq!(candidate, baseline);
        for candidate in [
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_matching_type(MatchingType::Greedy);
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_hash_algorithm(HashAlgorithm::RandomVector);
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(4));
                canonical_configuration
            },
        ] {
            let mut result = candidate;
            refine_short_match_policy(&mut result, &info, 256);
            assert_eq!(result, candidate);
        }
    }

    #[test]
    fn adjacent_hash_requires_ambiguous_fast_capacity_and_preserves_the_search_tuple() {
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
        info.min_len = 3;
        info.max_tokens_per_block = 3655;
        let parameters = crate::token_predictor::tests::zlib_level_1_params();
        let expected = memory_hash(7);
        assert_eq!(
            adjacent_memory_hash(&info, parameters.add_policy()),
            Some(expected)
        );
        assert_eq!(
            ambiguous_fast_hash(parameters, &info),
            Some({
                let mut canonical_configuration = parameters;
                canonical_configuration.set_hash_algorithm(expected);
                canonical_configuration
            })
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
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_hash_algorithm(expected);
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_hash_algorithm(HashAlgorithm::RandomVector);
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration
                    .set_matching_type(SLOW_PREFLATE_PARSER_SETTINGS[2].parser.matching_type());
                canonical_configuration
            },
            {
                let mut canonical_configuration = parameters;
                canonical_configuration.set_strategy(PreflateStrategy::RleOnly);
                canonical_configuration
            },
        ] {
            assert_eq!(ambiguous_fast_hash(candidate, &info), None);
        }
        info.max_tokens_per_block = 4095;
        info.max_unflushed_tokens_per_block = 4095;
        assert_eq!(adjacent_memory_hash(&info, parameters.add_policy()), None);
        info.max_unflushed_tokens_per_block = 0;
        info.max_tokens_per_block = 32767;
        assert_eq!(adjacent_memory_hash(&info, parameters.add_policy()), None);
        info.max_tokens_per_block = 63;
        assert_eq!(adjacent_memory_hash(&info, parameters.add_policy()), None);
    }

    #[test]
    fn memory_hash_requires_a_full_canonical_buffer_and_zlib_compatible_distances() {
        let baseline = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(crate::compressors::windows::HASH);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_short_match_cutoff(SHORT_MATCH_CUTOFF);
            canonical_configuration
        };
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
        for bits in 7..=15 {
            let parameters = {
                let mut canonical_configuration = baseline;
                canonical_configuration.max_token_count = (1u16 << bits) - 1;
                canonical_configuration
            };
            info.max_tokens_per_block = u32::from(parameters.max_token_count);
            assert_eq!(
                memory_hash_alternative(parameters, &info),
                Some({
                    let mut canonical_configuration = parameters;
                    canonical_configuration.set_hash_algorithm(memory_hash(bits - 6));
                    canonical_configuration
                })
            );
            info.max_tokens_per_block -= 1;
            assert_eq!(memory_hash_alternative(parameters, &info), None);
            info.max_tokens_per_block += 2;
            assert_eq!(memory_hash_alternative(parameters, &info), None);
        }
        for parameters in [
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.max_token_count = 63;
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.max_token_count = 2000;
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.max_token_count = u16::MAX;
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_hash_algorithm(DEFAULT_HASH);
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_full_window(true);
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_matches_to_start(true);
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_short_match_cutoff(SHORT_MATCH_CUTOFF + 1);
                canonical_configuration
            },
            {
                let mut canonical_configuration = baseline;
                canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(4));
                canonical_configuration
            },
        ] {
            info.max_tokens_per_block = u32::from(parameters.max_token_count);
            assert_eq!(
                memory_hash_alternative(parameters, &info),
                None,
                "{parameters:?}"
            );
        }
    }

    #[test]
    fn partial_block_hash_alternative_preserves_known_flush_limits() {
        let parameters = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(HashAlgorithm::Zlib {
                hash_mask: 8191,
                hash_shift: 5,
            });
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration
                .set_matching_type(SLOW_PREFLATE_PARSER_SETTINGS[3].parser.matching_type());
            canonical_configuration.max_token_count = 4095;
            canonical_configuration
        };
        let mut info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(&[]);
        info.min_len = 3;
        info.max_dist_3_matches = 3992;
        let result = flush_alternative(parameters, &info).unwrap();
        assert_eq!(
            result.hash_algorithm(),
            HashAlgorithm::Zlib {
                hash_mask: 16383,
                hash_shift: 5
            }
        );
        assert_eq!(result.max_chain(), 32);
        assert_eq!(result.nice_length(), 258);
        assert_eq!(result.max_dist_3_matches(), 4096);
        for (minimum, source_zero, short_distance) in
            [(4, false, 3992), (3, true, 3992), (3, false, 4097)]
        {
            info.min_len = minimum;
            info.matches_to_start_detected = source_zero;
            info.max_dist_3_matches = short_distance;
            assert!(flush_alternative(parameters, &info).is_none());
        }
        let known = {
            let mut canonical_configuration = parameters;
            canonical_configuration.set_hash_algorithm(result.hash_algorithm());
            canonical_configuration.set_window_bits(14);
            canonical_configuration.set_max_chain(32);
            canonical_configuration.set_short_match_cutoff(4076);
            canonical_configuration
        };
        info.count_stored_blocks = 1;
        let result = flush_alternative(known, &info).unwrap();
        assert_eq!(result.window_bits(), 14);
        assert_eq!(result.max_dist_3_matches(), 4076);
    }

    #[test]
    fn verify_zlib_recognition() {
        use crate::{
            deflate::deflate_reader::tests::parse_deflate_whole,
            estimator::preflate_parameter_estimator::tests::estimate_preflate_parameters,
            parameters::PreflateStrategy, utils::read_file,
        };

        for level in 0..=9 {
            let compressed = read_file(&format!("compressed_zlib_level{level}.deflate"));
            let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
            let parameters = estimate_preflate_parameters(&contents, &plain).unwrap();
            assert!(compatible(&parameters));
            if level == 0 {
                assert_eq!(parameters.strategy(), PreflateStrategy::Store);
                continue;
            }
            let config = if level < 4 {
                &ZLIB_PREFLATE_PARSER_SETTINGS[level - 1]
            } else {
                &SLOW_PREFLATE_PARSER_SETTINGS[level - 4]
            };
            assert!(
                parameters.max_chain() <= config.max_chain,
                "level {level}: chain {} exceeds {}",
                parameters.max_chain(),
                config.max_chain
            );
            assert_eq!(parameters.matching_type(), config.parser.matching_type());
            assert_eq!(parameters.add_policy(), config.dictionary_add_policy);
            assert_eq!(parameters.nice_length(), config.nice_length);
            assert_eq!(parameters.strategy(), PreflateStrategy::Default);
        }
    }
}
