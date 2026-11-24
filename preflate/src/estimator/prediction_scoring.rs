/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

//! Bounded replay and comparison of candidate compressor settings.
//!
//! Each candidate predicts tokens using the same state machinery as production,
//! but advances with the known actual tokens rather than encoding or recovering
//! corrections. Scores therefore count initial prediction mismatches, not
//! correction bytes or the total size of a reconstruction record.
//!
//! Refinement compares a bounded prefix and can continue selected ambiguous
//! candidates until their errors distinguish them or a work limit is reached.
//! Shared errors do not distinguish candidates. Long distance-one repetitions
//! advance dictionary history without consuming the informative-sample budget,
//! while separate total-work limits still bound the replay.

use super::{complevel_estimator::CandidateEvidence, preflate_stream_info::PreflateStreamInfo};
use crate::{
    deflate::deflate_token::{
        DeflateToken, DeflateTokenBlock, DeflateTokenBlockType, TokenFrequency,
    },
    estimator::{
        compressor_profile::CompressorProfile, estimation_result::EstimationResult, models,
    },
    prediction_state::PredictionState,
    preflate_input::{PlainText, PreflateInput},
    reconstruction_parameters::ReconstructionParameters,
};

#[derive(Default)]
struct ScoringBudget {
    tokens: usize,
    bytes: u32,
    total_tokens: usize,
}

impl ScoringBudget {
    fn exhausted(&self, position: u32, max_tokens: usize, max_bytes: u32) -> bool {
        self.tokens >= max_tokens
            || self.bytes >= max_bytes
            || self.total_tokens >= 32768
            || position >= 8 * 1024 * 1024
    }

    fn accept(&mut self, token: &DeflateToken) {
        self.total_tokens += 1;
        if matches!(token, DeflateToken::Reference(reference) if reference.dist() == 1 && reference.len() == 258)
        {
            return;
        }
        self.tokens += 1;
        self.bytes += match token {
            DeflateToken::Literal(_) => 1,
            DeflateToken::Reference(reference) => reference.len(),
        };
    }
}

pub fn refine_profile(
    profile: EstimationResult,
    info: &PreflateStreamInfo,
    contents: &crate::deflate::deflate_reader::DeflateContents,
    plain: &PlainText,
    zlib_candidates: &[CandidateEvidence],
) -> EstimationResult {
    if contents.compressed_size <= 1024 {
        return profile;
    }
    let parameters = profile.reconstruction;
    let first_match = models::generic::first_match(parameters);
    let mut candidates = crate::estimator::compressor_profile::profile_alternatives(
        parameters,
        info,
        zlib_candidates,
    );
    if contents.compressed_size < 4096 || profile.model != CompressorProfile::Custom {
        candidates.retain(|candidate| Some(candidate.reconstruction) != first_match);
    }
    if candidates.is_empty() {
        return profile;
    }
    let score = |parameters: &ReconstructionParameters| {
        score_profile_predictions(
            &mut PredictionState::from_reconstruction_parameters(*parameters),
            &contents.blocks,
            plain,
            4096,
            524288,
        )
    };
    let baseline = score(&parameters);
    let errors = baseline.errors;
    let tokens = baseline.tokens;
    // Keep an already-perfect prefix, even when another fingerprint also fits.
    if errors < 2 || tokens < 64 {
        return profile;
    }
    let greedy = (profile.model == CompressorProfile::Custom)
        .then(|| models::generic::primary_only_greedy(parameters, info))
        .flatten();
    let mut improved_parser = None;
    for candidate in candidates {
        let proposed = candidate.reconstruction;
        if proposed == parameters {
            continue;
        }
        let candidate_score = score(&proposed);
        let candidate_errors = candidate_score.errors;
        if candidate_score.tokens != tokens {
            continue;
        }
        if candidate_errors == 0 {
            return candidate;
        }
        if greedy == Some(proposed) && improves_generic_parser(errors, candidate_errors)
            || first_match == Some(proposed) && improves_first_match(&baseline, &candidate_score)
        {
            improved_parser = Some(candidate);
        }
    }
    improved_parser.unwrap_or(profile)
}

fn improves_generic_parser(errors: usize, candidate_errors: usize) -> bool {
    candidate_errors <= errors / 4 && errors.saturating_sub(candidate_errors) >= 16
}

fn improves_first_match(baseline: &PredictionScore, candidate: &PredictionScore) -> bool {
    candidate.errors <= baseline.errors
        && improves_generic_parser(baseline.reference_errors, candidate.reference_errors)
}

#[derive(Default)]
struct PredictionScore {
    errors: usize,
    reference_errors: usize,
    tokens: usize,
}

pub struct RefinementScores {
    pub errors: Vec<usize>,
    pub prefix_errors: Vec<usize>,
    pub tokens: usize,
    pub decisive: bool,
}

fn eliminate_refinement_candidates(errors: &[usize], active: &mut [bool]) -> bool {
    let best = errors
        .iter()
        .zip(active.iter())
        .filter_map(|(&errors, &active)| active.then_some(errors))
        .min()
        .expect("at least one refinement candidate");
    for (&errors, active) in errors.iter().zip(active.iter_mut()) {
        if *active && errors.saturating_sub(best) >= 8 {
            *active = false;
        }
    }
    active.iter().filter(|&&active| active).count() == 1
        || !active[0]
            && errors
                .iter()
                .zip(active.iter())
                .all(|(&errors, &active)| !active || errors == 0)
}

pub fn score_refinement(
    parameters: &[ReconstructionParameters],
    blocks: &[DeflateTokenBlock],
    plain: &PlainText,
    minimum_tokens: usize,
    extension_candidate: usize,
) -> RefinementScores {
    assert!((2..=12).contains(&parameters.len()));
    assert!((1..parameters.len()).contains(&extension_candidate));
    let mut predictors: Vec<_> = parameters
        .iter()
        .map(|parameters| PredictionState::from_reconstruction_parameters(*parameters))
        .collect();
    let max_tokens = 32768;
    let max_bytes = 1048576;
    let mut inputs = vec![PreflateInput::new(plain); predictors.len()];
    let mut errors = vec![0; predictors.len()];
    let mut active = vec![true; predictors.len()];
    let mut prefix_errors = Vec::new();
    let mut continuing = false;
    for predictor in predictors.iter_mut() {
        predictor.begin_chunk(blocks);
    }
    let mut budget = ScoringBudget::default();
    for block in blocks {
        match &block.block_type {
            DeflateTokenBlockType::Stored { uncompressed } => {
                for (i, predictor) in predictors.iter_mut().enumerate() {
                    if active[i] || i == 0 {
                        predictor
                            .begin_stored_block(&inputs[i])
                            .expect("idle candidate block");
                    }
                }
                for _ in uncompressed {
                    if budget.exhausted(inputs[0].pos(), max_tokens, max_bytes) {
                        return RefinementScores {
                            prefix_errors: if prefix_errors.is_empty() {
                                errors.clone()
                            } else {
                                prefix_errors
                            },
                            errors,
                            tokens: budget.total_tokens,
                            decisive: false,
                        };
                    }
                    budget.bytes += 1;
                    for (i, predictor) in predictors.iter_mut().enumerate() {
                        if active[i] || i == 0 {
                            predictor.advance_stored_byte(&mut inputs[i]);
                        }
                    }
                }
            }
            DeflateTokenBlockType::Huffman { tokens, .. } => {
                let mut frequencies: Vec<_> = (0..predictors.len())
                    .map(|_| TokenFrequency::default())
                    .collect();
                for (i, predictor) in predictors.iter_mut().enumerate() {
                    if !active[i] && i != 0 {
                        continue;
                    }
                    let input = &mut inputs[i];
                    predictor
                        .begin_known_huffman_block(tokens, input)
                        .expect("block-derived flush limit");
                }
                if prefix_errors.is_empty() && budget.bytes >= 262144 {
                    prefix_errors = errors.clone();
                }
                for actual in tokens {
                    if budget.exhausted(inputs[0].pos(), max_tokens, max_bytes) {
                        return RefinementScores {
                            prefix_errors: if prefix_errors.is_empty() {
                                errors.clone()
                            } else {
                                prefix_errors
                            },
                            errors,
                            tokens: budget.total_tokens,
                            decisive: false,
                        };
                    }
                    let mut any_wrong = false;
                    let mut any_right = false;
                    for (i, predictor) in predictors.iter_mut().enumerate() {
                        if !active[i] && i != 0 {
                            continue;
                        }
                        let input = &mut inputs[i];
                        let wrong = score_token(predictor, actual, input, &mut frequencies[i]);
                        errors[i] += usize::from(wrong);
                        if active[i] {
                            any_wrong |= wrong;
                            any_right |= !wrong;
                        }
                    }
                    budget.accept(actual);
                    {
                        if prefix_errors.is_empty()
                            && (budget.tokens >= minimum_tokens || budget.bytes >= 262144)
                        {
                            prefix_errors = errors.clone();
                        }
                        if prefix_errors.is_empty() {
                            continue;
                        }
                        let checkpoint = !continuing;
                        if checkpoint {
                            if prefix_errors[0] > 1
                                || prefix_errors[extension_candidate] != prefix_errors[0]
                            {
                                return RefinementScores {
                                    errors,
                                    prefix_errors,
                                    tokens: budget.total_tokens,
                                    decisive: false,
                                };
                            }
                            active.fill(false);
                            active[0] = true;
                            active[extension_candidate] = true;
                            continuing = true;
                        }
                        if !checkpoint && !(any_wrong && any_right) {
                            continue;
                        }
                        let settled = eliminate_refinement_candidates(&errors, &mut active);
                        if !settled {
                            continue;
                        }
                        for i in 1..errors.len() {
                            if !active[i] {
                                errors[i] = usize::MAX;
                            }
                        }
                        return RefinementScores {
                            errors,
                            prefix_errors,
                            tokens: budget.total_tokens,
                            decisive: true,
                        };
                    }
                }
            }
        }
        for (i, predictor) in predictors.iter_mut().enumerate() {
            if active[i] || i == 0 {
                predictor
                    .finish_block(&mut inputs[i])
                    .expect("block-derived flush limit");
            }
        }
    }
    for i in 1..errors.len() {
        if !active[i] {
            errors[i] = usize::MAX;
        }
    }
    RefinementScores {
        prefix_errors: if prefix_errors.is_empty() {
            errors.clone()
        } else {
            prefix_errors
        },
        errors,
        tokens: budget.total_tokens,
        decisive: true,
    }
}

pub fn score_predictions(
    prediction: &mut PredictionState,
    blocks: &[DeflateTokenBlock],
    plain: &PlainText,
    max_tokens: usize,
    max_bytes: u32,
) -> (usize, usize) {
    let score = score_profile_predictions(prediction, blocks, plain, max_tokens, max_bytes);
    (score.errors, score.tokens)
}

fn score_profile_predictions(
    prediction: &mut PredictionState,
    blocks: &[DeflateTokenBlock],
    plain: &PlainText,
    max_tokens: usize,
    max_bytes: u32,
) -> PredictionScore {
    prediction.begin_chunk(blocks);
    let mut input = PreflateInput::new(plain);
    let mut budget = ScoringBudget::default();
    let mut score = PredictionScore::default();
    for block in blocks {
        match &block.block_type {
            DeflateTokenBlockType::Stored { uncompressed } => {
                prediction.begin_stored_block(&input).expect("idle block");
                for _ in uncompressed {
                    if budget.exhausted(input.pos(), max_tokens, max_bytes) {
                        score.tokens = budget.total_tokens;
                        return score;
                    }
                    prediction.advance_stored_byte(&mut input);
                    budget.bytes += 1;
                }
            }
            DeflateTokenBlockType::Huffman { tokens, .. } => {
                prediction
                    .begin_known_huffman_block(tokens, &mut input)
                    .expect("block-derived flush limit");
                let mut frequency = TokenFrequency::default();
                for actual in tokens {
                    if budget.exhausted(input.pos(), max_tokens, max_bytes) {
                        score.tokens = budget.total_tokens;
                        return score;
                    }
                    if score_token(prediction, actual, &mut input, &mut frequency) {
                        score.errors += 1;
                        score.reference_errors +=
                            usize::from(matches!(actual, DeflateToken::Reference(_)));
                    }
                    budget.accept(actual);
                }
            }
        }
        prediction
            .finish_block(&mut input)
            .expect("block-derived flush limit");
    }
    score.tokens = budget.total_tokens;
    score
}

fn score_token(
    prediction: &mut PredictionState,
    actual: &DeflateToken,
    input: &mut PreflateInput,
    frequency: &mut TokenFrequency,
) -> bool {
    let predicted = prediction.predict(input, frequency);
    prediction.accept_token(actual, predicted, input);
    if prediction.needs_frequency() {
        frequency.commit_token(actual);
    }
    *actual != predicted
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        deflate::{
            deflate_reader::DeflateContents, deflate_token::DeflateHuffmanType,
            deflate_writer::DeflateWriter,
        },
        hash_algorithm::HashAlgorithm,
        parameters::DictionaryAddPolicy,
        stream_processor::encode_first_chunk_observed,
        token_predictor::TokenPredictor,
    };

    #[test]
    fn first_match_requires_better_references_without_increasing_total_errors() {
        for (before, after, before_references, after_references, accepted) in [
            (0, 0, 0, 0, false),
            (100, 100, 64, 16, true),
            (100, 101, 64, 0, false),
            (100, 99, 64, 17, false),
            (100, 99, 20, 5, false),
            (100, 99, 20, 4, true),
        ] {
            let baseline = PredictionScore {
                errors: before,
                reference_errors: before_references,
                tokens: 128,
            };
            let candidate = PredictionScore {
                errors: after,
                reference_errors: after_references,
                tokens: 128,
            };
            assert_eq!(improves_first_match(&baseline, &candidate), accepted);
        }
    }

    fn first_match_fixture(
        perfect: bool,
        groups: usize,
    ) -> (ReconstructionParameters, DeflateContents, PlainText) {
        let mut parameters = crate::token_predictor::tests::zlib_level_1_params();
        parameters.set_hash_algorithm(HashAlgorithm::RandomVector);
        parameters.set_insertion(DictionaryAddPolicy::AddFirst(0));
        parameters.set_max_chain(128);
        let mut bytes = vec![b'@'];
        let mut tokens = vec![DeflateToken::Literal(b'@')];
        let mut seed = 1234567u32;
        for index in 0..groups {
            let pattern: [u8; 4] = std::array::from_fn(|_| {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                (seed >> 24) as u8
            });
            let mut literal = |value| {
                bytes.push(value);
                tokens.push(DeflateToken::Literal(value));
            };
            for value in pattern {
                literal(value);
            }
            literal(pattern[3] ^ 17);
            let head = bytes.len();
            for value in &pattern[..3] {
                bytes.push(*value);
                tokens.push(DeflateToken::Literal(*value));
            }
            bytes.push(pattern[3] ^ 255);
            tokens.push(DeflateToken::Literal(pattern[3] ^ 255));
            if index % 4 != 0 {
                tokens.push(DeflateToken::new_ref(3, (bytes.len() - head) as u32));
            } else {
                tokens.extend(pattern[..3].iter().copied().map(DeflateToken::Literal));
            }
            bytes.extend_from_slice(&pattern[..3]);
            bytes.extend_from_slice(&[pattern[3], pattern[3] ^ 33]);
            tokens.extend([pattern[3], pattern[3] ^ 33].map(DeflateToken::Literal));
        }
        let plain = PlainText::new_with_data(bytes);
        let mut block = DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Huffman {
                tokens,
                huffman_type: DeflateHuffmanType::Static,
            },
            last: true,
        };
        if perfect {
            let mut state = PredictionState::from_reconstruction_parameters(parameters);
            state.begin_chunk(std::slice::from_ref(&block));
            let DeflateTokenBlockType::Huffman { tokens, .. } = &mut block.block_type else {
                unreachable!()
            };
            let mut input = PreflateInput::new(&plain);
            state.begin_known_huffman_block(tokens, &mut input).unwrap();
            tokens.clear();
            let mut frequency = TokenFrequency::default();
            while input.remaining() != 0 {
                let predicted = state.predict(&input, &frequency);
                state.accept_token(&predicted, predicted, &mut input);
                frequency.commit_token(&predicted);
                tokens.push(predicted);
            }
            state.finish_block(&mut input).unwrap();
        }
        let mut writer = DeflateWriter::new();
        writer.encode_block(&block).unwrap();
        writer.flush();
        let contents = DeflateContents {
            compressed_size: writer.detach_output().len(),
            blocks: vec![block],
        };
        assert!(contents.compressed_size > 1024);
        (parameters, contents, plain)
    }

    #[test]
    fn first_match_refinement_accepts_shared_literal_errors_and_preserves_exact_bytes() {
        let (parameters, contents, plain) = first_match_fixture(false, 512);
        assert!(contents.compressed_size >= 4096);
        let info =
            crate::estimator::preflate_stream_info::tests::extract_preflate_info(&contents.blocks);
        let first = models::generic::first_match(parameters).unwrap();
        let score = |parameters| {
            score_profile_predictions(
                &mut PredictionState::from_reconstruction_parameters(parameters),
                &contents.blocks,
                &plain,
                4096,
                524288,
            )
        };
        let before = score(parameters);
        let after = score(first);
        assert_eq!(before.tokens, after.tokens);
        assert!(after.errors > 0);
        assert_eq!(after.reference_errors, 0);
        assert!(before.reference_errors >= 64);
        assert!(!improves_generic_parser(before.errors, after.errors));
        assert!(improves_first_match(&before, &after));
        assert_eq!(
            refine_ambiguous_profile(parameters, &info, &contents, &plain),
            first
        );
        let encode = |parameters: &ReconstructionParameters| {
            encode_first_chunk_observed(
                &mut TokenPredictor::from_parameters(parameters),
                &contents,
                &plain,
                false,
                None,
                |_, _, _, _| {},
            )
            .unwrap()
        };
        let original = encode(&parameters);
        let improved = encode(&first);
        assert!(
            improved.len() < original.len(),
            "{} -> {}",
            original.len(),
            improved.len()
        );
        let mut writer = DeflateWriter::new();
        writer.encode_block(&contents.blocks[0]).unwrap();
        writer.flush();
        assert_eq!(
            crate::recreate_whole_deflate_stream(plain.text(), &improved).unwrap(),
            writer.detach_output()
        );
    }

    #[test]
    fn first_match_refinement_preserves_an_already_perfect_longer_match_parser() {
        let (parameters, contents, plain) = first_match_fixture(true, 512);
        assert!(contents.compressed_size >= 4096);
        let info =
            crate::estimator::preflate_stream_info::tests::extract_preflate_info(&contents.blocks);
        assert!(models::generic::first_match(parameters).is_some());
        assert_eq!(
            score_predictions(
                &mut PredictionState::from_reconstruction_parameters(parameters),
                &contents.blocks,
                &plain,
                4096,
                524288,
            )
            .0,
            0
        );
        assert_eq!(
            refine_ambiguous_profile(parameters, &info, &contents, &plain),
            parameters
        );
    }

    #[test]
    fn first_match_refinement_excludes_tiny_streams_and_recognized_profiles() {
        for (groups, model) in [
            (128, CompressorProfile::Custom),
            (512, CompressorProfile::Windows),
        ] {
            let (parameters, contents, plain) = first_match_fixture(false, groups);
            assert_eq!(contents.compressed_size >= 4096, groups == 512);
            let info = crate::estimator::preflate_stream_info::tests::extract_preflate_info(
                &contents.blocks,
            );
            assert_eq!(
                refine_profile(
                    model.with_parameters(parameters),
                    &info,
                    &contents,
                    &plain,
                    &[]
                )
                .reconstruction,
                parameters
            );
        }
    }

    #[test]
    fn generic_parser_refinement_requires_a_large_absolute_and_relative_gain() {
        for (before, after, accepted) in [
            (16, 1, false),
            (20, 4, true),
            (100, 25, true),
            (100, 26, false),
            (100, 100, false),
            (usize::MAX, usize::MAX / 4, true),
        ] {
            assert_eq!(improves_generic_parser(before, after), accepted);
        }
    }

    #[test]
    fn generic_greedy_refinement_accepts_an_imperfect_but_much_better_parser() {
        use crate::{
            deflate::{
                deflate_reader::DeflateContents, deflate_token::DeflateHuffmanType,
                deflate_writer::DeflateWriter,
            },
            parameters::{DictionaryAddPolicy, LazyBehavior, tests::MatchingType},
        };

        fn literal(tokens: &mut Vec<DeflateToken>, bytes: &mut Vec<u8>, value: u8) {
            tokens.push(DeflateToken::Literal(value));
            bytes.push(value);
        }
        let mut tokens = Vec::new();
        let mut bytes = Vec::new();
        let mut seed = 1234567u32;
        for index in 0..128 {
            let pattern: [u8; 12] = std::array::from_fn(|_| {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                (seed >> 24) as u8
            });
            let first = bytes.len();
            for value in &pattern[..4] {
                literal(&mut tokens, &mut bytes, *value);
            }
            literal(&mut tokens, &mut bytes, pattern[4] ^ 255);
            let second = bytes.len();
            for value in &pattern[1..] {
                literal(&mut tokens, &mut bytes, *value);
            }
            literal(&mut tokens, &mut bytes, pattern[0] ^ 255);
            let position = bytes.len();
            if index % 32 == 0 {
                for value in &pattern[..4] {
                    literal(&mut tokens, &mut bytes, *value);
                }
            } else {
                tokens.push(DeflateToken::new_ref(4, (position - first) as u32));
                bytes.extend_from_slice(&pattern[..4]);
            }
            tokens.push(DeflateToken::new_ref(8, (bytes.len() - second - 3) as u32));
            bytes.extend_from_slice(&pattern[4..]);
            literal(&mut tokens, &mut bytes, pattern[0]);
        }
        while tokens.len() < 4095 {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            literal(&mut tokens, &mut bytes, (seed >> 24) as u8);
        }
        let blocks = vec![DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Huffman {
                tokens,
                huffman_type: DeflateHuffmanType::Static,
            },
            last: true,
        }];
        let mut writer = DeflateWriter::new();
        writer.encode_block(&blocks[0]).unwrap();
        writer.flush();
        let compressed = writer.detach_output();
        assert!(compressed.len() > 1024);
        let contents = DeflateContents {
            compressed_size: compressed.len(),
            blocks,
        };
        let plain = PlainText::new_with_data(bytes);
        let info =
            crate::estimator::preflate_stream_info::tests::extract_preflate_info(&contents.blocks);
        let parameters = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(crate::HashAlgorithm::Libdeflate4Fast);
            canonical_configuration.set_full_window(true);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_nice_length(258);
            canonical_configuration.set_max_chain(128);
            canonical_configuration.set_short_match_cutoff(0);
            canonical_configuration.set_matching_type(MatchingType::Lazy {
                max_lazy: 16,
                filtered_matching: false,
                behavior: LazyBehavior::RecomputeAfterLiteral,
            });
            canonical_configuration.max_token_count = 4095;
            canonical_configuration
        };
        let greedy = models::generic::primary_only_greedy(parameters, &info).unwrap();
        let score = |parameters: &ReconstructionParameters| {
            score_predictions(
                &mut PredictionState::from_reconstruction_parameters(*parameters),
                &contents.blocks,
                &plain,
                4096,
                524288,
            )
        };
        let (errors, count) = score(&parameters);
        let (greedy_errors, greedy_count) = score(&greedy);
        assert_eq!(count, greedy_count);
        assert!(greedy_errors > 0);
        assert!(
            improves_generic_parser(errors, greedy_errors),
            "{errors} -> {greedy_errors}"
        );
        assert_eq!(
            refine_ambiguous_profile(parameters, &info, &contents, &plain),
            greedy
        );

        let encode = |parameters: &ReconstructionParameters| {
            crate::stream_processor::encode_first_chunk_observed(
                &mut crate::token_predictor::TokenPredictor::from_parameters(parameters),
                &contents,
                &plain,
                false,
                None,
                |_, _, _, _| {},
            )
            .unwrap()
        };
        let before = encode(&parameters);
        let after = encode(&greedy);
        assert!(
            after.len() < before.len(),
            "{} -> {}",
            before.len(),
            after.len()
        );
        assert_eq!(
            crate::recreate_whole_deflate_stream(plain.text(), &after).unwrap(),
            compressed
        );
    }

    #[test]
    fn repetition_budget_preserves_boundaries_and_hard_work_limits() {
        let mut budget = ScoringBudget::default();
        let repeated = DeflateToken::new_ref(258, 1);
        budget.accept(&repeated);
        assert_eq!(
            (budget.tokens, budget.bytes, budget.total_tokens),
            (0, 0, 1)
        );
        for token in [
            DeflateToken::Literal(b'a'),
            DeflateToken::new_ref(257, 1),
            DeflateToken::new_ref(258, 2),
        ] {
            budget.accept(&token);
        }
        assert_eq!(
            (budget.tokens, budget.bytes, budget.total_tokens),
            (3, 516, 4)
        );
        assert!(!budget.exhausted(0, 4, 517));
        assert!(budget.exhausted(0, 3, 517));
        assert!(budget.exhausted(0, 4, 516));
        assert!(!budget.exhausted(8 * 1024 * 1024 - 1, 4, 517));
        assert!(budget.exhausted(8 * 1024 * 1024, 4, 517));
        for _ in budget.total_tokens..32768 {
            budget.accept(&repeated);
        }
        assert!(budget.exhausted(0, 4, 517));
    }

    #[test]
    fn scoring_advances_repetitive_history_before_sampling_varied_tokens() {
        use crate::deflate::{deflate_token::DeflateHuffmanType, deflate_writer::DeflateWriter};
        let mut tokens = vec![DeflateToken::Literal(b'@'), DeflateToken::Literal(b'a')];
        let mut bytes = b"@a".to_vec();
        for _ in 0..6000 {
            tokens.push(DeflateToken::new_ref(258, 1));
            bytes.extend_from_slice(&[b'a'; 258]);
        }
        let tail = b"bcdefghabcde";
        tokens.extend(tail.iter().copied().map(DeflateToken::Literal));
        bytes.extend_from_slice(tail);
        let token_count = tokens.len();
        let blocks = vec![DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Huffman {
                tokens,
                huffman_type: DeflateHuffmanType::Static,
            },
            last: true,
        }];
        let plain = PlainText::new_with_data(bytes);
        let parameters = {
            let mut canonical_configuration = crate::token_predictor::tests::zlib_level_1_params();
            canonical_configuration.set_insertion(crate::parameters::DictionaryAddPolicy::AddAll);
            canonical_configuration.set_nice_length(258);
            canonical_configuration.set_max_chain(128);
            canonical_configuration
        };
        let (errors, count) = score_predictions(
            &mut PredictionState::from_reconstruction_parameters((&parameters).into()),
            &blocks,
            &plain,
            16,
            64,
        );
        assert_eq!(count, token_count);
        let scores = score_refinement(&[parameters; 2], &blocks, &plain, 1024, 1);
        assert_eq!(scores.tokens, token_count);
        assert_eq!(scores.errors, [errors; 2]);
        assert!(scores.decisive);

        let mut writer = DeflateWriter::new();
        writer.encode_block(&blocks[0]).unwrap();
        writer.flush();
        let compressed = writer.detach_output();
        let contents = crate::deflate::deflate_reader::DeflateContents {
            compressed_size: compressed.len(),
            blocks,
        };
        let mut predictor = crate::token_predictor::TokenPredictor::from_parameters(&parameters);
        predictor.trace = Some(crate::token_predictor::TokenPredictionTrace::default());
        let encoded = crate::stream_processor::encode_first_chunk_observed(
            &mut predictor,
            &contents,
            &plain,
            false,
            None,
            |_, _, _, _| {},
        )
        .unwrap();
        assert_eq!(predictor.trace.as_ref().unwrap().token_count, count);
        assert_eq!(predictor.trace.as_ref().unwrap().mismatch_count, errors);
        assert_eq!(
            crate::recreate_whole_deflate_stream(plain.text(), &encoded).unwrap(),
            compressed
        );
    }

    #[test]
    fn refinement_stopping_counts_relative_errors_not_shared_predictions() {
        let mut active = [true; 3];
        assert!(!eliminate_refinement_candidates(
            &[100, 100, 100],
            &mut active
        ));
        assert_eq!(active, [true; 3]);
        assert!(!eliminate_refinement_candidates(
            &[100, 107, 108],
            &mut active
        ));
        assert_eq!(active, [true, true, false]);
        assert!(eliminate_refinement_candidates(
            &[100, 108, 108],
            &mut active
        ));
        assert_eq!(active, [true, false, false]);
        let mut active = [true; 3];
        assert!(eliminate_refinement_candidates(&[8, 0, 0], &mut active));
        assert_eq!(active, [false, true, true]);
    }

    pub fn refine_ambiguous_profile(
        parameters: ReconstructionParameters,
        info: &PreflateStreamInfo,
        contents: &crate::deflate::deflate_reader::DeflateContents,
        plain: &PlainText,
    ) -> ReconstructionParameters {
        refine_profile(
            CompressorProfile::Custom.with_parameters(parameters),
            info,
            contents,
            plain,
            &[],
        )
        .reconstruction
    }
}
