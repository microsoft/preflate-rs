/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

//! Bounded candidate replay and refinement stopping, driven by shared prediction state.
//!
//! Scores count initial token mismatches, not correction bytes. Actual tokens advance
//! each candidate's history without correction recovery or trial encoding. Family
//! models own candidate construction; this module owns general profile-refinement
//! acceptance, replay limits and relative-error stopping. Family-specific refinement
//! retains its acceptance policy. Inconclusive continuation retains the prefix scores.
//! A work-limit or decisive early return deliberately discards unfinished contexts:
//! those candidate states are not reused after scoring.
//! Full-length distance-one matches advance normally and retain their errors,
//! but do not consume the informative sample budget. Total replay stays bounded.

use crate::{
    deflate::deflate_token::{
        DeflateToken, DeflateTokenBlock, DeflateTokenBlockType, TokenFrequency,
    },
    models::{self, CompressorProfile},
    parameters::TokenPredictorParameters,
    prediction_state::PredictionState,
    preflate_input::{PlainText, PreflateInput},
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

pub(crate) fn refine_profile(
    profile: CompressorProfile,
    info: &super::PreflateStreamInfo,
    contents: &crate::deflate::deflate_reader::DeflateContents,
    plain: &PlainText,
) -> CompressorProfile {
    if contents.compressed_size <= 1024 {
        return profile;
    }
    let parameters = profile.parameters();
    let candidates = models::profile_alternatives(parameters, info);
    if candidates.iter().all(Option::is_none) {
        return profile;
    }
    let score = |parameters: &TokenPredictorParameters| {
        score_predictions(
            &mut PredictionState::new(parameters),
            &contents.blocks,
            plain,
            4096,
            524288,
        )
    };
    let (errors, tokens) = score(&parameters);
    // Keep an already-perfect prefix, even when another fingerprint also fits.
    if errors < 2 || tokens < 64 {
        return profile;
    }
    for candidate in candidates.into_iter().flatten() {
        let proposed = candidate.parameters();
        if proposed != parameters && score(&proposed) == (0, tokens) {
            return candidate;
        }
    }
    profile
}

#[cfg(test)]
pub(crate) fn refine_ambiguous_profile(
    parameters: TokenPredictorParameters,
    info: &super::PreflateStreamInfo,
    contents: &crate::deflate::deflate_reader::DeflateContents,
    plain: &PlainText,
) -> TokenPredictorParameters {
    refine_profile(CompressorProfile::Custom(parameters), info, contents, plain).parameters()
}

pub(crate) struct RefinementScores {
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

pub(crate) fn score_refinement(
    parameters: &[TokenPredictorParameters],
    blocks: &[DeflateTokenBlock],
    plain: &PlainText,
    minimum_tokens: usize,
    extension_candidate: usize,
) -> RefinementScores {
    assert!((2..=12).contains(&parameters.len()));
    assert!((1..parameters.len()).contains(&extension_candidate));
    let mut predictors: Vec<_> = parameters.iter().map(PredictionState::new).collect();
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

pub(crate) fn score_predictions(
    prediction: &mut PredictionState,
    blocks: &[DeflateTokenBlock],
    plain: &PlainText,
    max_tokens: usize,
    max_bytes: u32,
) -> (usize, usize) {
    prediction.begin_chunk(blocks);
    let mut input = PreflateInput::new(plain);
    let mut budget = ScoringBudget::default();
    let mut mismatches = 0;
    for block in blocks {
        match &block.block_type {
            DeflateTokenBlockType::Stored { uncompressed } => {
                prediction.begin_stored_block(&input).expect("idle block");
                for _ in uncompressed {
                    if budget.exhausted(input.pos(), max_tokens, max_bytes) {
                        return (mismatches, budget.total_tokens);
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
                        return (mismatches, budget.total_tokens);
                    }
                    mismatches +=
                        usize::from(score_token(prediction, actual, &mut input, &mut frequency));
                    budget.accept(actual);
                }
            }
        }
        prediction
            .finish_block(&mut input)
            .expect("block-derived flush limit");
    }
    (mismatches, budget.total_tokens)
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
mod tests {
    use super::*;

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
        let parameters = TokenPredictorParameters {
            add_policy: crate::parameters::DictionaryAddPolicy::AddAll,
            nice_length: 258,
            max_chain: 128,
            ..crate::token_predictor::zlib_level_1_params()
        };
        let (errors, count) = score_predictions(
            &mut PredictionState::new(&parameters),
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
        let mut predictor = crate::token_predictor::TokenPredictor::new(&parameters);
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
}
