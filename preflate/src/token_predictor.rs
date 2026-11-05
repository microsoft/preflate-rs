/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

//! Prediction-correction encoding and decoding for DEFLATE blocks.
//!
//! Replays the selected compressor settings against plaintext and compares each
//! predicted token with the token parsed from the original stream. Differences
//! in literal/reference choice, match length, and distance become correction
//! actions. Reconstruction performs the inverse operation to recover the exact
//! token sequence rather than merely an equivalent decompressed result.
//!
//! `PredictionState` maintains matching history and lazy lookahead. This module
//! surrounds that state with block framing, correction codecs, Huffman-tree
//! prediction, and optional traces. It also finalizes the executable settings
//! after replay has established which parameter values are equivalent.

use crate::{
    bit_helper::DebugHash,
    deflate::{
        deflate_constants::MIN_MATCH,
        deflate_token::{
            BT_DYNAMICHUFF, BT_STATICHUFF, BT_STORED, DeflateHuffmanType, DeflateToken,
            DeflateTokenBlock, DeflateTokenBlockType, DeflateTokenReference, TokenFrequency,
        },
        huffman_calc::HufftreeBitCalc,
    },
    prediction_state::PredictionState,
    preflate_error::{AddContext, ExitCode, Result, err_exit_code},
    preflate_input::PreflateInput,
    reconstruction_parameters::{NormalizationBounds, ReconstructionParameters},
    statistical_codec::{CodecCorrection, PredictionDecoder, PredictionEncoder},
    tree_predictor::{predict_tree_for_block, recreate_tree_for_block},
};

const VERIFY: bool = false;

// Capture the initial prediction, before correction recovery can hide model mismatches.
#[cfg(any(test, feature = "diagnostics"))]
#[derive(Debug)]
pub struct TokenPredictionTrace {
    pub stage: &'static str,
    pub block_profile: &'static str,
    pub(crate) parameters: Option<crate::estimator::EstimationResult>,
    pub token_count: usize,
    pub mismatch_count: usize,
    pub first_mismatches: Vec<(u32, DeflateToken, DeflateToken)>,
    pub(crate) max_mismatches: usize,
    pub(crate) block_limit: Option<u32>,
    pub(crate) dictionary_reset: Option<bool>,
}

#[cfg(any(test, feature = "diagnostics"))]
impl TokenPredictionTrace {
    /// Serialize the latest available parameter report without exposing estimator types.
    pub fn estimator_parameters_json(&self) -> Result<Option<String>> {
        self.parameters
            .map(crate::estimator::EstimationResult::to_json)
            .transpose()
    }

    /// Serialize the latest executable settings without estimation metadata.
    pub fn reconstruction_parameters_json(&self) -> Result<Option<String>> {
        self.parameters
            .map(|report| report.reconstruction.to_json())
            .transpose()
    }
}

#[cfg(any(test, feature = "diagnostics"))]
impl Default for TokenPredictionTrace {
    fn default() -> Self {
        Self {
            stage: "not_started",
            block_profile: "Default",
            parameters: None,
            token_count: 0,
            mismatch_count: 0,
            first_mismatches: Vec::new(),
            max_mismatches: 8,
            block_limit: None,
            dictionary_reset: None,
        }
    }
}

pub struct TokenPredictor {
    prediction: PredictionState,
    finalized_parameters: Option<ReconstructionParameters>,
    #[cfg(any(test, feature = "diagnostics"))]
    pub(crate) trace: Option<TokenPredictionTrace>,
}

impl std::fmt::Debug for TokenPredictor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenPredictor")
            .field("prediction", &self.prediction)
            .finish()
    }
}

impl TokenPredictor {
    pub(crate) fn from_reconstruction_parameters(parameters: ReconstructionParameters) -> Self {
        Self {
            prediction: PredictionState::from_reconstruction_parameters(parameters),
            finalized_parameters: None,
            #[cfg(any(test, feature = "diagnostics"))]
            trace: None,
        }
    }

    pub(crate) fn begin_chunk(&mut self, blocks: &[DeflateTokenBlock]) -> usize {
        let tail_length = self.prediction.begin_chunk(blocks);
        #[cfg(any(test, feature = "diagnostics"))]
        if let Some(trace) = &mut self.trace {
            trace.block_profile = self.prediction.block_profile_name();
        }
        tail_length
    }

    pub(crate) fn predict_end_of_chunk(&self, input: &PreflateInput) -> bool {
        self.prediction.predict_end_of_chunk(input)
    }

    pub(crate) fn enable_parameter_normalization(
        &mut self,
        compressed_size: usize,
        complete: bool,
    ) {
        let parameters = self.prediction.reconstruction_parameters();
        self.prediction.enable_parameter_normalization(
            parameters.behavior.short_match_cutoff(),
            parameters.behavior.supports_deferred_cutoff(),
            compressed_size,
            complete,
        );
    }

    pub(crate) fn reconstruction_parameters(&self) -> ReconstructionParameters {
        self.finalized_parameters
            .unwrap_or_else(|| self.prediction.reconstruction_parameters())
    }

    pub(crate) fn finalize_reconstruction_parameters(&mut self) -> ReconstructionParameters {
        *self.finalized_parameters.get_or_insert_with(|| {
            self.prediction
                .reconstruction_parameters()
                .normalized(NormalizationBounds {
                    window_bits: self.prediction.normalized_window_bits(),
                    short_match_cutoff: self.prediction.short_match_distance_bounds(),
                    token_count: self.prediction.token_limit_bounds(),
                })
        })
    }

    fn encode_block_type(
        &mut self,
        codec: &mut impl PredictionEncoder,
        actual: u32,
        input: &PreflateInput,
    ) {
        let correction = self
            .prediction
            .block_type_correction(actual, input.remaining());
        codec.encode_correction(CodecCorrection::BlockTypeCorrection, correction);
    }

    #[allow(
        clippy::assertions_on_constants,
        reason = "Forbid checksum calls unless debug verification is enabled."
    )]
    pub fn checksum(&self) -> DebugHash {
        assert!(VERIFY);
        let mut c = DebugHash::default();
        self.prediction.checksum(&mut c);
        c
    }

    /// in the case where we are processing a continuation, we need to
    /// add the missing hashes of the entries that were at the end of the
    /// input so it can be found.
    pub fn add_missing_previous_hash(&mut self, input: &PreflateInput) {
        self.prediction.add_missing_previous_hash(input);
    }

    #[inline(never)] // don't inline so we get better call stacks
    pub fn predict_block<D: PredictionEncoder>(
        &mut self,
        block: &DeflateTokenBlock,
        codec: &mut D,
        input: &mut PreflateInput,
        final_block_in_chunk: bool,
    ) -> Result<()> {
        #[cfg(any(test, feature = "diagnostics"))]
        if let Some(trace) = &mut self.trace {
            trace.block_limit = None;
            trace.dictionary_reset = None;
        }
        codec.encode_verify_state("blocktypestart", 0);

        let (tokens, huffman_encoding) = match &block.block_type {
            DeflateTokenBlockType::Stored { uncompressed } => {
                self.prediction.begin_stored_block(input)?;
                self.encode_block_type(codec, BT_STORED, input);

                codec.encode_correction_diff(
                    CodecCorrection::UncompressBlockLenCorrection,
                    uncompressed.len() as u32,
                    self.prediction.predicted_stored_length(input.remaining()),
                );

                for _i in 0..uncompressed.len() {
                    self.prediction.advance_stored_byte(input);
                }

                self.prediction.finish_block(input)?;
                codec.encode_correction_bool(
                    CodecCorrection::Last,
                    block.last,
                    self.predict_end_of_chunk(input),
                );

                codec.encode_verify_state("done", if VERIFY { self.checksum().hash() } else { 0 });
                return Ok(());
            }

            DeflateTokenBlockType::Huffman {
                tokens: t,
                huffman_type,
                ..
            } => {
                let encoding = match huffman_type {
                    DeflateHuffmanType::Static => {
                        self.encode_block_type(codec, BT_STATICHUFF, input);
                        None
                    }
                    DeflateHuffmanType::Dynamic {
                        huffman_encoding: h,
                        ..
                    } => {
                        self.encode_block_type(codec, BT_DYNAMICHUFF, input);
                        Some(h)
                    }
                };
                (t, encoding)
            }
        };

        self.prediction.begin_known_huffman_block(tokens, input)?;
        #[cfg(any(test, feature = "diagnostics"))]
        if let Some(trace) = &mut self.trace {
            trace.block_limit = self.prediction.block_lookahead_limit()?;
            trace.dictionary_reset = self.prediction.block_reset_tag()?;
        }
        if self.prediction.flush_enabled() {
            codec.encode_correction(
                CodecCorrection::UncompressBlockLenCorrection,
                self.prediction
                    .block_lookahead_limit()?
                    .map_or(0, |length| length + 1),
            );
            if let Some(reset) = self.prediction.block_reset_tag()? {
                codec.encode_correction(
                    CodecCorrection::UncompressBlockLenCorrection,
                    u32::from(reset),
                );
            }
        }

        // if the block ends at an unexpected point, or it contains more tokens
        // than expected, we will need to encode the block size
        let predicted_count = self.prediction.predict_and_observe_token_count(
            input.remaining(),
            tokens.len(),
            final_block_in_chunk,
        );
        if (!final_block_in_chunk && tokens.len() != predicted_count)
            || tokens.len() > predicted_count
        {
            codec.encode_correction(
                CodecCorrection::TokenCount,
                u32::try_from(tokens.len()).unwrap() + 1,
            );
        } else {
            codec.encode_correction(CodecCorrection::TokenCount, 0);
        }

        codec.encode_verify_state("start", if VERIFY { self.checksum().hash() } else { 0 });

        let mut freq = TokenFrequency::default();

        for (i, target_token) in tokens.iter().enumerate() {
            codec.encode_verify_state(
                "token",
                if VERIFY {
                    self.checksum().hash()
                } else {
                    i as u64
                },
            );

            let predicted_token = self.prediction.predict(input, &freq);
            #[cfg(any(test, feature = "diagnostics"))]
            if let Some(trace) = &mut self.trace {
                trace.token_count += 1;
                if *target_token != predicted_token {
                    trace.mismatch_count += 1;
                    if trace.first_mismatches.len() < trace.max_mismatches {
                        trace
                            .first_mismatches
                            .push((input.pos(), *target_token, predicted_token));
                    }
                }
            }

            /*
            let hash = self.prediction.calculate_hash();
            println!(
                "B{}T{}: TGT({},{}) -> PRD({},{}), H({})",
                blockno,
                i,
                block.tokens[i].len(),
                block.tokens[i].dist(),
                predicted_token.len(),
                predicted_token.dist(),
                hash
            );
            */

            // Debug print statement
            // println!("B{}T{}: TGT({},{}) -> PRD({},{})", blockno, i, target_token.len, target_token.dist, predicted_token.len, predicted_token.dist);

            match target_token {
                DeflateToken::Literal(_) => {
                    match predicted_token {
                        DeflateToken::Literal(_) => {
                            codec.encode_misprediction(
                                CodecCorrection::LiteralPredictionWrong,
                                false,
                            );
                        }
                        DeflateToken::Reference(..) => {
                            // target had a literal, so we were wrong if we predicted a reference
                            codec.encode_misprediction(
                                CodecCorrection::ReferencePredictionWrong,
                                true,
                            );
                        }
                    }
                }
                DeflateToken::Reference(target_ref) => {
                    let predicted_ref = match predicted_token {
                        DeflateToken::Literal(_) => {
                            // target had a reference, so we were wrong if we predicted a literal
                            codec.encode_misprediction(
                                CodecCorrection::LiteralPredictionWrong,
                                true,
                            );
                            self.prediction
                                .repredict_reference(input)
                                .with_context(|| {
                                    format!(
                                        "repredict_reference target={:?} index={}",
                                        target_ref, i
                                    )
                                })?
                        }
                        DeflateToken::Reference(r) => {
                            // we predicted a reference correctly, so verify that the length/dist was correct
                            codec.encode_misprediction(
                                CodecCorrection::ReferencePredictionWrong,
                                false,
                            );
                            r
                        }
                    };

                    codec.encode_correction_diff(
                        CodecCorrection::LenCorrection,
                        target_ref.len(),
                        predicted_ref.len(),
                    );

                    if predicted_ref.len() != target_ref.len() {
                        let rematch = self
                            .prediction
                            .calculate_hops(target_ref, input)
                            .with_context(|| {
                                format!("calculate_hops p={:?}, t={:?}", predicted_ref, target_ref)
                            })?;
                        codec.encode_correction(
                            CodecCorrection::DistAfterLenCorrection,
                            rematch - 1,
                        );
                    } else if target_ref.dist() != predicted_ref.dist() {
                        let rematch = self
                            .prediction
                            .calculate_hops(target_ref, input)
                            .with_context(|| {
                                format!("calculate_hops p={:?}, t={:?}", predicted_ref, target_ref)
                            })?;
                        codec.encode_correction(CodecCorrection::DistOnlyCorrection, rematch);
                    } else {
                        codec.encode_correction(CodecCorrection::DistOnlyCorrection, 0);
                    }
                }
            }

            self.prediction
                .accept_token(target_token, predicted_token, input);
            freq.commit_token(target_token);
        }

        if let Some(huffman_encoding) = huffman_encoding {
            predict_tree_for_block(huffman_encoding, &freq, codec, HufftreeBitCalc::Zlib)?;
        }

        self.prediction.finish_block(input)?;
        codec.encode_correction_bool(
            CodecCorrection::Last,
            block.last,
            self.predict_end_of_chunk(input),
        );

        codec.encode_verify_state("done", if VERIFY { self.checksum().hash() } else { 0 });

        Ok(())
    }

    #[inline(never)] // don't inline so we get better call stacks
    pub fn recreate_block<D: PredictionDecoder>(
        &mut self,
        codec: &mut D,
        input: &mut PreflateInput,
    ) -> Result<DeflateTokenBlock> {
        codec.decode_verify_state("blocktypestart", 0);

        let bt = self.prediction.recover_block_type(
            codec.decode_correction(CodecCorrection::BlockTypeCorrection),
            input.remaining(),
        )?;

        match bt {
            BT_STORED => {
                self.prediction.begin_stored_block(input)?;
                let uncompressed_len = codec.decode_correction_diff(
                    CodecCorrection::UncompressBlockLenCorrection,
                    self.prediction.predicted_stored_length(input.remaining()),
                );

                if uncompressed_len > 65535 || uncompressed_len > input.remaining() {
                    return err_exit_code(ExitCode::InvalidDeflate, "Invalid stored block len");
                }

                let mut uncompressed = Vec::with_capacity(uncompressed_len as usize);

                for _i in 0..uncompressed_len {
                    uncompressed.push(input.cur_char(0));
                    self.prediction.advance_stored_byte(input);
                }

                self.prediction.finish_block(input)?;
                let last = codec.decode_correction_bool(
                    CodecCorrection::Last,
                    self.predict_end_of_chunk(input),
                );

                codec.decode_verify_state("done", if VERIFY { self.checksum().hash() } else { 0 });
                return Ok(DeflateTokenBlock {
                    block_type: DeflateTokenBlockType::Stored { uncompressed },
                    last,
                });
            }

            BT_STATICHUFF | BT_DYNAMICHUFF => {
                // continue
            }
            _ => {
                return err_exit_code(ExitCode::InvalidDeflate, "Invalid block type");
            }
        }

        let (limit, reset) = if self.prediction.flush_enabled() {
            let length = codec.decode_correction(CodecCorrection::UncompressBlockLenCorrection);
            let reset = if self.prediction.follows_empty_stored() {
                match codec.decode_correction(CodecCorrection::UncompressBlockLenCorrection) {
                    0 => false,
                    1 => true,
                    _ => return err_exit_code(ExitCode::InvalidDeflate, "Invalid flush reset tag"),
                }
            } else {
                false
            };
            (if length == 0 { None } else { Some(length - 1) }, reset)
        } else {
            (None, false)
        };
        self.prediction
            .begin_decoded_huffman_block(input, limit, reset)?;

        let mut blocksize = codec.decode_correction(CodecCorrection::TokenCount);
        if blocksize == 0 {
            blocksize = self.prediction.predicted_token_count(input.remaining());
        } else {
            blocksize -= 1;
            if self.prediction.flush_enabled() && blocksize > input.remaining() {
                return err_exit_code(ExitCode::InvalidDeflate, "Invalid flush token count");
            }
        }

        // rust aborts on OOM, so check before we allocate to avoid crashing the process
        let mut tokens = Vec::new();
        if tokens
            .try_reserve_exact(blocksize.min(input.remaining()) as usize)
            .is_err()
        {
            return err_exit_code(ExitCode::OutOfMemory, "Out of memory");
        }

        let mut freq = TokenFrequency::default();

        codec.decode_verify_state("start", if VERIFY { self.checksum().hash() } else { 0 });

        while input.remaining() != 0 && tokens.len() < blocksize as usize {
            codec.decode_verify_state(
                "token",
                if VERIFY {
                    self.checksum().hash()
                } else {
                    tokens.len() as u64
                },
            );

            let mut predicted_ref: DeflateTokenReference;
            let predicted_token = self.prediction.predict(input, &freq);
            match predicted_token {
                DeflateToken::Literal(l) => {
                    let not_ok =
                        codec.decode_misprediction(CodecCorrection::LiteralPredictionWrong);
                    if !not_ok {
                        self.prediction.accept_token(
                            &DeflateToken::Literal(l),
                            predicted_token,
                            input,
                        );
                        freq.commit_token(&DeflateToken::Literal(l));

                        tokens.push(DeflateToken::Literal(l));
                        continue;
                    }

                    predicted_ref =
                        self.prediction
                            .repredict_reference(input)
                            .with_context(|| {
                                format!("repredict_reference token_count={:?}", tokens.len())
                            })?;
                }
                DeflateToken::Reference(r) => {
                    let not_ok =
                        codec.decode_misprediction(CodecCorrection::ReferencePredictionWrong);
                    if not_ok {
                        let c = input.cur_char(0);
                        self.prediction.accept_token(
                            &DeflateToken::Literal(c),
                            predicted_token,
                            input,
                        );
                        freq.commit_token(&DeflateToken::Literal(c));

                        tokens.push(DeflateToken::Literal(c));
                        continue;
                    }

                    predicted_ref = r;
                }
            }

            let new_len =
                codec.decode_correction_diff(CodecCorrection::LenCorrection, predicted_ref.len());
            if !(MIN_MATCH..=258).contains(&new_len) || new_len > input.remaining() {
                return err_exit_code(ExitCode::InvalidDeflate, "Invalid reference length");
            }

            if new_len != predicted_ref.len() {
                let hops = codec.decode_correction(CodecCorrection::DistAfterLenCorrection) + 1;

                predicted_ref = DeflateTokenReference::new(
                    new_len,
                    self.prediction
                        .hop_match(new_len, hops, input)
                        .with_context(|| format!("hop_match l={} {:?}", new_len, predicted_ref))?,
                );
            } else {
                let hops = codec.decode_correction(CodecCorrection::DistOnlyCorrection);
                if hops != 0 {
                    let new_dist = self
                        .prediction
                        .hop_match(predicted_ref.len(), hops, input)
                        .with_context(|| format!("recalculate_distance token {}", tokens.len()))?;
                    predicted_ref = DeflateTokenReference::new(new_len, new_dist);
                }
            }

            self.prediction.accept_token(
                &DeflateToken::Reference(predicted_ref),
                predicted_token,
                input,
            );
            freq.commit_token(&DeflateToken::Reference(predicted_ref));
            tokens.push(DeflateToken::Reference(predicted_ref));
        }

        let huffman_type = if bt == BT_STATICHUFF {
            DeflateHuffmanType::Static
        } else {
            DeflateHuffmanType::Dynamic {
                huffman_encoding: recreate_tree_for_block(&freq, codec, HufftreeBitCalc::Zlib)?,
            }
        };

        self.prediction.finish_block(input)?;
        let last =
            codec.decode_correction_bool(CodecCorrection::Last, self.predict_end_of_chunk(input));

        let b = DeflateTokenBlock {
            last,
            block_type: DeflateTokenBlockType::Huffman {
                tokens,
                huffman_type,
            },
        };

        codec.decode_verify_state("done", if VERIFY { self.checksum().hash() } else { 0 });

        Ok(b)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        cabac::vp8::{VP8Reader, VP8Writer},
        cabac_codec::{PredictionDecoderCabac, PredictionEncoderCabac},
        statistical_codec::{CodecAction, VerifyPredictionDecoder, VerifyPredictionEncoder},
    };

    fn huffman(tokens: Vec<DeflateToken>, last: bool) -> DeflateTokenBlock {
        DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Huffman {
                tokens,
                huffman_type: DeflateHuffmanType::Static,
            },
            last,
        }
    }

    fn empty_stored() -> DeflateTokenBlock {
        DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Stored {
                uncompressed: vec![],
            },
            last: false,
        }
    }

    fn plaintext(blocks: &[DeflateTokenBlock]) -> PlainText {
        let mut plain = PlainText::new();
        for block in blocks {
            match &block.block_type {
                DeflateTokenBlockType::Stored { uncompressed } => plain.append(uncompressed),
                DeflateTokenBlockType::Huffman { tokens, .. } => {
                    for token in tokens {
                        match token {
                            DeflateToken::Literal(byte) => plain.push(*byte),
                            DeflateToken::Reference(r) => {
                                plain.append_reference(r.dist(), r.len()).unwrap();
                            }
                        }
                    }
                }
            }
        }
        plain
    }

    fn params() -> ReconstructionParameters {
        {
            let mut canonical_configuration = zlib_level_1_params();
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_nice_length(258);
            canonical_configuration.set_max_chain(32);
            canonical_configuration.set_matching_type(MatchingType::Greedy);
            canonical_configuration
        }
    }

    #[test]
    fn refinement_stopping_retains_state_and_stops_on_distinguishing_errors() {
        let blocks = [huffman(vec![DeflateToken::Literal(b'a'); 128], true)];
        let plain = plaintext(&blocks);
        let literal = {
            let mut canonical_configuration = params();
            canonical_configuration.set_strategy(crate::parameters::PreflateStrategy::HuffOnly);
            canonical_configuration
        };
        for parameters in [[literal, params()], [params(), literal]] {
            let scores = score_refinement(&parameters, &blocks, &plain, 0, 1);
            assert!(scores.decisive);
            assert!(scores.tokens < 128);
            let winner = usize::from(parameters[0] != literal);
            assert_eq!(scores.errors[winner], 0);
            for (index, parameters) in parameters.iter().enumerate() {
                if scores.errors[index] != usize::MAX {
                    let independent = score_predictions(
                        &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                            *parameters,
                        ),
                        &blocks,
                        &plain,
                        scores.tokens,
                        u32::MAX,
                    );
                    assert_eq!(independent, (scores.errors[index], scores.tokens));
                }
            }
        }
    }

    #[test]
    fn refinement_stopping_does_not_extend_a_distinguished_prefix() {
        let blocks = [huffman(vec![DeflateToken::Literal(b'a'); 128], true)];
        let plain = plaintext(&blocks);
        let literal = {
            let mut canonical_configuration = params();
            canonical_configuration.set_strategy(crate::parameters::PreflateStrategy::HuffOnly);
            canonical_configuration
        };
        for parameters in [[literal, params()], [params(), literal]] {
            let scores = score_refinement(&parameters, &blocks, &plain, 64, 1);
            assert!(!scores.decisive);
            assert_eq!(scores.tokens, 64);
            assert_eq!(scores.errors, scores.prefix_errors);
        }
    }

    #[test]
    fn refinement_stopping_continues_past_an_indistinguishable_prefix() {
        let mut tokens = Vec::new();
        for value in 0..1024u32 {
            tokens.extend([
                DeflateToken::Literal((value / 32) as u8),
                DeflateToken::Literal((value % 32) as u8),
                DeflateToken::Literal(255),
            ]);
        }
        tokens.extend(std::iter::repeat_n(DeflateToken::Literal(b'a'), 128));
        let blocks = [huffman(tokens, true)];
        let plain = plaintext(&blocks);
        let literal = {
            let mut canonical_configuration = params();
            canonical_configuration.set_strategy(crate::parameters::PreflateStrategy::HuffOnly);
            canonical_configuration
        };
        let scores = score_refinement(&[params(), literal], &blocks, &plain, 1024, 1);
        assert_eq!(scores.prefix_errors, [0, 0]);
        assert!(scores.decisive);
        assert!(scores.tokens > 3072 && scores.tokens < 3200);
        assert_eq!(scores.errors, [8, 0]);
    }

    #[test]
    fn refinement_stopping_keeps_ties_ambiguous_at_work_caps() {
        let blocks = [huffman(vec![DeflateToken::Literal(b'a'); 40000], true)];
        let plain = plaintext(&blocks);
        let literal = {
            let mut canonical_configuration = params();
            canonical_configuration.set_strategy(crate::parameters::PreflateStrategy::HuffOnly);
            canonical_configuration
        };
        let scores = score_refinement(&[literal, literal], &blocks, &plain, 1024, 1);
        assert!(!scores.decisive);
        assert_eq!(scores.tokens, 32768);
        assert_eq!(scores.errors[0], scores.errors[1]);
        let prefix = score_predictions(
            &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                (&literal).into(),
            ),
            &blocks,
            &plain,
            1024,
            262144,
        );
        assert_eq!(scores.prefix_errors, [prefix.0, prefix.0]);
        let blocks = [DeflateTokenBlock {
            last: true,
            block_type: DeflateTokenBlockType::Stored {
                uncompressed: vec![b'a'; 1048577],
            },
        }];
        let plain = plaintext(&blocks);
        let scores = score_refinement(&[params(), params()], &blocks, &plain, 0, 1);
        assert!(!scores.decisive);
        assert_eq!(scores.tokens, 0);
        assert_eq!(scores.errors, [0, 0]);
    }

    #[test]
    fn refinement_scoring_preserves_flushes_and_stored_history() {
        let blocks = [
            huffman(vec![DeflateToken::Literal(b'a'); 12], false),
            empty_stored(),
            DeflateTokenBlock {
                last: false,
                block_type: DeflateTokenBlockType::Stored {
                    uncompressed: b"abcdabcd".to_vec(),
                },
            },
            huffman(vec![DeflateToken::new_ref(4, 4)], true),
        ];
        let plain = plaintext(&blocks);
        let fixed = score_predictions(
            &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                (&params()).into(),
            ),
            &blocks,
            &plain,
            usize::MAX,
            u32::MAX,
        );
        let scores = score_refinement(&[params(), params()], &blocks, &plain, 0, 1);
        assert!(scores.decisive);
        assert_eq!(scores.tokens, fixed.1);
        assert_eq!(scores.errors, [fixed.0, fixed.0]);
        let measured = measure(&blocks, &plain, &params(), true);
        assert_eq!(fixed.0, measured.1);
    }

    #[test]
    fn shared_prediction_state_agrees_across_scoring_and_correction_roundtrips() {
        use crate::hash_algorithm::HashAlgorithm;

        let mut tokens: Vec<_> = b"@abcXbcdEFY"
            .iter()
            .copied()
            .map(DeflateToken::Literal)
            .collect();
        tokens.push(DeflateToken::new_ref(4, 10));
        tokens.extend(b"dEFQ".iter().copied().map(DeflateToken::Literal));
        tokens.extend(std::iter::repeat_n(DeflateToken::Literal(b'a'), 64));
        tokens.push(DeflateToken::new_ref(10, 1));
        tokens.extend(std::iter::repeat_n(DeflateToken::Literal(b'a'), 32));
        tokens.push(DeflateToken::new_ref(20, 1));
        let blocks = [huffman(tokens, true)];
        let plain = plaintext(&blocks);
        for (hash_algorithm, matching_type) in [
            (crate::compressors::zlib::DEFAULT_HASH, MatchingType::Greedy),
            (
                crate::compressors::zlib::DEFAULT_HASH,
                MatchingType::Lazy {
                    max_lazy: 16,
                    filtered_matching: false,
                    behavior: LazyBehavior::Zlib { good_length: 8 },
                },
            ),
            (
                HashAlgorithm::ZlibNG,
                MatchingType::Lazy {
                    max_lazy: 16,
                    filtered_matching: false,
                    behavior: LazyBehavior::RecomputeAfterLiteral,
                },
            ),
            (
                crate::compressors::zlib::DEFAULT_HASH,
                MatchingType::MiniZ {
                    max_probes: 16,
                    greedy: false,
                },
            ),
            (HashAlgorithm::Libdeflate4, MatchingType::LibdeflateGreedy),
            (
                HashAlgorithm::Libdeflate4,
                MatchingType::LibdeflateLazy {
                    two_positions: false,
                },
            ),
            (
                HashAlgorithm::Libdeflate4,
                MatchingType::LibdeflateLazy {
                    two_positions: true,
                },
            ),
            (
                HashAlgorithm::RandomVector,
                MatchingType::WindowsLazy { max_lazy: 128 },
            ),
        ] {
            let parameters = {
                let mut canonical_configuration = params();
                canonical_configuration.set_hash_algorithm(hash_algorithm);
                canonical_configuration.set_matching_type(matching_type);
                canonical_configuration
            };
            let fixed = score_predictions(
                &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                    (&parameters).into(),
                ),
                &blocks,
                &plain,
                usize::MAX,
                u32::MAX,
            );
            let measured = measure(&blocks, &plain, &parameters, true);
            assert!(measured.1 > 0, "{parameters:?}");
            assert_eq!(fixed.0, measured.1, "{parameters:?}");
            let scores = score_refinement(&[parameters; 2], &blocks, &plain, 0, 1);
            assert!(scores.decisive);
            assert_eq!(scores.tokens, fixed.1);
            assert_eq!(scores.errors, [fixed.0; 2], "{parameters:?}");
        }
    }

    fn measure(
        blocks: &[DeflateTokenBlock],
        plain: &PlainText,
        params: &ReconstructionParameters,
        flush: bool,
    ) -> (usize, usize, Option<u32>) {
        let mut predictor = TokenPredictor::from_parameters(params);
        if flush {
            predictor.begin_chunk(blocks);
        }
        predictor.trace = Some(TokenPredictionTrace {
            max_mismatches: 0,
            ..Default::default()
        });
        let mut input = PreflateInput::new(plain);
        let mut bytes = vec![];
        {
            let mut codec = PredictionEncoderCabac::new(VP8Writer::new(&mut bytes).unwrap());
            for (index, block) in blocks.iter().enumerate() {
                predictor
                    .predict_block(block, &mut codec, &mut input, index + 1 == blocks.len())
                    .unwrap();
            }
            codec.finish();
        }
        assert_eq!(input.remaining(), 0);
        let mismatches = predictor.trace.unwrap().mismatch_count;
        let mut decoder = TokenPredictor::from_parameters(params);
        decoder.begin_chunk(&[]);
        let mut input = PreflateInput::new(plain);
        let mut codec = PredictionDecoderCabac::new(VP8Reader::new(&bytes[..]).unwrap());
        for block in blocks {
            assert_eq!(
                decoder.recreate_block(&mut codec, &mut input).unwrap(),
                *block
            );
        }
        assert_eq!(input.remaining(), 0);
        assert_eq!(
            decoder.prediction.dictionary_reset_position(),
            predictor.prediction.dictionary_reset_position()
        );
        (
            bytes.len(),
            mismatches,
            decoder.prediction.dictionary_reset_position(),
        )
    }

    fn repeated_segment() -> Vec<DeflateToken> {
        let mut tokens: Vec<_> = b"@abcdef"
            .iter()
            .copied()
            .map(DeflateToken::Literal)
            .collect();
        tokens.push(DeflateToken::new_ref(192, 6));
        tokens
    }

    #[test]
    fn windows_lazy_scoring_encoding_and_decoding_agree() {
        let blocks = [huffman(
            vec![
                DeflateToken::Literal(b'a'),
                DeflateToken::new_ref(37, 1),
                DeflateToken::Literal(b'a'),
                DeflateToken::Literal(b'a'),
            ],
            true,
        )];
        let plain = plaintext(&blocks);
        let params = {
            let mut canonical_configuration = params();
            canonical_configuration
                .set_hash_algorithm(crate::hash_algorithm::HashAlgorithm::RandomVector);
            canonical_configuration.set_matches_to_start(true);
            canonical_configuration.set_max_chain(100);
            canonical_configuration.set_matching_type(MatchingType::WindowsLazy { max_lazy: 128 });
            canonical_configuration.max_token_count = 4;
            canonical_configuration
        };
        assert_eq!(measure(&blocks, &plain, &params, true).1, 0);
        assert_eq!(
            score_predictions(
                &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                    (&params).into()
                ),
                &blocks,
                &plain,
                usize::MAX,
                u32::MAX
            ),
            (0, 4)
        );
        let corrections = [huffman(
            vec![DeflateToken::Literal(b'a'), DeflateToken::new_ref(39, 1)],
            true,
        )];
        assert_eq!(
            measure(&corrections, &plaintext(&corrections), &params, true).1,
            1
        );
    }

    #[test]
    fn flush_sync_preserves_reused_dictionary() {
        let mut reused = vec![DeflateToken::Literal(b'@')];
        reused.push(DeflateToken::new_ref(198, 199));
        let blocks = [
            huffman(repeated_segment(), false),
            empty_stored(),
            huffman(reused, true),
        ];
        let plain = plaintext(&blocks);
        let params = {
            let mut canonical_configuration = params();
            canonical_configuration.set_max_chain(64);
            canonical_configuration
        };
        let baseline = measure(&blocks, &plain, &params, false);
        let improved = measure(&blocks, &plain, &params, true);
        assert_eq!(improved.2, None);
        assert_eq!(improved.1, 0);
        assert!(improved.1 <= baseline.1);
    }

    #[test]
    fn flush_marker_preserves_perfect_cross_boundary_four_byte_hashes() {
        let mut first: Vec<_> = b"@abcdZ"
            .iter()
            .copied()
            .map(DeflateToken::Literal)
            .collect();
        first.push(DeflateToken::new_ref(3, 5));
        let blocks = [
            huffman(first, false),
            empty_stored(),
            huffman(
                vec![
                    DeflateToken::Literal(0xe4),
                    DeflateToken::Literal(b'#'),
                    DeflateToken::new_ref(4, 5),
                ],
                true,
            ),
        ];
        let plain = plaintext(&blocks);
        for hash_algorithm in [
            crate::hash_algorithm::HashAlgorithm::Chromium { hash_mask: 0x7fff },
            crate::hash_algorithm::HashAlgorithm::Libdeflate4,
        ] {
            let params = {
                let mut canonical_configuration = params();
                canonical_configuration.set_hash_algorithm(hash_algorithm);
                canonical_configuration
            };
            let baseline = measure(&blocks, &plain, &params, false);
            assert_eq!(baseline.1, 0, "{hash_algorithm:?}");
            let improved = measure(&blocks, &plain, &params, true);
            assert_eq!(improved.1, 0, "{hash_algorithm:?}");
            assert_eq!(improved.2, None);
            assert_eq!(
                score_predictions(
                    &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                        (&params).into()
                    ),
                    &blocks,
                    &plain,
                    usize::MAX,
                    u32::MAX
                )
                .0,
                0
            );
        }
    }

    #[test]
    fn flush_full_reset_and_multiple_boundaries_reduce_initial_mismatches() {
        let blocks = [
            huffman(repeated_segment(), false),
            empty_stored(),
            huffman(repeated_segment(), false),
            empty_stored(),
            huffman(repeated_segment(), true),
        ];
        let plain = plaintext(&blocks);
        let baseline = measure(&blocks, &plain, &params(), false);
        let improved = measure(&blocks, &plain, &params(), true);
        assert!(improved.2.is_some());
        assert_eq!(improved.1, 0);
        assert!(improved.1 < baseline.1, "{} < {}", improved.1, baseline.1);
        assert_eq!(
            score_predictions(
                &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                    (&params()).into()
                ),
                &blocks,
                &plain,
                usize::MAX,
                u32::MAX
            )
            .0,
            improved.1
        );
    }

    #[test]
    fn flush_truncates_a_match_before_contiguous_repeated_data() {
        let mut second: Vec<_> = b"abcdef"
            .iter()
            .copied()
            .map(DeflateToken::Literal)
            .collect();
        second.push(DeflateToken::new_ref(192, 6));
        let blocks = [
            huffman(repeated_segment(), false),
            empty_stored(),
            huffman(second, true),
        ];
        let plain = plaintext(&blocks);
        let params = {
            let mut canonical_configuration = params();
            canonical_configuration.set_matches_to_start(true);
            canonical_configuration
        };
        let baseline = measure(&blocks, &plain, &params, false);
        let improved = measure(&blocks, &plain, &params, true);
        assert!(baseline.1 > 0);
        assert_eq!(improved.1, 0);
        assert_eq!(improved.2, Some(199));
    }

    #[test]
    fn flush_reset_evidence_survives_multiple_empty_blocks() {
        let blocks = [
            huffman(repeated_segment(), false),
            empty_stored(),
            huffman(vec![], false),
            empty_stored(),
            huffman(vec![], false),
            huffman(repeated_segment(), true),
        ];
        let plain = plaintext(&blocks);
        let improved = measure(&blocks, &plain, &params(), true);
        assert_eq!(improved.1, 0);
        assert_eq!(improved.2, Some(199));
    }

    #[test]
    fn flush_dictionary_state_survives_chunked_continuation() {
        let blocks = [
            huffman(repeated_segment(), false),
            empty_stored(),
            huffman(repeated_segment(), false),
            empty_stored(),
            huffman(repeated_segment(), true),
        ];
        let full = plaintext(&blocks);
        for ranges in [[0..2, 2..4, 4..5], [0..1, 1..3, 3..5]] {
            let mut plain = PlainText::new();
            let mut encoder_predictor = TokenPredictor::from_parameters(&params());
            encoder_predictor.trace = Some(TokenPredictionTrace::default());
            let mut decoder_predictor = TokenPredictor::from_parameters(&params());
            for (chunk, range) in ranges.into_iter().enumerate() {
                plain.append(&full.text()[chunk * 199..(chunk + 1) * 199]);
                let blocks = &blocks[range];
                encoder_predictor.begin_chunk(blocks);
                decoder_predictor.begin_chunk(&[]);
                let mut input = PreflateInput::new(&plain);
                if chunk != 0 {
                    encoder_predictor.add_missing_previous_hash(&input);
                    decoder_predictor.add_missing_previous_hash(&input);
                }
                let mut bytes = vec![];
                {
                    let mut codec =
                        PredictionEncoderCabac::new(VP8Writer::new(&mut bytes).unwrap());
                    for (index, block) in blocks.iter().enumerate() {
                        encoder_predictor
                            .predict_block(block, &mut codec, &mut input, index + 1 == blocks.len())
                            .unwrap();
                    }
                    codec.finish();
                }
                let mut input = PreflateInput::new(&plain);
                let mut codec = PredictionDecoderCabac::new(VP8Reader::new(&bytes[..]).unwrap());
                for block in blocks {
                    assert_eq!(
                        decoder_predictor
                            .recreate_block(&mut codec, &mut input)
                            .unwrap(),
                        *block
                    );
                }
                assert_eq!(input.remaining(), 0);
                assert_eq!(
                    encoder_predictor.prediction.dictionary_reset_position(),
                    decoder_predictor.prediction.dictionary_reset_position()
                );
                plain.shrink_to_dictionary();
            }
            assert_eq!(encoder_predictor.trace.unwrap().mismatch_count, 0);
            assert_eq!(
                decoder_predictor.prediction.dictionary_reset_position(),
                Some(398)
            );
        }
    }

    #[test]
    fn flush_reset_keeps_old_history_available_for_correction_recovery() {
        let mut first = repeated_segment();
        first.extend(b"!XYZ123".iter().copied().map(DeflateToken::Literal));
        let blocks = [
            huffman(first, false),
            empty_stored(),
            huffman(repeated_segment(), false),
            huffman(vec![DeflateToken::new_ref(7, 206)], true),
        ];
        let plain = plaintext(&blocks);
        assert_eq!(measure(&blocks, &plain, &params(), true).2, Some(206));
    }

    #[test]
    fn flush_rejects_malformed_limits_reset_tags_and_token_counts() {
        let blocks = [
            huffman(repeated_segment(), false),
            empty_stored(),
            huffman(repeated_segment(), true),
        ];
        let plain = plaintext(&blocks);
        let mut predictor = TokenPredictor::from_parameters(&params());
        predictor.begin_chunk(&blocks);
        let mut input = PreflateInput::new(&plain);
        let mut encoder = VerifyPredictionEncoder::default();
        for (index, block) in blocks.iter().enumerate() {
            predictor
                .predict_block(block, &mut encoder, &mut input, index + 1 == blocks.len())
                .unwrap();
        }
        let actions = encoder.actions();
        let fields: Vec<_> = actions
            .iter()
            .enumerate()
            .filter_map(|(index, action)| {
                matches!(
                    action,
                    CodecAction::Correction(CodecCorrection::UncompressBlockLenCorrection, _)
                )
                .then_some(index)
            })
            .collect();
        // First Huffman limit, second Huffman limit, and its reset flag.
        for (index, value) in [
            (fields[0], u32::MAX),
            (fields[0], 201),
            (fields[0], 1),
            (fields[3], 2),
        ] {
            let mut malformed = actions.clone();
            malformed[index] =
                CodecAction::Correction(CodecCorrection::UncompressBlockLenCorrection, value);
            let mut codec = VerifyPredictionDecoder::new(malformed);
            let mut decoder = TokenPredictor::from_parameters(&params());
            decoder.begin_chunk(&[]);
            let mut input = PreflateInput::new(&plain);
            assert!(
                blocks
                    .iter()
                    .any(|_| decoder.recreate_block(&mut codec, &mut input).is_err())
            );
        }
        let mut malformed = actions;
        let index = malformed
            .iter()
            .position(|action| {
                matches!(
                    action,
                    CodecAction::Correction(CodecCorrection::TokenCount, _)
                )
            })
            .unwrap();
        malformed[index] = CodecAction::Correction(CodecCorrection::TokenCount, u32::MAX);
        let mut codec = VerifyPredictionDecoder::new(malformed);
        assert!(
            TokenPredictor::from_parameters(&params())
                .recreate_block(&mut codec, &mut PreflateInput::new(&plain))
                .is_err()
        );
    }

    #[test]
    #[ignore = "optional local raw-stream measurement; prints only aggregate counts"]
    fn flush_private_aggregate_measurement() {
        let Some(path) = std::env::var_os("PREFLATE_FLUSH_INPUT") else {
            return;
        };
        let raw = std::fs::read(path).unwrap();
        let (contents, plain) =
            crate::deflate::deflate_reader::tests::parse_deflate_whole(&raw).unwrap();
        let params = {
            let mut canonical_configuration = zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(
                crate::hash_algorithm::HashAlgorithm::Zlib {
                    hash_mask: 16383,
                    hash_shift: 5,
                },
            );
            canonical_configuration.set_window_bits(15);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_nice_length(258);
            canonical_configuration.set_max_chain(32);
            canonical_configuration.set_short_match_cutoff(4076);
            canonical_configuration.set_matching_type(MatchingType::Lazy {
                max_lazy: 4,
                filtered_matching: false,
                behavior: LazyBehavior::Zlib { good_length: 8 },
            });
            canonical_configuration.max_token_count = 8191;
            canonical_configuration.block_type_strategy = BlockTypeStrategy::Mixed;
            canonical_configuration
        };
        let baseline = measure(&contents.blocks, &plain, &params, false);
        let improved = measure(&contents.blocks, &plain, &params, true);
        println!(
            "OPAQUE_FLUSH baseline_bytes={} baseline_mismatches={} bytes={} mismatches={} reset={}",
            baseline.0,
            baseline.1,
            improved.0,
            improved.1,
            improved.2.is_some()
        );
        assert!(improved.1 < baseline.1);
    }

    use crate::{
        estimator::test_support::{score_predictions, score_refinement},
        parameters::{BlockTypeStrategy, DictionaryAddPolicy, LazyBehavior, tests::MatchingType},
        preflate_input::PlainText,
    };

    pub(crate) fn zlib_level_1_params() -> ReconstructionParameters {
        use crate::{
            hash_algorithm::HashAlgorithm,
            parameters::{BlockTypeStrategy, DictionaryAddPolicy, PreflateStrategy},
        };

        {
            let mut canonical_configuration =
                crate::reconstruction_parameters::ReconstructionParameters {
                    max_token_count: 16383,
                    block_type_strategy: match BlockTypeStrategy::Dynamic {
                        crate::parameters::BlockTypeStrategy::Mixed => {
                            crate::parameters::BlockTypeStrategy::Dynamic
                        }
                        value => value,
                    },
                    behavior: crate::reconstruction_parameters::BehaviorSettings::NoDictionary {
                        strategy: crate::parameters::PreflateStrategy::HuffOnly,
                    },
                };
            canonical_configuration.set_hash_algorithm(HashAlgorithm::Zlib {
                hash_mask: 32767,
                hash_shift: 5,
            });
            canonical_configuration.set_window_bits(15);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddFirst(4));
            canonical_configuration.set_max_chain(4);
            canonical_configuration.set_nice_length(8);
            canonical_configuration.set_short_match_cutoff(32488);
            canonical_configuration.set_matching_type(MatchingType::Greedy);
            canonical_configuration.set_matches_to_start(false);
            canonical_configuration.set_strategy(PreflateStrategy::Default);
            canonical_configuration.set_full_window(false);
            canonical_configuration
        }
    }

    #[test]
    fn longer_prefix_resolves_a_table_hash_tie_to_the_memory_sized_zlib_hash() {
        use crate::{
            deflate::{
                deflate_reader::tests::parse_deflate_whole, deflate_token::DeflateHuffmanType,
                deflate_writer::DeflateWriter,
            },
            hash_algorithm::{HashAlgorithm, HashImplementation, ZlibRotatingHashFixed},
        };

        let expected = {
            let mut canonical_configuration = zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(HashAlgorithm::Zlib {
                hash_mask: 4095,
                hash_shift: 4,
            });
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_nice_length(128);
            canonical_configuration.set_max_chain(128);
            canonical_configuration.set_short_match_cutoff(4096);
            canonical_configuration.set_matching_type(MatchingType::Lazy {
                max_lazy: 16,
                filtered_matching: false,
                behavior: LazyBehavior::Zlib { good_length: 8 },
            });
            canonical_configuration.max_token_count = 2047;
            canonical_configuration
        };
        let baseline = {
            let mut canonical_configuration = expected;
            canonical_configuration.set_hash_algorithm(HashAlgorithm::RandomVector);
            canonical_configuration
        };
        let mut bytes = Vec::new();
        let mut random = 0x1234_5678u32;
        for _ in 0..1200 {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            bytes.push(random as u8);
        }
        let pattern: Vec<_> = (b'A'..=b'Z').cycle().take(89).collect();
        bytes.extend_from_slice(&pattern);
        let hash = ZlibRotatingHashFixed::<4, 4095>::default();
        let bucket = hash.get_hash(&pattern);
        let mut collisions = Vec::new();
        for first in 0..=255u32 {
            for second in 0..=255u32 {
                let third = bucket as u32 ^ ((first << 8) & 4095) ^ (second << 4);
                if third <= 255 && [first as u8, second as u8, third as u8] != pattern[..3] {
                    collisions.push([first as u8, second as u8, third as u8]);
                }
            }
        }
        for _ in 0..4 {
            for triple in collisions.iter().take(192) {
                bytes.extend_from_slice(triple);
            }
            bytes.extend_from_slice(&pattern);
        }
        for _ in 0..1200 {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            bytes.push(random as u8);
        }
        let plain = PlainText::new_with_data(bytes);
        let mut predictor = TokenPredictor::from_parameters(&expected);
        let mut input = PreflateInput::new(&plain);
        let mut writer = DeflateWriter::new();
        while input.remaining() != 0 {
            predictor
                .prediction
                .begin_decoded_huffman_block(&mut input, None, false)
                .unwrap();
            let mut tokens = Vec::new();
            while input.remaining() != 0 && tokens.len() < usize::from(expected.max_token_count) {
                let token = predictor
                    .prediction
                    .predict(&input, &TokenFrequency::default());
                predictor.prediction.accept_token(&token, token, &mut input);
                tokens.push(token);
            }
            predictor.prediction.finish_block(&mut input).unwrap();
            writer
                .encode_block(&DeflateTokenBlock {
                    block_type: DeflateTokenBlockType::Huffman {
                        tokens,
                        huffman_type: DeflateHuffmanType::Static,
                    },
                    last: input.remaining() == 0,
                })
                .unwrap();
        }
        writer.flush();
        let compressed = writer.detach_output();
        let (contents, decoded) = parse_deflate_whole(&compressed).unwrap();
        let score = |parameters: &ReconstructionParameters, limit| {
            score_predictions(
                &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                    *parameters,
                ),
                &contents.blocks,
                &decoded,
                limit,
                524288,
            )
        };
        assert_eq!(score(&baseline, 1024), (0, 1024));
        assert!(score(&baseline, 4096).0 >= 2);
        assert_eq!(score(&expected, 4096).0, 0);
        let info = crate::estimator::test_support::extract_preflate_info(&contents.blocks);
        assert_eq!(info.max_tokens_per_block, 2047);
        let selected = crate::estimator::test_support::refine_ambiguous_profile(
            baseline, &info, &contents, &decoded,
        );
        assert_eq!(selected, expected);
        let (record, plaintext) = crate::stream_processor::preflate_whole_deflate_stream(
            &compressed,
            &crate::PreflateConfig::default(),
        )
        .unwrap();
        assert_eq!(
            crate::stream_processor::recreate_whole_deflate_stream(
                plaintext.text(),
                &record.corrections
            )
            .unwrap(),
            compressed,
        );
    }

    #[test]
    fn longer_prefix_resolves_a_filtered_zlib_hash_alias() {
        use crate::{
            deflate::{
                deflate_reader::tests::parse_deflate_whole, deflate_token::DeflateHuffmanType,
                deflate_writer::DeflateWriter,
            },
            hash_algorithm::HashAlgorithm,
        };

        let expected = {
            let mut canonical_configuration = zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(crate::compressors::zlib::DEFAULT_HASH);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_nice_length(128);
            canonical_configuration.set_max_chain(128);
            canonical_configuration.set_short_match_cutoff(0);
            canonical_configuration.set_matching_type(MatchingType::Lazy {
                max_lazy: 16,
                filtered_matching: true,
                behavior: LazyBehavior::Zlib { good_length: 8 },
            });
            canonical_configuration.max_token_count = 8191;
            canonical_configuration
        };
        let baseline = {
            let mut canonical_configuration = expected;
            canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4Fast);
            canonical_configuration.set_max_chain(126);
            canonical_configuration.set_matching_type(MatchingType::Lazy {
                max_lazy: 16,
                filtered_matching: false,
                behavior: LazyBehavior::Zlib { good_length: 8 },
            });
            canonical_configuration
        };
        let mut bytes = Vec::new();
        let mut random = 0x1234_5678u32;
        for _ in 0..1200 {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            bytes.push(random as u8);
        }
        for index in 0..10000u32 {
            bytes.extend_from_slice(b"abcde");
            bytes.extend_from_slice(&index.to_le_bytes()[..3]);
            bytes.push(b'#');
        }
        let plain = PlainText::new_with_data(bytes);
        let mut predictor = TokenPredictor::from_parameters(&expected);
        let mut input = PreflateInput::new(&plain);
        let mut writer = DeflateWriter::new();
        while input.remaining() != 0 {
            predictor
                .prediction
                .begin_decoded_huffman_block(&mut input, None, false)
                .unwrap();
            let mut tokens = Vec::new();
            while input.remaining() != 0 && tokens.len() < usize::from(expected.max_token_count) {
                let token = predictor
                    .prediction
                    .predict(&input, &TokenFrequency::default());
                predictor.prediction.accept_token(&token, token, &mut input);
                tokens.push(token);
            }
            predictor.prediction.finish_block(&mut input).unwrap();
            writer
                .encode_block(&DeflateTokenBlock {
                    block_type: DeflateTokenBlockType::Huffman {
                        tokens,
                        huffman_type: DeflateHuffmanType::Static,
                    },
                    last: input.remaining() == 0,
                })
                .unwrap();
        }
        writer.flush();
        let compressed = writer.detach_output();
        let (contents, decoded) = parse_deflate_whole(&compressed).unwrap();
        let score = |parameters: &ReconstructionParameters, limit| {
            score_predictions(
                &mut crate::prediction_state::PredictionState::from_reconstruction_parameters(
                    *parameters,
                ),
                &contents.blocks,
                &decoded,
                limit,
                524288,
            )
        };
        assert_eq!(score(&baseline, 1024), (0, 1024));
        assert!(score(&baseline, 4096).0 >= 2);
        assert_eq!(score(&expected, 4096), (0, 4096));
        let info = crate::estimator::test_support::extract_preflate_info(&contents.blocks);
        assert!(info.min_len >= crate::compressors::zlib::FILTERED_MIN_MATCH_LENGTH);
        assert_eq!(
            info.max_tokens_per_block,
            u32::from(expected.max_token_count)
        );
        assert_eq!(
            crate::estimator::test_support::refine_ambiguous_profile(
                baseline, &info, &contents, &decoded
            ),
            expected,
        );
        let (record, plaintext) = crate::stream_processor::preflate_whole_deflate_stream(
            &compressed,
            &crate::PreflateConfig::default(),
        )
        .unwrap();
        assert_eq!(
            crate::stream_processor::recreate_whole_deflate_stream(
                plaintext.text(),
                &record.corrections,
            )
            .unwrap(),
            compressed,
        );
    }

    /// test predictor with a standard zlib match that doesn't need any correction
    #[test]
    fn test_predictor_block_perfect() {
        use crate::{
            deflate::deflate_reader, preflate_input::PreflateInput,
            statistical_codec::tests::AssertDefaultOnlyEncoder,
        };

        let compressed_data = crate::utils::read_file("compressed_zlib_level1.deflate");

        let (contents, plain_text) =
            deflate_reader::tests::parse_deflate_whole(&compressed_data).unwrap();

        let mut predictor = TokenPredictor::from_parameters(&zlib_level_1_params());

        // this codec doesn't do anything other than say default value for everything
        let mut codec = AssertDefaultOnlyEncoder {};

        let mut input = PreflateInput::new(&plain_text);

        for i in 0..contents.blocks.len() {
            predictor
                .predict_block(
                    &contents.blocks[i],
                    &mut codec,
                    &mut input,
                    i == contents.blocks.len() - 1,
                )
                .unwrap();
        }
    }

    /// test predictor only calleing PredictToken (excludes block prediction)
    #[test]
    fn test_predictor_token_only() {
        use crate::{deflate::deflate_reader, preflate_input::PreflateInput};

        let compressed_data = crate::utils::read_file("compressed_zlib_level1.deflate");

        let (contents, plain_text) =
            deflate_reader::tests::parse_deflate_whole(&compressed_data).unwrap();

        let mut predictor = TokenPredictor::from_parameters(&zlib_level_1_params());

        let mut input = PreflateInput::new(&plain_text);

        for i in 0..contents.blocks.len() {
            let b = &contents.blocks[i];
            match &b.block_type {
                DeflateTokenBlockType::Huffman { tokens, .. } => {
                    for token in tokens {
                        let predicted = predictor
                            .prediction
                            .predict(&input, &TokenFrequency::default());
                        assert_eq!(predicted, *token);
                        predictor
                            .prediction
                            .accept_token(token, predicted, &mut input);
                    }
                }
                _ => {
                    panic!("unexpected block type")
                }
            }
        }
    }

    /// test building plain_text incrementally
    #[test]
    fn test_predictor_incremental() {
        use crate::{
            deflate::deflate_reader,
            preflate_input::{PlainText, PreflateInput},
        };

        let compressed_data = crate::utils::read_file("compressed_zlib_level1.deflate");

        let (contents, plain_text_original) =
            deflate_reader::tests::parse_deflate_whole(&compressed_data).unwrap();

        let mut predictor = TokenPredictor::from_parameters(&zlib_level_1_params());

        let mut plain_text = PlainText::new();

        let mut start_pos = 0;

        for i in 0..contents.blocks.len() {
            // build th plain text from the block
            println!("block {}, plaintext {:?}", i, plain_text);
            let b = &contents.blocks[i];
            match &b.block_type {
                DeflateTokenBlockType::Huffman { tokens, .. } => {
                    for token in tokens {
                        match *token {
                            DeflateToken::Literal(l) => {
                                plain_text.append(&[l]);
                            }

                            DeflateToken::Reference(r) => {
                                plain_text.append_reference(r.dist(), r.len()).unwrap();
                            }
                        }
                    }
                    crate::utils::assert_eq_array(
                        plain_text.prefix(),
                        &plain_text_original.text()
                            [start_pos - plain_text.prefix().len()..start_pos],
                    );
                    crate::utils::assert_eq_array(
                        plain_text.text(),
                        &plain_text_original.text()[start_pos..start_pos + plain_text.len()],
                    );
                    let mut input = PreflateInput::new(&plain_text);
                    if !plain_text.prefix().is_empty() {
                        predictor.add_missing_previous_hash(&input);
                    }
                    for (i, token) in tokens.iter().enumerate() {
                        let predicted = predictor
                            .prediction
                            .predict(&input, &TokenFrequency::default());
                        assert_eq!(
                            predicted,
                            *token,
                            "token {} input {}",
                            i,
                            input.pos() as usize - start_pos
                        );
                        predictor
                            .prediction
                            .accept_token(token, predicted, &mut input);
                    }
                }
                _ => panic!("unexpected block type"),
            }
            start_pos += plain_text.len();
            plain_text.shrink_to_dictionary();
        }
    }

    impl TokenPredictor {
        pub(crate) fn track_short_match_distance(&mut self) {
            self.prediction.track_short_match_distance();
        }

        pub(crate) fn short_match_distance_bounds(&self) -> Option<(u32, u32)> {
            self.prediction.short_match_distance_bounds()
        }
    }
}
