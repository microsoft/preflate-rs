/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::{
    bit_helper::DebugHash,
    block_predictor::BlockPrediction,
    deflate::{
        deflate_constants::MIN_MATCH,
        deflate_token::{
            BT_DYNAMICHUFF, BT_STATICHUFF, BT_STORED, DeflateHuffmanType, DeflateToken,
            DeflateTokenBlock, DeflateTokenBlockType, DeflateTokenReference, TokenFrequency,
        },
        huffman_calc::HufftreeBitCalc,
    },
    estimator::{
        add_policy_estimator::DictionaryAddPolicy,
        preflate_parameter_estimator::{BlockTypeStrategy, TokenPredictorParameters},
        preflate_parse_config::MatchingType,
    },
    hash_chain_holder::{HashChainHolder, MatchResult, new_hash_chain_holder},
    models::{self, MatchPrediction, libdeflate, miniz, zlib},
    preflate_error::{AddContext, ExitCode, Result, err_exit_code},
    preflate_input::{PlainText, PreflateInput},
    statistical_codec::{CodecCorrection, PredictionDecoder, PredictionEncoder},
    tree_predictor::{predict_tree_for_block, recreate_tree_for_block},
};

#[cfg(test)]
use crate::estimator::preflate_parse_config::LazyBehavior;

const VERIFY: bool = false;

// Capture the initial prediction, before correction recovery can hide model mismatches.
#[cfg(any(test, feature = "diagnostics"))]
#[derive(Debug)]
pub struct TokenPredictionTrace {
    pub stage: &'static str,
    pub block_profile: &'static str,
    pub parameters: Option<TokenPredictorParameters>,
    pub token_count: usize,
    pub mismatch_count: usize,
    pub first_mismatches: Vec<(u32, DeflateToken, DeflateToken)>,
    pub(crate) max_mismatches: usize,
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
        }
    }
}

pub struct TokenPredictor {
    state: Box<dyn HashChainHolder>,
    params: TokenPredictorParameters,
    pending_reference: Option<DeflateTokenReference>,
    pending_literals: u8,
    min_match_length: u32,
    lazy_minimum: Option<libdeflate::LazyMinimum>,
    filtered_matching: bool,
    max_token_count: u32,
    block_prediction: BlockPrediction,
    #[cfg(any(test, feature = "diagnostics"))]
    pub(crate) trace: Option<TokenPredictionTrace>,
    /// Inclusive cutoff interval preserving all observed three-byte decisions.
    pub(crate) short_match_distance_bounds: Option<(u32, u32)>,
}

impl std::fmt::Debug for TokenPredictor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenPredictor")
            .field("params", &self.params)
            .field("pending_reference", &self.pending_reference)
            .field("max_token_count", &self.max_token_count)
            .finish()
    }
}

impl TokenPredictor {
    pub(crate) fn enable_parameter_normalization(
        &mut self,
        compressed_size: usize,
        complete: bool,
    ) {
        // A partial first chunk cannot certify the history needed by later chunks.
        if complete && compressed_size < 1024 {
            self.state.enable_window_normalization();
            self.short_match_distance_bounds = Some((0, self.params.max_dist_3_matches.max(32768)));
        }
    }

    pub(crate) fn reconstruction_parameters(&self) -> TokenPredictorParameters {
        TokenPredictorParameters {
            window_bits: self
                .state
                .normalized_window_bits()
                .unwrap_or(self.params.window_bits),
            max_dist_3_matches: self
                .short_match_distance_bounds
                .map_or(self.params.max_dist_3_matches, |bounds| {
                    self.params.canonical_short_match_cutoff(bounds)
                }),
            ..self.params
        }
    }

    pub fn new(params: &TokenPredictorParameters) -> Self {
        let predictor_state = new_hash_chain_holder(params);

        Self {
            state: predictor_state,
            params: *params,
            pending_reference: None,
            pending_literals: 0,
            min_match_length: MIN_MATCH,
            lazy_minimum: None,
            filtered_matching: true,
            max_token_count: params.max_token_count.into(),
            block_prediction: {
                let mut prediction = BlockPrediction::default();
                prediction.begin_chunk(&[]);
                prediction
            },
            #[cfg(any(test, feature = "diagnostics"))]
            trace: None,
            short_match_distance_bounds: None,
        }
    }

    pub(crate) fn new_legacy(params: &TokenPredictorParameters) -> Self {
        let mut predictor = Self::new(params);
        predictor.filtered_matching = false;
        predictor.block_prediction.legacy = true;
        predictor
    }

    pub(crate) fn begin_chunk(&mut self, blocks: &[DeflateTokenBlock]) -> usize {
        let tail_length = self.block_prediction.begin_chunk(blocks);
        #[cfg(any(test, feature = "diagnostics"))]
        if let Some(trace) = &mut self.trace {
            trace.block_profile = self.block_prediction.profile_name();
        }
        tail_length
    }

    pub(crate) fn predict_end_of_chunk(&self, input: &PreflateInput) -> bool {
        self.block_prediction.end_of_chunk(input.remaining())
    }

    fn encode_block_type(
        &mut self,
        codec: &mut impl PredictionEncoder,
        actual: u32,
        input: &PreflateInput,
    ) {
        let correction =
            self.block_prediction
                .encode_type(actual, self.predict_block_type(), input.remaining());
        codec.encode_correction(CodecCorrection::BlockTypeCorrection, correction);
    }

    pub fn checksum(&self) -> DebugHash {
        assert!(VERIFY);
        let mut c = DebugHash::default();
        self.state.checksum(&mut c);
        c
    }

    /// in the case where we are processing a continuation, we need to
    /// add the missing hashes of the entries that were at the end of the
    /// input so it can be found.
    pub fn add_missing_previous_hash(&mut self, input: &PreflateInput) {
        self.state.add_missing_previous_hash(input);
    }

    pub fn predict_block_type(&self) -> u32 {
        match self.params.block_type_strategy {
            BlockTypeStrategy::Dynamic => BT_DYNAMICHUFF,
            BlockTypeStrategy::Mixed => BT_DYNAMICHUFF,
            BlockTypeStrategy::Static => BT_STATICHUFF,
            BlockTypeStrategy::Uncompressed => BT_STORED,
        }
    }

    fn start_block(&mut self, input: &PreflateInput) {
        // Encoding and reconstruction must reset lookahead and infer the same minimum
        // at the same boundary, or their later correction decisions will diverge.
        self.pending_reference = None;
        self.pending_literals = 0;
        self.min_match_length = models::block_minimum_match_length(
            &self.params,
            self.filtered_matching,
            input.cur_chars(0),
        );
        self.lazy_minimum = (self.filtered_matching
            && matches!(
                self.params.matching_type,
                MatchingType::LibdeflateLazy { .. }
            ))
        .then(|| libdeflate::LazyMinimum::new(input.pos(), input.remaining()));
    }

    #[inline]
    fn refresh_minimum(&mut self, input: &PreflateInput, frequency: &TokenFrequency) {
        if let Some(minimum) = &mut self.lazy_minimum
            && self.pending_reference.is_none()
            && self.pending_literals == 0
            && let Some(length) = minimum.update(
                input.pos(),
                input.total_length(),
                &frequency.literal_codes[..256],
                self.params.max_chain.saturating_sub(1),
            )
        {
            self.min_match_length = length;
        }
    }

    pub(crate) fn score_predictions(
        &mut self,
        blocks: &[DeflateTokenBlock],
        plain: &PlainText,
        max_tokens: usize,
        max_bytes: u32,
    ) -> (usize, usize) {
        let mut input = PreflateInput::new(plain);
        let mut count = 0;
        let mut mismatches = 0;
        for block in blocks {
            self.start_block(&input);
            match &block.block_type {
                DeflateTokenBlockType::Stored { uncompressed } => {
                    for _ in uncompressed {
                        if input.pos() >= max_bytes || count >= max_tokens {
                            return (mismatches, count);
                        }
                        self.state.update_hash(1, &input);
                        input.advance(1);
                    }
                }
                DeflateTokenBlockType::Huffman { tokens, .. } => {
                    let mut frequency = TokenFrequency::default();
                    for actual in tokens {
                        if input.pos() >= max_bytes || count >= max_tokens {
                            return (mismatches, count);
                        }
                        self.refresh_minimum(&input, &frequency);
                        let predicted = self.predict_token(&input);
                        mismatches += usize::from(*actual != predicted);
                        count += 1;
                        if matches!(actual, DeflateToken::Reference(_))
                            && matches!(predicted, DeflateToken::Literal(_))
                        {
                            // Correction recovery discards the saved lookahead choice.
                            self.pending_reference = None;
                            self.pending_literals = 0;
                        }
                        self.commit_token(actual, &mut input);
                        if self.lazy_minimum.is_some() {
                            frequency.commit_token(actual);
                        }
                    }
                }
            }
        }
        (mismatches, count)
    }

    #[inline(never)] // don't inline so we get better call stacks
    pub fn predict_block<D: PredictionEncoder>(
        &mut self,
        block: &DeflateTokenBlock,
        codec: &mut D,
        input: &mut PreflateInput,
        final_block_in_chunk: bool,
    ) -> Result<()> {
        self.start_block(input);

        codec.encode_verify_state("blocktypestart", 0);
        let started_empty = input.remaining() == 0;

        let tokens;
        let huffman_encoding;

        match &block.block_type {
            DeflateTokenBlockType::Stored { uncompressed } => {
                self.encode_block_type(codec, BT_STORED, input);

                codec.encode_correction_diff(
                    CodecCorrection::UncompressBlockLenCorrection,
                    uncompressed.len() as u32,
                    self.block_prediction.stored_length(input.remaining()),
                );

                for _i in 0..uncompressed.len() {
                    self.state.update_hash(1, &input);
                    input.advance(1);
                }

                self.block_prediction
                    .record_stored_length(uncompressed.len() as u32);
                self.block_prediction.finish_block(started_empty);
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
                match huffman_type {
                    DeflateHuffmanType::Static { .. } => {
                        self.encode_block_type(codec, BT_STATICHUFF, input);
                        huffman_encoding = None;
                    }
                    DeflateHuffmanType::Dynamic {
                        huffman_encoding: h,
                        ..
                    } => {
                        self.encode_block_type(codec, BT_DYNAMICHUFF, input);
                        huffman_encoding = Some(h);
                    }
                }

                tokens = t
            }
        }

        // if the block ends at an unexpected point, or it contains more tokens
        // than expected, we will need to encode the block size
        let predicted_count =
            self.block_prediction
                .token_count(input.remaining(), self.max_token_count) as usize;
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

        for i in 0..tokens.len() {
            let target_token = &tokens[i];

            codec.encode_verify_state(
                "token",
                if VERIFY {
                    self.checksum().hash()
                } else {
                    i as u64
                },
            );

            /*
            if i == 7718
                && *target_token
                    == PreflateToken::Reference(PreflateTokenReference::new(7, 17, false))
            {
                println!("target = {:?}", target_token)
            }*/

            self.refresh_minimum(input, &freq);
            let predicted_token = self.predict_token(input);

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
            let hash = self.state.calculate_hash();
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
                            self.repredict_reference(Some(*target_ref), input)
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
                        let rematch =
                            self.state
                                .calculate_hops(target_ref, input)
                                .with_context(|| {
                                    format!(
                                        "calculate_hops p={:?}, t={:?}",
                                        predicted_ref, target_ref
                                    )
                                })?;
                        codec.encode_correction(
                            CodecCorrection::DistAfterLenCorrection,
                            rematch - 1,
                        );
                    } else if target_ref.dist() != predicted_ref.dist() {
                        let rematch =
                            self.state
                                .calculate_hops(target_ref, input)
                                .with_context(|| {
                                    format!(
                                        "calculate_hops p={:?}, t={:?}",
                                        predicted_ref, target_ref
                                    )
                                })?;
                        codec.encode_correction(CodecCorrection::DistOnlyCorrection, rematch);
                    } else {
                        codec.encode_correction(CodecCorrection::DistOnlyCorrection, 0);
                    }
                }
            }

            self.commit_token(target_token, input);
            freq.commit_token(target_token);
        }

        if let Some(huffman_encoding) = huffman_encoding {
            predict_tree_for_block(huffman_encoding, &freq, codec, HufftreeBitCalc::Zlib)?;
        }

        self.block_prediction.finish_block(started_empty);
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
        self.start_block(input);

        codec.decode_verify_state("blocktypestart", 0);
        let started_empty = input.remaining() == 0;

        let bt = self.block_prediction.decode_type(
            codec.decode_correction(CodecCorrection::BlockTypeCorrection),
            self.predict_block_type(),
            input.remaining(),
        )?;

        match bt {
            BT_STORED => {
                let uncompressed_len = codec.decode_correction_diff(
                    CodecCorrection::UncompressBlockLenCorrection,
                    self.block_prediction.stored_length(input.remaining()),
                );

                if uncompressed_len > 65535 || uncompressed_len > input.remaining() {
                    return err_exit_code(ExitCode::InvalidDeflate, "Invalid stored block len");
                }

                let mut uncompressed = Vec::with_capacity(uncompressed_len as usize);

                for _i in 0..uncompressed_len {
                    uncompressed.push(input.cur_char(0));
                    self.state.update_hash(1, &input);
                    input.advance(1);
                }

                self.block_prediction.record_stored_length(uncompressed_len);
                self.block_prediction.finish_block(started_empty);
                let last = codec.decode_correction_bool(
                    CodecCorrection::Last,
                    self.predict_end_of_chunk(input),
                );

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

        let mut blocksize = codec.decode_correction(CodecCorrection::TokenCount);
        if blocksize == 0 {
            blocksize = self
                .block_prediction
                .token_count(input.remaining(), self.max_token_count);
        } else {
            blocksize -= 1;
        }

        // rust aborts on OOM, so check before we allocate to avoid crashing the process
        let mut tokens = Vec::new();
        if tokens.try_reserve_exact(blocksize as usize).is_err() {
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
            self.refresh_minimum(input, &freq);
            match self.predict_token(input) {
                DeflateToken::Literal(l) => {
                    let not_ok =
                        codec.decode_misprediction(CodecCorrection::LiteralPredictionWrong);
                    if !not_ok {
                        self.commit_token(&DeflateToken::Literal(l), input);
                        freq.commit_token(&DeflateToken::Literal(l));

                        tokens.push(DeflateToken::Literal(l));
                        continue;
                    }

                    predicted_ref = self.repredict_reference(None, input).with_context(|| {
                        format!("repredict_reference token_count={:?}", tokens.len())
                    })?;
                }
                DeflateToken::Reference(r) => {
                    let not_ok =
                        codec.decode_misprediction(CodecCorrection::ReferencePredictionWrong);
                    if not_ok {
                        let c = input.cur_char(0);
                        self.commit_token(&DeflateToken::Literal(c), input);
                        freq.commit_token(&DeflateToken::Literal(c));

                        tokens.push(DeflateToken::Literal(c));
                        continue;
                    }

                    predicted_ref = r;
                }
            }

            let new_len =
                codec.decode_correction_diff(CodecCorrection::LenCorrection, predicted_ref.len());

            if new_len != predicted_ref.len() {
                let hops = codec.decode_correction(CodecCorrection::DistAfterLenCorrection) + 1;

                predicted_ref = DeflateTokenReference::new(
                    new_len,
                    self.state
                        .hop_match(new_len, hops, input)
                        .with_context(|| format!("hop_match l={} {:?}", new_len, predicted_ref))?,
                );
            } else {
                let hops = codec.decode_correction(CodecCorrection::DistOnlyCorrection);
                if hops != 0 {
                    let new_dist = self
                        .state
                        .hop_match(predicted_ref.len(), hops, input)
                        .with_context(|| format!("recalculate_distance token {}", tokens.len()))?;
                    predicted_ref = DeflateTokenReference::new(new_len, new_dist);
                }
            }

            self.commit_token(&DeflateToken::Reference(predicted_ref), input);
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

        self.block_prediction.finish_block(started_empty);
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

    #[inline(always)]
    fn predict_token(&mut self, input: &PreflateInput) -> DeflateToken {
        if self.pending_literals > 0 {
            self.pending_literals -= 1;
            return DeflateToken::Literal(input.cur_char(0));
        }
        if input.bytes_before() == 0
            || input.remaining() < MIN_MATCH
            || (self.params.add_policy == DictionaryAddPolicy::AddFirstExcept4kBoundary
                && miniz::cross_4k_boundary(input.pos()))
        {
            return DeflateToken::Literal(input.cur_char(0));
        }

        let m = if let Some(pending) = self.pending_reference {
            MatchResult::Success(pending)
        } else {
            let previous =
                libdeflate::initial_search_length(self.params.matching_type, self.min_match_length);
            self.state
                .match_token_0(previous, self.params.max_chain, input)
        };

        self.pending_reference = None;

        if let MatchResult::Success(match_token) = m {
            if match_token.len() < self.min_match_length {
                return DeflateToken::Literal(input.cur_char(0));
            }

            // match is too small and far way to be worth encoding as a distance/length pair.
            if match_token.len() == 3
                && let Some((lower, upper)) = &mut self.short_match_distance_bounds
            {
                if match_token.dist() <= self.params.max_dist_3_matches {
                    *lower = (*lower).max(match_token.dist());
                } else {
                    *upper = (*upper).min(match_token.dist() - 1);
                }
            }
            if match_token.len() == 3
                && match_token.dist() > u32::from(self.params.max_dist_3_matches)
            {
                return DeflateToken::Literal(input.cur_char(0));
            }

            let prediction = match self.params.matching_type {
                MatchingType::MiniZ { greedy, .. } => miniz::predict_token(
                    input,
                    self.state.as_ref(),
                    match_token,
                    greedy,
                    self.params.max_chain,
                ),
                MatchingType::LibdeflateLazy { two_positions } => libdeflate::predict_lazy(
                    input,
                    self.state.as_ref(),
                    match_token,
                    self.params.nice_length,
                    self.params.max_chain,
                    two_positions,
                ),
                MatchingType::Lazy {
                    max_lazy, behavior, ..
                } => zlib::predict_lazy(
                    input,
                    self.state.as_ref(),
                    match_token,
                    max_lazy,
                    behavior,
                    self.params.max_chain,
                ),
                _ => MatchPrediction::Reference,
            };
            match prediction {
                MatchPrediction::Reference => DeflateToken::Reference(match_token),
                MatchPrediction::Literal {
                    pending_reference,
                    pending_literals,
                } => {
                    self.pending_reference = pending_reference;
                    self.pending_literals = pending_literals;
                    DeflateToken::Literal(input.cur_char(0))
                }
            }
        } else {
            DeflateToken::Literal(input.cur_char(0))
        }
    }

    /// When the predicted token was a literal, but the actual token was a reference, try again
    /// to find a match for the reference.
    fn repredict_reference(
        &mut self,
        _dist_match: Option<DeflateTokenReference>,
        input: &mut PreflateInput,
    ) -> Result<DeflateTokenReference> {
        if input.bytes_before() == 0 || input.remaining() < MIN_MATCH {
            return err_exit_code(
                ExitCode::PredictionFailure,
                "Not enough space left to find a reference",
            );
        }

        /*
        if let Some(x) = dist_match {
            if x.dist() == 32653 {
                println!("dist_match = {:?}", dist_match);
            }
        }
        */

        let match_token = self.state.match_token_0(0, self.params.max_chain, input);

        // Re-prediction replaces any saved lookahead choice, including lazy2's extra literal.
        self.pending_reference = None;
        self.pending_literals = 0;

        if let MatchResult::Success(m) = match_token {
            if m.len() >= MIN_MATCH {
                return Ok(m);
            }
        }

        // If we didn't find a match, try again with a larger chain
        let match_token = self.state.match_token_0(0, 4096, input);

        if let MatchResult::Success(m) = match_token {
            if m.len() >= MIN_MATCH {
                return Ok(m);
            }
        }

        err_exit_code(
            ExitCode::PredictionFailure,
            format!("Didnt find a match {:?}", match_token).as_str(),
        )
    }

    fn commit_token(&mut self, token: &DeflateToken, input: &mut PreflateInput) {
        match token {
            DeflateToken::Literal(_) => {
                self.state.update_hash(1, input);
                input.advance(1);
            }
            DeflateToken::Reference(t) => {
                self.state.update_hash(t.len(), input);
                input.advance(t.len());
            }
        }
    }
}

// A block's alphabet estimate must not leak into the next block.
// Verify boundary resets change the minimum and honor the short remaining-input cutoff.
#[test]
fn libdeflate_greedy_recomputes_minimum_at_block_boundaries() {
    use crate::preflate_input::PlainText;
    let mut bytes: Vec<_> = (0..4096).map(|i| i as u8).collect();
    bytes.extend([b'a'; 512]);
    let plain = PlainText::new_with_data(bytes);
    let mut input = PreflateInput::new(&plain);
    let params = TokenPredictorParameters {
        matching_type: MatchingType::LibdeflateGreedy,
        max_chain: 17,
        ..zlib_level_1_params()
    };
    let mut predictor = TokenPredictor::new(&params);
    predictor.start_block(&input);
    assert_eq!(predictor.min_match_length, 3);
    input.advance(4096);
    predictor.start_block(&input);
    assert_eq!(predictor.min_match_length, 9);
    input.advance(1);
    predictor.start_block(&input);
    assert_eq!(predictor.min_match_length, 3);
}

#[test]
fn libdeflate_lazy_refreshes_minimum_only_for_fresh_searches() {
    use crate::preflate_input::PlainText;

    for two_positions in [false, true] {
        let mut bytes: Vec<_> = (0..4096).map(|i| i as u8).collect();
        bytes.extend([b'a'; 30000]);
        let plain = PlainText::new_with_data(bytes);
        let mut input = PreflateInput::new(&plain);
        let params = TokenPredictorParameters {
            matching_type: MatchingType::LibdeflateLazy { two_positions },
            max_chain: 101,
            ..zlib_level_1_params()
        };
        let mut predictor = TokenPredictor::new(&params);
        predictor.start_block(&input);
        assert_eq!(predictor.min_match_length, 3);
        let mut frequency = TokenFrequency::default();
        frequency.literal_codes[usize::from(b'a')] = 1024;
        input.advance(10000);
        predictor.pending_reference = Some(DeflateTokenReference::new(8, 1));
        predictor.refresh_minimum(&input, &frequency);
        assert_eq!(predictor.min_match_length, 3);
        predictor.pending_reference = None;
        predictor.pending_literals = 1;
        predictor.refresh_minimum(&input, &frequency);
        assert_eq!(predictor.min_match_length, 3);
        predictor.pending_literals = 0;
        predictor.refresh_minimum(&input, &frequency);
        assert_eq!(predictor.min_match_length, 9);

        input.advance(10000);
        frequency.literal_codes[..256].fill(2);
        predictor.refresh_minimum(&input, &frequency);
        assert_eq!(predictor.min_match_length, 3);
        predictor.start_block(&input);
        assert_eq!(predictor.min_match_length, 9);
        assert_eq!(
            predictor.lazy_minimum.as_mut().unwrap().update(
                input.pos(),
                input.total_length(),
                &frequency.literal_codes[..256],
                100,
            ),
            None
        );
        input.advance(input.remaining() - 511);
        predictor.start_block(&input);
        assert_eq!(predictor.min_match_length, 3);
    }
}

// Extracting miniz's parser decisions must preserve its window exclusion and deferred match.
// Verify zero-slot rejection, greedy emission and lazy pending-reference consumption.
#[test]
fn miniz_token_decisions_preserve_lazy_state_and_zero_slot_exclusion() {
    use crate::preflate_input::PlainText;

    for greedy in [true, false] {
        let mut bytes = b"@abcXbcdEFY".to_vec();
        let position = bytes.len() as u32;
        bytes.extend_from_slice(b"abcdEFQ");
        let plain = PlainText::new_with_data(bytes);
        let mut input = PreflateInput::new(&plain);
        let params = TokenPredictorParameters {
            matching_type: MatchingType::MiniZ {
                max_probes: 16,
                greedy,
            },
            add_policy: DictionaryAddPolicy::AddAll,
            max_chain: 18,
            ..zlib_level_1_params()
        };
        let mut predictor = TokenPredictor::new(&params);
        while input.pos() < position {
            predictor.commit_token(&DeflateToken::Literal(input.cur_char(0)), &mut input);
        }
        assert!(matches!(
            miniz::predict_token(
                &input,
                predictor.state.as_ref(),
                DeflateTokenReference::new(3, position),
                greedy,
                params.max_chain,
            ),
            MatchPrediction::Literal {
                pending_reference: None,
                pending_literals: 0
            }
        ));
        assert_eq!(predictor.pending_reference, None);
        let first = predictor.predict_token(&input);
        if greedy {
            assert_eq!(first, DeflateToken::new_ref(3, position - 1));
            assert_eq!(predictor.pending_reference, None);
        } else {
            assert_eq!(first, DeflateToken::Literal(b'a'));
            let next = DeflateTokenReference::new(5, position - 4);
            assert_eq!(predictor.pending_reference, Some(next));
            predictor.commit_token(&first, &mut input);
            assert_eq!(
                predictor.predict_token(&input),
                DeflateToken::Reference(next)
            );
            assert_eq!(predictor.pending_reference, None);
        }
    }
}

#[test]
fn lazy_behavior_controls_lookahead_budget_and_reference_reuse() {
    let mut text = b"@bcdefgQ#abcdX#bcdefY#".to_vec();
    let position = text.len() as u32;
    text.extend_from_slice(b"abcdefgZ");
    let plain = PlainText::new_with_data(text);
    for (behavior, expected, reuse) in [
        (
            LazyBehavior::Zlib { good_length: 4 },
            DeflateTokenReference::new(5, 8),
            true,
        ),
        (
            LazyBehavior::Zlib { good_length: 5 },
            DeflateTokenReference::new(6, 22),
            true,
        ),
        (
            LazyBehavior::RecomputeAfterLiteral,
            DeflateTokenReference::new(6, 22),
            false,
        ),
    ] {
        let params = TokenPredictorParameters {
            matching_type: MatchingType::Lazy {
                max_lazy: 16,
                filtered_matching: false,
                behavior,
            },
            add_policy: DictionaryAddPolicy::AddAll,
            nice_length: 258,
            max_chain: 4,
            ..zlib_level_1_params()
        };
        let mut predictor = TokenPredictor::new(&params);
        let mut input = PreflateInput::new(&plain);
        while input.pos() < position {
            predictor.commit_token(&DeflateToken::Literal(input.cur_char(0)), &mut input);
        }
        let first = predictor.predict_token(&input);
        assert_eq!(first, DeflateToken::Literal(b'a'), "{behavior:?}");
        assert_eq!(
            predictor.pending_reference,
            reuse.then_some(expected),
            "{behavior:?}"
        );
        predictor.commit_token(&first, &mut input);
        assert_eq!(
            predictor.predict_token(&input),
            DeflateToken::Reference(expected),
            "{behavior:?}"
        );
        assert_eq!(predictor.pending_reference, None);
    }
}

// Lazy2 must defer two literals without leaving stale choices during correction recovery.
// Verify one/two-position saved matches and re-prediction clearing the pending state.
#[test]
fn libdeflate_lazy_models_saved_matches_and_two_literals() {
    use crate::{hash_algorithm::HashAlgorithm, preflate_input::PlainText};
    for two_positions in [false, true] {
        let mut bytes = b"@abcX".to_vec();
        bytes.extend([b'Z'; 128]);
        bytes.extend_from_slice(if two_positions { b"cdEFGY" } else { b"bcdY" });
        let position = bytes.len() as u32;
        bytes.extend_from_slice(if two_positions { b"abcdEFGQ" } else { b"abcdQ" });
        let plain = PlainText::new_with_data(bytes);
        let mut input = PreflateInput::new(&plain);
        let params = TokenPredictorParameters {
            matching_type: MatchingType::LibdeflateLazy { two_positions },
            hash_algorithm: HashAlgorithm::Libdeflate4,
            add_policy: DictionaryAddPolicy::AddAll,
            nice_length: 258,
            max_chain: 301,
            ..zlib_level_1_params()
        };
        let mut predictor = TokenPredictor::new(&params);
        while input.pos() < position {
            predictor.commit_token(&DeflateToken::Literal(input.cur_char(0)), &mut input);
        }
        let first = predictor.predict_token(&input);
        assert_eq!(first, DeflateToken::Literal(b'a'));
        if two_positions {
            assert_eq!(predictor.pending_literals, 1);
            assert_eq!(
                predictor
                    .repredict_reference(None, &mut input)
                    .unwrap()
                    .len(),
                3
            );
            assert_eq!(predictor.pending_literals, 0);
            assert_eq!(predictor.pending_reference, None);
            assert_eq!(predictor.predict_token(&input), first);
        }
        predictor.commit_token(&first, &mut input);
        if two_positions {
            let second = predictor.predict_token(&input);
            assert_eq!(second, DeflateToken::Literal(b'b'));
            predictor.commit_token(&second, &mut input);
        }
        let expected = if two_positions {
            DeflateToken::new_ref(5, 8)
        } else {
            DeflateToken::new_ref(3, 5)
        };
        assert_eq!(predictor.predict_token(&input), expected);
        assert_eq!(predictor.pending_literals, 0);
    }
}

#[cfg(test)]
pub(crate) fn zlib_level_1_params() -> TokenPredictorParameters {
    use crate::estimator::add_policy_estimator::DictionaryAddPolicy;
    use crate::estimator::preflate_parameter_estimator::{BlockTypeStrategy, PreflateStrategy};
    use crate::hash_algorithm::HashAlgorithm;

    TokenPredictorParameters {
        matches_to_start_detected: false,
        very_far_matches_detected: false,
        window_bits: 15,
        strategy: PreflateStrategy::Default,
        nice_length: 8,
        add_policy: DictionaryAddPolicy::AddFirst(4),
        max_token_count: 16383,
        max_dist_3_matches: 32488,
        matching_type: MatchingType::Greedy,
        max_chain: 4,
        block_type_strategy: BlockTypeStrategy::Dynamic,
        hash_algorithm: HashAlgorithm::Zlib {
            hash_mask: 32767,
            hash_shift: 5,
        },
    }
}

/// test predictor with a standard zlib match that doesn't need any correction
#[test]
pub fn test_predictor_block_perfect() {
    use crate::deflate::deflate_reader;
    use crate::preflate_input::PreflateInput;
    use crate::statistical_codec::AssertDefaultOnlyEncoder;

    let compressed_data = crate::utils::read_file("compressed_zlib_level1.deflate");

    let (contents, plain_text) = deflate_reader::parse_deflate_whole(&compressed_data).unwrap();

    let mut predictor = TokenPredictor::new(&zlib_level_1_params());

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
pub fn test_predictor_token_only() {
    use crate::deflate::deflate_reader;
    use crate::preflate_input::PreflateInput;

    let compressed_data = crate::utils::read_file("compressed_zlib_level1.deflate");

    let (contents, plain_text) = deflate_reader::parse_deflate_whole(&compressed_data).unwrap();

    let mut predictor = TokenPredictor::new(&zlib_level_1_params());

    let mut input = PreflateInput::new(&plain_text);

    for i in 0..contents.blocks.len() {
        let b = &contents.blocks[i];
        match &b.block_type {
            DeflateTokenBlockType::Huffman { tokens, .. } => {
                for i in 0..tokens.len() {
                    assert_eq!(predictor.predict_token(&mut input), tokens[i]);
                    predictor.commit_token(&tokens[i], &mut input);
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
pub fn test_predictor_incremental() {
    use crate::deflate::deflate_reader;
    use crate::preflate_input::{PlainText, PreflateInput};

    let compressed_data = crate::utils::read_file("compressed_zlib_level1.deflate");

    let (contents, plain_text_original) =
        deflate_reader::parse_deflate_whole(&compressed_data).unwrap();

    let mut predictor = TokenPredictor::new(&zlib_level_1_params());

    let mut plain_text = PlainText::new();

    let mut start_pos = 0;

    for i in 0..contents.blocks.len() {
        // build th plain text from the block
        println!("block {}, plaintext {:?}", i, &plain_text);
        let b = &contents.blocks[i];
        match &b.block_type {
            DeflateTokenBlockType::Huffman { tokens, .. } => {
                for i in 0..tokens.len() {
                    match tokens[i] {
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
                    &plain_text_original.text()[start_pos - plain_text.prefix().len()..start_pos],
                );
                crate::utils::assert_eq_array(
                    plain_text.text(),
                    &plain_text_original.text()[start_pos..start_pos + plain_text.len()],
                );

                let mut input = PreflateInput::new(&plain_text);

                if plain_text.prefix().len() > 0 {
                    predictor.add_missing_previous_hash(&input);
                }

                for i in 0..tokens.len() {
                    assert_eq!(
                        predictor.predict_token(&input),
                        tokens[i],
                        "token {} input {}",
                        i,
                        input.pos() as usize - start_pos
                    );
                    predictor.commit_token(&tokens[i], &mut input);
                }
            }
            _ => {
                panic!("unexpected block type")
            }
        }

        start_pos += plain_text.len();

        plain_text.shrink_to_dictionary();
    }
}
