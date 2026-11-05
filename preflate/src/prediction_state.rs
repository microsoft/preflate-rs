/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

//! Shared token-prediction state for encoding, reconstruction, and candidate scoring.
//!
//! A token follows three steps: predict a literal or reference, resolve the actual
//! token, then accept it and advance the dictionary. Scoring already knows the
//! actual token; encoding and reconstruction resolve it through corrections.
//! Advancing from actual tokens keeps all three paths on the same input history.
//!
//! Lazy matching can retain a reference found one position ahead instead of
//! searching again after a literal. This state therefore includes pending matches
//! as well as hash history, token-buffer limits, and block/flush transitions.
//! Block context keeps temporary lookahead limits and reset decisions consistent
//! until the block finishes. Observed equivalence bounds are retained for later
//! parameter normalization without involving a correction codec.

use crate::{
    bit_helper::DebugHash,
    block_predictor::BlockPrediction,
    compressors::{
        DeferredCutoff, LazyMinimum, MatchPrediction, block_minimum_match_length,
        cross_4k_boundary, literal_at_buffer_edge, predict_libdeflate_lazy, predict_miniz_token,
        predict_windows_lazy, predict_zlib_lazy,
    },
    deflate::{
        deflate_constants::{MAX_MATCH, MIN_MATCH},
        deflate_token::{
            DeflateToken, DeflateTokenBlock, DeflateTokenBlockType, DeflateTokenReference,
            TokenFrequency,
        },
    },
    hash_chain_holder::{
        HashChainHolder, MatchResult, SearchPurpose, new_hash_chain_holder_for_behavior,
    },
    parameters::DictionaryAddPolicy,
    preflate_error::{ExitCode, Result, err_exit_code},
    preflate_input::PreflateInput,
    reconstruction_parameters::{
        BehaviorSettings, ChainParser, ReconstructionParameters, SearchBudget,
    },
};

/// Retained until finishing succeeds so limit cleanup uses the matching setup.
#[derive(Clone, Copy)]
struct BlockContext {
    started_empty: bool,
    start_position: u32,
    huffman: bool,
    limit: Option<u32>,
    reset_tag: Option<bool>,
}

/// Codec-free state shared by candidate scoring, encoding, and reconstruction.
pub(crate) struct PredictionState {
    state: Box<dyn HashChainHolder>,
    settings: ReconstructionParameters,
    budget: SearchBudget,
    insertion: DictionaryAddPolicy,
    short_match_cutoff: u32,
    pending_reference: Option<DeflateTokenReference>,
    pending_literals: u8,
    min_match_length: u32,
    lazy_minimum: Option<LazyMinimum>,
    max_token_count: u32,
    block_token_count: u32,
    block_prediction: BlockPrediction,
    block_context: Option<BlockContext>,
    previous_empty_stored: bool,
    dictionary_start: Option<u32>,
    /// Conservative cutoff interval preserving encoded token predictions.
    short_match_distance_bounds: Option<(u32, u32)>,
    deferred_cutoff: Option<DeferredCutoff>,
    lazy_cutoff_equivalence: bool,
    token_limit_bounds: Option<(u32, u32)>,
}

impl std::fmt::Debug for PredictionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PredictionState")
            .field("pending_reference", &self.pending_reference)
            .field("max_token_count", &self.max_token_count)
            .finish()
    }
}

impl PredictionState {
    #[cfg(any(test, feature = "diagnostics"))]
    pub fn block_profile_name(&self) -> &'static str {
        self.block_prediction.profile_name()
    }

    pub fn flush_enabled(&self) -> bool {
        self.block_prediction.flush
    }

    pub fn follows_empty_stored(&self) -> bool {
        self.previous_empty_stored
    }

    pub fn finish_block(&mut self, input: &mut PreflateInput) -> Result<()> {
        let Some(context) = self.block_context else {
            return err_exit_code(ExitCode::PredictionFailure, "No active block to finish");
        };
        self.finish_flush_limit(input, context.limit.is_some())?;
        if context.huffman {
            self.previous_empty_stored &= self.block_token_count == 0;
        } else {
            let length = input.pos() - context.start_position;
            self.block_prediction.record_stored_length(length);
            self.previous_empty_stored = length == 0;
        }
        self.block_prediction.finish_block(context.started_empty);
        self.block_context = None;
        Ok(())
    }

    pub fn advance_stored_byte(&mut self, input: &mut PreflateInput) {
        self.state.update_hash(1, input);
        input.advance(1);
    }

    pub fn predicted_stored_length(&self, remaining: u32) -> u32 {
        self.block_prediction.stored_length(remaining)
    }

    pub fn predicted_token_count(&self, remaining: u32) -> u32 {
        self.block_prediction
            .token_count(remaining, self.max_token_count)
    }

    fn predict_block_type(&self) -> u32 {
        use crate::{
            deflate::deflate_token::{BT_DYNAMICHUFF, BT_STATICHUFF, BT_STORED},
            parameters::BlockTypeStrategy,
        };
        match self.settings.block_type_strategy {
            BlockTypeStrategy::Dynamic | BlockTypeStrategy::Mixed => BT_DYNAMICHUFF,
            BlockTypeStrategy::Static => BT_STATICHUFF,
            BlockTypeStrategy::Uncompressed => BT_STORED,
        }
    }

    pub fn block_type_correction(&mut self, actual: u32, remaining: u32) -> u32 {
        self.block_prediction
            .encode_type(actual, self.predict_block_type(), remaining)
    }

    pub fn recover_block_type(&mut self, correction: u32, remaining: u32) -> Result<u32> {
        self.block_prediction
            .decode_type(correction, self.predict_block_type(), remaining)
    }

    pub fn checksum(&self, checksum: &mut DebugHash) {
        self.state.checksum(checksum);
    }

    pub fn add_missing_previous_hash(&mut self, input: &PreflateInput) {
        self.state.add_missing_previous_hash(input);
    }

    pub fn calculate_hops(
        &self,
        reference: &DeflateTokenReference,
        input: &PreflateInput,
    ) -> Result<u32> {
        self.state.calculate_hops(reference, input)
    }

    pub fn hop_match(&self, length: u32, hops: u32, input: &PreflateInput) -> Result<u32> {
        self.state.hop_match(length, hops, input)
    }

    pub fn needs_frequency(&self) -> bool {
        self.lazy_minimum.is_some()
    }

    pub fn enable_parameter_normalization(
        &mut self,
        short_match_cutoff: u32,
        lazy_cutoff_equivalence: bool,
        compressed_size: usize,
        complete: bool,
    ) {
        // Partial chunks cannot certify the history required by subsequent chunks.
        if complete && compressed_size < 1024 {
            self.state.enable_window_normalization();
            self.short_match_distance_bounds = Some((0, short_match_cutoff.max(32768)));
            self.lazy_cutoff_equivalence = lazy_cutoff_equivalence;
            if !matches!(
                self.settings.behavior,
                BehaviorSettings::Chain {
                    parser: ChainParser::WindowsLazy { .. },
                    ..
                }
            ) {
                self.token_limit_bounds = Some((0, u32::from(u16::MAX)));
            }
        }
    }

    pub fn normalized_window_bits(&self) -> Option<u32> {
        self.state.normalized_window_bits()
    }

    pub fn token_limit_bounds(&self) -> Option<(u32, u32)> {
        self.token_limit_bounds
    }

    pub fn short_match_distance_bounds(&self) -> Option<(u32, u32)> {
        self.short_match_distance_bounds.map(|(lower, upper)| {
            (
                lower,
                self.deferred_cutoff
                    .map_or(upper, |deferred| upper.min(deferred.upper_bound())),
            )
        })
    }

    pub fn predict_and_observe_token_count(
        &mut self,
        remaining: u32,
        actual: usize,
        final_block: bool,
    ) -> usize {
        let predicted = self.predicted_token_count(remaining) as usize;
        if predicted == self.max_token_count as usize
            && let Some((lower, upper)) = &mut self.token_limit_bounds
        {
            let actual = u32::try_from(actual).unwrap();
            if final_block && actual <= self.max_token_count {
                *lower = (*lower).max(actual);
            } else if actual < self.max_token_count {
                *lower = (*lower).max(actual + 1);
            } else if actual > self.max_token_count {
                *upper = (*upper).min(actual - 1);
            } else {
                *lower = (*lower).max(actual);
                *upper = (*upper).min(actual);
            }
        }
        predicted
    }

    pub fn reconstruction_parameters(&self) -> ReconstructionParameters {
        self.settings
    }

    fn retain_deferred_cutoff(&mut self) {
        if let Some(deferred) = self.deferred_cutoff.take()
            && let Some((_, upper)) = &mut self.short_match_distance_bounds
        {
            *upper = (*upper).min(deferred.upper_bound());
        }
    }

    pub fn from_reconstruction_parameters(settings: ReconstructionParameters) -> Self {
        let predictor_state = new_hash_chain_holder_for_behavior(&settings.behavior);
        let (budget, insertion) = settings.behavior.dictionary_and_budget().map_or(
            (SearchBudget { max_chain: 0 }, DictionaryAddPolicy::AddAll),
            |(dictionary, budget)| (budget, dictionary.insertion),
        );

        Self {
            state: predictor_state,
            settings,
            budget,
            insertion,
            short_match_cutoff: settings.behavior.short_match_cutoff(),
            pending_reference: None,
            pending_literals: 0,
            min_match_length: MIN_MATCH,
            lazy_minimum: None,
            max_token_count: settings.max_token_count.into(),
            block_token_count: 0,
            block_prediction: {
                let mut prediction = BlockPrediction::default();
                prediction.begin_chunk(&[]);
                prediction
            },
            previous_empty_stored: false,
            block_context: None,
            dictionary_start: None,
            short_match_distance_bounds: None,
            deferred_cutoff: None,
            lazy_cutoff_equivalence: false,
            token_limit_bounds: None,
        }
    }

    pub fn begin_chunk(&mut self, blocks: &[DeflateTokenBlock]) -> usize {
        let tail_length = self.block_prediction.begin_chunk(blocks);
        if self.previous_empty_stored
            && blocks.iter().any(|block| {
                matches!(&block.block_type, DeflateTokenBlockType::Huffman { tokens, .. } if !tokens.is_empty())
            })
        {
            self.block_prediction.flush = true;
        }
        tail_length
    }

    pub fn predict_end_of_chunk(&self, input: &PreflateInput) -> bool {
        self.block_prediction.end_of_chunk(input.remaining())
    }

    pub fn begin_known_huffman_block(
        &mut self,
        tokens: &[DeflateToken],
        input: &mut PreflateInput,
    ) -> Result<()> {
        self.require_idle_block()?;
        let limit = self.select_flush_limit(tokens, input);
        let reset = self.block_prediction.flush && self.select_flush_reset(tokens, input);
        self.begin_decoded_huffman_block(input, limit, reset)
    }

    pub fn block_lookahead_limit(&self) -> Result<Option<u32>> {
        self.active_huffman_context().map(|context| context.limit)
    }

    pub fn block_reset_tag(&self) -> Result<Option<bool>> {
        self.active_huffman_context()
            .map(|context| context.reset_tag)
    }

    fn active_huffman_context(&self) -> Result<&BlockContext> {
        match &self.block_context {
            Some(context) if context.huffman => Ok(context),
            _ => err_exit_code(ExitCode::PredictionFailure, "No active Huffman block"),
        }
    }

    fn require_idle_block(&self) -> Result<()> {
        if self.block_context.is_some() {
            return err_exit_code(ExitCode::PredictionFailure, "A block is already active");
        }
        Ok(())
    }

    pub fn begin_stored_block(&mut self, input: &PreflateInput) -> Result<()> {
        self.require_idle_block()?;
        let context = BlockContext {
            started_empty: input.remaining() == 0,
            start_position: input.pos(),
            huffman: false,
            limit: None,
            reset_tag: None,
        };
        self.start_block(input);
        self.block_context = Some(context);
        Ok(())
    }

    pub fn begin_decoded_huffman_block(
        &mut self,
        input: &mut PreflateInput,
        limit: Option<u32>,
        reset: bool,
    ) -> Result<()> {
        self.require_idle_block()?;
        let context = BlockContext {
            started_empty: input.remaining() == 0,
            start_position: input.pos(),
            huffman: true,
            limit,
            reset_tag: (self.block_prediction.flush && self.previous_empty_stored).then_some(reset),
        };
        if let Some(length) = limit {
            input.limit(length)?;
        }
        if reset {
            self.reset_dictionary(input.pos());
        }
        self.start_block(input);
        self.block_context = Some(context);
        Ok(())
    }

    fn start_block(&mut self, input: &PreflateInput) {
        self.retain_deferred_cutoff();
        // Encoding and reconstruction must reset lookahead and infer the same minimum
        // at the same boundary, or their later correction decisions will diverge.
        self.pending_reference = None;
        self.pending_literals = 0;
        self.block_token_count = 0;
        self.min_match_length =
            block_minimum_match_length(&self.settings.behavior, input.cur_chars(0));
        self.lazy_minimum = matches!(
            self.settings.behavior,
            BehaviorSettings::Chain {
                parser: ChainParser::LibdeflateLazy { .. },
                ..
            }
        )
        .then(|| LazyMinimum::new(input.pos(), input.remaining()));
    }

    fn select_flush_limit(&self, tokens: &[DeflateToken], input: &PreflateInput) -> Option<u32> {
        let length = self.block_prediction.flush_limit()?;
        let DeflateToken::Reference(reference) = tokens.last()? else {
            return None;
        };
        // An empty stored marker need not represent a producer flush. Bound lookahead
        // only when the actual terminal match was cut despite its source continuing.
        // Otherwise four-byte hashes must keep seeing bytes beyond the block boundary.
        if reference.len() == MAX_MATCH || length >= input.remaining() {
            return None;
        }
        (input.cur_char(length as i32) == input.cur_char(length as i32 - reference.dist() as i32))
            .then_some(length)
    }

    fn select_flush_reset(&mut self, tokens: &[DeflateToken], input: &PreflateInput) -> bool {
        if !self.previous_empty_stored || tokens.is_empty() {
            return false;
        }
        let mut produced = 0;
        for token in tokens {
            if let DeflateToken::Reference(reference) = token
                && reference.dist() > produced
            {
                return false;
            }
            produced += match token {
                DeflateToken::Literal(_) => 1,
                DeflateToken::Reference(reference) => reference.len(),
            };
        }
        // Compare a bounded literal prefix against preserved history. A fresh dictionary
        // can only predict a literal where that prefix contains no three-byte source.
        // Sync flushes that actually reuse history fail the independent-reference guard.
        let saved = (
            self.pending_reference,
            self.pending_literals,
            self.min_match_length,
            self.short_match_distance_bounds,
            self.deferred_cutoff,
        );
        self.min_match_length =
            block_minimum_match_length(&self.settings.behavior, input.cur_chars(0));
        let mut probe = input.clone();
        let mut reset = false;
        for (offset, token) in tokens.iter().take(32).enumerate() {
            if !matches!(token, DeflateToken::Literal(_)) || probe.remaining() < MIN_MATCH {
                break;
            }
            let local_match = (0..offset)
                .any(|source| input.cur_chars(0)[source..source + 3] == probe.cur_chars(0)[..3]);
            self.pending_reference = None;
            self.pending_literals = 0;
            if !local_match && matches!(self.predict_token(&probe), DeflateToken::Reference(_)) {
                reset = true;
                break;
            }
            probe.advance(1);
        }
        (
            self.pending_reference,
            self.pending_literals,
            self.min_match_length,
            self.short_match_distance_bounds,
            self.deferred_cutoff,
        ) = saved;
        reset
    }

    fn reset_dictionary(&mut self, position: u32) {
        self.retain_deferred_cutoff();
        self.dictionary_start = Some(position);
        self.state.set_dictionary_start(self.dictionary_start);
        self.pending_reference = None;
        self.pending_literals = 0;
    }

    fn finish_flush_limit(&mut self, input: &mut PreflateInput, limited: bool) -> Result<()> {
        if limited {
            if input.remaining() != 0 {
                return err_exit_code(ExitCode::InvalidDeflate, "Unconsumed flush lookahead limit");
            }
            input.clear_limit();
            if input.remaining() != 0 && input.bytes_before() >= 3 {
                // Sync flush preserves history, including hashes deferred at the boundary.
                self.state.add_missing_previous_hash(input);
            }
        }
        Ok(())
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
                self.budget.max_chain.saturating_sub(1),
            )
        {
            self.min_match_length = length;
        }
    }

    pub fn predict(&mut self, input: &PreflateInput, frequency: &TokenFrequency) -> DeflateToken {
        self.refresh_minimum(input, frequency);
        self.predict_token(input)
    }

    pub fn accept_token(
        &mut self,
        actual: &DeflateToken,
        predicted: DeflateToken,
        input: &mut PreflateInput,
    ) {
        if matches!(actual, DeflateToken::Reference(_))
            && matches!(predicted, DeflateToken::Literal(_))
        {
            // A corrected reference supersedes the prediction's saved lazy lookahead.
            self.pending_reference = None;
            self.pending_literals = 0;
        }
        self.commit_token(actual, input);
    }

    #[inline(always)]
    fn predict_token(&mut self, input: &PreflateInput) -> DeflateToken {
        if self.pending_literals > 0 {
            self.retain_deferred_cutoff();
            self.pending_literals -= 1;
            return DeflateToken::Literal(input.cur_char(0));
        }
        if input.bytes_before() == 0
            || input.remaining() < MIN_MATCH
            || (self.insertion == DictionaryAddPolicy::AddFirstExcept4kBoundary
                && cross_4k_boundary(input.pos()))
        {
            self.retain_deferred_cutoff();
            return DeflateToken::Literal(input.cur_char(0));
        }

        match self.settings.behavior {
            BehaviorSettings::NoDictionary { strategy: _ } => {
                self.predict_match::<false>(input, 0, |_, _| MatchPrediction::Reference)
            }
            BehaviorSettings::MiniZ { common, greedy, .. } => {
                self.predict_match::<false>(input, 0, |state, token| {
                    predict_miniz_token(input, state, token, greedy, common.search.budget)
                })
            }
            BehaviorSettings::Chain { common, parser } => match parser {
                ChainParser::Greedy { .. } => {
                    self.predict_match::<false>(input, 0, |_, _| MatchPrediction::Reference)
                }
                ChainParser::LibdeflateGreedy { .. } => {
                    self.predict_match::<false>(input, self.min_match_length - 1, |_, _| {
                        MatchPrediction::Reference
                    })
                }
                ChainParser::LibdeflateLazy { two_positions, .. } => {
                    self.predict_match::<false>(input, self.min_match_length - 1, |state, token| {
                        predict_libdeflate_lazy(input, state, token, common.search, two_positions)
                    })
                }
                ChainParser::Lazy { lookahead, .. } => {
                    self.predict_match::<false>(input, 0, |state, token| {
                        predict_zlib_lazy(input, state, token, lookahead, common.search.budget)
                    })
                }
                ChainParser::WindowsLazy { max_lazy, .. } => {
                    self.predict_match::<true>(input, 0, |state, token| {
                        predict_windows_lazy(input, state, token, max_lazy, common.search.budget)
                    })
                }
            },
        }
    }

    #[inline(always)]
    fn predict_match<const WINDOWS: bool>(
        &mut self,
        input: &PreflateInput,
        previous_length: u32,
        predict: impl FnOnce(&dyn HashChainHolder, DeflateTokenReference) -> MatchPrediction,
    ) -> DeflateToken {
        if WINDOWS
            && literal_at_buffer_edge(
                self.block_token_count,
                self.max_token_count,
                self.pending_reference.is_some(),
            )
        {
            self.retain_deferred_cutoff();
            return DeflateToken::Literal(input.cur_char(0));
        }
        let m = if let Some(pending) = self.pending_reference.filter(|_| !WINDOWS) {
            MatchResult::Success(pending)
        } else {
            self.state.match_token_0(
                previous_length,
                self.budget.max_chain,
                input,
                SearchPurpose::Prediction,
            )
        };

        self.pending_reference = None;
        if let Some(deferred) = self.deferred_cutoff.take()
            && !deferred.resolved_by(input, m)
            && let Some((_, upper)) = &mut self.short_match_distance_bounds
        {
            *upper = (*upper).min(deferred.upper_bound());
        }

        if let MatchResult::Success(match_token) = m {
            if match_token.len() < self.min_match_length {
                return DeflateToken::Literal(input.cur_char(0));
            }

            if match_token.len() == 3 && match_token.dist() > self.short_match_cutoff {
                self.deferred_cutoff = self
                    .lazy_cutoff_equivalence
                    .then(|| DeferredCutoff::new(input, match_token.dist()))
                    .flatten();
                if self.deferred_cutoff.is_none()
                    && let Some((_, upper)) = &mut self.short_match_distance_bounds
                {
                    *upper = (*upper).min(match_token.dist() - 1);
                }
                return DeflateToken::Literal(input.cur_char(0));
            }

            let prediction = predict(self.state.as_ref(), match_token);
            if match_token.len() == 3
                && !(self.lazy_cutoff_equivalence
                    && matches!(
                        prediction,
                        MatchPrediction::Literal {
                            pending_reference: None,
                            ..
                        }
                    ))
                && let Some((lower, _)) = &mut self.short_match_distance_bounds
            {
                *lower = (*lower).max(match_token.dist());
            }
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
    pub fn repredict_reference(
        &mut self,
        input: &mut PreflateInput,
    ) -> Result<DeflateTokenReference> {
        self.state.set_dictionary_start(None);
        let result = self.repredict_reference_with_history(input);
        self.state.set_dictionary_start(self.dictionary_start);
        result
    }

    fn repredict_reference_with_history(
        &mut self,
        input: &mut PreflateInput,
    ) -> Result<DeflateTokenReference> {
        if input.bytes_before() == 0 || input.remaining() < MIN_MATCH {
            return err_exit_code(
                ExitCode::PredictionFailure,
                "Not enough space left to find a reference",
            );
        }

        let match_token =
            self.state
                .match_token_0(0, self.budget.max_chain, input, SearchPurpose::Prediction);

        // Re-prediction replaces any saved lookahead choice, including lazy2's extra literal.
        self.pending_reference = None;
        self.pending_literals = 0;

        if let MatchResult::Success(m) = match_token
            && m.len() >= MIN_MATCH
        {
            return Ok(m);
        }

        // If we didn't find a match, try again with a larger chain
        let match_token =
            self.state
                .match_token_0(0, 4096, input, SearchPurpose::CorrectionRecovery);

        if let MatchResult::Success(m) = match_token
            && m.len() >= MIN_MATCH
        {
            return Ok(m);
        }

        err_exit_code(
            ExitCode::PredictionFailure,
            format!("Didnt find a match {:?}", match_token).as_str(),
        )
    }

    fn commit_token(&mut self, token: &DeflateToken, input: &mut PreflateInput) {
        self.block_token_count += 1;
        match token {
            DeflateToken::Literal(_) => {
                self.state.update_hash(1, input);
                input.advance(1);
            }
            DeflateToken::Reference(t) => {
                self.retain_deferred_cutoff();
                self.state.update_hash(t.len(), input);
                input.advance(t.len());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        parameters::{LazyBehavior, tests::MatchingType},
        preflate_input::PlainText,
        token_predictor::tests::zlib_level_1_params,
    };

    #[test]
    fn token_count_observation_uses_its_own_prediction() {
        let parameters = {
            let mut canonical_configuration = zlib_level_1_params();
            canonical_configuration.max_token_count = 4;
            canonical_configuration
        };
        for (actual, final_block, expected) in [
            (3, true, (3, 100)),
            (3, false, (4, 100)),
            (5, false, (0, 4)),
            (4, false, (4, 4)),
        ] {
            let mut prediction =
                PredictionState::from_reconstruction_parameters((&parameters).into());
            prediction.token_limit_bounds = Some((0, 100));
            assert_eq!(
                prediction.predict_and_observe_token_count(100, actual, final_block),
                4
            );
            assert_eq!(prediction.token_limit_bounds, Some(expected));
        }
        let mut prediction = PredictionState::from_reconstruction_parameters((&parameters).into());
        assert_eq!(prediction.predict_and_observe_token_count(100, 3, true), 4);
        assert_eq!(prediction.token_limit_bounds, None);
    }

    #[test]
    fn block_context_preserves_framing_decisions_until_finish() {
        let plain = PlainText::new_with_data(vec![b'a'; 8]);
        let mut input = PreflateInput::new(&plain);
        let mut prediction =
            PredictionState::from_reconstruction_parameters((&zlib_level_1_params()).into());
        assert!(prediction.block_reset_tag().is_err());
        prediction.block_prediction.flush = true;
        prediction.previous_empty_stored = true;
        prediction
            .begin_decoded_huffman_block(&mut input, Some(3), true)
            .unwrap();
        assert_eq!(prediction.block_lookahead_limit().unwrap(), Some(3));
        assert_eq!(prediction.block_reset_tag().unwrap(), Some(true));
        for _ in 0..3 {
            let actual = DeflateToken::Literal(b'a');
            let predicted = prediction.predict(&input, &TokenFrequency::default());
            prediction.accept_token(&actual, predicted, &mut input);
        }
        prediction.finish_block(&mut input).unwrap();
        assert!(prediction.block_reset_tag().is_err());
        assert!(!prediction.follows_empty_stored());
        prediction
            .begin_decoded_huffman_block(&mut input, None, false)
            .unwrap();
        assert_eq!(prediction.block_reset_tag().unwrap(), None);
        prediction.finish_block(&mut input).unwrap();
    }

    #[test]
    fn block_context_finishes_stored_and_empty_huffman_history() {
        let plain = PlainText::new_with_data(vec![b'a'; 8]);
        let mut input = PreflateInput::new(&plain);
        let mut prediction =
            PredictionState::from_reconstruction_parameters((&zlib_level_1_params()).into());

        prediction.begin_stored_block(&input).expect("idle block");
        prediction.advance_stored_byte(&mut input);
        prediction.advance_stored_byte(&mut input);
        prediction.finish_block(&mut input).unwrap();
        assert_eq!(prediction.predicted_stored_length(input.remaining()), 2);
        assert!(!prediction.follows_empty_stored());

        prediction.begin_stored_block(&input).expect("idle block");
        prediction.finish_block(&mut input).unwrap();
        assert!(prediction.follows_empty_stored());
        prediction
            .begin_decoded_huffman_block(&mut input, None, false)
            .unwrap();
        prediction.finish_block(&mut input).unwrap();
        assert!(prediction.follows_empty_stored());

        prediction
            .begin_decoded_huffman_block(&mut input, None, false)
            .unwrap();
        let actual = DeflateToken::Literal(b'a');
        let predicted = prediction.predict(&input, &TokenFrequency::default());
        prediction.accept_token(&actual, predicted, &mut input);
        prediction.finish_block(&mut input).unwrap();
        assert!(!prediction.follows_empty_stored());
    }

    #[test]
    fn block_context_applies_reset_and_restores_flush_lookahead() {
        let plain = PlainText::new_with_data(vec![b'a'; 16]);
        let mut input = PreflateInput::new(&plain);
        let mut prediction =
            PredictionState::from_reconstruction_parameters((&zlib_level_1_params()).into());
        for _ in 0..4 {
            prediction.advance_stored_byte(&mut input);
        }
        prediction
            .begin_decoded_huffman_block(&mut input, Some(3), true)
            .unwrap();
        assert_eq!(prediction.dictionary_reset_position(), Some(4));
        assert_eq!(input.remaining(), 3);
        for _ in 0..3 {
            let actual = DeflateToken::Literal(b'a');
            let predicted = prediction.predict(&input, &TokenFrequency::default());
            prediction.accept_token(&actual, predicted, &mut input);
        }
        prediction.finish_block(&mut input).unwrap();
        assert_eq!(input.pos(), 7);
        assert_eq!(input.remaining(), 9);
        assert_eq!(prediction.dictionary_reset_position(), Some(4));
    }

    #[test]
    fn block_context_rejects_unconsumed_flush_and_oversized_limits() {
        let plain = PlainText::new_with_data(vec![b'a'; 8]);
        let mut input = PreflateInput::new(&plain);
        let mut prediction =
            PredictionState::from_reconstruction_parameters((&zlib_level_1_params()).into());
        assert!(
            prediction
                .begin_decoded_huffman_block(&mut input, Some(9), false)
                .is_err()
        );
        prediction
            .begin_decoded_huffman_block(&mut input, Some(3), false)
            .unwrap();
        assert!(prediction.finish_block(&mut input).is_err());
        assert_eq!(input.remaining(), 3);
        assert!(prediction.block_context.is_some());
        assert!(prediction.begin_stored_block(&input).is_err());
        for _ in 0..3 {
            let actual = DeflateToken::Literal(b'a');
            let predicted = prediction.predict(&input, &TokenFrequency::default());
            prediction.accept_token(&actual, predicted, &mut input);
        }
        prediction.finish_block(&mut input).unwrap();
        assert!(prediction.block_context.is_none());
        assert_eq!(input.remaining(), 5);
    }

    #[test]
    fn block_context_rejects_nested_begin_and_unmatched_finish() {
        let plain = PlainText::new_with_data(vec![b'a'; 8]);
        let mut input = PreflateInput::new(&plain);
        let mut prediction =
            PredictionState::from_reconstruction_parameters((&zlib_level_1_params()).into());
        assert!(prediction.finish_block(&mut input).is_err());
        prediction.begin_stored_block(&input).unwrap();
        assert!(prediction.begin_stored_block(&input).is_err());
        assert!(
            prediction
                .begin_decoded_huffman_block(&mut input, Some(3), true)
                .is_err()
        );
        assert_eq!(input.remaining(), 8);
        assert_eq!(prediction.dictionary_reset_position(), None);
        prediction.finish_block(&mut input).unwrap();
        assert!(prediction.finish_block(&mut input).is_err());
        assert!(
            prediction
                .begin_decoded_huffman_block(&mut input, Some(9), true)
                .is_err()
        );
        assert!(prediction.block_context.is_none());
        assert_eq!(prediction.dictionary_reset_position(), None);
        prediction
            .begin_decoded_huffman_block(&mut input, None, false)
            .unwrap();
        prediction.finish_block(&mut input).unwrap();
    }
    #[test]
    fn accepting_a_corrected_reference_discards_only_superseded_lookahead() {
        let plain = PlainText::new_with_data(vec![b'a'; 32]);
        for actual in [DeflateToken::Literal(b'a'), DeflateToken::new_ref(3, 1)] {
            for predicted in [DeflateToken::Literal(b'a'), DeflateToken::new_ref(4, 1)] {
                let mut prediction =
                    PredictionState::from_reconstruction_parameters(zlib_level_1_params());
                let mut input = PreflateInput::new(&plain);
                prediction.commit_token(&DeflateToken::Literal(b'a'), &mut input);
                let pending = Some(DeflateTokenReference::new(8, 1));
                prediction.pending_reference = pending;
                prediction.pending_literals = 1;
                prediction.accept_token(&actual, predicted, &mut input);

                let superseded = matches!(actual, DeflateToken::Reference(_))
                    && matches!(predicted, DeflateToken::Literal(_));
                assert_eq!(
                    prediction.pending_reference,
                    if superseded { None } else { pending }
                );
                assert_eq!(prediction.pending_literals, u8::from(!superseded));
                assert_eq!(prediction.block_token_count, 2);
                assert_eq!(
                    input.pos(),
                    if matches!(actual, DeflateToken::Reference(_)) {
                        4
                    } else {
                        2
                    }
                );
            }
        }
    }

    #[test]
    fn unresolved_lazy_cutoff_proofs_retain_the_rejection_bound() {
        let parameters = {
            let mut canonical_configuration = zlib_level_1_params();
            canonical_configuration.set_short_match_cutoff(4);
            canonical_configuration
        };
        let plain = PlainText::new_with_data(vec![b'a'; 32]);
        let mut input = PreflateInput::new(&plain);
        input.advance(1);
        let mut predictor = PredictionState::from_reconstruction_parameters((&parameters).into());
        predictor.short_match_distance_bounds = Some((4, 32768));
        predictor.deferred_cutoff = DeferredCutoff::new(&input, 8);
        assert_eq!(predictor.short_match_distance_bounds(), Some((4, 7)));
        predictor.commit_token(&DeflateToken::new_ref(3, 1), &mut input);
        assert!(predictor.deferred_cutoff.is_none());
        assert_eq!(predictor.short_match_distance_bounds, Some((4, 7)));
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
        let params = {
            let mut canonical_configuration = zlib_level_1_params();
            canonical_configuration.set_max_chain(17);
            canonical_configuration.set_matching_type(MatchingType::LibdeflateGreedy);
            canonical_configuration
        };
        let mut predictor = PredictionState::from_reconstruction_parameters((&params).into());
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
            let params = {
                let mut canonical_configuration = zlib_level_1_params();
                canonical_configuration.set_max_chain(101);
                canonical_configuration
                    .set_matching_type(MatchingType::LibdeflateLazy { two_positions });
                canonical_configuration
            };
            let mut predictor = PredictionState::from_reconstruction_parameters((&params).into());
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
            let params = {
                let mut canonical_configuration = zlib_level_1_params();
                canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
                canonical_configuration.set_max_chain(18);
                canonical_configuration.set_matching_type(MatchingType::MiniZ {
                    max_probes: 16,
                    greedy,
                });
                canonical_configuration
            };
            let mut predictor = PredictionState::from_reconstruction_parameters((&params).into());
            while input.pos() < position {
                predictor.commit_token(&DeflateToken::Literal(input.cur_char(0)), &mut input);
            }
            assert!(matches!(
                predict_miniz_token(
                    &input,
                    predictor.state.as_ref(),
                    DeflateTokenReference::new(3, position),
                    greedy,
                    SearchBudget {
                        max_chain: params.max_chain()
                    },
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
            let params = {
                let mut canonical_configuration = zlib_level_1_params();
                canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
                canonical_configuration.set_nice_length(258);
                canonical_configuration.set_max_chain(4);
                canonical_configuration.set_matching_type(MatchingType::Lazy {
                    max_lazy: 16,
                    filtered_matching: false,
                    behavior,
                });
                canonical_configuration
            };
            let mut predictor = PredictionState::from_reconstruction_parameters((&params).into());
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
            let params = {
                let mut canonical_configuration = zlib_level_1_params();
                canonical_configuration.set_hash_algorithm(HashAlgorithm::Libdeflate4);
                canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
                canonical_configuration.set_nice_length(258);
                canonical_configuration.set_max_chain(301);
                canonical_configuration
                    .set_matching_type(MatchingType::LibdeflateLazy { two_positions });
                canonical_configuration
            };
            let mut predictor = PredictionState::from_reconstruction_parameters((&params).into());
            while input.pos() < position {
                predictor.commit_token(&DeflateToken::Literal(input.cur_char(0)), &mut input);
            }
            let first = predictor.predict_token(&input);
            assert_eq!(first, DeflateToken::Literal(b'a'));
            if two_positions {
                assert_eq!(predictor.pending_literals, 1);
                assert_eq!(predictor.repredict_reference(&mut input).unwrap().len(), 3);
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

    #[test]
    fn windows_lazy_reserves_tail_and_tracks_block_slots() {
        use crate::{hash_algorithm::HashAlgorithm, preflate_input::PlainText};
        let plain = PlainText::new_with_data(vec![b'a'; 40]);
        let params = {
            let mut canonical_configuration = zlib_level_1_params();
            canonical_configuration.set_hash_algorithm(HashAlgorithm::RandomVector);
            canonical_configuration.set_matches_to_start(true);
            canonical_configuration.set_insertion(DictionaryAddPolicy::AddAll);
            canonical_configuration.set_nice_length(258);
            canonical_configuration.set_max_chain(100);
            canonical_configuration.set_matching_type(MatchingType::WindowsLazy { max_lazy: 128 });
            canonical_configuration.max_token_count = 4;
            canonical_configuration
        };
        let mut predictor = PredictionState::from_reconstruction_parameters((&params).into());
        let mut input = PreflateInput::new(&plain);
        predictor.commit_token(&DeflateToken::Literal(b'a'), &mut input);
        assert_eq!(
            predictor.predict_token(&input),
            DeflateToken::new_ref(37, 1)
        );
        assert_eq!(predictor.repredict_reference(&mut input).unwrap().len(), 37);
        assert!(matches!(
            predictor.state.match_token_0(0, params.max_chain(), &input, SearchPurpose::CorrectionRecovery),
            MatchResult::Success(reference) if reference.len() == 39
        ));
        predictor.commit_token(&DeflateToken::new_ref(37, 1), &mut input);
        for _ in 0..2 {
            assert_eq!(predictor.predict_token(&input), DeflateToken::Literal(b'a'));
            predictor.commit_token(&DeflateToken::Literal(b'a'), &mut input);
        }
        assert_eq!(input.remaining(), 0);

        let mut predictor = PredictionState::from_reconstruction_parameters((&params).into());
        let mut input = PreflateInput::new(&plain);
        for _ in 0..3 {
            predictor.commit_token(&DeflateToken::Literal(b'a'), &mut input);
        }
        assert_eq!(predictor.predict_token(&input), DeflateToken::Literal(b'a'));
        predictor.pending_reference = Some(DeflateTokenReference::new(8, 1));
        assert_eq!(
            predictor.predict_token(&input),
            DeflateToken::new_ref(35, 1)
        );
        predictor.pending_reference = Some(DeflateTokenReference::new(8, 1));
        predictor.start_block(&input);
        assert_eq!(predictor.block_token_count, 0);
        assert_eq!(predictor.pending_reference, None);
        assert_eq!(
            predictor.predict_token(&input),
            DeflateToken::new_ref(35, 1)
        );

        let mut ordinary = PredictionState::from_reconstruction_parameters(
            (&{
                let mut canonical_configuration = params;
                canonical_configuration.set_matching_type(MatchingType::Lazy {
                    max_lazy: 128,
                    filtered_matching: false,
                    behavior: LazyBehavior::RecomputeAfterLiteral,
                });
                canonical_configuration
            })
                .into(),
        );
        let mut input = PreflateInput::new(&plain);
        ordinary.commit_token(&DeflateToken::Literal(b'a'), &mut input);
        assert_eq!(ordinary.predict_token(&input), DeflateToken::new_ref(39, 1));
    }

    impl PredictionState {
        pub fn dictionary_reset_position(&self) -> Option<u32> {
            self.dictionary_start
        }

        pub fn track_short_match_distance(&mut self) {
            self.short_match_distance_bounds = Some((0, 32768));
        }
    }
}
