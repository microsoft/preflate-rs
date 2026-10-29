/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

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
    estimator::{
        add_policy_estimator::{DictionaryAddPolicy, cross_4k_boundary},
        preflate_parameter_estimator::{BlockTypeStrategy, TokenPredictorParameters},
        preflate_parse_config::MatchingType,
    },
    hash_chain_holder::{HashChainHolder, MatchResult, new_hash_chain_holder},
    preflate_error::{AddContext, ExitCode, Result, err_exit_code},
    preflate_input::PreflateInput,
    statistical_codec::{CodecCorrection, PredictionDecoder, PredictionEncoder},
    tree_predictor::{predict_tree_for_block, recreate_tree_for_block},
};

const VERIFY: bool = false;

// Capture the initial prediction, before correction recovery can hide model mismatches.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TokenPredictionTrace {
    pub token_count: usize,
    pub mismatch_count: usize,
    pub first_mismatches: Vec<(u32, DeflateToken, DeflateToken)>,
}

pub struct TokenPredictor {
    state: Box<dyn HashChainHolder>,
    params: TokenPredictorParameters,
    pending_reference: Option<DeflateTokenReference>,
    pending_literals: u8,
    min_match_length: u32,
    max_token_count: u32,
    #[cfg(test)]
    pub(crate) trace: Option<TokenPredictionTrace>,
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
    pub fn new(params: &TokenPredictorParameters) -> Self {
        let predictor_state = new_hash_chain_holder(params);

        Self {
            state: predictor_state,
            params: *params,
            pending_reference: None,
            pending_literals: 0,
            min_match_length: MIN_MATCH,
            max_token_count: params.max_token_count.into(),
            #[cfg(test)]
            trace: None,
        }
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
        self.min_match_length = if self.params.matching_type == MatchingType::LibdeflateGreedy {
            libdeflate_min_match_length(input.cur_chars(0), self.params.max_chain.saturating_sub(1))
        } else {
            MIN_MATCH
        };
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

        let tokens;
        let huffman_encoding;

        match &block.block_type {
            DeflateTokenBlockType::Stored { uncompressed } => {
                codec.encode_correction_diff(
                    CodecCorrection::BlockTypeCorrection,
                    BT_STORED,
                    self.predict_block_type(),
                );

                codec.encode_correction_diff(
                    CodecCorrection::UncompressBlockLenCorrection,
                    uncompressed.len() as u32,
                    65535,
                );

                for _i in 0..uncompressed.len() {
                    self.state.update_hash(1, &input);
                    input.advance(1);
                }

                // last indicator is predicted by reaching the end of the input, although
                // we could have some empty blocks after this just for fun
                codec.encode_correction_bool(
                    CodecCorrection::Last,
                    block.last,
                    input.remaining() == 0,
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
                        codec.encode_correction_diff(
                            CodecCorrection::BlockTypeCorrection,
                            BT_STATICHUFF,
                            self.predict_block_type(),
                        );
                        huffman_encoding = None;
                    }
                    DeflateHuffmanType::Dynamic {
                        huffman_encoding: h,
                        ..
                    } => {
                        codec.encode_correction_diff(
                            CodecCorrection::BlockTypeCorrection,
                            BT_DYNAMICHUFF,
                            self.predict_block_type(),
                        );
                        huffman_encoding = Some(h);
                    }
                }

                tokens = t
            }
        }

        // if the block ends at an unexpected point, or it contains more tokens
        // than expected, we will need to encode the block size
        if (!final_block_in_chunk && tokens.len() != self.max_token_count as usize)
            || tokens.len() > self.max_token_count as usize
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

            let predicted_token = self.predict_token(input);

            #[cfg(test)]
            if let Some(trace) = &mut self.trace {
                trace.token_count += 1;
                if *target_token != predicted_token {
                    trace.mismatch_count += 1;
                    if trace.first_mismatches.len() < 8 {
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

        // last indicator is predicted by reaching the end of the input, although
        // we could have some empty blocks after this just for fun
        codec.encode_correction_bool(CodecCorrection::Last, block.last, input.remaining() == 0);

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

        let bt = codec.decode_correction_diff(
            CodecCorrection::BlockTypeCorrection,
            self.predict_block_type(),
        );

        match bt {
            BT_STORED => {
                let uncompressed_len = codec
                    .decode_correction_diff(CodecCorrection::UncompressBlockLenCorrection, 65535);

                if uncompressed_len > 65535 || uncompressed_len > input.remaining() {
                    return err_exit_code(ExitCode::InvalidDeflate, "Invalid stored block len");
                }

                let mut uncompressed = Vec::with_capacity(uncompressed_len as usize);

                for _i in 0..uncompressed_len {
                    uncompressed.push(input.cur_char(0));
                    self.state.update_hash(1, &input);
                    input.advance(1);
                }

                let last =
                    codec.decode_correction_bool(CodecCorrection::Last, input.remaining() == 0);

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
            blocksize = self.max_token_count;
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

        let last = codec.decode_correction_bool(CodecCorrection::Last, input.remaining() == 0);

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
                && cross_4k_boundary(input.pos()))
        {
            return DeflateToken::Literal(input.cur_char(0));
        }

        let m = if let Some(pending) = self.pending_reference {
            MatchResult::Success(pending)
        } else {
            let previous = if self.params.matching_type == MatchingType::LibdeflateGreedy {
                self.min_match_length - 1
            } else {
                0
            };
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
                && match_token.dist() > u32::from(self.params.max_dist_3_matches)
            {
                return DeflateToken::Literal(input.cur_char(0));
            }

            if let MatchingType::MiniZ { greedy, .. } = self.params.matching_type {
                return self.predict_miniz_token(input, match_token, greedy);
            }

            if let MatchingType::LibdeflateLazy { two_positions } = self.params.matching_type {
                if match_token.len() < self.params.nice_length
                    && input.remaining() > match_token.len()
                {
                    // Libdeflate halves/quarters the chain budget for lookahead and
                    // scores distance as well as length, so equal-length matches can win.
                    let depth = self.params.max_chain.saturating_sub(1);
                    if let MatchResult::Success(next) =
                        self.state
                            .match_token_1(match_token.len() - 1, (depth >> 1).max(1), input)
                    {
                        if prefer_libdeflate_match(match_token, next, 2) {
                            self.pending_reference = Some(next);
                            return DeflateToken::Literal(input.cur_char(0));
                        }
                    }
                    if two_positions && input.remaining() > match_token.len() + 1 {
                        if let MatchResult::Success(next) = self.state.match_token_2(
                            match_token.len() - 1,
                            (depth >> 2).max(1),
                            input,
                        ) {
                            if prefer_libdeflate_match(match_token, next, 6) {
                                self.pending_reference = Some(next);
                                // This return emits the first literal; save one more
                                // literal before the pending offset-two reference.
                                self.pending_literals = 1;
                                return DeflateToken::Literal(input.cur_char(0));
                            }
                        }
                    }
                }
                return DeflateToken::Reference(match_token);
            }

            // Check for a longer match that starts at the next byte, in which case we should
            // just emit a literal instead of a distance/length pair.
            if let MatchingType::Lazy {
                good_length,
                max_lazy,
            } = self.params.matching_type
            {
                if match_token.len() < u32::from(max_lazy)
                    && input.remaining() >= match_token.len() + 2
                {
                    let mut max_depth = self.params.max_chain;

                    if self.params.zlib_compatible && match_token.len() >= u32::from(good_length) {
                        // zlib shortens the amount we search by half if the match is "good" enough
                        max_depth >>= 2;
                    }

                    let match_next = self
                        .state
                        .match_token_1(match_token.len(), max_depth, input);

                    if let MatchResult::Success(m) = match_next {
                        if m.len() > match_token.len() {
                            self.pending_reference = Some(m);

                            if !self.params.zlib_compatible {
                                self.pending_reference = None;
                            }
                            return DeflateToken::Literal(input.cur_char(0));
                        }
                    }
                }
            }

            DeflateToken::Reference(match_token)
        } else {
            DeflateToken::Literal(input.cur_char(0))
        }
    }

    #[inline(always)]
    fn predict_miniz_token(
        &mut self,
        input: &PreflateInput,
        match_token: DeflateTokenReference,
        greedy: bool,
    ) -> DeflateToken {
        if match_token.dist() == input.pos() & 32767 {
            return DeflateToken::Literal(input.cur_char(0));
        }
        if !greedy && match_token.len() < 128 && input.remaining() > match_token.len() {
            if let MatchResult::Success(next) =
                self.state
                    .match_token_1(match_token.len(), self.params.max_chain, input)
            {
                if next.len() > match_token.len()
                    && !(next.len() == 3 && next.dist() >= 8192)
                    && next.dist() != (input.pos() + 1) & 32767
                {
                    self.pending_reference = Some(next);
                    return DeflateToken::Literal(input.cur_char(0));
                }
            }
        }
        DeflateToken::Reference(match_token)
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

// Reproduce libdeflate's block heuristic, not a parameter search. Its short-input
// cutoff and bounded alphabet sample must be identical during reconstruction.
fn libdeflate_min_match_length(bytes: &[u8], depth: u32) -> u32 {
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
                // More distinct bytes cannot lower the minimum below three.
                return MIN_MATCH;
            }
        }
    }
    let length = match distinct {
        0..=5 => 9,
        6..=7 => 8,
        8..=9 => 7,
        10..=15 => 6,
        16..=44 => 5,
        _ => 4,
    };
    // The compressor caps the alphabet-based estimate by its configured search depth.
    let cap = match depth {
        0..=4 => 4,
        5..=9 => 5,
        10..=15 => 7,
        _ => 9,
    };
    length.min(cap)
}

// Libdeflate's greedy minimum depends on alphabet size and search depth, not a fixed length.
// Verify threshold boundaries, depth caps, the short-input cutoff and the 4096-byte sample bound.
#[test]
fn libdeflate_minimum_match_length_is_bounded_and_depth_aware() {
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
        assert_eq!(libdeflate_min_match_length(&bytes, 16), expected);
        assert_eq!(libdeflate_min_match_length(&bytes, 12), expected.min(7));
        assert_eq!(libdeflate_min_match_length(&bytes, 6), expected.min(5));
        assert_eq!(libdeflate_min_match_length(&bytes, 4), expected.min(4));
        assert_eq!(libdeflate_min_match_length(&bytes[..511], 16), 3);
    }
    let mut bytes = vec![b'a'; 4096];
    bytes.extend(0..=255);
    assert_eq!(libdeflate_min_match_length(&bytes, 16), 9);
}

// The block heuristic should depend on alphabet cardinality, not particular byte values.
// Verify relabeling invariance and monotonic behavior across every alphabet size and depth cap.
#[test]
fn libdeflate_minimum_is_monotonic_and_alphabet_invariant() {
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
                let minimum = libdeflate_min_match_length(&bytes, depth);
                assert!((3..=9).contains(&minimum));
                assert_eq!(minimum, libdeflate_min_match_length(&relabeled, depth));
                assert!(minimum >= previous_depth);
                assert!(minimum <= previous_alphabet[index]);
                previous_depth = minimum;
                previous_alphabet[index] = minimum;
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

fn prefer_libdeflate_match(
    current: DeflateTokenReference,
    next: DeflateTokenReference,
    literal_cost: i32,
) -> bool {
    // Mirror the source parser's length/log-distance score and literal penalty;
    // choosing only the longest match would miss cheaper, nearer references.
    next.len() >= current.len()
        && 4 * (next.len() as i32 - current.len() as i32) + current.dist().ilog2() as i32
            - next.dist().ilog2() as i32
            > literal_cost
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
        assert_eq!(
            predictor.predict_miniz_token(&input, DeflateTokenReference::new(3, position), greedy),
            DeflateToken::Literal(b'a')
        );
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

// Longest-match-only selection misses libdeflate's distance-aware lazy decisions.
// Verify nearby equal-length matches can win, but insufficient savings or shorter matches cannot.
#[test]
fn libdeflate_lazy_prefers_a_nearer_equal_length_match() {
    let current = DeflateTokenReference::new(3, 136);
    assert!(prefer_libdeflate_match(
        current,
        DeflateTokenReference::new(3, 5),
        2
    ));
    assert!(!prefer_libdeflate_match(
        current,
        DeflateTokenReference::new(3, 32),
        2
    ));
    assert!(!prefer_libdeflate_match(
        current,
        DeflateTokenReference::new(3, 5),
        6
    ));
    assert!(!prefer_libdeflate_match(
        DeflateTokenReference::new(4, 136),
        DeflateTokenReference::new(3, 1),
        2
    ));
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
            zlib_compatible: false,
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
        zlib_compatible: true,
        max_dist_3_matches: 32488,
        matching_type: MatchingType::Greedy,
        max_chain: 4,
        min_len: 3,
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
