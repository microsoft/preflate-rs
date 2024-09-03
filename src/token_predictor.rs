/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use anyhow::Context;

use crate::{
    bit_helper::DebugHash,
    cabac_codec::{decode_difference, encode_difference},
    hash_algorithm::HashAlgorithm,
    hash_chain::DictionaryAddPolicy,
    hash_chain_holder::{new_hash_chain_holder, HashChainHolder, MatchResult},
    preflate_constants::MIN_MATCH,
    preflate_input::PreflateInput,
    preflate_parameter_estimator::PreflateStrategy,
    preflate_parse_config::MatchingType,
    preflate_token::{BlockType, PreflateToken, PreflateTokenBlock, PreflateTokenReference},
    statistical_codec::{
        CodecCorrection, CodecMisprediction, PredictionDecoder, PredictionEncoder,
    },
};

const VERIFY: bool = false;

pub struct TokenPredictor<'a> {
    state: Box<dyn HashChainHolder>,
    params: TokenPredictorParameters,
    pending_reference: Option<PreflateTokenReference>,
    current_token_count: u32,
    max_token_count: u32,
    input: PreflateInput<'a>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct TokenPredictorParameters {
    /// Zlib does not match to first byte of a file in order to reserve 0 for the end of chain
    pub matches_to_start_detected: bool,

    /// if there are matches that have a distance larger than window_size - MAX_MATCH.
    /// Zlib does not allow these.
    pub very_far_matches_detected: bool,
    pub window_bits: u32,

    pub strategy: PreflateStrategy,
    pub nice_length: u32,

    /// if something, then we use the "fast" compressor, which only adds smaller substrings
    /// to the dictionary
    pub add_policy: DictionaryAddPolicy,

    pub max_token_count: u16,

    pub zlib_compatible: bool,
    pub max_dist_3_matches: u16,
    pub matching_type: MatchingType,
    pub max_chain: u32,
    pub min_len: u32,

    pub hash_algorithm: HashAlgorithm,
}

impl<'a> TokenPredictor<'a> {
    pub fn new(uncompressed: &'a [u8], params: &TokenPredictorParameters) -> Self {
        // Implement constructor logic for PreflateTokenPredictor
        // Initialize fields as necessary
        // Create and initialize PreflatePredictorState, PreflateHashChainExt, and PreflateSeqChain instances
        // Construct the analysisResults vector

        let predictor_state = new_hash_chain_holder(params);

        Self {
            state: predictor_state,
            params: *params,
            pending_reference: None,
            current_token_count: 0,
            max_token_count: params.max_token_count.into(),
            input: PreflateInput::new(uncompressed),
        }
    }

    pub fn checksum(&self) -> DebugHash {
        let mut c = DebugHash::default();
        self.state.checksum(&mut c);
        c
    }

    pub fn predict_block<D: PredictionEncoder>(
        &mut self,
        block: &PreflateTokenBlock,
        codec: &mut D,
        last_block: bool,
    ) -> anyhow::Result<()> {
        self.current_token_count = 0;
        self.pending_reference = None;

        codec.encode_verify_state("blocktypestart", 0);

        codec.encode_correction(
            CodecCorrection::BlockTypeCorrection,
            encode_difference(BlockType::DynamicHuff as u32, block.block_type as u32),
        );

        if block.block_type == BlockType::Stored {
            codec.encode_value(block.uncompressed_len as u16, 16);

            codec.encode_correction(CodecCorrection::NonZeroPadding, block.padding_bits.into());

            for _i in 0..block.uncompressed_len {
                self.state.update_hash(1, &mut self.input, true);
            }

            return Ok(());
        }

        // if the block ends at an unexpected point, or it contains more tokens
        // than expected, we will need to encode the block size
        if (!last_block && block.tokens.len() != self.max_token_count as usize)
            || block.tokens.len() > self.max_token_count as usize
        {
            codec.encode_correction(
                CodecCorrection::TokenCount,
                u32::try_from(block.tokens.len()).unwrap() + 1,
            );
        } else {
            codec.encode_correction(CodecCorrection::TokenCount, 0);
        }

        codec.encode_verify_state("start", self.checksum().hash());

        for i in 0..block.tokens.len() {
            let target_token = &block.tokens[i];

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

            let predicted_token = self.predict_token();

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
                PreflateToken::Literal => {
                    match predicted_token {
                        PreflateToken::Literal => {
                            codec.encode_misprediction(
                                CodecMisprediction::LiteralPredictionWrong,
                                false,
                            );
                        }
                        PreflateToken::Reference(..) => {
                            // target had a literal, so we were wrong if we predicted a reference
                            codec.encode_misprediction(
                                CodecMisprediction::ReferencePredictionWrong,
                                true,
                            );
                        }
                    }
                }
                PreflateToken::Reference(target_ref) => {
                    let predicted_ref = match predicted_token {
                        PreflateToken::Literal => {
                            // target had a reference, so we were wrong if we predicted a literal
                            codec.encode_misprediction(
                                CodecMisprediction::LiteralPredictionWrong,
                                true,
                            );
                            self.repredict_reference(Some(*target_ref))
                                .with_context(|| {
                                    format!(
                                        "repredict_reference target={:?} index={}",
                                        target_ref, i
                                    )
                                })?
                        }
                        PreflateToken::Reference(r) => {
                            // we predicted a reference correctly, so verify that the length/dist was correct
                            codec.encode_misprediction(
                                CodecMisprediction::ReferencePredictionWrong,
                                false,
                            );
                            r
                        }
                    };

                    codec.encode_correction(
                        CodecCorrection::LenCorrection,
                        encode_difference(predicted_ref.len(), target_ref.len()),
                    );

                    if predicted_ref.len() != target_ref.len() {
                        let rematch = self
                            .state
                            .calculate_hops(target_ref, &self.input)
                            .with_context(|| {
                                format!("calculate_hops p={:?}, t={:?}", predicted_ref, target_ref)
                            })?;
                        codec.encode_correction(CodecCorrection::DistAfterLenCorrection, rematch);
                    } else if target_ref.dist() != predicted_ref.dist() {
                        let rematch = self
                            .state
                            .calculate_hops(target_ref, &self.input)
                            .with_context(|| {
                                format!("calculate_hops p={:?}, t={:?}", predicted_ref, target_ref)
                            })?;
                        codec.encode_correction(CodecCorrection::DistOnlyCorrection, rematch);
                    } else {
                        codec.encode_correction(CodecCorrection::DistOnlyCorrection, 0);
                    }

                    if target_ref.len() == 258 {
                        codec.encode_misprediction(
                            CodecMisprediction::IrregularLen258,
                            target_ref.get_irregular258(),
                        );
                    }
                }
            }

            self.commit_token(target_token, None);
        }

        codec.encode_verify_state("done", self.checksum().hash());

        Ok(())
    }

    pub fn recreate_block<D: PredictionDecoder>(
        &mut self,
        codec: &mut D,
    ) -> anyhow::Result<PreflateTokenBlock> {
        let mut block;
        self.current_token_count = 0;
        self.pending_reference = None;

        const BT_STORED: u32 = BlockType::Stored as u32;
        const BT_DYNAMICHUFF: u32 = BlockType::DynamicHuff as u32;
        const BT_STATICHUFF: u32 = BlockType::StaticHuff as u32;

        codec.decode_verify_state("blocktypestart", 0);

        let bt = decode_difference(
            BT_DYNAMICHUFF,
            codec.decode_correction(CodecCorrection::BlockTypeCorrection),
        );
        match bt {
            BT_STORED => {
                block = PreflateTokenBlock::new(BlockType::Stored);
                block.uncompressed_len = codec.decode_value(16).into();
                block.padding_bits = codec.decode_correction(CodecCorrection::NonZeroPadding) as u8;

                for _i in 0..block.uncompressed_len {
                    self.state.update_hash(1, &mut self.input, true);
                }
                return Ok(block);
            }
            BT_STATICHUFF => {
                block = PreflateTokenBlock::new(BlockType::StaticHuff);
            }
            BT_DYNAMICHUFF => {
                block = PreflateTokenBlock::new(BlockType::DynamicHuff);
            }
            _ => {
                return Err(anyhow::Error::msg(format!("Invalid block type {}", bt)));
            }
        }

        let mut blocksize = codec.decode_correction(CodecCorrection::TokenCount);
        if blocksize == 0 {
            blocksize = self.max_token_count;
        } else {
            blocksize -= 1;
        }

        block.tokens.reserve(blocksize as usize);

        codec.decode_verify_state("start", self.checksum().hash());

        while !self.input_eof() && self.current_token_count < blocksize {
            codec.decode_verify_state(
                "token",
                if VERIFY {
                    self.checksum().hash()
                } else {
                    self.current_token_count as u64
                },
            );

            let mut predicted_ref: PreflateTokenReference;
            match self.predict_token() {
                PreflateToken::Literal => {
                    let not_ok =
                        codec.decode_misprediction(CodecMisprediction::LiteralPredictionWrong);
                    if !not_ok {
                        self.commit_token(&PreflateToken::Literal, Some(&mut block));
                        continue;
                    }

                    predicted_ref = self.repredict_reference(None).with_context(|| {
                        format!(
                            "repredict_reference token_count={:?}",
                            self.current_token_count
                        )
                    })?;
                }
                PreflateToken::Reference(r) => {
                    let not_ok =
                        codec.decode_misprediction(CodecMisprediction::ReferencePredictionWrong);
                    if not_ok {
                        self.commit_token(&PreflateToken::Literal, Some(&mut block));
                        continue;
                    }

                    predicted_ref = r;
                }
            }

            let new_len = decode_difference(
                predicted_ref.len(),
                codec.decode_correction(CodecCorrection::LenCorrection),
            );
            if new_len != predicted_ref.len() {
                let hops = codec.decode_correction(CodecCorrection::DistAfterLenCorrection);

                predicted_ref = PreflateTokenReference::new(
                    new_len,
                    self.state
                        .hop_match(new_len, hops, &self.input)
                        .with_context(|| format!("hop_match l={} {:?}", new_len, predicted_ref))?,
                    false,
                );
            } else {
                let hops = codec.decode_correction(CodecCorrection::DistOnlyCorrection);
                if hops != 0 {
                    let new_dist = self
                        .state
                        .hop_match(predicted_ref.len(), hops, &self.input)
                        .with_context(|| {
                            format!("recalculate_distance token {}", self.current_token_count)
                        })?;
                    predicted_ref = PreflateTokenReference::new(new_len, new_dist, false);
                }
            }

            if predicted_ref.len() == 258
                && codec.decode_misprediction(CodecMisprediction::IrregularLen258)
            {
                predicted_ref.set_irregular258(true);
            }

            self.commit_token(&PreflateToken::Reference(predicted_ref), Some(&mut block));
        }

        codec.decode_verify_state("done", self.checksum().hash());

        Ok(block)
    }

    pub fn input_eof(&self) -> bool {
        // Return a boolean indicating whether input has reached EOF
        self.input.remaining() == 0
    }

    fn predict_token(&mut self) -> PreflateToken {
        if self.input.pos() == 0 || self.input.remaining() < MIN_MATCH {
            return PreflateToken::Literal;
        }

        let m = if let Some(pending) = self.pending_reference {
            MatchResult::Success(pending)
        } else {
            self.state
                .match_token(0, 0, self.params.max_chain, &self.input)
        };

        self.pending_reference = None;

        if let MatchResult::Success(match_token) = m {
            if match_token.len() < MIN_MATCH {
                return PreflateToken::Literal;
            }

            // match is too small and far way to be worth encoding as a distance/length pair.
            if match_token.len() == 3 && match_token.dist() > self.params.max_dist_3_matches.into()
            {
                return PreflateToken::Literal;
            }

            // Check for a longer match that starts at the next byte, in which case we should
            // just emit a literal instead of a distance/length pair.
            if let MatchingType::Lazy {
                good_length,
                max_lazy,
            } = self.params.matching_type
            {
                if match_token.len() < u32::from(max_lazy)
                    && self.input.remaining() >= match_token.len() + 2
                {
                    let mut max_depth = self.params.max_chain;

                    if self.params.zlib_compatible && match_token.len() >= u32::from(good_length) {
                        // zlib shortens the amount we search by half if the match is "good" enough
                        max_depth >>= 2;
                    }

                    let match_next =
                        self.state
                            .match_token(match_token.len(), 1, max_depth, &self.input);

                    if let MatchResult::Success(m) = match_next {
                        if m.len() > match_token.len() {
                            self.pending_reference = Some(m);

                            if !self.params.zlib_compatible {
                                self.pending_reference = None;
                            }
                            return PreflateToken::Literal;
                        }
                    }
                }
            }

            PreflateToken::Reference(match_token)
        } else {
            PreflateToken::Literal
        }
    }

    /// When the predicted token was a literal, but the actual token was a reference, try again
    /// to find a match for the reference.
    fn repredict_reference(
        &mut self,
        _dist_match: Option<PreflateTokenReference>,
    ) -> anyhow::Result<PreflateTokenReference> {
        if self.input.pos() == 0 || self.input.remaining() < MIN_MATCH {
            return Err(anyhow::Error::msg(
                "Not enough space left to find a reference",
            ));
        }

        /*
        if let Some(x) = dist_match {
            if x.dist() == 32653 {
                println!("dist_match = {:?}", dist_match);
            }
        }
        */

        let match_token = self
            .state
            .match_token(0, 0, self.params.max_chain, &self.input);

        self.pending_reference = None;

        if let MatchResult::Success(m) = match_token {
            if m.len() >= MIN_MATCH {
                return Ok(m);
            }
        }

        Err(anyhow::Error::msg(format!(
            "Didnt find a match {:?}",
            match_token
        )))
    }

    fn commit_token(&mut self, token: &PreflateToken, block: Option<&mut PreflateTokenBlock>) {
        match token {
            PreflateToken::Literal => {
                if let Some(block) = block {
                    block.add_literal(self.input.cur_char(0));
                }

                self.state.update_hash(1, &mut self.input, true);
            }
            PreflateToken::Reference(t) => {
                if let Some(block) = block {
                    block.add_reference(t.len(), t.dist(), t.get_irregular258());
                }

                self.state.update_hash(t.len(), &mut self.input, false);
            }
        }

        self.current_token_count += 1;
    }
}
