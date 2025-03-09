/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use bitcode::{Decode, Encode};

use crate::{
    bit_helper::DebugHash,
    deflate::{
        deflate_constants::MIN_MATCH,
        deflate_token::{
            DeflateHuffmanType, DeflateToken, DeflateTokenBlock, DeflateTokenBlockType,
            DeflateTokenReference, TokenFrequency, BT_DYNAMICHUFF, BT_STATICHUFF, BT_STORED,
        },
        huffman_calc::HufftreeBitCalc,
    },
    estimator::{
        add_policy_estimator::DictionaryAddPolicy, preflate_parameter_estimator::PreflateStrategy,
        preflate_parse_config::MatchingType,
    },
    hash_algorithm::HashAlgorithm,
    hash_chain_holder::{new_hash_chain_holder, HashChainHolder, MatchResult},
    preflate_error::{err_exit_code, AddContext, ExitCode, Result},
    preflate_input::PreflateInput,
    statistical_codec::{CodecCorrection, PredictionDecoder, PredictionEncoder},
    tree_predictor::{predict_tree_for_block, recreate_tree_for_block},
};

const VERIFY: bool = false;

pub struct TokenPredictor {
    state: Box<dyn HashChainHolder>,
    params: TokenPredictorParameters,
    pending_reference: Option<DeflateTokenReference>,
    current_token_count: u32,
    max_token_count: u32,
}

#[derive(Encode, Decode, Debug, Copy, Clone, Eq, PartialEq)]
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
    pub max_dist_3_matches: u32,
    pub matching_type: MatchingType,
    pub max_chain: u32,
    pub min_len: u32,

    pub hash_algorithm: HashAlgorithm,
}

impl TokenPredictor {
    pub fn new(params: &TokenPredictorParameters) -> Self {
        let predictor_state = new_hash_chain_holder(params);

        Self {
            state: predictor_state,
            params: *params,
            pending_reference: None,
            current_token_count: 0,
            max_token_count: params.max_token_count.into(),
        }
    }

    pub fn checksum(&self) -> DebugHash {
        assert!(VERIFY);
        let mut c = DebugHash::default();
        self.state.checksum(&mut c);
        c
    }

    pub fn predict_block<D: PredictionEncoder>(
        &mut self,
        block: &DeflateTokenBlock,
        codec: &mut D,
        input: &mut PreflateInput,
    ) -> Result<()> {
        self.current_token_count = 0;
        self.pending_reference = None;

        codec.encode_verify_state("blocktypestart", 0);

        let tokens;
        let huffman_encoding;

        match &block.block_type {
            DeflateTokenBlockType::Stored {
                uncompressed,
                padding_bits,
            } => {
                codec.encode_correction_diff(
                    CodecCorrection::BlockTypeCorrection,
                    BT_STORED,
                    BT_DYNAMICHUFF,
                );

                codec.encode_correction_diff(
                    CodecCorrection::UncompressBlockLenCorrection,
                    uncompressed.len() as u32,
                    65535,
                );

                codec.encode_correction(CodecCorrection::NonZeroPadding, (*padding_bits).into());

                for _i in 0..uncompressed.len() {
                    self.state.update_hash(1, &input);
                    input.advance(1);
                }
                return Ok(());
            }
            DeflateTokenBlockType::Huffman {
                tokens: t,
                huffman_type,
            } => {
                match huffman_type {
                    DeflateHuffmanType::Static { .. } => {
                        codec.encode_correction_diff(
                            CodecCorrection::BlockTypeCorrection,
                            BT_STATICHUFF,
                            BT_DYNAMICHUFF,
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
                            BT_DYNAMICHUFF,
                        );
                        huffman_encoding = Some(h);
                    }
                }

                tokens = t
            }
        }

        // if the block ends at an unexpected point, or it contains more tokens
        // than expected, we will need to encode the block size
        if (!block.last && tokens.len() != self.max_token_count as usize)
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

                    if target_ref.len() == 258 {
                        codec.encode_misprediction(
                            CodecCorrection::IrregularLen258,
                            target_ref.get_irregular258(),
                        );
                    }
                }
            }

            self.commit_token(target_token, input);
            freq.commit_token(target_token);
        }

        if let Some(huffman_encoding) = huffman_encoding {
            predict_tree_for_block(huffman_encoding, &freq, codec, HufftreeBitCalc::Zlib)?;
        }

        // we thought it was the end of the block, but it wasn't
        if input.remaining() == 0 && !block.last {
            codec.encode_misprediction(CodecCorrection::EOFMisprediction, false);
        }

        codec.encode_verify_state("done", if VERIFY { self.checksum().hash() } else { 0 });

        Ok(())
    }

    pub fn recreate_block<D: PredictionDecoder>(
        &mut self,
        codec: &mut D,
        input: &mut PreflateInput,
    ) -> Result<DeflateTokenBlock> {
        self.current_token_count = 0;
        self.pending_reference = None;

        codec.decode_verify_state("blocktypestart", 0);

        let bt = codec.decode_correction_diff(CodecCorrection::BlockTypeCorrection, BT_DYNAMICHUFF);

        match bt {
            BT_STORED => {
                let uncompressed_len = codec
                    .decode_correction_diff(CodecCorrection::UncompressBlockLenCorrection, 65535);
                let padding_bits = codec.decode_correction(CodecCorrection::NonZeroPadding) as u8;
                let mut uncompressed = Vec::with_capacity(uncompressed_len as usize);

                for _i in 0..uncompressed_len {
                    uncompressed.push(input.cur_char(0));
                    self.state.update_hash(1, &input);
                    input.advance(1);
                }

                return Ok(DeflateTokenBlock {
                    block_type: DeflateTokenBlockType::Stored {
                        uncompressed,
                        padding_bits,
                    },
                    last: input.remaining() == 0
                        && !codec.decode_misprediction(CodecCorrection::EOFMisprediction),
                    tail_padding_bits: 0,
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

        let mut tokens = Vec::with_capacity(blocksize as usize);
        let mut freq = TokenFrequency::default();

        codec.decode_verify_state("start", if VERIFY { self.checksum().hash() } else { 0 });

        while input.remaining() != 0 && self.current_token_count < blocksize {
            codec.decode_verify_state(
                "token",
                if VERIFY {
                    self.checksum().hash()
                } else {
                    self.current_token_count as u64
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
                        format!(
                            "repredict_reference token_count={:?}",
                            self.current_token_count
                        )
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
                    false,
                );
            } else {
                let hops = codec.decode_correction(CodecCorrection::DistOnlyCorrection);
                if hops != 0 {
                    let new_dist = self
                        .state
                        .hop_match(predicted_ref.len(), hops, input)
                        .with_context(|| {
                            format!("recalculate_distance token {}", self.current_token_count)
                        })?;
                    predicted_ref = DeflateTokenReference::new(new_len, new_dist, false);
                }
            }

            if predicted_ref.len() == 258
                && codec.decode_misprediction(CodecCorrection::IrregularLen258)
            {
                predicted_ref.set_irregular258(true);
            }

            self.commit_token(&DeflateToken::Reference(predicted_ref), input);
            freq.commit_token(&DeflateToken::Reference(predicted_ref));
            tokens.push(DeflateToken::Reference(predicted_ref));
        }

        let last = input.remaining() == 0
            && !codec.decode_misprediction(CodecCorrection::EOFMisprediction);
        let last_padding_bits = if last {
            codec.decode_correction(CodecCorrection::NonZeroPadding) as u8
        } else {
            0
        };

        let b = DeflateTokenBlock {
            last,
            tail_padding_bits: last_padding_bits,
            block_type: DeflateTokenBlockType::Huffman {
                tokens,
                huffman_type: if bt == BT_STATICHUFF {
                    DeflateHuffmanType::Static
                } else {
                    DeflateHuffmanType::Dynamic {
                        huffman_encoding: recreate_tree_for_block(
                            &freq,
                            codec,
                            HufftreeBitCalc::Zlib,
                        )?,
                    }
                },
            },
        };

        codec.decode_verify_state("done", if VERIFY { self.checksum().hash() } else { 0 });

        Ok(b)
    }

    fn predict_token(&mut self, input: &mut PreflateInput) -> DeflateToken {
        if input.pos() == 0 || input.remaining() < MIN_MATCH {
            return DeflateToken::Literal(input.cur_char(0));
        }

        let m = if let Some(pending) = self.pending_reference {
            MatchResult::Success(pending)
        } else {
            self.state.match_token_0(0, self.params.max_chain, input)
        };

        self.pending_reference = None;

        if let MatchResult::Success(match_token) = m {
            if match_token.len() < MIN_MATCH {
                return DeflateToken::Literal(input.cur_char(0));
            }

            // match is too small and far way to be worth encoding as a distance/length pair.
            if match_token.len() == 3 && match_token.dist() > self.params.max_dist_3_matches.into()
            {
                return DeflateToken::Literal(input.cur_char(0));
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

    /// When the predicted token was a literal, but the actual token was a reference, try again
    /// to find a match for the reference.
    fn repredict_reference(
        &mut self,
        _dist_match: Option<DeflateTokenReference>,
        input: &mut PreflateInput,
    ) -> Result<DeflateTokenReference> {
        if input.pos() == 0 || input.remaining() < MIN_MATCH {
            return err_exit_code(
                ExitCode::RecompressFailed,
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

        self.pending_reference = None;

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
            ExitCode::RecompressFailed,
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

        self.current_token_count += 1;
    }
}
