/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::{
    bit_helper::DebugHash,
    cabac_codec::{decode_difference, encode_difference},
    deflate::deflate_constants::MIN_MATCH,
    deflate::deflate_token::{
        DeflateHuffmanType, DeflateToken, DeflateTokenBlock, DeflateTokenReference, TokenFrequency,
        BT_DYNAMICHUFF, BT_STATICHUFF, BT_STORED,
    },
    deflate::huffman_calc::HufftreeBitCalc,
    estimator::{
        add_policy_estimator::DictionaryAddPolicy, preflate_parameter_estimator::PreflateStrategy,
        preflate_parse_config::MatchingType,
    },
    hash_algorithm::HashAlgorithm,
    hash_chain_holder::{new_hash_chain_holder, HashChainHolder, MatchResult},
    preflate_error::{err_exit_code, AddContext, ExitCode, Result},
    preflate_input::PreflateInput,
    statistical_codec::{
        CodecCorrection, CodecMisprediction, PredictionDecoder, PredictionEncoder,
    },
    tree_predictor::{predict_tree_for_block, recreate_tree_for_block},
};

const VERIFY: bool = false;

pub struct TokenPredictor<'a> {
    state: Box<dyn HashChainHolder>,
    params: TokenPredictorParameters,
    pending_reference: Option<DeflateTokenReference>,
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
    pub fn new(uncompressed: PreflateInput<'a>, params: &TokenPredictorParameters) -> Self {
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
            input: uncompressed,
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
        last_block: bool,
    ) -> Result<()> {
        self.current_token_count = 0;
        self.pending_reference = None;

        codec.encode_verify_state("blocktypestart", 0);

        let tokens;
        let huffman_encoding;

        match block {
            DeflateTokenBlock::Stored {
                uncompressed,
                padding_bits,
            } => {
                codec.encode_correction(
                    CodecCorrection::BlockTypeCorrection,
                    encode_difference(BT_DYNAMICHUFF, BT_STORED),
                );

                codec.encode_value(uncompressed.len() as u16, 16);

                codec.encode_correction(CodecCorrection::NonZeroPadding, (*padding_bits).into());

                for _i in 0..uncompressed.len() {
                    self.state.update_hash(1, &self.input);
                    self.input.advance(1);
                }
                return Ok(());
            }
            DeflateTokenBlock::Huffman {
                tokens: t,
                huffman_type,
            } => {
                match huffman_type {
                    DeflateHuffmanType::Static { .. } => {
                        codec.encode_correction(
                            CodecCorrection::BlockTypeCorrection,
                            encode_difference(BT_DYNAMICHUFF, BT_STATICHUFF),
                        );
                        huffman_encoding = None;
                    }
                    DeflateHuffmanType::Dynamic {
                        huffman_encoding: h,
                        ..
                    } => {
                        codec.encode_correction(
                            CodecCorrection::BlockTypeCorrection,
                            encode_difference(BT_DYNAMICHUFF, BT_DYNAMICHUFF),
                        );
                        huffman_encoding = Some(h);
                    }
                }

                tokens = t
            }
        }

        // if the block ends at an unexpected point, or it contains more tokens
        // than expected, we will need to encode the block size
        if (!last_block && tokens.len() != self.max_token_count as usize)
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
                DeflateToken::Literal(_) => {
                    match predicted_token {
                        DeflateToken::Literal(_) => {
                            codec.encode_misprediction(
                                CodecMisprediction::LiteralPredictionWrong,
                                false,
                            );
                        }
                        DeflateToken::Reference(..) => {
                            // target had a literal, so we were wrong if we predicted a reference
                            codec.encode_misprediction(
                                CodecMisprediction::ReferencePredictionWrong,
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
                        DeflateToken::Reference(r) => {
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

            self.commit_token(target_token);
            freq.commit_token(target_token);
        }

        if let Some(huffman_encoding) = huffman_encoding {
            predict_tree_for_block(huffman_encoding, &freq, codec, HufftreeBitCalc::Zlib)?;
        }

        codec.encode_verify_state("done", if VERIFY { self.checksum().hash() } else { 0 });

        Ok(())
    }

    pub fn recreate_block<D: PredictionDecoder>(
        &mut self,
        codec: &mut D,
    ) -> Result<DeflateTokenBlock> {
        self.current_token_count = 0;
        self.pending_reference = None;

        codec.decode_verify_state("blocktypestart", 0);

        let bt = decode_difference(
            BT_DYNAMICHUFF,
            codec.decode_correction(CodecCorrection::BlockTypeCorrection),
        );
        match bt {
            BT_STORED => {
                let uncompressed_len = codec.decode_value(16).into();
                let padding_bits = codec.decode_correction(CodecCorrection::NonZeroPadding) as u8;
                let mut uncompressed = Vec::with_capacity(uncompressed_len as usize);

                for _i in 0..uncompressed_len {
                    uncompressed.push(self.input.cur_char(0));
                    self.state.update_hash(1, &self.input);
                    self.input.advance(1);
                }

                return Ok(DeflateTokenBlock::Stored {
                    uncompressed,
                    padding_bits,
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

        while !self.input_eof() && self.current_token_count < blocksize {
            codec.decode_verify_state(
                "token",
                if VERIFY {
                    self.checksum().hash()
                } else {
                    self.current_token_count as u64
                },
            );

            let mut predicted_ref: DeflateTokenReference;
            match self.predict_token() {
                DeflateToken::Literal(l) => {
                    let not_ok =
                        codec.decode_misprediction(CodecMisprediction::LiteralPredictionWrong);
                    if !not_ok {
                        self.commit_token(&DeflateToken::Literal(l));
                        freq.commit_token(&DeflateToken::Literal(l));

                        tokens.push(DeflateToken::Literal(l));
                        continue;
                    }

                    predicted_ref = self.repredict_reference(None).with_context(|| {
                        format!(
                            "repredict_reference token_count={:?}",
                            self.current_token_count
                        )
                    })?;
                }
                DeflateToken::Reference(r) => {
                    let not_ok =
                        codec.decode_misprediction(CodecMisprediction::ReferencePredictionWrong);
                    if not_ok {
                        let c = self.input.cur_char(0);
                        self.commit_token(&DeflateToken::Literal(c));
                        freq.commit_token(&DeflateToken::Literal(c));

                        tokens.push(DeflateToken::Literal(c));
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

                predicted_ref = DeflateTokenReference::new(
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
                    predicted_ref = DeflateTokenReference::new(new_len, new_dist, false);
                }
            }

            if predicted_ref.len() == 258
                && codec.decode_misprediction(CodecMisprediction::IrregularLen258)
            {
                predicted_ref.set_irregular258(true);
            }

            self.commit_token(&DeflateToken::Reference(predicted_ref));
            freq.commit_token(&DeflateToken::Reference(predicted_ref));
            tokens.push(DeflateToken::Reference(predicted_ref));
        }

        let b = DeflateTokenBlock::Huffman {
            tokens,
            huffman_type: if bt == BT_STATICHUFF {
                DeflateHuffmanType::Static { incomplete: false }
            } else {
                DeflateHuffmanType::Dynamic {
                    huffman_encoding: recreate_tree_for_block(&freq, codec, HufftreeBitCalc::Zlib)?,
                }
            },
        };

        codec.decode_verify_state("done", if VERIFY { self.checksum().hash() } else { 0 });

        Ok(b)
    }

    pub fn input_eof(&self) -> bool {
        // Return a boolean indicating whether input has reached EOF
        self.input.remaining() == 0
    }

    fn predict_token(&mut self) -> DeflateToken {
        if self.input.pos() == 0 || self.input.remaining() < MIN_MATCH {
            return DeflateToken::Literal(self.input.cur_char(0));
        }

        let m = if let Some(pending) = self.pending_reference {
            MatchResult::Success(pending)
        } else {
            self.state
                .match_token_0(0, self.params.max_chain, &self.input)
        };

        self.pending_reference = None;

        if let MatchResult::Success(match_token) = m {
            if match_token.len() < MIN_MATCH {
                return DeflateToken::Literal(self.input.cur_char(0));
            }

            // match is too small and far way to be worth encoding as a distance/length pair.
            if match_token.len() == 3 && match_token.dist() > self.params.max_dist_3_matches.into()
            {
                return DeflateToken::Literal(self.input.cur_char(0));
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
                            .match_token_1(match_token.len(), max_depth, &self.input);

                    if let MatchResult::Success(m) = match_next {
                        if m.len() > match_token.len() {
                            self.pending_reference = Some(m);

                            if !self.params.zlib_compatible {
                                self.pending_reference = None;
                            }
                            return DeflateToken::Literal(self.input.cur_char(0));
                        }
                    }
                }
            }

            DeflateToken::Reference(match_token)
        } else {
            DeflateToken::Literal(self.input.cur_char(0))
        }
    }

    /// When the predicted token was a literal, but the actual token was a reference, try again
    /// to find a match for the reference.
    fn repredict_reference(
        &mut self,
        _dist_match: Option<DeflateTokenReference>,
    ) -> Result<DeflateTokenReference> {
        if self.input.pos() == 0 || self.input.remaining() < MIN_MATCH {
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

        let match_token = self
            .state
            .match_token_0(0, self.params.max_chain, &self.input);

        self.pending_reference = None;

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

    fn commit_token(&mut self, token: &DeflateToken) {
        match token {
            DeflateToken::Literal(_) => {
                self.state.update_hash(1, &self.input);
                self.input.advance(1);
            }
            DeflateToken::Reference(t) => {
                self.state.update_hash(t.len(), &self.input);
                self.input.advance(t.len());
            }
        }

        self.current_token_count += 1;
    }
}
