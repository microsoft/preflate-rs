use crate::{
    bit_helper::bit_length,
    predictor_state::PredictorState,
    preflate_constants::{MAX_MATCH, MIN_MATCH, TOO_FAR},
    preflate_parameter_estimator::PreflateParameters,
    preflate_token::{BlockType, PreflateToken, PreflateTokenBlock, PreflateTokenReference},
    statistical_codec::{PredictionDecoder, PredictionEncoder},
};

pub struct TokenPredictor<'a> {
    state: PredictorState<'a>,
    params: PreflateParameters,
    prev_len: u32,
    pending_reference: Option<PreflateTokenReference>,
    current_token_count: u32,
    max_token_count: u32,
}

impl<'a> TokenPredictor<'a> {
    pub fn new(
        uncompressed: &'a [u8],
        params: PreflateParameters,
        //params: &'a PreflateParameters,
        offset: u32,
    ) -> Self {
        // Implement constructor logic for PreflateTokenPredictor
        // Initialize fields as necessary
        // Create and initialize PreflatePredictorState, PreflateHashChainExt, and PreflateSeqChain instances
        // Construct the analysisResults vector

        let mut r = Self {
            state: PredictorState::<'a>::new(uncompressed, params),
            params,
            prev_len: 0,
            pending_reference: None,
            current_token_count: 0,
            max_token_count: ((1 << (6 + params.mem_level)) - 1),
        };

        if r.state.available_input_size() >= 2 {
            let b0 = r.state.input_cursor()[0];
            let b1 = r.state.input_cursor()[1];

            r.state.update_running_hash(b0);
            r.state.update_running_hash(b1);
            r.state.update_seq(2);
        }
        r.state.update_hash(offset);
        r.state.update_seq(offset);

        r
    }

    pub fn predict_block<D: PredictionEncoder>(
        &mut self,
        block: &PreflateTokenBlock,
        codec: &mut D,
    ) -> anyhow::Result<()> {
        self.current_token_count = 0;
        self.prev_len = 0;
        self.pending_reference = None;

        codec.encode_block_type(block.block_type);

        if block.block_type == BlockType::Stored {
            codec.encode_value(block.uncompressed_len as u16, 16);

            let pad = block.padding_bits != 0;
            codec.encode_non_zero_padding(pad);
            if pad {
                codec.encode_value(block.padding_bits.into(), 8);
            }
            self.state.update_hash(block.uncompressed_len as u32);
            self.state.update_seq(block.uncompressed_len as u32);

            return Ok(());
        }

        // if the block ends at an unexpected point, we will need to encode the block size
        if block.tokens.len() != self.max_token_count as usize
            && block.uncompressed_len != self.state.available_input_size()
        {
            codec.encode_eob_misprediction(true);

            let block_size_bits = bit_length(block.tokens.len() as u32);
            codec.encode_value(block_size_bits as u16, 5);
            if block_size_bits >= 2 {
                codec.encode_value(block.tokens.len() as u16, block_size_bits as u8);
            }
        } else {
            codec.encode_eob_misprediction(false);
        }

        for i in 0..block.tokens.len() {
            let target_token = &block.tokens[i];

            let mut predicted_token = self.predict_token();

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
                            codec.encode_literal_prediction_wrong(false);
                        }
                        PreflateToken::Reference(r) => {
                            // target had a literal, so we were wrong if we predicted a reference
                            codec.encode_reference_prediction_wrong(true);
                        }
                    }
                }
                PreflateToken::Reference(target_ref) => {
                    let predicted_ref;
                    match predicted_token {
                        PreflateToken::Literal => {
                            codec.encode_literal_prediction_wrong(true);
                            predicted_ref = self.repredict_reference()?;
                        }
                        PreflateToken::Reference(r) => {
                            // target had a reference, so we were wrong if we predicted a literal
                            codec.encode_reference_prediction_wrong(false);
                            predicted_ref = r;
                        }
                    }

                    codec
                        .encode_len_correction(predicted_ref.len() as u32, target_ref.len() as u32);

                    if predicted_ref.len() != target_ref.len() {
                        let rematch = self.repredict_match(&target_ref)?;
                        codec.encode_dist_after_len_correction(rematch - 1);
                    } else {
                        if target_ref.dist() != predicted_ref.dist() {
                            let rematch = self.repredict_match(&target_ref)?;
                            codec.encode_dist_only_correction(rematch - 1);
                        } else {
                            codec.encode_dist_only_correction(0);
                        }
                    }

                    if target_ref.len() == 258 {
                        codec.encode_irregular_len_258(target_ref.get_irregular258());
                    }
                }
            }

            self.commit_token(&target_token, None);
        }

        Ok(())
    }

    pub fn recreate_block<D: PredictionDecoder>(
        &mut self,
        codec: &mut D,
    ) -> anyhow::Result<PreflateTokenBlock> {
        let mut block;
        self.current_token_count = 0;
        self.prev_len = 0;
        self.pending_reference = None;

        let mut blocksize = 0;
        let mut check_eob = true;

        let bt = codec.decode_block_type();
        match bt {
            BlockType::Stored => {
                block = PreflateTokenBlock::new(BlockType::Stored);
                block.uncompressed_len = codec.decode_value(16).into();
                block.padding_bits = 0;
                if codec.decode_non_zero_padding() {
                    block.padding_bits = codec.decode_value(8) as u8;
                }
                self.state.update_hash(block.uncompressed_len);
                self.state.update_seq(block.uncompressed_len);
                return Ok(block);
            }
            BlockType::StaticHuff => {
                block = PreflateTokenBlock::new(BlockType::StaticHuff);
            }
            BlockType::DynamicHuff => {
                block = PreflateTokenBlock::new(BlockType::DynamicHuff);
            }
        }

        if codec.decode_eob_misprediction() {
            let blocksize_bits = codec.decode_value(5);
            if blocksize_bits >= 2 {
                blocksize = codec.decode_value(blocksize_bits as u8);
            } else {
                blocksize = blocksize_bits;
            }
            block.tokens.reserve(blocksize as usize);
            check_eob = false;
        } else {
            block.tokens.reserve(1 << (6 + self.params.mem_level));
        }

        while (check_eob && !self.predict_eob())
            || (!check_eob && self.current_token_count < blocksize as u32)
        {
            let mut predicted_ref: PreflateTokenReference;
            match self.predict_token() {
                PreflateToken::Literal => {
                    let not_ok = codec.decode_literal_prediction_wrong();
                    if !not_ok {
                        self.commit_token(&PreflateToken::Literal, Some(&mut block));
                        continue;
                    }

                    predicted_ref = self.repredict_reference()?;
                }
                PreflateToken::Reference(r) => {
                    let not_ok = codec.decode_reference_prediction_wrong();
                    if not_ok {
                        self.commit_token(&PreflateToken::Literal, Some(&mut block));
                        continue;
                    }

                    predicted_ref = r;
                }
            }

            let new_len = codec.decode_len_correction(predicted_ref.len());
            if new_len != predicted_ref.len() {
                let hops = codec.decode_dist_after_len_correction();

                predicted_ref.set_len(new_len);
                predicted_ref.set_dist(self.state.first_match(predicted_ref.len()));
                if hops != 0 {
                    predicted_ref.set_dist(self.recalculate_distance(&predicted_ref, hops)?);
                }

                if predicted_ref.len() < 3 || predicted_ref.len() > 258 {
                    return Err(anyhow::Error::msg("Prediction failure"));
                }
            } else {
                let hops = codec.decode_dist_only_correction();
                if hops != 0 {
                    predicted_ref.set_dist(self.recalculate_distance(&predicted_ref, hops)?);
                }
            }

            if predicted_ref.len() == 258 && codec.decode_irregular_len_258() {
                predicted_ref.set_irregular258(true);
            }

            self.commit_token(&PreflateToken::Reference(predicted_ref), Some(&mut block));
        }

        Ok(block)
    }

    pub fn input_eof(&self) -> bool {
        // Return a boolean indicating whether input has reached EOF
        self.state.available_input_size() == 0
    }

    fn predict_eob(&self) -> bool {
        self.state.available_input_size() == 0 || self.current_token_count == self.max_token_count
    }

    fn predict_token(&mut self) -> PreflateToken {
        if self.state.current_input_pos() == 0 || self.state.available_input_size() < MIN_MATCH {
            return PreflateToken::Literal;
        }

        let hash = self.state.calculate_hash();

        let m = if self.pending_reference.is_some() {
            self.pending_reference
        } else {
            let head = self.state.get_current_hash_head(hash);

            if !self.params.is_fast_compressor
                && self.state.seq_valid(self.state.current_input_pos())
            {
                self.state.seq_match(
                    self.state.current_input_pos(),
                    head,
                    self.prev_len,
                    if self.params.zlib_compatible {
                        0
                    } else {
                        1 << self.params.log2_of_max_chain_depth_m1
                    },
                )
            } else {
                self.state.match_token(
                    head,
                    self.prev_len,
                    0,
                    if self.params.zlib_compatible {
                        0
                    } else {
                        1 << self.params.log2_of_max_chain_depth_m1
                    },
                )
            }
        };

        self.prev_len = 0;
        self.pending_reference = None;

        if let Some(match_token) = m {
            if match_token.len() < MIN_MATCH {
                return PreflateToken::Literal;
            }

            if self.params.is_fast_compressor {
                return PreflateToken::Reference(match_token);
            }

            // match is too small and far way to be worth encoding as a distance/length pair.
            if match_token.len() == 3 && match_token.dist() > TOO_FAR {
                return PreflateToken::Literal;
            }

            // Check for a longer match that starts at the next byte, in which case we should
            // just emit a literal instead of a distance/length pair.
            if match_token.len() < self.params.max_lazy
                && self.state.available_input_size() >= match_token.len() + 2
            {
                let mut match_next;
                let hash_next = self.state.calculate_hash_next();
                let head_next = self.state.get_current_hash_head(hash_next);

                if !self.params.is_fast_compressor
                    && self.state.seq_valid(self.state.current_input_pos() + 1)
                {
                    match_next = self.state.seq_match(
                        self.state.current_input_pos() + 1,
                        head_next,
                        match_token.len(),
                        if self.params.zlib_compatible {
                            0
                        } else {
                            2 << self.params.log2_of_max_chain_depth_m1
                        },
                    );
                } else {
                    match_next = self.state.match_token(
                        head_next,
                        match_token.len(),
                        1,
                        if self.params.zlib_compatible {
                            0
                        } else {
                            2 << self.params.log2_of_max_chain_depth_m1
                        },
                    );

                    if (hash_next ^ hash) & self.state.hash_mask() == 0 {
                        let max_size =
                            std::cmp::min(self.state.available_input_size() - 1, MAX_MATCH);
                        let mut rle = 0;
                        let c = self.state.input_cursor();
                        let b = c[0];
                        while rle < max_size && c[1 + rle as usize] == b {
                            rle += 1;
                        }
                        if rle > match_token.len() && match_next.is_some_and(|x| rle >= x.len()) {
                            match_next = Some(PreflateTokenReference::new(rle, 1, false));
                        }
                    }
                }

                if let Some(m) = match_next {
                    if m.len() > match_token.len() {
                        self.prev_len = match_token.len();
                        self.pending_reference = match_next;

                        if !self.params.zlib_compatible {
                            self.prev_len = 0;
                            self.pending_reference = None;
                        }
                        return PreflateToken::Literal;
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
    fn repredict_reference(&mut self) -> anyhow::Result<PreflateTokenReference> {
        if self.state.current_input_pos() == 0 || self.state.available_input_size() < MIN_MATCH {
            return Err(anyhow::Error::msg(
                "Not enough space left to find a reference",
            ));
        }

        let hash = self.state.calculate_hash();
        let head = self.state.get_current_hash_head(hash);
        let match_token =
            self.state
                .match_token(head, 0, 0, 2 << self.params.log2_of_max_chain_depth_m1);

        self.prev_len = 0;
        self.pending_reference = None;

        if let Some(m) = match_token {
            if m.len() >= MIN_MATCH {
                return Ok(m);
            }
        }
        return Err(anyhow::Error::msg("Didnt find a match"));
    }

    /// For a given target token to match and the current state, find how many hops it takes to get to the same match
    fn repredict_match(&mut self, token: &PreflateTokenReference) -> anyhow::Result<u32> {
        let hash = self.state.calculate_hash();
        let head = self.state.get_current_hash_head(hash);
        self.state.calculate_hops(head, token)
    }

    fn recalculate_distance(
        &self,
        token: &PreflateTokenReference,
        hops: u32,
    ) -> anyhow::Result<u32> {
        self.state.hop_match(token, hops)
    }

    fn commit_token(&mut self, token: &PreflateToken, block: Option<&mut PreflateTokenBlock>) {
        match token {
            PreflateToken::Literal => {
                if let Some(block) = block {
                    block.add_literal(self.state.input_cursor()[0]);
                }

                self.state.update_hash(1);
                self.state.update_seq(1);
            }
            PreflateToken::Reference(t) => {
                if let Some(block) = block {
                    block.add_reference(t.len(), t.dist(), t.get_irregular258());
                }

                // max_lazy is reused by the fast compressor to mean that if a match is larger than a
                // certain size it should not be added to the dictionary in order to save on speed.
                if self.params.is_fast_compressor && t.len() > self.params.max_lazy {
                    self.state.skip_hash(t.len());
                } else {
                    self.state.update_hash(t.len());
                }
                self.state.update_seq(t.len());
            }
        }

        self.current_token_count += 1;
    }
}
