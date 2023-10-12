use crate::{
    preflate_constants::{MAX_MATCH, MIN_MATCH, TOO_FAR},
    preflate_parameter_estimator::PreflateParameters,
    preflate_predictor_state::{PreflatePredictorState, PreflateRematchInfo},
    preflate_statistical_codec::{PreflatePredictionDecoder, PreflatePredictionEncoder},
    preflate_statistical_model::PreflateStatisticsCounter,
    preflate_token::{BlockType, PreflateToken, PreflateTokenBlock, TOKEN_LITERAL, TOKEN_NONE},
};

pub struct PreflateTokenPredictor<'a> {
    state: PreflatePredictorState<'a>,
    params: &'a PreflateParameters,
    fast: bool,
    prev_len: u32,
    pending_token: PreflateToken,
    current_token_count: u32,
    empty_block_at_end: bool,
}

pub struct BlockAnalysisResult {
    block_type: BlockType,
    token_count: u32,
    block_size_predicted: bool,
    input_eof: bool,
    last_block: bool,
    padding_bits: u8,
    padding_counts: u8,
    token_info: Vec<u8>,
    correctives: Vec<i32>,
}

impl<'a> PreflateTokenPredictor<'a> {
    pub fn new(uncompressed: &'a [u8], params: &'a PreflateParameters, offset: u32) -> Self {
        // Implement constructor logic for PreflateTokenPredictor
        // Initialize fields as necessary
        // Create and initialize PreflatePredictorState, PreflateHashChainExt, and PreflateSeqChain instances
        // Construct the analysisResults vector

        let mut r = Self {
            state: PreflatePredictorState::<'a>::new(
                uncompressed,
                params.mem_level,
                params.config(),
                params.window_bits,
                params.mem_level,
            ),
            params,
            fast: params.is_fast_compressor(),
            prev_len: 0,
            pending_token: TOKEN_NONE,
            current_token_count: 0,
            empty_block_at_end: false,
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

    pub fn analyze_block(
        &mut self,
        block: &PreflateTokenBlock,
    ) -> anyhow::Result<BlockAnalysisResult> {
        self.current_token_count = 0;
        self.prev_len = 0;
        self.pending_token = TOKEN_NONE;

        let mut analysis = BlockAnalysisResult {
            block_type: block.block_type,
            token_count: block.tokens.len() as u32,
            token_info: vec![0; block.tokens.len()],
            block_size_predicted: true,
            input_eof: false,
            last_block: false, // Set this to true if this is the last block.
            padding_bits: block.padding_bits,
            padding_counts: block.padding_bit_count,
            correctives: Vec::new(),
        };

        if analysis.block_type == BlockType::Stored {
            analysis.token_count = block.uncompressed_len as u32;
            self.state.update_hash(analysis.token_count);
            self.state.update_seq(analysis.token_count);
            analysis.input_eof = self.state.available_input_size() == 0;

            return Ok(analysis);
        }

        for i in 0..block.tokens.len() {
            let target_token = &block.tokens[i];
            if self.predict_eob() {
                analysis.block_size_predicted = false;
            }

            /*if blockno == 1 && i == 704 {
                println!("hi");
            }*/

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

            if target_token.len() == 1 {
                if predicted_token.len() > 1 {
                    analysis.token_info[self.current_token_count as usize] = 2; // badly predicted LIT
                } else {
                    analysis.token_info[self.current_token_count as usize] = 0; // perfectly predicted LIT
                }
            } else {
                if predicted_token.len() == 1 {
                    analysis.token_info[self.current_token_count as usize] = 3; // badly predicted REF
                    predicted_token = self.repredict_reference()?;
                } else {
                    analysis.token_info[self.current_token_count as usize] = 1; // well predicted REF
                }

                let mut rematch = PreflateRematchInfo::default();
                if predicted_token.len() != target_token.len() {
                    analysis.token_info[self.current_token_count as usize] += 4; // bad LEN prediction, adds two corrective actions
                    analysis.correctives.push(predicted_token.len() as i32);
                    analysis
                        .correctives
                        .push(target_token.len() as i32 - predicted_token.len() as i32);
                    rematch = self.repredict_match(&target_token);

                    if rematch.requested_match_depth >= 0xffff {
                        return Err(anyhow::Error::msg("Prediction failure"));
                    }

                    analysis
                        .correctives
                        .push((rematch.condensed_hops - 1) as i32);
                } else {
                    if target_token.dist() != predicted_token.dist() {
                        analysis.token_info[self.current_token_count as usize] += 8; // bad DIST ONLY prediction, adds one corrective action
                        rematch = self.repredict_match(&target_token);

                        if rematch.requested_match_depth >= 0xffff {
                            return Err(anyhow::Error::msg("Prediction failure"));
                        }

                        analysis
                            .correctives
                            .push((rematch.condensed_hops - 1) as i32);
                    }
                }
            }

            if target_token.len() == 258 {
                analysis.token_info[self.current_token_count as usize] += 16;
                if target_token.get_irregular258() {
                    analysis.token_info[self.current_token_count as usize] += 32;
                }
            }

            self.commit_token(&target_token);
            self.current_token_count += 1;
        }

        if !self.predict_eob() {
            analysis.block_size_predicted = false;
        }

        analysis.input_eof = self.state.available_input_size() == 0;

        Ok(analysis)
    }

    fn encode_eof(&self, _codec: &mut PreflatePredictionEncoder, _blockno: u32, _last_block: bool) {
        // Implement encode_eof logic here
        // Use the codec to encode EOF information
        unreachable!("decode_block not implemented")
    }

    pub fn decode_block(
        &mut self,
        codec: &mut PreflatePredictionDecoder,
    ) -> anyhow::Result<PreflateTokenBlock> {
        let mut block;
        self.current_token_count = 0;
        self.prev_len = 0;
        self.pending_token = TOKEN_NONE;

        let mut blocksize = 0;
        let mut check_eob = true;

        let bt = codec.decode_block_type();
        match bt {
            BlockType::Stored => {
                block = PreflateTokenBlock::new(BlockType::Stored);
                block.uncompressed_len = codec.decode_value(16);
                block.padding_bits = 0;
                block.padding_bit_count = 0;
                if codec.decode_non_zero_padding() {
                    block.padding_bit_count = codec.decode_value(3) as u8;
                    if block.padding_bit_count > 0 {
                        block.padding_bits = ((1 << (block.padding_bit_count - 1))
                            + codec.decode_value(block.padding_bit_count as u32 - 1))
                            as u8;
                    } else {
                        block.padding_bits = 0;
                    }
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
                blocksize = codec.decode_value(blocksize_bits);
            } else {
                blocksize = blocksize_bits;
            }
            block.tokens.reserve(blocksize as usize);
            check_eob = false;
        } else {
            block.tokens.reserve(1 << (6 + self.params.mem_level));
        }

        while (check_eob && !self.predict_eob())
            || (!check_eob && self.current_token_count < blocksize)
        {
            let mut predicted_token = self.predict_token();

            if predicted_token.len() == 1 {
                let not_ok = codec.decode_literal_prediction_wrong();
                if !not_ok {
                    self.commit_token(&predicted_token);
                    block.tokens.push(predicted_token);
                    self.current_token_count += 1;
                    continue;
                }

                predicted_token = self.repredict_reference()?;
            } else {
                let not_ok = codec.decode_reference_prediction_wrong();
                if not_ok {
                    predicted_token = TOKEN_LITERAL;
                    self.commit_token(&predicted_token);
                    block.tokens.push(predicted_token);
                    self.current_token_count += 1;
                    continue;
                }
            }

            let new_len = codec.decode_len_correction(predicted_token.len());
            if new_len != predicted_token.len() {
                let hops = codec.decode_dist_after_len_correction();

                predicted_token.set_len(new_len);
                predicted_token.set_dist(self.state.first_match(predicted_token.len()));
                if hops != 0 {
                    predicted_token.set_dist(self.recalculate_distance(&predicted_token, hops));
                }

                if predicted_token.len() < 3
                    || predicted_token.len() > 258
                    || predicted_token.dist() == 0
                {
                    return Err(anyhow::Error::msg("Prediction failure"));
                }
            } else {
                let hops = codec.decode_dist_only_correction();
                if hops != 0 {
                    predicted_token.set_dist(self.recalculate_distance(&predicted_token, hops));
                    if predicted_token.dist() == 0 {
                        return Err(anyhow::Error::msg("Prediction failure"));
                    }
                }
            }

            if predicted_token.len() == 258 && codec.decode_irregular_len_258() {
                predicted_token.set_irregular258(true);
            }

            self.commit_token(&predicted_token);
            block.tokens.push(predicted_token);
            self.current_token_count += 1;
        }

        Ok(block)
    }

    fn decode_eof(&mut self, _codec: &mut PreflatePredictionDecoder) -> bool {
        // Implement decode_eof logic here
        // Decode and return a boolean value
        unreachable!("decode_block not implemented")
    }

    fn input_eof(&self) -> bool {
        // Implement input_eof logic here
        // Return a boolean indicating whether input has reached EOF
        unreachable!("decode_block not implemented")
    }

    fn predict_eob(&self) -> bool {
        self.state.available_input_size() == 0
            || self.current_token_count == self.state.max_token_count
    }

    fn predict_token(&mut self) -> PreflateToken {
        if self.state.current_input_pos() == 0 || self.state.available_input_size() < MIN_MATCH {
            return TOKEN_LITERAL;
        }

        let hash = self.state.calculate_hash();

        let match_token = if self.pending_token.len() > 1 {
            self.pending_token
        } else {
            let head = self.state.get_current_hash_head(hash);

            if !self.fast && self.state.seq_valid(self.state.current_input_pos()) {
                self.state.seq_match(
                    self.state.current_input_pos(),
                    head,
                    self.prev_len,
                    self.params.very_far_matches_detected,
                    self.params.matches_to_start_detected,
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
                    self.params.very_far_matches_detected,
                    self.params.matches_to_start_detected,
                    if self.params.zlib_compatible {
                        0
                    } else {
                        1 << self.params.log2_of_max_chain_depth_m1
                    },
                )
            }
        };

        self.prev_len = 0;
        self.pending_token = TOKEN_NONE;

        if match_token.len() < MIN_MATCH {
            return TOKEN_LITERAL;
        }

        if self.fast {
            return match_token;
        }

        // match is too small and far way to be worth encoding as a distance/length pair.
        if match_token.len() == 3 && match_token.dist() > TOO_FAR {
            return TOKEN_LITERAL;
        }

        // Check for a longer match that starts at the next byte, in which case we should
        // just emit a literal instead of a distance/length pair.
        if match_token.len() < self.state.lazy_match_length()
            && self.state.available_input_size() >= match_token.len() + 2
        {
            let mut match_next;
            let hash_next = self.state.calculate_hash_next();
            let head_next = self.state.get_current_hash_head(hash_next);

            if !self.fast && self.state.seq_valid(self.state.current_input_pos() + 1) {
                match_next = self.state.seq_match(
                    self.state.current_input_pos() + 1,
                    head_next,
                    match_token.len(),
                    self.params.very_far_matches_detected,
                    self.params.matches_to_start_detected,
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
                    self.params.very_far_matches_detected,
                    self.params.matches_to_start_detected,
                    if self.params.zlib_compatible {
                        0
                    } else {
                        2 << self.params.log2_of_max_chain_depth_m1
                    },
                );

                if (hash_next ^ hash) & self.state.hash_mask() == 0 {
                    let max_size = std::cmp::min(self.state.available_input_size() - 1, MAX_MATCH);
                    let mut rle = 0;
                    let c = self.state.input_cursor();
                    let b = c[0];
                    while rle < max_size && c[1 + rle as usize] == b {
                        rle += 1;
                    }
                    if rle > match_token.len() && rle >= match_next.len() {
                        match_next.set_len(rle);
                        match_next.set_dist(1);
                    }
                }
            }

            if match_next.len() > match_token.len() {
                self.prev_len = match_token.len();
                self.pending_token = match_next;
                if !self.params.zlib_compatible {
                    self.prev_len = 0;
                    self.pending_token = TOKEN_NONE;
                }
                return TOKEN_LITERAL;
            }
        }

        match_token
    }

    fn repredict_reference(&mut self) -> anyhow::Result<PreflateToken> {
        if self.state.current_input_pos() == 0 || self.state.available_input_size() < MIN_MATCH {
            return Err(anyhow::Error::msg(
                "Not enough space left to find a reference",
            ));
        }

        let hash = self.state.calculate_hash();
        let head = self.state.get_current_hash_head(hash);
        let match_token = self.state.match_token(
            head,
            0,
            0,
            self.params.very_far_matches_detected,
            self.params.matches_to_start_detected,
            2 << self.params.log2_of_max_chain_depth_m1,
        );

        self.prev_len = 0;
        self.pending_token = TOKEN_NONE;

        if match_token.len() < MIN_MATCH {
            return Err(anyhow::Error::msg("Didnt find another match"));
        }

        Ok(match_token)
    }

    fn repredict_match(&mut self, token: &PreflateToken) -> PreflateRematchInfo {
        let hash = self.state.calculate_hash();
        let head = self.state.get_current_hash_head(hash);
        let rematch_info = self.state.rematch_info(head, token);
        rematch_info
    }

    fn recalculate_distance(&self, token: &PreflateToken, hops: u32) -> u32 {
        self.state.hop_match(token, hops)
    }

    fn commit_token(&mut self, token: &PreflateToken) {
        if self.fast && token.len() > self.state.lazy_match_length() {
            self.state.skip_hash(token.len());
        } else {
            self.state.update_hash(token.len());
        }
        self.state.update_seq(token.len());
    }
}

impl BlockAnalysisResult {
    pub fn encode_block(&self, codec: &mut PreflatePredictionEncoder) {
        codec.encode_block_type(self.block_type);

        if self.block_type == BlockType::Stored {
            codec.encode_value(self.token_count, 16);
            let pad = self.padding_bits != 0;
            codec.encode_non_zero_padding(pad);
            if pad {
                let bits_to_save = self.padding_bits.count_ones();
                codec.encode_value(bits_to_save as u32, 3);
                if bits_to_save > 1 {
                    codec.encode_value(
                        self.padding_bits as u32 & ((1 << (bits_to_save - 1)) - 1),
                        bits_to_save - 1,
                    );
                }
            }
            return;
        }

        codec.encode_eob_misprediction(!self.block_size_predicted);
        if !self.block_size_predicted {
            let block_size_bits = self.token_count.count_ones();
            codec.encode_value(block_size_bits as u32, 5);
            if block_size_bits >= 2 {
                codec.encode_value(self.token_count, block_size_bits as u32);
            }
        }

        let mut corrective_pos = 0;
        for i in 0..self.token_count as usize {
            let info = self.token_info[i] as u8;
            match info & 3 {
                0 => {
                    // well predicted LIT
                    codec.encode_literal_prediction_wrong(false);
                    continue;
                }
                2 => {
                    // badly predicted LIT
                    codec.encode_reference_prediction_wrong(true);
                    continue;
                }
                1 => {
                    // well predicted REF
                    codec.encode_reference_prediction_wrong(false)
                }
                3 => {
                    // badly predicted REF
                    codec.encode_literal_prediction_wrong(true)
                }
                _ => unreachable!(),
            }
            if info & 4 != 0 {
                let pred = self.correctives[corrective_pos];
                let diff = self.correctives[corrective_pos + 1];
                let hops = self.correctives[corrective_pos + 2] as u32;
                codec.encode_len_correction(pred as u32, (pred + diff) as u32);
                codec.encode_dist_after_len_correction(hops);
                corrective_pos += 3;
            } else {
                codec.encode_len_correction(3, 3);
                if info & 8 != 0 {
                    let hops = self.correctives[corrective_pos] as u32;
                    codec.encode_dist_only_correction(hops);
                    corrective_pos += 1;
                } else {
                    codec.encode_dist_only_correction(0);
                }
            }
            if info & 16 != 0 {
                let is_irregular = (info & 32) != 0;
                codec.encode_irregular_len258(is_irregular);
            }
        }
    }

    pub fn update_counters(&self, model: &mut PreflateStatisticsCounter) {
        model.block.inc_block_type(self.block_type);

        if self.block_type == BlockType::Stored {
            model.block.inc_non_zero_padding(self.padding_bits != 0);
            return;
        }

        model
            .block
            .inc_eob_prediction_wrong(!self.block_size_predicted);

        let mut corrective_pos = 0;
        for i in 0..self.token_count as usize {
            let info = &self.token_info[i];
            match info & 3 {
                0 => model.token.inc_literal_prediction_wrong(false),
                2 => model.token.inc_reference_prediction_wrong(true),
                1 => model.token.inc_reference_prediction_wrong(false),
                3 => model.token.inc_literal_prediction_wrong(true),
                _ => {}
            }

            if info & 4 != 0 {
                let _pred = self.correctives[corrective_pos];
                let diff = self.correctives[corrective_pos + 1];
                let hops = self.correctives[corrective_pos + 2];
                model.token.inc_length_diff_to_prediction(diff);
                model
                    .token
                    .inc_distance_diff_to_prediction_after_incorrect_length_prediction(hops);
                corrective_pos += 3;
            } else {
                model.token.inc_length_diff_to_prediction(0);
                if info & 8 != 0 {
                    let hops = self.correctives[corrective_pos];
                    model
                        .token
                        .inc_distance_diff_to_prediction_after_correct_length_prediction(hops);
                    corrective_pos += 1;
                } else {
                    model
                        .token
                        .inc_distance_diff_to_prediction_after_correct_length_prediction(0);
                }
            }

            if info & 16 != 0 {
                model
                    .token
                    .inc_irregular_length_258_encoding(info & 32 != 0);
            }
        }
    }
}
