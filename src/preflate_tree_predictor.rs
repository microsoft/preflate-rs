use std::cmp::Ordering;

use crate::{
    preflate_constants::{
        DCode, LCode, CODETREE_CODE_COUNT, DIST_CODE_COUNT, LITLENDIST_CODE_COUNT,
        LITLEN_CODE_COUNT, NONLEN_CODE_COUNT, TREE_CODE_ORDER_TABLE,
    },
    preflate_input::PreflateInput,
    preflate_statistical_codec::{PreflatePredictionDecoder, PreflatePredictionEncoder},
    preflate_statistical_model::PreflateStatisticsCounter,
    preflate_token::{BlockType, PreflateTokenBlock},
};

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum TreeCodeType {
    TCT_BITS = 0,
    TCT_REP = 1,
    TCT_REPZS = 2,
    TCT_REPZL = 3,
}

struct TreeNode {
    parent: u32,
    idx: u32,
}

struct BlockAnalysisResult {
    block_type: BlockType,
    token_info: Vec<bool>,
    correctives: Vec<i32>,
}

pub struct PreflateTreePredictor<'a> {
    input: PreflateInput<'a>,
    prediction_failure: bool,
    analysis_results: Vec<BlockAnalysisResult>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct FreqIdxPair {
    freq: u32,
    idx: u32,
}

fn pq_smaller(p1: &FreqIdxPair, p2: &FreqIdxPair, node_depth: &[u8]) -> Ordering {
    match p1.freq.cmp(&p2.freq) {
        Ordering::Equal => {
            // If freq is equal, compare by idx field
            node_depth[p1.idx as usize].cmp(&node_depth[p2.idx as usize])
        }
        other => other,
    }
}

impl<'a> PreflateTreePredictor<'a> {
    // Function to calculate bit lengths for Huffman codes
    fn calc_bit_lengths(
        _sym_bit_len: &mut [u8],
        _sym_freq: &[u32],
        _max_bits: u32,
        _min_max_code: u32,
    ) -> u32 {
        // Vector to hold sorted frequency-index pairs
        0
    }

    fn build_l_bit_lengths(&self, _bit_lengths: &mut [u8], _lcodes: &[u32]) -> u32 {
        // Implementation for build_l_bit_lengths
        // ...
        0
    }

    fn build_d_bit_lengths(&self, _bit_lengths: &mut [u8], _dcodes: &[u32]) -> u32 {
        // Implementation for build_d_bit_lengths
        // ...
        0
    }

    fn build_tc_bit_lengths(
        &self,
        _bit_lengths: &mut [u8; CODETREE_CODE_COUNT as usize],
        _bl_freqs: &[u32; CODETREE_CODE_COUNT as usize],
    ) -> u32 {
        // Implementation for build_tc_bit_lengths
        // ...
        0
    }

    fn predict_code_type(
        &self,
        _sym_bit_len: &[u8],
        _sym_count: u32,
        _first: bool,
    ) -> TreeCodeType {
        // Implementation for predict_code_type
        // ...
        TreeCodeType::TCT_BITS
    }

    fn predict_ld_trees(
        &self,
        _analysis: &mut BlockAnalysisResult,
        _frequencies: &mut [u32],
        _sym_bit_len: &[u8],
        _sym_l_count: u32,
        _sym_d_count: u32,
        _target_codes: &[u8],
        _target_code_size: u32,
    ) {
        // Implementation for predict_ld_trees
        // ...
    }

    fn reconstruct_ld_trees(
        &self,
        codec: &mut PreflatePredictionDecoder,
        frequencies: &mut [u32],
        target_codes: &mut [u8],
        target_code_size: u32,
        sym_bit_len: &[u8],
        sym_l_count: u32,
        sym_d_count: u32,
    ) -> anyhow::Result<u32> {
        frequencies.iter_mut().for_each(|freq| *freq = 0);
        let mut ptr = sym_bit_len;
        let mut osize: u32 = 0;
        let mut count1 = sym_l_count;
        let mut count2 = sym_d_count;
        let mut first = true;

        while count1 + count2 > 0 {
            let predicted_tree_code_type = predict_code_type(ptr, count1, first);
            let predicted_tree_code_type =
                codec.decode_ld_type_correction(predicted_tree_code_type);

            let mut predicted_tree_code_data =
                predict_code_data(ptr, predicted_tree_code_type, count1, first);
            first = false;
            if predicted_tree_code_type != TreeCodeType::TCT_BITS {
                predicted_tree_code_data = codec.decode_repeat_count_correction(
                    predicted_tree_code_data,
                    predicted_tree_code_type,
                );
            } else {
                predicted_tree_code_data =
                    codec.decode_ld_bit_length_correction(predicted_tree_code_data);
            }

            let l: u32;
            if predicted_tree_code_type != TreeCodeType::TCT_BITS {
                frequencies[(predicted_tree_code_type as usize) + 15] += 1;
                l = predicted_tree_code_data.into();
                if osize + 2 > target_code_size {
                    return Err(anyhow::anyhow!("Reconstruction failed"));
                }
                target_codes[osize as usize] = (predicted_tree_code_type as u8) + 15;
                target_codes[osize as usize + 1] = predicted_tree_code_data;
                osize += 2;
            } else {
                frequencies[predicted_tree_code_data as usize] += 1;
                l = 1;
                if osize >= target_code_size {
                    return Err(anyhow::anyhow!("Reconstruction failed"));
                }
                target_codes[osize as usize] = predicted_tree_code_data;
                osize += 1;
            }

            ptr = &ptr[l as usize..];
            if count1 > l {
                count1 -= l;
            } else {
                count1 += count2;
                count2 = 0;
                first = true;
                if count1 >= l {
                    count1 -= l;
                } else {
                    return Err(anyhow::anyhow!("Reconstruction failed"));
                }
            }
        }

        if count1 + count2 != 0 {
            return Err(anyhow::anyhow!("Reconstruction failed"));
        }

        Ok(osize)
    }

    fn new(dump: &'a [u8], offset: u32) -> Self {
        // Implementation for new
        // ...
        let mut r = PreflateTreePredictor {
            input: PreflateInput::new(dump),
            prediction_failure: false,
            analysis_results: Vec::new(),
        };

        r.input.advance(offset);

        r
    }

    fn collect_token_statistics(
        &mut self,
        block: &PreflateTokenBlock,
    ) -> (
        [u32; LITLEN_CODE_COUNT as usize],
        [u32; DIST_CODE_COUNT as usize],
        u32,
        u32,
    ) {
        let mut Lcodes = [0; LITLEN_CODE_COUNT as usize];
        let mut Dcodes = [0; DIST_CODE_COUNT as usize];
        let mut Lcount = 0;
        let mut Dcount = 0;

        for token in &block.tokens {
            if token.len() == 1 {
                Lcodes[self.input.cur_char(0) as usize] += 1;
                Lcount += 1;
                self.input.advance(1);
            } else {
                Lcodes[(NONLEN_CODE_COUNT + LCode(token.len())) as usize] += 1;
                Lcount += 1;
                Dcodes[DCode(token.dist()) as usize] += 1;
                Dcount += 1;
                self.input.advance(token.len());
            }
        }
        Lcodes[256] = 1;

        (Lcodes, Dcodes, Lcount, Dcount)
    }

    fn analyze_block(&mut self, blockno: usize, block: &PreflateTokenBlock) {
        if blockno != self.analysis_results.len()
            || self.prediction_failure
            || block.block_type != BlockType::DynamicHuff
        {
            return;
        }

        let mut analysis = BlockAnalysisResult {
            block_type: block.block_type,
            token_info: Vec::new(),
            correctives: Vec::new(),
        };

        let (l_codes, d_codes, _l_count, _d_count) = self.collect_token_statistics(block);

        let mut bit_lengths = vec![0; LITLENDIST_CODE_COUNT as usize];
        let mut predicted_l_tree_size = self.build_l_bit_lengths(&mut bit_lengths, &l_codes[..]);
        analysis
            .token_info
            .push(predicted_l_tree_size != block.nlen.into());
        if predicted_l_tree_size != block.nlen.into() {
            analysis.correctives.push(block.nlen as i32);
        }
        predicted_l_tree_size = block.nlen.into();

        let mut predicted_d_tree_size =
            self.build_d_bit_lengths(&mut bit_lengths[predicted_l_tree_size as usize..], &d_codes);
        analysis
            .token_info
            .push(predicted_d_tree_size != block.ndist.into());
        if predicted_d_tree_size != block.ndist.into() {
            analysis.correctives.push(block.ndist as i32);
        }
        predicted_d_tree_size = block.ndist.into();

        let mut bl_freqs = [0; CODETREE_CODE_COUNT as usize];
        let target_codes = &block.tree_codes[block.ncode as usize..];
        let target_code_size = target_codes.len();
        self.predict_ld_trees(
            &mut analysis,
            &mut bl_freqs,
            &bit_lengths,
            predicted_l_tree_size,
            predicted_d_tree_size,
            target_codes,
            target_code_size as u32,
        );

        let mut simple_code_tree = [0; CODETREE_CODE_COUNT as usize];
        let mut predicted_c_tree_size = self.build_tc_bit_lengths(&mut simple_code_tree, &bl_freqs);
        analysis
            .token_info
            .push(predicted_c_tree_size != block.ncode.into());
        predicted_c_tree_size = block.ncode.into();

        for i in 0..predicted_c_tree_size {
            let predicted_bl = simple_code_tree[TREE_CODE_ORDER_TABLE[i as usize] as usize];
            analysis.correctives.push(predicted_bl as i32);
            analysis
                .correctives
                .push((target_codes[i as usize] as i32) - (predicted_bl as i32));
        }

        self.analysis_results.push(analysis);
    }

    fn update_counters(&mut self, _counter: &mut PreflateStatisticsCounter, _blockno: u32) {
        // Implementation for update_counters
        // ...
    }

    fn encode_block(&mut self, _encoder: &mut PreflatePredictionEncoder, _blockno: u32) {
        // Implementation for encode_block
        // ...
    }

    fn decode_block(
        &mut self,
        _block: &mut PreflateTokenBlock,
        _decoder: &mut PreflatePredictionDecoder,
    ) -> bool {
        // Implementation for decode_block
        // ...
        false
    }
}

fn predict_code_type(sym_bit_len: &[u8], sym_count: u32, first: bool) -> TreeCodeType {
    let code = sym_bit_len[0];
    if code == 0 {
        let mut curlen = 1;
        let max_cur_len = std::cmp::min(sym_count, 11);
        while curlen < max_cur_len && sym_bit_len[curlen as usize] == 0 {
            curlen += 1;
        }
        if curlen >= 11 {
            TreeCodeType::TCT_REPZL
        } else if curlen >= 3 {
            TreeCodeType::TCT_REPZS
        } else {
            TreeCodeType::TCT_BITS
        }
    } else if !first && code == sym_bit_len[sym_count as usize - 1] {
        let mut curlen = 1;
        let max_cur_len = std::cmp::min(sym_count, 3);
        while curlen < max_cur_len && sym_bit_len[curlen as usize] == code {
            curlen += 1;
        }
        if curlen >= 3 {
            TreeCodeType::TCT_REP
        } else {
            TreeCodeType::TCT_BITS
        }
    } else {
        TreeCodeType::TCT_BITS
    }
}

fn predict_code_data(
    sym_bit_len: &[u8],
    code_type: TreeCodeType,
    sym_count: u32,
    first: bool,
) -> u8 {
    let code = sym_bit_len[0];
    match code_type {
        TreeCodeType::TCT_BITS => code,
        TreeCodeType::TCT_REP => {
            let mut curlen = 3;
            let max_cur_len = std::cmp::min(sym_count, 6);
            while curlen < max_cur_len && sym_bit_len[curlen as usize] == code {
                curlen += 1;
            }
            curlen as u8
        }
        TreeCodeType::TCT_REPZS | TreeCodeType::TCT_REPZL => {
            let mut curlen = if code_type == TreeCodeType::TCT_REPZS {
                3
            } else {
                11
            };
            let max_cur_len = std::cmp::min(
                sym_count,
                if code_type == TreeCodeType::TCT_REPZS {
                    10
                } else {
                    138
                },
            );
            while curlen < max_cur_len && sym_bit_len[curlen as usize] == 0 {
                curlen += 1;
            }
            curlen as u8
        }
    }
}
