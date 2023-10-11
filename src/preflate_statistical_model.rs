use std::cmp;

use crate::preflate_token::BlockType;

#[derive(Default, Debug)]
pub struct PreflateStatisticsCounter {
    pub block: BlockPrediction,
    pub treecode: TreeCodePrediction,
    pub token: TokenPrediction,
}

#[derive(Default, Debug)]
pub struct BlockPrediction {
    block_type: [u32; 3],
    eob_misprediction: [u32; 2],
    non_zero_padding: [u32; 2],
    total_models: u32,
}

fn count_if<const N: usize>(arr: [u32; N], target: u32) -> u32 {
    let mut sum = 0;
    for i in 0..N {
        sum += arr[i];
    }
    if sum == target {
        1
    } else {
        0
    }
}

impl BlockPrediction {
    pub fn inc_block_type(&mut self, bt: BlockType) {
        self.block_type[bt as usize] += 1;
    }
    pub fn inc_eob_prediction_wrong(&mut self, mispredicted: bool) {
        self.eob_misprediction[mispredicted as usize] += 1;
    }
    pub fn inc_non_zero_padding(&mut self, nonzeropadding: bool) {
        self.non_zero_padding[nonzeropadding as usize] += 1;
    }
    pub fn total_models() -> u32 {
        3
    }
    pub fn check_default_models(&self) -> u32 {
        let mut cnt = 0;
        cnt += count_if(
            self.block_type,
            self.block_type[BlockType::DynamicHuff as usize],
        );
        cnt += count_if(self.eob_misprediction, self.eob_misprediction[0]);
        cnt += count_if(self.non_zero_padding, self.non_zero_padding[0]);
        cnt
    }
    pub fn print(&self) {
        // implementation needed
    }
}

#[derive(Default, Debug)]
pub struct TreeCodePrediction {
    tc_count_misprediction: [u32; 2],
    tc_bitlength_correction: [u32; 7],
    l_count_misprediction: [u32; 2],
    d_count_misprediction: [u32; 2],
    ld_type_misprediction: [[u32; 2]; 4],
    ld_type_replacement: [u32; 4],
    ld_repeat_count_correction: [u32; 3],
    ld_bitlength_correction: [u32; 9],
}

impl TreeCodePrediction {
    pub fn inc_tc_count_prediction_wrong(&mut self, mispredicted: bool) {
        self.tc_count_misprediction[mispredicted as usize] += 1;
    }
    pub fn inc_tc_length_diff_to_prediction(&mut self, len_diff: i32) {
        self.tc_bitlength_correction[cmp::max(cmp::min(len_diff, 3), -3) as usize + 3] += 1;
    }
    pub fn inc_literal_count_prediction_wrong(&mut self, mispredicted: bool) {
        self.l_count_misprediction[mispredicted as usize] += 1;
    }
    pub fn inc_distance_count_prediction_wrong(&mut self, mispredicted: bool) {
        self.d_count_misprediction[mispredicted as usize] += 1;
    }
    pub fn inc_ld_code_type_prediction_wrong(&mut self, codetype: u32, mispredicted: bool) {
        self.ld_type_misprediction[codetype as usize][mispredicted as usize] += 1;
    }
    pub fn inc_ld_code_type_replacement(&mut self, replacement_codetype: u32) {
        self.ld_type_replacement[replacement_codetype as usize] += 1;
    }
    pub fn inc_ld_code_repeat_diff_to_prediction(&mut self, len_diff: i32) {
        self.ld_repeat_count_correction[(cmp::max(cmp::min(len_diff, 1), -1) + 1) as usize] += 1;
    }
    pub fn inc_ld_code_length_diff_to_prediction(&mut self, len_diff: i32) {
        self.ld_bitlength_correction[(cmp::max(cmp::min(len_diff, 4), -4) + 4) as usize] += 1;
    }
    pub fn total_models() -> u32 {
        11
    }
    pub fn check_default_models(&self) -> u32 {
        let mut cnt = 0;
        cnt += count_if(self.tc_count_misprediction, self.tc_count_misprediction[0]);
        cnt += count_if(
            self.tc_bitlength_correction,
            self.tc_bitlength_correction[3],
        );
        cnt += count_if(self.l_count_misprediction, self.l_count_misprediction[0]);
        cnt += count_if(self.d_count_misprediction, self.d_count_misprediction[0]);
        for i in 0..4 {
            cnt += count_if(
                self.ld_type_misprediction[i],
                self.ld_type_misprediction[i][0],
            );
        }
        cnt += count_if(self.ld_type_replacement, 0);
        cnt += count_if(
            self.ld_repeat_count_correction,
            self.ld_repeat_count_correction[1],
        );
        cnt += count_if(
            self.ld_bitlength_correction,
            self.ld_bitlength_correction[4],
        );
        cnt
    }
    fn print(&self) {
        // implementation needed
    }
}

#[derive(Default, Debug)]
pub struct TokenPrediction {
    pub l_it_misprediction: [u32; 2],
    pub ref_misprediction: [u32; 2],
    pub len_correction: [u32; 13],
    pub len_258_irregular_encoding: [u32; 2],
    pub dist_after_len_correction: [u32; 4],
    pub dist_only_correction: [u32; 4],
}

impl TokenPrediction {
    pub fn inc_literal_prediction_wrong(&mut self, mispredicted: bool) {
        self.l_it_misprediction[mispredicted as usize] += 1;
    }
    pub fn inc_reference_prediction_wrong(&mut self, mispredicted: bool) {
        self.ref_misprediction[mispredicted as usize] += 1;
    }
    pub fn inc_length_diff_to_prediction(&mut self, len_diff: i32) {
        self.len_correction[(cmp::max(cmp::min(len_diff, 6), -6) + 6) as usize] += 1;
    }
    pub fn inc_irregular_length_258_encoding(&mut self, irregular: bool) {
        self.len_258_irregular_encoding[irregular as usize] += 1;
    }
    pub fn inc_distance_diff_to_prediction_after_incorrect_length_prediction(
        &mut self,
        len_diff: i32,
    ) {
        self.dist_after_len_correction[cmp::min(len_diff, 3) as usize] += 1;
    }
    pub fn inc_distance_diff_to_prediction_after_correct_length_prediction(
        &mut self,
        len_diff: i32,
    ) {
        self.dist_only_correction[cmp::min(len_diff, 3) as usize] += 1;
    }
    pub fn total_models() -> u32 {
        6
    }
    pub fn check_default_models(&self) -> u32 {
        let mut cnt = 0;
        cnt += count_if(self.l_it_misprediction, self.l_it_misprediction[0]);
        cnt += count_if(self.ref_misprediction, self.ref_misprediction[0]);
        cnt += count_if(self.len_correction, self.len_correction[6]);
        cnt += count_if(
            self.dist_after_len_correction,
            self.dist_after_len_correction[0],
        );
        cnt += count_if(self.dist_only_correction, self.dist_only_correction[0]);
        cnt += count_if(
            self.len_258_irregular_encoding,
            self.len_258_irregular_encoding[0],
        );
        cnt
    }

    pub fn print(&self) {
        // implementation needed
    }
}

impl PreflateStatisticsCounter {
    pub fn print(&self) {
        // implementation needed
    }
}
