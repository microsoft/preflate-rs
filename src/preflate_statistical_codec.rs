use crate::preflate_token::BlockType;

pub struct PreflatePredictionEncoder {}

pub struct PreflatePredictionDecoder {}

impl PreflatePredictionDecoder {
    pub fn decode_value(&mut self, _max_bits: u32) -> u32 {
        unreachable!();
    }

    pub fn decode_block_type(&mut self) -> BlockType {
        unreachable!();
    }

    pub fn decode_eob_misprediction(&mut self) -> bool {
        unreachable!();
    }

    pub fn decode_non_zero_padding(&mut self) -> bool {
        unreachable!();
    }

    pub fn decode_tree_code_count_misprediction(&mut self) -> bool {
        unreachable!();
    }

    pub fn decode_literal_count_misprediction(&mut self) -> bool {
        unreachable!();
    }

    pub fn decode_distance_count_misprediction(&mut self) -> bool {
        unreachable!();
    }

    pub fn decode_tree_code_bit_length_correction(&mut self, _predval: u32) -> u32 {
        unreachable!();
    }

    pub fn decode_ld_type_correction(&mut self, _predtype: u32) -> u32 {
        unreachable!();
    }

    pub fn decode_repeat_count_correction(&mut self, _predval: u32, _ldtype: u32) -> u32 {
        unreachable!();
    }

    pub fn decode_ld_bit_length_correction(&mut self, _predval: u32) -> u32 {
        unreachable!();
    }

    pub fn decode_literal_prediction_wrong(&mut self) -> bool {
        unreachable!();
    }

    pub fn decode_reference_prediction_wrong(&mut self) -> bool {
        unreachable!();
    }

    pub fn decode_len_correction(&mut self, _predval: u32) -> u32 {
        unreachable!();
    }

    pub fn decode_dist_only_correction(&mut self) -> u32 {
        unreachable!();
    }

    pub fn decode_dist_after_len_correction(&mut self) -> u32 {
        unreachable!();
    }

    pub fn decode_irregular_len_258(&mut self) -> bool {
        unreachable!();
    }
}
