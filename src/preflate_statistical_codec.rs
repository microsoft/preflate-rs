use std::cmp;

use crate::{huffman_decoder::TreeCodeType, preflate_token::BlockType};

pub struct PreflatePredictionDecoder {
    actions: Vec<PreflateAction>,
    index: usize,
}

#[derive(Default)]
pub struct PreflatePredictionEncoder {
    actions: Vec<PreflateAction>,

    encode_eob_misprediction: u32,
    non_zero_padding: u32,

    // Tree codes
    tree_code_count_misprediction: u32,
    literal_count_misprediction: u32,
    distance_count_misprediction: u32,
    tree_code_bit_length_correction: [u32; 4],
    ld_type_correction: [u32; 4],
    repeat_count_correction: [u32; 4],
    ld_bit_length_correction: [u32; 4],

    // Token
    literal_prediction_wrong: u32,
    reference_prediction_wrong: u32,
    len_correction: [u32; 4],
    dist_only_correction: [u32; 4],
    dist_after_len_correction: [u32; 4],

    irregular_len_258: u32,
}

#[derive(Clone)]
pub enum PreflateAction {
    EncodeValue { value: u16, max_bits: u8 },
    EncodeBlockType(BlockType),
    EncodeEOBMisprediction(bool),
    EncodeNonZeroPadding(bool),
    EncodeLiteralPredictionWrong(bool),
    EncodeReferencePredictionWrong(bool),
    EncodeLenCorrection(u32),
    EncodeDistOnlyCorrection(u32),
    EncodeDistAfterLenCorrection(u32),
    EncodeIrregularLen258(bool),

    EncodeTreeCodeCountMisprediction(bool),
    EncodeLiteralCountMisprediction(bool),
    EncodeDistanceCountMisprediction(bool),
    EncodeTreeCodeBitLengthCorrection(u8, u8),
    EncodeLDTypeCorrection(TreeCodeType, TreeCodeType),
    EncodeRepeatCountCorrection(u8, u8, TreeCodeType),
    EncodeLDBitLengthCorrection(u8, u8),
}

pub trait PredictionEncoder {
    fn encode_value(&mut self, value: u16, max_bits: u8);

    // Block
    fn encode_block_type(&mut self, block_type: BlockType);

    fn encode_eob_misprediction(&mut self, misprediction: bool);

    fn encode_non_zero_padding(&mut self, non_zero_padding: bool);

    // Tree codes
    fn encode_tree_code_count_misprediction(&mut self, misprediction: bool);

    fn encode_literal_count_misprediction(&mut self, misprediction: bool);

    fn encode_distance_count_misprediction(&mut self, misprediction: bool);

    fn encode_tree_code_bit_length_correction(&mut self, pred_val: u8, act_val: u8);

    fn encode_ld_type_correction(&mut self, pred_val: TreeCodeType, act_val: TreeCodeType);

    fn encode_repeat_count_correction(&mut self, pred_val: u8, act_val: u8, ld_type: TreeCodeType);
    fn encode_ld_bit_length_correction(&mut self, pred_val: u8, act_val: u8);

    // Token
    fn encode_literal_prediction_wrong(&mut self, misprediction: bool);

    fn encode_reference_prediction_wrong(&mut self, misprediction: bool);

    fn encode_len_correction(&mut self, pred_val: u32, act_val: u32);

    fn encode_dist_only_correction(&mut self, hops: u32);

    fn encode_dist_after_len_correction(&mut self, hops: u32);

    fn encode_irregular_len_258(&mut self, irregular: bool);
}

impl PreflatePredictionEncoder {
    pub fn make_decoder(&self) -> PreflatePredictionDecoder {
        PreflatePredictionDecoder {
            actions: self.actions.clone(),
            index: 0,
        }
    }

    pub fn print(&self) {
        print_if_nz("encode_eob_misprediction", self.encode_eob_misprediction);
        print_if_nz("non_zero_padding", self.non_zero_padding);

        print_if_nz(
            "literal_count_misprediction",
            self.literal_count_misprediction,
        );
        print_if_nz(
            "distance_count_misprediction",
            self.distance_count_misprediction,
        );
        print_if_nz(
            "tree_code_count_misprediction",
            self.tree_code_count_misprediction,
        );
        print_if_nz(
            "tree_code_bit_length_correction",
            count_wrong(&self.tree_code_bit_length_correction),
        );
        print_if_nz("ld_type_correction", count_wrong(&self.ld_type_correction));
        print_if_nz(
            "repeat_count_correction",
            count_wrong(&self.repeat_count_correction),
        );
        print_if_nz(
            "ld_bit_length_correction",
            count_wrong(&self.ld_bit_length_correction),
        );
        print_if_nz("t:literal_prediction_wrong", self.literal_prediction_wrong);
        print_if_nz(
            "t:reference_prediction_wrong",
            self.reference_prediction_wrong,
        );
        print_if_nz("t:len_correction", count_wrong(&self.len_correction));
        print_if_nz(
            "t:dist_only_correction",
            count_wrong(&self.dist_only_correction),
        );
        print_if_nz(
            "t:dist_after_len_correction",
            count_wrong(&self.dist_after_len_correction),
        );
        print_if_nz("t:irregular_len_258", self.irregular_len_258);
    }
}

fn print_if_nz(name: &str, val: u32) {
    if val != 0 {
        println!("{}: {}", name, val);
    }
}

/// counts the number of wrong predictions
fn count_wrong<const N: usize>(pred: &[u32; N]) -> u32 {
    pred[..].iter().sum::<u32>() - pred[N / 2]
}

fn inc_pred<const N: usize>(pred_val: u32, act_val: u32, pred: &mut [u32; N]) {
    let diff = (act_val as i32)
        .wrapping_sub(pred_val as i32)
        .wrapping_add(N as i32 / 2);
    pred[cmp::min(cmp::max(diff, 0), N as i32 - 1) as usize] += 1;
}

impl PredictionEncoder for PreflatePredictionEncoder {
    fn encode_value(&mut self, value: u16, max_bits: u8) {
        self.actions
            .push(PreflateAction::EncodeValue { value, max_bits });
    }

    // Block
    fn encode_block_type(&mut self, block_type: BlockType) {
        self.actions
            .push(PreflateAction::EncodeBlockType(block_type));
    }

    fn encode_eob_misprediction(&mut self, misprediction: bool) {
        self.actions
            .push(PreflateAction::EncodeEOBMisprediction(misprediction));
        if misprediction {
            self.encode_eob_misprediction += 1;
        }
    }

    fn encode_non_zero_padding(&mut self, non_zero_padding: bool) {
        self.actions
            .push(PreflateAction::EncodeNonZeroPadding(non_zero_padding));

        if non_zero_padding {
            self.non_zero_padding += 1;
        }
    }

    // Tree codes
    fn encode_tree_code_count_misprediction(&mut self, misprediction: bool) {
        self.actions
            .push(PreflateAction::EncodeTreeCodeCountMisprediction(
                misprediction,
            ));

        if misprediction {
            self.tree_code_count_misprediction += 1;
        }
    }

    fn encode_literal_count_misprediction(&mut self, misprediction: bool) {
        self.actions
            .push(PreflateAction::EncodeLiteralCountMisprediction(
                misprediction,
            ));

        if misprediction {
            self.literal_count_misprediction += 1;
        }
    }

    fn encode_distance_count_misprediction(&mut self, misprediction: bool) {
        self.actions
            .push(PreflateAction::EncodeDistanceCountMisprediction(
                misprediction,
            ));

        if misprediction {
            self.distance_count_misprediction += 1;
        }
    }

    fn encode_tree_code_bit_length_correction(&mut self, pred_val: u8, act_val: u8) {
        self.actions
            .push(PreflateAction::EncodeTreeCodeBitLengthCorrection(
                pred_val, act_val,
            ));

        inc_pred(
            pred_val.into(),
            act_val.into(),
            &mut self.tree_code_bit_length_correction,
        );
    }

    fn encode_ld_type_correction(&mut self, pred_val: TreeCodeType, act_val: TreeCodeType) {
        self.actions
            .push(PreflateAction::EncodeLDTypeCorrection(pred_val, act_val));

        inc_pred(
            pred_val as u32,
            act_val as u32,
            &mut self.ld_type_correction,
        );
    }

    fn encode_repeat_count_correction(&mut self, pred_val: u8, act_val: u8, ld_type: TreeCodeType) {
        self.actions
            .push(PreflateAction::EncodeRepeatCountCorrection(
                pred_val, act_val, ld_type,
            ));

        inc_pred(
            pred_val.into(),
            act_val.into(),
            &mut self.repeat_count_correction,
        );
    }

    fn encode_ld_bit_length_correction(&mut self, pred_val: u8, act_val: u8) {
        self.actions
            .push(PreflateAction::EncodeLDBitLengthCorrection(
                pred_val, act_val,
            ));

        inc_pred(
            pred_val.into(),
            act_val.into(),
            &mut self.ld_bit_length_correction,
        );
    }

    // Token
    fn encode_literal_prediction_wrong(&mut self, misprediction: bool) {
        self.actions
            .push(PreflateAction::EncodeLiteralPredictionWrong(misprediction));

        if misprediction {
            self.literal_prediction_wrong += 1;
        }
    }

    fn encode_reference_prediction_wrong(&mut self, misprediction: bool) {
        self.actions
            .push(PreflateAction::EncodeReferencePredictionWrong(
                misprediction,
            ));

        if misprediction {
            self.reference_prediction_wrong += 1;
        }
    }

    fn encode_len_correction(&mut self, pred_val: u32, act_val: u32) {
        self.actions.push(PreflateAction::EncodeLenCorrection(
            act_val.wrapping_sub(pred_val),
        ));

        inc_pred(pred_val.into(), act_val.into(), &mut self.len_correction);
    }

    fn encode_dist_only_correction(&mut self, hops: u32) {
        self.actions
            .push(PreflateAction::EncodeDistOnlyCorrection(hops));

        inc_pred(0, hops, &mut self.dist_only_correction);
    }

    fn encode_dist_after_len_correction(&mut self, hops: u32) {
        self.actions
            .push(PreflateAction::EncodeDistAfterLenCorrection(hops));

        inc_pred(0, hops, &mut self.dist_after_len_correction);
    }

    fn encode_irregular_len_258(&mut self, irregular: bool) {
        self.actions
            .push(PreflateAction::EncodeIrregularLen258(irregular));

        if irregular {
            self.irregular_len_258 += 1;
        }
    }
}

pub struct AssertEmptyEncoder {}

impl PredictionEncoder for AssertEmptyEncoder {
    fn encode_value(&mut self, _value: u16, _max_bits: u8) {
        unreachable!();
    }

    fn encode_block_type(&mut self, _block_type: BlockType) {
        unreachable!();
    }

    fn encode_eob_misprediction(&mut self, misprediction: bool) {
        assert!(!misprediction);
    }

    fn encode_non_zero_padding(&mut self, non_zero_padding: bool) {
        assert!(!non_zero_padding);
    }

    fn encode_tree_code_count_misprediction(&mut self, misprediction: bool) {
        assert!(!misprediction);
    }

    fn encode_literal_count_misprediction(&mut self, misprediction: bool) {
        assert!(!misprediction);
    }

    fn encode_distance_count_misprediction(&mut self, misprediction: bool) {
        assert!(!misprediction);
    }

    fn encode_tree_code_bit_length_correction(&mut self, pred_val: u8, act_val: u8) {
        assert_eq!(pred_val, act_val);
    }

    fn encode_ld_type_correction(&mut self, pred_val: TreeCodeType, act_val: TreeCodeType) {
        assert_eq!(pred_val, act_val);
    }

    fn encode_repeat_count_correction(
        &mut self,
        pred_val: u8,
        act_val: u8,
        _ld_type: TreeCodeType,
    ) {
        assert_eq!(pred_val, act_val);
    }

    fn encode_ld_bit_length_correction(&mut self, pred_val: u8, act_val: u8) {
        assert_eq!(pred_val, act_val);
    }

    fn encode_literal_prediction_wrong(&mut self, misprediction: bool) {
        assert!(!misprediction);
    }

    fn encode_reference_prediction_wrong(&mut self, misprediction: bool) {
        assert!(!misprediction);
    }

    fn encode_len_correction(&mut self, _pred_val: u32, _act_val: u32) {
        unreachable!();
    }

    fn encode_dist_only_correction(&mut self, _hops: u32) {
        unreachable!();
    }

    fn encode_dist_after_len_correction(&mut self, _hops: u32) {
        unreachable!();
    }

    fn encode_irregular_len_258(&mut self, irregular: bool) {
        assert!(!irregular);
    }
}

pub trait PredictionDecoder {
    fn decode_value(&mut self, max_bits_orig: u8) -> u16;
    fn decode_block_type(&mut self) -> BlockType;
    fn decode_eob_misprediction(&mut self) -> bool;
    fn decode_non_zero_padding(&mut self) -> bool;
    fn decode_tree_code_count_misprediction(&mut self) -> bool;
    fn decode_literal_count_misprediction(&mut self) -> bool;
    fn decode_distance_count_misprediction(&mut self) -> bool;
    fn decode_tree_code_bit_length_correction(&mut self, _predval: u8) -> u8;
    fn decode_ld_type_correction(&mut self, _predtype: TreeCodeType) -> TreeCodeType;
    fn decode_repeat_count_correction(&mut self, _predval: u8, _ldtype: TreeCodeType) -> u8;
    fn decode_ld_bit_length_correction(&mut self, _predval: u8) -> u8;
    fn decode_literal_prediction_wrong(&mut self) -> bool;
    fn decode_reference_prediction_wrong(&mut self) -> bool;
    fn decode_len_correction(&mut self, predval: u32) -> u32;
    fn decode_dist_only_correction(&mut self) -> u32;
    fn decode_dist_after_len_correction(&mut self) -> u32;
    fn decode_irregular_len_258(&mut self) -> bool;
}

/// Null decode that only returns the default values
pub struct EmptyDecoder {}

impl PredictionDecoder for EmptyDecoder {
    fn decode_value(&mut self, _max_bits_orig: u8) -> u16 {
        unreachable!();
    }
    fn decode_block_type(&mut self) -> BlockType {
        BlockType::Stored
    }
    fn decode_eob_misprediction(&mut self) -> bool {
        false
    }
    fn decode_non_zero_padding(&mut self) -> bool {
        false
    }
    fn decode_tree_code_count_misprediction(&mut self) -> bool {
        false
    }
    fn decode_literal_count_misprediction(&mut self) -> bool {
        false
    }
    fn decode_distance_count_misprediction(&mut self) -> bool {
        false
    }
    fn decode_tree_code_bit_length_correction(&mut self, predval: u8) -> u8 {
        predval
    }
    fn decode_ld_type_correction(&mut self, predtype: TreeCodeType) -> TreeCodeType {
        predtype
    }
    fn decode_repeat_count_correction(&mut self, predval: u8, ldtype: TreeCodeType) -> u8 {
        predval
    }
    fn decode_ld_bit_length_correction(&mut self, predval: u8) -> u8 {
        predval
    }
    fn decode_literal_prediction_wrong(&mut self) -> bool {
        false
    }
    fn decode_reference_prediction_wrong(&mut self) -> bool {
        false
    }
    fn decode_len_correction(&mut self, predval: u32) -> u32 {
        predval
    }
    fn decode_dist_only_correction(&mut self) -> u32 {
        unreachable!();
    }
    fn decode_dist_after_len_correction(&mut self) -> u32 {
        unreachable!();
    }
    fn decode_irregular_len_258(&mut self) -> bool {
        false
    }
}

impl PreflatePredictionDecoder {
    fn pop(&mut self) -> &PreflateAction {
        self.index += 1;
        &self.actions[self.index - 1]
    }
}

impl PredictionDecoder for PreflatePredictionDecoder {
    fn decode_value(&mut self, max_bits_orig: u8) -> u16 {
        if let &PreflateAction::EncodeValue { value, max_bits } = self.pop() {
            assert_eq!(max_bits, max_bits_orig);
            return value;
        }
        unreachable!();
    }

    fn decode_block_type(&mut self) -> BlockType {
        if let &PreflateAction::EncodeBlockType(block_type) = self.pop() {
            return block_type;
        }
        unreachable!();
    }

    fn decode_eob_misprediction(&mut self) -> bool {
        if let &PreflateAction::EncodeEOBMisprediction(misprediction) = self.pop() {
            return misprediction;
        }
        unreachable!();
    }

    fn decode_non_zero_padding(&mut self) -> bool {
        if let &PreflateAction::EncodeNonZeroPadding(non_zero_padding) = self.pop() {
            return non_zero_padding;
        }
        unreachable!();
    }

    fn decode_tree_code_count_misprediction(&mut self) -> bool {
        if let &PreflateAction::EncodeTreeCodeCountMisprediction(misprediction) = self.pop() {
            return misprediction;
        }
        unreachable!();
    }

    fn decode_literal_count_misprediction(&mut self) -> bool {
        if let &PreflateAction::EncodeLiteralCountMisprediction(misprediction) = self.pop() {
            return misprediction;
        }
        unreachable!();
    }

    fn decode_distance_count_misprediction(&mut self) -> bool {
        if let &PreflateAction::EncodeDistanceCountMisprediction(misprediction) = self.pop() {
            return misprediction;
        }
        unreachable!();
    }

    fn decode_tree_code_bit_length_correction(&mut self, _predval: u8) -> u8 {
        if let &PreflateAction::EncodeTreeCodeBitLengthCorrection(predval, actval) = self.pop() {
            assert_eq!(predval, _predval);
            return actval;
        }
        unreachable!();
    }

    fn decode_ld_type_correction(&mut self, _predtype: TreeCodeType) -> TreeCodeType {
        if let &PreflateAction::EncodeLDTypeCorrection(predtype, acttype) = self.pop() {
            assert_eq!(predtype, _predtype);
            return acttype;
        }
        unreachable!();
    }

    fn decode_repeat_count_correction(&mut self, _predval: u8, _ldtype: TreeCodeType) -> u8 {
        if let &PreflateAction::EncodeRepeatCountCorrection(predval, actval, ldtype) = self.pop() {
            assert_eq!(predval, _predval);
            assert_eq!(ldtype, _ldtype);
            return actval;
        }
        unreachable!();
    }

    fn decode_ld_bit_length_correction(&mut self, _predval: u8) -> u8 {
        if let &PreflateAction::EncodeLDBitLengthCorrection(predval, actval) = self.pop() {
            assert_eq!(predval, _predval);
            return actval;
        }
        unreachable!();
    }

    fn decode_literal_prediction_wrong(&mut self) -> bool {
        if let &PreflateAction::EncodeLiteralPredictionWrong(misprediction) = self.pop() {
            return misprediction;
        }
        unreachable!();
    }

    fn decode_reference_prediction_wrong(&mut self) -> bool {
        if let &PreflateAction::EncodeReferencePredictionWrong(misprediction) = self.pop() {
            return misprediction;
        }
        unreachable!();
    }

    fn decode_len_correction(&mut self, predval: u32) -> u32 {
        if let &PreflateAction::EncodeLenCorrection(correction) = self.pop() {
            return predval.wrapping_add(correction);
        }
        unreachable!();
    }

    fn decode_dist_only_correction(&mut self) -> u32 {
        if let &PreflateAction::EncodeDistOnlyCorrection(hops) = self.pop() {
            return hops as u32;
        }
        unreachable!();
    }

    fn decode_dist_after_len_correction(&mut self) -> u32 {
        if let &PreflateAction::EncodeDistAfterLenCorrection(hops) = self.pop() {
            return hops as u32;
        }
        unreachable!();
    }

    fn decode_irregular_len_258(&mut self) -> bool {
        if let &PreflateAction::EncodeIrregularLen258(is_irregular) = self.pop() {
            return is_irregular;
        }
        unreachable!();
    }
}
