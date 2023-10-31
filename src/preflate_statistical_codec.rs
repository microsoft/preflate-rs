use crate::preflate_token::BlockType;

pub struct PreflatePredictionDecoder {
    actions: Vec<PreflateAction>,
    index: usize,
}

pub struct PreflatePredictionEncoder {
    actions: Vec<PreflateAction>,
}

#[derive(Clone)]
pub enum PreflateAction {
    EncodeValue { value: u32, max_bits: u32 },
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
    EncodeTreeCodeBitLengthCorrection(u32, u32),
    EncodeLDTypeCorrection(u32, u32),
    EncodeRepeatCountCorrection(u32, u32, u32),
    EncodeLDBitLengthCorrection(u32, u32),
}

impl PreflatePredictionEncoder {
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),
        }
    }

    pub fn make_decoder(&self) -> PreflatePredictionDecoder {
        PreflatePredictionDecoder {
            actions: self.actions.clone(),
            index: 0,
        }
    }

    pub fn encode_value(&mut self, value: u32, max_bits: u32) {
        self.actions
            .push(PreflateAction::EncodeValue { value, max_bits });
    }

    // Block
    pub fn encode_block_type(&mut self, block_type: BlockType) {
        self.actions
            .push(PreflateAction::EncodeBlockType(block_type));
    }

    pub fn encode_eob_misprediction(&mut self, misprediction: bool) {
        self.actions
            .push(PreflateAction::EncodeEOBMisprediction(misprediction));
    }

    pub fn encode_non_zero_padding(&mut self, non_zero_padding: bool) {
        self.actions
            .push(PreflateAction::EncodeNonZeroPadding(non_zero_padding));
    }

    // Tree codes
    pub fn encode_tree_code_count_misprediction(&mut self, misprediction: bool) {
        self.actions
            .push(PreflateAction::EncodeTreeCodeCountMisprediction(
                misprediction,
            ));
    }

    // Block
    pub fn encode_literal_count_misprediction(&mut self, misprediction: bool) {
        self.actions
            .push(PreflateAction::EncodeLiteralCountMisprediction(
                misprediction,
            ));
    }

    pub fn encode_distance_count_misprediction(&mut self, misprediction: bool) {
        self.actions
            .push(PreflateAction::EncodeDistanceCountMisprediction(
                misprediction,
            ));
    }

    pub fn encode_tree_code_bit_length_correction(&mut self, pred_val: u32, act_val: u32) {
        self.actions
            .push(PreflateAction::EncodeTreeCodeBitLengthCorrection(
                pred_val, act_val,
            ));
    }

    pub fn encode_ld_type_correction(&mut self, pred_val: u32, act_val: u32) {
        self.actions
            .push(PreflateAction::EncodeLDTypeCorrection(pred_val, act_val));
    }

    pub fn encode_repeat_count_correction(&mut self, pred_val: u32, act_val: u32, ld_type: u32) {
        self.actions
            .push(PreflateAction::EncodeRepeatCountCorrection(
                pred_val, act_val, ld_type,
            ));
    }

    pub fn encode_ld_bit_length_correction(&mut self, pred_val: u32, act_val: u32) {
        self.actions
            .push(PreflateAction::EncodeLDBitLengthCorrection(
                pred_val, act_val,
            ));
    }

    // Token
    pub fn encode_literal_prediction_wrong(&mut self, misprediction: bool) {
        self.actions
            .push(PreflateAction::EncodeLiteralPredictionWrong(misprediction));
    }

    pub fn encode_reference_prediction_wrong(&mut self, misprediction: bool) {
        self.actions
            .push(PreflateAction::EncodeReferencePredictionWrong(
                misprediction,
            ));
    }

    pub fn encode_len_correction(&mut self, pred_val: u32, act_val: u32) {
        self.actions.push(PreflateAction::EncodeLenCorrection(
            act_val.wrapping_sub(pred_val),
        ));
    }

    pub fn encode_dist_only_correction(&mut self, hops: u32) {
        self.actions
            .push(PreflateAction::EncodeDistOnlyCorrection(hops));
    }

    pub fn encode_dist_after_len_correction(&mut self, hops: u32) {
        self.actions
            .push(PreflateAction::EncodeDistAfterLenCorrection(hops));
    }

    pub fn encode_irregular_len_258(&mut self, irregular: bool) {
        self.actions
            .push(PreflateAction::EncodeIrregularLen258(irregular));
    }

    pub fn encode_irregular_len258(&mut self, is_irregular: bool) {
        self.actions
            .push(PreflateAction::EncodeIrregularLen258(is_irregular));
    }
}

impl PreflatePredictionDecoder {
    fn pop(&mut self) -> &PreflateAction {
        self.index += 1;
        &self.actions[self.index - 1]
    }

    pub fn decode_value(&mut self, max_bits_orig: u32) -> u32 {
        if let &PreflateAction::EncodeValue { value, max_bits } = self.pop() {
            assert_eq!(max_bits, max_bits_orig);
            return value;
        }
        unreachable!();
    }

    pub fn decode_block_type(&mut self) -> BlockType {
        if let &PreflateAction::EncodeBlockType(block_type) = self.pop() {
            return block_type;
        }
        unreachable!();
    }

    pub fn decode_eob_misprediction(&mut self) -> bool {
        if let &PreflateAction::EncodeEOBMisprediction(misprediction) = self.pop() {
            return misprediction;
        }
        unreachable!();
    }

    pub fn decode_non_zero_padding(&mut self) -> bool {
        if let &PreflateAction::EncodeNonZeroPadding(non_zero_padding) = self.pop() {
            return non_zero_padding;
        }
        unreachable!();
    }

    pub fn decode_tree_code_count_misprediction(&mut self) -> bool {
        if let &PreflateAction::EncodeTreeCodeCountMisprediction(misprediction) = self.pop() {
            return misprediction;
        }
        unreachable!();
    }

    pub fn decode_literal_count_misprediction(&mut self) -> bool {
        if let &PreflateAction::EncodeLiteralCountMisprediction(misprediction) = self.pop() {
            return misprediction;
        }
        unreachable!();
    }

    pub fn decode_distance_count_misprediction(&mut self) -> bool {
        if let &PreflateAction::EncodeDistanceCountMisprediction(misprediction) = self.pop() {
            return misprediction;
        }
        unreachable!();
    }

    pub fn decode_tree_code_bit_length_correction(&mut self, _predval: u32) -> u32 {
        if let &PreflateAction::EncodeTreeCodeBitLengthCorrection(predval, actval) = self.pop() {
            assert_eq!(predval, _predval);
            return actval;
        }
        unreachable!();
    }

    pub fn decode_ld_type_correction(&mut self, _predtype: u32) -> u32 {
        if let &PreflateAction::EncodeLDTypeCorrection(predtype, acttype) = self.pop() {
            assert_eq!(predtype, _predtype);
            return acttype;
        }
        unreachable!();
    }

    pub fn decode_repeat_count_correction(&mut self, _predval: u32, _ldtype: u32) -> u32 {
        if let &PreflateAction::EncodeRepeatCountCorrection(predval, actval, ldtype) = self.pop() {
            assert_eq!(predval, _predval);
            assert_eq!(ldtype, _ldtype);
            return actval;
        }
        unreachable!();
    }

    pub fn decode_ld_bit_length_correction(&mut self, _predval: u32) -> u32 {
        if let &PreflateAction::EncodeLDBitLengthCorrection(predval, actval) = self.pop() {
            assert_eq!(predval, _predval);
            return actval;
        }
        unreachable!();
    }

    pub fn decode_literal_prediction_wrong(&mut self) -> bool {
        if let &PreflateAction::EncodeLiteralPredictionWrong(misprediction) = self.pop() {
            return misprediction;
        }
        unreachable!();
    }

    pub fn decode_reference_prediction_wrong(&mut self) -> bool {
        if let &PreflateAction::EncodeReferencePredictionWrong(misprediction) = self.pop() {
            return misprediction;
        }
        unreachable!();
    }

    pub fn decode_len_correction(&mut self, predval: u32) -> u32 {
        if let &PreflateAction::EncodeLenCorrection(correction) = self.pop() {
            return predval.wrapping_add(correction);
        }
        unreachable!();
    }

    pub fn decode_dist_only_correction(&mut self) -> u32 {
        if let &PreflateAction::EncodeDistOnlyCorrection(hops) = self.pop() {
            return hops as u32;
        }
        unreachable!();
    }

    pub fn decode_dist_after_len_correction(&mut self) -> u32 {
        if let &PreflateAction::EncodeDistAfterLenCorrection(hops) = self.pop() {
            return hops as u32;
        }
        unreachable!();
    }

    pub fn decode_irregular_len_258(&mut self) -> bool {
        if let &PreflateAction::EncodeIrregularLen258(is_irregular) = self.pop() {
            return is_irregular;
        }
        unreachable!();
    }
}
