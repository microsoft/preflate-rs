use std::{cmp, default};

use crate::{bit_helper::DebugHash, huffman_encoding::TreeCodeType, preflate_token::BlockType};

pub struct PreflatePredictionDecoder {
    actions: Vec<PreflateAction>,
    index: usize,
    default_actions_left: u32,
    verify: bool,
}

#[derive(Default)]
pub struct PreflatePredictionEncoder {
    actions: Vec<PreflateAction>,
    verify: bool,

    encode_eob_misprediction: u32,
    encode_eof_misprediction: u32,
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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PreflateAction {
    Default(u32),
    Value { value: u16, max_bits: u8 },
    BlockType(BlockType),
    EOBMisprediction,
    EOFMisprediction,
    NonZeroPadding,
    LiteralPredictionWrong,
    ReferencePredictionWrong,
    LenCorrection(u8),
    DistOnlyCorrection(u16),
    DistAfterLenCorrection(u16),
    IrregularLen258,

    TreeCodeCountMisprediction,
    LiteralCountMisprediction,
    DistanceCountMisprediction,
    TreeCodeBitLengthCorrection(u8, u8),
    LDTypeCorrection(TreeCodeType, TreeCodeType),
    RepeatCountCorrection(u8, u8),
    LDBitLengthCorrection(u8, u8),
    VerifyState(&'static str, u64),
}

pub trait PredictionEncoder {
    fn encode_value(&mut self, value: u16, max_bits: u8);

    // Block
    fn encode_block_type(&mut self, block_type: BlockType);

    fn encode_eob_misprediction(&mut self, misprediction: bool);

    fn encode_non_zero_padding(&mut self, non_zero_padding: bool);

    fn encode_eof_misprediction(&mut self, misprediction: bool);

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

    fn encode_verify_state<C: FnOnce() -> u64>(&mut self, message: &'static str, checksum: C);
}

impl PreflatePredictionEncoder {
    pub fn make_decoder(&self) -> PreflatePredictionDecoder {
        PreflatePredictionDecoder {
            actions: self.actions.clone(),
            index: 0,
            default_actions_left: 0,
            verify: self.verify,
        }
    }

    pub fn count_nondefault_actions(&self) -> usize {
        self.actions.len()
    }

    fn record_action(
        &mut self,
        default_value: bool,
        action: PreflateAction,
        increment: fn(&mut PreflatePredictionEncoder),
    ) {
        if default_value {
            if let Some(PreflateAction::Default(d)) = self.actions.last_mut() {
                *d += 1;
                return;
            }
            self.actions.push(PreflateAction::Default(1));
        } else {
            self.actions.push(action);
            increment(self);
        }
    }

    pub fn print(&self) {
        println!("nondefault actions: {}", self.count_nondefault_actions());
        print_if_nz("encode_eob_misprediction", self.encode_eob_misprediction);
        print_if_nz("encode_eof_misprediction", self.encode_eof_misprediction);
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
        self.actions.push(PreflateAction::Value { value, max_bits });
    }

    // Block
    fn encode_block_type(&mut self, block_type: BlockType) {
        self.record_action(
            block_type == BlockType::DynamicHuff,
            PreflateAction::BlockType(block_type),
            |_v| {},
        );
    }

    fn encode_eob_misprediction(&mut self, misprediction: bool) {
        self.record_action(!misprediction, PreflateAction::EOBMisprediction, |v| {
            v.encode_eob_misprediction += 1
        });
    }

    fn encode_eof_misprediction(&mut self, misprediction: bool) {
        self.record_action(!misprediction, PreflateAction::EOFMisprediction, |v| {
            v.encode_eof_misprediction += 1
        });
    }

    fn encode_non_zero_padding(&mut self, non_zero_padding: bool) {
        self.record_action(!non_zero_padding, PreflateAction::NonZeroPadding, |v| {
            v.non_zero_padding += 1
        });
    }

    // Tree codes
    fn encode_tree_code_count_misprediction(&mut self, misprediction: bool) {
        self.record_action(
            !misprediction,
            PreflateAction::TreeCodeCountMisprediction,
            |v| v.tree_code_count_misprediction += 1,
        );
    }

    fn encode_literal_count_misprediction(&mut self, misprediction: bool) {
        self.record_action(
            !misprediction,
            PreflateAction::LiteralCountMisprediction,
            |v| v.literal_count_misprediction += 1,
        );
    }

    fn encode_distance_count_misprediction(&mut self, misprediction: bool) {
        self.record_action(
            !misprediction,
            PreflateAction::DistanceCountMisprediction,
            |v| v.distance_count_misprediction += 1,
        );
    }

    fn encode_tree_code_bit_length_correction(&mut self, pred_val: u8, act_val: u8) {
        self.record_action(
            pred_val == act_val,
            PreflateAction::TreeCodeBitLengthCorrection(pred_val, act_val),
            |_v| {},
        );

        inc_pred(
            pred_val.into(),
            act_val.into(),
            &mut self.tree_code_bit_length_correction,
        );
    }

    fn encode_ld_type_correction(&mut self, pred_val: TreeCodeType, act_val: TreeCodeType) {
        self.record_action(
            pred_val == act_val,
            PreflateAction::LDTypeCorrection(pred_val, act_val),
            |_v| {},
        );

        inc_pred(
            pred_val as u32,
            act_val as u32,
            &mut self.ld_type_correction,
        );
    }

    fn encode_repeat_count_correction(
        &mut self,
        pred_val: u8,
        act_val: u8,
        _ld_type: TreeCodeType,
    ) {
        self.record_action(
            pred_val == act_val,
            PreflateAction::RepeatCountCorrection(pred_val, act_val),
            |_v| {},
        );

        inc_pred(
            pred_val.into(),
            act_val.into(),
            &mut self.repeat_count_correction,
        );
    }

    fn encode_ld_bit_length_correction(&mut self, pred_val: u8, act_val: u8) {
        self.record_action(
            pred_val == act_val,
            PreflateAction::LDBitLengthCorrection(pred_val, act_val),
            |_v| {},
        );

        inc_pred(
            pred_val.into(),
            act_val.into(),
            &mut self.ld_bit_length_correction,
        );
    }

    // Token
    fn encode_literal_prediction_wrong(&mut self, misprediction: bool) {
        self.record_action(
            !misprediction,
            PreflateAction::LiteralPredictionWrong,
            |v| v.literal_prediction_wrong += 1,
        );
    }

    fn encode_reference_prediction_wrong(&mut self, misprediction: bool) {
        self.record_action(
            !misprediction,
            PreflateAction::ReferencePredictionWrong,
            |v| v.reference_prediction_wrong += 1,
        );
    }

    fn encode_len_correction(&mut self, pred_val: u32, act_val: u32) {
        self.record_action(
            pred_val == act_val,
            PreflateAction::LenCorrection(((act_val - 3) as u8).wrapping_sub((pred_val - 3) as u8)),
            |_v| {},
        );

        inc_pred(pred_val.into(), act_val.into(), &mut self.len_correction);
    }

    fn encode_dist_only_correction(&mut self, hops: u32) {
        self.record_action(
            hops == 0,
            PreflateAction::DistOnlyCorrection(hops as u16),
            |_v| {},
        );

        inc_pred(0, hops, &mut self.dist_only_correction);
    }

    fn encode_dist_after_len_correction(&mut self, hops: u32) {
        self.record_action(
            hops == 0,
            PreflateAction::DistAfterLenCorrection(hops as u16),
            |_v| {},
        );

        inc_pred(0, hops, &mut self.dist_after_len_correction);
    }

    fn encode_irregular_len_258(&mut self, irregular: bool) {
        self.record_action(!irregular, PreflateAction::IrregularLen258, |v| {
            v.irregular_len_258 += 1
        });
    }

    fn encode_verify_state<C: FnOnce() -> u64>(&mut self, message: &'static str, checksum: C) {
        if self.verify {
            self.actions
                .push(PreflateAction::VerifyState(message, checksum()))
        }
    }
}

pub trait PredictionDecoder {
    fn decode_value(&mut self, max_bits_orig: u8) -> u16;
    fn decode_block_type(&mut self) -> BlockType;
    fn decode_eob_misprediction(&mut self) -> bool;
    fn decode_eof_misprediction(&mut self) -> bool;
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
    fn decode_verify_state<C: FnOnce() -> u64>(&mut self, message: &'static str, checksum: C);
}

impl PreflatePredictionDecoder {
    #[allow(dead_code)]
    pub fn default_decoder() -> Self {
        Self {
            actions: Vec::new(),
            index: 0,
            default_actions_left: 0,
            verify: false,
        }
    }

    fn pop(&mut self) -> Option<PreflateAction> {
        if self.default_actions_left > 0 {
            self.default_actions_left -= 1;
            None
        } else {
            self.index += 1;
            if self.index > self.actions.len() {
                return None;
            } else if let PreflateAction::Default(x) = self.actions[self.index - 1] {
                self.default_actions_left = x - 1;
                None
            } else {
                Some(self.actions[self.index - 1])
            }
        }
    }
}

impl PredictionDecoder for PreflatePredictionDecoder {
    fn decode_value(&mut self, max_bits_orig: u8) -> u16 {
        let x = self.pop().unwrap();
        if let PreflateAction::Value { value, max_bits } = x {
            assert_eq!(max_bits, max_bits_orig);
            return value;
        }
        unreachable!("{:?}", x);
    }

    fn decode_block_type(&mut self) -> BlockType {
        if let Some(x) = self.pop() {
            if let PreflateAction::BlockType(block_type) = x {
                return block_type;
            }
            unreachable!("{:?}", x);
        }
        BlockType::DynamicHuff
    }

    fn decode_eob_misprediction(&mut self) -> bool {
        if let Some(x) = self.pop() {
            if PreflateAction::EOBMisprediction == x {
                return true;
            }
            unreachable!("{:?}", x);
        }
        false
    }

    fn decode_eof_misprediction(&mut self) -> bool {
        if let Some(x) = self.pop() {
            if PreflateAction::EOFMisprediction == x {
                return true;
            }
            unreachable!("{:?}", x);
        }
        false
    }

    fn decode_non_zero_padding(&mut self) -> bool {
        if let Some(x) = self.pop() {
            assert_eq!(x, PreflateAction::NonZeroPadding);
            return true;
        }
        false
    }

    fn decode_tree_code_count_misprediction(&mut self) -> bool {
        if let Some(x) = self.pop() {
            assert_eq!(x, PreflateAction::TreeCodeCountMisprediction);
            return true;
        }
        false
    }

    fn decode_literal_count_misprediction(&mut self) -> bool {
        if let Some(x) = self.pop() {
            assert_eq!(x, PreflateAction::LiteralCountMisprediction);
            return true;
        }
        false
    }

    fn decode_distance_count_misprediction(&mut self) -> bool {
        if let Some(x) = self.pop() {
            assert_eq!(x, PreflateAction::DistanceCountMisprediction);
            return true;
        }
        false
    }

    fn decode_tree_code_bit_length_correction(&mut self, predval: u8) -> u8 {
        if let Some(x) = self.pop() {
            if let PreflateAction::TreeCodeBitLengthCorrection(orig_predval, actval) = x {
                assert_eq!(predval, orig_predval);
                return actval;
            }
            unreachable!("{:?}", x);
        }
        predval
    }

    fn decode_ld_type_correction(&mut self, predtype: TreeCodeType) -> TreeCodeType {
        if let Some(x) = self.pop() {
            if let PreflateAction::LDTypeCorrection(orig_predtype, acttype) = x {
                assert_eq!(predtype, orig_predtype);
                return acttype;
            }
            unreachable!("{:?}", x);
        }
        predtype
    }

    fn decode_repeat_count_correction(&mut self, predval: u8, _ldtype: TreeCodeType) -> u8 {
        if let Some(x) = self.pop() {
            if let PreflateAction::RepeatCountCorrection(orig_predval, actval) = x {
                assert_eq!(orig_predval, predval);
                return actval;
            }
            unreachable!("{:?}", x);
        }
        predval
    }

    fn decode_ld_bit_length_correction(&mut self, predval: u8) -> u8 {
        if let Some(x) = self.pop() {
            if let PreflateAction::LDBitLengthCorrection(orig_predval, actval) = x {
                assert_eq!(orig_predval, predval);
                return actval;
            }
            unreachable!("{:?}", x);
        }
        predval
    }

    fn decode_literal_prediction_wrong(&mut self) -> bool {
        if let Some(x) = self.pop() {
            assert_eq!(
                x,
                PreflateAction::LiteralPredictionWrong,
                "mismatch at index {}",
                self.index
            );
            return true;
        }
        false
    }

    fn decode_reference_prediction_wrong(&mut self) -> bool {
        if let Some(x) = self.pop() {
            assert_eq!(
                x,
                PreflateAction::ReferencePredictionWrong,
                "mismatch at index {}",
                self.index
            );
            return true;
        }
        false
    }

    fn decode_len_correction(&mut self, predval: u32) -> u32 {
        if let Some(x) = self.pop() {
            if let PreflateAction::LenCorrection(correction) = x {
                return ((predval - 3) as u8).wrapping_add(correction) as u32 + 3;
            }
            unreachable!("{:?}", x);
        }
        predval
    }

    fn decode_dist_only_correction(&mut self) -> u32 {
        if let Some(x) = self.pop() {
            if let PreflateAction::DistOnlyCorrection(hops) = x {
                return hops.into();
            }
            unreachable!("{:?}", x);
        }
        0
    }

    fn decode_dist_after_len_correction(&mut self) -> u32 {
        if let Some(x) = self.pop() {
            if let PreflateAction::DistAfterLenCorrection(hops) = x {
                return hops.into();
            }
            unreachable!("{:?}", x);
        }
        0
    }

    fn decode_irregular_len_258(&mut self) -> bool {
        if let Some(x) = self.pop() {
            assert_eq!(x, PreflateAction::IrregularLen258);
        }
        false
    }

    fn decode_verify_state<C: FnOnce() -> u64>(&mut self, message: &'static str, checksum: C) {
        if self.verify {
            if let Some(x) = self.pop() {
                assert_eq!(
                    x,
                    PreflateAction::VerifyState(message, checksum()),
                    "mismatch {} (left encode, right decode)",
                    self.index
                );
            }
        }
    }
}
