use std::{cmp, collections::btree_map::Values};

use crate::{
    bit_helper::{bit_length, DebugHash},
    huffman_encoding::TreeCodeType,
    preflate_token::BlockType,
};

/// boolean misprediction indictions
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CodecMisprediction {
    EOBMisprediction,
    EOFMisprediction,
    NonZeroPadding,
    LiteralPredictionWrong,
    ReferencePredictionWrong,
    IrregularLen258,

    TreeCodeCountMisprediction,
    LiteralCountMisprediction,
    DistanceCountMisprediction,
    MAX,
}

/// correction indictions, which are followed by a 16 bit value
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CodecCorrection {
    BlockTypeCorrection,
    LenCorrection,
    DistOnlyCorrection,
    DistAfterLenCorrection,
    TreeCodeBitLengthCorrection,
    LDTypeCorrection,
    RepeatCountCorrection,
    LDBitLengthCorrection,
    MAX,
}

pub trait PredictionEncoder {
    fn encode_correction(&mut self, action: CodecCorrection, value: u32);
    fn encode_misprediction(&mut self, action: CodecMisprediction, value: bool);
    fn encode_value(&mut self, value: u16, max_bits: u8);

    fn encode_verify_state<C: FnOnce() -> u64>(&mut self, message: &'static str, checksum: C);
}

pub trait PredictionDecoder {
    fn decode_value(&mut self, max_bits_orig: u8) -> u16;
    fn decode_correction(&mut self, correction: CodecCorrection) -> u32;
    fn decode_misprediction(&mut self, misprediction: CodecMisprediction) -> bool;
    fn decode_verify_state<C: FnOnce() -> u64>(&mut self, message: &'static str, checksum: C);
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CodecAction {
    Misprediction(CodecMisprediction, bool),
    Correction(CodecCorrection, u32),
    Value(u16, u8),
    VerifyState(&'static str, u64),
}

#[derive(Default)]
pub struct CountNonDefaultActions {
    pub mispredictions_count: [u32; CodecMisprediction::MAX as usize],
    pub corrections_count: [u32; CodecCorrection::MAX as usize],
}

impl CountNonDefaultActions {
    pub fn record_correction(&mut self, correction: CodecCorrection, value: u32) {
        if value != 0 {
            self.corrections_count[correction as usize] += 1;
        }
    }

    pub fn record_misprediction(&mut self, misprediction: CodecMisprediction, value: bool) {
        if value {
            self.mispredictions_count[misprediction as usize] += 1;
        }
    }

    pub fn print(&self) {
        use CodecCorrection::*;
        use CodecMisprediction::*;

        let corr = [
            BlockTypeCorrection,
            LenCorrection,
            DistOnlyCorrection,
            DistAfterLenCorrection,
            TreeCodeBitLengthCorrection,
            LDTypeCorrection,
            RepeatCountCorrection,
            LDBitLengthCorrection,
        ];

        let mispred = [
            EOBMisprediction,
            EOFMisprediction,
            NonZeroPadding,
            LiteralPredictionWrong,
            ReferencePredictionWrong,
            IrregularLen258,
            TreeCodeCountMisprediction,
            LiteralCountMisprediction,
            DistanceCountMisprediction,
        ];

        for i in corr {
            if self.corrections_count[i as usize] != 0 {
                println!("{:?}: {}", i, self.corrections_count[i as usize]);
            }
        }

        for i in mispred {
            if self.mispredictions_count[i as usize] != 0 {
                println!("{:?}: {}", i, self.mispredictions_count[i as usize]);
            }
        }
    }
}

pub struct PreflatePredictionDecoder {
    actions: Vec<CodecAction>,
    index: usize,
    verify: bool,
}

#[derive(Default)]
pub struct PreflatePredictionEncoder {
    actions: Vec<CodecAction>,
    verify: bool,

    count: CountNonDefaultActions,
}

impl PreflatePredictionEncoder {
    pub fn make_decoder(&self) -> PreflatePredictionDecoder {
        PreflatePredictionDecoder {
            actions: self.actions.clone(),
            index: 0,
            verify: self.verify,
        }
    }

    pub fn print(&self) {
        self.count.print();
    }

    pub fn count_nondefault_actions(&self) -> usize {
        self.actions.len()
    }
}

impl PredictionEncoder for PreflatePredictionEncoder {
    fn encode_value(&mut self, value: u16, max_bits: u8) {
        self.actions.push(CodecAction::Value(value, max_bits));
    }

    fn encode_verify_state<C: FnOnce() -> u64>(&mut self, message: &'static str, checksum: C) {
        if self.verify {
            self.actions
                .push(CodecAction::VerifyState(message, checksum()))
        }
    }

    fn encode_correction(&mut self, action: CodecCorrection, value: u32) {
        self.actions.push(CodecAction::Correction(action, value));
        self.count.record_correction(action, value);
    }

    fn encode_misprediction(&mut self, action: CodecMisprediction, value: bool) {
        self.actions.push(CodecAction::Misprediction(action, value));
        self.count.record_misprediction(action, value)
    }
}

impl PreflatePredictionDecoder {
    fn pop(&mut self) -> Option<CodecAction> {
        if self.index >= self.actions.len() {
            None
        } else {
            self.index += 1;
            Some(self.actions[self.index - 1])
        }
    }
}

impl PredictionDecoder for PreflatePredictionDecoder {
    fn decode_value(&mut self, max_bits_orig: u8) -> u16 {
        let x = self.pop().unwrap();
        if let CodecAction::Value(value, max_bits) = x {
            assert_eq!(max_bits, max_bits_orig);
            return value;
        }
        unreachable!("{:?}", x);
    }

    fn decode_verify_state<C: FnOnce() -> u64>(&mut self, message: &'static str, checksum: C) {
        if self.verify {
            if let Some(x) = self.pop() {
                assert_eq!(
                    x,
                    CodecAction::VerifyState(message, checksum()),
                    "mismatch {} (left encode, right decode)",
                    self.index
                );
            }
        }
    }

    fn decode_correction(&mut self, correction: CodecCorrection) -> u32 {
        let x = self.pop().unwrap();
        if let CodecAction::Correction(c, value) = x {
            assert_eq!(correction, c);
            return value;
        }
        unreachable!("{:?}", x);
    }

    fn decode_misprediction(&mut self, misprediction: CodecMisprediction) -> bool {
        let x = self.pop().unwrap();
        if let CodecAction::Misprediction(m, value) = x {
            assert_eq!(misprediction, m);
            return value;
        }
        unreachable!("{:?}", x);
    }
}

#[cfg(test)]
pub fn drive_encoder<T: PredictionEncoder>(encoder: &mut T, actions: &[CodecAction]) {
    for action in actions {
        match action {
            &CodecAction::Value(value, max_bits) => {
                encoder.encode_value(value, max_bits);
            }
            &CodecAction::Correction(correction, value) => {
                encoder.encode_correction(correction, value);
            }
            &CodecAction::Misprediction(misprediction, value) => {
                encoder.encode_misprediction(misprediction, value);
            }
            &CodecAction::VerifyState(message, checksum) => {
                encoder.encode_verify_state(message, || checksum);
            }
        }
    }
}

pub fn verify_decoder<T: PredictionDecoder>(decoder: &mut T, actions: &[CodecAction]) {
    for action in actions {
        match action {
            &CodecAction::Value(value, max_bits) => {
                let x = decoder.decode_value(max_bits);
                assert_eq!(x, value);
            }
            &CodecAction::Correction(correction, value) => {
                let x = decoder.decode_correction(correction);
                assert_eq!(x, value);
            }
            &CodecAction::Misprediction(misprediction, value) => {
                let x = decoder.decode_misprediction(misprediction);
                assert_eq!(x, value);
            }
            &CodecAction::VerifyState(message, checksum) => {
                decoder.decode_verify_state(message, || checksum);
            }
        }
    }
}

#[cfg(test)]
pub struct DefaultOnlyDecoder {}

#[cfg(test)]
impl PredictionDecoder for DefaultOnlyDecoder {
    fn decode_value(&mut self, max_bits_orig: u8) -> u16 {
        unimplemented!()
    }

    fn decode_correction(&mut self, correction: CodecCorrection) -> u32 {
        0
    }

    fn decode_misprediction(&mut self, misprediction: CodecMisprediction) -> bool {
        false
    }

    fn decode_verify_state<C: FnOnce() -> u64>(&mut self, message: &'static str, checksum: C) {}
}

#[test]
fn test_encode_decode() {}
