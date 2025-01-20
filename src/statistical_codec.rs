/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

/// boolean misprediction indictions
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CodecMisprediction {
    EOFMisprediction,
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
    TokenCount,
    NonZeroPadding,
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

    fn encode_verify_state(&mut self, message: &'static str, checksum: u64);

    fn finish(&mut self);
}

pub trait PredictionDecoder {
    fn decode_value(&mut self, max_bits_orig: u8) -> u16;
    fn decode_correction(&mut self, correction: CodecCorrection) -> u32;
    fn decode_misprediction(&mut self, misprediction: CodecMisprediction) -> bool;
    fn decode_verify_state(&mut self, message: &'static str, checksum: u64);
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
    pub total_non_default: u32,
    pub mispredictions_count: [u32; CodecMisprediction::MAX as usize],
    pub corrections_count: [u32; CodecCorrection::MAX as usize],
}

impl CountNonDefaultActions {
    pub fn record_correction(&mut self, correction: CodecCorrection, value: u32) {
        if value != 0 {
            self.corrections_count[correction as usize] += 1;
            self.total_non_default += 1;
        }
    }

    pub fn record_misprediction(&mut self, misprediction: CodecMisprediction, value: bool) {
        if value {
            self.mispredictions_count[misprediction as usize] += 1;
            self.total_non_default += 1;
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
            NonZeroPadding,
        ];

        let mispred = [
            EOFMisprediction,
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

pub struct VerifyPredictionDecoder {
    actions: Vec<CodecAction>,
    index: usize,
}

#[derive(Default)]
pub struct VerifyPredictionEncoder {
    actions: Vec<CodecAction>,
    count: CountNonDefaultActions,
}

// used for testing mostly
#[allow(dead_code)]
impl VerifyPredictionEncoder {
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),
            count: CountNonDefaultActions::default(),
        }
    }

    pub fn actions(&self) -> Vec<CodecAction> {
        self.actions.clone()
    }

    pub fn print(&self) {
        self.count.print();
    }

    pub fn count_nondefault_actions(&self) -> usize {
        self.count.total_non_default as usize
    }
}

impl PredictionEncoder for VerifyPredictionEncoder {
    fn encode_value(&mut self, value: u16, max_bits: u8) {
        self.actions.push(CodecAction::Value(value, max_bits));
    }

    fn encode_verify_state(&mut self, message: &'static str, checksum: u64) {
        self.actions
            .push(CodecAction::VerifyState(message, checksum));
    }

    fn encode_correction(&mut self, action: CodecCorrection, value: u32) {
        self.actions.push(CodecAction::Correction(action, value));
        self.count.record_correction(action, value);
    }

    fn encode_misprediction(&mut self, action: CodecMisprediction, value: bool) {
        self.actions.push(CodecAction::Misprediction(action, value));
        self.count.record_misprediction(action, value);
    }

    fn finish(&mut self) {}
}

// used for testing mostly
#[allow(dead_code)]
impl VerifyPredictionDecoder {
    pub fn new(actions: Vec<CodecAction>) -> Self {
        Self { actions, index: 0 }
    }

    fn pop(&mut self) -> Option<CodecAction> {
        if self.index >= self.actions.len() {
            None
        } else {
            self.index += 1;
            Some(self.actions[self.index - 1])
        }
    }
}

impl PredictionDecoder for VerifyPredictionDecoder {
    fn decode_value(&mut self, max_bits_orig: u8) -> u16 {
        let x = self.pop().unwrap();
        if let CodecAction::Value(value, max_bits) = x {
            assert_eq!(max_bits, max_bits_orig);
            return value;
        }
        unreachable!("{:?}", x);
    }

    fn decode_verify_state(&mut self, message: &'static str, checksum: u64) {
        let x = self.pop().unwrap();
        assert_eq!(
            x,
            CodecAction::VerifyState(message, checksum),
            "mismatch {} (left encode, right decode)",
            self.index
        );
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
                encoder.encode_verify_state(message, checksum);
            }
        }
    }
}

#[cfg(test)]
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
                decoder.decode_verify_state(message, checksum);
            }
        }
    }
}

// used by tests to ensure that perfect prediction is performed for data
// that we know should be encoded without any mispredictions or corrections
#[cfg(test)]
#[derive(Default)]
pub struct AssertDefaultOnlyEncoder {}

#[cfg(test)]
impl PredictionEncoder for AssertDefaultOnlyEncoder {
    fn encode_correction(&mut self, action: CodecCorrection, value: u32) {
        assert_eq!(0, value, "unexpected correction {:?}", action);
    }

    fn encode_misprediction(&mut self, action: CodecMisprediction, value: bool) {
        assert_eq!(false, value, "unexpected misprediction {:?}", action);
    }

    fn encode_value(&mut self, _value: u16, _max_bits: u8) {}

    fn encode_verify_state(&mut self, _message: &'static str, _checksum: u64) {}

    fn finish(&mut self) {}
}

#[cfg(test)]
#[derive(Default)]
pub struct AssertDefaultOnlyDecoder {}

#[cfg(test)]
impl PredictionDecoder for AssertDefaultOnlyDecoder {
    fn decode_value(&mut self, _max_bits_orig: u8) -> u16 {
        unimplemented!()
    }

    fn decode_correction(&mut self, _correction: CodecCorrection) -> u32 {
        0
    }

    fn decode_misprediction(&mut self, _misprediction: CodecMisprediction) -> bool {
        false
    }

    fn decode_verify_state(&mut self, _message: &'static str, _checksum: u64) {}
}

/// This implements a prediction encoder that tees the input to two different
/// encoders. This allows us to verify that the behavior of two encoders is the same
impl<A, B> PredictionEncoder for (A, B)
where
    A: PredictionEncoder,
    B: PredictionEncoder,
{
    fn encode_value(&mut self, value: u16, max_bits: u8) {
        self.0.encode_value(value, max_bits);
        self.1.encode_value(value, max_bits);
    }

    fn encode_verify_state(&mut self, message: &'static str, checksum: u64) {
        self.0.encode_verify_state(message, checksum);
        self.1.encode_verify_state(message, checksum);
    }

    fn encode_correction(&mut self, action: CodecCorrection, value: u32) {
        self.0.encode_correction(action, value);
        self.1.encode_correction(action, value);
    }

    fn encode_misprediction(&mut self, action: CodecMisprediction, value: bool) {
        self.0.encode_misprediction(action, value);
        self.1.encode_misprediction(action, value);
    }

    fn finish(&mut self) {
        self.0.finish();
        self.1.finish();
    }
}

/// Implement the same for decoders, where we verify that the output
/// is identical for both decoders
impl<A, B> PredictionDecoder for (A, B)
where
    A: PredictionDecoder,
    B: PredictionDecoder,
{
    fn decode_value(&mut self, max_bits_orig: u8) -> u16 {
        let a = self.0.decode_value(max_bits_orig);
        let b = self.1.decode_value(max_bits_orig);
        assert_eq!(a, b);
        a
    }

    fn decode_correction(&mut self, correction: CodecCorrection) -> u32 {
        let a = self.0.decode_correction(correction);
        let b = self.1.decode_correction(correction);
        assert_eq!(a, b);
        a
    }

    fn decode_misprediction(&mut self, misprediction: CodecMisprediction) -> bool {
        let a = self.0.decode_misprediction(misprediction);
        let b = self.1.decode_misprediction(misprediction);
        assert_eq!(a, b);
        a
    }

    fn decode_verify_state(&mut self, message: &'static str, checksum: u64) {
        self.0.decode_verify_state(message, checksum);
        self.1.decode_verify_state(message, checksum);
    }
}
