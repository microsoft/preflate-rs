/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::cabac::{CabacReader, CabacWriter};
use crate::preflate_error::{ExitCode, PreflateError, Result};

use crate::{
    bit_helper::bit_length,
    statistical_codec::{
        CodecCorrection, CountNonDefaultActions, PredictionDecoder, PredictionEncoder,
    },
};

/// calculates the difference between two values, keeping track
/// of the sign as the lowest bit so that the difference is never negative
pub fn encode_difference(pred_val: u32, act_val: u32) -> u32 {
    if pred_val >= act_val {
        (pred_val - act_val) << 1
    } else {
        ((act_val - pred_val) << 1) | 1
    }
}

/// decodes the result of the previous calculation
pub fn decode_difference(pred_val: u32, encoded_val: u32) -> Result<u32> {
    let value = if encoded_val & 1 == 0 {
        pred_val.checked_sub(encoded_val >> 1)
    } else {
        pred_val.checked_add(encoded_val >> 1)
    };
    value.ok_or_else(|| {
        PreflateError::new(
            ExitCode::InvalidPredictionData,
            "Correction arithmetic overflow",
        )
    })
}

#[test]
fn test_encode_decode_difference() {
    for i in 0..10 {
        assert_eq!(i, decode_difference(0, encode_difference(0, i)).unwrap());
        assert_eq!(i, decode_difference(10, encode_difference(10, i)).unwrap());
        assert_eq!(
            i,
            decode_difference(100, encode_difference(100, i)).unwrap()
        );
    }
}

#[derive(Default)]
struct PredictionCabacContext<CTX> {
    default_signal_ctx: [CTX; CodecCorrection::MAX as usize],

    default_ctx: [[CTX; 32]; CodecCorrection::MAX as usize],
    default_ctx_bits: [[CTX; 32]; CodecCorrection::MAX as usize],

    correction_ctx: [[CTX; 32]; CodecCorrection::MAX as usize],
    correction_ctx_bits: [[CTX; 32]; CodecCorrection::MAX as usize],
    //debug_ops: VecDeque<DebugOps>,
}

impl<CTX> PredictionCabacContext<CTX> {
    fn write_exp_encoded<const N: usize, W: CabacWriter<CTX>>(
        value: u32,
        context: &mut [CTX; N],
        context_bits: &mut [CTX; N],
        writer: &mut W,
    ) {
        let bl = bit_length(value) as usize;

        writer.put_unary_encoded(bl, context).unwrap();

        if bl > 1 {
            writer
                .put_n_bits(value.into(), bl - 1, context_bits)
                .unwrap();
        }
    }

    fn read_exp_value<R: CabacReader<CTX>, const N: usize>(
        context: &mut [CTX; N],
        context_bits: &mut [CTX; N],
        reader: &mut R,
    ) -> Result<u32> {
        let mut bits_found = 0;
        while reader.get(&mut context[bits_found.min(N - 1)])? {
            if bits_found == 32 {
                return Err(PreflateError::new(
                    ExitCode::InvalidPredictionData,
                    "Correction exceeds u32",
                ));
            }
            bits_found += 1;
        }

        Ok(match bits_found {
            0 => 0,
            1 => 1,
            _ => reader.get_n_bits(bits_found - 1, context_bits)? as u32 | (1 << (bits_found - 1)),
        })
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Actions {
    Default(CodecCorrection, u32),
    Correction(CodecCorrection, u32),
}

pub struct PredictionEncoderCabac<W, CTX> {
    context: PredictionCabacContext<CTX>,

    actions: Vec<Actions>,

    last_action: [Option<usize>; CodecCorrection::MAX as usize],

    action_seen: [bool; CodecCorrection::MAX as usize],

    count: CountNonDefaultActions,
    writer: W,
}

impl<W: CabacWriter<CTX>, CTX: Default> PredictionEncoderCabac<W, CTX> {
    pub fn new(writer: W) -> Self {
        Self {
            context: PredictionCabacContext::<CTX>::default(),
            writer,
            actions: Default::default(),
            last_action: Default::default(),
            count: CountNonDefaultActions::default(),
            action_seen: Default::default(),
        }
    }

    /// for debugging
    #[allow(dead_code)]
    pub fn print(&self) {
        self.count.print();
    }
}

impl<W: CabacWriter<CTX>, CTX: Default> PredictionEncoder for PredictionEncoderCabac<W, CTX> {
    fn encode_verify_state(&mut self, _message: &'static str, _checksum: u64) {}

    fn encode_correction(&mut self, c: CodecCorrection, value: u32) {
        let i = c as usize;

        // if it is a non-zero correction, then we just insert it
        if value != 0 {
            self.last_action[i] = Some(self.actions.len());
            self.actions.push(Actions::Correction(c, value));
            self.action_seen[i] = true;

            self.count.record_correction(c, value);
            return;
        }

        // otherwise we look to see if the last action was a default action
        // and if so, just increment it
        if let Some(l) = self.last_action[i] {
            let a = &mut self.actions[l];
            if let Actions::Default(_, x) = a {
                *x += 1;
                return;
            }
        }

        // otherwise we add a new default action
        self.last_action[c as usize] = Some(self.actions.len());
        self.actions.push(Actions::Default(c, 1));
    }

    fn finish(&mut self) {
        // Now that we've collected everything, we can write out the actions
        // in the correct order so that the callers can just read them in order
        //
        // This is necessary since the reads are done the first time we need
        // something, so we can't write them out in the same order that we get them.

        // first write the bit set of things we've seen so we can completely exclude
        let mut actions_seen_ctx = CTX::default();
        for &s in self.action_seen.iter() {
            self.writer.put(s, &mut actions_seen_ctx).unwrap();
        }

        // now write all the actions
        for &a in self.actions.iter() {
            match a {
                Actions::Default(c, value) => {
                    let i = c as usize;

                    if self.action_seen[i] {
                        self.writer
                            .put(true, &mut self.context.default_signal_ctx[i])
                            .unwrap();

                        PredictionCabacContext::write_exp_encoded(
                            value - 1,
                            &mut self.context.default_ctx[i],
                            &mut self.context.default_ctx_bits[i],
                            &mut self.writer,
                        );
                    }
                }
                Actions::Correction(c, value) => {
                    let i = c as usize;
                    self.writer
                        .put(false, &mut self.context.default_signal_ctx[i])
                        .unwrap();
                    PredictionCabacContext::write_exp_encoded(
                        value - 1,
                        &mut self.context.correction_ctx[i],
                        &mut self.context.correction_ctx_bits[i],
                        &mut self.writer,
                    );
                }
            }
        }

        self.writer.finish().unwrap();
    }
}

pub struct PredictionDecoderCabac<R, CTX> {
    context: PredictionCabacContext<CTX>,
    reader: R,

    actions_seen: [bool; CodecCorrection::MAX as usize],
    default_actions: [u32; CodecCorrection::MAX as usize],
}

impl<R: CabacReader<CTX>, CTX: Default> PredictionDecoderCabac<R, CTX> {
    pub fn new(mut reader: R) -> Result<Self> {
        let mut actions_seen = [false; CodecCorrection::MAX as usize];
        let mut actions_seen_ctx = CTX::default();
        for i in 0..actions_seen.len() {
            actions_seen[i] = reader.get(&mut actions_seen_ctx)?;
        }

        Ok(Self {
            context: PredictionCabacContext::<CTX>::default(),
            default_actions: Default::default(),
            actions_seen,
            reader,
        })
    }

    #[cold]
    fn decode_correction_slow(&mut self, c: usize) -> Result<u32> {
        if self.reader.get(&mut self.context.default_signal_ctx[c])? {
            let value = PredictionCabacContext::read_exp_value(
                &mut self.context.default_ctx[c],
                &mut self.context.default_ctx_bits[c],
                &mut self.reader,
            )?
            .checked_add(1)
            .ok_or_else(|| {
                PreflateError::new(
                    ExitCode::InvalidPredictionData,
                    "Correction run exceeds u32",
                )
            })?;

            self.default_actions[c] = value - 1;
            return Ok(0);
        } else {
            let value = PredictionCabacContext::read_exp_value(
                &mut self.context.correction_ctx[c],
                &mut self.context.correction_ctx_bits[c],
                &mut self.reader,
            )?
            .checked_add(1)
            .ok_or_else(|| {
                PreflateError::new(ExitCode::InvalidPredictionData, "Correction exceeds u32")
            })?;

            return Ok(value);
        }
    }
}

impl<R: CabacReader<CTX>, CTX: Default> PredictionDecoder for PredictionDecoderCabac<R, CTX> {
    fn decode_verify_state(&mut self, _message: &'static str, _checksum: u64) {}

    #[inline]
    fn decode_correction(&mut self, correction: CodecCorrection) -> Result<u32> {
        // if the action hasn't been seen at all, then always return 0
        if !self.actions_seen[correction as usize] {
            return Ok(0);
        }

        // otherwise if we still have default actions left, use those
        let c = correction as usize;
        if self.default_actions[c] > 0 {
            self.default_actions[c] -= 1;
            return Ok(0);
        }

        self.decode_correction_slow(c)
    }
}

#[test]
fn roundtree_cabac_decoding() {
    use crate::cabac::vp8::{VP8Reader, VP8Writer};
    use crate::statistical_codec::{CodecAction, drive_encoder, verify_decoder};
    use std::io::Cursor;

    let mut buffer = Vec::new();

    let test_codec_actions = [
        CodecAction::Correction(CodecCorrection::DistanceCountCorrection, 1),
        CodecAction::Correction(CodecCorrection::TokenCount, 100000),
        CodecAction::Correction(CodecCorrection::BlockTypeCorrection, 5),
        CodecAction::Correction(CodecCorrection::DistAfterLenCorrection, 0),
    ];

    let mut encoder = PredictionEncoderCabac::new(VP8Writer::new(&mut buffer).unwrap());

    drive_encoder(&mut encoder, &test_codec_actions);

    encoder.finish();

    let mut decoder =
        PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(&buffer)).unwrap()).unwrap();

    verify_decoder(&mut decoder, &test_codec_actions);
}

#[cfg(test)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Operation {
    Correction(u32, CodecCorrection),
}

#[test]
fn roundtree_cabac_correction() {
    // use the debug version of the cabac writer/reader to make sure that the we don't mix up contexts anywhere
    use crate::cabac::debug::{DebugReader, DebugWriter};
    use std::io::Cursor;

    // generate a random set of operations
    let operations = [
        Operation::Correction(5, CodecCorrection::DistanceCountCorrection),
        Operation::Correction(1, CodecCorrection::BlockTypeCorrection),
        Operation::Correction(2, CodecCorrection::BlockTypeCorrection),
        Operation::Correction(3, CodecCorrection::BlockTypeCorrection),
        Operation::Correction(4, CodecCorrection::BlockTypeCorrection),
        Operation::Correction(0, CodecCorrection::DistAfterLenCorrection),
        Operation::Correction(0, CodecCorrection::DistOnlyCorrection),
        Operation::Correction(7, CodecCorrection::LDTypeCorrection),
        Operation::Correction(9, CodecCorrection::LenCorrection),
        Operation::Correction(0, CodecCorrection::LiteralPredictionWrong),
        Operation::Correction(100000, CodecCorrection::TokenCount),
        Operation::Correction(1, CodecCorrection::ReferencePredictionWrong),
    ];

    let mut buffer = Vec::new();

    let writer = DebugWriter::new(&mut buffer).unwrap();

    let mut encoder = PredictionEncoderCabac::new(writer);

    for &o in operations.iter() {
        match o {
            Operation::Correction(val, context_type) => {
                encoder.encode_correction(context_type, val);
            }
        }
    }

    encoder.finish();

    let reader = DebugReader::new(Cursor::new(&buffer)).unwrap();

    let mut decoder = PredictionDecoderCabac::new(reader).unwrap();

    for (i, &o) in operations.iter().enumerate() {
        match o {
            Operation::Correction(val, context_type) => {
                assert_eq!(
                    val,
                    decoder.decode_correction(context_type).unwrap(),
                    "operation {}",
                    i
                );
            }
        }
    }
}

#[test]
fn roundtrip_cabac_write_value() {
    use crate::cabac::vp8::{VP8Context, VP8Reader, VP8Writer};
    use std::io::Cursor;

    let mut buffer = Vec::new();

    let mut writer = VP8Writer::new(&mut buffer).unwrap();

    let mut context = [
        VP8Context::default(),
        VP8Context::default(),
        VP8Context::default(),
        VP8Context::default(),
    ];

    let mut context_bits = [
        VP8Context::default(),
        VP8Context::default(),
        VP8Context::default(),
        VP8Context::default(),
    ];

    for i in 0..10 {
        PredictionCabacContext::write_exp_encoded(
            i * 13,
            &mut context,
            &mut context_bits,
            &mut writer,
        );
    }

    writer.finish().unwrap();

    let mut reader = VP8Reader::new(Cursor::new(&buffer)).unwrap();
    context = [
        VP8Context::default(),
        VP8Context::default(),
        VP8Context::default(),
        VP8Context::default(),
    ];

    context_bits = [
        VP8Context::default(),
        VP8Context::default(),
        VP8Context::default(),
        VP8Context::default(),
    ];

    for i in 0..10 {
        assert_eq!(
            i * 13,
            PredictionCabacContext::read_exp_value(&mut context, &mut context_bits, &mut reader)
                .unwrap()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cabac::vp8::{VP8Context, VP8Reader, VP8Writer};
    use std::io::{Cursor, Error, ErrorKind, Result as IoResult};

    struct ConstantReader(bool);

    impl CabacReader<()> for ConstantReader {
        fn get_bypass(&mut self) -> IoResult<bool> {
            self.get(&mut ())
        }

        fn get(&mut self, _: &mut ()) -> IoResult<bool> {
            if self.0 {
                Ok(true)
            } else {
                Err(Error::new(ErrorKind::UnexpectedEof, "truncated correction"))
            }
        }
    }

    #[test]
    fn invalid_correction_arithmetic_and_unary_lengths_return_errors() {
        assert!(decode_difference(0, 2).is_err());
        assert!(decode_difference(u32::MAX, 3).is_err());
        assert!(
            PredictionCabacContext::read_exp_value(
                &mut [(); 32],
                &mut [(); 32],
                &mut ConstantReader(true),
            )
            .is_err()
        );
        assert!(PredictionDecoderCabac::new(ConstantReader(false)).is_err());
    }

    #[test]
    fn full_width_correction_values_roundtrip() {
        let values = [0, 1, 1 << 31, u32::MAX];
        let mut bytes = Vec::new();
        let mut writer = VP8Writer::new(&mut bytes).unwrap();
        let mut context = [VP8Context::default(); 32];
        let mut bits = context;
        for value in values {
            PredictionCabacContext::write_exp_encoded(value, &mut context, &mut bits, &mut writer);
        }
        writer.finish().unwrap();
        let mut reader = VP8Reader::new(Cursor::new(&bytes)).unwrap();
        context = [VP8Context::default(); 32];
        bits = context;
        for value in values {
            assert_eq!(
                PredictionCabacContext::read_exp_value(&mut context, &mut bits, &mut reader)
                    .unwrap(),
                value
            );
        }
    }
}
