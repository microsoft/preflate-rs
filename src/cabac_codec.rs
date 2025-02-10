/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use cabac::traits::{CabacReader, CabacWriter};

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
pub fn decode_difference(pred_val: u32, encoded_val: u32) -> u32 {
    if encoded_val & 1 == 0 {
        pred_val - (encoded_val >> 1)
    } else {
        pred_val + (encoded_val >> 1)
    }
}

#[test]
fn test_encode_decode_difference() {
    for i in 0..10 {
        assert_eq!(i, decode_difference(0, encode_difference(0, i)));
        assert_eq!(i, decode_difference(10, encode_difference(10, i)));
        assert_eq!(i, decode_difference(100, encode_difference(100, i)));
    }
}

#[derive(Default)]
struct PredictionCabacContext<CTX> {
    default_count: u32,

    default_encoding: [CTX; 16],
    default_encoding_nbits: [CTX; 16],
    correction: [[CTX; 8]; CodecCorrection::MAX as usize],
    correction_bits: [[CTX; 8]; CodecCorrection::MAX as usize],

    bypass_bits: u32,
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
                .put_n_bits((value & ((1 << bl) - 1)).into(), bl - 1, context_bits)
                .unwrap();
        }
    }

    fn read_exp_value<R: CabacReader<CTX>, const N: usize>(
        context: &mut [CTX; N],
        context_bits: &mut [CTX; N],
        reader: &mut R,
    ) -> u32 {
        let bits_found = reader.get_unary_encoded(context).unwrap();

        match bits_found {
            0 => 0,
            1 => 1,
            _ => {
                reader.get_n_bits(bits_found - 1, context_bits).unwrap() as u32
                    | (1 << (bits_found - 1))
            }
        }
    }

    fn write_default<W: CabacWriter<CTX>>(&mut self, writer: &mut W) {
        Self::write_exp_encoded(
            self.default_count,
            &mut self.default_encoding,
            &mut self.default_encoding_nbits,
            writer,
        );

        /*self.debug_ops
        .push_back(DebugOps::Default(self.default_count));*/

        self.default_count = 0;
    }

    fn encode_correction<W: CabacWriter<CTX>>(
        &mut self,
        val: u32,
        context: CodecCorrection,
        writer: &mut W,
    ) {
        if self.default_count > 0 {
            self.write_default(writer);
        }

        if val != 0 {
            self.write_default(writer);

            //self.debug_ops.push_back(DebugOps::Correction(val, context));

            Self::write_exp_encoded(
                val,
                &mut self.correction[context as usize],
                &mut self.correction_bits[context as usize],
                writer,
            );
        } else {
            self.default_count += 1;
        }
    }

    fn flush_encode(&mut self, writer: &mut impl CabacWriter<CTX>) {
        if self.default_count > 0 {
            self.write_default(writer);
        }
    }

    fn read_default<R: CabacReader<CTX>>(&mut self, reader: &mut R) {
        let c = Self::read_exp_value(
            &mut self.default_encoding,
            &mut self.default_encoding_nbits,
            reader,
        );

        self.default_count = c;

        //assert_eq!(DebugOps::Default(c), self.debug_ops.pop_front().unwrap());
    }

    fn decode_correction<R: CabacReader<CTX>>(
        &mut self,
        context: CodecCorrection,
        reader: &mut R,
    ) -> u32 {
        if self.default_count == 0 {
            self.read_default(reader);
        }

        if self.default_count > 0 {
            self.default_count -= 1;
            0
        } else {
            /*assert_eq!(
                DebugOps::Correction(r, context),
                self.debug_ops.pop_front().unwrap()
            );*/
            Self::read_exp_value(
                &mut self.correction[context as usize],
                &mut self.correction_bits[context as usize],
                reader,
            )
        }
    }
}

pub struct PredictionEncoderCabac<W, CTX> {
    context: PredictionCabacContext<CTX>,
    count: CountNonDefaultActions,
    writer: W,
}

impl<W: CabacWriter<CTX>, CTX: Default> PredictionEncoderCabac<W, CTX> {
    pub fn new(writer: W) -> Self {
        Self {
            context: PredictionCabacContext::<CTX>::default(),
            writer,
            count: CountNonDefaultActions::default(),
        }
    }

    /// for debugging
    #[allow(dead_code)]
    pub fn print(&self) {
        self.count.print();
        println!("bypass bits: {} bytes", self.context.bypass_bits / 8)
    }
}

impl<W: CabacWriter<CTX>, CTX> PredictionEncoder for PredictionEncoderCabac<W, CTX> {
    fn encode_verify_state(&mut self, _message: &'static str, _checksum: u64) {}

    fn encode_correction(&mut self, action: CodecCorrection, value: u32) {
        self.context
            .encode_correction(value, action, &mut self.writer);
        self.count.record_correction(action, value);
    }

    fn finish(&mut self) {
        self.context.flush_encode(&mut self.writer);
        self.writer.finish().unwrap();
    }
}

pub struct PredictionDecoderCabac<R, CTX> {
    context: PredictionCabacContext<CTX>,
    reader: R,
}

impl<R: CabacReader<CTX>, CTX: Default> PredictionDecoderCabac<R, CTX> {
    pub fn new(reader: R) -> Self {
        Self {
            context: PredictionCabacContext::<CTX>::default(),
            reader,
        }
    }
}

impl<R: CabacReader<CTX>, CTX> PredictionDecoder for PredictionDecoderCabac<R, CTX> {
    fn decode_verify_state(&mut self, _message: &'static str, _checksum: u64) {}

    fn decode_correction(&mut self, correction: CodecCorrection) -> u32 {
        self.context.decode_correction(correction, &mut self.reader)
    }
}

#[test]
fn roundtree_cabac_decoding() {
    use crate::statistical_codec::{drive_encoder, verify_decoder, CodecAction};
    use cabac::vp8::{VP8Reader, VP8Writer};
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

    let mut decoder = PredictionDecoderCabac::new(VP8Reader::new(Cursor::new(&buffer)).unwrap());

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
    use cabac::debug::{DebugReader, DebugWriter};
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
        Operation::Correction(0, CodecCorrection::IrregularLen258),
        Operation::Correction(1, CodecCorrection::ReferencePredictionWrong),
    ];

    let mut buffer = Vec::new();

    let mut context = PredictionCabacContext::default();
    let mut writer = DebugWriter::new(&mut buffer).unwrap();

    for &o in operations.iter() {
        match o {
            Operation::Correction(val, context_type) => {
                context.encode_correction(val, context_type, &mut writer);
            }
        }
    }

    context.flush_encode(&mut writer);
    writer.finish().unwrap();

    context = PredictionCabacContext::default();

    let mut reader = DebugReader::new(Cursor::new(&buffer)).unwrap();

    for (i, &o) in operations.iter().enumerate() {
        match o {
            Operation::Correction(val, context_type) => {
                assert_eq!(
                    val,
                    context.decode_correction(context_type, &mut reader),
                    "operation {}",
                    i
                );
            }
        }
    }
}

#[test]
fn roundtrip_cabac_write_value() {
    use cabac::vp8::{VP8Context, VP8Reader, VP8Writer};
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
        );
    }
}
