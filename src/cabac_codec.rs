use cabac::traits::{CabacReader, CabacWriter};

use crate::{
    bit_helper::bit_length,
    statistical_codec::{
        CodecCorrection, CodecMisprediction, CountNonDefaultActions, PredictionDecoder,
        PredictionEncoder,
    },
};

/// calculates the difference between two values, keeping track
/// of the sign as the lowest bit so that the difference is never negative
pub fn encode_difference(pred_val: u32, act_val: u32) -> u32 {
    if pred_val >= act_val {
        return (pred_val - act_val) << 1;
    } else {
        return ((act_val - pred_val) << 1) | 1;
    }
}

/// decodes the result of the previous calculation
pub fn decode_difference(pred_val: u32, encoded_val: u32) -> u32 {
    if encoded_val & 1 == 0 {
        return pred_val - (encoded_val >> 1);
    } else {
        return pred_val + (encoded_val >> 1);
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

    /// on the reading side, whether we read the #of defaults or not
    default_read: bool,

    default_encoding: [CTX; 16],
    default_encoding_nbits: [CTX; 16],
    correction: [[CTX; 8]; CodecCorrection::MAX as usize],
    correction_bits: [[CTX; 8]; CodecCorrection::MAX as usize],

    non_default_ops_corr: [u32; CodecCorrection::MAX as usize],
    non_default_ops_mis: [u32; CodecMisprediction::MAX as usize],

    bypass_bits: u32,
}

impl<CTX> PredictionCabacContext<CTX> {
    pub fn flush_default<W: CabacWriter<CTX>>(&mut self, writer: &mut W) {
        if self.default_count > 0 {
            Self::write_value(
                self.default_count,
                32,
                &mut self.default_encoding,
                &mut self.default_encoding_nbits,
                writer,
            );
            self.default_count = 0;
        }
    }

    pub fn write_value_bypass<W: CabacWriter<CTX>>(value: u32, max_bits: u8, writer: &mut W) {
        for i in (0..max_bits).rev() {
            writer.put_bypass((value >> i) & 1 == 1).unwrap();
        }
    }

    pub fn write_value<const N: usize, W: CabacWriter<CTX>>(
        value: u32,
        max_bits: u8,
        context: &mut [CTX; N],
        context_bits: &mut [CTX; N],
        writer: &mut W,
    ) {
        let bl = bit_length(value) as usize;
        debug_assert!(bl <= max_bits as usize);

        writer.put_unary_encoded(bl, context).unwrap();

        if bl > 1 {
            writer
                .put_n_bits((value & ((1 << bl) - 1)).into(), bl - 1, context_bits)
                .unwrap();
        }
    }

    pub fn read_value_bypass<R: CabacReader<CTX>>(max_bits: u8, reader: &mut R) -> u32 {
        let mut retval = 0;
        for _i in 0..max_bits {
            retval <<= 1;
            retval |= reader.get_bypass().unwrap() as u32;
        }

        retval
    }

    pub fn read_value<R: CabacReader<CTX>, const N: usize>(
        max_bits: u8,
        context: &mut [CTX; N],
        context_bits: &mut [CTX; N],
        reader: &mut R,
    ) -> u32 {
        let mut bits_found = reader.get_unary_encoded(context).unwrap();

        match bits_found {
            0 => 0,
            1 => 1,
            _ => {
                reader.get_n_bits(bits_found - 1, context_bits).unwrap() as u32
                    | (1 << (bits_found - 1))
            }
        }
    }

    pub fn encode_misprediction<W: CabacWriter<CTX>>(
        &mut self,
        misprediction: bool,
        context: CodecMisprediction,
        writer: &mut W,
    ) {
        if misprediction {
            Self::write_value(
                self.default_count,
                32,
                &mut self.default_encoding,
                &mut self.default_encoding_nbits,
                writer,
            );
            self.default_count = 0;
            self.non_default_ops_mis[context as usize] += 1;
        } else {
            self.default_count += 1;
        }
    }

    pub fn encode_correction<W: CabacWriter<CTX>>(
        &mut self,
        val: u32,
        context: CodecCorrection,
        writer: &mut W,
    ) {
        if val != 0 {
            Self::write_value(
                self.default_count,
                32,
                &mut self.default_encoding,
                &mut self.default_encoding_nbits,
                writer,
            );
            self.default_count = 0;
            self.non_default_ops_corr[context as usize] += 1;
            Self::write_value(
                val,
                32,
                &mut self.correction[context as usize],
                &mut self.correction_bits[context as usize],
                writer,
            );
        } else {
            self.default_count += 1;
        }
    }

    fn ensure_default_read<R: CabacReader<CTX>>(&mut self, reader: &mut R) {
        if !self.default_read {
            self.default_count = Self::read_value(
                32,
                &mut self.default_encoding,
                &mut self.default_encoding_nbits,
                reader,
            );
            self.default_read = true;
        }
    }

    pub fn decode_misprediction<R: CabacReader<CTX>>(
        &mut self,
        _context: CodecMisprediction,
        reader: &mut R,
    ) -> bool {
        self.ensure_default_read(reader);

        if self.default_count > 0 {
            self.default_count -= 1;
            return false;
        } else {
            self.default_read = false;
            return true;
        }
    }

    fn decode_correction<R: CabacReader<CTX>>(
        &mut self,
        context: CodecCorrection,
        reader: &mut R,
    ) -> u32 {
        self.ensure_default_read(reader);

        if self.default_count > 0 {
            self.default_count -= 1;
            return 0;
        } else {
            let r = Self::read_value(
                32,
                &mut self.correction[context as usize],
                &mut self.correction_bits[context as usize],
                reader,
            );
            self.default_count = Self::read_value(
                32,
                &mut self.default_encoding,
                &mut self.default_encoding_nbits,
                reader,
            );
            return r;
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
            writer: writer,
            count: CountNonDefaultActions::default(),
        }
    }

    pub fn print(&self) {
        self.count.print();
        println!("bypass bits: {} bytes", self.context.bypass_bits / 8)
    }
}

impl<W: CabacWriter<CTX>, CTX> PredictionEncoder for PredictionEncoderCabac<W, CTX> {
    fn encode_value(&mut self, value: u16, max_bits: u8) {
        // flush any defaults that are pending before the value is written, otherwise
        // we won't know how many defaults to skip when reading
        PredictionCabacContext::flush_default(&mut self.context, &mut self.writer);
        PredictionCabacContext::write_value_bypass(value.into(), max_bits, &mut self.writer);
        self.context.bypass_bits += max_bits as u32;
    }

    fn encode_verify_state(&mut self, _message: &'static str, _checksum: u64) {}

    fn encode_correction(&mut self, action: CodecCorrection, value: u32) {
        self.context
            .encode_correction(value, action, &mut self.writer);
        self.count.record_correction(action, value);
    }

    fn encode_misprediction(&mut self, action: CodecMisprediction, value: bool) {
        self.context
            .encode_misprediction(value, action, &mut self.writer);
        self.count.record_misprediction(action, value);
    }

    fn finish(&mut self) {
        self.context.flush_default(&mut self.writer);
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
            reader: reader,
        }
    }
}

impl<R: CabacReader<CTX>, CTX> PredictionDecoder for PredictionDecoderCabac<R, CTX> {
    fn decode_value(&mut self, max_bits_orig: u8) -> u16 {
        PredictionCabacContext::read_value_bypass(max_bits_orig, &mut self.reader) as u16
    }
    fn decode_verify_state(&mut self, _message: &'static str, _checksum: u64) {}

    fn decode_correction(&mut self, correction: CodecCorrection) -> u32 {
        self.context.decode_correction(correction, &mut self.reader)
    }

    fn decode_misprediction(&mut self, misprediction: CodecMisprediction) -> bool {
        self.context
            .decode_misprediction(misprediction, &mut self.reader)
    }
}

#[test]
fn roundtree_cabac_decoding() {
    use crate::statistical_codec::{drive_encoder, verify_decoder, CodecAction};
    use cabac::vp8::{VP8Context, VP8Reader, VP8Writer};
    use std::io::Cursor;

    let mut buffer = Vec::new();

    let test_codec_actions = [
        CodecAction::Value(200, 8),
        CodecAction::Misprediction(CodecMisprediction::DistanceCountMisprediction, true),
        CodecAction::Misprediction(CodecMisprediction::EOBMisprediction, false),
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
    Misprediction(bool, CodecMisprediction),
}

#[test]
fn roundtree_cabac_correction() {
    use cabac::vp8::{VP8Context, VP8Reader, VP8Writer};
    use std::io::Cursor;

    // generate a random set of operations
    let operations = [
        Operation::Correction(0, CodecCorrection::BlockTypeCorrection),
        Operation::Correction(1, CodecCorrection::BlockTypeCorrection),
        Operation::Correction(2, CodecCorrection::BlockTypeCorrection),
        Operation::Correction(0, CodecCorrection::BlockTypeCorrection),
        Operation::Correction(0, CodecCorrection::BlockTypeCorrection),
        Operation::Correction(0, CodecCorrection::BlockTypeCorrection),
        Operation::Correction(3, CodecCorrection::BlockTypeCorrection),
        Operation::Misprediction(false, CodecMisprediction::DistanceCountMisprediction),
        Operation::Misprediction(false, CodecMisprediction::DistanceCountMisprediction),
        Operation::Misprediction(false, CodecMisprediction::DistanceCountMisprediction),
        Operation::Misprediction(true, CodecMisprediction::DistanceCountMisprediction),
    ];

    let mut buffer = Vec::new();

    let mut context = PredictionCabacContext::default();
    let mut writer = VP8Writer::new(&mut buffer).unwrap();

    for &o in operations.iter() {
        match o {
            Operation::Correction(val, context_type) => {
                context.encode_correction(val, context_type, &mut writer);
            }
            Operation::Misprediction(val, context_type) => {
                context.encode_misprediction(val, context_type, &mut writer);
            }
        }
    }

    context.flush_default(&mut writer);

    writer.finish().unwrap();

    context = PredictionCabacContext::default();
    let mut reader = VP8Reader::new(Cursor::new(&buffer)).unwrap();

    for &o in operations.iter() {
        match o {
            Operation::Correction(val, context_type) => {
                assert_eq!(val, context.decode_correction(context_type, &mut reader));
            }
            Operation::Misprediction(val, context_type) => {
                assert_eq!(val, context.decode_misprediction(context_type, &mut reader));
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
        PredictionCabacContext::write_value(
            i * 13,
            32,
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
            PredictionCabacContext::read_value(32, &mut context, &mut context_bits, &mut reader)
        );
    }
}
