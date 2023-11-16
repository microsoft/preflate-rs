use std::io::{Read, Write};

use cabac::{
    traits::{CabacReader, CabacWriter},
    vp8::{VP8Context, VP8Reader, VP8Writer},
};

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
struct PredictionCabacContext {
    default_count: u32,

    /// on the reading side, whether we read the #of defaults or not
    default_read: bool,

    default_encoding: [VP8Context; 4],
    correction: [[VP8Context; 8]; CodecCorrection::MAX as usize],

    non_default_ops_corr: [u32; CodecCorrection::MAX as usize],
    non_default_ops_mis: [u32; CodecMisprediction::MAX as usize],
}

impl PredictionCabacContext {
    pub fn flush_default<W: Write>(&mut self, writer: &mut VP8Writer<W>) {
        if self.default_count > 0 {
            Self::write_value(self.default_count, 32, &mut self.default_encoding, writer);
            self.default_count = 0;
        }
    }

    pub fn write_value_bypass<W: Write>(value: u32, max_bits: u8, writer: &mut VP8Writer<W>) {
        for i in (0..max_bits).rev() {
            writer.put_bypass((value >> i) & 1 == 1).unwrap();
        }
    }

    pub fn write_value<const N: usize, W: Write>(
        value: u32,
        max_bits: u8,
        context: &mut [VP8Context; N],
        writer: &mut VP8Writer<W>,
    ) {
        let bl = bit_length(value) as usize;
        debug_assert!(bl <= max_bits as usize);

        for i in 0..bl {
            writer
                .put(true, &mut context[std::cmp::min(N - 1, i)])
                .unwrap();
        }
        if bl < max_bits as usize {
            writer
                .put(false, &mut context[std::cmp::min(N - 1, bl)])
                .unwrap();
        }

        Self::write_value_bypass(value, bl as u8, writer);
    }

    pub fn read_value_bypass<R: Read>(max_bits: u8, reader: &mut VP8Reader<R>) -> u32 {
        let mut retval = 0;
        for _i in 0..max_bits {
            retval <<= 1;
            retval |= reader.get_bypass().unwrap() as u32;
        }

        retval
    }

    pub fn read_value<R: Read, const N: usize>(
        max_bits: u8,
        context: &mut [VP8Context; N],
        reader: &mut VP8Reader<R>,
    ) -> u32 {
        let mut bits_found = 0;
        while bits_found < max_bits as usize {
            let bit = reader
                .get(&mut context[std::cmp::min(N - 1, bits_found)])
                .unwrap();
            if !bit {
                break;
            }
            bits_found += 1;
        }

        Self::read_value_bypass(bits_found as u8, reader)
    }

    pub fn encode_misprediction<W: Write>(
        &mut self,
        misprediction: bool,
        context: CodecMisprediction,
        writer: &mut VP8Writer<W>,
    ) {
        if misprediction {
            Self::write_value(self.default_count, 32, &mut self.default_encoding, writer);
            self.default_count = 0;
            self.non_default_ops_mis[context as usize] += 1;
        } else {
            self.default_count += 1;
        }
    }

    pub fn encode_correction<W: Write>(
        &mut self,
        val: u32,
        context: CodecCorrection,
        writer: &mut VP8Writer<W>,
    ) {
        if val != 0 {
            Self::write_value(self.default_count, 32, &mut self.default_encoding, writer);
            self.default_count = 0;
            self.non_default_ops_corr[context as usize] += 1;
            Self::write_value(val, 32, &mut self.correction[context as usize], writer);
        } else {
            self.default_count += 1;
        }
    }

    fn ensure_default_read<R: Read>(&mut self, reader: &mut VP8Reader<R>) {
        if !self.default_read {
            self.default_count = Self::read_value(32, &mut self.default_encoding, reader);
            self.default_read = true;
        }
    }

    pub fn decode_misprediction<R: Read>(
        &mut self,
        _context: CodecMisprediction,
        reader: &mut VP8Reader<R>,
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

    fn decode_correction<R: Read>(
        &mut self,
        context: CodecCorrection,
        reader: &mut VP8Reader<R>,
    ) -> u32 {
        self.ensure_default_read(reader);

        if self.default_count > 0 {
            self.default_count -= 1;
            return 0;
        } else {
            let r = Self::read_value(32, &mut self.correction[context as usize], reader);
            self.default_count = Self::read_value(32, &mut self.default_encoding, reader);
            return r;
        }
    }
}

pub struct PredictionEncoderCabac<W> {
    context: PredictionCabacContext,
    count: CountNonDefaultActions,
    writer: VP8Writer<W>,
}

impl<W: Write> PredictionEncoderCabac<W> {
    pub fn new(writer: W) -> Self {
        Self {
            context: PredictionCabacContext::default(),
            writer: VP8Writer::new(writer).unwrap(),
            count: CountNonDefaultActions::default(),
        }
    }

    pub fn print(&self) {
        self.count.print();
    }
}

impl<W: Write> PredictionEncoder for PredictionEncoderCabac<W> {
    fn encode_value(&mut self, value: u16, max_bits: u8) {
        // flush any defaults that are pending before the value is written, otherwise
        // we won't know how many defaults to skip when reading
        PredictionCabacContext::flush_default(&mut self.context, &mut self.writer);
        PredictionCabacContext::write_value_bypass(value.into(), max_bits, &mut self.writer);
    }

    fn encode_verify_state(&mut self, _message: &'static str, _checksum: u64) {}

    fn encode_correction(&mut self, action: CodecCorrection, value: u32) {
        self.context
            .encode_correction(value, action, &mut self.writer);
    }

    fn encode_misprediction(&mut self, action: CodecMisprediction, value: bool) {
        self.context
            .encode_misprediction(value, action, &mut self.writer);
    }

    fn finish(&mut self) {
        self.context.flush_default(&mut self.writer);
        self.writer.finish().unwrap();
    }
}

pub struct PredictionDecoderCabac<R> {
    context: PredictionCabacContext,
    reader: VP8Reader<R>,
}

impl<R: Read> PredictionDecoderCabac<R> {
    pub fn new(reader: R) -> Self {
        Self {
            context: PredictionCabacContext::default(),
            reader: VP8Reader::new(reader).unwrap(),
        }
    }
}

impl<R: Read> PredictionDecoder for PredictionDecoderCabac<R> {
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
    use std::io::Cursor;

    let mut buffer = Vec::new();

    let test_codec_actions = [
        CodecAction::Value(200, 8),
        CodecAction::Misprediction(CodecMisprediction::DistanceCountMisprediction, true),
        CodecAction::Misprediction(CodecMisprediction::EOBMisprediction, false),
        CodecAction::Correction(CodecCorrection::BlockTypeCorrection, 5),
        CodecAction::Correction(CodecCorrection::DistAfterLenCorrection, 0),
    ];

    let mut encoder = PredictionEncoderCabac::new(&mut buffer);

    drive_encoder(&mut encoder, &test_codec_actions);

    encoder.finish();

    let mut decoder = PredictionDecoderCabac::new(Cursor::new(&buffer));

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
fn roundtree_cabac_write_value() {
    use std::io::Cursor;

    let mut buffer = Vec::new();

    let mut writer = VP8Writer::new(&mut buffer).unwrap();

    let mut context = [
        VP8Context::default(),
        VP8Context::default(),
        VP8Context::default(),
        VP8Context::default(),
    ];

    for i in 0..10 {
        PredictionCabacContext::write_value(i * 13, 32, &mut context, &mut writer);
    }

    writer.finish().unwrap();

    let mut reader = VP8Reader::new(Cursor::new(&buffer)).unwrap();
    context = [
        VP8Context::default(),
        VP8Context::default(),
        VP8Context::default(),
        VP8Context::default(),
    ];

    for i in 0..10 {
        assert_eq!(
            i * 13,
            PredictionCabacContext::read_value(32, &mut context, &mut reader)
        );
    }
}
