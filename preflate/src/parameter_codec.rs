/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Packed parameter encoding, separate from the executable settings' Rust layout.
//! The wire view and conversions are generated from the authoritative declarations.
//! Integers use compact exponents for powers of two and power-minus-one values,
//! with an exact seven-bit-group literal fallback.

use naia_serde::{BitReader, BitWrite, FileBitWriter, Serde, SerdeErr, UnsignedVariableInteger};

use crate::{
    preflate_error::{ExitCode, PreflateError, Result},
    reconstruction_parameters::ReconstructionParameters,
};

fn power_encoding(value: u64) -> Option<(bool, u32)> {
    if value.is_power_of_two() {
        Some((false, value.trailing_zeros()))
    } else if value & value.wrapping_add(1) == 0 {
        // Zero reuses the redundant power-minus-one representation of one.
        Some((true, value.trailing_ones().saturating_sub(1)))
    } else {
        None
    }
}

pub(crate) fn variable_integer_bit_length(value: u64, width: u32) -> u32 {
    if power_encoding(value).is_some() {
        2 + width.ilog2()
    } else {
        1 + UnsignedVariableInteger::<7>::new(value).bit_length()
    }
}

macro_rules! variable_integer {
    ($name:ident, $inner:ty) => {
        #[derive(Debug, Copy, Clone, PartialEq)]
        struct $name($inner);

        impl From<$inner> for $name {
            fn from(value: $inner) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $inner {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl Serde for $name {
            fn ser(&self, writer: &mut dyn BitWrite) {
                if let Some((minus_one, exponent)) = power_encoding(u64::from(self.0)) {
                    writer.write_bit(true);
                    writer.write_bit(minus_one);
                    for bit in 0..<$inner>::BITS.ilog2() {
                        writer.write_bit(exponent & (1 << bit) != 0);
                    }
                } else {
                    writer.write_bit(false);
                    UnsignedVariableInteger::<7>::new(self.0).ser(writer);
                }
            }

            fn de(reader: &mut BitReader) -> std::result::Result<Self, SerdeErr> {
                if reader.read_bit()? {
                    let minus_one = reader.read_bit()?;
                    let mut exponent = 0u32;
                    for bit in 0..<$inner>::BITS.ilog2() {
                        exponent |= u32::from(reader.read_bit()?) << bit;
                    }
                    let value = if minus_one {
                        if exponent == 0 {
                            0
                        } else {
                            u64::MAX >> (u64::BITS - 1 - exponent)
                        }
                    } else {
                        1u64 << exponent
                    };
                    return <$inner>::try_from(value).map(Self).map_err(|_| SerdeErr);
                }
                let mut value = 0u64;
                for shift in (0..<$inner>::BITS).step_by(7) {
                    let more = reader.read_bit()?;
                    let mut group = 0u64;
                    for bit in 0..7 {
                        group |= u64::from(reader.read_bit()?) << bit;
                    }
                    if group > (u64::MAX >> shift) {
                        return Err(SerdeErr);
                    }
                    value |= group << shift;
                    if !more {
                        if (shift != 0 && group == 0) || power_encoding(value).is_some() {
                            return Err(SerdeErr);
                        }
                        return <$inner>::try_from(value).map(Self).map_err(|_| SerdeErr);
                    }
                }
                Err(SerdeErr)
            }

            fn bit_length(&self) -> u32 {
                variable_integer_bit_length(u64::from(self.0), <$inner>::BITS)
            }
        }
    };
}

variable_integer!(VariableU16, u16);
variable_integer!(VariableU32, u32);
variable_integer!(VariableU64, u64);

mod wire {
    include!(concat!(env!("OUT_DIR"), "/parameter_wire.rs"));
}

fn encode_header(parameters: &ReconstructionParameters, corrections_len: u64) -> Vec<u8> {
    let mut writer = FileBitWriter::new();
    wire::ReconstructionParameters::from(*parameters).ser(&mut writer);
    VariableU64(corrections_len).ser(&mut writer);
    writer.to_vec()
}

pub(crate) fn encode(parameters: &ReconstructionParameters, corrections: &[u8]) -> Vec<u8> {
    let mut result = encode_header(parameters, corrections.len() as u64);
    result.extend_from_slice(corrections);
    result
}

pub(crate) fn decode(data: &[u8]) -> Result<(ReconstructionParameters, &[u8])> {
    let mut reader = BitReader::new(data);
    let invalid = |e| {
        PreflateError::new(
            ExitCode::InvalidCompressedWrapper,
            format!("invalid parameters: {e}"),
        )
    };
    let parameters = wire::ReconstructionParameters::de(&mut reader).map_err(invalid)?;
    let length = VariableU64::de(&mut reader).map_err(invalid)?;
    let bits = parameters.bit_length() + length.bit_length();
    let bytes = bits.div_ceil(8) as usize;
    let (header, corrections) = data.split_at_checked(bytes).ok_or_else(|| {
        PreflateError::new(
            ExitCode::InvalidCompressedWrapper,
            "truncated parameter header",
        )
    })?;
    let padding = bits % 8;
    if padding != 0 && header[bytes - 1] >> padding != 0 {
        return Err(PreflateError::new(
            ExitCode::InvalidCompressedWrapper,
            "nonzero parameter padding",
        ));
    }
    if corrections.len() as u64 != length.0 {
        return Err(PreflateError::new(
            ExitCode::InvalidCompressedWrapper,
            "correction payload length does not match header",
        ));
    }
    Ok((parameters.into(), corrections))
}

#[cfg(test)]
pub(crate) fn encode_parameters(parameters: &ReconstructionParameters) -> Vec<u8> {
    let mut writer = FileBitWriter::new();
    wire::ReconstructionParameters::from(*parameters).ser(&mut writer);
    writer.to_vec()
}

#[cfg(test)]
pub(crate) fn parameter_bit_length(parameters: &ReconstructionParameters) -> u32 {
    wire::ReconstructionParameters::from(*parameters).bit_length()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        parameters::{BlockTypeStrategy, DictionaryAddPolicy, PreflateStrategy},
        reconstruction_parameters::{
            BehaviorSettings, ChainDistancePolicy, ChainParser, InputTailPolicy,
            SourceHistorySettings, WindowBounds,
        },
        token_predictor::tests::zlib_level_1_params,
    };

    fn integer_round_trip<T: Serde + std::fmt::Debug>(value: T, offset: u32) {
        let mut writer = FileBitWriter::new();
        for _ in 0..offset {
            writer.write_bit(true);
        }
        value.ser(&mut writer);
        writer.write_bit(false);
        writer.write_bit(true);
        let data = writer.to_vec();
        assert_eq!(
            data.len(),
            (value.bit_length() + offset + 2).div_ceil(8) as usize
        );
        let mut reader = BitReader::new(&data);
        for _ in 0..offset {
            assert!(reader.read_bit().unwrap());
        }
        assert_eq!(T::de(&mut reader).unwrap(), value);
        assert!(!reader.read_bit().unwrap());
        assert!(reader.read_bit().unwrap());
    }

    #[test]
    fn variable_integers_preserve_every_u16_at_every_bit_offset() {
        for value in 0..=u16::MAX {
            for offset in 0..8 {
                integer_round_trip(VariableU16(value), offset);
            }
        }
    }

    #[test]
    fn variable_integers_preserve_power_and_group_boundaries() {
        for shift in 0..u64::BITS {
            let power = 1u64 << shift;
            for value in [
                power.saturating_sub(2),
                power - 1,
                power,
                power + 1,
                u64::MAX - 1,
                u64::MAX,
            ] {
                for offset in 0..8 {
                    integer_round_trip(VariableU64(value), offset);
                    if let Ok(value) = u32::try_from(value) {
                        integer_round_trip(VariableU32(value), offset);
                    }
                }
            }
        }
    }

    #[test]
    fn compact_integer_sizes_include_selectors_and_literal_escapes() {
        for value in [0, 1, 2, 3, 127, 128, 16383, 16384, 32767, 32768, 65535] {
            assert_eq!(VariableU16(value).bit_length(), 6);
            assert_eq!(VariableU32(u32::from(value)).bit_length(), 7);
            assert_eq!(VariableU64(u64::from(value)).bit_length(), 8);
        }
        for (value, bits) in [(5, 9), (126, 9), (130, 17), (258, 17), (32769, 25)] {
            assert_eq!(VariableU16(value).bit_length(), bits);
            assert_eq!(VariableU32(u32::from(value)).bit_length(), bits);
            assert_eq!(VariableU64(u64::from(value)).bit_length(), bits);
        }
        assert_eq!(VariableU32(u32::MAX).bit_length(), 7);
        assert_eq!(VariableU64(u64::MAX).bit_length(), 8);
        assert_eq!(VariableU64(u64::MAX - 1).bit_length(), 81);
    }

    fn literal_bytes(bytes: &[u8]) -> Vec<u8> {
        let mut writer = FileBitWriter::new();
        writer.write_bit(false);
        for &byte in bytes {
            byte.ser(&mut writer);
        }
        writer.to_vec()
    }

    #[test]
    fn overflowing_unterminated_and_noncanonical_integers_are_rejected() {
        for bytes in [&[1, 0][..], &[255; 64][..], &[]] {
            let bytes = literal_bytes(bytes);
            assert!(VariableU16::de(&mut BitReader::new(&bytes)).is_err());
            assert!(VariableU32::de(&mut BitReader::new(&bytes)).is_err());
            assert!(VariableU64::de(&mut BitReader::new(&bytes)).is_err());
        }
        for value in [0, 1, 2, 3, 127, 128, 65535, u64::MAX] {
            let mut writer = FileBitWriter::new();
            writer.write_bit(false);
            UnsignedVariableInteger::<7>::new(value).ser(&mut writer);
            let bytes = writer.to_vec();
            assert!(VariableU16::de(&mut BitReader::new(&bytes)).is_err());
            assert!(VariableU32::de(&mut BitReader::new(&bytes)).is_err());
            assert!(VariableU64::de(&mut BitReader::new(&bytes)).is_err());
        }
        for bytes in [&[255, 255, 8][..], &[255, 255, 255, 255, 32][..]] {
            let bytes = literal_bytes(bytes);
            assert!(VariableU16::de(&mut BitReader::new(&bytes)).is_err());
        }
        assert!(
            VariableU32::de(&mut BitReader::new(&literal_bytes(&[
                255, 255, 255, 255, 32,
            ])))
            .is_err()
        );
        assert!(
            VariableU64::de(&mut BitReader::new(&literal_bytes(&[
                255, 255, 255, 255, 255, 255, 255, 255, 255, 4,
            ])))
            .is_err()
        );
        for offset in 1..8 {
            let mut writer = FileBitWriter::new();
            for _ in 0..offset {
                writer.write_bit(false);
            }
            VariableU64(u64::MAX).ser(&mut writer);
            let bytes = writer.to_vec();
            let mut reader = BitReader::new(&bytes[..1]);
            for _ in 0..offset {
                reader.read_bit().unwrap();
            }
            assert!(VariableU64::de(&mut reader).is_err());
        }
    }

    #[test]
    fn generated_conversions_preserve_every_scalar_width() {
        for value in [0, 127, 128, 16383, 16384, u32::MAX] {
            let mut parameters = zlib_level_1_params();
            parameters.max_token_count = u16::try_from(value.min(u16::MAX.into())).unwrap();
            let BehaviorSettings::Chain { common, parser } = &mut parameters.behavior else {
                unreachable!()
            };
            common.dictionary.window_bits = value;
            common.search.budget.max_chain = value;
            common.search.nice_length = value;
            *parser = ChainParser::Greedy {
                short_match_cutoff: value,
            };
            let encoded = encode(&parameters, b"unchanged CABAC");
            let (decoded, corrections) = decode(&encoded).unwrap();
            assert_eq!(decoded, parameters);
            assert_eq!(corrections, b"unchanged CABAC");
        }
    }

    #[test]
    fn generated_conversions_preserve_independent_policies() {
        for insertion in [
            DictionaryAddPolicy::AddAll,
            DictionaryAddPolicy::AddFirst(u16::MAX),
            DictionaryAddPolicy::AddFirstAndLast(0),
            DictionaryAddPolicy::AddFirstExcept4kBoundary,
            DictionaryAddPolicy::AddFirstWith32KBoundary,
        ] {
            for input_tail in [
                InputTailPolicy::HashMinimum,
                InputTailPolicy::AtLeastFiveBytes,
            ] {
                let mut distances =
                    vec![ChainDistancePolicy::Disabled, ChainDistancePolicy::RleOnly];
                for bounds in [
                    WindowBounds::Full,
                    WindowBounds::ExcludeOldest,
                    WindowBounds::Lookahead,
                    WindowBounds::LookaheadMinusOne,
                ] {
                    for matches_to_start in [false, true] {
                        distances.push(ChainDistancePolicy::Window {
                            history: SourceHistorySettings { matches_to_start },
                            bounds,
                        });
                    }
                }
                for distance in distances {
                    let mut parameters = zlib_level_1_params();
                    let BehaviorSettings::Chain { common, .. } = &mut parameters.behavior else {
                        unreachable!()
                    };
                    common.dictionary.insertion = insertion;
                    common.search.input_tail = input_tail;
                    common.distance = distance;
                    let encoded = encode(&parameters, b"corrections");
                    assert_eq!(decode(&encoded).unwrap(), (parameters, &b"corrections"[..]));
                }
            }
        }
    }

    #[test]
    fn malformed_headers_and_payload_lengths_are_rejected() {
        let parameters = ReconstructionParameters {
            max_token_count: 0,
            block_type_strategy: BlockTypeStrategy::Dynamic,
            behavior: BehaviorSettings::NoDictionary {
                strategy: PreflateStrategy::Store,
            },
        };
        let encoded = encode(&parameters, b"payload");
        for length in 0..encoded.len() {
            assert_eq!(
                decode(&encoded[..length]).unwrap_err().exit_code(),
                ExitCode::InvalidCompressedWrapper
            );
        }
        let mut extra = encoded.clone();
        extra.push(0);
        assert!(decode(&extra).is_err());
        let mut padding = encoded.clone();
        let header_bytes = encoded.len() - b"payload".len();
        padding[header_bytes - 1] |= 128;
        assert!(decode(&padding).is_err());
        let mut invalid_tag = encoded;
        invalid_tag[1] |= 0b11;
        assert!(decode(&invalid_tag).is_err());
        let huge_length = encode_header(&parameters, u64::MAX);
        assert!(decode(&huge_length).is_err());
    }
}
