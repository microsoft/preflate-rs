//! Internal performance tests for the various entropy coders.
//!
//! These are used for benmarking the performance of the encoders. These are not meant to be used
//!  as part of the library as a normal use case, but are useful for verifying that the
//! library is working and performing correctly.
use std::io::Cursor;

#[cfg(feature = "simd")]
use crate::fpaq0parallel::Fpaq0DecoderParallelSimd;

use crate::{
    fpaq0::{Fpaq0Decoder, Fpaq0Encoder},
    fpaq0parallel::{Fpaq0DecoderParallel, Fpaq0EncoderParallel, ParallelEncoderOutput},
    rans32::{RansReader32, RansWriter32},
    traits::{CabacReader, CabacWriter},
    vp8::{VP8Context, VP8Reader, VP8Writer},
};

#[inline(always)]
fn generic_put_pattern<'a, C: Default, CW: CabacWriter<C>>(
    bypass: bool,
    pattern: &[bool],
    mut writer: CW,
) {
    let mut context = [C::default(), C::default(), C::default(), C::default()];

    if bypass {
        pattern.chunks_exact(4).for_each(|chunk| {
            writer.put_bypass(chunk[0]).unwrap();
            writer.put_bypass(chunk[1]).unwrap();
            writer.put_bypass(chunk[2]).unwrap();
            writer.put_bypass(chunk[3]).unwrap();
        });
    } else {
        pattern.chunks_exact(4).for_each(|chunk| {
            writer.put(chunk[0], &mut context[0]).unwrap();
            writer.put(chunk[1], &mut context[1]).unwrap();
            writer.put(chunk[2], &mut context[2]).unwrap();
            writer.put(chunk[3], &mut context[3]).unwrap();
        });
    }

    writer.finish().unwrap();
}

#[inline(always)]
fn generic_get_pattern<'a, C: Default, CR: CabacReader<C>, FR: FnOnce(&'a [u8]) -> CR>(
    bypass: bool,
    pattern: &[bool],
    source: &'a [u8],
    f: FR,
) -> Box<[bool]> {
    let mut context = [C::default(), C::default(), C::default(), C::default()];

    let mut output = vec![false; pattern.len()].into_boxed_slice();

    let mut reader = f(source);

    assert!(output.len() == pattern.len());
    if bypass {
        output.chunks_exact_mut(4).for_each(|chunk| {
            chunk[0] = reader.get_bypass().unwrap();
            chunk[1] = reader.get_bypass().unwrap();
            chunk[2] = reader.get_bypass().unwrap();
            chunk[3] = reader.get_bypass().unwrap();
        });
    } else {
        output.chunks_exact_mut(4).for_each(|chunk| {
            chunk[0] = reader.get(&mut context[0]).unwrap();
            chunk[1] = reader.get(&mut context[1]).unwrap();
            chunk[2] = reader.get(&mut context[2]).unwrap();
            chunk[3] = reader.get(&mut context[3]).unwrap();
        });
    }

    output
}

#[cfg(test)]
fn generic_test_pattern(get: fn(&[bool], &[u8]) -> Box<[bool]>, put: fn(&[bool]) -> Vec<u8>) {
    let mut pattern = Vec::new();
    rand::Rng::sample_iter(rand::thread_rng(), &rand::distributions::Standard)
        .take(200)
        .for_each(|x| pattern.push(x));

    let encoded = put(&pattern);
    let decoded = get(&pattern, &encoded);

    assert!(pattern == &decoded[..]);
}

// rans32
#[inline(never)]
#[allow(dead_code)]
pub fn rans32_put_pattern(pattern: &[bool]) -> Vec<u8> {
    let mut output = Vec::new();

    generic_put_pattern(false, pattern, RansWriter32::new(&mut output));

    output
}

#[inline(never)]
#[allow(dead_code)]
pub fn rans32_get_pattern(pattern: &[bool], source: &[u8]) -> Box<[bool]> {
    generic_get_pattern(false, pattern, &source, |vec| {
        RansReader32::new(Cursor::new(vec)).unwrap()
    })
}

#[inline(never)]
#[allow(dead_code)]
pub fn rans32_put_pattern_bypass(pattern: &[bool]) -> Vec<u8> {
    let mut output = Vec::new();
    generic_put_pattern(true, pattern, RansWriter32::new(&mut output));
    output
}

#[inline(never)]
#[allow(dead_code)]
pub fn rans32_get_pattern_bypass(pattern: &[bool], source: &[u8]) -> Box<[bool]> {
    generic_get_pattern(true, pattern, &source, |vec| {
        RansReader32::new(Cursor::new(vec)).unwrap()
    })
}

#[test]
fn rans32_test_pattern() {
    generic_test_pattern(rans32_get_pattern, rans32_put_pattern);
    generic_test_pattern(rans32_get_pattern_bypass, rans32_put_pattern_bypass);
}

#[inline(never)]
#[allow(dead_code)]
pub fn vp8_put_pattern(pattern: &[bool]) -> Vec<u8> {
    let mut output = Vec::new();
    generic_put_pattern(false, pattern, VP8Writer::new(&mut output).unwrap());
    output
}

#[inline(never)]
#[allow(dead_code)]
pub fn vp8_get_pattern(pattern: &[bool], source: &[u8]) -> Box<[bool]> {
    generic_get_pattern(false, pattern, source, |vec| {
        VP8Reader::new(Cursor::new(vec)).unwrap()
    })
}

#[inline(never)]
#[allow(dead_code)]
pub fn vp8_put_pattern_bypass(pattern: &[bool]) -> Vec<u8> {
    let mut output = Vec::new();
    generic_put_pattern(true, pattern, VP8Writer::new(&mut output).unwrap());
    output
}

#[inline(never)]
#[allow(dead_code)]
pub fn vp8_get_pattern_bypass(pattern: &[bool], source: &[u8]) -> Box<[bool]> {
    generic_get_pattern(true, pattern, source, |vec| {
        VP8Reader::new(Cursor::new(vec)).unwrap()
    })
}

#[test]
fn vp8_test_pattern() {
    generic_test_pattern(vp8_get_pattern, vp8_put_pattern);
    generic_test_pattern(vp8_get_pattern_bypass, vp8_put_pattern_bypass);
}

#[inline(never)]
#[allow(dead_code)]
pub fn fpaq_put_pattern(pattern: &[bool]) -> Vec<u8> {
    let mut output = Vec::new();
    generic_put_pattern(false, pattern, Fpaq0Encoder::new(&mut output));
    output
}

#[inline(never)]
#[allow(dead_code)]
pub fn fpaq_get_pattern(pattern: &[bool], source: &[u8]) -> Box<[bool]> {
    generic_get_pattern(false, pattern, source, |vec| {
        Fpaq0Decoder::new(Cursor::new(vec)).unwrap()
    })
}

#[test]
fn fpaq_test_pattern() {
    generic_test_pattern(fpaq_get_pattern, fpaq_put_pattern);
}

#[inline(never)]
#[allow(dead_code)]
pub fn fpaq_parallel_put_pattern(pattern: &[bool]) -> Vec<u8> {
    {
        let mut context = [
            VP8Context::default(),
            VP8Context::default(),
            VP8Context::default(),
            VP8Context::default(),
        ];

        let mut outputbuffer = Vec::new();
        let mut output = ParallelEncoderOutput::new(&mut outputbuffer);

        let mut writer = [
            Fpaq0EncoderParallel::new(&mut output),
            Fpaq0EncoderParallel::new(&mut output),
            Fpaq0EncoderParallel::new(&mut output),
            Fpaq0EncoderParallel::new(&mut output),
        ];

        for p in 0..pattern.len() / 4 {
            for i in 0..4 {
                writer[i]
                    .put(pattern[p * 4 + i], &mut context[i], &mut output)
                    .unwrap();
            }
        }

        for i in 0..4 {
            writer[i].finish(&mut output).unwrap();
        }

        outputbuffer
    }
}

#[cfg(feature = "simd")]
#[inline(never)]
#[allow(dead_code)]
pub fn fpaq_parallel_simd_get_pattern(pattern: &[bool], source: &[u8]) -> Box<[bool]> {
    let mut context = [
        VP8Context::default(),
        VP8Context::default(),
        VP8Context::default(),
        VP8Context::default(),
    ];

    let pattern = pattern;

    let mut output = vec![false; pattern.len()].into_boxed_slice();

    let mut input = Cursor::new(source);

    let mut reader = Fpaq0DecoderParallelSimd::new(&mut input).unwrap();

    assert!(output.len() == pattern.len());

    output.chunks_exact_mut(4).for_each(|chunk| {
        let r = reader.get(&mut context, &mut input).unwrap();
        chunk[0] = r & 1 != 0;
        chunk[1] = r & 2 != 0;
        chunk[2] = r & 4 != 0;
        chunk[3] = r & 8 != 0;
    });

    output
}

#[inline(never)]
#[allow(dead_code)]
pub fn fpaq_parallel_get_pattern(pattern: &[bool], source: &[u8]) -> Box<[bool]> {
    let mut context = [
        VP8Context::default(),
        VP8Context::default(),
        VP8Context::default(),
        VP8Context::default(),
    ];

    let pattern = pattern;

    let mut output = vec![false; pattern.len()].into_boxed_slice();

    let mut input = Cursor::new(source);

    let mut reader = [
        Fpaq0DecoderParallel::new(&mut input).unwrap(),
        Fpaq0DecoderParallel::new(&mut input).unwrap(),
        Fpaq0DecoderParallel::new(&mut input).unwrap(),
        Fpaq0DecoderParallel::new(&mut input).unwrap(),
    ];

    output.chunks_exact_mut(4).for_each(|chunk| {
        for i in 0..4 {
            chunk[i] = reader[i].get(&mut context[i], &mut input).unwrap();
        }
    });

    output
}

#[cfg(feature = "simd")]
#[test]
fn fpaq_parallel_simd_test_pattern() {
    generic_test_pattern(fpaq_parallel_simd_get_pattern, fpaq_parallel_put_pattern);
}

#[test]
fn fpaq_parallel_test_pattern() {
    generic_test_pattern(fpaq_parallel_get_pattern, fpaq_parallel_put_pattern);
}
