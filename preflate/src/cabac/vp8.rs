//! Based on the Google VP8 codec as used by the JPEG Lepton compressor.
//!
//! It uses a 16 bit state for the probability of the next bit being 0.
/*
 *  Copyright (c) 2010 The WebM project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE banner below
 *  An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the VPX_AUTHORS file in this directory
 */
/*
Copyright (c) 2010, Google Inc. All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
Neither the name of Google nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
use std::{
    io::{Read, Result, Write},
    num::NonZeroU8,
};

use byteorder::WriteBytesExt;

use super::traits::{CabacReader, CabacWriter};

const BITS_IN_BYTE: i32 = 8;
const BITS_IN_LONG: i32 = 64;
const BITS_IN_LONG_MINUS_LAST_BYTE: i32 = BITS_IN_LONG - BITS_IN_BYTE;

/// context for VP8 encoder/decoder. Consists of two 8 bit counts (lower byte for true, top byte for false).
/// the probability of the next symbol being zero is false_count / (false_count + true_count)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VP8Context {
    counts: u16,
}

impl std::fmt::Debug for VP8Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VP8Context {{ counts: {:x} }}", self.counts)
    }
}

impl Default for VP8Context {
    /// default value is balanced between zeros or ones
    fn default() -> Self {
        VP8Context { counts: 0x101 }
    }
}

/// precalculate the probabilities to avoid doing division during the hot loop.
/// Unfortunately this lookup table is kind of large (too big to fit in CPU L1 in many cases).
/// I tested against the other option of multiplying by the reciprocal
/// (which would only require a 2 * 512 byte lookup table and a multiply) and it was significantly slower.
///
/// I suspect the reason is that there are some very common probability patterns that result in those cache
/// lines staying in L1 cache, with only the rarer patterns causing cache misses.
const fn problookup() -> [NonZeroU8; 65536] {
    let mut retval = [NonZeroU8::MIN; 65536];
    let mut i = 1i32;
    while i < 65536 {
        let a = i >> 8;
        let b = i & 0xff;

        if let Some(x) = NonZeroU8::new(((a << 8) / (a + b)) as u8) {
            retval[i as usize] = x;
        }
        i += 1;
    }

    return retval;
}

static PROB_LOOKUP: [NonZeroU8; 65536] = problookup();

impl VP8Context {
    pub fn new() -> Self {
        Self { counts: 0x0101 }
    }

    /// returns the probability of the next symbol being zero (in the range 0-255)
    #[inline(always)]
    pub fn get_probability(&self) -> NonZeroU8 {
        PROB_LOOKUP[self.counts as usize]
    }

    #[inline(always)]
    pub fn record_and_update_bit(&self, bit: bool) -> Self {
        // rotation is used to update either the true or false counter
        // this allows the same code to be used without branching,
        // which makes the CPU about 20% happier.
        //
        // Since the bits are randomly 1/0, the CPU branch predictor does
        // a terrible job and ends up wasting a lot of time. Normally
        // branches are a better idea if the branch very predictable vs
        // this case where it is better to always pay the price of the
        // extra rotation to avoid the branch.
        let orig = self.counts.rotate_left(bit as u32 * 8);
        let (mut sum, o) = orig.overflowing_add(0x100);
        if o {
            // normalize, except in special case where we have 0xff or more same bits in a row
            // in which case we want to bias the probability to get better compression
            //
            // CPU branch prediction soon realizes that this section is not often executed
            // and will optimize for the common case where the counts are not 0xff.
            let mask = if orig == 0xff01 { 0xff00 } else { 0x8100 };

            // upper byte is 0 since we incremented 0xffxx so we don't have to mask it
            sum = ((orig.wrapping_add(0x101)) >> 1) | mask;
        }

        Self {
            counts: sum.rotate_left(bit as u32 * 8),
        }
    }
}

pub struct VP8Reader<R> {
    value: u64,
    range: u32,
    count: i32,
    upstream_reader: R,
}

impl<R: Read> CabacReader<VP8Context> for VP8Reader<R> {
    #[inline(always)]
    fn get(&mut self, branch: &mut VP8Context) -> Result<bool> {
        let mut tmp_value = self.value;
        let mut tmp_range = self.range;
        let mut tmp_count = self.count;

        if tmp_count < 0 {
            Self::vpx_reader_fill(&mut tmp_value, &mut tmp_count, &mut self.upstream_reader)?;
        }

        let probability = branch.get_probability().get() as u32;

        let split = 1 + (((tmp_range - 1) * probability) >> BITS_IN_BYTE);
        let big_split = (split as u64) << BITS_IN_LONG_MINUS_LAST_BYTE;
        let bit = tmp_value >= big_split;

        let shift;
        let b = branch.record_and_update_bit(bit);
        if bit {
            tmp_range -= split;
            tmp_value -= big_split;

            // so optimizer understands that 0 should never happen and uses a cold jump
            // if we don't have LZCNT on x86 CPUs (older BSR instruction requires check for zero).
            // This is better since the branch prediction figures quickly this never happens and can run
            // the code sequentially.
            #[cfg(all(
                not(target_feature = "lzcnt"),
                any(target_arch = "x86", target_arch = "x86_64")
            ))]
            assert!(tmp_range > 0);

            shift = tmp_range.leading_zeros() as i32 - 24;
        } else {
            tmp_range = split;

            // optimizer understands that split > 0
            shift = split.leading_zeros() as i32 - 24;
        }

        *branch = b;
        self.value = tmp_value << shift;
        self.range = tmp_range << shift;
        self.count = tmp_count - shift;
        return Ok(bit);
    }

    #[inline(always)]
    fn get_bypass(&mut self) -> Result<bool> {
        let mut tmp_value = self.value;
        let mut tmp_range = self.range;
        let mut tmp_count = self.count;

        if tmp_count < 0 {
            Self::vpx_reader_fill(&mut tmp_value, &mut tmp_count, &mut self.upstream_reader)?;
        }

        let split = 1 + (tmp_range >> 1);
        let big_split = (split as u64) << BITS_IN_LONG_MINUS_LAST_BYTE;
        let bit = tmp_value >= big_split;

        let shift;
        if bit {
            tmp_range -= split;
            tmp_value -= big_split;

            // so optimizer understands that 0 should never happen and uses a cold jump
            // if we don't have LZCNT on x86 CPUs (older BSR instruction requires check for zero).
            // This is better since the branch prediction figures quickly this never happens and can run
            // the code sequentially.
            #[cfg(all(
                not(target_feature = "lzcnt"),
                any(target_arch = "x86", target_arch = "x86_64")
            ))]
            assert!(tmp_range > 0);

            shift = tmp_range.leading_zeros() as i32 - 24;
        } else {
            tmp_range = split;

            // optimizer understands that split > 0
            shift = split.leading_zeros() as i32 - 24;
        }

        self.value = tmp_value << shift;
        self.range = tmp_range << shift;
        self.count = tmp_count - shift;
        return Ok(bit);
    }
}

impl<R: Read> VP8Reader<R> {
    pub fn new(reader: R) -> Result<Self> {
        let mut r = VP8Reader {
            upstream_reader: reader,
            value: 0,
            count: -8,
            range: 255,
        };

        Self::vpx_reader_fill(&mut r.value, &mut r.count, &mut r.upstream_reader)?;

        let mut dummy_branch = VP8Context::new();
        let _ = r.get(&mut dummy_branch)?; // marker bit

        return Ok(r);
    }

    #[cold]
    #[inline(always)]
    fn vpx_reader_fill(
        tmp_value: &mut u64,
        tmp_count: &mut i32,
        upstream_reader: &mut R,
    ) -> Result<()> {
        let mut shift = BITS_IN_LONG_MINUS_LAST_BYTE - (*tmp_count + BITS_IN_BYTE);

        while shift >= 0 {
            // BufReader is already pretty efficient handling small reads, so optimization doesn't help that much
            let mut v = [0u8; 1];
            let bytes_read = upstream_reader.read(&mut v)?;
            if bytes_read == 0 {
                break;
            }

            *tmp_value |= (v[0] as u64) << shift;
            shift -= BITS_IN_BYTE;
            *tmp_count += BITS_IN_BYTE;
        }

        return Ok(());
    }
}

/// encoder from VP8/WebM
pub struct VP8Writer<W> {
    low_value: u32,
    range: u32,
    bits_left: i32,
    writer: W,
    num_buffered_bytes: u32,
    buffered_byte: u8,
}

impl<W: Write> VP8Writer<W> {
    pub fn new(writer: W) -> Result<Self> {
        let mut retval = VP8Writer {
            low_value: 0,
            range: 255,
            bits_left: -24,
            writer: writer,
            num_buffered_bytes: 0,
            buffered_byte: 0,
        };

        let mut dummy_branch = VP8Context::default();
        retval.put(false, &mut dummy_branch)?;

        Ok(retval)
    }

    #[inline]
    fn send_to_output(
        &mut self,
        shift: &mut i32,
        tmp_count: &mut i32,
        tmp_low_value: &mut u32,
    ) -> Result<()> {
        let offset = *shift - *tmp_count;

        let last_byte = *tmp_low_value >> (24 - offset);

        if (last_byte & 0x100) != 0 {
            self.flush_buffered_bytes(1)?;
        }

        let last_byte = last_byte as u8;

        if last_byte == 0xff {
            self.num_buffered_bytes += 1;
        } else {
            self.flush_buffered_bytes(0)?;

            self.buffered_byte = last_byte;
            self.num_buffered_bytes = 1;
        }

        *tmp_low_value <<= offset;
        *shift = *tmp_count;
        *tmp_low_value &= 0xffffff;
        *tmp_count -= 8;

        Ok(())
    }

    fn flush_buffered_bytes(&mut self, carry: u8) -> Result<()> {
        if self.num_buffered_bytes > 0 {
            self.writer
                .write_u8(self.buffered_byte.wrapping_add(carry))?;
            self.num_buffered_bytes -= 1;

            while self.num_buffered_bytes > 0 {
                self.writer.write_u8(0xffu8.wrapping_add(carry))?;
                self.num_buffered_bytes -= 1;
            }
        }
        Ok(())
    }
}

impl<W: Write> CabacWriter<VP8Context> for VP8Writer<W> {
    #[inline(always)]
    fn put(&mut self, value: bool, branch: &mut VP8Context) -> Result<()> {
        let probability = branch.get_probability().get() as u32;

        let mut tmp_range = self.range;
        let split = 1 + (((tmp_range - 1) * probability) >> 8);

        let mut tmp_low_value = self.low_value;

        let mut shift;
        let b = branch.record_and_update_bit(value);
        if value {
            tmp_low_value += split;
            tmp_range -= split;

            shift = (tmp_range as u8).leading_zeros() as i32;
        } else {
            tmp_range = split;

            // optimizer understands that split > 0, so it can optimize this
            shift = (split as u8).leading_zeros() as i32;
        }

        tmp_range <<= shift;

        let mut tmp_count = self.bits_left;
        tmp_count += shift;

        if tmp_count >= 0 {
            self.send_to_output(&mut shift, &mut tmp_count, &mut tmp_low_value)?;
        }

        tmp_low_value <<= shift;

        *branch = b;
        self.bits_left = tmp_count;
        self.low_value = tmp_low_value;
        self.range = tmp_range;

        Ok(())
    }

    #[inline(always)]
    fn put_bypass(&mut self, value: bool) -> Result<()> {
        let mut tmp_range = self.range;
        let split = 1 + (tmp_range >> 1);

        let mut tmp_low_value = self.low_value;

        let mut shift;
        if value {
            tmp_low_value += split;
            tmp_range -= split;

            shift = (tmp_range as u8).leading_zeros() as i32;
        } else {
            tmp_range = split;

            // optimizer understands that split > 0, so it can optimize this
            shift = (split as u8).leading_zeros() as i32;
        }

        tmp_range <<= shift;

        let mut tmp_count = self.bits_left;
        tmp_count += shift;

        if tmp_count >= 0 {
            self.send_to_output(&mut shift, &mut tmp_count, &mut tmp_low_value)?;
        }

        tmp_low_value <<= shift;

        self.bits_left = tmp_count;
        self.low_value = tmp_low_value;
        self.range = tmp_range;

        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        // pad the rest of the stream so we don't have to
        // worry about carrying the last byte
        while self.low_value > 0 {
            self.put_bypass(false)?;
        }

        self.flush_buffered_bytes(0)?;

        Ok(())
    }
}

#[test]
fn test_all_contexts() {
    use std::io::Cursor;

    let mut contexts = Vec::new();
    for i in 0..=65535 {
        contexts.push(VP8Context { counts: i });
    }

    let mut buffer: Vec<_> = Vec::new();
    let mut writer = VP8Writer::new(&mut buffer).unwrap();
    for i in 0..=65535 {
        writer.put(true, &mut contexts[i]).unwrap();
        writer.put(false, &mut contexts[i]).unwrap();
        writer.put_bypass(true).unwrap();
        writer.put_bypass(false).unwrap();
    }
    writer.finish().unwrap();

    for i in 0..=65535 {
        contexts[i] = VP8Context { counts: i as u16 };
    }

    let mut reader = VP8Reader::new(Cursor::new(&buffer[..])).unwrap();
    for i in 0..=65535 {
        assert_eq!(reader.get(&mut contexts[i]).unwrap(), true, "i = {}", i);
        assert_eq!(reader.get(&mut contexts[i]).unwrap(), false, "i = {}", i);
        assert_eq!(reader.get_bypass().unwrap(), true, "i = {}", i);
        assert_eq!(reader.get_bypass().unwrap(), false, "i = {}", i);
    }
}

/// run through all the possible combinations of counts and ensure that the probability is the same
#[test]
fn test_all_probabilities() {
    /// This is copied from the C++ implementation to ensure that the behavior is the same
    struct OriginalImplForTest {
        counts: [u8; 2],
        probability: u8,
    }

    impl OriginalImplForTest {
        fn true_count(&self) -> u32 {
            return self.counts[1] as u32;
        }
        fn false_count(&self) -> u32 {
            return self.counts[0] as u32;
        }

        fn record_obs_and_update(&mut self, obs: bool) {
            let fcount = self.counts[0] as u32;
            let tcount = self.counts[1] as u32;

            let overflow = self.counts[obs as usize] == 0xff;

            if overflow {
                // check less than 512
                let neverseen = self.counts[!obs as usize] == 1;
                if neverseen {
                    self.counts[obs as usize] = 0xff;
                    self.probability = if obs { 0 } else { 255 };
                } else {
                    self.counts[0] = ((1 + fcount) >> 1) as u8;
                    self.counts[1] = ((1 + tcount) >> 1) as u8;
                    self.counts[obs as usize] = 129;
                    self.probability = self.optimize(self.counts[0] as u32 + self.counts[1] as u32);
                }
            } else {
                self.counts[obs as usize] += 1;
                self.probability = self.optimize(fcount + tcount + 1);
            }
        }

        fn optimize(&self, sum: u32) -> u8 {
            let prob = (self.false_count() << 8) / sum;

            prob as u8
        }
    }

    for i in 0u16..=65535 {
        let mut old_f = OriginalImplForTest {
            counts: [(i >> 8) as u8, i as u8],
            probability: 0,
        };

        if old_f.true_count() == 0 || old_f.false_count() == 0 {
            // starting counts can't be zero (we use 0 as an internal special value for the new implementation for the edge case of many trues in a row)
            continue;
        }

        let mut new_f = VP8Context { counts: i };

        for _k in 0..10 {
            old_f.record_obs_and_update(false);
            new_f = new_f.record_and_update_bit(false);
            assert_eq!(old_f.probability, new_f.get_probability().get());
        }

        let mut old_t = OriginalImplForTest {
            counts: [(i >> 8) as u8, i as u8],
            probability: 0,
        };
        let mut new_t = VP8Context { counts: i };

        for _k in 0..10 {
            old_t.record_obs_and_update(true);
            new_t = new_t.record_and_update_bit(true);

            if old_t.probability == 0 {
                // there is a change of behavior here compared to the C++ version,
                // but because of the way split is calculated it doesn't result in an
                // overall change in the way that encoding is done, but it does simplify
                // one of the corner cases.
                assert_eq!(new_t.get_probability(), NonZeroU8::new(1).unwrap());
            } else {
                assert_eq!(old_t.probability, new_t.get_probability().get());
            }
        }
    }
}
