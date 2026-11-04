/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use crate::{
    cabac_codec::encode_difference,
    deflate::deflate_token::{
        BT_STATICHUFF, BT_STORED, DeflateHuffmanType, DeflateTokenBlock, DeflateTokenBlockType,
    },
    preflate_error::{ExitCode, Result, err_exit_code},
};

const TAILS: &[&[u32]] = &[
    &[],
    &[BT_STATICHUFF],
    &[BT_STATICHUFF, BT_STATICHUFF],
    &[BT_STORED, BT_STATICHUFF],
    &[BT_STORED, BT_STORED, BT_STATICHUFF],
    &[BT_STORED],
    &[BT_STORED, BT_STORED],
    &[BT_STATICHUFF, BT_STORED, BT_STATICHUFF],
];

#[derive(Debug, Default)]
pub(crate) struct BlockPrediction {
    profile: usize,
    tail_position: usize,
    first_block: bool,
    zero_stored: bool,
    previous_stored_length: Option<u32>,
    pub(crate) legacy: bool,
    pub(crate) flush: bool,
    flush_limits: Vec<(usize, u32)>,
    block_index: usize,
}

impl BlockPrediction {
    pub(crate) fn begin_chunk(&mut self, blocks: &[DeflateTokenBlock]) -> usize {
        self.profile = 0;
        self.tail_position = 0;
        self.first_block = true;
        self.zero_stored = false;
        self.flush = false;
        self.flush_limits.clear();
        self.block_index = 0;
        if !self.legacy {
            let last_data = blocks.iter().rposition(|block| match &block.block_type {
                DeflateTokenBlockType::Stored { uncompressed } => !uncompressed.is_empty(),
                DeflateTokenBlockType::Huffman { tokens, .. } => !tokens.is_empty(),
            });
            let flush_count = blocks
                .iter()
                .enumerate()
                .filter(|(index, block)| {
                    last_data.is_some_and(|last| *index < last)
                        && matches!(&block.block_type, DeflateTokenBlockType::Stored { uncompressed } if uncompressed.is_empty())
                })
                .take(65)
                .count();
            // Bound metadata even for adversarial streams with many empty blocks.
            for (index, pair) in blocks.windows(2).enumerate() {
                if let DeflateTokenBlockType::Huffman { tokens, .. } = &pair[0].block_type
                    && !tokens.is_empty()
                    && matches!(&pair[1].block_type,
                        DeflateTokenBlockType::Stored { uncompressed } if uncompressed.is_empty())
                    && !pair[0].last
                    && last_data.is_some_and(|last| index + 1 < last)
                {
                    if self.flush_limits.len() == 64 {
                        self.flush_limits.clear();
                        break;
                    }
                    self.flush_limits.push((
                        index,
                        tokens
                            .iter()
                            .map(|t| match t {
                                crate::deflate::deflate_token::DeflateToken::Literal(_) => 1,
                                crate::deflate::deflate_token::DeflateToken::Reference(r) => {
                                    r.len()
                                }
                            })
                            .sum(),
                    ));
                }
            }
            self.flush = (1..=64).contains(&flush_count);
            if !self.flush {
                self.flush_limits.clear();
            }
        }
        if !self.legacy {
            let last_data = blocks.iter().rposition(|block| match &block.block_type {
                DeflateTokenBlockType::Stored { uncompressed } => !uncompressed.is_empty(),
                DeflateTokenBlockType::Huffman { tokens, .. } => !tokens.is_empty(),
            });
            let all_stored_empty = blocks.iter().all(|block| match &block.block_type {
                DeflateTokenBlockType::Stored { uncompressed } => uncompressed.is_empty(),
                _ => true,
            });
            self.zero_stored = all_stored_empty
                && last_data.is_some_and(|last| {
                    blocks[..last].iter().any(|block| {
                        matches!(block.block_type, DeflateTokenBlockType::Stored { .. })
                    })
                });
        }
        if !self.legacy && blocks.last().is_some_and(|block| block.last) {
            for (profile, tail) in TAILS.iter().enumerate().skip(1) {
                if blocks.len() > tail.len()
                    && match &blocks[blocks.len() - tail.len() - 1].block_type {
                        DeflateTokenBlockType::Stored { uncompressed } => !uncompressed.is_empty(),
                        DeflateTokenBlockType::Huffman { tokens, .. } => !tokens.is_empty(),
                    }
                    && blocks[blocks.len() - tail.len()..]
                        .iter()
                        .zip(tail.iter())
                        .all(|(block, &expected)| match &block.block_type {
                            DeflateTokenBlockType::Stored { uncompressed } => {
                                expected == BT_STORED && uncompressed.is_empty()
                            }

                            DeflateTokenBlockType::Huffman {
                                tokens,
                                huffman_type: DeflateHuffmanType::Static,
                            } => expected == BT_STATICHUFF && tokens.is_empty(),
                            _ => false,
                        })
                {
                    self.profile = profile;
                    break;
                }
            }
        }
        TAILS[self.profile].len()
    }

    #[cfg(any(test, feature = "diagnostics"))]
    pub(crate) fn profile_name(&self) -> &'static str {
        if self.flush {
            return "Flush";
        }
        match (self.zero_stored, self.profile) {
            (false, 0) => "Default",
            (false, 1) => "Fixed",
            (false, 2) => "FixedFixed",
            (false, 3) => "StoredFixed",
            (false, 4) => "StoredStoredFixed",
            (false, 5) => "Stored",
            (false, 6) => "StoredStored",
            (false, 7) => "FixedStoredFixed",
            (true, 0) => "ZeroStored",
            (true, 1) => "Fixed+ZeroStored",
            (true, 2) => "FixedFixed+ZeroStored",
            (true, 3) => "StoredFixed+ZeroStored",
            (true, 4) => "StoredStoredFixed+ZeroStored",
            (true, 5) => "Stored+ZeroStored",
            (true, 6) => "StoredStored+ZeroStored",
            (true, 7) => "FixedStoredFixed+ZeroStored",
            _ => unreachable!(),
        }
    }

    fn tail_type(&self, remaining: u32) -> Option<u32> {
        if remaining == 0 {
            TAILS[self.profile].get(self.tail_position).copied()
        } else {
            None
        }
    }

    pub(crate) fn token_count(&self, remaining: u32, fallback: u32) -> u32 {
        if self.tail_type(remaining).is_some() {
            0
        } else {
            fallback
        }
    }

    pub(crate) fn stored_length(&self, remaining: u32) -> u32 {
        if self.legacy {
            65535
        } else if self.zero_stored {
            0
        } else {
            remaining.min(self.previous_stored_length.unwrap_or(65535))
        }
    }

    pub(crate) fn record_stored_length(&mut self, length: u32) {
        if length != 0 {
            self.previous_stored_length = Some(length);
        }
    }

    pub(crate) fn encode_type(&mut self, actual: u32, fallback: u32, remaining: u32) -> u32 {
        let predicted = self.tail_type(remaining).unwrap_or(fallback);
        let mut correction = encode_difference(predicted, actual);
        if self.first_block {
            // Ordinary block-type differences occupy 0..=5. Tag the first one with
            // a tail profile without adding a CABAC channel or changing default chunks.
            let profile = self.profile
                + if self.zero_stored { TAILS.len() } else { 0 }
                + if self.flush { 2 * TAILS.len() } else { 0 };
            correction += 6 * profile as u32;
            self.first_block = false;
        }
        correction
    }

    pub(crate) fn decode_type(
        &mut self,
        mut correction: u32,
        fallback: u32,
        remaining: u32,
    ) -> Result<u32> {
        if self.first_block {
            let profile = (correction / 6) as usize;
            if profile >= 4 * TAILS.len() || (self.legacy && profile != 0) {
                return err_exit_code(ExitCode::InvalidDeflate, "Invalid block prediction profile");
            }
            self.profile = profile % TAILS.len();
            self.zero_stored = profile % (2 * TAILS.len()) >= TAILS.len();
            self.flush = profile >= 2 * TAILS.len();
            correction %= 6;
            self.first_block = false;
        }
        let predicted = self.tail_type(remaining).unwrap_or(fallback);
        (0..=2)
            .find(|&actual| encode_difference(predicted, actual) == correction)
            .ok_or_else(|| {
                crate::PreflateError::new(ExitCode::InvalidDeflate, "Invalid block type")
            })
    }

    pub(crate) fn finish_block(&mut self, started_empty: bool) {
        self.block_index += 1;
        if started_empty && self.tail_position < TAILS[self.profile].len() {
            self.tail_position += 1;
        }
    }

    pub(crate) fn flush_limit(&self) -> Option<u32> {
        self.flush_limits
            .iter()
            .find_map(|&(index, length)| (index == self.block_index).then_some(length))
    }

    pub(crate) fn end_of_chunk(&self, remaining: u32) -> bool {
        remaining == 0 && self.tail_position == TAILS[self.profile].len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_stored_fixed_tail_requires_empty_blocks_after_data() {
        use crate::deflate::deflate_token::DeflateToken;
        let fixed = |tokens, last| DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Huffman {
                tokens,
                huffman_type: DeflateHuffmanType::Static,
            },
            last,
        };
        let mut blocks = [
            fixed(vec![DeflateToken::Literal(b'x')], false),
            fixed(vec![], false),
            DeflateTokenBlock {
                block_type: DeflateTokenBlockType::Stored {
                    uncompressed: vec![],
                },
                last: false,
            },
            fixed(vec![], true),
        ];
        let mut encoder = BlockPrediction::default();
        assert_eq!(encoder.begin_chunk(&blocks), 3);
        assert_eq!(encoder.profile_name(), "FixedStoredFixed");
        let mut decoder = BlockPrediction::default();
        decoder.begin_chunk(&[]);
        let tag = encoder.encode_type(BT_STATICHUFF, BT_STATICHUFF, 1);
        assert_eq!(
            decoder.decode_type(tag, BT_STATICHUFF, 1).unwrap(),
            BT_STATICHUFF
        );
        encoder.finish_block(false);
        decoder.finish_block(false);
        for (index, actual) in [BT_STATICHUFF, BT_STORED, BT_STATICHUFF]
            .into_iter()
            .enumerate()
        {
            assert!(!encoder.end_of_chunk(0));
            assert!(!decoder.end_of_chunk(0));
            assert_eq!(encoder.token_count(0, 16383), 0);
            let correction = encoder.encode_type(actual, 2, 0);
            assert_eq!(correction, 0);
            assert_eq!(decoder.decode_type(correction, 2, 0).unwrap(), actual);
            encoder.finish_block(true);
            decoder.finish_block(true);
            assert_eq!(encoder.end_of_chunk(0), index == 2);
            assert_eq!(decoder.end_of_chunk(0), index == 2);
        }
        blocks[3].last = false;
        encoder.begin_chunk(&blocks);
        assert_eq!(encoder.profile_name(), "Default");
        blocks[3].last = true;
        blocks[1] = fixed(vec![DeflateToken::Literal(b'y')], false);
        encoder.begin_chunk(&blocks);
        assert_eq!(encoder.profile_name(), "StoredFixed");
    }

    #[test]
    fn flush_profiles_are_bounded_and_do_not_change_empty_tails() {
        use crate::deflate::deflate_token::DeflateToken;
        let data = || DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Huffman {
                tokens: vec![DeflateToken::Literal(b'x')],
                huffman_type: DeflateHuffmanType::Static,
            },
            last: false,
        };
        let stored = || DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Stored {
                uncompressed: vec![],
            },
            last: false,
        };
        let mut predictor = BlockPrediction::default();
        predictor.begin_chunk(&[data(), stored()]);
        assert!(!predictor.flush);
        assert_eq!(predictor.flush_limit(), None);
        let mut blocks = vec![];
        for _ in 0..65 {
            blocks.push(data());
            blocks.push(stored());
        }
        blocks.push(data());
        predictor.begin_chunk(&blocks);
        assert!(!predictor.flush);
        assert!(predictor.flush_limits.is_empty());
        blocks.truncate(127);
        predictor.begin_chunk(&blocks);
        assert!(predictor.flush);
        assert_eq!(predictor.flush_limit(), Some(1));
    }

    #[test]
    fn block_type_profiles_roundtrip_and_reject_invalid_values() {
        for profile in 0..4 * TAILS.len() {
            for remaining in [0, 100] {
                for fallback in 0..=2 {
                    for actual in 0..=2 {
                        let mut encoder = BlockPrediction::default();
                        encoder.begin_chunk(&[]);
                        encoder.profile = profile % TAILS.len();
                        encoder.zero_stored = profile % (2 * TAILS.len()) >= TAILS.len();
                        encoder.flush = profile >= 2 * TAILS.len();
                        let mut decoder = BlockPrediction::default();
                        decoder.begin_chunk(&[]);
                        let value = encoder.encode_type(actual, fallback, remaining);
                        assert_eq!(
                            decoder.decode_type(value, fallback, remaining).unwrap(),
                            actual
                        );
                        assert_eq!(decoder.profile, encoder.profile);
                        assert_eq!(decoder.zero_stored, encoder.zero_stored);
                        assert_eq!(decoder.flush, encoder.flush);
                        let next = encoder.encode_type(actual, fallback, remaining);
                        assert_eq!(
                            decoder.decode_type(next, fallback, remaining).unwrap(),
                            actual
                        );
                    }
                }
            }
        }
        for invalid in [24 * TAILS.len() as u32, 255, u32::MAX] {
            let mut prediction = BlockPrediction::default();
            prediction.begin_chunk(&[]);
            assert!(prediction.decode_type(invalid, 0, 100).is_err());
        }
        let mut legacy = BlockPrediction {
            legacy: true,
            ..Default::default()
        };
        legacy.begin_chunk(&[]);
        assert!(legacy.decode_type(6, 0, 100).is_err());
        let mut prediction = BlockPrediction::default();
        prediction.begin_chunk(&[]);
        assert!(prediction.decode_type(2, 0, 100).is_err());
    }

    #[test]
    fn stored_lengths_use_remaining_input_except_in_legacy_mode() {
        let current = BlockPrediction::default();
        let legacy = BlockPrediction {
            legacy: true,
            ..Default::default()
        };
        for remaining in [0, 1, 123, 65535, 65536, u32::MAX] {
            assert_eq!(current.stored_length(remaining), remaining.min(65535));
            assert_eq!(legacy.stored_length(remaining), 65535);
        }
        let flush = BlockPrediction {
            zero_stored: true,
            ..Default::default()
        };
        assert_eq!(flush.stored_length(1234), 0);
        let mut learned = BlockPrediction::default();
        learned.record_stored_length(2047);
        assert_eq!(learned.stored_length(10000), 2047);
        assert_eq!(learned.stored_length(1000), 1000);
        learned.record_stored_length(0);
        learned.begin_chunk(&[]);
        assert_eq!(learned.stored_length(10000), 2047);
        let mut legacy = legacy;
        legacy.record_stored_length(2047);
        assert_eq!(legacy.stored_length(10000), 65535);
    }
}
