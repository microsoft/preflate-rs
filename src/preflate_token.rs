/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::{
    huffman_encoding::HuffmanOriginalEncoding,
    preflate_constants::{
        quantize_distance, quantize_length, DIST_CODE_COUNT, LITLENDIST_CODE_COUNT,
        NONLEN_CODE_COUNT,
    },
};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PreflateTokenReference {
    len: u8,
    dist: u16,
    irregular258: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PreflateToken {
    Literal(u8),
    Reference(PreflateTokenReference),
}

impl PreflateToken {
    pub fn new_reference(len: u32, dist: u32, irregular258: bool) -> PreflateToken {
        PreflateToken::Reference(PreflateTokenReference::new(len, dist, irregular258))
    }
}

impl PreflateTokenReference {
    pub fn new(len: u32, dist: u32, irregular258: bool) -> PreflateTokenReference {
        PreflateTokenReference {
            len: (len - 3) as u8,
            dist: dist as u16,
            irregular258,
        }
    }

    pub fn len(&self) -> u32 {
        (self.len as u32) + 3
    }

    pub fn dist(&self) -> u32 {
        self.dist as u32
    }

    pub fn get_irregular258(&self) -> bool {
        self.irregular258
    }

    pub fn set_irregular258(&mut self, irregular258: bool) {
        self.irregular258 = irregular258;
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum BlockType {
    DynamicHuff = 0,
    Stored = 1,
    StaticHuff = 2,
}

#[derive(Debug)]
pub struct PreflateTokenBlock {
    pub block_type: BlockType,
    // if this is an uncompressed block, then this is the length
    pub uncompressed: Vec<u8>,
    pub context_len: i32,
    pub padding_bits: u8,
    pub tokens: Vec<PreflateToken>,
    pub huffman_encoding: HuffmanOriginalEncoding,
    pub freq: TokenFrequency,
}

#[derive(Debug)]
pub struct TokenFrequency {
    pub literal_codes: [u16; LITLENDIST_CODE_COUNT],
    pub distance_codes: [u16; DIST_CODE_COUNT],
}

impl Default for TokenFrequency {
    fn default() -> Self {
        let mut t = TokenFrequency {
            literal_codes: [0; LITLENDIST_CODE_COUNT],
            distance_codes: [0; DIST_CODE_COUNT],
        };

        // include the end of block code
        t.literal_codes[256] = 1;

        t
    }
}

impl PreflateTokenBlock {
    pub fn new(block_type: BlockType) -> PreflateTokenBlock {
        PreflateTokenBlock {
            block_type,
            uncompressed: Vec::new(),
            context_len: 0,
            padding_bits: 0,
            tokens: Vec::new(),
            freq: TokenFrequency::default(),
            huffman_encoding: HuffmanOriginalEncoding::default(),
        }
    }

    pub fn add_literal(&mut self, lit: u8) {
        self.tokens.push(PreflateToken::Literal(lit));
        if self.block_type == BlockType::DynamicHuff {
            self.freq.literal_codes[lit as usize] += 1;
        }
    }

    pub fn add_reference(&mut self, len: u32, dist: u32, irregular258: bool) {
        self.tokens
            .push(PreflateToken::new_reference(len, dist, irregular258));

        if self.block_type == BlockType::DynamicHuff {
            self.freq.literal_codes[NONLEN_CODE_COUNT + quantize_length(len)] += 1;
            self.freq.distance_codes[quantize_distance(dist)] += 1;
        }
    }
}
