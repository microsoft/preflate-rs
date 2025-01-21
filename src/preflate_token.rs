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

pub const BT_STORED: u32 = 1;
pub const BT_DYNAMICHUFF: u32 = 0;
pub const BT_STATICHUFF: u32 = 2;

#[derive(Debug, PartialEq)]
pub enum PreflateHuffmanType {
    Dynamic {
        huffman_encoding: HuffmanOriginalEncoding,
    },
    Static {
        incomplete: bool,
    },
}

#[derive(Debug)]
pub enum PreflateTokenBlock {
    Huffman {
        tokens: Vec<PreflateToken>,
        huffman_type: PreflateHuffmanType,
    },
    Stored {
        uncompressed: Vec<u8>,
        padding_bits: u8,
    },
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

impl TokenFrequency {
    pub fn commit_token(&mut self, token: &PreflateToken) {
        match token {
            PreflateToken::Literal(lit) => {
                self.literal_codes[*lit as usize] += 1;
            }
            PreflateToken::Reference(t) => {
                self.literal_codes[NONLEN_CODE_COUNT + quantize_length(t.len())] += 1;
                self.distance_codes[quantize_distance(t.dist())] += 1;
            }
        }
    }
}
