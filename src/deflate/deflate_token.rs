/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::deflate::huffman_encoding::HuffmanOriginalEncoding;

use super::deflate_constants::{
    quantize_distance, quantize_length, DIST_CODE_COUNT, LITLENDIST_CODE_COUNT, NONLEN_CODE_COUNT,
};

/// In a DEFLATE stream, tokens are either literals (bytes) or references to previous bytes
/// with a distance and length.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DeflateToken {
    Literal(u8),
    Reference(DeflateTokenReference),
}

impl DeflateToken {
    #[cfg(test)]
    pub fn new_ref(len: u32, dist: u32, irregular258: bool) -> DeflateToken {
        DeflateToken::Reference(DeflateTokenReference::new(len, dist, irregular258))
    }
}

/// In the case of a distance and length, the length is the number of bytes to copy from the
/// previous bytes, and the distance is the number of bytes back to start copying from.
///
/// the irregular258 field is used to indicate that the 258 length code was used but in a
/// suboptimal way (the RFC allows for two different ways to encode 258)
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct DeflateTokenReference {
    len: u8,
    dist: u16,
    irregular258: bool,
}

impl std::fmt::Debug for DeflateTokenReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.irregular258 {
            write!(
                f,
                "DeflateTokenReference {{ len: {}, dist: {}, irregular258: {} }}",
                self.len(),
                self.dist(),
                self.irregular258
            )
        } else {
            write!(
                f,
                "DeflateTokenReference {{ len: {}, dist: {} }}",
                self.len(),
                self.dist()
            )
        }
    }
}

impl DeflateTokenReference {
    pub fn new(len: u32, dist: u32, irregular258: bool) -> DeflateTokenReference {
        DeflateTokenReference {
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
pub enum DeflateHuffmanType {
    Static,
    Dynamic {
        huffman_encoding: HuffmanOriginalEncoding,
    },
}

impl Default for DeflateHuffmanType {
    fn default() -> Self {
        DeflateHuffmanType::Static
    }
}

#[derive(PartialEq)]
pub enum DeflateTokenBlockType {
    Huffman {
        tokens: Vec<DeflateToken>,
        huffman_type: DeflateHuffmanType,
    },
    Stored {
        uncompressed: Vec<u8>,
    },
}

/// Debug implementation for DeflateTokenBlockType doesn't print all the tokens
impl std::fmt::Debug for DeflateTokenBlockType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeflateTokenBlockType::Huffman {
                tokens,
                huffman_type: DeflateHuffmanType::Static { .. },
            } => {
                write!(f, "StaticHuffman {{ tokens: len={} }}", tokens.len(),)
            }
            DeflateTokenBlockType::Huffman {
                tokens,
                huffman_type: DeflateHuffmanType::Dynamic { .. },
            } => {
                write!(f, "DynamicHuffman {{ tokens: len={} }}", tokens.len(),)
            }
            DeflateTokenBlockType::Stored { uncompressed } => {
                write!(f, "Stored {{ uncompressed: len={} }}", uncompressed.len(),)
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct DeflateTokenBlock {
    pub block_type: DeflateTokenBlockType,

    pub last: bool,
}

/// Used to track the frequence of tokens in the DEFLATE stream
/// which are later used to build the huffman encoding.
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
    pub fn commit_token(&mut self, token: &DeflateToken) {
        match token {
            DeflateToken::Literal(lit) => {
                self.literal_codes[*lit as usize] += 1;
            }
            DeflateToken::Reference(t) => {
                self.literal_codes[NONLEN_CODE_COUNT + quantize_length(t.len())] += 1;
                self.distance_codes[quantize_distance(t.dist())] += 1;
            }
        }
    }
}
