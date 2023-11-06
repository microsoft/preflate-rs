use crate::{
    huffman_table::HuffmanOriginalEncoding,
    preflate_constants::{
        quantize_distance, quantize_length, DIST_CODE_COUNT, LITLENDIST_CODE_COUNT,
        NONLEN_CODE_COUNT,
    },
};

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct PreflateToken {
    len: u16,
    irregular258: bool,
    dist: u16,
}

pub const TOKEN_LITERAL: PreflateToken = PreflateToken {
    len: 1,
    irregular258: false,
    dist: 0,
};

impl PreflateToken {
    pub fn len(&self) -> u32 {
        self.len as u32
    }

    pub fn dist(&self) -> u32 {
        self.dist as u32
    }

    pub fn get_irregular258(&self) -> bool {
        self.irregular258
    }

    pub fn set_len(&mut self, len: u32) {
        self.len = len as u16;
    }

    pub fn set_dist(&mut self, dist: u32) {
        self.dist = dist as u16;
    }

    pub fn set_irregular258(&mut self, irregular258: bool) {
        self.irregular258 = irregular258;
    }

    pub fn new_reference(len: u32, dist: u32, irregular258: bool) -> PreflateToken {
        PreflateToken {
            len: len as u16,
            irregular258,
            dist: dist as u16,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum BlockType {
    Stored,
    DynamicHuff,
    StaticHuff,
}

#[derive(Debug)]
pub struct PreflateTokenBlock {
    pub block_type: BlockType,
    pub uncompressed_start_pos: u32,
    pub uncompressed_len: u32,
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
            block_type: block_type,
            uncompressed_start_pos: 0,
            uncompressed_len: 0,
            context_len: 0,
            padding_bits: 0,
            tokens: Vec::new(),
            freq: TokenFrequency::default(),
            huffman_encoding: HuffmanOriginalEncoding::default(),
        }
    }

    pub fn add_literal(&mut self, lit: u8) {
        self.tokens.push(TOKEN_LITERAL);
        self.freq.literal_codes[lit as usize] += 1;
    }

    pub fn add_reference(&mut self, len: u32, dist: u32, irregular258: bool) {
        self.tokens
            .push(PreflateToken::new_reference(len, dist, irregular258));
        self.freq.literal_codes[NONLEN_CODE_COUNT as usize + quantize_length(len)] += 1;
        self.freq.distance_codes[quantize_distance(dist)] += 1;
    }
}
