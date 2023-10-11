#[derive(Copy, Clone, Debug, Default)]
pub struct PreflateToken {
    len: u16,
    irregular258: bool,
    dist: u16,
}

pub const TOKEN_NONE: PreflateToken = PreflateToken {
    len: 0,
    irregular258: false,
    dist: 0,
};

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
    pub nlen: u16,
    pub ndist: u16,
    pub ncode: u16,
    pub padding_bit_count: u8,
    pub padding_bits: u8,
    pub tree_codes: Vec<u8>,
    pub tokens: Vec<PreflateToken>,
}

impl PreflateTokenBlock {
    pub fn new(block_type: BlockType) -> PreflateTokenBlock {
        PreflateTokenBlock {
            block_type: block_type,
            uncompressed_start_pos: 0,
            uncompressed_len: 0,
            context_len: 0,
            nlen: 0,
            ndist: 0,
            ncode: 0,
            padding_bit_count: 0,
            padding_bits: 0,
            tree_codes: Vec::new(),
            tokens: Vec::new(),
        }
    }

    pub fn set_huff_lengths(&mut self, nlen: u16, ndist: u16, ncode: u16) {
        self.nlen = nlen;
        self.ndist = ndist;
        self.ncode = ncode;
    }

    pub fn add_tree_code(&mut self, code: u8) {
        self.tree_codes.push(code);
    }

    pub fn add_token(&mut self, token: PreflateToken) {
        self.tokens.push(token);
    }
}
