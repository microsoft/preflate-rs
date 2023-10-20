use std::cmp;
use std::io::Result;

use crate::preflate_complevel_estimator::PreflateCompLevelInfo;
use crate::preflate_token::{PreflateToken, PreflateTokenBlock};
use crate::preflate_token_predictor::BlockAnalysisResult;

pub fn estimate_zlib_comp_level(
    unpacked_output: &[u8],
    blocks: &Vec<PreflateTokenBlock>,
) -> PreflateCompLevelInfo {
    let mut complevel = PreflateCompLevelInfo::default();

    let mut comp = CompressorOxide::new(0);

    let mut p = Prediction {
        current_block: 0,
        current_token: 0,
        tokens: &blocks,
    };

    //compress_fast(&mut comp, unpacked_output, &mut p);

    complevel
}

struct Prediction<'a> {
    current_block: usize,
    current_token: usize,
    tokens: &'a [PreflateTokenBlock],
}

impl<'a> Prediction<'a> {
    fn pop_token(&mut self) -> Option<PreflateToken> {
        if self.current_block >= self.tokens.len() {
            return None;
        }

        if self.current_token >= self.tokens[self.current_token].tokens.len() {
            self.current_block += 1;
            self.current_token = 0;
        }

        Some(self.tokens[self.current_block].tokens[self.current_token])
    }
}

/// Length code for length values.
#[rustfmt::skip]
const LEN_SYM: [u16; 256] = [
    257, 258, 259, 260, 261, 262, 263, 264, 265, 265, 266, 266, 267, 267, 268, 268,
    269, 269, 269, 269, 270, 270, 270, 270, 271, 271, 271, 271, 272, 272, 272, 272,
    273, 273, 273, 273, 273, 273, 273, 273, 274, 274, 274, 274, 274, 274, 274, 274,
    275, 275, 275, 275, 275, 275, 275, 275, 276, 276, 276, 276, 276, 276, 276, 276,
    277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277,
    278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278,
    279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279,
    280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280,
    281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281,
    281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281,
    282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282,
    282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282,
    283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283,
    283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283,
    284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284,
    284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 285
];

/// Number of extra bits for length values.
#[rustfmt::skip]
const LEN_EXTRA: [u8; 256] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 0
];

/// Distance codes for distances smaller than 512.
#[rustfmt::skip]
const SMALL_DIST_SYM: [u8; 512] = [
     0,  1,  2,  3,  4,  4,  5,  5,  6,  6,  6,  6,  7,  7,  7,  7,
     8,  8,  8,  8,  8,  8,  8,  8,  9,  9,  9,  9,  9,  9,  9,  9,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17
];

/// Number of extra bits for distances smaller than 512.
#[rustfmt::skip]
const SMALL_DIST_EXTRA: [u8; 512] = [
    0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7
];

/// Base values to calculate distances above 512.
#[rustfmt::skip]
const LARGE_DIST_SYM: [u8; 128] = [
     0,  0, 18, 19, 20, 20, 21, 21, 22, 22, 22, 22, 23, 23, 23, 23,
    24, 24, 24, 24, 24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 25,
    26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
    29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29
];

/// Number of extra bits distances above 512.
#[rustfmt::skip]
const LARGE_DIST_EXTRA: [u8; 128] = [
     0,  0,  8,  8,  9,  9,  9,  9, 10, 10, 10, 10, 10, 10, 10, 10,
    11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13
];

#[rustfmt::skip]
const BITMASKS: [u32; 17] = [
    0x0000, 0x0001, 0x0003, 0x0007, 0x000F, 0x001F, 0x003F, 0x007F, 0x00FF,
    0x01FF, 0x03FF, 0x07FF, 0x0FFF, 0x1FFF, 0x3FFF, 0x7FFF, 0xFFFF
];

/// Whether to use a zlib wrapper.
pub const TDEFL_WRITE_ZLIB_HEADER: u32 = 0x0000_1000;
/// Should we compute the adler32 checksum.
pub const TDEFL_COMPUTE_ADLER32: u32 = 0x0000_2000;
/// Should we use greedy parsing (as opposed to lazy parsing where look ahead one or more
/// bytes to check for better matches.)
pub const TDEFL_GREEDY_PARSING_FLAG: u32 = 0x0000_4000;
/// Used in miniz to skip zero-initializing hash and dict. We don't do this here, so
/// this flag is ignored.
pub const TDEFL_NONDETERMINISTIC_PARSING_FLAG: u32 = 0x0000_8000;
/// Only look for matches with a distance of 0.
pub const TDEFL_RLE_MATCHES: u32 = 0x0001_0000;
/// Only use matches that are at least 6 bytes long.
pub const TDEFL_FILTER_MATCHES: u32 = 0x0002_0000;
/// Force the compressor to only output static blocks. (Blocks using the default huffman codes
/// specified in the deflate specification.)
pub const TDEFL_FORCE_ALL_STATIC_BLOCKS: u32 = 0x0004_0000;
/// Force the compressor to only output raw/uncompressed blocks.
pub const TDEFL_FORCE_ALL_RAW_BLOCKS: u32 = 0x0008_0000;

/// Size of the buffer of lz77 encoded data.
pub const LZ_CODE_BUF_SIZE: usize = 64 * 1024;
/// Size of the output buffer.
pub const OUT_BUF_SIZE: usize = (LZ_CODE_BUF_SIZE * 13) / 10;
pub const LZ_DICT_FULL_SIZE: usize = LZ_DICT_SIZE + MAX_MATCH_LEN - 1 + 1;

/// Size of hash values in the hash chains.
pub const LZ_HASH_BITS: i32 = 15;
/// How many bits to shift when updating the current hash value.
pub const LZ_HASH_SHIFT: i32 = (LZ_HASH_BITS + 2) / 3;
/// Size of the chained hash tables.
pub const LZ_HASH_SIZE: usize = 1 << LZ_HASH_BITS;

const MAX_HUFF_SYMBOLS: usize = 288;
/// Size of hash chain for fast compression mode.
pub const LEVEL1_HASH_SIZE_MASK: u32 = 4095;
/// The number of huffman tables used by the compressor.
/// Literal/length, Distances and Length of the huffman codes for the other two tables.
const MAX_HUFF_TABLES: usize = 3;
/// Literal/length codes
const MAX_HUFF_SYMBOLS_0: usize = 288;
/// Distance codes.
const MAX_HUFF_SYMBOLS_1: usize = 32;
/// Huffman length values.
const MAX_HUFF_SYMBOLS_2: usize = 19;
/// Size of the chained hash table.
pub(crate) const LZ_DICT_SIZE: usize = 32_768;
/// Mask used when stepping through the hash chains.
const LZ_DICT_SIZE_MASK: usize = (LZ_DICT_SIZE as u32 - 1) as usize;
/// The minimum length of a match.
const MIN_MATCH_LEN: u8 = 3;
/// The maximum length of a match.
pub(crate) const MAX_MATCH_LEN: usize = 258;

/// A list of deflate flush types.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum TDEFLFlush {
    /// Normal operation.
    ///
    /// Compress as much as there is space for, and then return waiting for more input.
    None = 0,

    /// Try to flush all the current data and output an empty raw block.
    Sync = 2,

    /// Same as [`Sync`][Self::Sync], but reset the dictionary so that the following data does not
    /// depend on previous data.
    Full = 3,

    /// Try to flush everything and end the deflate stream.
    ///
    /// On success this will yield a [`TDEFLStatus::Done`] return status.
    Finish = 4,
}

/// A struct containing data about huffman codes and symbol frequencies.
///
/// NOTE: Only the literal/lengths have enough symbols to actually use
/// the full array. It's unclear why it's defined like this in miniz,
/// it could be for cache/alignment reasons.
struct HuffmanOxide {
    /// Number of occurrences of each symbol.
    pub count: [[u16; MAX_HUFF_SYMBOLS]; MAX_HUFF_TABLES],
    /// The bits of the huffman code assigned to the symbol
    pub codes: [[u16; MAX_HUFF_SYMBOLS]; MAX_HUFF_TABLES],
    /// The length of the huffman code assigned to the symbol.
    pub code_sizes: [[u8; MAX_HUFF_SYMBOLS]; MAX_HUFF_TABLES],
}

impl Default for HuffmanOxide {
    fn default() -> Self {
        HuffmanOxide {
            count: [[0; MAX_HUFF_SYMBOLS]; MAX_HUFF_TABLES],
            codes: [[0; MAX_HUFF_SYMBOLS]; MAX_HUFF_TABLES],
            code_sizes: [[0; MAX_HUFF_SYMBOLS]; MAX_HUFF_TABLES],
        }
    }
}

struct DictOxide {
    /// The maximum number of checks in the hash chain, for the initial,
    /// and the lazy match respectively.
    pub max_probes: [u32; 2],
    /// Buffer of input data.
    /// Padded with 1 byte to simplify matching code in `compress_fast`.
    pub b: Box<HashBuffers>,

    pub code_buf_dict_pos: usize,
    pub lookahead_size: usize,
    pub lookahead_pos: usize,
    pub size: usize,
}

const fn probes_from_flags(flags: u32) -> [u32; 2] {
    [
        1 + ((flags & 0xFFF) + 2) / 3,
        1 + (((flags & 0xFFF) >> 2) + 2) / 3,
    ]
}

fn memset<T: Copy>(slice: &mut [T], val: T) {
    for x in slice {
        *x = val
    }
}

#[cfg(test)]
#[inline]
fn write_u16_le(val: u16, slice: &mut [u8], pos: usize) {
    slice[pos] = val as u8;
    slice[pos + 1] = (val >> 8) as u8;
}

// Read the two bytes starting at pos and interpret them as an u16.
#[inline]
const fn read_u16_le(slice: &[u8], pos: usize) -> u16 {
    // The compiler is smart enough to optimize this into an unaligned load.
    slice[pos] as u16 | ((slice[pos + 1] as u16) << 8)
}

impl DictOxide {
    fn new(flags: u32) -> Self {
        DictOxide {
            max_probes: probes_from_flags(flags),
            b: Box::default(),
            code_buf_dict_pos: 0,
            lookahead_size: 0,
            lookahead_pos: 0,
            size: 0,
        }
    }

    fn update_flags(&mut self, flags: u32) {
        self.max_probes = probes_from_flags(flags);
    }

    fn reset(&mut self) {
        self.b.reset();
        self.code_buf_dict_pos = 0;
        self.lookahead_size = 0;
        self.lookahead_pos = 0;
        self.size = 0;
    }

    /// Do an unaligned read of the data at `pos` in the dictionary and treat it as if it was of
    /// type T.
    #[inline]
    fn read_unaligned_u32(&self, pos: usize) -> u32 {
        // Masking the value here helps avoid bounds checks.
        let pos = (pos & LZ_DICT_SIZE_MASK) as usize;
        let end = pos + 4;
        // Somehow this assertion makes things faster.
        assert!(end < LZ_DICT_FULL_SIZE);

        let bytes: [u8; 4] = self.b.dict[pos..end].try_into().unwrap();
        u32::from_le_bytes(bytes)
    }

    /// Do an unaligned read of the data at `pos` in the dictionary and treat it as if it was of
    /// type T.
    #[inline]
    fn read_unaligned_u64(&self, pos: usize) -> u64 {
        let pos = pos as usize;
        let bytes: [u8; 8] = self.b.dict[pos..pos + 8].try_into().unwrap();
        u64::from_le_bytes(bytes)
    }

    /// Do an unaligned read of the data at `pos` in the dictionary and treat it as if it was of
    /// type T.
    #[inline]
    fn read_as_u16(&self, pos: usize) -> u16 {
        read_u16_le(&self.b.dict[..], pos)
    }

    /// Try to find a match for the data at lookahead_pos in the dictionary that is
    /// longer than `match_len`.
    /// Returns a tuple containing (match_distance, match_length). Will be equal to the input
    /// values if no better matches were found.
    fn find_match(
        &self,
        lookahead_pos: usize,
        max_dist: usize,
        max_match_len: u32,
        mut match_dist: u32,
        mut match_len: u32,
    ) -> (u32, u32) {
        // Clamp the match len and max_match_len to be valid. (It should be when this is called, but
        // do it for now just in case for safety reasons.)
        // This should normally end up as at worst conditional moves,
        // so it shouldn't slow us down much.
        // TODO: Statically verify these so we don't need to do this.
        let max_match_len = cmp::min(MAX_MATCH_LEN as u32, max_match_len);
        match_len = cmp::max(match_len, 1);

        let pos = lookahead_pos as usize & LZ_DICT_SIZE_MASK;
        let mut probe_pos = pos;
        // Number of probes into the hash chains.
        let mut num_probes_left = self.max_probes[(match_len >= 32) as usize];

        // If we already have a match of the full length don't bother searching for another one.
        if max_match_len <= match_len {
            return (match_dist, match_len);
        }

        // Read the last byte of the current match, and the next one, used to compare matches.
        let mut c01: u16 = self.read_as_u16(pos as usize + match_len as usize - 1);
        // Read the two bytes at the end position of the current match.
        let s01: u16 = self.read_as_u16(pos as usize);

        'outer: loop {
            let mut dist;
            'found: loop {
                num_probes_left -= 1;
                if num_probes_left == 0 {
                    // We have done as many probes in the hash chain as the current compression
                    // settings allow, so return the best match we found, if any.
                    return (match_dist, match_len);
                }

                for _ in 0..3 {
                    let next_probe_pos = self.b.next[probe_pos as usize] as usize;

                    dist = (lookahead_pos - next_probe_pos) & 0xFFFF;
                    if next_probe_pos == 0 || dist > max_dist {
                        // We reached the end of the hash chain, or the next value is further away
                        // than the maximum allowed distance, so return the best match we found, if
                        // any.
                        return (match_dist, match_len);
                    }

                    // Mask the position value to get the position in the hash chain of the next
                    // position to match against.
                    probe_pos = next_probe_pos & LZ_DICT_SIZE_MASK;

                    if self.read_as_u16((probe_pos + match_len as usize - 1) as usize) == c01 {
                        break 'found;
                    }
                }
            }

            if dist == 0 {
                // We've looked through the whole match range, so return the best match we
                // found.
                return (match_dist, match_len);
            }

            // Check if the two first bytes match.
            if self.read_as_u16(probe_pos as usize) != s01 {
                continue;
            }

            let mut p = pos + 2;
            let mut q = probe_pos + 2;
            // The first two bytes matched, so check the full length of the match.
            for _ in 0..32 {
                let p_data: u64 = self.read_unaligned_u64(p);
                let q_data: u64 = self.read_unaligned_u64(q);
                // Compare of 8 bytes at a time by using unaligned loads of 64-bit integers.
                let xor_data = p_data ^ q_data;
                if xor_data == 0 {
                    p += 8;
                    q += 8;
                } else {
                    // If not all of the last 8 bytes matched, check how may of them did.
                    let trailing = xor_data.trailing_zeros();

                    let probe_len = p - pos + (trailing as usize >> 3);
                    if probe_len > match_len as usize {
                        match_dist = dist as u32;
                        match_len = cmp::min(max_match_len, probe_len as u32);
                        if match_len == max_match_len {
                            // We found a match that had the maximum allowed length,
                            // so there is now point searching further.
                            return (match_dist, match_len);
                        }
                        // We found a better match, so save the last two bytes for further match
                        // comparisons.
                        c01 = self.read_as_u16(pos + match_len as usize - 1)
                    }
                    continue 'outer;
                }
            }

            return (dist as u32, cmp::min(max_match_len, MAX_MATCH_LEN as u32));
        }
    }
}

pub struct HashBuffers {
    pub dict: [u8; LZ_DICT_FULL_SIZE],
    pub next: [u16; LZ_DICT_SIZE],
    pub hash: [u16; LZ_DICT_SIZE],
}

impl HashBuffers {
    #[inline]
    pub fn reset(&mut self) {
        *self = HashBuffers::default();
    }
}

impl Default for HashBuffers {
    fn default() -> HashBuffers {
        HashBuffers {
            dict: [0; LZ_DICT_FULL_SIZE],
            next: [0; LZ_DICT_SIZE],
            hash: [0; LZ_DICT_SIZE],
        }
    }
}

struct LZOxide {
    pub codes: [u8; LZ_CODE_BUF_SIZE],
    pub code_position: usize,
    pub flag_position: usize,

    // The total number of bytes in the current block.
    // (Could maybe use usize, but it's not possible to exceed a block size of )
    pub total_bytes: u32,
    pub num_flags_left: u32,
}

impl LZOxide {
    const fn new() -> Self {
        LZOxide {
            codes: [0; LZ_CODE_BUF_SIZE],
            code_position: 1,
            flag_position: 0,
            total_bytes: 0,
            num_flags_left: 8,
        }
    }

    fn write_code(&mut self, val: u8) {
        self.codes[self.code_position] = val;
        self.code_position += 1;
    }

    fn init_flag(&mut self) {
        if self.num_flags_left == 8 {
            *self.get_flag() = 0;
            self.code_position -= 1;
        } else {
            *self.get_flag() >>= self.num_flags_left;
        }
    }

    fn get_flag(&mut self) -> &mut u8 {
        &mut self.codes[self.flag_position]
    }

    fn plant_flag(&mut self) {
        self.flag_position = self.code_position;
        self.code_position += 1;
    }

    fn consume_flag(&mut self) {
        self.num_flags_left -= 1;
        if self.num_flags_left == 0 {
            self.num_flags_left = 8;
            self.plant_flag();
        }
    }
}

#[inline]
pub fn update_hash(current_hash: u16, byte: u8) -> u16 {
    ((current_hash << LZ_HASH_SHIFT) ^ u16::from(byte)) & (LZ_HASH_SIZE as u16 - 1)
}

fn record_literal(h: &mut HuffmanOxide, lz: &mut LZOxide, lit: u8, p: &mut Prediction) {
    lz.total_bytes += 1;
    lz.write_code(lit);

    *lz.get_flag() >>= 1;
    lz.consume_flag();

    h.count[0][lit as usize] += 1;

    //let token = p.pop_token();
    //if let Some(t) = token {}
}

fn record_match(
    h: &mut HuffmanOxide,
    lz: &mut LZOxide,
    mut match_len: u32,
    mut match_dist: u32,
    p: &mut Prediction,
) {
    assert!(match_len >= MIN_MATCH_LEN.into());
    assert!(match_dist >= 1);
    assert!(match_dist as usize <= LZ_DICT_SIZE);

    lz.total_bytes += match_len;
    match_dist -= 1;
    match_len -= u32::from(MIN_MATCH_LEN);
    lz.write_code(match_len as u8);
    lz.write_code(match_dist as u8);
    lz.write_code((match_dist >> 8) as u8);

    *lz.get_flag() >>= 1;
    *lz.get_flag() |= 0x80;
    lz.consume_flag();

    let symbol = if match_dist < 512 {
        SMALL_DIST_SYM[match_dist as usize]
    } else {
        LARGE_DIST_SYM[((match_dist >> 8) & 127) as usize]
    } as usize;
    h.count[1][symbol] += 1;
    h.count[0][LEN_SYM[match_len as usize] as usize] += 1;
}

pub const MZ_ADLER32_INIT: u32 = 1;

/// Main compression struct.
pub struct CompressorOxide {
    lz: LZOxide,
    params: ParamsOxide,
    huff: Box<HuffmanOxide>,
    dict: DictOxide,
}

impl ParamsOxide {
    fn new(flags: u32) -> Self {
        ParamsOxide {
            flags,
            greedy_parsing: flags & TDEFL_GREEDY_PARSING_FLAG != 0,
            block_index: 0,
            saved_match_dist: 0,
            saved_match_len: 0,
            saved_lit: 0,
            flush: TDEFLFlush::None,
            flush_ofs: 0,
            flush_remaining: 0,
            finished: false,
            adler32: MZ_ADLER32_INIT,
            src_pos: 0,
            out_buf_ofs: 0,
            prev_return_status: TDEFLStatus::Okay,
            saved_bit_buffer: 0,
            saved_bits_in: 0,
        }
    }

    fn update_flags(&mut self, flags: u32) {
        self.flags = flags;
        self.greedy_parsing = self.flags & TDEFL_GREEDY_PARSING_FLAG != 0;
    }

    /// Reset state, saving settings.
    fn reset(&mut self) {
        self.block_index = 0;
        self.saved_match_len = 0;
        self.saved_match_dist = 0;
        self.saved_lit = 0;
        self.flush = TDEFLFlush::None;
        self.flush_ofs = 0;
        self.flush_remaining = 0;
        self.finished = false;
        self.adler32 = MZ_ADLER32_INIT;
        self.src_pos = 0;
        self.out_buf_ofs = 0;
        self.prev_return_status = TDEFLStatus::Okay;
        self.saved_bit_buffer = 0;
        self.saved_bits_in = 0;
    }
}

impl CompressorOxide {
    /// Create a new `CompressorOxide` with the given flags.
    ///
    /// # Notes
    /// This function may be changed to take different parameters in the future.
    pub fn new(flags: u32) -> Self {
        CompressorOxide {
            lz: LZOxide::new(),
            params: ParamsOxide::new(flags),
            /// Put HuffmanOxide on the heap with default trick to avoid
            /// excessive stack copies.
            huff: Box::default(),
            dict: DictOxide::new(flags),
        }
    }
}

/// Return status of compression.
#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum TDEFLStatus {
    /// Usage error.
    ///
    /// This indicates that either the [`CompressorOxide`] experienced a previous error, or the
    /// stream has already been [`TDEFLFlush::Finish`]'d.
    BadParam = -2,

    /// Error putting data into output buffer.
    ///
    /// This usually indicates a too-small buffer.
    PutBufFailed = -1,

    /// Compression succeeded normally.
    Okay = 0,

    /// Compression succeeded and the deflate stream was ended.
    ///
    /// This is the result of calling compression with [`TDEFLFlush::Finish`].
    Done = 1,
}

struct ParamsOxide {
    pub flags: u32,
    pub greedy_parsing: bool,
    pub block_index: u32,

    pub saved_match_dist: u32,
    pub saved_match_len: u32,
    pub saved_lit: u8,

    pub flush: TDEFLFlush,
    pub flush_ofs: u32,
    pub flush_remaining: u32,
    pub finished: bool,

    pub adler32: u32,

    pub src_pos: usize,

    pub out_buf_ofs: usize,
    pub prev_return_status: TDEFLStatus,

    pub saved_bit_buffer: u32,
    pub saved_bits_in: u32,
}

fn compress_normal(d: &mut CompressorOxide, in_buf: &[u8], p: &mut Prediction) -> bool {
    let mut src_pos = d.params.src_pos;

    let mut lookahead_size = d.dict.lookahead_size;
    let mut lookahead_pos = d.dict.lookahead_pos;
    let mut saved_lit = d.params.saved_lit;
    let mut saved_match_dist = d.params.saved_match_dist;
    let mut saved_match_len = d.params.saved_match_len;

    while src_pos < in_buf.len() || (d.params.flush != TDEFLFlush::None && lookahead_size != 0) {
        let src_buf_left = in_buf.len() - src_pos;
        let num_bytes_to_process = cmp::min(src_buf_left, MAX_MATCH_LEN - lookahead_size as usize);

        if lookahead_size + d.dict.size >= usize::from(MIN_MATCH_LEN) - 1
            && num_bytes_to_process > 0
        {
            let dictb = &mut d.dict.b;

            let mut dst_pos = (lookahead_pos + lookahead_size as usize) & LZ_DICT_SIZE_MASK;
            let mut ins_pos = lookahead_pos + lookahead_size as usize - 2;
            // Start the hash value from the first two bytes
            let mut hash = update_hash(
                u16::from(dictb.dict[(ins_pos & LZ_DICT_SIZE_MASK) as usize]),
                dictb.dict[((ins_pos + 1) & LZ_DICT_SIZE_MASK) as usize],
            );

            lookahead_size += num_bytes_to_process;

            for &c in &in_buf[src_pos..src_pos + num_bytes_to_process] {
                // Add byte to input buffer.
                dictb.dict[dst_pos as usize] = c;
                if (dst_pos as usize) < MAX_MATCH_LEN - 1 {
                    dictb.dict[LZ_DICT_SIZE + dst_pos as usize] = c;
                }

                // Generate hash from the current byte,
                hash = update_hash(hash, c);
                dictb.next[(ins_pos & LZ_DICT_SIZE_MASK) as usize] = dictb.hash[hash as usize];
                // and insert it into the hash chain.
                dictb.hash[hash as usize] = ins_pos as u16;
                dst_pos = (dst_pos + 1) & LZ_DICT_SIZE_MASK;
                ins_pos += 1;
            }
            src_pos += num_bytes_to_process;
        } else {
            let dictb = &mut d.dict.b;
            for &c in &in_buf[src_pos..src_pos + num_bytes_to_process] {
                let dst_pos = (lookahead_pos + lookahead_size) & LZ_DICT_SIZE_MASK;
                dictb.dict[dst_pos as usize] = c;
                if (dst_pos as usize) < MAX_MATCH_LEN - 1 {
                    dictb.dict[LZ_DICT_SIZE + dst_pos as usize] = c;
                }

                lookahead_size += 1;
                if lookahead_size + d.dict.size >= MIN_MATCH_LEN.into() {
                    let ins_pos = lookahead_pos + lookahead_size - 3;
                    let hash = ((u32::from(dictb.dict[(ins_pos & LZ_DICT_SIZE_MASK) as usize])
                        << (LZ_HASH_SHIFT * 2))
                        ^ ((u32::from(dictb.dict[((ins_pos + 1) & LZ_DICT_SIZE_MASK) as usize])
                            << LZ_HASH_SHIFT)
                            ^ u32::from(c)))
                        & (LZ_HASH_SIZE as u32 - 1);

                    dictb.next[(ins_pos & LZ_DICT_SIZE_MASK) as usize] = dictb.hash[hash as usize];
                    dictb.hash[hash as usize] = ins_pos as u16;
                }
            }

            src_pos += num_bytes_to_process;
        }

        d.dict.size = cmp::min(LZ_DICT_SIZE - lookahead_size, d.dict.size);
        if d.params.flush == TDEFLFlush::None && (lookahead_size as usize) < MAX_MATCH_LEN {
            break;
        }

        let mut len_to_move = 1;
        let mut cur_match_dist = 0;
        let mut cur_match_len = if saved_match_len != 0 {
            saved_match_len
        } else {
            u32::from(MIN_MATCH_LEN) - 1
        };
        let cur_pos = lookahead_pos & LZ_DICT_SIZE_MASK;
        if d.params.flags & (TDEFL_RLE_MATCHES | TDEFL_FORCE_ALL_RAW_BLOCKS) != 0 {
            // If TDEFL_RLE_MATCHES is set, we only look for repeating sequences of the current byte.
            if d.dict.size != 0 && d.params.flags & TDEFL_FORCE_ALL_RAW_BLOCKS == 0 {
                let c = d.dict.b.dict[((cur_pos.wrapping_sub(1)) & LZ_DICT_SIZE_MASK) as usize];
                cur_match_len = d.dict.b.dict[cur_pos as usize..(cur_pos + lookahead_size) as usize]
                    .iter()
                    .take_while(|&x| *x == c)
                    .count() as u32;
                if cur_match_len < MIN_MATCH_LEN.into() {
                    cur_match_len = 0
                } else {
                    cur_match_dist = 1
                }
            }
        } else {
            // Try to find a match for the bytes at the current position.
            let dist_len = d.dict.find_match(
                lookahead_pos,
                d.dict.size,
                lookahead_size as u32,
                cur_match_dist,
                cur_match_len,
            );
            cur_match_dist = dist_len.0;
            cur_match_len = dist_len.1;
        }

        let far_and_small = cur_match_len == MIN_MATCH_LEN.into() && cur_match_dist >= 8 * 1024;
        let filter_small = d.params.flags & TDEFL_FILTER_MATCHES != 0 && cur_match_len <= 5;
        if far_and_small || filter_small || cur_pos == cur_match_dist as usize {
            cur_match_dist = 0;
            cur_match_len = 0;
        }

        if saved_match_len != 0 {
            if cur_match_len > saved_match_len {
                record_literal(&mut d.huff, &mut d.lz, saved_lit, p);
                if cur_match_len >= 128 {
                    record_match(&mut d.huff, &mut d.lz, cur_match_len, cur_match_dist, p);
                    saved_match_len = 0;
                    len_to_move = cur_match_len as usize;
                } else {
                    saved_lit = d.dict.b.dict[cur_pos as usize];
                    saved_match_dist = cur_match_dist;
                    saved_match_len = cur_match_len;
                }
            } else {
                record_match(&mut d.huff, &mut d.lz, saved_match_len, saved_match_dist, p);
                len_to_move = (saved_match_len - 1) as usize;
                saved_match_len = 0;
            }
        } else if cur_match_dist == 0 {
            record_literal(
                &mut d.huff,
                &mut d.lz,
                d.dict.b.dict[cmp::min(cur_pos as usize, d.dict.b.dict.len() - 1)],
                p,
            );
        } else if d.params.greedy_parsing
            || (d.params.flags & TDEFL_RLE_MATCHES != 0)
            || cur_match_len >= 128
        {
            // If we are using lazy matching, check for matches at the next byte if the current
            // match was shorter than 128 bytes.
            record_match(&mut d.huff, &mut d.lz, cur_match_len, cur_match_dist, p);
            len_to_move = cur_match_len as usize;
        } else {
            saved_lit = d.dict.b.dict[cmp::min(cur_pos as usize, d.dict.b.dict.len() - 1)];
            saved_match_dist = cur_match_dist;
            saved_match_len = cur_match_len;
        }

        lookahead_pos += len_to_move;
        assert!(lookahead_size >= len_to_move);
        lookahead_size -= len_to_move;
        d.dict.size = cmp::min(d.dict.size + len_to_move, LZ_DICT_SIZE);

        let lz_buf_tight = d.lz.code_position > LZ_CODE_BUF_SIZE - 8;
        let raw = d.params.flags & TDEFL_FORCE_ALL_RAW_BLOCKS != 0;
        let fat = ((d.lz.code_position * 115) >> 7) >= d.lz.total_bytes as usize;
        let fat_or_raw = (d.lz.total_bytes > 31 * 1024) && (fat || raw);

        if lz_buf_tight || fat_or_raw {
            d.params.src_pos = src_pos;
            // These values are used in flush_block, so we need to write them back here.
            d.dict.lookahead_size = lookahead_size;
            d.dict.lookahead_pos = lookahead_pos;

            let n = flush_block(d, TDEFLFlush::None).unwrap_or(TDEFLStatus::PutBufFailed as i32);
            if n != 0 {
                d.params.saved_lit = saved_lit;
                d.params.saved_match_dist = saved_match_dist;
                d.params.saved_match_len = saved_match_len;
                return n > 0;
            }
        }
    }

    d.params.src_pos = src_pos;
    d.dict.lookahead_size = lookahead_size;
    d.dict.lookahead_pos = lookahead_pos;
    d.params.saved_lit = saved_lit;
    d.params.saved_match_dist = saved_match_dist;
    d.params.saved_match_len = saved_match_len;
    true
}

const COMP_FAST_LOOKAHEAD_SIZE: usize = 4096;

enum Match {
    Literal(u8),
    Match(u16, u16),
}

pub struct MinzAnalyzer<'a> {
    buffer: &'a [u8],
    c: CompressorOxide,
}

impl<'a> MinzAnalyzer<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        MinzAnalyzer {
            buffer: buffer,
            c: CompressorOxide::new(0),
        }
    }

    pub fn analyze(&mut self, block: &PreflateTokenBlock) -> anyhow::Result<BlockAnalysisResult> {
        let mut analysis = BlockAnalysisResult {
            block_type: block.block_type,
            token_count: block.tokens.len() as u32,
            token_info: vec![0; block.tokens.len()],
            block_size_predicted: true,
            input_eof: false,
            last_block: false, // Set this to true if this is the last block.
            padding_bits: block.padding_bits,
            padding_counts: block.padding_bit_count,
            correctives: Vec::new(),
        };

        for i in 0..block.tokens.len() {
            let target_token = &block.tokens[i];

            let mut predicted_token = find_next_token(&mut self.c, self.buffer);
            match predicted_token {
                Some(Match::Literal(_lit)) => {
                    assert!(target_token.len() == 1);
                }
                Some(Match::Match(match_len, match_dist)) => {
                    assert!(
                        target_token.dist() == match_dist.into()
                            && target_token.len() == match_len.into()
                    );
                }
                None => {
                    break;
                }
            }
        }

        Ok(analysis)
    }
}

fn find_next_token(d: &mut CompressorOxide, in_buf: &[u8]) -> Option<Match> {
    let mut src_pos = d.params.src_pos;
    let mut lookahead_size = d.dict.lookahead_size;
    let mut lookahead_pos = d.dict.lookahead_pos;

    let mut cur_pos = lookahead_pos & LZ_DICT_SIZE_MASK;

    debug_assert!(d.lz.code_position < LZ_CODE_BUF_SIZE - 2);

    if !(src_pos < in_buf.len() || (d.params.flush != TDEFLFlush::None && lookahead_size > 0)) {
        return None;
    }

    let mut dst_pos = ((lookahead_pos + lookahead_size) & LZ_DICT_SIZE_MASK) as usize;
    let mut num_bytes_to_process = cmp::min(
        in_buf.len() - src_pos,
        (COMP_FAST_LOOKAHEAD_SIZE - lookahead_size) as usize,
    );
    lookahead_size += num_bytes_to_process;

    while num_bytes_to_process != 0 {
        let n = cmp::min(LZ_DICT_SIZE - dst_pos, num_bytes_to_process);
        d.dict.b.dict[dst_pos..dst_pos + n].copy_from_slice(&in_buf[src_pos..src_pos + n]);

        if dst_pos < MAX_MATCH_LEN - 1 {
            let m = cmp::min(n, MAX_MATCH_LEN - 1 - dst_pos);
            d.dict.b.dict[dst_pos + LZ_DICT_SIZE..dst_pos + LZ_DICT_SIZE + m]
                .copy_from_slice(&in_buf[src_pos..src_pos + m]);
        }

        src_pos += n;
        dst_pos = (dst_pos + n) & LZ_DICT_SIZE_MASK as usize;
        num_bytes_to_process -= n;
    }

    d.dict.size = cmp::min(LZ_DICT_SIZE - lookahead_size, d.dict.size);
    if d.params.flush == TDEFLFlush::None && lookahead_size < COMP_FAST_LOOKAHEAD_SIZE {
        return None;
    }

    if let Some(token) = find_token(d, cur_pos, lookahead_pos, lookahead_size) {
        let cur_match_len;

        match token {
            Match::Literal(_lit) => {
                cur_match_len = 1;
            }
            Match::Match(match_len, _match_dist) => {
                cur_match_len = match_len;
            }
        }

        lookahead_pos += cur_match_len as usize;
        d.dict.size = cmp::min(d.dict.size + cur_match_len as usize, LZ_DICT_SIZE);
        cur_pos = (cur_pos + cur_match_len as usize) & LZ_DICT_SIZE_MASK;
        lookahead_size -= cur_match_len as usize;

        d.params.src_pos = src_pos;
        d.dict.lookahead_size = lookahead_size;
        d.dict.lookahead_pos = lookahead_pos;

        return Some(token);
    } else {
        return None;
    }
}

fn advance(l: usize) {}

fn find_token(
    d: &mut CompressorOxide,
    cur_pos: usize,
    lookahead_pos: usize,
    lookahead_size: usize,
) -> Option<Match> {
    if lookahead_size < MIN_MATCH_LEN.into() {
        if lookahead_size == 0 {
            return None;
        }

        return Some(Match::Literal(d.dict.b.dict[cur_pos]));
    }

    let mut cur_match_len = 1;

    let first_trigram = d.dict.read_unaligned_u32(cur_pos) & 0xFF_FFFF;

    let hash =
        (first_trigram ^ (first_trigram >> (24 - (LZ_HASH_BITS - 8)))) & LEVEL1_HASH_SIZE_MASK;

    let mut probe_pos = usize::from(d.dict.b.hash[hash as usize]);
    d.dict.b.hash[hash as usize] = lookahead_pos as u16;

    let cur_match_dist = (lookahead_pos - probe_pos as usize) as u16;
    if cur_match_dist as usize <= d.dict.size {
        probe_pos &= LZ_DICT_SIZE_MASK;

        let trigram = d.dict.read_unaligned_u32(probe_pos) & 0xFF_FFFF;

        if first_trigram == trigram {
            // Trigram was tested, so we can start with "+ 3" displacement.
            let mut p = cur_pos + 3;
            let mut q = probe_pos + 3;
            cur_match_len = (|| {
                for _ in 0..32 {
                    let p_data: u64 = d.dict.read_unaligned_u64(p);
                    let q_data: u64 = d.dict.read_unaligned_u64(q);
                    let xor_data = p_data ^ q_data;
                    if xor_data == 0 {
                        p += 8;
                        q += 8;
                    } else {
                        let trailing = xor_data.trailing_zeros();
                        return p as u32 - cur_pos as u32 + (trailing >> 3);
                    }
                }

                if cur_match_dist == 0 {
                    0
                } else {
                    MAX_MATCH_LEN as u32
                }
            })();

            if cur_match_len < MIN_MATCH_LEN.into()
                || (cur_match_len == MIN_MATCH_LEN.into() && cur_match_dist >= 8 * 1024)
            {
                let lit = first_trigram as u8;
                Some(Match::Literal(lit))
            } else {
                // Limit the match to the length of the lookahead so we don't create a match
                // that ends after the end of the input data.
                cur_match_len = cmp::min(cur_match_len, lookahead_size as u32);
                debug_assert!(cur_match_len >= MIN_MATCH_LEN.into());
                debug_assert!(cur_match_dist >= 1);
                debug_assert!(cur_match_dist as usize <= LZ_DICT_SIZE);

                Some(Match::Match(cur_match_len as u16, cur_match_dist as u16))
            }
        } else {
            Some(Match::Literal(first_trigram as u8))
        }
    } else {
        None
    }
}

fn flush_block(d: &mut CompressorOxide, flags: TDEFLFlush) -> Result<i32> {
    Ok(1)
}
