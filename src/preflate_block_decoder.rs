use crate::crc32::Crc32;
use crate::{preflate_token};

use std::io::{Read, Seek};

use crate::{
    huffman_decoder::HuffmanDecoder,
    preflate_constants,
    preflate_token::{BlockType, PreflateToken, PreflateTokenBlock},
    zip_bit_reader::ZipBitReader,
};

pub struct PreflateBlockDecoder<'a, R> {
    input: ZipBitReader<'a, R>,
    pub output: Vec<u8>,
}

impl<'a, R: Read + Seek> PreflateBlockDecoder<'a, R> {
    pub fn new(input: &'a mut R, max_readable_bytes: i64) -> anyhow::Result<Self> {
        Ok(PreflateBlockDecoder {
            input: ZipBitReader::new(input, max_readable_bytes)?,
            output: Vec::new(),
        })
    }

    fn read_bit(&mut self) -> anyhow::Result<bool> {
        Ok(self.input.get(1)? != 0)
    }

    fn read_bits(&mut self, cbits: u32) -> anyhow::Result<u32> {
        self.input.get(cbits)
    }

    fn write_literal(&mut self, byte: u8, crc: &mut Crc32) {
        self.output.push(byte);
        crc.update_crc(byte);
    }

    fn write_reference(&mut self, dist: u32, len: u32, crc: &mut Crc32) {
        let start = self.output.len() - dist as usize;
        for i in 0..len {
            let byte = self.output[start + i as usize];
            crc.update_crc(byte);
            self.output.push(byte);
        }
    }

    pub fn read_block(
        &mut self,
        last: &mut bool,
        crc: &mut Crc32,
    ) -> anyhow::Result<PreflateTokenBlock> {
        let mut blk;

        *last = self.read_bit()?;
        let mode = self.read_bits(2)?;

        match mode {
            0 => {
                blk = PreflateTokenBlock::new_stored_block(0);
                blk.uncompressed_start_pos = self.output.len() as u32;
                blk.block_type = BlockType::Stored;
                blk.padding_bit_count = ((-self.input.bit_position()?) & 7) as u8;
                blk.padding_bits = self.read_bits(blk.padding_bit_count.into())? as u8;
                let len = self.read_bits(16)?;
                let ilen = self.read_bits(16)?;
                if (len ^ ilen) != 0xffff {
                    return Err(anyhow::Error::msg("Blocllength mismatch"));
                }
                blk.uncompressed_len = len.into();
                blk.context_len = 0;

                for _i in 0..len {
                    let b = self.input.read_byte()?;
                    self.write_literal(b, crc);
                }

                Ok(blk)
            }
            1 => {
                blk = PreflateTokenBlock::new_huff_block(BlockType::StaticHuff);
                blk.uncompressed_start_pos = self.output.len() as u32;
                let decoder = HuffmanDecoder::create_fixed()?;
                self.decode_block(&decoder, &mut blk, crc)?;
                return Ok(blk);
            }

            2 => {
                blk = PreflateTokenBlock::new_huff_block(BlockType::DynamicHuff);
                blk.uncompressed_start_pos = self.output.len() as u32;
                let decoder = HuffmanDecoder::create_from_bit_reader(&mut self.input, 0)?;
                self.decode_block(&decoder, &mut blk, crc)?;
                return Ok(blk);
            }

            _ => {
                return Err(anyhow::Error::msg("Invalid block type"));
            }
        }
    }

    fn decode_block(
        &mut self,
        decoder: &HuffmanDecoder,
        blk: &mut PreflateTokenBlock,
        crc: &mut Crc32,
    ) -> anyhow::Result<()> {
        let mut earliest_reference = i32::MAX;
        let mut cur_pos = 0;

        Ok(loop {
            let lit_len: u32 = decoder.fetch_next_literal_code(&mut self.input)?.into();
            if lit_len < 256 {
                self.write_literal(lit_len as u8, crc);
                blk.tokens.push(preflate_token::TOKEN_LITERAL);
                cur_pos += 1;
            } else if lit_len == 256 {
                blk.uncompressed_len = self.output.len() as u32 - blk.uncompressed_start_pos;
                blk.context_len = -earliest_reference;
                break;
            } else {
                let lcode: u32 = lit_len - preflate_constants::NONLEN_CODE_COUNT as u32;
                if lcode >= preflate_constants::LEN_CODE_COUNT.into() {
                    return Err(anyhow::Error::msg("Invalid length code"));
                }
                let len: u32 = preflate_constants::MIN_MATCH as u32
                    + preflate_constants::LENGTH_BASE_TABLE[lcode as usize] as u32
                    + self
                        .read_bits(preflate_constants::LENGTH_EXTRA_TABLE[lcode as usize].into())?;
                let irregular_258 =
                    len == 258 && lcode != preflate_constants::LEN_CODE_COUNT as u32 - 1;
                let dcode = decoder.fetch_next_distance_char(&mut self.input)? as u32;
                if dcode >= preflate_constants::DIST_CODE_COUNT.into() {
                    return Err(anyhow::Error::msg("Invalid distance code"));
                }
                let dist = 1
                    + preflate_constants::DIST_BASE_TABLE[dcode as usize] as u32
                    + self
                        .read_bits(preflate_constants::DIST_EXTRA_TABLE[dcode as usize].into())?;
                if dist as usize > self.output.len() {
                    return Err(anyhow::Error::msg("Invalid distance"));
                }
                self.write_reference(dist as u32, len as u32, crc);
                blk.tokens
                    .push(PreflateToken::new_reference(len, dist, irregular_258));
                earliest_reference = std::cmp::min(earliest_reference, cur_pos - (dist as i32));
                cur_pos += len as i32;
            }
        })
    }
}
