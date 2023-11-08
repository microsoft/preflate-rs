use anyhow::Context;

use std::io::{Read, Seek};

use crate::{
    huffman_table::{HuffmanOriginalEncoding, HuffmanReader},
    preflate_constants,
    preflate_token::{BlockType, PreflateTokenBlock},
    zip_bit_reader::ZipBitReader,
};

/// Used to read binary data in deflate format and convert it to plaintext and a list of tokenized blocks
/// containing the literals and distance codes that were used to compress the file
pub struct DeflateDecoder<'a, R> {
    input: ZipBitReader<'a, R>,
    plain_text: Vec<u8>,
}

impl<'a, R: Read + Seek> DeflateDecoder<'a, R> {
    pub fn new(compressed_text: &'a mut R, max_readable_bytes: i64) -> anyhow::Result<Self> {
        Ok(DeflateDecoder {
            input: ZipBitReader::new(compressed_text, max_readable_bytes)?,
            plain_text: Vec::new(),
        })
    }

    /// reads the padding at the end of the file
    pub fn read_eof_padding(&mut self) -> u8 {
        let padding_bit_count = 8 - self.input.bit_position_in_current_byte() as u8;
        self.input.get(padding_bit_count.into()).unwrap() as u8
    }

    pub fn get_plain_text(&self) -> &[u8] {
        &self.plain_text
    }

    fn read_bit(&mut self) -> anyhow::Result<bool> {
        Ok(self.input.get(1)? != 0)
    }

    fn read_bits(&mut self, cbits: u32) -> anyhow::Result<u32> {
        self.input.get(cbits)
    }

    fn write_literal(&mut self, byte: u8) {
        self.plain_text.push(byte);
    }

    fn write_reference(&mut self, dist: u32, len: u32) {
        let start = self.plain_text.len() - dist as usize;
        for i in 0..len {
            let byte = self.plain_text[start + i as usize];
            self.plain_text.push(byte);
        }
    }

    pub fn read_block(&mut self, last: &mut bool) -> anyhow::Result<PreflateTokenBlock> {
        let mut blk;

        *last = self.read_bit()?;
        let mode = self.read_bits(2)?;

        match mode {
            0 => {
                blk = PreflateTokenBlock::new(BlockType::Stored);
                blk.block_type = BlockType::Stored;
                let padding_bit_count = 8 - self.input.bit_position_in_current_byte() as u8;
                blk.padding_bits = self.read_bits(padding_bit_count.into())? as u8;

                let len = self.read_bits(16)?;
                let ilen = self.read_bits(16)?;
                if (len ^ ilen) != 0xffff {
                    return Err(anyhow::Error::msg("Blocllength mismatch"));
                }
                blk.uncompressed_len = len.into();
                blk.context_len = 0;

                self.input.flush_buffer_to_byte_boundary()?;

                for _i in 0..len {
                    let b = self.input.read_byte()?;
                    self.write_literal(b);
                }

                Ok(blk)
            }
            1 => {
                blk = PreflateTokenBlock::new(BlockType::StaticHuff);
                let decoder = HuffmanReader::create_fixed()?;
                self.decode_block(&decoder, &mut blk)?;
                return Ok(blk);
            }

            2 => {
                blk = PreflateTokenBlock::new(BlockType::DynamicHuff);

                blk.huffman_encoding = HuffmanOriginalEncoding::read(&mut self.input)?;

                let decoder = HuffmanReader::create_from_original_encoding(&blk.huffman_encoding)?;

                self.decode_block(&decoder, &mut blk)
                    .with_context(|| "decode_block dyn")?;
                return Ok(blk);
            }

            _ => {
                return Err(anyhow::Error::msg("Invalid block type"));
            }
        }
    }

    fn decode_block(
        &mut self,
        decoder: &HuffmanReader,
        blk: &mut PreflateTokenBlock,
    ) -> anyhow::Result<()> {
        let mut earliest_reference = i32::MAX;
        let mut cur_pos = 0;

        Ok(loop {
            let lit_len: u32 = decoder.fetch_next_literal_code(&mut self.input)?.into();
            if lit_len < 256 {
                self.write_literal(lit_len as u8);
                blk.add_literal(lit_len as u8);
                cur_pos += 1;
            } else if lit_len == 256 {
                blk.uncompressed_len = cur_pos as u32;
                blk.context_len = -earliest_reference;
                break;
            } else {
                let lcode: u32 = lit_len - preflate_constants::NONLEN_CODE_COUNT as u32;
                if lcode >= preflate_constants::LEN_CODE_COUNT as u32 {
                    return Err(anyhow::Error::msg("Invalid length code"));
                }
                let len: u32 = preflate_constants::MIN_MATCH as u32
                    + preflate_constants::LENGTH_BASE_TABLE[lcode as usize] as u32
                    + self
                        .read_bits(preflate_constants::LENGTH_EXTRA_TABLE[lcode as usize].into())?;

                // length of 258 can be encoded two ways: 284 with 5 one bits (non-standard) or as 285 with 0 extra bits (standard)
                let irregular_258 =
                    len == 258 && lcode != preflate_constants::LEN_CODE_COUNT as u32 - 1;

                let dcode = decoder.fetch_next_distance_char(&mut self.input)? as u32;
                if dcode >= preflate_constants::DIST_CODE_COUNT as u32 {
                    return Err(anyhow::Error::msg("Invalid distance code"));
                }
                let dist = 1
                    + preflate_constants::DIST_BASE_TABLE[dcode as usize] as u32
                    + self
                        .read_bits(preflate_constants::DIST_EXTRA_TABLE[dcode as usize].into())?;
                if dist as usize > self.plain_text.len() {
                    return Err(anyhow::Error::msg("Invalid distance"));
                }
                self.write_reference(dist as u32, len as u32);
                blk.add_reference(len, dist, irregular_258);

                earliest_reference = std::cmp::min(earliest_reference, cur_pos - (dist as i32));
                cur_pos += len as i32;
            }
        })
    }
}
