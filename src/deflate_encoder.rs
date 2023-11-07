use anyhow::Result;

use crate::{
    bit_writer::BitWriter,
    huffman_table::HuffmanReader,
    preflate_token::{BlockType, PreflateTokenBlock},
};

pub struct DeflateEncoder {
    pub data: Vec<u8>,
    pub pos: u32,
    pub bit_buffer: u32,
    pub bit_buffer_len: u32,
}

impl DeflateEncoder {
    pub fn encode_block(
        &mut self,
        plain_text: &[u8],
        bitwriter: &mut BitWriter,
        block: &PreflateTokenBlock,
    ) -> Result<()> {
        match block.block_type {
            BlockType::Stored => {
                bitwriter.write(0, 2, &mut self.data);
                bitwriter.pad(block.padding_bits, &mut self.data);
                bitwriter.flush_whole_bytes(&mut self.data);

                self.data
                    .extend_from_slice(&block.uncompressed_len.to_le_bytes());
                self.data
                    .extend_from_slice(&(!block.uncompressed_len).to_le_bytes());

                self.data.extend_from_slice(
                    &plain_text[block.uncompressed_start_pos as usize
                        ..(block.uncompressed_start_pos + block.uncompressed_len) as usize],
                );
            }
            BlockType::StaticHuff => {
                bitwriter.write(1, 2, &mut self.data);
                let decoder = HuffmanReader::create_fixed()?;
                self.encode_block_with_decoder(bitwriter, block, &decoder)?;
            }
            BlockType::DynamicHuff => {
                let decoder =
                    HuffmanReader::create_from_original_encoding(&block.huffman_encoding)?;

                self.encode_block_with_decoder(bitwriter, block, &decoder)?;
            }
        }

        Ok(())
    }

    pub fn encode_block_with_decoder(
        &mut self,
        bitwriter: &mut BitWriter,
        block: &PreflateTokenBlock,
        decoder: &HuffmanReader,
    ) -> Result<()> {
        Ok(())
    }
}
