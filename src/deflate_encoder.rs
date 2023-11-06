use anyhow::Result;
use byteorder::NetworkEndian;

use crate::{
    bit_writer::BitWriter,
    huffman_table::{HuffmanTable, TreeCodeType},
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
                let decoder = HuffmanTable::create_fixed()?;
                self.encode_block_with_decoder(bitwriter, block, &decoder)?;
            }
            BlockType::DynamicHuff => {
                let decoder = HuffmanTable::create_from_original_encoding(&block.huffman_encoding)?;

                bitwriter.write(2, 2, &mut self.data);

                bitwriter.write(
                    block.huffman_encoding.num_literals as u64 - 257,
                    5,
                    &mut self.data,
                );
                bitwriter.write(
                    block.huffman_encoding.num_dist as u64 - 1,
                    5,
                    &mut self.data,
                );
                bitwriter.write(
                    block.huffman_encoding.code_lengths.len() as u64 - 4,
                    4,
                    &mut self.data,
                );

                let tc_codes =
                    HuffmanTable::calc_huffman_codes(&block.huffman_encoding.code_lengths)?;

                let rg_map_code_length_alphabet_code_lengths = [
                    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
                ];

                for i in 0..tc_codes.len() {
                    let index = rg_map_code_length_alphabet_code_lengths[i];
                    bitwriter.write(
                        block.huffman_encoding.code_lengths[index].into(),
                        3,
                        &mut self.data,
                    );
                }

                for (tree_code, length) in block.huffman_encoding.lengths.iter() {
                    match *tree_code {
                        TreeCodeType::Code => {
                            bitwriter.write(
                                tc_codes[*length as usize].into(),
                                block.huffman_encoding.code_lengths[*length as usize].into(),
                                &mut self.data,
                            );
                        }
                        TreeCodeType::Repeat => {
                            bitwriter.write(
                                tc_codes[16].into(),
                                block.huffman_encoding.code_lengths[16].into(),
                                &mut self.data,
                            );
                            bitwriter.write(*length as u64 - 3 as u64, 2, &mut self.data);
                        }
                        TreeCodeType::ZeroShort => {
                            bitwriter.write(
                                tc_codes[17].into(),
                                block.huffman_encoding.code_lengths[17].into(),
                                &mut self.data,
                            );
                            bitwriter.write(*length as u64 - 10, 3, &mut self.data);
                        }
                        TreeCodeType::ZeroLong => {
                            bitwriter.write(
                                tc_codes[18].into(),
                                block.huffman_encoding.code_lengths[18].into(),
                                &mut self.data,
                            );
                            bitwriter.write(*length as u64 - 138, 11, &mut self.data);
                        }
                    }
                }

                self.encode_block_with_decoder(bitwriter, block, &decoder)?;
            }
        }

        Ok(())
    }

    pub fn encode_block_with_decoder(
        &mut self,
        bitwriter: &mut BitWriter,
        block: &PreflateTokenBlock,
        decoder: &HuffmanTable,
    ) -> Result<()> {
        Ok(())
    }
}
