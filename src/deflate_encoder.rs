use anyhow::Result;

use crate::{
    bit_writer::BitWriter,
    huffman_encoding::HuffmanWriter,
    preflate_constants::{
        quantize_distance, quantize_length, DIST_BASE_TABLE, DIST_EXTRA_TABLE, LENGTH_BASE_TABLE,
        LENGTH_EXTRA_TABLE, LITLEN_CODE_COUNT, MIN_MATCH, NONLEN_CODE_COUNT,
    },
    preflate_token::{BlockType, PreflateToken, PreflateTokenBlock},
};

pub struct DeflateEncoder<'a> {
    /// original uncompressed plain text
    plain_text: &'a [u8],

    /// how far we have gotten through the plain text
    plain_text_index: usize,

    /// bit writer to write partial bits to output
    bitwriter: BitWriter,

    /// compressed output
    output: Vec<u8>,
}

impl<'a> DeflateEncoder<'a> {
    pub fn new(plain_text: &'a [u8]) -> Self {
        Self {
            output: Vec::new(),
            plain_text,
            plain_text_index: 0,
            bitwriter: BitWriter::default(),
        }
    }

    pub fn get_output(&self) -> &[u8] {
        &self.output
    }

    pub fn encode_block(&mut self, block: &PreflateTokenBlock, last: bool) -> Result<()> {
        self.bitwriter.write(last as u32, 1, &mut self.output);
        match block.block_type {
            BlockType::Stored => {
                self.bitwriter.write(0, 2, &mut self.output);
                self.bitwriter.pad(block.padding_bits, &mut self.output);
                self.bitwriter.flush_whole_bytes(&mut self.output);

                self.output
                    .extend_from_slice(&(block.uncompressed_len as u16).to_le_bytes());
                self.output
                    .extend_from_slice(&(!block.uncompressed_len as u16).to_le_bytes());

                self.output.extend_from_slice(
                    &self.plain_text[self.plain_text_index
                        ..self.plain_text_index + block.uncompressed_len as usize],
                );

                self.plain_text_index += block.uncompressed_len as usize;
            }
            BlockType::StaticHuff => {
                self.bitwriter.write(1, 2, &mut self.output);
                let huffman_writer = HuffmanWriter::start_fixed_huffman_table();
                self.encode_block_with_decoder(block, &huffman_writer);
            }
            BlockType::DynamicHuff => {
                let huffman_writer = HuffmanWriter::start_dynamic_huffman_table(
                    &mut self.bitwriter,
                    &block.huffman_encoding,
                    &mut self.output,
                )?;

                self.encode_block_with_decoder(block, &huffman_writer);
            }
        }

        Ok(())
    }

    pub fn flush_with_padding(&mut self, padding: u8) {
        self.bitwriter.pad(padding, &mut self.output);
        self.bitwriter.flush_whole_bytes(&mut self.output);
    }

    fn encode_block_with_decoder(
        &mut self,
        block: &PreflateTokenBlock,
        huffman_writer: &HuffmanWriter,
    ) {
        let mut index = self.plain_text_index;

        for token in &block.tokens {
            match token {
                PreflateToken::Literal => {
                    huffman_writer.write_literal(
                        &mut self.bitwriter,
                        &mut self.output,
                        self.plain_text[index].into(),
                    );
                    index += 1;
                }
                PreflateToken::Reference(reference) => {
                    if reference.get_irregular258() {
                        huffman_writer.write_literal(
                            &mut self.bitwriter,
                            &mut self.output,
                            LITLEN_CODE_COUNT as u16 - 2,
                        );
                        self.bitwriter.write(5, 31, &mut self.output);
                    } else {
                        let lencode = quantize_length(reference.len());
                        huffman_writer.write_literal(
                            &mut self.bitwriter,
                            &mut self.output,
                            NONLEN_CODE_COUNT as u16 + lencode as u16,
                        );

                        let lenextra = LENGTH_EXTRA_TABLE[lencode];
                        if lenextra > 0 {
                            self.bitwriter.write(
                                reference.len() - MIN_MATCH - LENGTH_BASE_TABLE[lencode] as u32,
                                lenextra.into(),
                                &mut self.output,
                            );
                        }

                        let distcode = quantize_distance(reference.dist());
                        huffman_writer.write_distance(
                            &mut self.bitwriter,
                            &mut self.output,
                            distcode as u16,
                        );

                        let distextra = DIST_EXTRA_TABLE[distcode];
                        if distextra > 0 {
                            self.bitwriter.write(
                                reference.dist() - 1 - DIST_BASE_TABLE[distcode] as u32,
                                distextra.into(),
                                &mut self.output,
                            );
                        }
                    }

                    index += reference.len() as usize;
                }
            }

            self.plain_text_index = index;
        }

        huffman_writer.write_literal(&mut self.bitwriter, &mut self.output, 256);
    }
}
