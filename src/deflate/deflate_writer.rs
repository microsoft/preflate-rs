/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::preflate_error::Result;

use crate::preflate_token::PreflateHuffmanType;
use crate::{
    preflate_constants::{
        quantize_distance, quantize_length, DIST_BASE_TABLE, DIST_EXTRA_TABLE, LENGTH_BASE_TABLE,
        LENGTH_EXTRA_TABLE, LITLEN_CODE_COUNT, MIN_MATCH, NONLEN_CODE_COUNT,
    },
    preflate_token::{PreflateToken, PreflateTokenBlock},
};

use super::bit_writer::BitWriter;
use super::huffman_encoding::HuffmanWriter;

/// Takes a tokenized block and writes it to the original compressed output.
pub struct DeflateWriter {
    /// bit writer to write partial bits to output
    bitwriter: BitWriter,

    /// compressed output
    output: Vec<u8>,
}

impl DeflateWriter {
    pub fn new() -> Self {
        Self {
            output: Vec::new(),
            bitwriter: BitWriter::default(),
        }
    }

    pub fn detach_output(&mut self) -> Vec<u8> {
        let mut o = Vec::new();
        o.append(&mut self.output);
        o
    }

    pub fn encode_block(&mut self, block: &PreflateTokenBlock, last: bool) -> Result<()> {
        self.bitwriter.write(last as u32, 1, &mut self.output);
        match block {
            PreflateTokenBlock::Stored {
                uncompressed,
                padding_bits,
            } => {
                self.bitwriter.write(0, 2, &mut self.output);
                self.bitwriter.pad(*padding_bits, &mut self.output);
                self.bitwriter.flush_whole_bytes(&mut self.output);

                self.output
                    .extend_from_slice(&(uncompressed.len() as u16).to_le_bytes());
                self.output
                    .extend_from_slice(&(!uncompressed.len() as u16).to_le_bytes());

                self.output.extend_from_slice(&uncompressed);
            }
            PreflateTokenBlock::Huffman {
                tokens,
                huffman_type,
            } => match huffman_type {
                PreflateHuffmanType::Static { .. } => {
                    self.bitwriter.write(1, 2, &mut self.output);
                    let huffman_writer = HuffmanWriter::start_fixed_huffman_table();
                    self.encode_block_with_decoder(tokens, &huffman_writer);
                }
                PreflateHuffmanType::Dynamic {
                    huffman_encoding, ..
                } => {
                    let huffman_writer = HuffmanWriter::start_dynamic_huffman_table(
                        &mut self.bitwriter,
                        &huffman_encoding,
                        &mut self.output,
                    )?;

                    self.encode_block_with_decoder(tokens, &huffman_writer);
                }
            },
        }

        Ok(())
    }

    pub fn flush_with_padding(&mut self, padding: u8) {
        self.bitwriter.pad(padding, &mut self.output);
        self.bitwriter.flush_whole_bytes(&mut self.output);
    }

    fn encode_block_with_decoder(
        &mut self,
        tokens: &Vec<PreflateToken>,
        huffman_writer: &HuffmanWriter,
    ) {
        for token in tokens {
            match token {
                PreflateToken::Literal(lit) => {
                    huffman_writer.write_literal(
                        &mut self.bitwriter,
                        &mut self.output,
                        u16::from(*lit),
                    );
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
                }
            }
        }

        huffman_writer.write_literal(&mut self.bitwriter, &mut self.output, 256);
    }
}
