/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::{
    deflate::deflate_token::{DeflateHuffmanType, DeflateToken, DeflateTokenReference},
    preflate_error::{err_exit_code, AddContext, ExitCode, Result},
};

use std::io::{Cursor, Read};

use super::{deflate_constants, deflate_token::DeflateTokenBlock};

use super::{
    bit_reader::BitReader,
    huffman_encoding::{HuffmanOriginalEncoding, HuffmanReader},
};

/// Used to read binary data in DEFLATE format and convert it to plaintext and a list of tokenized blocks
/// containing the literals and distance codes that were used to compress the file
pub struct DeflateReader<R> {
    input: BitReader<R>,
    plain_text: Vec<u8>,
}

impl<R: Read> DeflateReader<R> {
    pub fn new(compressed_text: R) -> Self {
        DeflateReader {
            input: BitReader::new(compressed_text),
            plain_text: Vec::new(),
        }
    }

    /// reads the padding at the end of the file
    pub fn read_eof_padding(&mut self) -> u8 {
        let padding_bit_count = 8 - self.input.bit_position_in_current_byte() as u8;
        self.input.get(padding_bit_count.into()).unwrap() as u8
    }

    /// moves ownership out of block reader
    pub fn move_plain_text(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.plain_text)
    }

    fn read_bit(&mut self) -> Result<bool> {
        Ok(self.input.get(1)? != 0)
    }

    fn read_bits(&mut self, cbits: u32) -> std::io::Result<u32> {
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

    pub fn read_block(&mut self, last: &mut bool) -> Result<DeflateTokenBlock> {
        *last = self.read_bit()?;
        let mode = self.read_bits(2)?;

        match mode {
            0 => {
                let padding_bit_count = 8 - self.input.bit_position_in_current_byte() as u8;
                let padding_bits = self.read_bits(padding_bit_count.into())? as u8;

                let len = self.read_bits(16)?;
                let ilen = self.read_bits(16)?;
                if (len ^ ilen) != 0xffff {
                    return err_exit_code(ExitCode::InvalidDeflate, "Block length mismatch");
                }

                self.input.flush_buffer_to_byte_boundary();

                let mut uncompressed = Vec::with_capacity(len as usize);

                for _i in 0..len {
                    let b = self.input.read_byte()?;
                    uncompressed.push(b);
                    self.write_literal(b);
                }

                Ok(DeflateTokenBlock::Stored {
                    uncompressed,
                    padding_bits,
                })
            }
            1 => {
                // some compressors don't flush blocks at all if they are using static huffman encoding
                // since there's no need to keep track of statistics etc.

                let mut tokens = Vec::new();
                let decoder = HuffmanReader::create_fixed()?;
                if let Err(e) = self.decode_block(&decoder, &mut tokens) {
                    if e.exit_code() == ExitCode::ShortRead {
                        Ok(DeflateTokenBlock::Huffman {
                            tokens,
                            huffman_type: DeflateHuffmanType::Static { incomplete: true },
                        })
                    } else {
                        Err(e)
                    }
                } else {
                    Ok(DeflateTokenBlock::Huffman {
                        tokens,
                        huffman_type: DeflateHuffmanType::Static { incomplete: false },
                    })
                }
            }

            2 => {
                let huffman_encoding = HuffmanOriginalEncoding::read(&mut self.input)?;

                let decoder = HuffmanReader::create_from_original_encoding(&huffman_encoding)?;

                let mut tokens = Vec::new();
                self.decode_block(&decoder, &mut tokens).context()?;

                Ok(DeflateTokenBlock::Huffman {
                    tokens,
                    huffman_type: DeflateHuffmanType::Dynamic { huffman_encoding },
                })
            }

            _ => err_exit_code(ExitCode::InvalidDeflate, "Invalid block type"),
        }
    }

    fn decode_block(
        &mut self,
        decoder: &HuffmanReader,
        tokens: &mut Vec<DeflateToken>,
    ) -> Result<()> {
        let mut earliest_reference = i32::MAX;
        let mut cur_pos = 0;

        loop {
            let lit_len: u32 = decoder.fetch_next_literal_code(&mut self.input)?.into();
            if lit_len < 256 {
                self.write_literal(lit_len as u8);
                tokens.push(DeflateToken::Literal(lit_len as u8));
                cur_pos += 1;
            } else if lit_len == 256 {
                return Ok(());
            } else {
                let lcode: u32 = lit_len - deflate_constants::NONLEN_CODE_COUNT as u32;
                if lcode >= deflate_constants::LEN_CODE_COUNT as u32 {
                    return err_exit_code(ExitCode::InvalidDeflate, "Invalid length code");
                }
                let len: u32 = deflate_constants::MIN_MATCH
                    + deflate_constants::LENGTH_BASE_TABLE[lcode as usize] as u32
                    + self
                        .read_bits(deflate_constants::LENGTH_EXTRA_TABLE[lcode as usize].into())?;

                // length of 258 can be encoded two ways: 284 with 5 one bits (non-standard) or as 285 with 0 extra bits (standard)
                let irregular258 =
                    len == 258 && lcode != deflate_constants::LEN_CODE_COUNT as u32 - 1;

                let dcode = decoder.fetch_next_distance_char(&mut self.input)? as u32;
                if dcode >= deflate_constants::DIST_CODE_COUNT as u32 {
                    return err_exit_code(ExitCode::InvalidDeflate, "Invalid distance code");
                }

                let dist = 1
                    + deflate_constants::DIST_BASE_TABLE[dcode as usize] as u32
                    + self.read_bits(deflate_constants::DIST_EXTRA_TABLE[dcode as usize].into())?;

                if dist as usize > self.plain_text.len() {
                    return err_exit_code(ExitCode::InvalidDeflate, "Invalid distance");
                }

                self.write_reference(dist, len);
                tokens.push(DeflateToken::Reference(DeflateTokenReference::new(
                    len,
                    dist,
                    irregular258,
                )));

                earliest_reference = std::cmp::min(earliest_reference, cur_pos - (dist as i32));
                cur_pos += len as i32;
            }
        }
    }
}

/// represents the complete deflate stream
pub struct DeflateContents {
    pub compressed_size: usize,
    pub plain_text: Vec<u8>,
    pub blocks: Vec<DeflateTokenBlock>,
    pub eof_padding: u8,
}

pub fn parse_deflate(
    compressed_data: &[u8],
    deflate_info_dump_level: u32,
) -> Result<DeflateContents> {
    let mut input_stream = Cursor::new(compressed_data);
    let mut block_decoder = DeflateReader::new(&mut input_stream);
    let mut blocks = Vec::new();
    let mut last = false;
    while !last {
        let block = block_decoder.read_block(&mut last)?;

        if deflate_info_dump_level > 0 {
            // Log information about this deflate compressed block
            match &block {
                DeflateTokenBlock::Stored {
                    uncompressed,
                    padding_bits,
                } => {
                    println!(
                        "Block: stored, uncompressed={} padding_bits={}",
                        uncompressed.len(),
                        padding_bits
                    );
                }
                DeflateTokenBlock::Huffman { tokens, .. } => {
                    println!("Block: tokens={}", tokens.len());
                }
            }
        }

        blocks.push(block);
    }
    let eof_padding = block_decoder.read_eof_padding();
    let plain_text = block_decoder.move_plain_text();
    let compressed_size = input_stream.position() as usize;

    /*// write to file
     let mut f = std::fs::File::create("c:\\temp\\treegdi.deflate")
    .unwrap();
    std::io::Write::write_all(&mut f, &compressed_data[0..compressed_size]).unwrap();*/

    Ok(DeflateContents {
        compressed_size,
        plain_text,
        blocks,
        eof_padding,
    })
}
