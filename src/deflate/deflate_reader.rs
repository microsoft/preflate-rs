/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::{
    deflate::deflate_token::{DeflateHuffmanType, DeflateToken, DeflateTokenReference},
    preflate_error::{err_exit_code, AddContext, ExitCode, Result},
    preflate_input::PlainText,
};

use std::io::{Cursor, Read};

use super::{
    bit_reader::ReadBits,
    deflate_constants,
    deflate_token::{DeflateTokenBlock, DeflateTokenBlockType, PartialBlock},
};

use super::{
    bit_reader::BitReader,
    huffman_encoding::{HuffmanOriginalEncoding, HuffmanReader},
};

#[derive(Debug)]
pub struct DeflateParser {
    state: DeflateParserState,
    bit_reader: BitReader,
    plain_text: PlainText,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum DeflateParserState {
    StartBlock,
    ContinueStaticBlock { last: bool },
    Done,
}

impl DeflateParser {
    pub fn new() -> Self {
        Self {
            state: DeflateParserState::StartBlock,
            bit_reader: BitReader::new(),
            plain_text: PlainText::new(),
        }
    }

    pub fn is_done(&self) -> bool {
        self.state == DeflateParserState::Done
    }

    pub fn plain_text(&self) -> &PlainText {
        &self.plain_text
    }

    pub fn detach_plain_text(self) -> PlainText {
        self.plain_text
    }

    pub fn parse(&mut self, compressed_data: &[u8]) -> Result<DeflateContents> {
        let mut blocks = Vec::new();

        let mut cursor = &mut Cursor::new(compressed_data);

        self.read_blocks_internal(&mut cursor, &mut blocks)?;

        Ok(DeflateContents {
            compressed_size: self.bit_reader.bytes_read() as usize,
            blocks,
        })
    }

    fn read_blocks_internal<R: Read>(
        &mut self,
        reader: &mut R,
        blocks: &mut Vec<DeflateTokenBlock>,
    ) -> Result<DeflateParserState> {
        loop {
            let (last, mode) = match self.state {
                DeflateParserState::StartBlock => (
                    self.bit_reader.get(1, reader)? != 0,
                    self.bit_reader.get(2, reader)?,
                ),
                DeflateParserState::ContinueStaticBlock { last } => (last, 1),
                DeflateParserState::Done => {
                    return Ok(DeflateParserState::Done);
                }
            };

            match mode {
                0 => {
                    let padding_bits = self.bit_reader.read_padding_bits() as u8;

                    assert!(self.bit_reader.bits_left() == 0);

                    let len = self.bit_reader.get(16, reader)?;
                    let ilen = self.bit_reader.get(16, reader)?;
                    if (len ^ ilen) != 0xffff {
                        return err_exit_code(ExitCode::InvalidDeflate, "Block length mismatch");
                    }

                    let mut uncompressed = Vec::with_capacity(len as usize);

                    for _i in 0..len {
                        let b = self.bit_reader.read_byte(reader)?;
                        uncompressed.push(b);
                        self.plain_text.push(b);
                    }

                    blocks.push(DeflateTokenBlock {
                        block_type: DeflateTokenBlockType::Stored {
                            uncompressed,
                            head_padding_bits: padding_bits,
                        },
                        last,
                    });
                }
                1 => {
                    // some compressors don't flush blocks at all if they are using static huffman encoding
                    // since there's no need to keep track of statistics etc.

                    let mut tokens = Vec::new();
                    let decoder = HuffmanReader::create_fixed()?;
                    decode_tokens(
                        &decoder,
                        &mut tokens,
                        &mut self.plain_text,
                        &mut self.bit_reader,
                        reader,
                        &mut 0,
                        &mut 0,
                        &mut 0,
                    )
                    .context()?;

                    blocks.push(DeflateTokenBlock {
                        block_type: DeflateTokenBlockType::Huffman {
                            tokens,
                            huffman_type: DeflateHuffmanType::Static,
                            partial: PartialBlock::Whole,
                            tail_padding_bits: if last {
                                Some(self.bit_reader.read_padding_bits())
                            } else {
                                None
                            },
                        },
                        last,
                    });
                }

                2 => {
                    let huffman_encoding =
                        HuffmanOriginalEncoding::read(&mut self.bit_reader, reader)?;

                    let decoder = HuffmanReader::create_from_original_encoding(&huffman_encoding)?;

                    let mut tokens = Vec::new();

                    // don't checkpoint dynamic huffman blocks since they don't get very big
                    // and it adds unnecessary complexity
                    decode_tokens(
                        &decoder,
                        &mut tokens,
                        &mut self.plain_text,
                        &mut self.bit_reader,
                        reader,
                        &mut 0,
                        &mut 0,
                        &mut 0,
                    )
                    .context()?;

                    blocks.push(DeflateTokenBlock {
                        block_type: DeflateTokenBlockType::Huffman {
                            tokens,
                            huffman_type: DeflateHuffmanType::Dynamic { huffman_encoding },
                            tail_padding_bits: if last {
                                Some(self.bit_reader.read_padding_bits())
                            } else {
                                None
                            },
                            partial: PartialBlock::Whole,
                        },
                        last,
                    });
                }

                _ => return err_exit_code(ExitCode::InvalidDeflate, "Invalid block type"),
            }

            if last {
                self.state = DeflateParserState::Done;
            }
        }
    }
}

fn decode_tokens<R: Read>(
    decoder: &HuffmanReader,
    tokens: &mut Vec<DeflateToken>,
    plain_text: &mut PlainText,
    bit_reader: &mut BitReader,
    reader: &mut R,
    checkpoint_bytes_read: &mut usize,
    checkpoint_plain_text: &mut usize,
    checkpoint_tokens: &mut usize,
) -> Result<()> {
    let mut earliest_reference = i32::MAX;
    let mut cur_pos = 0;

    loop {
        let lit_len: u32 = decoder.fetch_next_literal_code(bit_reader, reader)?.into();
        if lit_len < 256 {
            plain_text.push(lit_len as u8);
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
                + bit_reader.get(
                    deflate_constants::LENGTH_EXTRA_TABLE[lcode as usize].into(),
                    reader,
                )?;

            // length of 258 can be encoded two ways: 284 with 5 one bits (non-standard) or as 285 with 0 extra bits (standard)
            let irregular258 = len == 258 && lcode != deflate_constants::LEN_CODE_COUNT as u32 - 1;

            let dcode = decoder.fetch_next_distance_char(bit_reader, reader)? as u32;
            if dcode >= deflate_constants::DIST_CODE_COUNT as u32 {
                return err_exit_code(ExitCode::InvalidDeflate, "Invalid distance code");
            }

            let dist = 1
                + deflate_constants::DIST_BASE_TABLE[dcode as usize] as u32
                + bit_reader.get(
                    deflate_constants::DIST_EXTRA_TABLE[dcode as usize].into(),
                    reader,
                )?;

            plain_text.append_reference(dist, len)?;
            tokens.push(DeflateToken::Reference(DeflateTokenReference::new(
                len,
                dist,
                irregular258,
            )));

            earliest_reference = std::cmp::min(earliest_reference, cur_pos - (dist as i32));
            cur_pos += len as i32;
        }

        // checkpoint a good byte aligned place to stop if we hit the end of the stream
        if bit_reader.bits_left() == 0 {
            *checkpoint_bytes_read = bit_reader.bytes_read() as usize;
            *checkpoint_plain_text = plain_text.text().len();
            *checkpoint_tokens = tokens.len();
        }
    }
}

/// represents the complete deflate stream
pub struct DeflateContents {
    pub compressed_size: usize,
    pub blocks: Vec<DeflateTokenBlock>,
}

impl std::fmt::Debug for DeflateContents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeflateContents")
            .field("compressed_size", &self.compressed_size)
            .field("blocks", &self.blocks.len())
            .finish()
    }
}

/// parses an entire deflate stream and asserts if it isn't complete
#[cfg(test)]
pub fn parse_deflate_whole(compressed_data: &[u8]) -> Result<(DeflateContents, PlainText)> {
    let mut parse = DeflateParser::new();
    let deflate_content = parse.parse(compressed_data)?;

    match parse.state {
        DeflateParserState::Done => (),
        _ => panic!("Deflate stream not complete"),
    }

    Ok((deflate_content, parse.plain_text))
}

#[test]
fn test_partial_read() {
    use crate::utils::{assert_eq_array, read_file};

    let d = read_file("bigcompressed_zlibng_level1.deflate");
    let (complete, _plain_text_complete) = parse_deflate_whole(&d).unwrap();

    let mut start_offset = 0;
    let mut end_offset = 1;
    let mut allblocks = Vec::new();

    let mut deflate_parser = DeflateParser::new();

    while !deflate_parser.is_done() {
        match deflate_parser.parse(&d[start_offset..end_offset]) {
            Ok(mut dc) => {
                allblocks.append(&mut dc.blocks);
                start_offset += dc.compressed_size;

                end_offset = (start_offset + 1).min(d.len());
            }
            Err(e) => {
                assert_eq!(e.exit_code(), ExitCode::ShortRead);
                end_offset = (end_offset + 100000).min(d.len());
            }
        }
    }

    println!("blocks {:?}", allblocks);

    assert_eq_array(&get_tokens(&allblocks), &get_tokens(&complete.blocks));

    let reconstruct = crate::deflate::deflate_writer::write_deflate_blocks(&allblocks);

    assert_eq_array(&reconstruct, &d);
}

#[cfg(test)]
fn get_tokens(blocks: &[DeflateTokenBlock]) -> Vec<DeflateToken> {
    let mut tokens = Vec::new();
    for b in blocks {
        match &b.block_type {
            DeflateTokenBlockType::Huffman { tokens: t, .. } => tokens.extend_from_slice(t),
            DeflateTokenBlockType::Stored { uncompressed, .. } => {
                for u in uncompressed {
                    tokens.push(DeflateToken::Literal(*u));
                }
            }
        }
    }

    tokens
}
