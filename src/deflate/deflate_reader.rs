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

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum DeflateParserState {
    StartBlock,
    ContinueStaticBlock { last: bool },
    Done,
}

fn read_blocks(
    state: DeflateParserState,
    plain_text: &mut PlainText,
    input: &[u8],
    blocks: &mut Vec<DeflateTokenBlock>,
) -> Result<(usize, DeflateParserState)> {
    let mut input = BitReader::new(Cursor::new(input));

    let mut checkpoint_bytes_read = 0;
    let mut checkpoint_plain_text = plain_text.text().len();

    if let DeflateParserState::ContinueStaticBlock { last } = state {
        let decoder = HuffmanReader::create_fixed()?;

        let mut tokens = Vec::new();
        let mut checkpoint_tokens = 0;
        let r = decode_tokens(
            &decoder,
            &mut tokens,
            plain_text,
            &mut input,
            &mut checkpoint_bytes_read,
            &mut checkpoint_plain_text,
            &mut checkpoint_tokens,
        );

        tokens.truncate(checkpoint_tokens);

        // check for short read
        if let Err(e) = r {
            if e.exit_code() == ExitCode::ShortRead && checkpoint_bytes_read != 0 {
                plain_text.truncate(checkpoint_plain_text);

                blocks.push(DeflateTokenBlock {
                    block_type: DeflateTokenBlockType::Huffman {
                        tokens,
                        huffman_type: DeflateHuffmanType::Static,
                        partial: PartialBlock::Middle,
                        tail_padding_bits: None,
                    },
                    last,
                });

                return Ok((
                    checkpoint_bytes_read,
                    DeflateParserState::ContinueStaticBlock { last: last },
                ));
            }
            // any other error is a real error
            return Err(e).context();
        } else {
            blocks.push(DeflateTokenBlock {
                block_type: DeflateTokenBlockType::Huffman {
                    tokens,
                    huffman_type: DeflateHuffmanType::Static,
                    tail_padding_bits: if last {
                        Some(input.read_padding_bits())
                    } else {
                        None
                    },
                    partial: PartialBlock::End,
                },
                last,
            });
        }

        if last {
            return Ok((input.bytes_read() as usize, DeflateParserState::Done));
        }
    }

    let mut checkpoint_blocks = blocks.len();

    let r = read_blocks_internal(
        &mut input,
        plain_text,
        blocks,
        &mut checkpoint_bytes_read,
        &mut checkpoint_plain_text,
        &mut checkpoint_blocks,
    );
    match r {
        Err(e) => {
            if e.exit_code() == ExitCode::ShortRead && checkpoint_bytes_read != 0 {
                plain_text.truncate(checkpoint_plain_text);
                blocks.truncate(checkpoint_blocks);

                // if we errored out trying to read the block, we can still return
                // the good data we have so far that was lined up to the byte boundary
                return Ok((checkpoint_bytes_read, DeflateParserState::StartBlock));
            }
            return Err(e).context();
        }

        Ok(s) => {
            plain_text.truncate(checkpoint_plain_text);
            Ok((checkpoint_bytes_read, s))
        }
    }
}

fn read_blocks_internal<R: Read>(
    input: &mut BitReader<R>,
    plain_text: &mut PlainText,
    blocks: &mut Vec<DeflateTokenBlock>,
    checkpoint_bytes_read: &mut usize,
    checkpoint_plain_text: &mut usize,
    checkpoint_blocks: &mut usize,
) -> Result<DeflateParserState> {
    loop {
        let last = input.get(1)? != 0;
        let mode = input.get(2)?;

        match mode {
            0 => {
                let padding_bits = input.read_padding_bits() as u8;

                assert!(input.bits_left() == 0);

                let len = input.get(16)?;
                let ilen = input.get(16)?;
                if (len ^ ilen) != 0xffff {
                    return err_exit_code(ExitCode::InvalidDeflate, "Block length mismatch");
                }

                let mut uncompressed = Vec::with_capacity(len as usize);

                for _i in 0..len {
                    let b = input.read_byte()?;
                    uncompressed.push(b);
                    plain_text.push(b);
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

                let mut checkpoint_tokens = 0;
                let mut tokens = Vec::new();
                let decoder = HuffmanReader::create_fixed()?;
                let r = decode_tokens(
                    &decoder,
                    &mut tokens,
                    plain_text,
                    input,
                    checkpoint_bytes_read,
                    checkpoint_plain_text,
                    &mut checkpoint_tokens,
                );

                if let Err(e) = r {
                    if e.exit_code() == ExitCode::ShortRead && tokens.len() > 0 {
                        tokens.truncate(checkpoint_tokens);
                        blocks.push(DeflateTokenBlock {
                            block_type: DeflateTokenBlockType::Huffman {
                                tokens,
                                huffman_type: DeflateHuffmanType::Static,
                                partial: PartialBlock::Start,
                                tail_padding_bits: None,
                            },
                            last,
                        });
                        return Ok(DeflateParserState::ContinueStaticBlock { last });
                    } else {
                        return Err(e).context();
                    }
                }

                blocks.push(DeflateTokenBlock {
                    block_type: DeflateTokenBlockType::Huffman {
                        tokens,
                        huffman_type: DeflateHuffmanType::Static,
                        partial: PartialBlock::Whole,
                        tail_padding_bits: if last {
                            Some(input.read_padding_bits())
                        } else {
                            None
                        },
                    },
                    last,
                });
            }

            2 => {
                let huffman_encoding = HuffmanOriginalEncoding::read(input)?;

                let decoder = HuffmanReader::create_from_original_encoding(&huffman_encoding)?;

                let mut tokens = Vec::new();

                // don't checkpoint dynamic huffman blocks since they don't get very big
                // and it adds unnecessary complexity
                decode_tokens(
                    &decoder,
                    &mut tokens,
                    plain_text,
                    input,
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
                            Some(input.read_padding_bits())
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

        // if we are at a good boundary, record where we are so we can continue from there
        if (input.bits_left() & 7) == 0 {
            *checkpoint_bytes_read = input.bytes_read() as usize;
            *checkpoint_plain_text = plain_text.text().len();
            *checkpoint_blocks = blocks.len();
        }

        if last {
            return Ok(DeflateParserState::Done);
        }
    }
}

fn decode_tokens<R: Read>(
    decoder: &HuffmanReader,
    tokens: &mut Vec<DeflateToken>,
    plain_text: &mut PlainText,
    input: &mut BitReader<R>,
    checkpoint_bytes_read: &mut usize,
    checkpoint_plain_text: &mut usize,
    checkpoint_tokens: &mut usize,
) -> Result<()> {
    let mut earliest_reference = i32::MAX;
    let mut cur_pos = 0;

    loop {
        let lit_len: u32 = decoder.fetch_next_literal_code(input)?.into();
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
                + input.get(deflate_constants::LENGTH_EXTRA_TABLE[lcode as usize].into())?;

            // length of 258 can be encoded two ways: 284 with 5 one bits (non-standard) or as 285 with 0 extra bits (standard)
            let irregular258 = len == 258 && lcode != deflate_constants::LEN_CODE_COUNT as u32 - 1;

            let dcode = decoder.fetch_next_distance_char(input)? as u32;
            if dcode >= deflate_constants::DIST_CODE_COUNT as u32 {
                return err_exit_code(ExitCode::InvalidDeflate, "Invalid distance code");
            }

            let dist = 1
                + deflate_constants::DIST_BASE_TABLE[dcode as usize] as u32
                + input.get(deflate_constants::DIST_EXTRA_TABLE[dcode as usize].into())?;

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
        if input.bits_left() == 0 {
            *checkpoint_bytes_read = input.bytes_read() as usize;
            *checkpoint_plain_text = plain_text.text().len();
            *checkpoint_tokens = tokens.len();
        }
    }
}

/// represents the complete deflate stream
pub struct DeflateContents {
    pub compressed_size: usize,
    pub blocks: Vec<DeflateTokenBlock>,
    pub state: DeflateParserState,
}

impl std::fmt::Debug for DeflateContents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeflateContents")
            .field("compressed_size", &self.compressed_size)
            .field("blocks", &self.blocks.len())
            .field("state", &self.state)
            .finish()
    }
}

/// parses an entire deflate stream and asserts if it isn't complete
#[cfg(test)]
pub fn parse_deflate_whole(compressed_data: &[u8]) -> Result<(DeflateContents, PlainText)> {
    let mut plain_text = PlainText::new();
    match parse_deflate(
        DeflateParserState::StartBlock,
        compressed_data,
        &mut plain_text,
    ) {
        Ok(v) => {
            // no partial reads allowed here
            assert_eq!(v.state, DeflateParserState::Done);
            Ok((v, plain_text))
        }
        Err(e) => Err(e).context(),
    }
}

pub fn parse_deflate(
    start_state: DeflateParserState,
    compressed_data: &[u8],
    plain_text: &mut PlainText,
) -> Result<DeflateContents> {
    let mut blocks = Vec::new();

    let (compressed_size, state) =
        read_blocks(start_state, plain_text, compressed_data, &mut blocks)?;

    Ok(DeflateContents {
        compressed_size: compressed_size,
        blocks,
        state,
    })
}

#[test]
fn test_partial_read() {
    use crate::utils::{assert_eq_array, read_file};

    let d = read_file("bigcompressed_zlibng_level1.deflate");
    let (complete, _plain_text_complete) = parse_deflate_whole(&d).unwrap();

    let mut start_offset = 0;
    let mut end_offset = 1;
    let mut allblocks = Vec::new();
    let mut plain_text = PlainText::new();
    let mut block_state = DeflateParserState::StartBlock;

    loop {
        let r = parse_deflate(block_state, &d[start_offset..end_offset], &mut plain_text);
        match r {
            Ok(mut dc) => {
                println!("{} {} {:?}", start_offset, dc.blocks.len(), dc.state);
                allblocks.append(&mut dc.blocks);
                start_offset += dc.compressed_size;

                end_offset = (start_offset + 1).min(d.len());

                if dc.state == DeflateParserState::Done {
                    break;
                }

                block_state = dc.state;
            }
            Err(e) => {
                assert_eq!(e.exit_code(), ExitCode::ShortRead);
                end_offset = (end_offset + 100000).min(d.len());
            }
        }
    }

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
