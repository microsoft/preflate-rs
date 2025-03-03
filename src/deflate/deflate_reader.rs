/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::{
    deflate::{
        bit_reader::ReadBits,
        deflate_token::{DeflateHuffmanType, DeflateToken, DeflateTokenReference},
    },
    preflate_error::{err_exit_code, ExitCode, Result},
};

use std::io::Cursor;

use super::{
    bit_reader::ScopedRead,
    deflate_constants,
    deflate_token::{DeflateTokenBlock, DeflateTokenBlockType},
};

use super::{
    bit_reader::BitReader,
    huffman_encoding::{HuffmanOriginalEncoding, HuffmanReader},
};

enum ReadState {
    BlockStart,
    BlockStartType,
    StartUncompressed,
    InsideUncompressed(usize, Vec<u8>, u8),
    StartHuffmanDynamic,
    Huffman(HuffmanReader, DeflateHuffmanType, Vec<DeflateToken>),
}

/// Used to read binary data in DEFLATE format and convert it to plaintext and a list of tokenized blocks
/// containing the literals and distance codes that were used to compress the file
pub struct DeflateReader {
    read_state: ReadState,
    last_block: bool,
}

impl DeflateReader {
    pub fn new() -> Self {
        DeflateReader {
            read_state: ReadState::BlockStart,
            last_block: false,
        }
    }

    pub fn read_block<R: ScopedRead>(
        &mut self,
        bit_reader: &mut BitReader<R>,
        plain_text: &mut Vec<u8>,
    ) -> Result<DeflateTokenBlock> {
        loop {
            match &mut self.read_state {
                ReadState::BlockStart => {
                    self.last_block = bit_reader.get(1)? == 1;
                    self.read_state = ReadState::BlockStartType;
                }
                ReadState::BlockStartType => {
                    let mode = bit_reader.get(2)?;
                    match mode {
                        0 => self.read_state = ReadState::StartUncompressed,
                        1 => {
                            self.read_state = ReadState::Huffman(
                                HuffmanReader::create_fixed()?,
                                DeflateHuffmanType::Static,
                                Vec::new(),
                            )
                        }
                        2 => self.read_state = ReadState::StartHuffmanDynamic,
                        _ => return err_exit_code(ExitCode::InvalidDeflate, "Invalid block type"),
                    }
                }
                ReadState::StartUncompressed => {
                    let (len, padding_bits) = bit_reader.scoped_read(|r| {
                        let padding_bits = r.read_padding_bits();

                        debug_assert!(r.bits_left() & 7 == 0);

                        let len = r.get(16)?;
                        let ilen = r.get(16)?;
                        if (len ^ ilen) != 0xffff {
                            return err_exit_code(
                                ExitCode::InvalidDeflate,
                                "Block length mismatch",
                            );
                        }
                        Ok((len as usize, padding_bits))
                    })?;

                    self.read_state = ReadState::InsideUncompressed(
                        len as usize,
                        Vec::with_capacity(len as usize),
                        padding_bits,
                    );
                }
                ReadState::InsideUncompressed(len, content, padding_bits) => {
                    while content.len() < *len {
                        content.push(bit_reader.read_byte()?);
                    }

                    plain_text.extend_from_slice(content.as_slice());

                    let block = DeflateTokenBlock {
                        block_type: DeflateTokenBlockType::Stored {
                            uncompressed: std::mem::take(content),
                            padding_bits: *padding_bits,
                        },
                        last: self.last_block,
                        tail_padding_bits: 0, // never unaligned for uncompressed blocks
                    };

                    self.read_state = ReadState::BlockStart;
                    return Ok(block);
                }

                ReadState::Huffman(reader, hufftype, tokens) => {
                    Self::decode_block(bit_reader, plain_text, reader, tokens)?;
                    let b = DeflateTokenBlockType::Huffman {
                        tokens: core::mem::take(tokens),
                        huffman_type: core::mem::take(hufftype),
                    };

                    let last_padding_bits = if self.last_block {
                        bit_reader.read_padding_bits()
                    } else {
                        0
                    };

                    self.read_state = ReadState::BlockStart;
                    return Ok(DeflateTokenBlock {
                        block_type: b,
                        last: self.last_block,
                        tail_padding_bits: last_padding_bits,
                    });
                }
                ReadState::StartHuffmanDynamic => {
                    let huffman_encoding =
                        bit_reader.scoped_read(|r| HuffmanOriginalEncoding::read(r))?;

                    let decoder = HuffmanReader::create_from_original_encoding(&huffman_encoding)?;

                    self.read_state = ReadState::Huffman(
                        decoder,
                        DeflateHuffmanType::Dynamic { huffman_encoding },
                        Vec::new(),
                    );
                }
            }
        }
    }

    fn decode_block<R: ScopedRead>(
        input: &mut BitReader<R>,
        plain_text: &mut Vec<u8>,
        decoder: &HuffmanReader,
        tokens: &mut Vec<DeflateToken>,
    ) -> Result<()> {
        let mut earliest_reference = i32::MAX;
        let mut cur_pos = 0;

        loop {
            let token = input.scoped_read(|r| {
                let lit_len: u32 = decoder.fetch_next_literal_code(r)?.into();
                if lit_len < 256 {
                    return Ok(Some(DeflateToken::new_lit(lit_len as u8)));
                } else if lit_len == 256 {
                    return Ok(None);
                } else {
                    let lcode: u32 = lit_len - deflate_constants::NONLEN_CODE_COUNT as u32;
                    if lcode >= deflate_constants::LEN_CODE_COUNT as u32 {
                        return err_exit_code(ExitCode::InvalidDeflate, "Invalid length code");
                    }
                    let len: u32 = deflate_constants::MIN_MATCH
                        + deflate_constants::LENGTH_BASE_TABLE[lcode as usize] as u32
                        + r.get(deflate_constants::LENGTH_EXTRA_TABLE[lcode as usize].into())?;

                    // length of 258 can be encoded two ways: 284 with 5 one bits (non-standard) or as 285 with 0 extra bits (standard)
                    let irregular258 =
                        len == 258 && lcode != deflate_constants::LEN_CODE_COUNT as u32 - 1;

                    let dcode = decoder.fetch_next_distance_char(r)? as u32;
                    if dcode >= deflate_constants::DIST_CODE_COUNT as u32 {
                        return err_exit_code(ExitCode::InvalidDeflate, "Invalid distance code");
                    }

                    let dist = 1
                        + deflate_constants::DIST_BASE_TABLE[dcode as usize] as u32
                        + r.get(deflate_constants::DIST_EXTRA_TABLE[dcode as usize].into())?;

                    if dist as usize > plain_text.len() {
                        return err_exit_code(ExitCode::InvalidDeflate, "Invalid distance");
                    }

                    return Ok(Some(DeflateToken::Reference(DeflateTokenReference::new(
                        len,
                        dist,
                        irregular258,
                    ))));
                }
            })?;

            match token {
                Some(t) => {
                    match t {
                        DeflateToken::Literal(byte) => {
                            plain_text.push(byte);
                            cur_pos += 1;
                        }
                        DeflateToken::Reference(r) => {
                            append_reference_to_plaintext(plain_text, r.dist(), r.len());
                            earliest_reference =
                                std::cmp::min(earliest_reference, cur_pos - (r.dist() as i32));
                            cur_pos += r.len() as i32;
                        }
                    }
                    tokens.push(t);
                }
                None => {
                    return Ok(());
                }
            }
        }
    }
}

/// represents the complete deflate stream
pub struct DeflateContents {
    pub compressed_size: usize,
    pub plain_text: Vec<u8>,
    pub blocks: Vec<DeflateTokenBlock>,
}

pub fn parse_deflate(
    compressed_data: &[u8],
    deflate_info_dump_level: u32,
) -> Result<DeflateContents> {
    let mut bit_reader = BitReader::new(Cursor::new(compressed_data));
    let mut block_decoder = DeflateReader::new();
    let mut plain_text = Vec::new();
    let mut blocks = Vec::new();
    let mut last = false;
    while !last {
        let block = block_decoder.read_block(&mut bit_reader, &mut plain_text)?;

        if deflate_info_dump_level > 0 {
            // Log information about this deflate compressed block
            match &block.block_type {
                DeflateTokenBlockType::Stored {
                    uncompressed,
                    padding_bits,
                    ..
                } => {
                    println!(
                        "Block: stored, uncompressed={} padding_bits={}",
                        uncompressed.len(),
                        padding_bits
                    );
                }
                DeflateTokenBlockType::Huffman { tokens, .. } => {
                    println!("Block: tokens={}", tokens.len());
                }
            }
        }

        last = block.last;

        blocks.push(block);
    }

    let compressed_size = bit_reader.position() as usize;

    /*// write to file
     let mut f = std::fs::File::create("c:\\temp\\treegdi.deflate")
    .unwrap();
    std::io::Write::write_all(&mut f, &compressed_data[0..compressed_size]).unwrap();*/

    Ok(DeflateContents {
        compressed_size,
        plain_text,
        blocks,
    })
}

/// writes a reference to the buffer, which copies the text from a previous location
/// to the current location. In most cases this is non-overlapping, but there are some
/// cases where there is overlap between the source and destination.
pub fn append_reference_to_plaintext(plain_text: &mut Vec<u8>, dist: u32, len: u32) {
    if dist == 1 {
        // special case for distance 1, just repeat the last byte n times
        let byte = plain_text[plain_text.len() - 1];
        plain_text.resize(plain_text.len() + len as usize, byte);
    } else if dist >= len {
        // no overlap
        plain_text.extend_from_within(
            plain_text.len() - dist as usize..plain_text.len() - dist as usize + len as usize,
        );
    } else {
        // general case, rarely called, copy one character at a time
        let start = plain_text.len() - dist as usize;

        plain_text.reserve(len as usize);

        for i in 0..len {
            let byte = plain_text[start + i as usize];
            plain_text.push(byte);
        }
    }
}

/// read file piece by piece, testing the partial read logic that should be able to handle
/// a buffer break at any point
#[test]
fn read_partial_blocks() {
    use byteorder::ReadBytesExt;
    use std::collections::VecDeque;

    let mut file = Cursor::new(crate::process::read_file(
        "compressed_flate2_level0.deflate",
    ));

    let mut read = BitReader::new(VecDeque::new());

    let mut r = crate::deflate::deflate_reader::DeflateReader::new();
    let mut plain_text = Vec::new();

    let mut newcontent = Vec::new();
    loop {
        let b = loop {
            match r.read_block(&mut read, &mut plain_text) {
                Ok(block) => {
                    break block;
                }
                Err(e) => {
                    assert_eq!(e.exit_code(), ExitCode::ShortRead);
                }
            }
            read.get_inner_mut().push_back(file.read_u8().unwrap());
        };
        let last = b.last;
        newcontent.push(b);
        if last {
            break;
        }
    }
}
