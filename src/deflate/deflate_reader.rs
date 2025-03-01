/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::{
    deflate::deflate_token::{DeflateHuffmanType, DeflateToken, DeflateTokenReference},
    preflate_error::{err_exit_code, ExitCode, Result},
};

use std::io::{Cursor, Read, Seek};

use super::{
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
    StartHuffmanDynamic,
    Huffman(HuffmanReader, DeflateHuffmanType, Vec<DeflateToken>),
}

/// Used to read binary data in DEFLATE format and convert it to plaintext and a list of tokenized blocks
/// containing the literals and distance codes that were used to compress the file
pub struct DeflateReader<R: Read + Seek> {
    input: BitReader<R>,
    plain_text: Vec<u8>,
    read_state: ReadState,
    last_block: bool,
}

impl<R: Read + Seek> DeflateReader<R> {
    pub fn new(compressed_text: R) -> Self {
        DeflateReader {
            input: BitReader::new(compressed_text),
            plain_text: Vec::new(),
            read_state: ReadState::BlockStart,
            last_block: false,
        }
    }

    /// reads the padding at the end of the file
    pub fn read_eof_padding(&mut self) -> u8 {
        let padding_bit_count = self.input.bits_left() & 7;
        self.input.get(padding_bit_count).unwrap() as u8
    }

    /// moves ownership out of block reader
    pub fn move_plain_text(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.plain_text)
    }

    fn write_literal(&mut self, byte: u8) {
        self.plain_text.push(byte);
    }

    pub fn read_block(&mut self) -> Result<DeflateTokenBlock> {
        loop {
            match &mut self.read_state {
                ReadState::BlockStart => {
                    self.last_block = self.input.get(1)? == 1;
                    self.read_state = ReadState::BlockStartType;
                }
                ReadState::BlockStartType => {
                    let mode = self.input.get(2)?;
                    match mode {
                        0 => self.read_state = ReadState::StartUncompressed,
                        1 => {
                            self.read_state = ReadState::Huffman(
                                HuffmanReader::create_fixed()?,
                                DeflateHuffmanType::Static { incomplete: false },
                                Vec::new(),
                            )
                        }
                        2 => self.read_state = ReadState::StartHuffmanDynamic,
                        _ => return err_exit_code(ExitCode::InvalidDeflate, "Invalid block type"),
                    }
                }
                ReadState::StartUncompressed => {
                    let (uncompressed, padding_bits) = self.input.run_with_rollback(|r| {
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

                        let mut uncompressed = Vec::with_capacity(len as usize);

                        for _i in 0..len {
                            let b = r.read_byte()?;
                            uncompressed.push(b);
                        }
                        Ok((uncompressed, padding_bits))
                    })?;

                    for i in uncompressed.iter() {
                        self.write_literal(*i);
                    }

                    self.read_state = ReadState::BlockStart;
                    return Ok(DeflateTokenBlock {
                        block_type: DeflateTokenBlockType::Stored {
                            uncompressed,
                            padding_bits,
                        },
                        last: self.last_block,
                        last_padding_bits: 0, // never bit unaligned for uncompressed blocks
                    });
                }
                ReadState::Huffman(reader, hufftype, tokens) => {
                    Self::decode_block(&mut self.input, &mut self.plain_text, reader, tokens)?;
                    let b = DeflateTokenBlockType::Huffman {
                        tokens: core::mem::take(tokens),
                        huffman_type: core::mem::take(hufftype),
                    };

                    let last_padding_bits = if self.last_block {
                        self.input.read_padding_bits()
                    } else {
                        0
                    };

                    self.read_state = ReadState::BlockStart;
                    return Ok(DeflateTokenBlock {
                        block_type: b,
                        last: self.last_block,
                        last_padding_bits,
                    });
                }
                ReadState::StartHuffmanDynamic => {
                    let huffman_encoding = self
                        .input
                        .run_with_rollback(|r| HuffmanOriginalEncoding::read(r))?;

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

    fn decode_block(
        input: &mut BitReader<R>,
        plain_text: &mut Vec<u8>,
        decoder: &HuffmanReader,
        tokens: &mut Vec<DeflateToken>,
    ) -> Result<()> {
        let mut earliest_reference = i32::MAX;
        let mut cur_pos = 0;

        loop {
            let token = input.run_with_rollback(|r| {
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
        let block = block_decoder.read_block()?;

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
        assert!(start + len as usize <= plain_text.capacity());

        for i in 0..len {
            let byte = plain_text[start + i as usize];
            plain_text.push(byte);
        }
    }
}
