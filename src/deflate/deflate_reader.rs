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

use super::{
    bit_reader::ReadBits,
    deflate_constants,
    deflate_token::{DeflateTokenBlock, DeflateTokenBlockType},
};

use super::{
    bit_reader::BitReader,
    huffman_encoding::{HuffmanOriginalEncoding, HuffmanReader},
};

/// Used to read binary data in DEFLATE format and convert it to plaintext and a list of tokenized blocks
/// containing the literals and distance codes that were used to compress the file
struct DeflateReader<R: Read> {
    input: BitReader<R>,
    plain_text: Vec<u8>,
    blocks: Vec<DeflateTokenBlock>,
    last_good_block: usize,
    last_good_bytes_read: usize,
    last_good_plain_text: usize,
}

impl<R: Read> DeflateReader<R> {
    /// remember the last good position we were in if we hit the end of stream
    fn checkpoint(&mut self) {
        if self.blocks.len() > 0 {
            self.last_good_block = self.blocks.len() - 1;
            self.last_good_bytes_read = self.bytes_read() as usize;
            self.last_good_plain_text = self.plain_text.len();
        }
    }

    fn new(compressed_text: R) -> Self {
        DeflateReader {
            input: BitReader::new(compressed_text),
            plain_text: Vec::new(),
            last_good_block: 0,
            last_good_bytes_read: 0,
            last_good_plain_text: 0,
            blocks: Vec::new(),
        }
    }

    /// moves ownership out of block reader
    fn move_plain_text(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.plain_text)
    }

    fn move_blocks(&mut self) -> Vec<DeflateTokenBlock> {
        std::mem::take(&mut self.blocks)
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

    fn bytes_read(&self) -> u32 {
        self.input.bytes_read()
    }

    fn read_blocks(&mut self) -> Result<()> {
        loop {
            let last = self.read_bit()?;
            let mode = self.read_bits(2)?;

            match mode {
                0 => {
                    let padding_bits = self.input.read_padding_bits() as u8;

                    assert!(self.input.bits_left() == 0);

                    let len = self.read_bits(16)?;
                    let ilen = self.read_bits(16)?;
                    if (len ^ ilen) != 0xffff {
                        return err_exit_code(ExitCode::InvalidDeflate, "Block length mismatch");
                    }

                    let mut uncompressed = Vec::with_capacity(len as usize);

                    for _i in 0..len {
                        let b = self.input.read_byte()?;
                        uncompressed.push(b);
                        self.write_literal(b);
                    }

                    self.blocks.push(DeflateTokenBlock {
                        block_type: DeflateTokenBlockType::Stored {
                            uncompressed,
                            padding_bits,
                        },
                        last,
                        tail_padding_bits: 0,
                    });
                }
                1 => {
                    // some compressors don't flush blocks at all if they are using static huffman encoding
                    // since there's no need to keep track of statistics etc.

                    let mut tokens = Vec::new();
                    let decoder = HuffmanReader::create_fixed()?;
                    self.decode_block(&decoder, &mut tokens).context()?;

                    self.blocks.push(DeflateTokenBlock {
                        block_type: DeflateTokenBlockType::Huffman {
                            tokens,
                            huffman_type: DeflateHuffmanType::Static,
                        },
                        last,
                        tail_padding_bits: if last {
                            self.input.read_padding_bits()
                        } else {
                            0
                        },
                    });
                }

                2 => {
                    let huffman_encoding = HuffmanOriginalEncoding::read(&mut self.input)?;

                    let decoder = HuffmanReader::create_from_original_encoding(&huffman_encoding)?;

                    let mut tokens = Vec::new();
                    self.decode_block(&decoder, &mut tokens).context()?;

                    self.blocks.push(DeflateTokenBlock {
                        block_type: DeflateTokenBlockType::Huffman {
                            tokens,
                            huffman_type: DeflateHuffmanType::Dynamic { huffman_encoding },
                        },
                        last,
                        tail_padding_bits: if last {
                            self.input.read_padding_bits()
                        } else {
                            0
                        },
                    });
                }

                _ => return err_exit_code(ExitCode::InvalidDeflate, "Invalid block type"),
            }

            if self.input.bits_left() == 0 {
                self.checkpoint();
            }

            if last {
                return Ok(());
            }
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

/// represents the complete deflate stream
pub struct DeflateContents {
    pub compressed_size: usize,
    pub plain_text: Vec<u8>,
    pub blocks: Vec<DeflateTokenBlock>,
}

pub fn parse_deflate(compressed_data: &[u8]) -> Result<DeflateContents> {
    let mut b = DeflateReader::new(Cursor::new(compressed_data));

    if let Err(e) = b.read_blocks() {
        // if we hit the end of the stream, we can still return the good data we have so far
        if e.exit_code() != ExitCode::ShortRead {
            return Err(e);
        }

        if b.blocks.len() > 0 {
            b.blocks.truncate(b.last_good_block);
            b.plain_text.truncate(b.last_good_plain_text);
        }
    }
    Ok(DeflateContents {
        compressed_size: b.last_good_bytes_read,
        plain_text: b.move_plain_text(),
        blocks: b.move_blocks(),
    })
}
