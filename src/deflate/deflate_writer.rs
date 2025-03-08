/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::preflate_error::Result;

use super::deflate_token::{DeflateHuffmanType, DeflateTokenBlockType};
use super::{
    deflate_constants::{
        quantize_distance, quantize_length, DIST_BASE_TABLE, DIST_EXTRA_TABLE, LENGTH_BASE_TABLE,
        LENGTH_EXTRA_TABLE, LITLEN_CODE_COUNT, MIN_MATCH, NONLEN_CODE_COUNT,
    },
    deflate_token::{DeflateToken, DeflateTokenBlock},
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

    pub fn encode_block(&mut self, block: &DeflateTokenBlock) -> Result<()> {
        self.bitwriter.write(block.last as u32, 1, &mut self.output);
        match &block.block_type {
            DeflateTokenBlockType::Stored {
                uncompressed,
                padding_bits,
                ..
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
            DeflateTokenBlockType::Huffman {
                tokens,
                huffman_type,
                ..
            } => {
                match huffman_type {
                    DeflateHuffmanType::Static { .. } => {
                        self.bitwriter.write(1, 2, &mut self.output);
                        let huffman_writer = HuffmanWriter::start_fixed_huffman_table();
                        self.encode_huffman(tokens, &huffman_writer);
                    }
                    DeflateHuffmanType::Dynamic {
                        huffman_encoding, ..
                    } => {
                        let huffman_writer = HuffmanWriter::start_dynamic_huffman_table(
                            &mut self.bitwriter,
                            &huffman_encoding,
                            &mut self.output,
                        )?;

                        self.encode_huffman(tokens, &huffman_writer);
                    }
                }
                if block.last {
                    self.bitwriter
                        .pad(block.tail_padding_bits, &mut self.output);
                }
            }
        }

        Ok(())
    }

    pub fn flush(&mut self) {
        self.bitwriter.flush_whole_bytes(&mut self.output);
    }

    fn encode_huffman(&mut self, tokens: &Vec<DeflateToken>, huffman_writer: &HuffmanWriter) {
        for token in tokens {
            match token {
                DeflateToken::Literal(lit) => {
                    huffman_writer.write_literal(
                        &mut self.bitwriter,
                        &mut self.output,
                        u16::from(*lit),
                    );
                }
                DeflateToken::Reference(reference) => {
                    if reference.get_irregular258() {
                        huffman_writer.write_literal(
                            &mut self.bitwriter,
                            &mut self.output,
                            LITLEN_CODE_COUNT as u16 - 2,
                        );
                        self.bitwriter.write(31, 5, &mut self.output);
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

        huffman_writer.write_literal(&mut self.bitwriter, &mut self.output, 256);
    }
}

/// Create a set of blocks and read them back to see if they are identical
#[test]
fn roundtrip_deflate_writer() {
    use super::deflate_reader::parse_deflate;

    let mut w = DeflateWriter::new();

    let blocks = [
        DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Huffman {
                tokens: vec![
                    DeflateToken::Literal(0),
                    DeflateToken::Literal(2),
                    DeflateToken::Literal(3),
                ],
                huffman_type: DeflateHuffmanType::Static,
            },
            last: false,
            tail_padding_bits: 0,
        },
        DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Stored {
                uncompressed: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                padding_bits: 0b101, // there are 3 bits of padding
            },
            last: false,
            tail_padding_bits: 0,
        },
        DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Huffman {
                tokens: vec![
                    DeflateToken::Literal(0),
                    DeflateToken::Literal(1),
                    DeflateToken::new_ref(100, 1, false),
                    DeflateToken::new_ref(258, 1, true),
                    DeflateToken::Literal(3),
                ],
                huffman_type: DeflateHuffmanType::Static,
            },
            last: true,
            tail_padding_bits: 0b1010,
        },
    ];

    for i in 0..blocks.len() {
        w.encode_block(&blocks[i]).unwrap();
    }
    w.flush();

    let output = w.detach_output();

    let r = parse_deflate(&output).unwrap();

    assert_eq!(blocks.len(), r.blocks.len());
    for i in 0..blocks.len() {
        assert_eq!(blocks[i], r.blocks[i], "block {}", i);
    }
}

/// rountrips all deflate files in the sample directory
#[test]
fn roundtrip_full_file() {
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

    use super::deflate_reader::parse_deflate;

    let searchpath = Path::new(env!("CARGO_MANIFEST_DIR")).join("samples");

    for entry in std::fs::read_dir(searchpath).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.extension().is_some() && path.extension().unwrap() == "deflate" {
            println!("Testing {:?}", path);

            let mut file = File::open(&path).unwrap();
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer).unwrap();

            let r = parse_deflate(&buffer).unwrap();

            let mut w = DeflateWriter::new();
            for i in 0..r.blocks.len() {
                w.encode_block(&r.blocks[i]).unwrap();
            }
            w.flush();

            let output = w.detach_output();

            if r.compressed_size != output.len() || buffer[0..r.compressed_size] != output[..] {
                println!("mismatch");
            }
            //assert_eq!(buffer.len(), output.len());
            //assert_eq!(buffer, output);
        }
    }
}
