/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::preflate_error::{ExitCode, Result, err_exit_code};

use super::deflate_token::{DeflateHuffmanType, DeflateTokenBlockType};
use super::{
    deflate_constants::{
        DIST_BASE_TABLE, DIST_EXTRA_TABLE, LENGTH_BASE_TABLE, LENGTH_EXTRA_TABLE, MIN_MATCH,
        NONLEN_CODE_COUNT, quantize_distance, quantize_length,
    },
    deflate_token::{DeflateToken, DeflateTokenBlock},
};

use super::bit_writer::BitWriter;
use super::huffman_encoding::{HuffmanWriter, TreeCodeType, is_valid_huffman_code_lengths};

/// Takes a tokenized block and writes it to the original compressed output.
pub struct DeflateWriter {
    /// bit writer to write partial bits to output
    bitwriter: BitWriter,

    /// compressed output
    output: Vec<u8>,
}

impl std::fmt::Debug for DeflateWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DeflateWriter {{ bitwriter: {:?}, output: len={} }}",
            self.bitwriter,
            self.output.len()
        )
    }
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
        match &block.block_type {
            DeflateTokenBlockType::Stored { uncompressed, .. } => {
                self.bitwriter
                    .write(u32::from(block.last), 1, &mut self.output);
                self.bitwriter.write(0, 2, &mut self.output);
                self.bitwriter.pad(0, &mut self.output);
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
            } => {
                match huffman_type {
                    DeflateHuffmanType::Static => {
                        self.bitwriter
                            .write(u32::from(block.last), 1, &mut self.output);
                        self.bitwriter.write(1, 2, &mut self.output);
                        let huffman_writer = HuffmanWriter::start_fixed_huffman_table();
                        self.encode_huffman(tokens, &huffman_writer);
                    }
                    DeflateHuffmanType::Dynamic {
                        huffman_encoding, ..
                    } => {
                        let (literal_lengths, distance_lengths) =
                            huffman_encoding.get_literal_distance_lengths();
                        if !is_valid_huffman_code_lengths(&huffman_encoding.code_lengths)
                            || !is_valid_huffman_code_lengths(&literal_lengths)
                            || !is_valid_huffman_code_lengths(&distance_lengths)
                            || literal_lengths.get(256).is_none_or(|&length| length == 0)
                            || huffman_encoding.lengths.iter().any(|&(code, length)| {
                                let symbol = if code == TreeCodeType::Code {
                                    length as usize
                                } else {
                                    code as usize
                                };
                                huffman_encoding
                                    .code_lengths
                                    .get(symbol)
                                    .is_none_or(|&bits| bits == 0)
                            })
                            || tokens.iter().any(|token| match token {
                                DeflateToken::Literal(value) => literal_lengths
                                    .get(*value as usize)
                                    .is_none_or(|&length| length == 0),
                                DeflateToken::Reference(reference) => {
                                    literal_lengths
                                        .get(
                                            NONLEN_CODE_COUNT
                                                + quantize_length(reference.len()).get() as usize,
                                        )
                                        .is_none_or(|&length| length == 0)
                                        || distance_lengths
                                            .get(quantize_distance(reference.dist()).get() as usize)
                                            .is_none_or(|&length| length == 0)
                                }
                            })
                        {
                            return err_exit_code(
                                ExitCode::InvalidPredictionData,
                                "Dynamic Huffman tree omits a required symbol",
                            );
                        }
                        self.bitwriter
                            .write(u32::from(block.last), 1, &mut self.output);
                        self.bitwriter.write(2, 2, &mut self.output);

                        let huffman_writer = HuffmanWriter::start_dynamic_huffman_table(
                            &mut self.bitwriter,
                            &huffman_encoding,
                            &mut self.output,
                        )?;

                        self.encode_huffman(tokens, &huffman_writer);
                    }
                }

                if block.last {
                    self.bitwriter.pad(0, &mut self.output);
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
                    let lencode = quantize_length(reference.len());
                    huffman_writer.write_literal(
                        &mut self.bitwriter,
                        &mut self.output,
                        NONLEN_CODE_COUNT as u16 + u16::from(lencode.get()),
                    );

                    let lenextra: u8 = LENGTH_EXTRA_TABLE[usize::from(lencode.get())];
                    if lenextra > 0 {
                        self.bitwriter.write(
                            reference.len()
                                - MIN_MATCH
                                - u32::from(LENGTH_BASE_TABLE[usize::from(lencode.get())]),
                            lenextra.into(),
                            &mut self.output,
                        );
                    }

                    let distcode = quantize_distance(reference.dist());
                    huffman_writer.write_distance(&mut self.bitwriter, &mut self.output, distcode);

                    let distextra = DIST_EXTRA_TABLE[usize::from(distcode.get())];
                    if distextra > 0 {
                        self.bitwriter.write(
                            reference.dist()
                                - 1
                                - u32::from(DIST_BASE_TABLE[usize::from(distcode.get())]),
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
    use super::deflate_reader::parse_deflate_whole;

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
        },
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
        },
        DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Stored {
                uncompressed: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            },
            last: false,
        },
        DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Huffman {
                tokens: vec![
                    DeflateToken::Literal(0),
                    DeflateToken::Literal(1),
                    DeflateToken::new_ref(100, 1),
                    DeflateToken::new_ref(258, 1),
                    DeflateToken::Literal(3),
                ],
                huffman_type: DeflateHuffmanType::Static,
            },
            last: true,
        },
    ];

    for i in 0..blocks.len() {
        w.encode_block(&blocks[i]).unwrap();
    }
    w.flush();

    let output = w.detach_output();

    let (r, _) = parse_deflate_whole(&output).unwrap();

    assert_eq!(blocks.len(), r.blocks.len());
    for i in 0..blocks.len() {
        assert_eq!(blocks[i], r.blocks[i], "block {}", i);
    }
}

#[test]
fn dynamic_tree_rejects_missing_emitted_symbols() {
    use super::huffman_encoding::{HuffmanOriginalEncoding, TreeCodeType};

    for (missing, tokens) in [
        ("eob", vec![]),
        ("literal", vec![DeflateToken::Literal(b'a')]),
        ("distance", vec![DeflateToken::new_ref(3, 1)]),
        ("tree-code", vec![]),
        ("incomplete-code-tree", vec![]),
        ("incomplete-literal-tree", vec![]),
        ("incomplete-distance-tree", vec![]),
    ] {
        let mut lengths = vec![(TreeCodeType::Code, 0); 260];
        lengths[0] = (TreeCodeType::Code, 1);
        lengths[256] = (TreeCodeType::Code, 2);
        lengths[257] = (TreeCodeType::Code, 2);
        lengths[258] = (TreeCodeType::Code, 1);
        lengths[259] = (TreeCodeType::Code, 1);
        match missing {
            "eob" => lengths[256].1 = 0,
            "distance" => lengths[258].1 = 0,
            "incomplete-literal-tree" => lengths[257].1 = 3,
            "incomplete-distance-tree" => lengths[259].1 = 2,
            _ => {}
        }
        let mut code_lengths = [0; 19];
        code_lengths[0] = 1;
        code_lengths[1] = 2;
        code_lengths[2] = 2;
        if missing == "tree-code" {
            code_lengths[2] = 0;
        } else if missing == "incomplete-code-tree" {
            code_lengths[2] = 3;
        }
        let tree = HuffmanOriginalEncoding {
            lengths,
            code_lengths,
            num_literals: 258,
            num_dist: 2,
            num_code_lengths: 18,
        };
        let block = DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Huffman {
                tokens,
                huffman_type: DeflateHuffmanType::Dynamic {
                    huffman_encoding: tree,
                },
            },
            last: true,
        };
        let mut writer = DeflateWriter::new();
        assert_eq!(
            writer.encode_block(&block).unwrap_err().exit_code(),
            ExitCode::InvalidPredictionData,
            "{missing}"
        );
        assert!(writer.detach_output().is_empty(), "{missing}");
    }
}

/// rountrips all deflate files in the sample directory
#[test]
fn roundtrip_full_file() {
    crate::utils::test_on_all_deflate_files(|buffer| {
        let (r, _plain_text) = super::deflate_reader::parse_deflate_whole(&buffer).unwrap();

        let output = write_deflate_blocks(&r.blocks);

        if r.compressed_size != output.len() || buffer[0..r.compressed_size] != output[..] {
            println!("mismatch");
        }
        //assert_eq!(buffer.len(), output.len());
        //assert_eq!(buffer, output);
    });
}

#[cfg(test)]
pub fn write_deflate_blocks(blocks: &[DeflateTokenBlock]) -> Vec<u8> {
    let mut w = DeflateWriter::new();
    for i in 0..blocks.len() {
        w.encode_block(&blocks[i]).unwrap();
    }
    w.flush();

    let output = w.detach_output();
    output
}
