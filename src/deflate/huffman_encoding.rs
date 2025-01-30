/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::preflate_error::{err_exit_code, ExitCode, Result};

use crate::deflate::{
    bit_reader::ReadBits,
    bit_writer::BitWriter,
    deflate_constants::TREE_CODE_ORDER_TABLE,
    huffman_helper::{calc_huffman_codes, calculate_huffman_code_tree, decode_symbol},
};

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum TreeCodeType {
    /// Code length 0 - 15
    Code = 0,
    /// Copy the previous code length 3 - 6 times.
    Repeat = 16,
    /// Repeat a code length of 0 for 3 - 10 times. (3 bits of length)
    ZeroShort = 17,
    /// Repeat a code length of 0 for 11 - 138 times (7 bits of length)
    ZeroLong = 18,
}

/// Represents the original encoding of the huffman table as it was read from the file
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct HuffmanOriginalEncoding {
    /// Huffman literal/distance lengths as RLE encoded in the file
    pub lengths: Vec<(TreeCodeType, u8)>,

    /// huffman lengths for the code length alphabet used to
    /// encode the huffman table
    pub code_lengths: [u8; 19],

    /// # of Literal/Length codes  (257 - 286)
    pub num_literals: usize,

    /// # of Distance codes         (1 - 32)
    pub num_dist: usize,

    /// # of Code Length codes      (4 - 19)
    pub num_code_lengths: usize,
}

impl HuffmanOriginalEncoding {
    /// Reads a dynamic huffman table from the bit reader. The structure
    /// holds all the information necessary to recode the huffman table
    /// exactly as it was written.
    pub fn read<R: ReadBits>(bit_reader: &mut R) -> Result<HuffmanOriginalEncoding> {
        // 5 Bits: HLIT, # of Literal/Length codes - 257 (257 - 286)
        let hlit = bit_reader.get(5)? as usize + 257;
        // 5 Bits: HDIST, # of Distance codes - 1        (1 - 32)
        let hdist = bit_reader.get(5)? as usize + 1;
        // 4 Bits: HCLEN, # of Code Length codes - 4     (4 - 19)
        let hclen = bit_reader.get(4)? as usize + 4;

        //  HCLEN + 4) x 3 bits: code lengths for the code length
        //  alphabet given just above, in the order: 16, 17, 18,
        //  0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
        //	These code lengths are interpreted as 3-bit integers
        //	(0-7); as above, a code length of 0 means the
        //	corresponding symbol (literal/length or distance code
        //	length) is not used.

        let mut code_length_alphabet_code_lengths = [0; 19];
        for i in 0..hclen {
            code_length_alphabet_code_lengths[TREE_CODE_ORDER_TABLE[i]] = bit_reader.get(3)? as u8;
        }

        let code_length_huff_code_tree =
            calculate_huffman_code_tree(&code_length_alphabet_code_lengths)?;

        let c_lengths_combined = hlit + hdist;

        let mut combined_lengths = Vec::new();
        combined_lengths.reserve_exact(c_lengths_combined);

        let mut codes_read: usize = 0;

        while codes_read < c_lengths_combined {
            let w_next: u16 = decode_symbol(bit_reader, &code_length_huff_code_tree)?;

            if w_next <= 15 {
                //	0 - 15: Represent code lengths of 0 - 15
                combined_lengths.push((TreeCodeType::Code, w_next as u8));
                codes_read += 1;
            } else {
                // 16 - 18 represent a repeat code
                let tree_code = match w_next {
                    16 => TreeCodeType::Repeat,
                    17 => TreeCodeType::ZeroShort,
                    18 => TreeCodeType::ZeroLong,
                    _ => {
                        return err_exit_code(ExitCode::InvalidDeflate, "Invalid code length");
                    }
                };

                let (sub, bits) = Self::get_tree_code_adjustment(tree_code);

                let v = bit_reader.get(bits)? as u8 + sub;
                combined_lengths.push((tree_code, v));

                codes_read += v as usize;
            }
        }

        if codes_read != c_lengths_combined {
            return err_exit_code(
                ExitCode::InvalidDeflate,
                "Code table should be same size as hdist + hlit",
            );
        }

        Ok(HuffmanOriginalEncoding {
            lengths: combined_lengths,
            code_lengths: code_length_alphabet_code_lengths,
            num_literals: hlit,
            num_dist: hdist,
            num_code_lengths: hclen,
        })
    }

    /// writes dynamic huffman table to the output buffer using the bitwriter
    pub fn write(&self, bitwriter: &mut BitWriter, output_buffer: &mut Vec<u8>) -> Result<()> {
        bitwriter.write(self.num_literals as u32 - 257, 5, output_buffer);
        bitwriter.write(self.num_dist as u32 - 1, 5, output_buffer);
        bitwriter.write(self.num_code_lengths as u32 - 4, 4, output_buffer);

        for i in 0..self.num_code_lengths {
            bitwriter.write(
                self.code_lengths[TREE_CODE_ORDER_TABLE[i]].into(),
                3,
                output_buffer,
            );
        }

        let codes = calc_huffman_codes(&self.code_lengths)?;

        for &(tree_code, length) in self.lengths.iter() {
            match tree_code {
                TreeCodeType::Code => {
                    bitwriter.write(
                        codes[length as usize].into(),
                        self.code_lengths[length as usize].into(),
                        output_buffer,
                    );
                }
                TreeCodeType::Repeat | TreeCodeType::ZeroShort | TreeCodeType::ZeroLong => {
                    bitwriter.write(
                        codes[tree_code as usize].into(),
                        self.code_lengths[tree_code as usize].into(),
                        output_buffer,
                    );

                    let (sub, bits) = Self::get_tree_code_adjustment(tree_code);
                    bitwriter.write((length - sub).into(), bits, output_buffer);
                }
            }
        }

        Ok(())
    }

    /// returns the length and distance tables for the fixed huffman table
    fn get_fixed_distance_lengths() -> (Vec<u8>, Vec<u8>) {
        let mut lit_code_lengths = Vec::new();
        lit_code_lengths.reserve_exact(288);

        // Create Length table for the Literal Alphabet
        //   Range	Code Length
        //   0 - 143     8
        // 144 - 255     9
        // 256 - 279     7
        // 280 - 287     8
        for i in 0..288 {
            let mut wbits: u8 = 8;
            if (144..=255).contains(&i) {
                wbits = 9;
            } else if (256..=279).contains(&i) {
                wbits = 7;
            }

            lit_code_lengths.push(wbits);
        }

        (lit_code_lengths, vec![5; 32])
    }

    /// returns the combined literal and distance lengths
    pub fn get_literal_distance_lengths(&self) -> (Vec<u8>, Vec<u8>) {
        let mut lengths = Vec::new();
        let mut prevcode = 0;

        for &(tree_code, length) in self.lengths.iter() {
            match tree_code {
                TreeCodeType::Code => {
                    lengths.push(length);
                    prevcode = length;
                }
                TreeCodeType::Repeat => {
                    for _ in 0..length {
                        lengths.push(prevcode);
                    }
                }
                TreeCodeType::ZeroShort | TreeCodeType::ZeroLong => {
                    for _ in 0..length {
                        lengths.push(0);
                    }
                }
            }
        }

        (
            lengths[0..self.num_literals].to_vec(),
            lengths[self.num_literals..].to_vec(),
        )
    }

    /// returns the constants used to adjust the coding of tree code types
    /// (amount to subtract, #bits to encode)
    const fn get_tree_code_adjustment(tree_code: TreeCodeType) -> (u8, u32) {
        match tree_code {
            TreeCodeType::Repeat => (3, 2),
            TreeCodeType::ZeroShort => (3, 3),
            TreeCodeType::ZeroLong => (11, 7),
            TreeCodeType::Code => unreachable!(),
        }
    }
}

pub(super) struct HuffmanReader {
    lit_huff_code_tree: Vec<i32>,
    dist_huff_code_tree: Vec<i32>,
}

pub(super) struct HuffmanWriter {
    lit_code_lengths: Vec<u8>,
    lit_huffman_codes: Vec<u16>,
    dist_code_lengths: Vec<u8>,
    dist_huffman_codes: Vec<u16>,
}

impl HuffmanReader {
    /// Create Fixed Huffman code tables
    ///
    /// The Huffman codes for the two alphabets are fixed, and are not
    /// represented explicitly in the data.  The Huffman code lengths
    /// for the literal/length alphabet are:
    ///
    /// Lit Value    Bits        Codes
    /// ---------    ----        -----
    ///   0 - 143     8          00110000 through
    ///                          10111111
    /// 144 - 255     9          110010000 through
    ///                          111111111
    /// 256 - 279     7          0000000 through
    ///                          0010111
    /// 280 - 287     8          11000000 through
    ///                          11000111
    /// The code lengths are sufficient to generate the actual codes,
    /// as described above; we show the codes in the table for added
    /// clarity.  Literal/length values 286-287 will never actually
    /// occur in the compressed data, but participate in the code
    /// construction.
    pub fn create_fixed() -> Result<Self> {
        let (lit_lengths, dist_lengths) = HuffmanOriginalEncoding::get_fixed_distance_lengths();

        Ok(HuffmanReader {
            lit_huff_code_tree: calculate_huffman_code_tree(&lit_lengths)?,
            dist_huff_code_tree: calculate_huffman_code_tree(&dist_lengths)?,
        })
    }

    /// creates a reader from the encoding of the huffman table
    pub fn create_from_original_encoding(
        huffman_original_encoding: &HuffmanOriginalEncoding,
    ) -> Result<Self> {
        let (lit_lengths, dist_lengths) = huffman_original_encoding.get_literal_distance_lengths();

        Ok(HuffmanReader {
            lit_huff_code_tree: calculate_huffman_code_tree(&lit_lengths)?,
            dist_huff_code_tree: calculate_huffman_code_tree(&dist_lengths)?,
        })
    }

    pub fn fetch_next_literal_code<R: ReadBits>(&self, bit_reader: &mut R) -> Result<u16> {
        decode_symbol(bit_reader, &self.lit_huff_code_tree)
    }

    pub fn fetch_next_distance_char<R: ReadBits>(&self, bit_reader: &mut R) -> Result<u16> {
        decode_symbol(bit_reader, &self.dist_huff_code_tree)
    }
}

impl HuffmanWriter {
    pub fn start_dynamic_huffman_table(
        bitwriter: &mut BitWriter,
        huffman_encoding: &HuffmanOriginalEncoding,
        output_buffer: &mut Vec<u8>,
    ) -> Result<Self> {
        bitwriter.write(2, 2, output_buffer);

        huffman_encoding.write(bitwriter, output_buffer)?; // write the huffman table

        let (lit_lengths, dist_lengths) = huffman_encoding.get_literal_distance_lengths();

        let lit_codes = calc_huffman_codes(&lit_lengths)?;
        let dist_codes = calc_huffman_codes(&dist_lengths)?;

        Ok(HuffmanWriter {
            lit_code_lengths: lit_lengths,
            lit_huffman_codes: lit_codes,
            dist_code_lengths: dist_lengths,
            dist_huffman_codes: dist_codes,
        })
    }

    pub fn start_fixed_huffman_table() -> Self {
        let (lit_lengths, dist_lengths) = HuffmanOriginalEncoding::get_fixed_distance_lengths();

        let lit_codes = calc_huffman_codes(&lit_lengths).unwrap();
        let dist_codes = calc_huffman_codes(&dist_lengths).unwrap();

        HuffmanWriter {
            lit_code_lengths: lit_lengths,
            lit_huffman_codes: lit_codes,
            dist_code_lengths: dist_lengths,
            dist_huffman_codes: dist_codes,
        }
    }

    pub fn write_literal(&self, bitwriter: &mut BitWriter, output_buffer: &mut Vec<u8>, lit: u16) {
        let code = self.lit_huffman_codes[lit as usize];
        let c_bits = self.lit_code_lengths[lit as usize];

        bitwriter.write(code.into(), c_bits.into(), output_buffer);
    }

    pub fn write_distance(
        &self,
        bitwriter: &mut BitWriter,
        output_buffer: &mut Vec<u8>,
        dist: u16,
    ) {
        let code = self.dist_huffman_codes[dist as usize];
        let c_bits = self.dist_code_lengths[dist as usize];

        bitwriter.write(code.into(), c_bits.into(), output_buffer);
    }
}

#[test]
fn roundtrip_huffman_bitreadwrite() {
    use crate::deflate::bit_reader::BitReader;
    use std::io::Cursor;

    let code_lengths = [1, 0, 3, 3, 4, 4, 3, 0];

    let codes = calc_huffman_codes(&code_lengths).unwrap();

    let mut bit_writer = BitWriter::default();
    let mut data_buffer = Vec::new();
    for i in 0..code_lengths.len() {
        if code_lengths[i] != 0 {
            bit_writer.write(codes[i] as u32, code_lengths[i] as u32, &mut data_buffer);
        }
    }
    // write a sentinal to make sure that we read everything properly
    bit_writer.write(0x1234, 16, &mut data_buffer);
    bit_writer.pad(0, &mut data_buffer);

    let mut reader = Cursor::new(&data_buffer);
    let mut bit_reader = BitReader::new(&mut reader);

    let huffman_tree = calculate_huffman_code_tree(&code_lengths).unwrap();

    for i in 0..code_lengths.len() {
        if code_lengths[i] != 0 {
            assert_eq!(
                i as u16,
                decode_symbol(&mut bit_reader, &huffman_tree).unwrap()
            );
        }
    }

    // read sentinal to make sure we read everything correctly
    assert_eq!(
        bit_reader.get(16).unwrap(),
        0x1234,
        "sentinal value didn't match"
    );
}

#[test]
fn roundtrip_complicated() {
    #[rustfmt::skip]
    let h = HuffmanOriginalEncoding {
        lengths: vec![(TreeCodeType::ZeroShort, 10), (TreeCodeType::Code, 11), (TreeCodeType::Code, 0), (TreeCodeType::Code, 0),
            (TreeCodeType::Code, 11), (TreeCodeType::ZeroLong, 18), (TreeCodeType::Code, 6), (TreeCodeType::Code, 14), (TreeCodeType::ZeroShort, 5),
            (TreeCodeType::Code, 11), (TreeCodeType::Code, 9), (TreeCodeType::Code, 10), (TreeCodeType::Code, 0), (TreeCodeType::Code, 0), (TreeCodeType::Code, 10),
            (TreeCodeType::Code, 11), (TreeCodeType::Code, 8), (TreeCodeType::Code, 0), (TreeCodeType::Code, 7), (TreeCodeType::Code, 6), (TreeCodeType::Repeat, 6),
            (TreeCodeType::Code, 6), (TreeCodeType::Code, 7), (TreeCodeType::Code, 10), (TreeCodeType::Code, 0), (TreeCodeType::Code, 0), (TreeCodeType::Code, 10),
            (TreeCodeType::ZeroShort, 3), (TreeCodeType::Code, 8), (TreeCodeType::Repeat, 5), (TreeCodeType::Code, 11), (TreeCodeType::Code, 0), (TreeCodeType::Code, 9),
            (TreeCodeType::Code, 0), (TreeCodeType::Code, 0), (TreeCodeType::Code, 10), (TreeCodeType::Code, 10), (TreeCodeType::Code, 11), (TreeCodeType::Code, 9),
            (TreeCodeType::Code, 10), (TreeCodeType::Code, 12), (TreeCodeType::Code, 10), (TreeCodeType::Code, 9), (TreeCodeType::Code, 10),
            (TreeCodeType::Code, 11), (TreeCodeType::Code, 0), (TreeCodeType::Code, 11), (TreeCodeType::ZeroShort, 3), (TreeCodeType::Code, 11), (TreeCodeType::Code, 9), (TreeCodeType::Code, 11),
            (TreeCodeType::Code, 0), (TreeCodeType::Code, 11), (TreeCodeType::Code, 12), (TreeCodeType::Code, 7), (TreeCodeType::Code, 10), (TreeCodeType::Code, 8),
            (TreeCodeType::Code, 8), (TreeCodeType::Code, 6), (TreeCodeType::Code, 9), (TreeCodeType::Code, 8), (TreeCodeType::Code, 8),
            (TreeCodeType::Code, 8), (TreeCodeType::Code, 0), (TreeCodeType::Code, 10), (TreeCodeType::Code, 8), (TreeCodeType::Code, 9),
            (TreeCodeType::Code, 7), (TreeCodeType::Code, 7), (TreeCodeType::Code, 8), (TreeCodeType::Code, 13), (TreeCodeType::Code, 7), (TreeCodeType::Code, 7), (TreeCodeType::Code, 7), (TreeCodeType::Code, 8), (TreeCodeType::Code, 11),
            (TreeCodeType::Code, 10), (TreeCodeType::Code, 10), (TreeCodeType::Code, 8), (TreeCodeType::Code, 12), (TreeCodeType::ZeroLong, 133), (TreeCodeType::Code, 14), (TreeCodeType::Code, 5),
            (TreeCodeType::Code, 6), (TreeCodeType::Code, 6), (TreeCodeType::Code, 4), (TreeCodeType::Code, 5), (TreeCodeType::Code, 5), (TreeCodeType::Code, 8), (TreeCodeType::Code, 5),
            (TreeCodeType::Code, 5), (TreeCodeType::Code, 6), (TreeCodeType::Code, 4), (TreeCodeType::Code, 6), (TreeCodeType::Code, 5), (TreeCodeType::Code, 9), (TreeCodeType::Code, 5), (TreeCodeType::Code, 7), (TreeCodeType::Code, 4),
            (TreeCodeType::Code, 5), (TreeCodeType::Code, 6), (TreeCodeType::Code, 7), (TreeCodeType::Code, 4), (TreeCodeType::Code, 6), (TreeCodeType::Code, 6), (TreeCodeType::Code, 6), (TreeCodeType::Code, 7), (TreeCodeType::Code, 7),
            (TreeCodeType::Code, 8), (TreeCodeType::Code, 8), (TreeCodeType::Code, 6), (TreeCodeType::Code, 12), (TreeCodeType::Code, 0), (TreeCodeType::Code, 0), (TreeCodeType::Code, 13),
            (TreeCodeType::Code, 13), (TreeCodeType::Code, 11), (TreeCodeType::Code, 9), (TreeCodeType::Code, 10), (TreeCodeType::Code, 9), (TreeCodeType::Code, 9), (TreeCodeType::Code, 5), (TreeCodeType::Code, 7), (TreeCodeType::Code, 6),
            (TreeCodeType::Code, 5), (TreeCodeType::Code, 5), (TreeCodeType::Code, 6), (TreeCodeType::Code, 5), (TreeCodeType::Code, 5), (TreeCodeType::Code, 4), (TreeCodeType::Code, 4),
            (TreeCodeType::Code, 3), (TreeCodeType::Code, 3), (TreeCodeType::Code, 4), (TreeCodeType::Repeat, 4), (TreeCodeType::Code, 5), (TreeCodeType::Code, 4), (TreeCodeType::Code, 6)],
        code_lengths: [3, 0, 0, 6, 4, 3, 3, 4, 3, 4, 3, 4, 5, 6, 6, 0, 6, 6, 6],
        num_literals: 286,
        num_dist: 30,
        num_code_lengths: 17
    };

    rountrip_test(h);
}

#[test]
fn roundtrip_huffman_table() {
    // simple hardcoded encoding

    let encoding = HuffmanOriginalEncoding {
        lengths: vec![
            (TreeCodeType::Code, 1),
            (TreeCodeType::Code, 2),
            (TreeCodeType::Code, 3),
            (TreeCodeType::ZeroLong, 138),
            (TreeCodeType::ZeroLong, 115),
            (TreeCodeType::Code, 3),
            (TreeCodeType::Code, 1),
            (TreeCodeType::Code, 2),
            (TreeCodeType::Code, 2),
        ],
        code_lengths: [0, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        num_literals: 257,
        num_dist: 3,
        num_code_lengths: 19,
    };

    rountrip_test(encoding);
}

#[cfg(test)]
fn rountrip_test(encoding: HuffmanOriginalEncoding) {
    use super::bit_reader::BitReader;
    use std::io::Cursor;

    let mut output_buffer = Vec::new();
    let mut bit_writer = BitWriter::default();
    encoding.write(&mut bit_writer, &mut output_buffer).unwrap();

    // write a sentinal to make sure that we read everything properly
    bit_writer.write(0x1234, 16, &mut output_buffer);

    // flush everything
    bit_writer.pad(0, &mut output_buffer);
    bit_writer.flush_whole_bytes(&mut output_buffer);

    // now re-read the encoding
    let mut reader = Cursor::new(&output_buffer);
    let mut bit_reader = BitReader::new(&mut reader);
    let encoding2 = HuffmanOriginalEncoding::read(&mut bit_reader).unwrap();
    assert_eq!(encoding, encoding2);

    // verify sentinal to make sure we didn't write anything extra or too little
    assert_eq!(
        bit_reader.get(16).unwrap(),
        0x1234,
        "sentinal value didn't match"
    );
}
