use std::io::{Read, Seek};

use crate::zip_bit_reader::ZipBitReader;

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum TreeCodeType {
    Code,
    ZeroShort,
    ZeroLong,
    Repeat,
}

#[derive(Debug, Default)]
pub struct HuffmanOriginalEncoding {
    pub lengths: Vec<(TreeCodeType, u8)>,

    pub code_lengths: Vec<u16>,

    /// 5 Bits: HLIT, # of Literal/Length codes - 257 (257 - 286)
    pub num_literals: usize,
    /// 5 Bits: HDIST, # of Distance codes - 1        (1 - 32)
    pub num_dist: usize,
}

pub struct HuffmanDecoder {
    encoding: HuffmanOriginalEncoding,
    rg_literal_alphabet_code_lengths: Vec<u16>,
    rg_literal_alphabet_huffman_codes: Vec<u16>,
    rg_distance_alphabet_code_lengths: Vec<u16>,
    rg_distance_alphabet_huffman_codes: Vec<u16>,
    rg_literal_alphabet_huff_code_tree: Vec<i32>,
    rg_distance_alphabet_huff_code_tree: Vec<i32>,
    number_of_non_zero_literal_alphabet_code_lengths: i32,
    number_of_non_zero_distance_alphabet_code_lengths: i32,
}

impl HuffmanDecoder {
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
    pub fn create_fixed() -> anyhow::Result<Self> {
        let mut hd = HuffmanDecoder {
            encoding: HuffmanOriginalEncoding::default(),
            rg_literal_alphabet_code_lengths: vec![0; 288],
            rg_literal_alphabet_huffman_codes: vec![0; 288],
            rg_distance_alphabet_code_lengths: vec![5; 32], // Distance codes are represented by 5-bit codes
            rg_distance_alphabet_huffman_codes: vec![0; 32],
            rg_literal_alphabet_huff_code_tree: vec![0; 0], // set below
            rg_distance_alphabet_huff_code_tree: vec![0; 0], // set below
            number_of_non_zero_literal_alphabet_code_lengths: 288,
            number_of_non_zero_distance_alphabet_code_lengths: 32,
        };

        // Create Length table for the Literal Alphabet
        //   Range	Code Length
        //   0 - 143     8
        // 144 - 255     9
        // 256 - 279     7
        // 280 - 287     8
        for i in 0..288 {
            let mut wbits: u16 = 8;
            if i >= 144 && i <= 255 {
                wbits = 9;
            } else if i >= 256 && i <= 279 {
                wbits = 7;
            }

            hd.rg_literal_alphabet_code_lengths[i] = wbits;
        }

        Self::calc_huffman_codes(
            &hd.rg_literal_alphabet_code_lengths,
            &mut hd.rg_literal_alphabet_huffman_codes,
        )?;
        hd.rg_literal_alphabet_huff_code_tree = Self::calculate_huffman_code_tree(
            &hd.rg_literal_alphabet_code_lengths,
            &hd.rg_literal_alphabet_huffman_codes,
        )?;

        // Create the Length table for the Distance Alphabet
        // Distance codes 0-31 are represented by (fixed-length) 5-bit
        // codes, with possible additional bits as shown in the table
        // shown in Paragraph 3.2.5, above.  Note that distance codes 30-
        // 31 will never actually occur in the compressed data.

        Self::calc_huffman_codes(
            &hd.rg_distance_alphabet_code_lengths,
            &mut hd.rg_distance_alphabet_huffman_codes,
        )?;
        hd.rg_distance_alphabet_huff_code_tree = Self::calculate_huffman_code_tree(
            &hd.rg_distance_alphabet_code_lengths,
            &hd.rg_distance_alphabet_huffman_codes,
        )?;

        Ok(hd)
    }

    /// returns the original encoding information so that we can see if it matches
    /// the predictions and if not, emit the appropriate diffs so we can recreate it exactly
    pub fn get_encoding(&self) -> &HuffmanOriginalEncoding {
        &self.encoding
    }

    /// Create Huffman code table for Literal alphabet 0-287 and distance alphabet 0-29 by
    /// reading the Huffman code length tables from the file.
    pub fn create_from_bit_reader<R: Read + Seek>(
        bit_reader: &mut ZipBitReader<R>,
        huffman_info_dump_level: i32,
    ) -> anyhow::Result<Self> {
        let mut rg_code_length_alphabet_code_lengths: Vec<u16> = vec![0; 19];
        let mut rg_code_length_alphabet_huffman_codes: Vec<u16> = vec![0; 19];

        let bit_position_at_start = bit_reader.bit_position()?;

        // 5 Bits: HLIT, # of Literal/Length codes - 257 (257 - 286)
        let hlit: u32 = bit_reader.get(5)?;
        // 5 Bits: HDIST, # of Distance codes - 1        (1 - 32)
        let hdist: u32 = bit_reader.get(5)?;
        // 4 Bits: HCLEN, # of Code Length codes - 4     (4 - 19)
        let hclen: u32 = bit_reader.get(4)?;

        if huffman_info_dump_level == 2 {
            println!("HLIT = {} -> {} Literal/Length codes", hlit, hlit + 257);
            println!("HDIST = {} -> {} Distance codes", hdist, hdist + 1);
            println!("HCLEN = {} -> {} Code Length codes", hclen, hclen + 4);
        }

        //  HCLEN + 4) x 3 bits: code lengths for the code length
        //  alphabet given just above, in the order: 16, 17, 18,
        //  0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
        //	These code lengths are interpreted as 3-bit integers
        //	(0-7); as above, a code length of 0 means the
        //	corresponding symbol (literal/length or distance code
        //	length) is not used.

        let rg_map_code_length_alphabet_code_lengths = [
            16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
        ];
        for i in 0..hclen + 4 {
            rg_code_length_alphabet_code_lengths
                [rg_map_code_length_alphabet_code_lengths[i as usize]] = bit_reader.get(3)? as u16;
        }

        Self::calc_huffman_codes(
            &rg_code_length_alphabet_code_lengths,
            &mut rg_code_length_alphabet_huffman_codes,
        )?;
        let rg_code_length_huff_code_tree = Self::calculate_huffman_code_tree(
            &rg_code_length_alphabet_code_lengths,
            &rg_code_length_alphabet_huffman_codes,
        )?;

        if huffman_info_dump_level == 2 {
            println!(
                "Code Length Alphabet Huffman code lengths requires {},{} bytes",
                (bit_reader.bit_position()? - bit_position_at_start) / 8,
                (bit_reader.bit_position()? - bit_position_at_start) % 8
            );
            println!("Reading Huffman encoded code lengths using above Huffman codes");
        }

        let mut hd = HuffmanDecoder {
            encoding: HuffmanOriginalEncoding {
                lengths: Vec::new(),
                code_lengths: rg_code_length_alphabet_code_lengths[0..hclen as usize + 4].to_vec(),
                num_literals: hlit as usize,
                num_dist: hdist as usize,
            },
            rg_literal_alphabet_code_lengths: vec![0; 286],
            rg_literal_alphabet_huffman_codes: vec![0; 286],
            rg_distance_alphabet_code_lengths: vec![0; 30],
            rg_distance_alphabet_huffman_codes: vec![0; 30],
            rg_literal_alphabet_huff_code_tree: vec![0; 0], // set below
            rg_distance_alphabet_huff_code_tree: vec![0; 0], // set below
            number_of_non_zero_literal_alphabet_code_lengths: 288,
            number_of_non_zero_distance_alphabet_code_lengths: 32,
        };

        // HLIT + 257 code lengths for the literal/length alphabet,
        // encoded using the code length Huffman code
        // HDIST + 1 code lengths for the distance alphabet,
        // encoded using the code length Huffman code
        // The code length repeat codes can cross from HLIT + 257 to the
        // HDIST + 1 code lengths.  In other words, all code lengths form
        // a single sequence of HLIT + HDIST + 258 values.

        let bit_position_start_of_combined_lengths = bit_reader.bit_position()?;
        let c_lengths_combined = hlit + 257 + hdist + 1;
        let mut rg_combined_lengths: Vec<u16> = vec![0; c_lengths_combined as usize];
        let mut cli = 0;
        while cli < c_lengths_combined {
            let _bits_consumed: i32 = 0;
            let w_next: u16 = Self::fetch_next_char(bit_reader, &rg_code_length_huff_code_tree)?;
            let base_adjust: u32 = match cli < (hlit + 257) {
                true => 0,
                false => hlit + 257,
            };

            if w_next <= 15 {
                //	0 - 15: Represent code lengths of 0 - 15
                rg_combined_lengths[cli as usize] = w_next;
                if huffman_info_dump_level == 3 {
                    println!(
                        "{} {} Code Length(v0-15) = {2}",
                        match base_adjust == 0 {
                            true => "Literal",
                            false => "Distance",
                        },
                        cli - base_adjust,
                        w_next
                    );
                }

                hd.encoding.lengths.push((TreeCodeType::Code, w_next as u8));
            } else {
                let mut c_copy: i32 = 0;
                let mut w_copy: u16 = 0;

                if w_next == 16 {
                    // 16: Copy the previous code length 3 - 6 times.
                    //		The next 2 bits indicate repeat length
                    //		(0 = 3, ... , 3 = 6)
                    //		Example:  Codes 8, 16 (+2 bits 11),
                    //		16 (+2 bits 10) will expand to
                    //		12 code lengths of 8 (1 + 6 + 5)
                    let v = bit_reader.get(2)?;

                    c_copy = 3 + v as i32;
                    w_copy = rg_combined_lengths[cli as usize - 1];
                    if huffman_info_dump_level == 3 {
                        println!(
                            "{} Copy Previous Code(v16) {} times",
                            match base_adjust == 0 {
                                true => "Literal",
                                false => "Distance",
                            },
                            c_copy
                        );
                    }

                    hd.encoding
                        .lengths
                        .push((TreeCodeType::Repeat, c_copy as u8));
                } else if w_next == 17 {
                    // 17: Repeat a code length of 0 for 3 - 10 times. (3 bits of length)
                    let v = bit_reader.get(3)?;

                    c_copy = 3 + v as i32;
                    w_copy = 0;
                    if huffman_info_dump_level == 3 {
                        println!(
                            "{} Fill with zero next {} length code (v17)",
                            match base_adjust == 0 {
                                true => "Literal",
                                false => "Distance",
                            },
                            c_copy
                        );
                    }

                    hd.encoding
                        .lengths
                        .push((TreeCodeType::ZeroShort, c_copy as u8));
                } else if w_next == 18 {
                    // 18: Repeat a code length of 0 for 11 - 138 times (7 bits of length)
                    let v = bit_reader.get(7)?;

                    c_copy = 11 + v as i32;
                    w_copy = 0;
                    if huffman_info_dump_level == 3 {
                        println!(
                            "{} Fill with zero next {} length code (v18)",
                            match base_adjust == 0 {
                                true => "Literal",
                                false => "Distance",
                            },
                            c_copy
                        );
                    }

                    hd.encoding
                        .lengths
                        .push((TreeCodeType::ZeroLong, c_copy as u8));
                } else {
                    println!("Bogus value returned");
                }

                loop {
                    rg_combined_lengths[cli as usize] = w_copy;
                    c_copy -= 1;
                    if c_copy == 0 {
                        break;
                    }
                    cli += 1;
                }
            }
            cli += 1;
        }

        if huffman_info_dump_level == 2 {
            println!(
                "Literal and Distance Huffman code lengths requires {},{} bytes",
                (bit_reader.bit_position()? - bit_position_start_of_combined_lengths) / 8,
                (bit_reader.bit_position()? - bit_position_start_of_combined_lengths) % 8
            );
        }

        // Copy from Combined Lengths to individual Length Arrays);
        for i in 0..hlit + 257 {
            let literal_length = rg_combined_lengths[i as usize];
            hd.rg_literal_alphabet_code_lengths[i as usize] = literal_length;
            if literal_length != 0 {
                hd.number_of_non_zero_literal_alphabet_code_lengths += 1;
            }
        }

        cli = hlit + 257;
        for j in 0..hdist + 1 {
            let distance_length = rg_combined_lengths[cli as usize];
            hd.rg_distance_alphabet_code_lengths[j as usize] = distance_length;
            if distance_length != 0 {
                hd.number_of_non_zero_distance_alphabet_code_lengths += 1;
            }

            cli += 1;
        }

        Self::calc_huffman_codes(
            &hd.rg_literal_alphabet_code_lengths,
            &mut hd.rg_literal_alphabet_huffman_codes,
        )?;
        hd.rg_literal_alphabet_huff_code_tree = Self::calculate_huffman_code_tree(
            &hd.rg_literal_alphabet_code_lengths,
            &hd.rg_literal_alphabet_huffman_codes,
        )?;

        if huffman_info_dump_level == 2 {
            println!("Literal Alpahbet Huffman code Lengths and codes");
            let mut title_row = String::from("     ");

            for k in 0..16 {
                title_row += format!("  {:1X}  ", k).as_str();
            }
            println!("{}", title_row);

            for k in 0..((hlit + 257) / 16 + 1) {
                let mut data_row = format!("  {:2X} ", k);
                let max_value_to_output = std::cmp::min(16, (hlit + 257) - (k * 16));

                for l in 0..max_value_to_output {
                    let alphabetchar = k * 16 + l;
                    let displaychar: char = (match alphabetchar > 32 && alphabetchar < 256 {
                        true => alphabetchar as u8,
                        false => 32,
                    }) as char;

                    data_row += format!(
                        " {:1} {:1X} ",
                        displaychar, hd.rg_literal_alphabet_code_lengths[alphabetchar as usize]
                    )
                    .as_str();
                }
                println!("{}", data_row);
            }
        }

        Self::calc_huffman_codes(
            &hd.rg_distance_alphabet_code_lengths,
            &mut hd.rg_distance_alphabet_huffman_codes,
        )?;
        hd.rg_distance_alphabet_huff_code_tree = Self::calculate_huffman_code_tree(
            &hd.rg_distance_alphabet_code_lengths,
            &hd.rg_distance_alphabet_huffman_codes,
        )?;

        Ok(hd)
    }

    pub fn fetch_next_literal_code<R: Read + Seek>(
        &self,
        bit_reader: &mut ZipBitReader<R>,
    ) -> anyhow::Result<u16> {
        Self::fetch_next_char(bit_reader, &self.rg_literal_alphabet_huff_code_tree)
    }

    pub fn fetch_next_distance_char<R: Read + Seek>(
        &self,
        bit_reader: &mut ZipBitReader<R>,
    ) -> anyhow::Result<u16> {
        Self::fetch_next_char(bit_reader, &self.rg_distance_alphabet_huff_code_tree)
    }

    /// Reads the next Huffman encoded char from bitReader using the Huffman tree encoded in rgHuffCodeTree
    /// Huffman Nodes are encoded in the array of ints as follows:
    /// '0' child link of node 'N' is at rgHuffCodeTree[N], '1' child link is at rgHuffCodesTree[N + 1]
    /// Root of tree is at rgHuffCodeTree.Length - 2
    fn fetch_next_char<R: Read + Seek>(
        bit_reader: &mut ZipBitReader<R>,
        rg_huff_code_tree: &Vec<i32>,
    ) -> anyhow::Result<u16> {
        let mut i_node_cur: i32 = rg_huff_code_tree.len() as i32 - 2; // Start at the root of the Huffman tree

        loop {
            // Use next bit of input to decide next node
            i_node_cur = rg_huff_code_tree[(bit_reader.get(1)? as i32 + i_node_cur) as usize];

            // Negative indicates a leaf node, return alphabet char for this leaf
            if i_node_cur < 0 {
                return Ok((0 - (i_node_cur + 1)) as u16);
            }
        }
    }

    /// Calculates Huffman code array given an array of Huffman Code Lengths using the RFC 1951 algorithm
    fn calc_huffman_codes(
        rg_code_lengths: &Vec<u16>,
        rg_codes: &mut Vec<u16>,
    ) -> anyhow::Result<()> {
        if rg_code_lengths.len() != rg_codes.len() {
            return Err(anyhow::Error::msg("ArgumentException"));
        }

        let mut bl_count: [u16; 32] = [0; 32];
        let mut next_code: [u16; 32] = [0; 32];

        // The following algorithm generates the codes as integers, intended to be read
        // from most- to least-significant bit.  The code lengths are
        // initially in tree[I].Len (rgCodeLengths); the codes are produced in
        // tree[I].Code (rgCodes).

        // 1)  Count the number of codes for each code length.  Let
        // bl_count[N] be the number of codes of length N, N >= 1.

        let mut maxbits = 0;
        for cbit in rg_code_lengths {
            bl_count[*cbit as usize] += 1;
            if *cbit > maxbits {
                maxbits = *cbit;
            }
        }

        //	2)  Find the numerical value of the smallest code for each code length:

        let mut code: u16 = 0;
        bl_count[0] = 0;
        for bits in 1..=maxbits {
            code = (code + bl_count[bits as usize - 1]) << 1;
            next_code[bits as usize] = code;
        }

        // 3)  Assign numerical values to all codes, using consecutive
        // values for all codes of the same length with the base
        // values determined at step 2. Codes that are never used
        // (which have a bit length of zero) must not be assigned a
        // value.

        for n in 0..rg_code_lengths.len() {
            let len = rg_code_lengths[n];
            if len != 0 {
                rg_codes[n] = next_code[len as usize];
                next_code[len as usize] += 1;
            }
        }

        Ok(())
    }

    /// Calculates Huffman code array given an array of Huffman Code Lengths using the RFC 1951 algorithm
    /// Huffman tree will be returned in rgHuffNodes where:
    /// 1. when N is an even number rgHuffNodes[N] is the array index of the '0' child and
    ///		rgHuffNodes[N+1] is the array index of the '1' child
    ///	2. If rgHuffNodes[i] is less than zero then it is a leaf and the literal alphabet value is -rgHuffNodes[i] + 1
    ///	3. The root node index 'N' is rgHuffNodes.Length - 2. Search should start at that node.
    fn calculate_huffman_code_tree(
        rg_code_lengths: &Vec<u16>,
        rg_codes: &Vec<u16>,
    ) -> anyhow::Result<Vec<i32>> {
        let mut c_codes: i32 = 0;
        let mut c_bits_largest = 0;
        if rg_code_lengths.len() != rg_codes.len() {
            return Err(anyhow::Error::msg("ArgumentException"));
        }

        // First calculate total number of leaf nodes in the Huffman Tree and the max huffman code length
        for c_bits in rg_code_lengths {
            if *c_bits != 0 {
                c_codes += 1;
            }

            if *c_bits > c_bits_largest {
                c_bits_largest = *c_bits;
            }
        }

        // Number of internal nodes in the tree will be the ((number of leaf nodes) - 1)
        let mut rg_huff_nodes: Vec<i32> = vec![0; ((c_codes - 1) * 2) as usize]; // Allocation is double as each node has 2 links

        let mut i_huff_nodes: i32 = 0;
        let mut i_huff_nodes_previous_level: i32 = 0;

        // Build the tree from the bottom starting with leafs of longs codes
        for c_bits_cur in (1..=c_bits_largest).rev() {
            let i_huff_nodes_start = i_huff_nodes;
            // Create parent nodes for all leaf codes at current bit length
            for j in 0..rg_code_lengths.len() {
                if rg_code_lengths[j] == c_bits_cur {
                    rg_huff_nodes[i_huff_nodes as usize] = -1 - j as i32; // Leaf nodes links store the actual literal character negative biased by -1
                    i_huff_nodes += 1;
                }
            }

            // Create parent node links for all remaining nodes from previous iteration
            for j in (i_huff_nodes_previous_level..i_huff_nodes_start).step_by(2) {
                rg_huff_nodes[i_huff_nodes as usize] = j as i32;
                i_huff_nodes += 1;
            }

            i_huff_nodes_previous_level = i_huff_nodes_start;
        }

        Ok(rg_huff_nodes)
    }
}
