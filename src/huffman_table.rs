use anyhow::Result;
use std::io::{Read, Seek};

use crate::{
    bit_writer::BitWriter, preflate_constants::TREE_CODE_ORDER_TABLE, zip_bit_reader::ZipBitReader,
};

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
#[repr(u16)]
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

#[derive(Debug, Clone, Eq, PartialEq)]
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

impl Default for HuffmanOriginalEncoding {
    fn default() -> Self {
        HuffmanOriginalEncoding {
            lengths: Vec::new(),
            code_lengths: [0; 19],
            num_literals: 0,
            num_dist: 0,
            num_code_lengths: 0,
        }
    }
}

impl HuffmanOriginalEncoding {
    /// Reads a dynamic huffman table from the bit reader. The structure
    /// holds all the information necessary to recode the huffman table
    /// exactly as it was written.
    pub fn read<R: Read + Seek>(
        bit_reader: &mut ZipBitReader<R>,
    ) -> anyhow::Result<HuffmanOriginalEncoding> {
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
            let w_next: u16 = fetch_next_char(bit_reader, &code_length_huff_code_tree)?;

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
                    _ => return Err(anyhow::Error::msg("Invalid code length")),
                };

                let (sub, bits) = Self::get_tree_code_adjustment(tree_code);

                let v = bit_reader.get(bits)? as u8 + sub;
                combined_lengths.push((tree_code, v));

                codes_read += v as usize;
            }
        }

        if codes_read != c_lengths_combined {
            return Err(anyhow::Error::msg(
                "Code table should be same size as hdist + hlit",
            ));
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
    pub fn write(
        &self,
        bitwriter: &mut BitWriter,
        output_buffer: &mut Vec<u8>,
    ) -> anyhow::Result<()> {
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
            if i >= 144 && i <= 255 {
                wbits = 9;
            } else if i >= 256 && i <= 279 {
                wbits = 7;
            }

            lit_code_lengths.push(wbits);
        }

        (lit_code_lengths, vec![5; 32])
    }

    /// returns the combined literal and distance lengths
    fn get_literal_distance_lengths(&self) -> (Vec<u8>, Vec<u8>) {
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

pub struct HuffmanReader {
    lit_huff_code_tree: Vec<i32>,
    dist_huff_code_tree: Vec<i32>,
}

pub struct HuffmanWriter {
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
    pub fn create_fixed() -> anyhow::Result<Self> {
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

    pub fn fetch_next_literal_code<R: Read + Seek>(
        &self,
        bit_reader: &mut ZipBitReader<R>,
    ) -> anyhow::Result<u16> {
        fetch_next_char(bit_reader, &self.lit_huff_code_tree)
    }

    pub fn fetch_next_distance_char<R: Read + Seek>(
        &self,
        bit_reader: &mut ZipBitReader<R>,
    ) -> anyhow::Result<u16> {
        fetch_next_char(bit_reader, &self.dist_huff_code_tree)
    }
}

impl HuffmanWriter {
    pub fn start_dynamic_huffman_table(
        bitwriter: &mut BitWriter,
        huffman_encoding: &HuffmanOriginalEncoding,
        output_buffer: &mut Vec<u8>,
    ) -> Result<Self> {
        bitwriter.write(2, 2, output_buffer);

        bitwriter.write(huffman_encoding.num_literals as u32 - 257, 5, output_buffer);
        bitwriter.write(huffman_encoding.num_dist as u32 - 1, 5, output_buffer);
        bitwriter.write(
            huffman_encoding.num_code_lengths as u32 - 4,
            4,
            output_buffer,
        );

        for i in 0..huffman_encoding.num_code_lengths {
            bitwriter.write(
                huffman_encoding.code_lengths[TREE_CODE_ORDER_TABLE[i]].into(),
                3,
                output_buffer,
            );
        }

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

/// Calculates Huffman code array given an array of Huffman Code Lengths using the RFC 1951 algorithm
pub fn calc_huffman_codes(code_lengths: &[u8]) -> anyhow::Result<Vec<u16>> {
    let mut result: Vec<u16> = vec![0; code_lengths.len()];

    // The following algorithm generates the codes as integers, intended to be read
    // from least- to most-significant bit.

    // 1)  Count the number of codes for each code length.  Let
    // bl_count[N] be the number of codes of length N, N >= 1.

    let mut maxbits = 0;
    let mut bl_count: [u16; 32] = [0; 32];
    for cbit in code_lengths {
        bl_count[*cbit as usize] += 1;
        if *cbit > maxbits {
            maxbits = *cbit;
        }
    }

    //	2)  Find the numerical value of the smallest code for each code length:

    let mut code: u16 = 0;
    bl_count[0] = 0;
    let mut next_code: [u16; 32] = [0; 32];
    for bits in 1..=maxbits {
        code = (code + bl_count[bits as usize - 1]) << 1;
        next_code[bits as usize] = code;
    }

    // 3)  Assign numerical values to all codes, using consecutive
    // values for all codes of the same length with the base
    // values determined at step 2. Codes that are never used
    // (which have a bit length of zero) must not be assigned a
    // value.

    for n in 0..code_lengths.len() {
        let len = code_lengths[n];
        if len != 0 {
            let mut code = next_code[len as usize];

            // code should be stored in reverse bit order
            let mut rev_code = 0;
            for _ in 0..len {
                rev_code = (rev_code << 1) | (code & 1);
                code >>= 1;
            }

            result[n] = rev_code;
            next_code[len as usize] += 1;
        }
    }

    Ok(result)
}

/// Calculates Huffman code array given an array of Huffman Code Lengths using the RFC 1951 algorithm
/// Huffman tree will be returned in rgHuffNodes where:
/// 1. when N is an even number rgHuffNodes[N] is the array index of the '0' child and
///		rgHuffNodes[N+1] is the array index of the '1' child
///	2. If rgHuffNodes[i] is less than zero then it is a leaf and the literal alphabet value is -rgHuffNodes[i] + 1
///	3. The root node index 'N' is rgHuffNodes.Length - 2. Search should start at that node.
fn calculate_huffman_code_tree(code_lengths: &[u8]) -> anyhow::Result<Vec<i32>> {
    let mut c_codes: i32 = 0;
    let mut c_bits_largest = 0;

    // First calculate total number of leaf nodes in the Huffman Tree and the max huffman code length
    for c_bits in code_lengths {
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
        for j in 0..code_lengths.len() {
            if code_lengths[j] == c_bits_cur {
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

/// verify that the huffman codes generated can be decoded with the huffman code tree
#[test]
fn roundtrip_huffman_code() {
    let code_lengths = [1, 0, 3, 3, 4, 4, 3, 0];

    let codes = calc_huffman_codes(&code_lengths).unwrap();

    let huffman_tree = calculate_huffman_code_tree(&code_lengths).unwrap();

    for i in 0..code_lengths.len() {
        // skip zero length codes
        if code_lengths[i] != 0 {
            // calculate the stream of bits for the code
            let mut bitstream = Vec::new();
            for j in 0..code_lengths[i] {
                bitstream.push((codes[i] >> j) & 1);
            }

            // now decode the stream of bits and make sure we end up back with the same code
            let mut i_node_cur: i32 = huffman_tree.len() as i32 - 2; // Start at the root of the Huffman tree

            loop {
                // Use next bit of input to decide next node
                i_node_cur = huffman_tree[(bitstream.pop().unwrap() as i32 + i_node_cur) as usize];

                // Negative indicates a leaf node, return alphabet char for this leaf
                if i_node_cur < 0 {
                    break;
                }
            }

            assert_eq!(i, (0 - (i_node_cur + 1)) as usize);
        }
    }
}

#[test]
fn roundtrip_huffman_bitreadwrite() {
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

    let data_buffer_size = data_buffer.len();
    let mut reader = Cursor::new(&data_buffer);
    let mut bit_reader = ZipBitReader::new(&mut reader, data_buffer_size as i64).unwrap();

    let huffman_tree = calculate_huffman_code_tree(&code_lengths).unwrap();

    for i in 0..code_lengths.len() {
        if code_lengths[i] != 0 {
            assert_eq!(
                i as u16,
                fetch_next_char(&mut bit_reader, &huffman_tree).unwrap()
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
fn roundtrip_huffman_table() {
    // simple hardcoded encoding

    use std::io::Cursor;
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

    let mut output_buffer = Vec::new();

    let mut bit_writer = BitWriter::default();

    encoding.write(&mut bit_writer, &mut output_buffer).unwrap();

    // write a sentinal to make sure that we read everything properly
    bit_writer.write(0x1234, 16, &mut output_buffer);
    bit_writer.pad(0, &mut output_buffer);

    bit_writer.flush_whole_bytes(&mut output_buffer);

    let mut reader = Cursor::new(&output_buffer);
    let mut bit_reader = ZipBitReader::new(&mut reader, output_buffer.len() as i64).unwrap();

    let encoding2 = HuffmanOriginalEncoding::read(&mut bit_reader).unwrap();

    // read sentinal to make sure we read everything correctly
    assert_eq!(
        bit_reader.get(16).unwrap(),
        0x1234,
        "sentinal value didn't match"
    );

    assert_eq!(encoding, encoding2);
}
