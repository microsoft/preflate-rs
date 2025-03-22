/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::preflate_error::{err_exit_code, ExitCode, Result};
use std::{io::Read, vec};

use super::{bit_reader::ReadBits, huffman_encoding::HuffmanTree};

/// Calculates Huffman code array given an array of Huffman Code Lengths using the RFC 1951 algorithm
pub fn calc_huffman_codes(code_lengths: &[u8]) -> Result<Vec<u16>> {
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

fn is_valid_huffman_code_lengths(code_lengths: &[u8]) -> bool {
    // Ensure that the array is not empty
    if code_lengths.is_empty() {
        return false;
    }

    // Count the number of codes for each code length using an array
    const MAX_CODE_LENGTH: usize = 16;
    let mut length_count = [0; MAX_CODE_LENGTH];
    for &length in code_lengths.iter() {
        if length as usize >= MAX_CODE_LENGTH {
            return false;
        }
        length_count[length as usize] += 1;
    }

    // essential property of huffman codes is that all internal nodes
    // have exactly two children. This means that the number of internal
    // nodes doubles each time we go down one level in the tree.
    let mut internal_nodes = 2;
    for i in 1..length_count.len() {
        internal_nodes -= length_count[i];
        if internal_nodes < 0 {
            return false;
        }
        internal_nodes *= 2;
    }

    // there should be no more internal nodes left
    internal_nodes == 0
}

/// Calculates Huffman code array given an array of Huffman Code Lengths using the RFC 1951 algorithm
/// Huffman tree will be returned in rg_huff_nodes where:
/// 1. when N is an even number rg_huff_nodes[N] is the array index of the '0' child and
///    rg_huff_nodes[N+1] is the array index of the '1' child
/// 2. If rg_huff_nodes[i] is less than zero then it is a leaf and the literal alphabet value is -rg_huff_nodes[i] + 1
/// 3. The root node index 'N' is rg_huff_nodes.len() - 2. Search should start at that node.
pub fn calculate_huffman_code_tree(code_lengths: &[u8]) -> Result<HuffmanTree> {
    if !is_valid_huffman_code_lengths(code_lengths) {
        return err_exit_code(ExitCode::InvalidDeflate, "Invalid Huffman code lengths");
    }

    let mut c_codes: i32 = 0;
    let mut c_bits_largest = 0;

    // First calculate total number of leaf nodes in the Huffman Tree and the max huffman code length
    for &c_bits in code_lengths {
        if c_bits != 0 {
            c_codes += 1;
        }

        if c_bits > c_bits_largest {
            c_bits_largest = c_bits;
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
            rg_huff_nodes[i_huff_nodes as usize] = j;
            i_huff_nodes += 1;
        }

        i_huff_nodes_previous_level = i_huff_nodes_start;
    }

    let mut fast_decode = [(0u8, 0u16); 256];
    for i in 0..256 {
        let mut i_node_cur = rg_huff_nodes.len() - 2; // Start at the root of the Huffman tree

        let mut v = i;
        let mut num_bits = 1;
        loop {
            // Use next bit of input to decide next node
            let next = rg_huff_nodes[(v & 1) + i_node_cur];

            // Negative indicates a leaf node, return alphabet char for this leaf
            if next < 0 {
                fast_decode[i] = (num_bits, (0 - (next + 1)) as u16);
                break;
            }

            i_node_cur = next as usize;
            v >>= 1;
            num_bits += 1;
        }
    }

    Ok(HuffmanTree {
        tree: rg_huff_nodes,
        fast_decode,
    })
}

/// Reads the next Huffman encoded char from bitReader using the Huffman tree encoded in huffman_tree
/// Huffman Nodes are encoded in the array of ints as follows:
/// '0' child link of node 'N' is at huffman_tree[N], '1' child link is at huffman_tree[N + 1]
/// Root of tree is at huffman_tree.len() - 2
pub fn decode_symbol(
    bit_reader: &mut impl ReadBits,
    reader: &mut impl Read,
    huffman_tree: &HuffmanTree,
) -> Result<u16> {
    // try fast decode the entire symbol if we have enough bits available
    let (num_bits, code) = huffman_tree.fast_decode[bit_reader.peek_byte() as usize];
    if u32::from(num_bits) <= bit_reader.bits_left() {
        bit_reader.consume(u32::from(num_bits));
        return Ok(code);
    }

    decode_symbol_cold(bit_reader, reader, huffman_tree)
}

fn decode_symbol_cold(
    bit_reader: &mut impl ReadBits,
    reader: &mut impl Read,
    huffman_tree: &HuffmanTree,
) -> Result<u16> {
    let mut i_node_cur: i32 = huffman_tree.tree.len() as i32 - 2;
    loop {
        // Use next bit of input to decide next node
        i_node_cur = huffman_tree.tree[(bit_reader.get(1, reader)? as i32 + i_node_cur) as usize];

        // Negative indicates a leaf node, return alphabet char for this leaf
        if i_node_cur < 0 {
            return Ok((0 - (i_node_cur + 1)) as u16);
        }
    }
}

#[cfg(test)]
/// A ReadBits implementation that reads bits from a single u32 used for unit tests
struct SingleCode {
    pub code: u32,
}

#[cfg(test)]
impl ReadBits for SingleCode {
    fn get(&mut self, cbits: u32, _: &mut impl Read) -> std::io::Result<u32> {
        let result = self.code & ((1 << cbits) - 1);
        self.code >>= cbits;

        Ok(result)
    }

    fn peek_byte(&self) -> u8 {
        (self.code & 0xff) as u8
    }

    fn bits_left(&self) -> u32 {
        8
    }

    fn consume(&mut self, cbits: u32) {
        self.code >>= cbits;
    }
}

#[cfg(test)]
fn roundtrip(frequencies: &[u16], huffcalc: super::huffman_calc::HufftreeBitCalc) {
    use super::huffman_calc::calc_bit_lengths;

    let code_lengths = calc_bit_lengths(huffcalc, frequencies, 7);

    let codes = calc_huffman_codes(&code_lengths).unwrap();

    let huffman_tree = calculate_huffman_code_tree(&code_lengths).unwrap();

    for i in 0..code_lengths.len() {
        // skip zero length codes
        if code_lengths[i] != 0 {
            // calculate the stream of bits for the code
            let mut code = SingleCode {
                code: codes[i].into(),
            };

            let symbol = decode_symbol(&mut code, &mut std::io::empty(), &huffman_tree).unwrap();

            assert_eq!(i, symbol as usize);
        }
    }
}
/// verify that the huffman codes generated can be decoded with the huffman code tree
#[test]
fn roundtrip_huffman_code() {
    roundtrip(
        &[1, 0, 2, 3, 5, 8, 13, 0],
        super::huffman_calc::HufftreeBitCalc::Miniz,
    );
    roundtrip(
        &[1, 0, 2, 3, 5, 8, 13, 0],
        super::huffman_calc::HufftreeBitCalc::Zlib,
    );

    roundtrip(
        &[1, 0, 2, 3, 5, 1008, 113, 1, 1, 1, 100, 10000],
        super::huffman_calc::HufftreeBitCalc::Zlib,
    );
}
