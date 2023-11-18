use crate::zip_bit_reader::ReadBits;
use std::vec;

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
pub fn calculate_huffman_code_tree(code_lengths: &[u8]) -> anyhow::Result<Vec<i32>> {
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

/// Reads the next Huffman encoded char from bitReader using the Huffman tree encoded in huffman_tree
/// Huffman Nodes are encoded in the array of ints as follows:
/// '0' child link of node 'N' is at huffman_tree[N], '1' child link is at huffman_tree[N + 1]
/// Root of tree is at huffman_tree.len() - 2
pub fn decode_symbol<R: ReadBits>(
    bit_reader: &mut R,
    huffman_tree: &Vec<i32>,
) -> anyhow::Result<u16> {
    let mut i_node_cur: i32 = huffman_tree.len() as i32 - 2; // Start at the root of the Huffman tree

    loop {
        // Use next bit of input to decide next node
        i_node_cur = huffman_tree[(bit_reader.get(1)? as i32 + i_node_cur) as usize];

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
    fn get(&mut self, cbits: u32) -> anyhow::Result<u32> {
        let result = self.code & ((1 << cbits) - 1);
        self.code >>= cbits;

        Ok(result)
    }
}

#[cfg(test)]
fn roundtrip(frequencies: &[u16], huffcalc: crate::huffman_calc::HufftreeBitCalc) {
    use crate::huffman_calc::calc_bit_lengths;

    let code_lengths = calc_bit_lengths(huffcalc, &frequencies, 7);

    let codes = calc_huffman_codes(&code_lengths).unwrap();

    let huffman_tree = calculate_huffman_code_tree(&code_lengths).unwrap();

    for i in 0..code_lengths.len() {
        // skip zero length codes
        if code_lengths[i] != 0 {
            // calculate the stream of bits for the code
            let mut code = SingleCode {
                code: codes[i].into(),
            };

            let symbol = decode_symbol(&mut code, &huffman_tree).unwrap();

            assert_eq!(i, symbol as usize);
        }
    }
}
/// verify that the huffman codes generated can be decoded with the huffman code tree
#[test]
fn roundtrip_huffman_code() {
    roundtrip(
        &[1, 0, 2, 3, 5, 8, 13, 0],
        crate::huffman_calc::HufftreeBitCalc::Miniz,
    );
    roundtrip(
        &[1, 0, 2, 3, 5, 8, 13, 0],
        crate::huffman_calc::HufftreeBitCalc::Zlib,
    );

    roundtrip(
        &[1, 0, 2, 3, 5, 1008, 113, 1, 1, 1, 100, 10000],
        crate::huffman_calc::HufftreeBitCalc::Zlib,
    );
}
