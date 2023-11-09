use crate::zip_bit_reader::ReadBits;
use std::{mem, vec};

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

pub const MAX_BL: usize = 16;

pub fn count_symbols(
    next_code: &mut [u32; MAX_BL + 2],
    min_length: &mut u8,
    max_length: &mut u8,
    symbol_bit_lengths: &[u8],
    symbol_count: u32,
    disable_zero_bit_symbols: bool,
) -> bool {
    if symbol_count < 1 || symbol_count >= 1024 {
        return false;
    }

    let mut bl_count: [u16; MAX_BL + 2] = [0; MAX_BL + 2];

    // Count symbol frequencies
    for i in 0..symbol_count as usize {
        let l = symbol_bit_lengths[i] as usize + 1;
        if l > MAX_BL + 1 {
            return false;
        }
        bl_count[l as usize] += 1;
    }

    *min_length = 1;
    while *min_length <= MAX_BL as u8 + 1 && bl_count[*min_length as usize] == 0 {
        *min_length += 1;
    }

    *max_length = MAX_BL as u8 + 1;
    while *max_length >= *min_length && bl_count[*max_length as usize] == 0 {
        *max_length -= 1;
    }

    if *min_length > *max_length {
        return false;
    }

    // Remove deleted symbols
    bl_count[0] = 0;
    if disable_zero_bit_symbols {
        bl_count[1] = 0;
    }

    // Calculate start codes
    let mut code = 0;
    for i in *min_length..=*max_length {
        code = (code + bl_count[(i - 1) as usize]) << 1;
        next_code[i as usize] = code as u32;
    }

    if *min_length == *max_length && bl_count[*max_length as usize] == 1 {
        true
    } else {
        // Check that we don't have holes
        next_code[*max_length as usize] + bl_count[*max_length as usize] as u32
            == (1 << (*max_length - 1))
    }
}

#[derive(Copy, Clone)]
struct SymFreq {
    key: u16,
    sym_index: u16,
}

fn radix_sort_symbols<'a>(
    symbols0: &'a mut [SymFreq],
    symbols1: &'a mut [SymFreq],
) -> &'a mut [SymFreq] {
    let mut hist = [[0; 256]; 2];

    for freq in symbols0.iter() {
        hist[0][(freq.key & 0xFF) as usize] += 1;
        hist[1][((freq.key >> 8) & 0xFF) as usize] += 1;
    }

    let mut n_passes = 2;
    if symbols0.len() == hist[1][0] {
        n_passes -= 1;
    }

    let mut current_symbols = symbols0;
    let mut new_symbols = symbols1;

    for (pass, hist_item) in hist.iter().enumerate().take(n_passes) {
        let mut offsets = [0; 256];
        let mut offset = 0;
        for i in 0..256 {
            offsets[i] = offset;
            offset += hist_item[i];
        }

        for sym in current_symbols.iter() {
            let j = ((sym.key >> (pass * 8)) & 0xFF) as usize;
            new_symbols[offsets[j]] = *sym;
            offsets[j] += 1;
        }

        mem::swap(&mut current_symbols, &mut new_symbols);
    }

    current_symbols
}

fn calculate_minimum_redundancy(symbols: &mut [SymFreq]) {
    match symbols.len() {
        0 => (),
        1 => symbols[0].key = 1,
        n => {
            symbols[0].key += symbols[1].key;
            let mut root = 0;
            let mut leaf = 2;
            for next in 1..n - 1 {
                if (leaf >= n) || (symbols[root].key < symbols[leaf].key) {
                    symbols[next].key = symbols[root].key;
                    symbols[root].key = next as u16;
                    root += 1;
                } else {
                    symbols[next].key = symbols[leaf].key;
                    leaf += 1;
                }

                if (leaf >= n) || (root < next && symbols[root].key < symbols[leaf].key) {
                    symbols[next].key = symbols[next].key.wrapping_add(symbols[root].key);
                    symbols[root].key = next as u16;
                    root += 1;
                } else {
                    symbols[next].key = symbols[next].key.wrapping_add(symbols[leaf].key);
                    leaf += 1;
                }
            }

            symbols[n - 2].key = 0;
            for next in (0..n - 2).rev() {
                symbols[next].key = symbols[symbols[next].key as usize].key + 1;
            }

            let mut avbl = 1;
            let mut used = 0;
            let mut dpth = 0;
            let mut root = (n - 2) as i32;
            let mut next = (n - 1) as i32;
            while avbl > 0 {
                while (root >= 0) && (symbols[root as usize].key == dpth) {
                    used += 1;
                    root -= 1;
                }
                while avbl > used {
                    symbols[next as usize].key = dpth;
                    next -= 1;
                    avbl -= 1;
                }
                avbl = 2 * used;
                dpth += 1;
                used = 0;
            }
        }
    }
}

fn enforce_max_code_size(num_codes: &mut [i32], code_list_len: usize, max_code_size: usize) {
    if code_list_len <= 1 {
        return;
    }

    num_codes[max_code_size] += num_codes[max_code_size + 1..].iter().sum::<i32>();
    let total = num_codes[1..=max_code_size]
        .iter()
        .rev()
        .enumerate()
        .fold(0u32, |total, (i, &x)| total + ((x as u32) << i));

    for _ in (1 << max_code_size)..total {
        num_codes[max_code_size] -= 1;
        for i in (1..max_code_size).rev() {
            if num_codes[i] != 0 {
                num_codes[i] -= 1;
                num_codes[i + 1] += 2;
                break;
            }
        }
    }
}

const MAX_SUPPORTED_HUFF_CODESIZE: usize = 32;

/// calculates the bit lengths for a given distribution of symbols.
/// Trailing zeros are removed and the maximum code size is enforced.
pub fn calc_bit_lengths(sym_count: &[u16], code_size_limit: usize) -> Vec<u8> {
    let mut symbols0 = Vec::new();
    let mut max_used = 0;

    for i in 0..sym_count.len() {
        if sym_count[i] != 0 {
            symbols0.push(SymFreq {
                key: sym_count[i],
                sym_index: i as u16,
            });
            max_used = i + 1;
        }
    }

    let num_used_symbols = symbols0.len();

    let mut symbols1 = Vec::new();
    symbols1.resize(
        num_used_symbols,
        SymFreq {
            key: 0,
            sym_index: 0,
        },
    );

    let symbols = radix_sort_symbols(&mut symbols0[..], &mut symbols1[..]);
    calculate_minimum_redundancy(symbols);

    let mut num_codes = [0i32; MAX_SUPPORTED_HUFF_CODESIZE + 1];
    for symbol in symbols.iter() {
        num_codes[symbol.key as usize] += 1;
    }

    enforce_max_code_size(&mut num_codes, num_used_symbols, code_size_limit);

    let mut code_sizes = Vec::new();
    code_sizes.resize(max_used, 0);

    let mut last = num_used_symbols;
    for (i, &num_item) in num_codes
        .iter()
        .enumerate()
        .take(code_size_limit + 1)
        .skip(1)
    {
        let first = last - num_item as usize;
        for symbol in &symbols[first..last] {
            code_sizes[symbol.sym_index as usize] = i as u8;
        }
        last = first;
    }

    code_sizes
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

/// verify that the huffman codes generated can be decoded with the huffman code tree
#[test]
fn roundtrip_huffman_code() {
    let frequencies = [1, 0, 2, 3, 5, 8, 13, 0];

    let code_lengths = calc_bit_lengths(&frequencies, 7);

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
