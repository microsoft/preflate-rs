// Rust

use std::mem;

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
const MAX_HUFF_SYMBOLS: usize = 288;

pub fn calc_bit_lengths(
    code_sizes: &mut [u8],
    sym_count: &[u16],
    table_len: usize,
    code_size_limit: usize,
) -> usize {
    let mut num_codes = [0i32; MAX_SUPPORTED_HUFF_CODESIZE + 1];

    let mut symbols0 = [SymFreq {
        key: 0,
        sym_index: 0,
    }; MAX_HUFF_SYMBOLS];
    let mut symbols1 = [SymFreq {
        key: 0,
        sym_index: 0,
    }; MAX_HUFF_SYMBOLS];

    let mut num_used_symbols = 0;
    for i in 0..table_len {
        if sym_count[i] != 0 {
            symbols0[num_used_symbols] = SymFreq {
                key: sym_count[i],
                sym_index: i as u16,
            };
            num_used_symbols += 1;
        }
    }

    let symbols = radix_sort_symbols(
        &mut symbols0[..num_used_symbols],
        &mut symbols1[..num_used_symbols],
    );
    calculate_minimum_redundancy(symbols);

    for symbol in symbols.iter() {
        num_codes[symbol.key as usize] += 1;
    }

    enforce_max_code_size(&mut num_codes, num_used_symbols, code_size_limit);

    code_sizes[..].fill(0);

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

    num_used_symbols
}
