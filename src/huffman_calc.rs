pub mod calc_minzoxide {
    use std::mem;

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
}

mod calc_zlib {
    /*
    struct FreqIdxPair {
        freq: u32,
        idx: u32,
    }

    struct TreeNode {
        parent: u32,
        idx: u32,
    }

    fn pq_smaller(p1: &FreqIdxPair, p2: &FreqIdxPair, nodedepth: &[u8]) -> bool {
        p1.freq < p2.freq || (p1.freq == p2.freq && nodedepth[p1.idx as usize] <= nodedepth[p2.idx as usize])
    }

    fn pq_downheap(ptr: &mut Vec<FreqIdxPair>, index: usize, len: usize, depth: &[u8]) {
        let mut k = index;
        let v = ptr[k];
        let mut j = k * 2 + 1; // left son of k
        while j < len {
            // Set j to the smallest of the two sons:
            if j + 1 < len && pq_smaller(&ptr[j + 1], &ptr[j], depth) {
                j += 1;
            }
            // Exit if v is smaller than both sons
            if pq_smaller(&v, &ptr[j], depth) {
                break;
            }
            // Exchange v with the smallest son
            ptr[k] = ptr[j];
            k = j;
            // Continue down the tree, setting j to the left son of k
            j = k * 2 + 1;
        }
        ptr[k] = v;
    }

    fn pq_makeheap(ptr: &mut Vec<FreqIdxPair>, len: usize, depth: &[u8]) {
        for n in (len - 1) / 2 + 1..=1 {
            pq_downheap(ptr, n - 1, len, depth);
        }
    }

    fn pq_remove(ptr: &mut Vec<FreqIdxPair>, len: &mut usize, depth: &[u8]) -> FreqIdxPair {
        let result = ptr[0];
        ptr[0] = ptr[*len - 1];
        *len -= 1;
        pq_downheap(ptr, 0, *len, depth);
        result
    }

    fn calc_bit_lengths(
        symbitlen: &mut [u8],
        symfreq: &[u32],
        symcount: u32,
        maxbits: u32,
        minmaxcode: u32,
    ) -> u32 {
        // Implementation of calc_bit_lengths...
        // (Your original C++ code translated to Rust)
    }
    */
}
