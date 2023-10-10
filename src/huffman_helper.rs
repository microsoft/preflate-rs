// Rust

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
