pub fn bit_length(n: u32) -> u32 {
    n.leading_zeros() ^ 31
}
