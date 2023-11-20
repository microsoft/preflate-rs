pub fn bit_length(n: u32) -> u32 {
    32 - n.leading_zeros()
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct DebugHash {
    hash: u64,
}

impl DebugHash {
    pub fn update<T: Into<i64>>(&mut self, v: T) {
        self.hash = self.hash.wrapping_mul(13).wrapping_add(v.into() as u64);
    }

    pub fn update_slice<T: Into<i64> + Copy>(&mut self, v: &[T]) {
        v.iter().for_each(|x| self.update(*x));
    }

    pub fn hash(&self) -> u64 {
        self.hash
    }
}
