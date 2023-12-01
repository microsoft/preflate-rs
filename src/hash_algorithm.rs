#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub enum HashAlgorithm {
    #[default]
    Zlib,
    MiniZFast,
    Libdeflate4,
}
pub trait RotatingHashTrait: Default + Copy + Clone {
    fn hash(&self, mask: u16) -> usize;
    fn append(&self, c: u8, hash_shift: u32) -> Self;
    fn hash_algorithm() -> HashAlgorithm;
    fn num_hash_bytes() -> u16;
}

#[derive(Default, Debug, Copy, Clone)]
pub struct ZlibRotatingHash {
    hash: u16,
}

impl RotatingHashTrait for ZlibRotatingHash {
    fn hash(&self, mask: u16) -> usize {
        usize::from(self.hash & mask)
    }

    fn append(&self, c: u8, hash_shift: u32) -> ZlibRotatingHash {
        ZlibRotatingHash {
            hash: (self.hash << hash_shift) ^ u16::from(c),
        }
    }

    fn hash_algorithm() -> HashAlgorithm {
        HashAlgorithm::Zlib
    }

    fn num_hash_bytes() -> u16 {
        3
    }
}

#[derive(Default, Copy, Clone)]
pub struct MiniZHash {
    hash: u32,
}

impl RotatingHashTrait for MiniZHash {
    fn hash(&self, mask: u16) -> usize {
        debug_assert!(mask == 0x7fff);
        ((self.hash ^ (self.hash >> 17)) & 0x7fff) as usize
    }

    fn append(&self, c: u8, _hash_shift: u32) -> Self {
        MiniZHash {
            hash: (c as u32) << 16 | (self.hash >> 8),
        }
    }

    fn hash_algorithm() -> HashAlgorithm {
        HashAlgorithm::MiniZFast
    }

    fn num_hash_bytes() -> u16 {
        3
    }
}

#[derive(Default, Copy, Clone)]
pub struct LibdeflateRotatingHash4 {
    hash: u32,
}

impl RotatingHashTrait for LibdeflateRotatingHash4 {
    fn hash(&self, mask: u16) -> usize {
        debug_assert!(mask == 0xffff);
        (self.hash.wrapping_mul(0x1E35A7BD) >> 16) as usize
    }

    fn append(&self, c: u8, _hash_shift: u32) -> Self {
        Self {
            hash: ((c as u32) << 24) | (self.hash >> 8),
        }
    }

    fn hash_algorithm() -> HashAlgorithm {
        HashAlgorithm::Libdeflate4
    }

    fn num_hash_bytes() -> u16 {
        4
    }
}

/// This is the 3 byte version of the libdeflate hash algorithm, which is used
/// as a secondary hash value to find 3 byte matches within the first 4096K if
/// we fail to find any four byte matches with the primary hash.
#[derive(Default, Copy, Clone)]
pub struct LibdeflateRotatingHash3 {
    hash: u32,
}

impl RotatingHashTrait for LibdeflateRotatingHash3 {
    fn hash(&self, mask: u16) -> usize {
        debug_assert!(mask == 0x7fff);
        (self.hash.wrapping_mul(0x1E35A7BD) >> 17) as usize
    }

    fn append(&self, c: u8, _hash_shift: u32) -> Self {
        Self {
            hash: (c as u32) << 16 | (self.hash >> 8),
        }
    }

    fn hash_algorithm() -> HashAlgorithm {
        unimplemented!();
    }

    fn num_hash_bytes() -> u16 {
        3
    }
}
