use default_boxed::DefaultBoxed;

use crate::{
    deflate::{deflate_constants, deflate_token::DeflateTokenReference},
    hash_algorithm::*,
    preflate_input::PreflateInput,
};

use super::add_policy_estimator::DictionaryAddPolicy;

pub trait HashTableDepthEstimator {
    fn update_hash(&mut self, add_policy: DictionaryAddPolicy, input: &PreflateInput, length: u32);

    /// sees how many matches we need to walk to reach match_pos, which we
    /// do by subtracting the depth of the current node from the depth of the
    /// match node.
    fn match_depth(&mut self, token: DeflateTokenReference, input: &PreflateInput) -> bool;

    fn max_chain_found(&self) -> u32;

    fn very_far_matches_detected(&self, wsize: u32) -> bool;

    fn hash_algorithm(&self) -> HashAlgorithm;
}

#[derive(DefaultBoxed)]
struct MinizDepthEstimator {
    positions: [u32; 4096],

    zero_chain_found: u32,
    nonzero_chain_found: u32,
}

impl HashTableDepthEstimator for MinizDepthEstimator {
    fn update_hash(&mut self, add_policy: DictionaryAddPolicy, input: &PreflateInput, length: u32) {
        add_policy.update_hash(
            input.cur_chars(0),
            input.pos(),
            length,
            |chars, pos, length| {
                if length as usize + 2 >= chars.len() {
                    // reached on of the stream so there will be no more matches
                    return;
                }

                for i in 0..length {
                    let length3hash = MiniZHash::default().get_hash(&chars[i as usize..]);
                    self.positions[usize::from(length3hash)] = pos + i;
                }
            },
        );
    }

    fn match_depth(&mut self, token: DeflateTokenReference, input: &PreflateInput) -> bool {
        let length3hash = MiniZHash::default().get_hash(input.cur_chars(0));
        let dictpos = self.positions[usize::from(length3hash)];
        let distance3 = input.pos() - dictpos;

        if distance3 == token.dist() {
            self.zero_chain_found += 1;
        } else {
            self.nonzero_chain_found += 1;
        }

        true
    }

    /// The maximum chain length found, in this case if non-zero chains
    /// make up more than 1/256 of the total chains, then we return
    fn max_chain_found(&self) -> u32 {
        if self.zero_chain_found / 256 > self.nonzero_chain_found {
            0
        } else {
            u32::MAX
        }
    }

    fn very_far_matches_detected(&self, _wsize: u32) -> bool {
        true
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::MiniZFast
    }
}

#[derive(DefaultBoxed)]
struct HashTableDepthEstimatorImpl<H: HashImplementation> {
    /// Represents the head of the hash chain for a given hash value.
    head: [u16; 65536],

    /// Represents the number of following nodes in the chain for a given
    /// position. For example, if chainDepth[100] == 5, then there are 5 more
    /// matches if we follow the prev chain from position 100 back to 0. The value goes back
    /// all the way to be beginning of the compressed data (not readjusted when we shift
    /// the compression window), so in order to calculate the number of chain positions,
    /// you need to subtract the value from the head position.
    ///
    /// This is used during estimation only to figure out how deep we need to match
    /// into the hash chain, which allows us to estimate which parameters were used
    /// to generate the deflate data.
    chain_depth: [i32; 65536],

    /// the hash at this particular position. This is verified to make sure that it
    /// is part of the same hash chain, if not, we know that this was not the correct
    /// hash function to use.
    chain_depth_hash_verify: [u16; 65536],

    /// hash function used to calculate the hash
    hash: H,

    /// the dictionary add policy used to update the hash
    add_policy: DictionaryAddPolicy,

    /// the maximum chain length found
    max_chain_found: u32,

    longest_dist_at_hop_0: u32,

    longest_dist_at_hop_1_plus: u32,
}

impl<H: HashImplementation> HashTableDepthEstimatorImpl<H> {
    /// depth is the number of matches we need to walk to reach the match_pos. This
    /// is only valid if this was part of the same hash chain
    #[inline]
    fn get_node_depth(&self, node: u16, expected_hash: u16) -> i32 {
        debug_assert_eq!(
            self.chain_depth_hash_verify[node as usize],
            expected_hash,
            "hash chain imcomplete {:?} {:?}",
            self.hash.algorithm(),
            self.add_policy
        );
        self.chain_depth[node as usize]
    }

    pub fn box_new(hash: H) -> Box<Self> {
        let mut l = HashTableDepthEstimatorImpl::<H>::default_boxed();
        l.hash = hash;
        l
    }

    fn internal_update_hash(&mut self, chars: &[u8], pos: u32, length: u32) {
        debug_assert!(length as usize <= chars.len());
        if length as usize + H::NUM_HASH_BYTES - 1 >= chars.len() {
            // reached on of the stream so there will be no more matches
            return;
        }

        let mut pos = pos as u16;

        for i in 0..length {
            let h = self.hash.get_hash(&chars[i as usize..]);

            self.chain_depth[usize::from(pos)] =
                self.chain_depth[self.head[usize::from(h)] as usize] + 1;
            self.chain_depth_hash_verify[usize::from(pos)] = h;

            self.head[usize::from(h)] = pos;

            pos = pos.wrapping_add(1);
        }
    }

    fn match_depth_internal(&self, token: DeflateTokenReference, input: &PreflateInput<'_>) -> u32 {
        let match_pos = (input.pos() - token.dist()) as u16;

        let h = self.hash.get_hash(input.cur_chars(0));
        let head = self.head[usize::from(h)];

        // since we already calculated the dictionary add policy, we should
        // always be on the same chain as the the head
        let cur_depth = self.get_node_depth(head, h);
        let match_depth = self.get_node_depth(match_pos, h);

        debug_assert!(
            cur_depth >= match_depth,
            "current match should be >= to previous c: {} m: {}",
            cur_depth,
            match_depth
        );

        (cur_depth - match_depth) as u32
    }
}

impl<H: HashImplementation> HashTableDepthEstimator for HashTableDepthEstimatorImpl<H> {
    fn update_hash(&mut self, add_policy: DictionaryAddPolicy, input: &PreflateInput, length: u32) {
        self.add_policy = add_policy;
        add_policy.update_hash(
            input.cur_chars(0),
            input.pos(),
            length,
            |chars, pos, len| self.internal_update_hash(chars, pos, len),
        );
    }

    /// sees how many matches we need to walk to reach match_pos, which we
    /// do by subtracting the depth of the current node from the depth of the
    /// match node.
    fn match_depth(&mut self, token: DeflateTokenReference, input: &PreflateInput) -> bool {
        let mdepth = self.match_depth_internal(token, input);

        self.max_chain_found = std::cmp::max(self.max_chain_found, mdepth);

        if mdepth == 0 {
            self.longest_dist_at_hop_0 = std::cmp::max(self.longest_dist_at_hop_0, token.dist());
        } else {
            self.longest_dist_at_hop_1_plus =
                std::cmp::max(self.longest_dist_at_hop_1_plus, token.dist());
        }

        mdepth < 4096
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash.algorithm()
    }

    fn max_chain_found(&self) -> u32 {
        self.max_chain_found
    }

    fn very_far_matches_detected(&self, wsize: u32) -> bool {
        self.longest_dist_at_hop_0 > wsize - deflate_constants::MIN_LOOKAHEAD
            || self.longest_dist_at_hop_1_plus >= wsize - deflate_constants::MIN_LOOKAHEAD
    }
}

/// Libdeflate is a bit special because it uses the first candidate of the 3 byte match,
/// but then continues with the next 4 bytes.
#[derive(DefaultBoxed)]
struct HashTableDepthEstimatorLibdeflate {
    length4: HashTableDepthEstimatorImpl<LibdeflateHash4>,
    head3: [u32; 65536],

    max_chain_found: u32,
}

const LIB_DEFLATE3_HASH: LibdeflateHash3Secondary = LibdeflateHash3Secondary {};

impl HashTableDepthEstimatorLibdeflate {
    fn internal_update_hash3(&mut self, chars: &[u8], pos: u32, length: u32) {
        debug_assert!(length as usize <= chars.len());
        if length as usize + 3 - 1 >= chars.len() {
            // reached on of the stream so there will be no more matches
            return;
        }

        for i in 0..length {
            let h = LIB_DEFLATE3_HASH.get_hash(&chars[i as usize..]);

            self.head3[usize::from(h)] = pos + i;
        }
    }
}

impl HashTableDepthEstimator for HashTableDepthEstimatorLibdeflate {
    fn update_hash(&mut self, add_policy: DictionaryAddPolicy, input: &PreflateInput, length: u32) {
        add_policy.update_hash(
            input.cur_chars(0),
            input.pos(),
            length,
            |chars, pos, len| {
                self.length4.internal_update_hash(chars, pos, len);
                self.internal_update_hash3(chars, pos, len);
            },
        );
    }

    /// sees how many matches we need to walk to reach match_pos, which we
    /// do by subtracting the depth of the current node from the depth of the
    /// match node.
    fn match_depth(&mut self, token: DeflateTokenReference, input: &PreflateInput) -> bool {
        let length3hash = LIB_DEFLATE3_HASH.get_hash(input.cur_chars(0));
        let distance3 = input.pos() - self.head3[usize::from(length3hash)];

        let mdepth = if distance3 == token.dist() {
            1
        } else {
            // anything length 3 should have matched before
            if token.len() == 3 {
                65535
            } else {
                (if distance3 < 32768 { 1 } else { 0 })
                    + self.length4.match_depth_internal(token, input)
            }
        };

        self.max_chain_found = std::cmp::max(self.max_chain_found, mdepth);

        mdepth < 4096
    }

    fn max_chain_found(&self) -> u32 {
        self.max_chain_found
    }

    fn very_far_matches_detected(&self, _wsize: u32) -> bool {
        true // allowed to have very far matches
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Libdeflate4
    }
}

/// Factory function to create a new HashTableDepthEstimator based on the hash algorithm
pub fn new_depth_estimator(hash_algorithm: HashAlgorithm) -> Box<dyn HashTableDepthEstimator> {
    match hash_algorithm {
        HashAlgorithm::None => panic!("No hash algorithm specified"),
        HashAlgorithm::Zlib {
            hash_mask,
            hash_shift,
        } => HashTableDepthEstimatorImpl::box_new(ZlibRotatingHash {
            hash_mask,
            hash_shift,
        }),
        HashAlgorithm::MiniZFast => MinizDepthEstimator::default_boxed(),
        HashAlgorithm::Libdeflate4 => HashTableDepthEstimatorLibdeflate::default_boxed(),
        HashAlgorithm::Libdeflate4Fast => {
            HashTableDepthEstimatorImpl::box_new(LibdeflateHash4Fast {})
        }

        HashAlgorithm::ZlibNG => HashTableDepthEstimatorImpl::box_new(ZlibNGHash {}),
        HashAlgorithm::RandomVector => HashTableDepthEstimatorImpl::box_new(RandomVectorHash {}),
        HashAlgorithm::Crc32cHash => HashTableDepthEstimatorImpl::box_new(Crc32cHash {}),
    }
}

#[test]
fn verify_max_chain_length() {
    use crate::{
        deflate::deflate_token::{DeflateToken, DeflateTokenBlock},
        process::parse_deflate,
    };

    let zlib = HashAlgorithm::Zlib {
        hash_mask: 0x7FFF,
        hash_shift: 5,
    };

    #[rustfmt::skip]
    let levels = [
        ("compressed_zlibng_level1.deflate", HashAlgorithm::Crc32cHash, DictionaryAddPolicy::AddFirstWith32KBoundary, 0),
        ("compressed_zlibng_level2.deflate", HashAlgorithm::Crc32cHash, DictionaryAddPolicy::AddFirstAndLast(4), 3),
        ("compressed_zlibng_level3.deflate", HashAlgorithm::Crc32cHash, DictionaryAddPolicy::AddFirstAndLast(96), 5),
        ("compressed_zlibng_level4.deflate", HashAlgorithm::Crc32cHash, DictionaryAddPolicy::AddFirstAndLast(191), 23),
        ("compressed_libdeflate_level1.deflate", HashAlgorithm::Libdeflate4Fast, DictionaryAddPolicy::AddAll, 1),
        ("compressed_libdeflate_level2.deflate", HashAlgorithm::Libdeflate4, DictionaryAddPolicy::AddAll, 6),
        ("compressed_libdeflate_level3.deflate", HashAlgorithm::Libdeflate4, DictionaryAddPolicy::AddAll, 12),
        ("compressed_libdeflate_level4.deflate", HashAlgorithm::Libdeflate4, DictionaryAddPolicy::AddAll, 16),
        ("compressed_libdeflate_level5.deflate", HashAlgorithm::Libdeflate4, DictionaryAddPolicy::AddAll, 16),
        ("compressed_libdeflate_level6.deflate", HashAlgorithm::Libdeflate4, DictionaryAddPolicy::AddAll, 35),
        ("compressed_libdeflate_level7.deflate", HashAlgorithm::Libdeflate4, DictionaryAddPolicy::AddAll, 100),
        ("compressed_libdeflate_level8.deflate", HashAlgorithm::Libdeflate4, DictionaryAddPolicy::AddAll, 300),
        ("compressed_libdeflate_level9.deflate", HashAlgorithm::Libdeflate4, DictionaryAddPolicy::AddAll, 597 /*600*/),
        ("compressed_zlib_level1.deflate", zlib, DictionaryAddPolicy::AddFirst(4), 3),
        ("compressed_zlib_level2.deflate", zlib, DictionaryAddPolicy::AddFirst(5), 7),
        ("compressed_zlib_level3.deflate", zlib, DictionaryAddPolicy::AddFirst(6), 31),
        ("compressed_zlib_level4.deflate", zlib, DictionaryAddPolicy::AddAll, 15),
        ("compressed_zlib_level5.deflate", zlib, DictionaryAddPolicy::AddAll, 31),
        ("compressed_zlib_level6.deflate", zlib, DictionaryAddPolicy::AddAll, 127),
        ("compressed_zlib_level7.deflate", zlib, DictionaryAddPolicy::AddAll, 255),
        ("compressed_zlib_level8.deflate", zlib, DictionaryAddPolicy::AddAll, 1022),
        ("compressed_zlib_level9.deflate", zlib, DictionaryAddPolicy::AddAll, 3986),
        ("compressed_minizoxide_level1.deflate", HashAlgorithm::MiniZFast, DictionaryAddPolicy::AddFirstExcept4kBoundary, 0),

    ];

    for (filename, hash_algorithm, add_policy, max_chain_length) in levels {
        let compressed_data = crate::process::read_file(filename);

        let parsed = parse_deflate(&compressed_data, 0).unwrap();

        let add_policy_estimator = super::add_policy_estimator::estimate_add_policy(&parsed.blocks);

        assert_eq!(
            add_policy_estimator, add_policy,
            "add policy for file {} is incorrect (should be {:?})",
            filename, add_policy
        );

        let mut estimator = new_depth_estimator(hash_algorithm);

        let mut plaintext = Vec::new();
        for block in parsed.blocks.iter() {
            block.append_to_plaintext(&mut plaintext);
        }

        assert_eq!(
            plaintext.len(),
            parsed.plain_text.len(),
            "decompression for file {} is incorrect",
            filename,
        );

        let mut input = PreflateInput::new(&plaintext);

        for block in &parsed.blocks {
            match block {
                DeflateTokenBlock::Stored { uncompressed, .. } => {
                    estimator.update_hash(
                        DictionaryAddPolicy::AddAll,
                        &input,
                        uncompressed.len() as u32,
                    );
                }
                DeflateTokenBlock::Huffman { tokens, .. } => {
                    for token in tokens {
                        let len = match token {
                            DeflateToken::Literal(_) => 1,
                            DeflateToken::Reference(r) => {
                                assert!(estimator.match_depth(*r, &input));
                                r.len()
                            }
                        };

                        estimator.update_hash(add_policy, &input, len);
                        input.advance(len);
                    }
                }
            }
        }
        assert_eq!(
            estimator.max_chain_found(),
            max_chain_length,
            "max depth {} for file {} is incorrect (should be {})",
            estimator.max_chain_found(),
            filename,
            max_chain_length
        );
    }
}
