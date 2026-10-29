use default_boxed::DefaultBoxed;

use crate::{
    deflate::{
        deflate_constants,
        deflate_reader::DeflateContents,
        deflate_token::{DeflateToken, DeflateTokenBlockType, DeflateTokenReference},
    },
    hash_algorithm::*,
    preflate_input::{PlainText, PreflateInput},
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

    fn greedy_parser_detected(&self) -> bool {
        false
    }
}

#[derive(Default)]
struct GreedyParserObservations {
    samples: u16,
    skipped_better_matches: u16,
}

impl GreedyParserObservations {
    fn needs_sample(&self, token: DeflateTokenReference, input: &PreflateInput) -> bool {
        self.samples < 256 && token.len() == 3 && input.remaining() >= 5
    }

    fn observe(&mut self, token: DeflateTokenReference, input: &PreflateInput, next_head: u16) {
        debug_assert!(self.needs_sample(token, input));
        self.samples += 1;
        if next_head == 0 {
            return;
        }
        let next_distance = (input.pos() as u16).wrapping_add(1).wrapping_sub(next_head) as u32;
        // A lazy parser would prefer this longer, no-more-expensive match.
        // Restricting the distance also keeps the probe inside the original window.
        if next_distance == 0 || next_distance > token.dist() {
            return;
        }
        if input.cur_chars(1)[..4] == input.cur_chars(1 - next_distance as i32)[..4] {
            self.skipped_better_matches += 1;
        }
    }

    fn detected(&self) -> bool {
        self.skipped_better_matches >= 4
    }
}

#[derive(DefaultBoxed)]
struct MinizDepthEstimator {
    positions: [u32; 4096],

    zero_chain_found: u32,
    nonzero_chain_found: u32,
}

// Merge adjacent 16-bit buckets to test the 15-bit signature without another hash pass.
#[derive(DefaultBoxed)]
struct LibdeflateFastDepthEstimator {
    // Keep the full legacy history so a failed fingerprint needs no replay.
    legacy: HashTableDepthEstimatorImpl<LibdeflateHash4Fast>,
    // The second-newest entry in each half-bucket is enough to detect ranks above one.
    previous_heads: [u16; 65536],
    invalid15: bool,
    samples: u16,
    max_chain_found: u32,
}

impl HashTableDepthEstimator for LibdeflateFastDepthEstimator {
    fn update_hash(&mut self, add_policy: DictionaryAddPolicy, input: &PreflateInput, length: u32) {
        self.legacy.add_policy = add_policy;
        let legacy = &mut self.legacy;
        let previous_heads = &mut self.previous_heads;
        // After the bounded sample, stop per-byte bookkeeping but retain legacy depth checks.
        let valid15 = !self.invalid15 && self.samples < 256;
        add_policy.update_hash(
            input.cur_chars(0),
            input.pos(),
            length,
            |chars, pos, len| {
                if valid15 {
                    legacy.internal_update_hash_observe(chars, pos, len, |hash, previous| {
                        previous_heads[usize::from(hash)] = previous;
                    });
                } else {
                    legacy.internal_update_hash(chars, pos, len);
                }
            },
        );
    }

    fn match_depth(&mut self, token: DeflateTokenReference, input: &PreflateInput) -> bool {
        let depth16 = self.legacy.match_depth_internal(token, input);
        if depth16 > 1 || token.dist() >= 32768 {
            self.invalid15 = true;
        }
        if !self.invalid15 && self.samples < 256 {
            self.samples += 1;
            // Dropping the low hash bit merges h and h ^ 1. Count newer nodes in the
            // opposite half to recover the reference's rank in the two-entry bucket.
            let other = LibdeflateHash4Fast {}.get_hash(input.cur_chars(0)) ^ 1;
            let head = self.legacy.head[usize::from(other)];
            let previous = self.previous_heads[usize::from(other)];
            let newer = |position: u16| {
                // Positions wrap at 16 bits; reject overwritten slots and nodes outside
                // the interval between this reference's source and the current position.
                let age = u32::from((input.pos() as u16).wrapping_sub(position));
                self.legacy.chain_depth_hash_verify[usize::from(position)] == other
                    && self.legacy.chain_depth[usize::from(position)] > 0
                    && age > 0
                    && age < token.dist()
            };
            let depth15 =
                depth16 + u32::from(newer(head)) + u32::from(previous != head && newer(previous));
            if depth15 <= 1 {
                self.max_chain_found = self.max_chain_found.max(depth15);
            } else {
                self.invalid15 = true;
            }
        }
        self.legacy.record_depth(token, depth16)
    }

    fn max_chain_found(&self) -> u32 {
        if self.invalid15 {
            self.legacy.max_chain_found()
        } else {
            self.max_chain_found
        }
    }

    fn very_far_matches_detected(&self, wsize: u32) -> bool {
        !self.invalid15 || self.legacy.very_far_matches_detected(wsize)
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        if self.invalid15 {
            HashAlgorithm::Libdeflate4Fast
        } else {
            HashAlgorithm::Libdeflate4Fast15
        }
    }
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
                    self.positions[length3hash as usize] = pos + i;
                }
            },
        );
    }

    fn match_depth(&mut self, token: DeflateTokenReference, input: &PreflateInput) -> bool {
        let length3hash = MiniZHash::default().get_hash(input.cur_chars(0));
        let dictpos = self.positions[length3hash as usize];
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

    parser_observations: GreedyParserObservations,
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
        self.internal_update_hash_observe(chars, pos, length, |_, _| {});
    }

    fn internal_update_hash_observe(
        &mut self,
        chars: &[u8],
        pos: u32,
        length: u32,
        mut observe: impl FnMut(u16, u16),
    ) {
        debug_assert!(length as usize <= chars.len());
        if length as usize + H::NUM_HASH_BYTES - 1 >= chars.len() {
            // reached on of the stream so there will be no more matches
            return;
        }

        let mut pos = pos as u16;

        for i in 0..length {
            let h = self.hash.get_hash(&chars[i as usize..]);
            observe(h, self.head[usize::from(h)]);

            self.chain_depth[usize::from(pos)] =
                self.chain_depth[self.head[h as usize] as usize] + 1;
            self.chain_depth_hash_verify[usize::from(pos)] = h;

            self.head[h as usize] = pos;

            pos = pos.wrapping_add(1);
        }
    }

    fn record_depth(&mut self, token: DeflateTokenReference, depth: u32) -> bool {
        self.max_chain_found = self.max_chain_found.max(depth);
        if depth == 0 {
            self.longest_dist_at_hop_0 = self.longest_dist_at_hop_0.max(token.dist());
        } else {
            self.longest_dist_at_hop_1_plus = self.longest_dist_at_hop_1_plus.max(token.dist());
        }
        depth < 4096
    }

    fn match_depth_internal(&self, token: DeflateTokenReference, input: &PreflateInput<'_>) -> u32 {
        let match_pos = (input.pos() - token.dist()) as u16;

        let h = self.hash.get_hash(input.cur_chars(0));
        let head = self.head[h as usize];

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
        if self.add_policy == DictionaryAddPolicy::AddAll
            && self.parser_observations.needs_sample(token, input)
        {
            let next_hash = self.hash.get_hash(input.cur_chars(1));
            self.parser_observations
                .observe(token, input, self.head[next_hash as usize]);
        }
        let mdepth = self.match_depth_internal(token, input);
        self.record_depth(token, mdepth)
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

    fn greedy_parser_detected(&self) -> bool {
        self.parser_observations.detected()
    }
}

/// Libdeflate is a bit special because it uses the first candidate of the 3 byte match,
/// but then continues with the next 4 bytes.
#[derive(DefaultBoxed)]
struct HashTableDepthEstimatorLibdeflate {
    length4: HashTableDepthEstimatorImpl<LibdeflateHash4>,
    head3: [u32; 65536],

    max_chain_found: u32,

    parser_observations: GreedyParserObservations,
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

            self.head3[h as usize] = pos + i;
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
        if self.parser_observations.needs_sample(token, input) {
            let next_hash = self.length4.hash.get_hash(input.cur_chars(1));
            self.parser_observations
                .observe(token, input, self.length4.head[next_hash as usize]);
        }
        let length3hash = LIB_DEFLATE3_HASH.get_hash(input.cur_chars(0));
        let distance3 = input.pos() - self.head3[length3hash as usize];

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

    fn greedy_parser_detected(&self) -> bool {
        self.parser_observations.detected()
    }
}

/// Factory function to create a new HashTableDepthEstimator based on the hash algorithm
pub fn new_depth_estimator(hash_algorithm: HashAlgorithm) -> Box<dyn HashTableDepthEstimator> {
    match hash_algorithm {
        HashAlgorithm::None => panic!("No hash algorithm specified"),
        HashAlgorithm::Zlib {
            hash_mask: 0x7fff,
            hash_shift: 5,
        } => HashTableDepthEstimatorImpl::box_new(ZlibRotatingHashFixed::<5, 0x7fff> {}),
        HashAlgorithm::Zlib {
            hash_mask: 2047,
            hash_shift: 4,
        } => HashTableDepthEstimatorImpl::box_new(ZlibRotatingHashFixed::<4, 2047> {}),
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
        HashAlgorithm::Libdeflate4Fast15 => LibdeflateFastDepthEstimator::default_boxed(),

        HashAlgorithm::ZlibNG => HashTableDepthEstimatorImpl::box_new(ZlibNGHash {}),
        HashAlgorithm::RandomVector => HashTableDepthEstimatorImpl::box_new(RandomVectorHash {}),
        HashAlgorithm::Crc32cHash => HashTableDepthEstimatorImpl::box_new(Crc32cHash {}),
    }
}

fn update_candidate_hashes(
    length: u32,
    candidates: &mut Vec<Box<dyn HashTableDepthEstimator>>,
    add_policy: DictionaryAddPolicy,
    input: &mut PreflateInput,
) {
    for i in candidates {
        i.update_hash(add_policy, &input, length);
    }

    input.advance(length);
}

/// Runs all the candidates against the compression stream to see which one
/// does best. The candidates are updated in place and removed if the hash
/// chain goes above the limit.
pub fn run_depth_candidates(
    add_policy: DictionaryAddPolicy,
    deflate: &DeflateContents,
    plain_text: &PlainText,
    candidates: &mut Vec<Box<dyn HashTableDepthEstimator>>,
) {
    let mut input = PreflateInput::new(&plain_text);

    for (_i, b) in deflate.blocks.iter().enumerate() {
        match &b.block_type {
            DeflateTokenBlockType::Stored { uncompressed, .. } => {
                for _i in 0..uncompressed.len() {
                    update_candidate_hashes(1, candidates, add_policy, &mut input);
                }
            }
            DeflateTokenBlockType::Huffman { tokens, .. } => {
                for (_j, t) in tokens.iter().enumerate() {
                    match t {
                        DeflateToken::Literal(_) => {
                            update_candidate_hashes(1, candidates, add_policy, &mut input);
                        }
                        &DeflateToken::Reference(token) => {
                            candidates.retain_mut(|c| c.match_depth(token, &input));

                            update_candidate_hashes(
                                token.len(),
                                candidates,
                                add_policy,
                                &mut input,
                            );
                        }
                    }
                }
            }
        }
    }
}

// The fastest fingerprint must remain cheap without losing legacy compatibility.
// Verify the 256-reference bookkeeping cap, wrapped positions and legacy fallback.
#[test]
fn fastest_fingerprint_is_bounded_and_preserves_legacy_fallback() {
    use crate::{deflate::deflate_reader::parse_deflate_whole, utils::read_file};
    for (name, start_sampling, expected) in [
        (
            "compressed_libdeflate_level1.deflate",
            0,
            HashAlgorithm::Libdeflate4Fast15,
        ),
        (
            "compressed_libdeflate_level1.deflate",
            65500,
            HashAlgorithm::Libdeflate4Fast15,
        ),
        (
            "compressed_zlibng_level3.deflate",
            0,
            HashAlgorithm::Libdeflate4Fast,
        ),
    ] {
        let (contents, plain) = parse_deflate_whole(&read_file(name)).unwrap();
        let mut estimator = LibdeflateFastDepthEstimator::default_boxed();
        let mut input = PreflateInput::new(&plain);
        let mut frozen_heads = None;
        'blocks: for block in &contents.blocks {
            let DeflateTokenBlockType::Huffman { tokens, .. } = &block.block_type else {
                panic!("expected Huffman fixture");
            };
            for token in tokens {
                let length = match token {
                    DeflateToken::Literal(_) => 1,
                    DeflateToken::Reference(reference) => {
                        if input.pos() >= start_sampling {
                            assert!(estimator.match_depth(*reference, &input));
                            if estimator.samples == 256 && frozen_heads.is_none() {
                                frozen_heads = Some(estimator.previous_heads.to_vec());
                            }
                            if estimator.invalid15 {
                                break 'blocks;
                            }
                        }
                        reference.len()
                    }
                };
                estimator.update_hash(DictionaryAddPolicy::AddAll, &input, length);
                input.advance(length);
            }
        }
        assert_eq!(estimator.hash_algorithm(), expected, "{name}");
        if expected == HashAlgorithm::Libdeflate4Fast15 {
            assert_eq!(estimator.samples, 256);
            assert_eq!(estimator.previous_heads.as_slice(), frozen_heads.unwrap());
        }
    }
}

#[test]
fn verify_max_chain_length() {
    use crate::deflate::deflate_reader::parse_deflate_whole;

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
        ("compressed_libdeflate_level1.deflate", HashAlgorithm::Libdeflate4Fast15, DictionaryAddPolicy::AddAll, 1),
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
        println!("testing {}", filename);
        let compressed_data = crate::utils::read_file(filename);

        let (parsed, plain_text) = parse_deflate_whole(&compressed_data).unwrap();

        let add_policy_estimator = super::add_policy_estimator::estimate_add_policy(&parsed.blocks);

        assert_eq!(
            add_policy_estimator, add_policy,
            "add policy for file {} is incorrect (should be {:?})",
            filename, add_policy
        );

        let estimator = new_depth_estimator(hash_algorithm);

        let mut candidates = vec![estimator];
        run_depth_candidates(add_policy, &parsed, &plain_text, &mut candidates);

        assert!(candidates.len() == 1);

        let estimator = candidates.pop().unwrap();

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

// One skipped lazy opportunity is not enough evidence to classify a parser as greedy.
// Verify the repeated-evidence threshold and the 256-observation sampling limit.
#[test]
fn greedy_observations_require_repeated_better_matches() {
    let text = PlainText::new_with_data(b"@abcdXbcdefYabcdefZ".to_vec());
    let mut input = PreflateInput::new(&text);
    input.advance(12);
    let token = DeflateTokenReference::new(3, 11);
    let mut observations = GreedyParserObservations::default();
    for _ in 0..3 {
        observations.observe(token, &input, 6);
        assert!(!observations.detected());
    }
    observations.observe(token, &input, 6);
    assert!(observations.detected());
    while observations.needs_sample(token, &input) {
        observations.observe(token, &input, 6);
    }
    assert_eq!(observations.samples, 256);
}

// Unusable lookahead candidates must not create false greedy fingerprints.
// Verify invalid, farther and mismatching candidates, plus token-length/tail guards.
#[test]
fn greedy_observations_reject_invalid_or_costlier_candidates() {
    let text = PlainText::new_with_data(b"@bcdeZ@bcX@abcdXbcdefYabcdefZ".to_vec());
    let mut input = PreflateInput::new(&text);
    input.advance(22);
    let token = DeflateTokenReference::new(3, 11);
    let mut observations = GreedyParserObservations::default();
    for head in [0, 1, 7, 22] {
        observations.observe(token, &input, head);
    }
    assert_eq!(observations.skipped_better_matches, 0);
    assert!(!observations.needs_sample(DeflateTokenReference::new(4, 11), &input));
    input.advance(3);
    assert!(!observations.needs_sample(token, &input));
}

// Hash heads store only 16-bit positions, so lookahead can cross their wrap boundary.
// Verify that a genuine skipped better match is still counted after position 65536.
#[test]
fn greedy_observations_handle_wrapped_positions() {
    let mut text = vec![b'X'; 65536];
    text.extend_from_slice(b"@abcdXbcdefYabcdefZ");
    let text = PlainText::new_with_data(text);
    let mut input = PreflateInput::new(&text);
    input.advance(65536 + 12);
    let mut observations = GreedyParserObservations::default();
    observations.observe(DeflateTokenReference::new(3, 11), &input, 6);
    assert_eq!(observations.skipped_better_matches, 1);
}
