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

use super::{
    add_policy_estimator::DictionaryAddPolicy, evidence_policy::ParserEvidencePolicy,
    parser_estimator::ParserEvidence,
};

/// Whether the model reserves zlib's lookahead space or permits the full window.
/// Full-window use can follow a compressor fingerprint, not just an observed distance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DistancePolicy {
    ZlibWindow,
    FullWindow,
}

pub(crate) trait HashTableDepthEstimator {
    fn update_hash(&mut self, add_policy: DictionaryAddPolicy, input: &PreflateInput, length: u32);

    /// sees how many matches we need to walk to reach match_pos, which we
    /// do by subtracting the depth of the current node from the depth of the
    /// match node.
    fn match_depth(&mut self, token: DeflateTokenReference, input: &PreflateInput) -> bool;

    fn max_chain_found(&self) -> u32;

    fn distance_policy(&self, wsize: u32) -> DistancePolicy;

    fn hash_algorithm(&self) -> HashAlgorithm;

    fn greedy_parser_detected(&self) -> bool {
        false
    }

    fn observe_literal(
        &mut self,
        _next: DeflateTokenReference,
        _minimum_length: u32,
        _max_dist_3_matches: u32,
        _window_bytes: u32,
        _input: &PreflateInput,
    ) {
    }

    fn parser_evidence(&self) -> ParserEvidence {
        ParserEvidence::default()
    }

    fn observe_literal_run(
        &mut self,
        _max_dist_3_matches: u32,
        _window_bytes: u32,
        _input: &PreflateInput,
    ) {
    }

    fn short_match_rejections(&self) -> u16 {
        0
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

    fn distance_policy(&self, wsize: u32) -> DistancePolicy {
        if self.invalid15 {
            self.legacy.distance_policy(wsize)
        } else {
            DistancePolicy::FullWindow
        }
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        if self.invalid15 {
            HashAlgorithm::Libdeflate4Fast
        } else {
            HashAlgorithm::Libdeflate4Fast15
        }
    }

    fn parser_evidence(&self) -> ParserEvidence {
        self.legacy.parser_evidence()
    }

    fn observe_literal(
        &mut self,
        next: DeflateTokenReference,
        minimum_length: u32,
        max_dist_3_matches: u32,
        window_bytes: u32,
        input: &PreflateInput,
    ) {
        self.legacy.observe_literal(
            next,
            minimum_length,
            max_dist_3_matches,
            window_bytes,
            input,
        );
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

    fn distance_policy(&self, _wsize: u32) -> DistancePolicy {
        DistancePolicy::FullWindow
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

    evidence: ParserEvidence,

    evidence_policy: ParserEvidencePolicy,

    short_match_rejections: u16,
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

    pub fn box_new(hash: H, evidence_policy: ParserEvidencePolicy) -> Box<Self> {
        let mut l = HashTableDepthEstimatorImpl::<H>::default_boxed();
        l.hash = hash;
        l.evidence_policy = evidence_policy;
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
        let add_policy =
            crate::models::chromium::depth_add_policy(self.hash.algorithm(), add_policy);
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

    fn distance_policy(&self, wsize: u32) -> DistancePolicy {
        if self.longest_dist_at_hop_0 > wsize - deflate_constants::MIN_LOOKAHEAD
            || self.longest_dist_at_hop_1_plus >= wsize - deflate_constants::MIN_LOOKAHEAD
        {
            DistancePolicy::FullWindow
        } else {
            DistancePolicy::ZlibWindow
        }
    }

    fn greedy_parser_detected(&self) -> bool {
        self.parser_observations.detected()
    }

    fn parser_evidence(&self) -> ParserEvidence {
        self.evidence
    }

    fn observe_literal_run(
        &mut self,
        max_dist_3_matches: u32,
        window_bytes: u32,
        input: &PreflateInput,
    ) {
        if !matches!(self.hash.algorithm(), HashAlgorithm::Zlib { .. }) {
            return;
        }
        let head = self.head[usize::from(self.hash.get_hash(input.cur_chars(0)))];
        if head != 0 {
            let distance = u32::from((input.pos() as u16).wrapping_sub(head));
            self.short_match_rejections += u16::from(crate::models::zlib::short_match_rejected(
                input,
                distance,
                max_dist_3_matches,
                window_bytes,
            ));
        }
    }

    fn short_match_rejections(&self) -> u16 {
        self.short_match_rejections
    }

    fn observe_literal(
        &mut self,
        next: DeflateTokenReference,
        minimum_length: u32,
        max_dist_3_matches: u32,
        window_bytes: u32,
        input: &PreflateInput,
    ) {
        let minimum_length = self.evidence_policy.minimum_deferred_match(minimum_length);
        if next.len() <= minimum_length {
            return;
        }
        let head = self.head[usize::from(self.hash.get_hash(input.cur_chars(0)))];
        let distance = u32::from((input.pos() as u16).wrapping_sub(head));
        if head == 0 || distance == 0 || distance > input.pos().min(window_bytes) {
            return;
        }
        let comparison_limit = next.len().min(129);
        let length = input
            .cur_chars(0)
            .iter()
            .zip(input.cur_chars(-(distance as i32)))
            .take(comparison_limit as usize)
            .take_while(|(a, b)| a == b)
            .count() as u32;
        if length >= minimum_length
            && length < comparison_limit
            && (length != 3 || distance <= max_dist_3_matches)
        {
            self.evidence.lazy_matches += 1;
            self.evidence.longest_lazy_match = self.evidence.longest_lazy_match.max(length as u16);
        }
    }
}

#[test]
fn lazy_evidence_checks_the_existing_head_and_respects_the_minimum() {
    let plain = PlainText::new_with_data(b"@bcdefYabcXabcdef".to_vec());
    let mut input = PreflateInput::new(&plain);
    let mut estimator = HashTableDepthEstimatorImpl::box_new(
        ZlibRotatingHashFixed::<5, 32767> {},
        ParserEvidencePolicy::default(),
    );
    estimator.update_hash(DictionaryAddPolicy::AddAll, &input, 11);
    input.advance(11);
    let next = DeflateTokenReference::new(5, 11);
    estimator.observe_literal(next, 6, u32::MAX, 32768, &input);
    assert_eq!(estimator.parser_evidence().lazy_matches, 0);
    estimator.observe_literal(next, 3, 3, 32768, &input);
    assert_eq!(estimator.parser_evidence().lazy_matches, 0);
    estimator.observe_literal(next, 3, 4, 3, &input);
    assert_eq!(estimator.parser_evidence().lazy_matches, 0);
    estimator.observe_literal(next, 3, 4, 4, &input);
    assert_eq!(estimator.parser_evidence().lazy_matches, 1);
    assert_eq!(estimator.parser_evidence().longest_lazy_match, 3);

    for (mismatch_at, expected_observations) in [(128, 1), (129, 0), (258, 0)] {
        let mut bytes = vec![b'a'; 1024];
        bytes[256 + mismatch_at] = b'b';
        let plain = PlainText::new_with_data(bytes);
        let mut input = PreflateInput::new(&plain);
        let mut estimator = HashTableDepthEstimatorImpl::box_new(
            ZlibRotatingHashFixed::<5, 32767> {},
            ParserEvidencePolicy::default(),
        );
        estimator.update_hash(DictionaryAddPolicy::AddAll, &input, 256);
        input.advance(256);
        estimator.observe_literal(
            DeflateTokenReference::new(258, 1),
            3,
            u32::MAX,
            32768,
            &input,
        );
        assert_eq!(
            estimator.parser_evidence().lazy_matches,
            expected_observations,
            "mismatch_at={mismatch_at}"
        );
    }
}

#[test]
fn literal_probes_are_capped_in_the_existing_depth_walk() {
    use crate::deflate::{
        deflate_reader::parse_deflate_whole,
        deflate_token::{DeflateHuffmanType, DeflateTokenBlock},
        deflate_writer::DeflateWriter,
    };
    use std::{cell::Cell, rc::Rc};

    struct CountingEstimator(Rc<Cell<(u32, u32, u32)>>);
    impl HashTableDepthEstimator for CountingEstimator {
        fn update_hash(&mut self, _: DictionaryAddPolicy, _: &PreflateInput, length: u32) {
            let (bytes, probes, references) = self.0.get();
            self.0.set((bytes + length, probes, references));
        }
        fn match_depth(&mut self, _: DeflateTokenReference, _: &PreflateInput) -> bool {
            let (bytes, probes, references) = self.0.get();
            self.0.set((bytes, probes, references + 1));
            true
        }
        fn max_chain_found(&self) -> u32 {
            0
        }
        fn distance_policy(&self, _: u32) -> DistancePolicy {
            DistancePolicy::ZlibWindow
        }
        fn hash_algorithm(&self) -> HashAlgorithm {
            HashAlgorithm::RandomVector
        }
        fn observe_literal(
            &mut self,
            _: DeflateTokenReference,
            _: u32,
            _: u32,
            _: u32,
            _: &PreflateInput,
        ) {
            let (bytes, probes, references) = self.0.get();
            self.0.set((bytes, probes + 1, references));
        }
    }
    let mut writer = DeflateWriter::new();
    writer
        .encode_block(&DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Huffman {
                tokens: (0..1024)
                    .flat_map(|_| [DeflateToken::Literal(b'a'), DeflateToken::new_ref(3, 1)])
                    .collect(),
                huffman_type: DeflateHuffmanType::Static,
            },
            last: true,
        })
        .unwrap();
    writer.flush();
    let (contents, plain) = parse_deflate_whole(&writer.detach_output()).unwrap();
    let counts = Rc::new(Cell::new((0, 0, 0)));
    let mut candidates: Vec<Box<dyn HashTableDepthEstimator>> =
        vec![Box::new(CountingEstimator(counts.clone()))];
    run_depth_candidates(
        DictionaryAddPolicy::AddAll,
        &contents,
        &plain,
        &mut candidates,
        3,
        u32::MAX,
        32768,
    );
    assert_eq!(counts.get(), (plain.len() as u32, 256, 1024));
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

    fn distance_policy(&self, _wsize: u32) -> DistancePolicy {
        DistancePolicy::FullWindow
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Libdeflate4
    }

    fn greedy_parser_detected(&self) -> bool {
        self.parser_observations.detected()
    }

    fn parser_evidence(&self) -> ParserEvidence {
        self.length4.parser_evidence()
    }

    fn observe_literal(
        &mut self,
        next: DeflateTokenReference,
        minimum_length: u32,
        max_dist_3_matches: u32,
        window_bytes: u32,
        input: &PreflateInput,
    ) {
        self.length4.observe_literal(
            next,
            minimum_length,
            max_dist_3_matches,
            window_bytes,
            input,
        );
    }
}

/// Factory function to create a new HashTableDepthEstimator based on the hash algorithm
pub(super) fn new_depth_estimator(
    hash_algorithm: HashAlgorithm,
) -> Box<dyn HashTableDepthEstimator> {
    let evidence_policy = ParserEvidencePolicy::for_hash(hash_algorithm);
    match hash_algorithm {
        HashAlgorithm::None => panic!("No hash algorithm specified"),
        HashAlgorithm::Zlib {
            hash_mask: 0x7fff,
            hash_shift: 5,
        } => HashTableDepthEstimatorImpl::box_new(
            ZlibRotatingHashFixed::<5, 0x7fff> {},
            evidence_policy,
        ),
        HashAlgorithm::Zlib {
            hash_mask: 2047,
            hash_shift: 4,
        } => HashTableDepthEstimatorImpl::box_new(
            ZlibRotatingHashFixed::<4, 2047> {},
            evidence_policy,
        ),
        HashAlgorithm::Zlib {
            hash_mask,
            hash_shift,
        } => HashTableDepthEstimatorImpl::box_new(
            ZlibRotatingHash {
                hash_mask,
                hash_shift,
            },
            evidence_policy,
        ),
        HashAlgorithm::MiniZFast => MinizDepthEstimator::default_boxed(),
        HashAlgorithm::Libdeflate4 => {
            let mut estimator = HashTableDepthEstimatorLibdeflate::default_boxed();
            estimator.length4.evidence_policy = evidence_policy;
            estimator
        }
        HashAlgorithm::Libdeflate4Fast => {
            HashTableDepthEstimatorImpl::box_new(LibdeflateHash4Fast {}, evidence_policy)
        }
        HashAlgorithm::Libdeflate4Fast15 => {
            let mut estimator = LibdeflateFastDepthEstimator::default_boxed();
            // Literal probes use the legacy table even while testing the 15-bit
            // fingerprint, and must retain that table's policy after fallback.
            estimator.legacy.evidence_policy =
                ParserEvidencePolicy::for_hash(HashAlgorithm::Libdeflate4Fast);
            estimator
        }

        HashAlgorithm::ZlibNG => {
            HashTableDepthEstimatorImpl::box_new(ZlibNGHash {}, evidence_policy)
        }
        HashAlgorithm::Chromium { hash_mask } => {
            HashTableDepthEstimatorImpl::box_new(ChromiumHash { hash_mask }, evidence_policy)
        }
        HashAlgorithm::RandomVector => {
            HashTableDepthEstimatorImpl::box_new(RandomVectorHash {}, evidence_policy)
        }
        HashAlgorithm::Crc32cHash => {
            HashTableDepthEstimatorImpl::box_new(Crc32cHash {}, evidence_policy)
        }
    }
}

#[cfg(test)]
mod evidence_policy_tests {
    use super::*;
    use crate::{
        PreflateConfig,
        deflate::{
            deflate_reader::parse_deflate_whole,
            deflate_token::{DeflateHuffmanType, DeflateTokenBlock},
            deflate_writer::DeflateWriter,
        },
        estimator::{
            parser_estimator::ParserInference, preflate_stream_info::extract_preflate_info,
        },
        preflate_whole_deflate_stream, recreate_whole_deflate_stream,
    };

    fn deferred_match_stream(
        deferred_length: usize,
        include_short_reference: bool,
    ) -> (Vec<u8>, DeflateContents, PlainText) {
        let mut expected = b"^abcabc".to_vec();
        let mut tokens: Vec<_> = if include_short_reference {
            b"^abc".iter().copied().map(DeflateToken::Literal).collect()
        } else {
            expected
                .iter()
                .copied()
                .map(DeflateToken::Literal)
                .collect()
        };
        if include_short_reference {
            tokens.push(DeflateToken::new_ref(3, 3));
        }
        let pattern: Vec<_> = (0..258).map(|i| b'a' + (i % 26) as u8).collect();
        let source = expected.len();
        tokens.extend(pattern.iter().copied().map(DeflateToken::Literal));
        expected.extend_from_slice(&pattern);
        for marker in b"@#$%" {
            let older_match = expected.len();
            let mut prefix = vec![*marker];
            prefix.extend_from_slice(&pattern[..deferred_length - 1]);
            prefix.extend_from_slice(b"!|");
            tokens.extend(prefix.iter().copied().map(DeflateToken::Literal));
            expected.extend_from_slice(&prefix);

            let current = expected.len();
            tokens.push(DeflateToken::Literal(*marker));
            expected.push(*marker);
            tokens.push(DeflateToken::new_ref(258, (expected.len() - source) as u32));
            expected.extend_from_slice(&pattern);
            // Prove the fixture offers exactly this shorter match before the
            // emitted literal/reference pair, independently of the collector.
            assert_eq!(
                &expected[older_match..older_match + deferred_length],
                &expected[current..current + deferred_length],
            );
            assert_ne!(
                expected[older_match + deferred_length],
                expected[current + deferred_length]
            );
        }
        let mut writer = DeflateWriter::new();
        writer
            .encode_block(&DeflateTokenBlock {
                block_type: DeflateTokenBlockType::Huffman {
                    tokens,
                    huffman_type: DeflateHuffmanType::Static,
                },
                last: true,
            })
            .unwrap();
        writer.flush();
        let compressed = writer.detach_output();
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        assert_eq!(plain.text(), expected);
        let info = extract_preflate_info(&contents.blocks);
        assert_eq!(info.min_len, if include_short_reference { 3 } else { 258 });
        assert_eq!(
            info.reference_count,
            if include_short_reference { 5 } else { 4 }
        );
        (compressed, contents, plain)
    }

    fn collect(
        mut candidates: Vec<Box<dyn HashTableDepthEstimator>>,
        contents: &DeflateContents,
        plain: &PlainText,
    ) -> Vec<Box<dyn HashTableDepthEstimator>> {
        let info = extract_preflate_info(&contents.blocks);
        let count = candidates.len();
        run_depth_candidates(
            DictionaryAddPolicy::AddAll,
            contents,
            plain,
            &mut candidates,
            info.min_len,
            info.max_dist_3_matches,
            32768,
        );
        assert_eq!(
            candidates.len(),
            count,
            "fixture unexpectedly eliminated a candidate"
        );
        candidates
    }

    #[test]
    fn valid_streams_distinguish_filtered_matches_from_lazy_evidence() {
        for (algorithm, eight_byte_samples, nine_byte_samples) in [
            (
                HashAlgorithm::Zlib {
                    hash_mask: 32767,
                    hash_shift: 5,
                },
                4,
                4,
            ),
            (
                HashAlgorithm::Zlib {
                    hash_mask: 2047,
                    hash_shift: 4,
                },
                4,
                4,
            ),
            (
                HashAlgorithm::Zlib {
                    hash_mask: 511,
                    hash_shift: 3,
                },
                4,
                4,
            ),
            (HashAlgorithm::MiniZFast, 0, 0),
            (HashAlgorithm::Libdeflate4, 0, 4),
            (HashAlgorithm::Libdeflate4Fast, 4, 4),
            (HashAlgorithm::Libdeflate4Fast15, 4, 4),
            (HashAlgorithm::ZlibNG, 4, 4),
            (HashAlgorithm::Chromium { hash_mask: 0x7fff }, 4, 4),
            (HashAlgorithm::RandomVector, 4, 4),
            (HashAlgorithm::Crc32cHash, 4, 4),
        ] {
            for (length, expected_samples) in [
                (8, eight_byte_samples),
                (9, nine_byte_samples),
                (128, nine_byte_samples),
                (129, 0),
            ] {
                let (_, contents, plain) = deferred_match_stream(length, true);
                let candidates = collect(vec![new_depth_estimator(algorithm)], &contents, &plain);
                let evidence = candidates[0].parser_evidence();
                assert_eq!(
                    evidence.lazy_matches, expected_samples,
                    "{algorithm:?}, length={length}"
                );
                let expected = if expected_samples == 0 {
                    ParserInference::Unresolved
                } else {
                    ParserInference::Lazy {
                        longest_deferred_match: length as u16,
                    }
                };
                assert_eq!(
                    evidence.infer(candidates[0].greedy_parser_detected()),
                    expected,
                    "{algorithm:?}, length={length}",
                );
            }
        }
    }

    #[test]
    fn identical_plaintext_with_longer_minimum_does_not_imply_lazy_parsing() {
        for length in [8, 9, 128] {
            let (_, _, with_short_reference) = deferred_match_stream(length, true);
            let (_, contents, plain) = deferred_match_stream(length, false);
            assert_eq!(plain.text(), with_short_reference.text());
            let candidates = collect(
                vec![
                    new_depth_estimator(HashAlgorithm::Zlib {
                        hash_mask: 32767,
                        hash_shift: 5,
                    }),
                    new_depth_estimator(HashAlgorithm::Libdeflate4),
                ],
                &contents,
                &plain,
            );
            for candidate in candidates {
                assert_eq!(candidate.parser_evidence().lazy_matches, 0);
            }
        }
    }

    #[test]
    fn incorrect_family_policies_change_the_fixture_outcome() {
        let (_, contents, plain) = deferred_match_stream(8, true);
        let mut unrestricted_libdeflate = HashTableDepthEstimatorLibdeflate::default_boxed();
        unrestricted_libdeflate.length4.evidence_policy = ParserEvidencePolicy::default();
        let overrestricted_zlib = HashTableDepthEstimatorImpl::box_new(
            ZlibRotatingHashFixed::<5, 32767> {},
            ParserEvidencePolicy::for_hash(HashAlgorithm::Libdeflate4),
        );
        let candidates = collect(
            vec![
                new_depth_estimator(HashAlgorithm::Libdeflate4),
                unrestricted_libdeflate,
                new_depth_estimator(HashAlgorithm::Zlib {
                    hash_mask: 32767,
                    hash_shift: 5,
                }),
                overrestricted_zlib,
            ],
            &contents,
            &plain,
        );
        let observations: Vec<_> = candidates
            .iter()
            .map(|candidate| candidate.parser_evidence().lazy_matches)
            .collect();
        assert_eq!(observations, [0, 4, 4, 0]);
    }

    #[test]
    fn deferred_match_fixtures_reconstruct_exact_bitstreams() {
        for length in [8, 9, 128, 129] {
            for include_short_reference in [false, true] {
                let (compressed, _, plain) = deferred_match_stream(length, include_short_reference);
                let (result, decoded) =
                    preflate_whole_deflate_stream(&compressed, &PreflateConfig::default()).unwrap();
                assert_eq!(decoded.text(), plain.text());
                assert_eq!(
                    recreate_whole_deflate_stream(decoded.text(), &result.corrections).unwrap(),
                    compressed,
                );
            }
        }
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
pub(super) fn run_depth_candidates(
    add_policy: DictionaryAddPolicy,
    deflate: &DeflateContents,
    plain_text: &PlainText,
    candidates: &mut Vec<Box<dyn HashTableDepthEstimator>>,
    minimum_length: u32,
    max_dist_3_matches: u32,
    window_bytes: u32,
) {
    let mut input = PreflateInput::new(&plain_text);
    let mut literal_samples = 0;
    let mut short_samples = if crate::models::zlib::sample_short_match_policy(
        add_policy,
        minimum_length,
        max_dist_3_matches,
        plain_text.len(),
    ) {
        0
    } else {
        256
    };
    #[cfg(test)]
    if std::env::var_os("PREFLATE_ESTIMATOR_TRACE").is_some() {
        println!(
            "WALK policy={add_policy:?} minimum={minimum_length} short_distance={max_dist_3_matches} bytes={} short_sampling={}",
            plain_text.len(),
            short_samples == 0,
        );
    }

    for (_i, b) in deflate.blocks.iter().enumerate() {
        match &b.block_type {
            DeflateTokenBlockType::Stored { uncompressed, .. } => {
                #[cfg(test)]
                if std::env::var_os("PREFLATE_ESTIMATOR_TRACE").is_some() {
                    println!("WALK stored={} at={}", uncompressed.len(), input.pos());
                }
                short_samples = 256;
                for _i in 0..uncompressed.len() {
                    update_candidate_hashes(1, candidates, add_policy, &mut input);
                }
            }
            DeflateTokenBlockType::Huffman { tokens, .. } => {
                for (j, t) in tokens.iter().enumerate() {
                    match t {
                        DeflateToken::Literal(_) => {
                            if short_samples < 256
                                && matches!(tokens.get(j + 1), Some(DeflateToken::Literal(_)))
                                && matches!(tokens.get(j + 2), Some(DeflateToken::Literal(_)))
                            {
                                short_samples += 1;
                                for candidate in candidates.iter_mut() {
                                    candidate.observe_literal_run(
                                        max_dist_3_matches,
                                        window_bytes,
                                        &input,
                                    );
                                }
                            }
                            if literal_samples < 256
                                && let Some(DeflateToken::Reference(next)) = tokens.get(j + 1)
                                && !crate::models::miniz::cross_4k_boundary(input.pos())
                            {
                                literal_samples += 1;
                                for candidate in candidates.iter_mut() {
                                    candidate.observe_literal(
                                        *next,
                                        minimum_length,
                                        max_dist_3_matches,
                                        window_bytes,
                                        &input,
                                    );
                                }
                            }
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

#[test]
fn short_literal_run_probes_are_bounded_in_the_existing_walk() {
    use crate::deflate::deflate_token::{DeflateHuffmanType, DeflateTokenBlock};
    use std::{cell::Cell, rc::Rc};

    struct Counter(Rc<Cell<usize>>);
    impl HashTableDepthEstimator for Counter {
        fn update_hash(&mut self, _: DictionaryAddPolicy, _: &PreflateInput, _: u32) {}
        fn match_depth(&mut self, _: DeflateTokenReference, _: &PreflateInput) -> bool {
            true
        }
        fn max_chain_found(&self) -> u32 {
            0
        }
        fn distance_policy(&self, _: u32) -> DistancePolicy {
            DistancePolicy::ZlibWindow
        }
        fn hash_algorithm(&self) -> HashAlgorithm {
            crate::models::zlib::DEFAULT_HASH
        }
        fn observe_literal_run(&mut self, _: u32, _: u32, _: &PreflateInput) {
            self.0.set(self.0.get() + 1);
        }
    }
    let contents = DeflateContents {
        compressed_size: 0,
        blocks: vec![DeflateTokenBlock {
            block_type: DeflateTokenBlockType::Huffman {
                tokens: vec![DeflateToken::Literal(b'a'); 65536],
                huffman_type: DeflateHuffmanType::Static,
            },
            last: true,
        }],
    };
    let plain = PlainText::new_with_data(vec![b'a'; 65536]);
    for (policy, minimum, cutoff, expected) in [
        (DictionaryAddPolicy::AddAll, 3, 4096, 256),
        (DictionaryAddPolicy::AddAll, 4, 4096, 0),
        (DictionaryAddPolicy::AddAll, 3, 4097, 0),
        (DictionaryAddPolicy::AddAll, 3, 0, 0),
        (DictionaryAddPolicy::AddFirst(4), 3, 4096, 256),
        (DictionaryAddPolicy::AddFirstAndLast(4), 3, 4096, 0),
    ] {
        let count = Rc::new(Cell::new(0));
        let mut candidates: Vec<Box<dyn HashTableDepthEstimator>> =
            vec![Box::new(Counter(count.clone()))];
        run_depth_candidates(
            policy,
            &contents,
            &plain,
            &mut candidates,
            minimum,
            cutoff,
            32768,
        );
        assert_eq!(count.get(), expected);
    }
}

#[test]
#[ignore = "offline hash ambiguity audit; requires PREFLATE_REFERENCE raw stream"]
fn diagnose_hash_chain_constraints() {
    use crate::{deflate::deflate_reader::parse_deflate_whole, estimator::extract_preflate_info};

    fn audit<H: HashImplementation>(
        hash: H,
        policy: DictionaryAddPolicy,
        contents: &DeflateContents,
        plain: &PlainText,
    ) {
        let mut state = HashTableDepthEstimatorImpl::box_new(hash, ParserEvidencePolicy::default());
        let mut input = PreflateInput::new(plain);
        let mut references = 0;
        let mut incompatible_hashes = 0;
        let mut missing_depths = 0;
        let mut over_budget = 0;
        let mut maximum_depth = 0;
        let mut maximum_short_depth = 0;
        for block in &contents.blocks {
            match &block.block_type {
                DeflateTokenBlockType::Stored { uncompressed } => {
                    for _ in uncompressed {
                        state.update_hash(policy, &input, 1);
                        input.advance(1);
                    }
                }
                DeflateTokenBlockType::Huffman { tokens, .. } => {
                    for token in tokens {
                        let length = match token {
                            DeflateToken::Literal(_) => 1,
                            DeflateToken::Reference(reference) => {
                                references += 1;
                                let current_hash = hash.get_hash(input.cur_chars(0));
                                let source_hash =
                                    hash.get_hash(input.cur_chars(-(reference.dist() as i32)));
                                let source = (input.pos() - reference.dist()) as u16;
                                let head = state.head[usize::from(current_hash)];
                                let source_depth = state.chain_depth[usize::from(source)];
                                let head_depth = state.chain_depth[usize::from(head)];
                                if current_hash != source_hash {
                                    incompatible_hashes += 1;
                                } else if state.chain_depth_hash_verify[usize::from(source)]
                                    != current_hash
                                    || source_depth <= 0
                                    || head_depth < source_depth
                                {
                                    missing_depths += 1;
                                } else {
                                    let depth = (head_depth - source_depth) as u32 + 1;
                                    maximum_depth = maximum_depth.max(depth);
                                    if reference.len() == 3 {
                                        maximum_short_depth = maximum_short_depth.max(depth);
                                    }
                                    over_budget += usize::from(depth > 4096);
                                }
                                reference.len()
                            }
                        };
                        state.update_hash(policy, &input, length);
                        input.advance(length);
                    }
                }
            }
        }
        assert_eq!(input.pos() as usize, plain.len());
        println!(
            "HASH_AUDIT hash={:?} insertion={policy:?} references={references} incompatible_hashes={incompatible_hashes} missing_depths={missing_depths} over_4096={over_budget} maximum_depth={maximum_depth} maximum_short_depth={maximum_short_depth}",
            hash.algorithm(),
        );
    }

    let path = std::env::var_os("PREFLATE_REFERENCE").expect("set PREFLATE_REFERENCE");
    let compressed = std::fs::read(path).unwrap();
    let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
    assert_eq!(contents.compressed_size, compressed.len());
    let info = extract_preflate_info(&contents.blocks);
    let inferred = super::add_policy_estimator::estimate_add_policy(&contents.blocks);
    println!(
        "HASH_SOURCE min_length={} max_length={} references={} short_references={} inferred_insertion={inferred:?}",
        info.min_len, info.max_len, info.reference_count, info.short_reference_count,
    );
    for policy in [inferred, DictionaryAddPolicy::AddAll] {
        audit(
            ZlibRotatingHashFixed::<5, 32767> {},
            policy,
            &contents,
            &plain,
        );
        audit(
            ZlibRotatingHashFixed::<4, 2047> {},
            policy,
            &contents,
            &plain,
        );
        audit(
            ZlibRotatingHashFixed::<6, 65535> {},
            policy,
            &contents,
            &plain,
        );
        audit(RandomVectorHash {}, policy, &contents, &plain);
    }
}

#[cfg(test)]
mod collision_diagnostics {
    use super::*;
    use crate::hash_chain::{HashChain, HashChainDefault};

    #[derive(Debug, PartialEq, Eq)]
    struct HeadObservation {
        head: Option<u32>,
        head_match_length: usize,
        first_prefix_match: Option<u32>,
    }

    fn observe_head<H: HashImplementation>(
        chain: &HashChainDefault<H>,
        input: &PreflateInput,
        reference: DeflateTokenReference,
    ) -> HeadObservation {
        assert_eq!(H::NUM_HASH_BYTES, 3);
        let current = input.cur_chars(0);
        let mut candidates = chain
            .iterate::<0>(input)
            .take_while(|&distance| distance <= 32768);
        let head = candidates.next();
        let head_match_length = head.map_or(0, |distance| {
            assert!(distance > 0);
            current
                .iter()
                .zip(input.cur_chars(-(distance as i32)))
                .take(reference.len() as usize)
                .take_while(|(a, b)| a == b)
                .count()
        });
        let first_prefix_match = if head_match_length >= 3 {
            head
        } else {
            candidates.find(|&distance| {
                assert!(distance > 0);
                current[..3] == input.cur_chars(-(distance as i32))[..3]
            })
        };
        HeadObservation {
            head,
            head_match_length,
            first_prefix_match,
        }
    }

    #[derive(Debug, Default)]
    struct HeadCounts {
        references: usize,
        actual_at_both_heads: usize,
        actual_at_zlib_head_only: usize,
        actual_at_windows_head_only: usize,
        zlib_head_with_windows_collision: usize,
        windows_head_with_zlib_collision: usize,
        actual_at_neither_head: usize,
        different_first_prefix_matches: usize,
        actual_at_first_prefix_match: usize,
    }

    fn audit(
        contents: &DeflateContents,
        plain: &PlainText,
        policy: DictionaryAddPolicy,
        print_examples: bool,
    ) -> HeadCounts {
        let mut zlib = HashChainDefault::new(ZlibRotatingHashFixed::<5, 32767> {});
        let mut windows = HashChainDefault::new(RandomVectorHash {});
        let mut input = PreflateInput::new(plain);
        let mut counts = HeadCounts::default();
        let mut examples = [0; 2];
        for block in &contents.blocks {
            let lengths: Box<dyn Iterator<Item = (u32, Option<DeflateTokenReference>)> + '_> =
                match &block.block_type {
                    DeflateTokenBlockType::Stored { uncompressed } => {
                        Box::new(uncompressed.iter().map(|_| (1, None)))
                    }
                    DeflateTokenBlockType::Huffman { tokens, .. } => {
                        Box::new(tokens.iter().map(|token| match token {
                            DeflateToken::Literal(_) => (1, None),
                            DeflateToken::Reference(reference) => {
                                (reference.len(), Some(*reference))
                            }
                        }))
                    }
                };
            for (length, reference) in lengths {
                if let Some(reference) = reference {
                    let a = observe_head(&zlib, &input, reference);
                    let b = observe_head(&windows, &input, reference);
                    counts.references += 1;
                    let a_selected = a.head == Some(reference.dist());
                    let b_selected = b.head == Some(reference.dist());
                    match (a_selected, b_selected) {
                        (true, true) => counts.actual_at_both_heads += 1,
                        (true, false) => counts.actual_at_zlib_head_only += 1,
                        (false, true) => counts.actual_at_windows_head_only += 1,
                        (false, false) => counts.actual_at_neither_head += 1,
                    }
                    counts.zlib_head_with_windows_collision +=
                        usize::from(a_selected && b.head.is_some() && b.head_match_length < 3);
                    counts.windows_head_with_zlib_collision +=
                        usize::from(b_selected && a.head.is_some() && a.head_match_length < 3);
                    counts.different_first_prefix_matches +=
                        usize::from(a.first_prefix_match != b.first_prefix_match);
                    counts.actual_at_first_prefix_match +=
                        usize::from(a.first_prefix_match == Some(reference.dist()));
                    if print_examples && a_selected != b_selected {
                        let direction = usize::from(b_selected);
                        if examples[direction] < 4 {
                            examples[direction] += 1;
                            println!(
                                "HEAD_EXAMPLE insertion={policy:?} offset={} length={} actual_distance={} zlib={a:?} windows={b:?}",
                                input.pos(),
                                reference.len(),
                                reference.dist(),
                            );
                        }
                    }
                }
                policy.update_hash(
                    input.cur_chars(0),
                    input.pos(),
                    length,
                    |chars, pos, len| {
                        zlib.update_hash(chars, pos, len);
                        windows.update_hash(chars, pos, len);
                    },
                );
                input.advance(length);
            }
        }
        assert_eq!(input.pos() as usize, plain.len());
        counts
    }

    #[test]
    fn hash_head_collision_checks_skip_unrelated_bucket_entries() {
        let zlib_hash = ZlibRotatingHashFixed::<5, 32767> {};
        let windows_hash = RandomVectorHash {};
        let target = *b"abc";
        for collide_with_zlib in [true, false] {
            let collision = (0u32..1 << 24)
                .map(|value| [value as u8, (value >> 8) as u8, (value >> 16) as u8])
                .find(|candidate| {
                    let same_zlib = zlib_hash.get_hash(candidate) == zlib_hash.get_hash(&target);
                    let same_windows =
                        windows_hash.get_hash(candidate) == windows_hash.get_hash(&target);
                    same_zlib == collide_with_zlib && same_windows != collide_with_zlib
                })
                .expect("a collision in exactly one of the tested hashes");
            let mut data = target.to_vec();
            data.push(b'!');
            data.extend(collision);
            data.push(b'?');
            data.extend(target);
            let plain = PlainText::new_with_data(data);
            let mut zlib = HashChainDefault::new(zlib_hash);
            let mut windows = HashChainDefault::new(windows_hash);
            for position in [0, 4] {
                zlib.update_hash(&plain.text()[position..], position as u32, 1);
                windows.update_hash(&plain.text()[position..], position as u32, 1);
            }
            let mut input = PreflateInput::new(&plain);
            input.advance(8);
            let reference = DeflateTokenReference::new(3, 8);
            let a = observe_head(&zlib, &input, reference);
            let b = observe_head(&windows, &input, reference);
            let (colliding, noncolliding) = if collide_with_zlib { (a, b) } else { (b, a) };
            assert_eq!(colliding.head, Some(4));
            assert!(colliding.head_match_length < 3);
            assert_eq!(noncolliding.head, Some(8));
            assert_eq!(noncolliding.head_match_length, 3);
            assert_eq!(colliding.first_prefix_match, Some(8));
            assert_eq!(noncolliding.first_prefix_match, Some(8));
        }
    }

    #[test]
    fn native_zlib_hash_head_collision_controls() {
        use crate::{deflate::deflate_reader::parse_deflate_whole, utils::read_file};
        for level in [1, 6] {
            let (contents, plain) =
                parse_deflate_whole(&read_file(&format!("compressed_zlib_level{level}.deflate")))
                    .unwrap();
            let policy = super::super::add_policy_estimator::estimate_add_policy(&contents.blocks);
            let counts = audit(&contents, &plain, policy, false);
            assert!(counts.actual_at_zlib_head_only > 0);
            // More direct-head hits do not identify the native compressor's hash.
            assert!(counts.actual_at_windows_head_only > counts.actual_at_zlib_head_only);
            assert_eq!(
                counts.zlib_head_with_windows_collision,
                counts.actual_at_zlib_head_only,
            );
            assert_eq!(
                counts.windows_head_with_zlib_collision,
                counts.actual_at_windows_head_only,
            );
            assert_eq!(counts.different_first_prefix_matches, 0);
        }
    }

    #[test]
    #[ignore = "offline collision witnesses; requires PREFLATE_REFERENCE raw stream"]
    fn diagnose_hash_head_collisions() {
        use crate::deflate::deflate_reader::parse_deflate_whole;
        let path = std::env::var_os("PREFLATE_REFERENCE").expect("set PREFLATE_REFERENCE");
        let compressed = std::fs::read(path).unwrap();
        let (contents, plain) = parse_deflate_whole(&compressed).unwrap();
        assert_eq!(contents.compressed_size, compressed.len());
        let inferred = super::super::add_policy_estimator::estimate_add_policy(&contents.blocks);
        let mut policies = vec![inferred];
        if inferred != DictionaryAddPolicy::AddAll {
            policies.push(DictionaryAddPolicy::AddAll);
        }
        for policy in policies {
            let counts = audit(&contents, &plain, policy, true);
            println!("HEAD_COUNTS insertion={policy:?} {counts:?}");
        }
    }
}

#[test]
fn native_zlib_literal_runs_do_not_reject_usable_three_byte_head_matches() {
    use crate::{
        deflate::deflate_reader::parse_deflate_whole, estimator::extract_preflate_info,
        utils::read_file,
    };
    for level in 4..=9 {
        let (contents, plain) =
            parse_deflate_whole(&read_file(&format!("compressed_zlib_level{level}.deflate")))
                .unwrap();
        let info = extract_preflate_info(&contents.blocks);
        let mut candidates = vec![new_depth_estimator(crate::models::zlib::DEFAULT_HASH)];
        run_depth_candidates(
            DictionaryAddPolicy::AddAll,
            &contents,
            &plain,
            &mut candidates,
            info.min_len,
            info.max_dist_3_matches,
            32768,
        );
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].short_match_rejections(), 0, "level {level}");
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
        run_depth_candidates(
            add_policy,
            &parsed,
            &plain_text,
            &mut candidates,
            3,
            u32::MAX,
            32768,
        );

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
