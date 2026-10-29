/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::bit_helper::DebugHash;
use crate::deflate::deflate_constants::{MAX_MATCH, MIN_LOOKAHEAD, MIN_MATCH};
use crate::deflate::deflate_token::DeflateTokenReference;
use crate::estimator::preflate_parameter_estimator::{PreflateStrategy, TokenPredictorParameters};
use crate::estimator::preflate_parse_config::MatchingType;
use crate::hash_algorithm::{
    Crc32cHash, HashAlgorithm, LibdeflateHash4Fast, LibdeflateHash4Fast15, MiniZHash,
    RandomVectorHash, ZlibNGHash, ZlibRotatingHash, ZlibRotatingHashFixed,
};
use crate::hash_chain::{HashChain, HashChainDefault, HashChainLibflate4, MAX_UPDATE_HASH_BATCH};
use crate::preflate_error::{ExitCode, Result, err_exit_code};
use crate::preflate_input::PreflateInput;

use std::cmp;

#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub enum MatchResult {
    Success(DeflateTokenReference),
    NoInput,
    NoMoreMatchesFound,
}

/// Factory function to create a new HashChainHolder based on the parameters and returns
/// a boxed trait object. The reason for this is that this lets the compiler inline hash
/// implementation.
pub fn new_hash_chain_holder(params: &TokenPredictorParameters) -> Box<dyn HashChainHolder> {
    match params.hash_algorithm {
        HashAlgorithm::None => Box::<()>::default(),

        // most common Zlib combo, optimize with fixed parameters
        HashAlgorithm::Zlib {
            hash_mask: 0x7fff,
            hash_shift: 5,
        } => Box::new(HashChainHolderImpl::new(
            params,
            HashChainDefault::new(ZlibRotatingHashFixed::<5, 0x7fff> {}),
        )),

        HashAlgorithm::Zlib {
            hash_mask,
            hash_shift,
        } => Box::new(HashChainHolderImpl::new(
            params,
            HashChainDefault::new(ZlibRotatingHash {
                hash_mask,
                hash_shift,
            }),
        )),

        HashAlgorithm::MiniZFast => Box::new(HashChainHolderImpl::new(
            params,
            HashChainDefault::new(MiniZHash {}),
        )),

        HashAlgorithm::Libdeflate4 => {
            Box::new(HashChainHolderImpl::new(params, HashChainLibflate4::new()))
        }

        HashAlgorithm::Libdeflate4Fast => Box::new(HashChainHolderImpl::new(
            params,
            HashChainDefault::new(LibdeflateHash4Fast {}),
        )),
        HashAlgorithm::Libdeflate4Fast15 => Box::new(HashChainHolderImpl::new(
            params,
            HashChainDefault::new(LibdeflateHash4Fast15 {}),
        )),

        HashAlgorithm::ZlibNG => Box::new(HashChainHolderImpl::new(
            params,
            HashChainDefault::new(ZlibNGHash {}),
        )),

        HashAlgorithm::RandomVector => Box::new(HashChainHolderImpl::new(
            params,
            HashChainDefault::new(RandomVectorHash {}),
        )),

        HashAlgorithm::Crc32cHash => Box::new(HashChainHolderImpl::new(
            params,
            HashChainDefault::new(Crc32cHash {}),
        )),
    }
}

/// trait that is not dependent on the HashImplementation so it can
/// be used in a concrete boxed type by the TokenPredictor
pub trait HashChainHolder {
    /// updates the hash dictionary for a given length of matches.
    ///
    /// If this is a literal, then the update policy is to add all the bytes to the dictionary.
    fn update_hash(&mut self, length: u32, input: &PreflateInput);

    /// searches the hash chain for a given match, returns the longest result found if any
    ///
    /// prev_len is the length of the previous match. We won't match anything shorter than that.
    /// max_depth is the maximum number of hops we will take in the hash chain
    fn match_token_0(&self, prev_len: u32, max_depth: u32, input: &PreflateInput) -> MatchResult;

    /// searches the hash chain for a given match, returns the longest result found if any.
    ///
    /// This is the lazy matching, so it starts at offset 1
    ///
    /// prev_len is the length of the previous match. We won't match anything shorter than that.
    /// max_depth is the maximum number of hops we will take in the hash chain
    fn match_token_1(&self, prev_len: u32, max_depth: u32, input: &PreflateInput) -> MatchResult;

    fn match_token_2(&self, prev_len: u32, max_depth: u32, input: &PreflateInput) -> MatchResult;

    /// Tries to find the match by continuing on the hash chain, returns how many hops we went
    /// or none if it wasn't found
    fn calculate_hops(
        &self,
        target_reference: &DeflateTokenReference,
        input: &PreflateInput,
    ) -> Result<u32>;

    /// Does the inverse of calculate_hops, where we start from the predicted token and
    /// get the new distance based on the number of hops
    fn hop_match(&self, len: u32, hops: u32, input: &PreflateInput) -> Result<u32>;

    /// when we continue compression on a block, we won't have added the last
    /// n - 1 hashes to the dictionary. Add them here.
    fn add_missing_previous_hash(&mut self, input: &PreflateInput);

    /// debugging function to verify that the hash chain is correct
    #[allow(dead_code)]
    fn verify_hash(&self, _dist: Option<DeflateTokenReference>);

    fn checksum(&self, checksum: &mut DebugHash);
}

/// empty implementation of HashChainHolder if there is no dictionary
/// being used (for example the file is stored or huffman only encoded)
impl HashChainHolder for () {
    fn update_hash(&mut self, _length: u32, _input: &PreflateInput) {}

    fn match_token_0(
        &self,
        _prev_len: u32,
        _max_depth: u32,
        _input: &PreflateInput,
    ) -> MatchResult {
        MatchResult::NoMoreMatchesFound
    }

    fn match_token_1(
        &self,
        _prev_len: u32,
        _max_depth: u32,
        _input: &PreflateInput,
    ) -> MatchResult {
        MatchResult::NoMoreMatchesFound
    }

    fn match_token_2(
        &self,
        _prev_len: u32,
        _max_depth: u32,
        _input: &PreflateInput,
    ) -> MatchResult {
        MatchResult::NoMoreMatchesFound
    }

    fn calculate_hops(
        &self,
        _target_reference: &DeflateTokenReference,
        _input: &PreflateInput,
    ) -> Result<u32> {
        unimplemented!()
    }

    fn hop_match(&self, _len: u32, _hops: u32, _input: &PreflateInput) -> Result<u32> {
        unimplemented!()
    }

    fn add_missing_previous_hash(&mut self, _input: &PreflateInput) {}

    fn verify_hash(&self, _dist: Option<DeflateTokenReference>) {}

    fn checksum(&self, _checksum: &mut DebugHash) {}
}

/// implemenation of HashChainHolder depends type of hash implemenatation
struct HashChainHolderImpl<H: HashChain> {
    hash: H,
    params: TokenPredictorParameters,
    window_bytes: u32,
}

impl<H: HashChain + 'static> HashChainHolder for HashChainHolderImpl<H> {
    fn update_hash(&mut self, length: u32, input: &PreflateInput) {
        debug_assert!(length <= MAX_UPDATE_HASH_BATCH);

        self.params.add_policy.update_hash(
            input.cur_chars(0),
            input.pos(),
            length,
            |input, pos, length| {
                self.hash.update_hash(input, pos, length);
            },
        );
    }

    fn match_token_0(&self, prev_len: u32, max_depth: u32, input: &PreflateInput) -> MatchResult {
        self.match_token_offset::<0>(prev_len, max_depth, input)
    }

    fn match_token_1(&self, prev_len: u32, max_depth: u32, input: &PreflateInput) -> MatchResult {
        self.match_token_offset::<1>(prev_len, max_depth, input)
    }

    fn match_token_2(&self, prev_len: u32, max_depth: u32, input: &PreflateInput) -> MatchResult {
        self.match_token_offset::<2>(prev_len, max_depth, input)
    }

    /// Tries to find the match by continuing on the hash chain, returns how many hops we went
    /// or none if it wasn't found
    fn calculate_hops(
        &self,
        target_reference: &DeflateTokenReference,
        input: &PreflateInput,
    ) -> Result<u32> {
        let max_len = std::cmp::min(input.remaining(), MAX_MATCH);

        if max_len < target_reference.len() {
            return err_exit_code(ExitCode::InvalidDeflate, "max_len < target_reference.len()");
        }

        if max_len < H::min_lookup_bytes() as u32 {
            return err_exit_code(ExitCode::MatchNotFound, "too few bytes left to hash");
        }

        let max_chain_org = 0xffff; // max hash chain length
        let mut max_chain = max_chain_org; // max hash chain length
        let best_len = target_reference.len();
        let mut hops = 0;

        let cur_max_dist = std::cmp::min(input.bytes_before(), self.window_bytes);

        for dist in self.hash.iterate::<0>(input) {
            if dist > cur_max_dist {
                break;
            }

            let match_pos = input.cur_chars(-(dist as i32));
            let match_length = prefix_compare(match_pos, input.cur_chars(0), best_len);

            if match_length >= 3 && match_length >= best_len {
                hops += 1;
            }

            if dist >= target_reference.dist() {
                if dist == target_reference.dist() {
                    return Ok(hops);
                } else {
                    break;
                }
            }

            if max_chain <= 1 {
                break;
            }

            max_chain -= 1;
        }
        self.hash.assert_dictionary_valid(*target_reference, input);

        err_exit_code(ExitCode::MatchNotFound, "no match found")
    }

    /// Does the inverse of calculate_hops, where we start from the predicted token and
    /// get the new distance based on the number of hops
    fn hop_match(&self, len: u32, hops: u32, input: &PreflateInput) -> Result<u32> {
        let max_len = std::cmp::min(input.remaining(), MAX_MATCH);
        if max_len < len {
            return err_exit_code(ExitCode::RecompressFailed, "not enough data left to match");
        }

        if max_len < H::min_lookup_bytes() as u32 {
            return err_exit_code(ExitCode::RecompressFailed, "too few bytes left to hash");
        }

        let cur_max_dist = std::cmp::min(input.bytes_before(), self.window_bytes);
        let mut current_hop = 0;

        for dist in self.hash.iterate::<0>(input) {
            if dist > cur_max_dist {
                break;
            }

            let match_length =
                prefix_compare(input.cur_chars(-(dist as i32)), input.cur_chars(0), len);

            if match_length >= 3 && match_length >= len {
                current_hop += 1;
                if current_hop == hops {
                    return Ok(dist);
                }
            }
        }

        err_exit_code(ExitCode::RecompressFailed, "no match found")
    }

    /// adds the hashes that couldn't be added because we were at the boundary.
    fn add_missing_previous_hash(&mut self, input: &PreflateInput) {
        let length = H::get_num_hash_bytes() as u32 - 1;

        self.hash.update_hash(
            input.cur_chars(-(length as i32)),
            input.pos() - length,
            length,
        );
    }

    /// debugging function to verify that the hash chain is correct
    #[allow(dead_code)]
    fn verify_hash(&self, _dist: Option<DeflateTokenReference>) {
        //self.hash.verify_hash(dist, &self.input);
    }

    #[allow(dead_code)]
    fn checksum(&self, checksum: &mut DebugHash) {
        self.hash.checksum(checksum);
    }
}

// Read the two bytes starting at pos and interpret them as an u16.
#[inline(always)]
fn read_u16_le(slice: &[u8], pos: usize) -> u16 {
    // The compiler is smart enough to optimize this into an unaligned load.
    u16::from_le_bytes((&slice[pos..pos + 2]).try_into().unwrap())
}

// Read the two bytes starting at pos and interpret them as an u32.
#[inline(always)]
fn read_u32_le(slice: &[u8], pos: usize) -> u32 {
    // The compiler is smart enough to optimize this into an unaligned load.
    u32::from_le_bytes((&slice[pos..pos + 4]).try_into().unwrap())
}

impl<H: HashChain> HashChainHolderImpl<H> {
    pub fn new(params: &TokenPredictorParameters, hash: H) -> Self {
        Self {
            hash,
            window_bytes: 1 << params.window_bits,
            params: *params,
        }
    }

    #[inline]
    fn match_token_offset<const OFFSET: u32>(
        &self,
        prev_len: u32,
        max_depth: u32,
        input: &PreflateInput,
    ) -> MatchResult {
        let start_pos = input.pos() + OFFSET;
        let max_len = std::cmp::min(input.total_length() - start_pos, MAX_MATCH);
        // Apply source-compressor exclusions only to normal prediction. Expanded-budget
        // correction searches must still recover references outside the selected profile.
        let fast_profile = self.hash.algorithm() == HashAlgorithm::Libdeflate4Fast15
            && max_depth <= self.params.max_chain;
        let greedy_profile = self.hash.algorithm() == HashAlgorithm::Libdeflate4
            && self.params.matching_type == MatchingType::LibdeflateGreedy
            && max_depth <= self.params.max_chain;
        if (fast_profile || greedy_profile) && max_len < 5 {
            return MatchResult::NoInput;
        }
        if max_len
            < std::cmp::max(
                prev_len + 1,
                std::cmp::max(H::min_lookup_bytes() as u32, MIN_MATCH),
            )
        {
            return MatchResult::NoInput;
        }

        let hist_to_start = input.bytes_before() + OFFSET;
        let max_dist_to_start = hist_to_start
            - if self.params.matches_to_start_detected {
                0
            } else {
                1
            };

        let cur_max_dist_hop0;
        let cur_max_dist_hop1_plus;
        if self.params.very_far_matches_detected {
            // These libdeflate modes exclude the exact window-edge distance.
            cur_max_dist_hop0 = cmp::min(
                max_dist_to_start,
                self.window_bytes - u32::from(fast_profile || greedy_profile),
            );
            cur_max_dist_hop1_plus = cur_max_dist_hop0;
        } else {
            match self.params.strategy {
                PreflateStrategy::HuffOnly | PreflateStrategy::Store => {
                    return MatchResult::NoMoreMatchesFound;
                }
                PreflateStrategy::RleOnly => {
                    cur_max_dist_hop0 = 1;
                    cur_max_dist_hop1_plus = 1;
                }
                _ => {
                    let max_dist: u32 = self.window_bytes - MIN_LOOKAHEAD + 1;
                    cur_max_dist_hop0 = cmp::min(max_dist_to_start, max_dist);
                    cur_max_dist_hop1_plus = cmp::min(max_dist_to_start, max_dist - 1);
                }
            }
        }

        let nice_length = std::cmp::min(self.params.nice_length, max_len);

        let best_len = prev_len.max(1);

        let secondary = if OFFSET > 0 && prev_len < 3 {
            self.hash.secondary_match(input, OFFSET)
        } else {
            None
        };
        // A minimum of four or more bypasses the singleton three-byte candidate.
        // The stored budget includes that slot, so remove both the slot and its probe.
        let skip_secondary =
            OFFSET == 0 && prev_len >= 3 && self.hash.algorithm() == HashAlgorithm::Libdeflate4;
        let max_depth = max_depth.saturating_sub(u32::from(skip_secondary)).max(1);
        let mut iter = secondary
            .into_iter()
            .chain(self.hash.iterate::<OFFSET>(input));
        if skip_secondary {
            iter.next();
        }

        if let MatchingType::MiniZ { max_probes, .. } = self.params.matching_type {
            let available = (input.total_length() - start_pos).min(MAX_MATCH);
            // Miniz reserves room for the possible match, reducing its usable distance.
            let window = self.window_bytes.saturating_sub(available);
            let max_dist = max_dist_to_start.min(window);
            let probes = if max_depth > self.params.max_chain {
                max_depth
            } else {
                u32::from(max_probes)
            };
            return match_miniz::<OFFSET>(input, max_len, max_dist, probes, prev_len.max(2), iter);
        }

        match_less3::<OFFSET>(
            input,
            max_len,
            cur_max_dist_hop0,
            cur_max_dist_hop1_plus,
            nice_length,
            max_depth,
            best_len,
            iter,
        )
    }
}

#[inline]
fn match_miniz<const OFFSET: u32>(
    input: &PreflateInput<'_>,
    max_len: u32,
    max_dist: u32,
    max_probes: u32,
    mut best_len: u32,
    mut iter: impl Iterator<Item = u32>,
) -> MatchResult {
    let bytes = input.cur_chars(OFFSET as i32);
    let probes = if best_len < 32 {
        max_probes
    } else {
        max_probes >> 2
    };
    // A group contains up to three suffix probes. Its first suffix hit consumes
    // the group even if the prefix fails, unlike a simple N-hop chain budget.
    let mut groups = probes.div_ceil(3);
    let mut best = MatchResult::NoMoreMatchesFound;
    while groups > 0 {
        groups -= 1;
        let suffix = read_u16_le(bytes, (best_len - 1) as usize);
        let mut candidate = None;
        for _ in 0..3 {
            let Some(dist) = iter.next() else { return best };
            if dist > max_dist {
                return best;
            }
            let source = input.cur_chars(OFFSET as i32 - dist as i32);
            if read_u16_le(source, (best_len - 1) as usize) == suffix {
                candidate = Some((dist, source));
                break;
            }
        }
        if let Some((dist, source)) = candidate {
            if read_u16_le(source, 0) != read_u16_le(bytes, 0) {
                continue;
            }
            let length = prefix_compare(source, bytes, max_len);
            if length > best_len {
                best_len = length;
                best = MatchResult::Success(DeflateTokenReference::new(length, dist));
                if length == max_len {
                    return best;
                }
            }
        }
    }
    best
}

/// searches for a match that is at least 3 bytes long
#[inline]
fn match_less3<const OFFSET: u32>(
    input: &PreflateInput<'_>,
    max_len: u32,
    cur_max_dist_hop0: u32,
    cur_max_dist_hop1_plus: u32,
    nice_length: u32,
    mut max_chain: u32,
    best_len: u32,
    mut iter: impl Iterator<Item = u32>,
) -> MatchResult {
    let input_chars = input.cur_chars(OFFSET as i32);

    // look at last two characters of best length so far
    let c0 = read_u16_le(input_chars, (best_len - 1) as usize);

    let mut best = MatchResult::NoMoreMatchesFound;
    let mut max_dist = cur_max_dist_hop0;

    while let Some(dist) = iter.next() {
        if dist > max_dist {
            break;
        }

        max_dist = cur_max_dist_hop1_plus;

        let match_start = input.cur_chars(OFFSET as i32 - dist as i32);

        if read_u16_le(match_start, (best_len - 1) as usize) == c0 {
            let match_length = prefix_compare(match_start, input_chars, max_len);

            if match_length >= 3 && match_length > best_len {
                best = MatchResult::Success(DeflateTokenReference::new(match_length, dist));

                if match_length >= nice_length || match_length == max_len {
                    break;
                }

                max_chain -= 1;
                if max_chain == 0 {
                    break;
                }

                match_4::<OFFSET>(
                    input,
                    max_len,
                    max_dist,
                    nice_length,
                    max_chain,
                    match_length,
                    iter,
                    &mut best,
                );
                return best;
            }
        }

        max_chain -= 1;

        if max_chain == 0 {
            break;
        }
    }
    best
}

/// Once we know that we have a least a 3 byte match, we can be faster by comparing 4 bytes at a time
#[inline]
fn match_4<const OFFSET: u32>(
    input: &PreflateInput<'_>,
    max_len: u32,
    max_dist: u32,
    nice_length: u32,
    mut max_chain: u32,
    mut best_len: u32,
    mut iter: impl Iterator<Item = u32>,
    best: &mut MatchResult,
) {
    let input_chars = input.cur_chars(OFFSET as i32);

    // look at last 3 characters of best length so far + 1 because we want to improve the match
    let mut c0 = read_u32_le(input_chars, (best_len - 3) as usize);

    while let Some(dist) = iter.next() {
        if dist > max_dist {
            break;
        }

        let match_start = input.cur_chars(OFFSET as i32 - dist as i32);

        if read_u32_le(match_start, (best_len - 3) as usize) == c0 {
            let match_length = prefix_compare(match_start, input_chars, max_len);

            if match_length > best_len {
                *best = MatchResult::Success(DeflateTokenReference::new(match_length, dist));

                if match_length >= nice_length || match_length == max_len {
                    break;
                }

                best_len = match_length;

                c0 = read_u32_le(input_chars, (best_len - 3) as usize);
            }
        }

        max_chain -= 1;

        if max_chain == 0 {
            break;
        }
    }
}

#[inline(always)]
fn prefix_compare(s1: &[u8], s2: &[u8], max_len: u32) -> u32 {
    if max_len == 258 {
        prefix_compare_fast(s1, s2)
    } else {
        prefix_cmp_odd_size(max_len, s1, s2)
    }
}

#[inline(always)]
fn prefix_compare_fast(s1: &[u8], s2: &[u8]) -> u32 {
    assert!(s1.len() >= 258 && s2.len() >= 258);
    for i in 0..32 {
        let c = comp_8_bytes(
            &s1[(i * 8) as usize..(i * 8 + 8) as usize],
            &s2[(i * 8) as usize..(i * 8 + 8) as usize],
        );
        if c != 0 {
            return calc_diff(c) + (i * 8);
        }
    }
    if s1[256] != s2[256] {
        return 256;
    }
    if s1[257] != s2[257] {
        return 257;
    }
    return 258;
}

#[inline(never)]
fn prefix_cmp_odd_size(max_len: u32, s1: &[u8], s2: &[u8]) -> u32 {
    assert!(
        max_len >= 3 && s1.len() >= max_len as usize && s2.len() >= max_len as usize,
        "maxlen:{}, s1:{}, s2:{}",
        max_len,
        s1.len(),
        s2.len()
    );

    if read_u16_le(s1, 0) != read_u16_le(s2, 0) {
        return 0;
    }

    let mut match_len = 2;
    // Initialize with the length of the fixed prefix
    for i in 2..max_len {
        if s1[i as usize] != s2[i as usize] {
            break;
        }
        match_len = i + 1;
    }

    match_len
}

fn comp_8_bytes(s1: &[u8], s2: &[u8]) -> u64 {
    let a = u64::from_le_bytes(s1[0..8].try_into().unwrap());
    let b = u64::from_le_bytes(s2[0..8].try_into().unwrap());
    a ^ b
}

fn calc_diff(diff: u64) -> u32 {
    if diff != 0 {
        return diff.trailing_zeros() / 8;
    }
    return 8;
}

// Source tail/window exclusions must not prevent recovery of valid foreign references.
// Verify normal boundary decisions and expanded-budget recovery for both low-level models.
#[test]
fn libdeflate_low_level_limits_preserve_correction_recovery() {
    use crate::{
        estimator::add_policy_estimator::DictionaryAddPolicy, preflate_input::PlainText,
        token_predictor::zlib_level_1_params,
    };
    for (hash_algorithm, matching_type) in [
        (HashAlgorithm::Libdeflate4Fast15, MatchingType::Greedy),
        (HashAlgorithm::Libdeflate4, MatchingType::LibdeflateGreedy),
    ] {
        let params = TokenPredictorParameters {
            hash_algorithm,
            matching_type,
            add_policy: DictionaryAddPolicy::AddAll,
            matches_to_start_detected: true,
            very_far_matches_detected: true,
            max_chain: 2,
            nice_length: 32,
            ..zlib_level_1_params()
        };
        for distance in [5, 32767, 32768] {
            let mut bytes = vec![b'.'; distance];
            bytes[..5].copy_from_slice(b"abcdX");
            bytes.extend_from_slice(if distance == 5 { b"abcd" } else { b"abcdY" });
            let plain = PlainText::new_with_data(bytes);
            let mut input = PreflateInput::new(&plain);
            let mut holder = new_hash_chain_holder(&params);
            while input.pos() < distance as u32 {
                let length = (distance as u32 - input.pos()).min(MAX_UPDATE_HASH_BATCH);
                holder.update_hash(length, &input);
                input.advance(length);
            }
            let normal = holder.match_token_0(2, params.max_chain, &input);
            if distance == 32767 {
                assert!(
                    matches!(normal, MatchResult::Success(reference) if reference == DeflateTokenReference::new(4, distance as u32))
                );
            } else {
                assert!(!matches!(normal, MatchResult::Success(_)));
            }
            assert!(matches!(
                holder.match_token_0(2, params.max_chain + 1, &input),
                MatchResult::Success(reference) if reference == DeflateTokenReference::new(4, distance as u32)
            ));
        }
    }
}

// Miniz spends one group on three failed suffix probes rather than treating each as a group.
// Verify the fourth candidate is unreachable with one group but reachable with two.
#[test]
fn miniz_probe_groups_skip_three_failed_suffixes() {
    use crate::preflate_input::PlainText;
    let mut bytes = vec![b'X'; 69];
    for pos in [40, 48, 56] {
        bytes[pos..pos + 5].copy_from_slice(b"abZZZ");
    }
    bytes[32..37].copy_from_slice(b"abcdX");
    bytes[64..].copy_from_slice(b"abcdY");
    let plain = PlainText::new_with_data(bytes);
    let mut input = PreflateInput::new(&plain);
    input.advance(64);
    assert!(matches!(
        match_miniz::<0>(&input, 5, 64, 3, 2, [8, 16, 24, 32].into_iter()),
        MatchResult::NoMoreMatchesFound
    ));
    assert!(matches!(
        match_miniz::<0>(&input, 5, 64, 6, 2, [8, 16, 24, 32].into_iter()),
        MatchResult::Success(reference) if reference == DeflateTokenReference::new(4, 32)
    ));
}

// A suffix hit ends miniz's probe group even when its prefix fails.
// Verify neither a short match nor a false suffix hit searches the group's remaining nodes.
#[test]
fn miniz_successful_suffix_consumes_a_probe_group() {
    use crate::preflate_input::PlainText;
    for first in [b"abcXY", b"ZbcXY"] {
        let mut bytes = vec![b'X'; 69];
        bytes[56..61].copy_from_slice(first);
        bytes[48..53].copy_from_slice(b"abcdX");
        bytes[64..].copy_from_slice(b"abcdY");
        let plain = PlainText::new_with_data(bytes);
        let mut input = PreflateInput::new(&plain);
        input.advance(64);
        let result = match_miniz::<0>(&input, 5, 64, 3, 2, [8, 16].into_iter());
        if first == b"abcXY" {
            assert!(matches!(result, MatchResult::Success(reference) if reference.len() == 3));
        } else {
            assert!(matches!(result, MatchResult::NoMoreMatchesFound));
        }
    }
}

// Miniz reduces lazy search effort once the saved match reaches length 32.
// Verify the quartered budget misses a candidate that the unreduced budget reaches.
#[test]
fn miniz_long_saved_match_quarters_the_probe_budget() {
    use crate::preflate_input::PlainText;
    let mut bytes = vec![b'A'; 290];
    for pos in [112, 160, 208] {
        bytes[pos + 31] = b'B';
    }
    let plain = PlainText::new_with_data(bytes);
    let mut input = PreflateInput::new(&plain);
    input.advance(256);
    assert!(matches!(
        match_miniz::<0>(&input, 34, 256, 12, 32, [48, 96, 144, 192].into_iter()),
        MatchResult::NoMoreMatchesFound
    ));
    assert!(matches!(
        match_miniz::<0>(&input, 34, 256, 12, 2, [48, 96, 144, 192].into_iter()),
        MatchResult::Success(reference) if reference == DeflateTokenReference::new(34, 192)
    ));
}
