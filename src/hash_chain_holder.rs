/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::bit_helper::DebugHash;
use crate::hash_algorithm::{
    Crc32cHash, HashAlgorithm, HashImplementation, LibdeflateHash4, LibdeflateHash4Fast, MiniZHash,
    RandomVectorHash, ZlibNGHash, ZlibRotatingHash,
};
use crate::hash_chain::{HashChain, MAX_UPDATE_HASH_BATCH};
use crate::preflate_constants::{MAX_MATCH, MIN_LOOKAHEAD, MIN_MATCH};
use crate::preflate_error::{err_exit_code, ExitCode, Result};
use crate::preflate_input::PreflateInput;
use crate::preflate_parameter_estimator::PreflateStrategy;
use crate::preflate_token::PreflateTokenReference;
use crate::token_predictor::TokenPredictorParameters;

use std::cmp;

#[derive(Debug, Copy, Clone)]
pub enum MatchResult {
    Success(PreflateTokenReference),
    DistanceLargerThanHop0(u32, u32),
    NoInput,
    NoMoreMatchesFound,
    MaxChainExceeded(u32),
}

/// Factory function to create a new HashChainHolder based on the parameters and returns
/// a boxed trait object. The reason for this is that this lets the compiler optimize the
pub fn new_hash_chain_holder(params: &TokenPredictorParameters) -> Box<dyn HashChainHolder> {
    match params.hash_algorithm {
        HashAlgorithm::None => Box::<()>::default(),
        HashAlgorithm::Zlib {
            hash_mask,
            hash_shift,
        } => Box::new(HashChainHolderImpl::new(
            params,
            ZlibRotatingHash {
                hash_mask,
                hash_shift,
            },
        )),
        HashAlgorithm::MiniZFast => Box::new(HashChainHolderImpl::new(params, MiniZHash {})),
        HashAlgorithm::Libdeflate4 => {
            Box::new(HashChainHolderImpl::new(params, LibdeflateHash4 {}))
        }
        HashAlgorithm::Libdeflate4Fast => {
            Box::new(HashChainHolderImpl::new(params, LibdeflateHash4Fast {}))
        }

        HashAlgorithm::ZlibNG => Box::new(HashChainHolderImpl::new(params, ZlibNGHash {})),
        HashAlgorithm::RandomVector => {
            Box::new(HashChainHolderImpl::new(params, RandomVectorHash {}))
        }
        HashAlgorithm::Crc32cHash => Box::new(HashChainHolderImpl::new(params, Crc32cHash {})),
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

    /// Tries to find the match by continuing on the hash chain, returns how many hops we went
    /// or none if it wasn't found
    fn calculate_hops(
        &self,
        target_reference: &PreflateTokenReference,
        input: &PreflateInput,
    ) -> Result<u32>;

    /// Does the inverse of calculate_hops, where we start from the predicted token and
    /// get the new distance based on the number of hops
    fn hop_match(&self, len: u32, hops: u32, input: &PreflateInput) -> Result<u32>;

    /// debugging function to verify that the hash chain is correct
    #[allow(dead_code)]
    fn verify_hash(&self, _dist: Option<PreflateTokenReference>);

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

    fn calculate_hops(
        &self,
        _target_reference: &PreflateTokenReference,
        _input: &PreflateInput,
    ) -> Result<u32> {
        unimplemented!()
    }

    fn hop_match(&self, _len: u32, _hops: u32, _input: &PreflateInput) -> Result<u32> {
        unimplemented!()
    }

    fn verify_hash(&self, _dist: Option<PreflateTokenReference>) {}

    fn checksum(&self, _checksum: &mut DebugHash) {}
}

/// implemenation of HashChainHolder depends type of hash implemenatation
struct HashChainHolderImpl<H: HashImplementation> {
    hash: H::HashChainType,
    params: TokenPredictorParameters,
    window_bytes: u32,
}

impl<H: HashImplementation> HashChainHolder for HashChainHolderImpl<H> {
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

    /// Tries to find the match by continuing on the hash chain, returns how many hops we went
    /// or none if it wasn't found
    fn calculate_hops(
        &self,
        target_reference: &PreflateTokenReference,
        input: &PreflateInput,
    ) -> Result<u32> {
        let max_len = std::cmp::min(input.remaining(), MAX_MATCH);

        if max_len < target_reference.len() {
            return err_exit_code(ExitCode::InvalidDeflate, "max_len < target_reference.len()");
        }

        let max_chain_org = 0xffff; // max hash chain length
        let mut max_chain = max_chain_org; // max hash chain length
        let best_len = target_reference.len();
        let mut hops = 0;

        let cur_max_dist = std::cmp::min(input.pos(), self.window_bytes);

        for dist in self.hash.iterate(input, 0) {
            if dist > cur_max_dist {
                break;
            }

            let match_pos = input.cur_chars(-(dist as i32));
            let match_length =
                prefix_compare(match_pos, input.cur_chars(0), best_len - 1, best_len);

            if match_length >= best_len {
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

        err_exit_code(ExitCode::MatchNotFound, "no match found")
    }

    /// Does the inverse of calculate_hops, where we start from the predicted token and
    /// get the new distance based on the number of hops
    fn hop_match(&self, len: u32, hops: u32, input: &PreflateInput) -> Result<u32> {
        let max_len = std::cmp::min(input.remaining(), MAX_MATCH);
        if max_len < len {
            return err_exit_code(ExitCode::RecompressFailed, "not enough data left to match");
        }

        let cur_max_dist = std::cmp::min(input.pos(), self.window_bytes);
        let mut current_hop = 0;

        for dist in self.hash.iterate(input, 0) {
            if dist > cur_max_dist {
                break;
            }

            let match_length = prefix_compare(
                input.cur_chars(-(dist as i32)),
                input.cur_chars(0),
                len - 1,
                len,
            );

            if match_length >= len {
                current_hop += 1;
                if current_hop == hops {
                    return Ok(dist);
                }
            }
        }

        err_exit_code(ExitCode::RecompressFailed, "no match found")
    }

    /// debugging function to verify that the hash chain is correct
    #[allow(dead_code)]
    fn verify_hash(&self, _dist: Option<PreflateTokenReference>) {
        //self.hash.verify_hash(dist, &self.input);
    }

    #[allow(dead_code)]
    fn checksum(&self, checksum: &mut DebugHash) {
        self.hash.checksum(checksum);
    }
}

impl<H: HashImplementation> HashChainHolderImpl<H> {
    pub fn new(params: &TokenPredictorParameters, hash: H) -> Self {
        Self {
            hash: hash.new_hash_chain(),
            window_bytes: 1 << params.window_bits,
            params: *params,
        }
    }

    #[inline(never)]
    fn match_token_offset<const OFFSET: u32>(
        &self,
        prev_len: u32,
        max_depth: u32,
        input: &PreflateInput,
    ) -> MatchResult {
        let start_pos = input.pos() + OFFSET;
        let max_len = std::cmp::min(input.size() - start_pos, MAX_MATCH);
        if max_len
            < std::cmp::max(
                prev_len + 1,
                std::cmp::max(H::NUM_HASH_BYTES as u32, MIN_MATCH),
            )
        {
            return MatchResult::NoInput;
        }

        let max_dist_to_start = start_pos
            - if self.params.matches_to_start_detected {
                0
            } else {
                1
            };

        let cur_max_dist_hop0;
        let cur_max_dist_hop1_plus;
        if self.params.very_far_matches_detected {
            cur_max_dist_hop0 = cmp::min(max_dist_to_start, self.window_bytes);
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
        let max_dist_3_matches = u32::from(self.params.max_dist_3_matches);
        let mut max_chain = max_depth;

        let input_chars = input.cur_chars(OFFSET as i32);
        let mut best_len = prev_len;
        let mut best_match: Option<PreflateTokenReference> = None;
        let mut first = true;

        for dist in self.hash.iterate(input, OFFSET) {
            // first entry gets a special treatment to make sure it doesn't exceed
            // the limits we calculated for the first hop
            if first {
                first = false;
                if dist > cur_max_dist_hop0 {
                    return MatchResult::DistanceLargerThanHop0(dist, cur_max_dist_hop0);
                }
            } else if dist > cur_max_dist_hop1_plus {
                break;
            }

            let match_start = input.cur_chars(OFFSET as i32 - dist as i32);

            let match_length = prefix_compare(match_start, input_chars, best_len, max_len);
            if match_length > best_len {
                let r = PreflateTokenReference::new(match_length, dist, false);

                if match_length >= nice_length && (match_length > 3 || dist <= max_dist_3_matches) {
                    return MatchResult::Success(r);
                }

                best_len = match_length;
                best_match = Some(r);
            }

            max_chain -= 1;

            if max_chain == 0 {
                if let Some(r) = best_match {
                    return MatchResult::Success(r);
                } else {
                    return MatchResult::MaxChainExceeded(max_depth);
                }
            }
        }

        if let Some(r) = best_match {
            MatchResult::Success(r)
        } else {
            MatchResult::NoMoreMatchesFound
        }
    }
}

#[inline(always)]
fn prefix_compare(s1: &[u8], s2: &[u8], best_len: u32, max_len: u32) -> u32 {
    prefix_cmp_odd_size(max_len, s1, s2, best_len)
    /*
    not working yet

    if max_len == 258 {
        assert!(s1.len() >= 258 && s2.len() >= 258);

        let c = comp_8_bytes(&s1[0..8], &s2[0..8]);
        if c != 0 {
            let d = calc_diff(c);
            if d < 3 {
                return 0;
            } else {
                return d;
            }
        }

        for i in 0..7 {
            let c = comp_8_bytes(
                &s1[i as usize..(i + 8) as usize],
                &s2[i as usize..(i + 8) as usize],
            );
            if c != 0 {
                return calc_diff(c) + (i + 1) * 8;
            }
        }
        if s1[256] != s2[256] {
            return 256;
        }
        if s1[257] != s2[257] {
            return 257;
        }
        return 258;
    } else {
        prefix_cmp_odd_size(max_len, s1, s2, best_len)
    }*/
}

#[cold]
fn prefix_cmp_odd_size(max_len: u32, s1: &[u8], s2: &[u8], best_len: u32) -> u32 {
    assert!(
        max_len >= 3
            && s1.len() >= max_len as usize
            && s2.len() >= max_len as usize
            && best_len < max_len
    );

    if s1[best_len as usize] != s2[best_len as usize] {
        return 0;
    }
    if s1[0] != s2[0] || s1[1] != s2[1] || s1[2] != s2[2] {
        return 0;
    }

    let mut match_len = 3;
    // Initialize with the length of the fixed prefix
    for i in 3..max_len {
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
