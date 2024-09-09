/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::bit_helper::DebugHash;
use crate::hash_algorithm::{
    Crc32cHash, HashAlgorithm, HashImplementation, LibdeflateRotatingHash4, MiniZHash,
    RandomVectorHash, ZlibNGHash, ZlibRotatingHash,
};
use crate::hash_chain::{
    DictionaryAddPolicy, HashChain, MAX_UPDATE_HASH_BATCH, UPDATE_MODE_ALL, UPDATE_MODE_FIRST,
    UPDATE_MODE_FIRST_AND_LAST,
};
use crate::preflate_constants::{MAX_MATCH, MIN_LOOKAHEAD, MIN_MATCH};
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
    let predictor_state: Box<dyn HashChainHolder>;
    match params.hash_algorithm {
        HashAlgorithm::Zlib {
            hash_mask,
            hash_shift,
        } => {
            predictor_state = Box::new(HashChainHolderImpl::new(
                params,
                ZlibRotatingHash {
                    hash_mask,
                    hash_shift,
                },
            ))
        }
        HashAlgorithm::MiniZFast => {
            predictor_state = Box::new(HashChainHolderImpl::new(params, MiniZHash {}))
        }
        HashAlgorithm::Libdeflate4 => {
            predictor_state = Box::new(HashChainHolderImpl::new(params, LibdeflateRotatingHash4 {}))
        }
        HashAlgorithm::ZlibNG => {
            predictor_state = Box::new(HashChainHolderImpl::new(params, ZlibNGHash {}))
        }
        HashAlgorithm::RandomVector => {
            predictor_state = Box::new(HashChainHolderImpl::new(params, RandomVectorHash {}))
        }
        HashAlgorithm::Crc32cHash => {
            predictor_state = Box::new(HashChainHolderImpl::new(params, Crc32cHash {}))
        }
    }
    predictor_state
}

/// trait that is not dependent on the HashImplementation so it can
/// be used in a concrete boxed type by the TokenPredictor
pub trait HashChainHolder {
    /// updates the hash dictionary for a given length of matches.
    ///
    /// If this is a literal, then the update policy is to add all the bytes to the dictionary.
    fn update_hash(&mut self, length: u32, input: &PreflateInput);

    /// updates the hash dictionary for a given length of matches, and also updates the depth
    /// map of the hash chain.
    ///
    /// If this is a literal, then the update policy is to add all the bytes to the dictionary.
    fn update_hash_with_depth(&mut self, length: u32, input: &PreflateInput);

    /// searches the hash chain for a given match, returns the longest result found if any
    ///
    /// prev_len is the length of the previous match. We won't match anything shorter than that.
    /// offset is the offset from the current position in the input (can be 0 for current or 1 for lazy matches)
    /// max_depth is the maximum number of hops we will take in the hash chain
    fn match_token(
        &self,
        prev_len: u32,
        offset: u32,
        max_depth: u32,
        input: &PreflateInput,
    ) -> MatchResult;

    /// Tries to find the match by continuing on the hash chain, returns how many hops we went
    /// or none if it wasn't found
    fn calculate_hops(
        &self,
        target_reference: &PreflateTokenReference,
        input: &PreflateInput,
    ) -> anyhow::Result<u32>;

    /// Does the inverse of calculate_hops, where we start from the predicted token and
    /// get the new distance based on the number of hops
    fn hop_match(&self, len: u32, hops: u32, input: &PreflateInput) -> anyhow::Result<u32>;

    /// Returns the depth of the match, which refers to the number of hops in the hashtable
    fn match_depth(
        &self,
        token: PreflateTokenReference,
        window_size: u32,
        input: &PreflateInput,
    ) -> u32;

    /// debugging function to verify that the hash chain is correct
    fn verify_hash(&self, _dist: Option<PreflateTokenReference>);

    fn checksum(&self, checksum: &mut DebugHash);
}

/// implemenation of HashChainHolder depends type of hash implemenatation
struct HashChainHolderImpl<H: HashImplementation> {
    hash: H::HashChainType,
    params: TokenPredictorParameters,
    window_bytes: u32,
}

impl<H: HashImplementation> HashChainHolder for HashChainHolderImpl<H> {
    fn update_hash(&mut self, length: u32, input: &PreflateInput) {
        self.update_hash_with_policy::<false>(length, input, self.params.add_policy);
    }

    fn update_hash_with_depth(&mut self, length: u32, input: &PreflateInput) {
        self.update_hash_with_policy::<true>(length, input, self.params.add_policy);
    }

    fn match_depth(
        &self,
        token: PreflateTokenReference,
        window_size: u32,
        input: &PreflateInput,
    ) -> u32 {
        self.hash.match_depth(&token, window_size, input)
    }

    fn match_token(
        &self,
        prev_len: u32,
        offset: u32,
        max_depth: u32,
        input: &PreflateInput,
    ) -> MatchResult {
        let start_pos = input.pos() + offset;
        let max_len = std::cmp::min(input.size() - start_pos, MAX_MATCH);
        if max_len
            < std::cmp::max(
                prev_len + 1,
                std::cmp::max(H::num_hash_bytes() as u32, MIN_MATCH),
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

        let input_chars = input.cur_chars(offset as i32);
        let mut best_len = prev_len;
        let mut best_match: Option<PreflateTokenReference> = None;
        let mut first = true;

        for dist in self.hash.iterate(input, offset) {
            // first entry gets a special treatment to make sure it doesn't exceed
            // the limits we calculated for the first hop
            if first {
                first = false;
                if dist > cur_max_dist_hop0 {
                    return MatchResult::DistanceLargerThanHop0(dist, cur_max_dist_hop0);
                }
            } else {
                if dist > cur_max_dist_hop1_plus {
                    break;
                }
            }

            let match_start = input.cur_chars(offset as i32 - dist as i32);

            let match_length = Self::prefix_compare(match_start, input_chars, best_len, max_len);
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

    /// Tries to find the match by continuing on the hash chain, returns how many hops we went
    /// or none if it wasn't found
    fn calculate_hops(
        &self,
        target_reference: &PreflateTokenReference,
        input: &PreflateInput,
    ) -> anyhow::Result<u32> {
        let max_len = std::cmp::min(input.remaining(), MAX_MATCH);

        if max_len < target_reference.len() {
            return Err(anyhow::anyhow!("max_len < target_reference.len()"));
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
                Self::prefix_compare(match_pos, input.cur_chars(0), best_len - 1, best_len);

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

        Err(anyhow::anyhow!("no match found"))
    }

    /// Does the inverse of calculate_hops, where we start from the predicted token and
    /// get the new distance based on the number of hops
    fn hop_match(&self, len: u32, hops: u32, input: &PreflateInput) -> anyhow::Result<u32> {
        let max_len = std::cmp::min(input.remaining(), MAX_MATCH);
        if max_len < len {
            return Err(anyhow::anyhow!("not enough data left to match"));
        }

        let cur_max_dist = std::cmp::min(input.pos(), self.window_bytes);
        let mut current_hop = 0;

        for dist in self.hash.iterate(input, 0) {
            if dist > cur_max_dist {
                break;
            }

            let match_length = Self::prefix_compare(
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

        Err(anyhow::anyhow!("no match found"))
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

    fn update_hash_with_policy<const MAINTAIN_DEPTH: bool>(
        &mut self,
        length: u32,
        input: &PreflateInput,
        add_policy: DictionaryAddPolicy,
    ) {
        debug_assert!(length <= MAX_UPDATE_HASH_BATCH);

        match add_policy {
            DictionaryAddPolicy::AddAll => {
                self.hash
                    .update_hash::<MAINTAIN_DEPTH, UPDATE_MODE_ALL>(length, input);
            }
            DictionaryAddPolicy::AddFirst(limit) => {
                if length > limit.into() {
                    self.hash
                        .update_hash::<MAINTAIN_DEPTH, UPDATE_MODE_FIRST>(length, input);
                } else {
                    self.hash
                        .update_hash::<MAINTAIN_DEPTH, UPDATE_MODE_ALL>(length, input);
                }
            }
            DictionaryAddPolicy::AddFirstAndLast(limit) => {
                if length > limit.into() {
                    self.hash
                        .update_hash::<MAINTAIN_DEPTH, UPDATE_MODE_FIRST_AND_LAST>(length, input);
                } else {
                    self.hash
                        .update_hash::<MAINTAIN_DEPTH, UPDATE_MODE_ALL>(length, input);
                }
            }
            DictionaryAddPolicy::AddFirstExcept4kBoundary => {
                if length > 1 || (input.pos() % 4096) < 4093 {
                    self.hash
                        .update_hash::<MAINTAIN_DEPTH, UPDATE_MODE_FIRST>(length, input);
                }
            }
        }
    }

    fn prefix_compare(s1: &[u8], s2: &[u8], best_len: u32, max_len: u32) -> u32 {
        assert!(max_len >= 3 && s1.len() >= max_len as usize && s2.len() >= max_len as usize);

        if s1[best_len as usize] != s2[best_len as usize] {
            return 0;
        }
        if s1[0] != s2[0] || s1[1] != s2[1] || s1[2] != s2[2] {
            return 0;
        }

        let mut match_len = 3; // Initialize with the length of the fixed prefix
        for i in 3..max_len {
            if s1[i as usize] != s2[i as usize] {
                break;
            }
            match_len = i + 1;
        }

        match_len
    }
}
