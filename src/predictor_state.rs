/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::bit_helper::DebugHash;
use crate::hash_algorithm::RotatingHashTrait;
use crate::hash_chain::{DictionaryAddPolicy, HashChain, MAX_UPDATE_HASH_BATCH};
use crate::preflate_constants::{MAX_MATCH, MIN_LOOKAHEAD, MIN_MATCH};
use crate::preflate_input::PreflateInput;
use crate::preflate_parameter_estimator::{PreflateParameters, PreflateStrategy};
use crate::preflate_token::PreflateTokenReference;
use std::cmp;
use std::sync::atomic;

#[derive(Debug, Copy, Clone)]
pub enum MatchResult {
    Success(PreflateTokenReference),
    DistanceLargerThanHop0(u32, u32),
    NoInput,
    NoMoreMatchesFound,
    MaxChainExceeded(u32),
}

#[derive(Default)]
pub struct PreflateRematchInfo {
    pub requested_match_depth: u32,
    pub condensed_hops: u32,
}

pub struct PredictorState<'a, H: RotatingHashTrait> {
    hash: HashChain<H>,
    input: PreflateInput<'a>,
    params: PreflateParameters,
    window_bytes: u32,
    last_chain: atomic::AtomicU32,
}

impl<'a, H: RotatingHashTrait> PredictorState<'a, H> {
    pub fn new(uncompressed: &'a [u8], params: &PreflateParameters) -> Self {
        let input = PreflateInput::new(uncompressed);

        Self {
            hash: HashChain::new(params.hash_shift, params.hash_mask, &input),
            window_bytes: 1 << params.window_bits,
            params: *params,
            input,
            last_chain: atomic::AtomicU32::new(0),
        }
    }

    #[allow(dead_code)]
    pub fn checksum(&self, checksum: &mut DebugHash) {
        self.hash.checksum(checksum);
    }

    pub fn update_hash_with_policy(&mut self, length: u32, add_policy: DictionaryAddPolicy) {
        self.hash
            .update_hash_with_policy::<false>(length, &self.input, add_policy);
        self.input.advance(length);
    }

    pub fn update_hash_batch(&mut self, mut length: u32) {
        while length > 0 {
            let batch_len = cmp::min(length, MAX_UPDATE_HASH_BATCH);

            self.hash.update_hash_with_policy::<false>(
                batch_len,
                &self.input,
                DictionaryAddPolicy::AddAll,
            );
            self.input.advance(batch_len);
            length -= batch_len;
        }
    }

    pub fn current_input_pos(&self) -> u32 {
        self.input.pos()
    }

    pub fn input_cursor(&self) -> &[u8] {
        self.input.cur_chars(0)
    }

    pub fn input_cursor_offset(&self, offset: i32) -> &[u8] {
        self.input.cur_chars(offset)
    }

    pub fn window_size(&self) -> u32 {
        self.window_bytes
    }

    fn total_input_size(&self) -> u32 {
        self.input.size()
    }

    pub fn available_input_size(&self) -> u32 {
        self.input.remaining()
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

    pub fn match_token(&self, prev_len: u32, offset: u32, max_depth: u32) -> MatchResult {
        let start_pos = self.current_input_pos() + offset;
        let max_len = std::cmp::min(self.total_input_size() - start_pos, MAX_MATCH);
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
            cur_max_dist_hop0 = cmp::min(max_dist_to_start, self.window_size());
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
                    let max_dist: u32 = self.window_size() - MIN_LOOKAHEAD + 1;
                    cur_max_dist_hop0 = cmp::min(max_dist_to_start, max_dist);
                    cur_max_dist_hop1_plus = cmp::min(max_dist_to_start, max_dist - 1);
                }
            }
        }

        let nice_len = std::cmp::min(self.params.nice_length, max_len);
        let mut max_chain = max_depth;

        let input = self.input.cur_chars(offset as i32);
        let mut best_len = prev_len;
        let mut best_match: Option<PreflateTokenReference> = None;
        let mut num_chain_matches = 0;
        let mut first = true;

        for dist in self.hash.iterate(&self.input, offset) {
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

            let match_start = self.input.cur_chars(offset as i32 - dist as i32);

            let match_length = Self::prefix_compare(match_start, input, best_len, max_len);
            if match_length > best_len {
                let r = PreflateTokenReference::new(match_length, dist, false);

                if match_length >= nice_len {
                    return MatchResult::Success(r);
                }

                best_len = match_length;
                best_match = Some(r);
            }

            max_chain -= 1;
            num_chain_matches += 1;

            if max_chain == 0 {
                if let Some(r) = best_match {
                    self.last_chain
                        .store(num_chain_matches, atomic::Ordering::Relaxed);
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
    pub fn calculate_hops(&self, target_reference: &PreflateTokenReference) -> anyhow::Result<u32> {
        let max_len = std::cmp::min(self.available_input_size(), MAX_MATCH);

        if max_len < target_reference.len() {
            return Err(anyhow::anyhow!("max_len < target_reference.len()"));
        }

        let max_chain_org = 0xffff; // max hash chain length
        let mut max_chain = max_chain_org; // max hash chain length
        let best_len = target_reference.len();
        let mut hops = 0;

        let cur_max_dist = std::cmp::min(self.current_input_pos(), self.window_size());

        for dist in self.hash.iterate(&self.input, 0) {
            if dist > cur_max_dist {
                break;
            }

            let match_pos = self.input_cursor_offset(-(dist as i32));
            let match_length =
                Self::prefix_compare(match_pos, self.input_cursor(), best_len - 1, best_len);

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
    pub fn hop_match(&self, len: u32, hops: u32) -> anyhow::Result<u32> {
        let max_len = std::cmp::min(self.available_input_size(), MAX_MATCH);
        if max_len < len {
            return Err(anyhow::anyhow!("not enough data left to match"));
        }

        let cur_max_dist = std::cmp::min(self.current_input_pos(), self.window_size());
        let mut current_hop = 0;

        for dist in self.hash.iterate(&self.input, 0) {
            if dist > cur_max_dist {
                break;
            }

            let match_length = Self::prefix_compare(
                self.input_cursor_offset(-(dist as i32)),
                self.input_cursor(),
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
    pub fn verify_hash(&self, _dist: Option<PreflateTokenReference>) {
        //self.hash.verify_hash(dist, &self.input);
    }
}
