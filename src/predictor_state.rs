/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::bit_helper::DebugHash;
use crate::hash_chain::{HashChain, RotatingHash};
use crate::preflate_constants::{MAX_MATCH, MIN_LOOKAHEAD, MIN_MATCH};
use crate::preflate_parameter_estimator::PreflateParameters;
use crate::preflate_token::PreflateTokenReference;
use std::cmp;

#[derive(Debug, Copy, Clone)]
pub enum MatchResult {
    Success(PreflateTokenReference),
    DistanceLargerThanHop0(u32, u32),
    NoInput,
    NoMoreMatchesFound(u32),
    MaxChainExceeded,
}

#[derive(Default)]
pub struct PreflateRematchInfo {
    pub requested_match_depth: u32,
    pub condensed_hops: u32,
}

pub struct PredictorState<'a> {
    hash: HashChain<'a>,
    params: PreflateParameters,
    window_bytes: u32,
}

impl<'a> PredictorState<'a> {
    pub fn new(uncompressed: &'a [u8], params: &PreflateParameters) -> Self {
        Self {
            hash: HashChain::new(uncompressed, params.mem_level),
            window_bytes: 1 << params.window_bits,
            params: *params,
        }
    }

    #[allow(dead_code)]
    pub fn checksum(&self, checksum: &mut DebugHash) {
        self.hash.checksum(checksum);
    }

    pub fn update_running_hash(&mut self, b: u8) {
        self.hash.update_running_hash(b);
    }

    pub fn update_hash(&mut self, pos: u32) {
        self.hash.update_hash(pos);
    }

    pub fn skip_hash(&mut self, pos: u32) {
        self.hash.skip_hash(pos);
    }

    pub fn current_input_pos(&self) -> u32 {
        self.hash.input().pos()
    }

    pub fn input_cursor(&self) -> &[u8] {
        self.hash.input().cur_chars(0)
    }

    pub fn input_cursor_offset(&self, offset: i32) -> &[u8] {
        self.hash.input().cur_chars(offset)
    }

    pub fn window_size(&self) -> u32 {
        self.window_bytes.into()
    }

    fn total_input_size(&self) -> u32 {
        self.hash.input().size()
    }

    pub fn available_input_size(&self) -> u32 {
        self.hash.input().remaining()
    }

    pub fn hash_equal(&self, a: RotatingHash, b: RotatingHash) -> bool {
        self.hash.hash_equal(a, b)
    }

    pub fn calculate_hash(&self) -> RotatingHash {
        self.hash.cur_hash()
    }

    pub fn calculate_hash_next(&self) -> RotatingHash {
        self.hash.cur_plus_1_hash()
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

    pub fn match_token(
        &self,
        hash: RotatingHash,
        prev_len: u32,
        offset: u32,
        max_depth: u32,
    ) -> MatchResult {
        let start_pos = self.current_input_pos() + offset;
        let max_len = std::cmp::min(self.total_input_size() - start_pos, MAX_MATCH as u32);
        if max_len < std::cmp::max(prev_len + 1, MIN_MATCH as u32) {
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
            let max_dist: u32 = (self.window_size() - MIN_LOOKAHEAD).into();
            cur_max_dist_hop0 = cmp::min(max_dist_to_start, max_dist);
            cur_max_dist_hop1_plus = cmp::min(max_dist_to_start, max_dist - 1);
        }

        let mut max_chain;
        let nice_len;
        if max_depth > 0 {
            max_chain = max_depth;
            nice_len = max_len;
        } else {
            max_chain = self.params.max_chain; // max hash chain length
            nice_len = std::cmp::min(self.params.nice_length, max_len);

            if prev_len >= self.params.good_length {
                max_chain >>= 2;
            }
        }

        let mut chain_it = self
            .hash
            .iterate_from_head(hash, start_pos, cur_max_dist_hop1_plus);
        // Handle ZLIB quirk: the very first entry in the hash chain can have a larger
        // distance than all following entries
        if chain_it.dist() > cur_max_dist_hop0 {
            let d = chain_it.dist();
            return MatchResult::DistanceLargerThanHop0(d, cur_max_dist_hop0);
        }

        let mut best_len = prev_len;
        let mut best_match: Option<PreflateTokenReference> = None;
        let input = self.hash.input().cur_chars(offset as i32);
        loop {
            let match_start = self
                .hash
                .input()
                .cur_chars(offset as i32 - chain_it.dist() as i32);

            let match_length = Self::prefix_compare(match_start, input, best_len, max_len);
            if match_length > best_len {
                let r = PreflateTokenReference::new(match_length, chain_it.dist(), false);

                if match_length >= nice_len {
                    return MatchResult::Success(r);
                }

                best_len = match_length;
                best_match = Some(r);
            }

            if !chain_it.next() {
                if let Some(r) = best_match {
                    return MatchResult::Success(r);
                } else {
                    return MatchResult::NoMoreMatchesFound(match_length);
                }
            }

            max_chain -= 1;

            if max_chain == 0 {
                if let Some(r) = best_match {
                    return MatchResult::Success(r);
                } else {
                    return MatchResult::MaxChainExceeded;
                }
            }
        }
    }

    /// Tries to find the match by continuing on the hash chain, returns how many hops we went
    /// or none if it wasn't found
    pub fn calculate_hops(&self, target_reference: &PreflateTokenReference) -> anyhow::Result<u32> {
        let hash = self.hash.cur_hash();

        let max_len = std::cmp::min(self.available_input_size(), MAX_MATCH);

        if max_len < target_reference.len() {
            return Err(anyhow::anyhow!("max_len < target_reference.len()"));
        }

        let max_dist = self.window_size();
        let cur_pos = self.current_input_pos();
        let cur_max_dist = std::cmp::min(cur_pos, max_dist);

        let mut chain_it = self.hash.iterate_from_head(hash, cur_pos, cur_max_dist);
        if !chain_it.valid() {
            return Err(anyhow::anyhow!("no valid chain_it"));
        }

        let max_chain_org = 0xffff; // max hash chain length
        let mut max_chain = max_chain_org; // max hash chain length
        let best_len = target_reference.len();
        let mut hops = 0;

        loop {
            let match_pos = self.input_cursor_offset(-(chain_it.dist() as i32));
            let match_length =
                Self::prefix_compare(match_pos, self.input_cursor(), best_len - 1, best_len);

            if match_length >= best_len {
                hops += 1;
            }

            if chain_it.dist() >= target_reference.dist() {
                if chain_it.dist() == target_reference.dist() {
                    return Ok(hops);
                } else {
                    break;
                }
            }

            if !chain_it.next() || max_chain <= 1 {
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

        let cur_pos = self.current_input_pos();
        let cur_max_dist = std::cmp::min(cur_pos, self.window_size());

        let hash = self.calculate_hash();

        let mut chain_it = self.hash.iterate_from_head(hash, cur_pos, cur_max_dist);
        if !chain_it.valid() {
            return Err(anyhow::anyhow!("no match found"));
        }

        let mut current_hop = 0;

        loop {
            let match_length = Self::prefix_compare(
                self.input_cursor_offset(-(chain_it.dist() as i32)),
                self.input_cursor(),
                len - 1,
                len,
            );

            if match_length >= len {
                current_hop += 1;
                if current_hop == hops {
                    return Ok(chain_it.dist());
                }
            }

            if !chain_it.next() {
                return Err(anyhow::anyhow!("no match found"));
            }
        }
    }
}
