/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::hash_chain::{HashChain, ZlibRotatingHash};
use crate::preflate_constants;
use crate::preflate_parse_config::{FAST_PREFLATE_PARSER_SETTINGS, SLOW_PREFLATE_PARSER_SETTINGS};
use crate::preflate_token::{BlockType, PreflateToken, PreflateTokenBlock, PreflateTokenReference};

#[derive(Default)]
pub struct CompLevelInfo {
    pub zlib_compatible: bool,
    pub reference_count: u32,
    pub unfound_references: u32,
    pub max_chain_depth: u32,
    pub match_to_start: bool,
    pub very_far_matches: bool,
    pub far_len_3_matches: bool,
    pub hash_mask: u16,
    pub hash_shift: u32,
    pub fast_compressor: bool,
    pub good_length: u32,
    pub max_lazy: u32,
    pub nice_length: u32,
    pub max_chain: u32,
}

struct CandidateInfo<'a> {
    hash_mask: u16,
    hash_shift: u32,
    skip_length: u32,
    max_chain_found: u32,
    hash_chain: HashChain<'a, ZlibRotatingHash>,
}

struct CompLevelEstimatorState<'a> {
    slow_hash: HashChain<'a, ZlibRotatingHash>,

    // fast compressor candidates, depending on the hash shift and mask
    // and what length of matches we should skip adding to the hash table.
    // As we look at the data, we remove candidates that have impossible
    // matches, and at the end we pick the best candidate.
    fast_candidates: Vec<Box<CandidateInfo<'a>>>,

    blocks: &'a Vec<PreflateTokenBlock>,
    wsize: u16,
    reference_count: u32,
    unfound_references: u32,
    slow_max_chain_depth: u32,
    match_to_start: bool,

    longest_dist_at_hop_0: u32,
    longest_dist_at_hop_1_plus: u32,
    longest_len_3_dist: u32,
}

impl<'a> CompLevelEstimatorState<'a> {
    pub fn new(
        wbits: u32,
        mem_level: u32,
        plain_text: &'a [u8],
        blocks: &'a Vec<PreflateTokenBlock>,
    ) -> Self {
        let hash_bits = mem_level + 7;
        let mem_hash_shift = (hash_bits + 2) / 3;
        let mem_hash_mask = ((1u32 << hash_bits) - 1) as u16;

        let mut hashparameters = vec![(mem_hash_shift, mem_hash_mask)];
        if mem_hash_shift != 5 || mem_hash_mask != 32726 {
            hashparameters.push((5, 32767));
        }

        let mut candidates = Vec::new();
        for config in &FAST_PREFLATE_PARSER_SETTINGS {
            for &(hash_shift, hash_mask) in hashparameters.iter() {
                candidates.push(Box::new(CandidateInfo {
                    skip_length: config.max_lazy,
                    hash_mask,
                    hash_shift,
                    max_chain_found: 0,
                    hash_chain: HashChain::<'a>::new(plain_text, hash_shift, hash_mask),
                }));
            }
        }

        CompLevelEstimatorState::<'a> {
            slow_hash: HashChain::<'a>::new(plain_text, 5, 32767),
            fast_candidates: candidates,
            blocks,
            wsize: 1 << wbits,
            reference_count: 0,
            unfound_references: 0,
            slow_max_chain_depth: 0,
            match_to_start: false,
            longest_dist_at_hop_0: 0,
            longest_dist_at_hop_1_plus: 0,
            longest_len_3_dist: 0,
        }
    }

    fn update_hash(&mut self, len: u32) {
        for i in &mut self.fast_candidates {
            i.hash_chain.update_hash::<true>(len);
        }

        self.slow_hash.update_hash::<true>(len);
    }

    pub fn update_or_skip_hash(&mut self, len: u32) {
        for c in &mut self.fast_candidates {
            Self::update_or_skip_single_fast_hash(&mut c.hash_chain, len, c.skip_length);
        }

        self.slow_hash.update_hash::<true>(len);
    }

    fn check_match(&mut self, token: &PreflateTokenReference) {
        let hash_head = self.slow_hash.cur_hash();

        self.reference_count += 1;

        if self.slow_hash.input().pos() < token.dist() {
            self.unfound_references += 1;
            return;
        }

        let window_size = self.window_size();

        self.fast_candidates.retain_mut(|c| {
            let mdepth = c.hash_chain.match_depth(hash_head, token, window_size);

            // remove element if the match was impossible due to matching the
            // content of references in fast mode, where we only add the beginning
            // of each reference to the hash table, not every subsequent byte.
            if mdepth != 0xffff {
                c.max_chain_found = std::cmp::max(c.max_chain_found, mdepth);
                true
            } else {
                false
            }
        });

        let mdepth = self
            .slow_hash
            .match_depth(hash_head, token, self.window_size());
        if mdepth >= 0x8001 {
            self.unfound_references += 1;
        } else {
            self.slow_max_chain_depth = std::cmp::max(self.slow_max_chain_depth, mdepth);
        }

        if token.dist() == self.slow_hash.input().pos() {
            self.match_to_start = true;
        }

        if mdepth == 0 {
            self.longest_dist_at_hop_0 = std::cmp::max(self.longest_dist_at_hop_0, token.dist());
        } else {
            self.longest_dist_at_hop_1_plus =
                std::cmp::max(self.longest_dist_at_hop_1_plus, token.dist());
        }

        if token.len() == 3 {
            self.longest_len_3_dist = std::cmp::max(self.longest_len_3_dist, token.dist());
        }
    }

    fn check_dump(&mut self) {
        for (_i, b) in self.blocks.iter().enumerate() {
            if b.block_type == BlockType::Stored {
                self.update_hash(b.uncompressed_len);
                continue;
            }
            for (_j, t) in b.tokens.iter().enumerate() {
                match t {
                    PreflateToken::Literal => {
                        self.update_hash(1);
                    }
                    PreflateToken::Reference(r) => {
                        self.check_match(r);
                        self.update_or_skip_hash(r.len());
                    }
                }
            }
        }
    }

    fn recommend(&mut self) -> CompLevelInfo {
        let mut hash_mask = 32767;
        let mut hash_shift = 5;
        let mut fast_compressor = false;

        let mut good_length = 32;
        let mut max_lazy = 258;
        let mut nice_length = 258;
        let mut max_chain = 4096;

        if !self.fast_candidates.is_empty() {
            let candidate = self
                .fast_candidates
                .iter()
                .min_by(|&a, &b| a.max_chain_found.cmp(&b.max_chain_found))
                .unwrap();

            hash_mask = candidate.hash_mask;
            hash_shift = candidate.hash_shift;
            fast_compressor = true;
            max_chain = candidate.max_chain_found;
            max_lazy = candidate.skip_length;

            for config in &FAST_PREFLATE_PARSER_SETTINGS {
                if candidate.max_chain_found <= config.max_chain
                    && candidate.skip_length <= config.max_lazy
                {
                    good_length = config.good_length;
                    max_lazy = config.max_lazy;
                    nice_length = config.nice_length;
                    max_chain = config.max_chain;
                    break;
                }
            }
        } else {
            for config in &SLOW_PREFLATE_PARSER_SETTINGS {
                if self.slow_max_chain_depth <= config.max_chain {
                    good_length = config.good_length;
                    max_lazy = config.max_lazy;
                    nice_length = config.nice_length;
                    max_chain = config.max_chain;
                    break;
                }
            }
        }

        let very_far_matches = self.longest_dist_at_hop_0
            > self.window_size() - preflate_constants::MIN_LOOKAHEAD
            || self.longest_dist_at_hop_1_plus
                >= self.window_size() - preflate_constants::MIN_LOOKAHEAD;

        let far_len_3_matches = self.longest_len_3_dist > 4096;

        CompLevelInfo {
            reference_count: self.reference_count,
            unfound_references: self.unfound_references,
            max_chain_depth: self.slow_max_chain_depth,
            match_to_start: self.match_to_start,
            very_far_matches,
            far_len_3_matches,
            hash_mask,
            hash_shift,
            fast_compressor,
            good_length,
            max_lazy,
            nice_length,
            max_chain,
            zlib_compatible: !self.match_to_start
                && !very_far_matches
                && (far_len_3_matches || fast_compressor),
        }
    }

    fn update_or_skip_single_fast_hash(
        hash: &mut HashChain<ZlibRotatingHash>,
        len: u32,
        skip_length: u32,
    ) {
        if len <= skip_length {
            hash.update_hash::<true>(len);
        } else {
            hash.skip_hash::<true>(len);
        }
    }

    fn window_size(&self) -> u32 {
        self.wsize.into()
    }
}

pub fn estimate_preflate_comp_level(
    wbits: u32,
    mem_level: u32,
    plain_text: &[u8],
    blocks: &Vec<PreflateTokenBlock>,
) -> CompLevelInfo {
    let mut state = CompLevelEstimatorState::new(wbits, mem_level, plain_text, blocks);
    state.check_dump();
    state.recommend()
}
