/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::hash_chain::{HashChain, RotatingHash};
use crate::preflate_constants;
use crate::preflate_parse_config::{
    PreflateParserConfig, FAST_PREFLATE_PARSER_SETTINGS, SLOW_PREFLATE_PARSER_SETTINGS,
};
use crate::preflate_token::{BlockType, PreflateToken, PreflateTokenBlock, PreflateTokenReference};

#[derive(Default)]
pub struct CompLevelInfo {
    pub possible_compression_levels: u32,
    pub recommended_compression_level: u32,
    pub zlib_compatible: bool,
    pub reference_count: u32,
    pub unfound_references: u32,
    pub max_chain_depth: u32,
    pub longest_len_3_dist: u32,
    pub longest_dist_at_hop_0: u32,
    pub longest_dist_at_hop_1_plus: u32,
    pub match_to_start: bool,
    pub very_far_matches: bool,
    pub far_len_3_matches: bool,
}
struct CompLevelEstimatorState<'a> {
    slow_hash: HashChain<'a>,
    fast_l1_hash: HashChain<'a>,
    fast_l2_hash: HashChain<'a>,
    fast_l3_hash: HashChain<'a>,
    blocks: &'a Vec<PreflateTokenBlock>,
    info: CompLevelInfo,
    wsize: u16,
}

impl<'a> CompLevelEstimatorState<'a> {
    pub fn new(
        wbits: u32,
        mbits: u32,
        plain_text: &'a [u8],
        blocks: &'a Vec<PreflateTokenBlock>,
    ) -> Self {
        CompLevelEstimatorState::<'a> {
            slow_hash: HashChain::<'a>::new(plain_text, mbits),
            fast_l1_hash: HashChain::<'a>::new(plain_text, mbits),
            fast_l2_hash: HashChain::<'a>::new(plain_text, mbits),
            fast_l3_hash: HashChain::<'a>::new(plain_text, mbits),
            blocks,
            info: CompLevelInfo {
                possible_compression_levels: 0b_111111110,
                ..CompLevelInfo::default()
            },
            wsize: 1 << wbits,
        }
    }

    fn update_hash(&mut self, len: u32) {
        if self.info.possible_compression_levels & (1 << 1) != 0 {
            self.fast_l1_hash.update_hash(len);
        }
        if self.info.possible_compression_levels & (1 << 2) != 0 {
            self.fast_l2_hash.update_hash(len);
        }
        if self.info.possible_compression_levels & (1 << 3) != 0 {
            self.fast_l3_hash.update_hash(len);
        }
        self.slow_hash.update_hash(len);
    }

    pub fn update_or_skip_hash(&mut self, len: u32) {
        if self.info.possible_compression_levels & (1 << 1) != 0 {
            Self::update_or_skip_single_fast_hash(
                &mut self.fast_l1_hash,
                len,
                &FAST_PREFLATE_PARSER_SETTINGS[0],
            );
        }
        if self.info.possible_compression_levels & (1 << 2) != 0 {
            Self::update_or_skip_single_fast_hash(
                &mut self.fast_l2_hash,
                len,
                &FAST_PREFLATE_PARSER_SETTINGS[1],
            );
        }
        if self.info.possible_compression_levels & (1 << 3) != 0 {
            Self::update_or_skip_single_fast_hash(
                &mut self.fast_l3_hash,
                len,
                &FAST_PREFLATE_PARSER_SETTINGS[2],
            );
        }
        self.slow_hash.update_hash(len);
    }

    fn check_match(&mut self, token: &PreflateTokenReference) {
        let hash_head = self.slow_hash.cur_hash();

        if self.slow_hash.input().pos() >= token.dist() {
            if self.info.possible_compression_levels & (1 << 1) != 0
                && !Self::check_match_single_fast_hash(
                    token,
                    &self.fast_l1_hash,
                    &FAST_PREFLATE_PARSER_SETTINGS[0],
                    hash_head,
                    self.window_size(),
                )
            {
                self.info.possible_compression_levels &= !(1 << 1);
            }
            if self.info.possible_compression_levels & (1 << 2) != 0
                && !Self::check_match_single_fast_hash(
                    token,
                    &self.fast_l2_hash,
                    &FAST_PREFLATE_PARSER_SETTINGS[1],
                    hash_head,
                    self.window_size(),
                )
            {
                self.info.possible_compression_levels &= !(1 << 2);
            }
            if self.info.possible_compression_levels & (1 << 3) != 0
                && !Self::check_match_single_fast_hash(
                    token,
                    &self.fast_l3_hash,
                    &FAST_PREFLATE_PARSER_SETTINGS[2],
                    hash_head,
                    self.window_size(),
                )
            {
                self.info.possible_compression_levels &= !(1 << 3);
            }
        }

        if self.slow_hash.input().pos() >= token.dist() {
            self.info.reference_count += 1;

            let mdepth = self
                .slow_hash
                .match_depth(hash_head, token, self.window_size());
            if mdepth >= 0x8001 {
                self.info.unfound_references += 1;
            } else {
                self.info.max_chain_depth = std::cmp::max(self.info.max_chain_depth, mdepth);
            }

            if token.dist() == self.slow_hash.input().pos() {
                self.info.match_to_start = true;
            }

            if mdepth == 0 {
                self.info.longest_dist_at_hop_0 =
                    std::cmp::max(self.info.longest_dist_at_hop_0, token.dist());
            } else {
                self.info.longest_dist_at_hop_1_plus =
                    std::cmp::max(self.info.longest_dist_at_hop_1_plus, token.dist());
            }

            if token.len() == 3 {
                self.info.longest_len_3_dist =
                    std::cmp::max(self.info.longest_len_3_dist, token.dist());
            }

            if self.info.possible_compression_levels & ((1 << 10) - (1 << 4)) != 0 {
                for i in 0..6 {
                    if self.info.possible_compression_levels & (1 << (4 + i)) != 0 {
                        let config = &SLOW_PREFLATE_PARSER_SETTINGS[i];
                        if mdepth > config.max_chain {
                            self.info.possible_compression_levels &= !(1 << (4 + i));
                        }
                    }
                }
            }
        }
    }

    fn check_dump(&mut self, early_out: bool) {
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
                if early_out
                    && (self.info.possible_compression_levels
                        & (self.info.possible_compression_levels - 1))
                        == 0
                {
                    return;
                }
            }
        }
    }

    fn recommend(&mut self) {
        self.info.recommended_compression_level = 9;
        self.info.very_far_matches = self.info.longest_dist_at_hop_0
            > self.window_size() - preflate_constants::MIN_LOOKAHEAD
            || self.info.longest_dist_at_hop_1_plus
                >= self.window_size() - preflate_constants::MIN_LOOKAHEAD;
        self.info.far_len_3_matches = self.info.longest_len_3_dist > 4096;

        self.info.zlib_compatible = self.info.possible_compression_levels > 1
            && !self.info.match_to_start
            && !self.info.very_far_matches
            && (!self.info.far_len_3_matches || (self.info.possible_compression_levels & 0xe) != 0);
        if self.info.unfound_references != 0 {
            return;
        }

        if self.info.zlib_compatible && self.info.possible_compression_levels > 1 {
            let mut l = self.info.possible_compression_levels >> 1;
            self.info.recommended_compression_level = 1;
            while (l & 1) == 0 {
                self.info.recommended_compression_level += 1;
                l >>= 1;
            }
            return;
        }
        for i in 0..6 {
            let config = &SLOW_PREFLATE_PARSER_SETTINGS[i];
            if self.info.max_chain_depth <= config.max_chain {
                self.info.recommended_compression_level = 4 + i as u32;
                return;
            }
        }
    }

    fn update_or_skip_single_fast_hash(
        hash: &mut HashChain,
        len: u32,
        config: &PreflateParserConfig,
    ) {
        if len <= config.max_lazy {
            hash.update_hash(len);
        } else {
            hash.skip_hash(len);
        }
    }

    fn check_match_single_fast_hash(
        token: &PreflateTokenReference,
        hash: &HashChain,
        config: &PreflateParserConfig,
        hash_head: RotatingHash,
        window_size: u32,
    ) -> bool {
        let mdepth = hash.match_depth(hash_head, token, window_size);
        if mdepth > config.max_chain {
            return false;
        }
        true
    }

    fn window_size(&self) -> u32 {
        self.wsize.into()
    }
}

pub fn estimate_preflate_comp_level(
    wbits: u32,
    mbits: u32,
    plain_text: &[u8],
    blocks: &Vec<PreflateTokenBlock>,
    early_out: bool,
) -> CompLevelInfo {
    let mut state = CompLevelEstimatorState::new(wbits, mbits, plain_text, blocks);
    state.check_dump(early_out);
    state.recommend();
    state.info
}
