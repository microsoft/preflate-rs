/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use crate::hash_algorithm::{HashAlgorithm, LibdeflateRotatingHash, MiniZHash, ZlibRotatingHash};
use crate::hash_chain::HashChain;
use crate::preflate_constants;
use crate::preflate_input::PreflateInput;
use crate::preflate_parse_config::{FAST_PREFLATE_PARSER_SETTINGS, SLOW_PREFLATE_PARSER_SETTINGS};
use crate::preflate_token::{BlockType, PreflateToken, PreflateTokenBlock, PreflateTokenReference};

#[derive(Default)]
pub struct CompLevelInfo {
    pub zlib_compatible: bool,
    pub reference_count: u32,
    pub unfound_references: u32,
    pub match_to_start: bool,
    pub very_far_matches: bool,
    pub max_dist_3_matches: u16,
    pub min_len: u32,
    pub hash_mask: u16,
    pub hash_shift: u32,
    pub fast_compressor: bool,
    pub hash_algorithm: HashAlgorithm,
    pub good_length: u32,
    pub max_lazy: u32,
    pub nice_length: u32,
    pub max_chain: u32,
}

enum HashChainType {
    Zlib(HashChain<ZlibRotatingHash>),
    MiniZ(HashChain<MiniZHash>),
    LibFlate4(HashChain<LibdeflateRotatingHash>),
}

struct CandidateInfo {
    hash_mask: u16,
    hash_shift: u32,
    skip_length: Option<u32>,
    hash_chain: HashChainType,

    longest_dist_at_hop_0: u32,
    longest_dist_at_hop_1_plus: u32,
    max_chain_found: u32,
}

impl CandidateInfo {
    fn invoke_update_hash(&mut self, len: u32, input: &PreflateInput) {
        match self.hash_chain {
            HashChainType::Zlib(ref mut h) => h.update_hash::<true>(len, input),
            HashChainType::MiniZ(ref mut h) => h.update_hash::<true>(len, input),
            HashChainType::LibFlate4(ref mut h) => h.update_hash::<true>(len, input),
        }
    }

    fn invoke_skip_hash(&mut self, len: u32, input: &PreflateInput) {
        match self.hash_chain {
            HashChainType::Zlib(ref mut h) => h.skip_hash::<true>(len, input),
            HashChainType::MiniZ(ref mut h) => h.skip_hash::<true>(len, input),
            HashChainType::LibFlate4(ref mut h) => h.skip_hash::<true>(len, input),
        }
    }

    fn invoke_match_depth(
        &mut self,
        token: &PreflateTokenReference,
        window_size: u32,
        input: &PreflateInput,
    ) -> u32 {
        match self.hash_chain {
            HashChainType::Zlib(ref mut h) => h.match_depth(token, window_size, input),
            HashChainType::MiniZ(ref mut h) => h.match_depth(token, window_size, input),
            HashChainType::LibFlate4(ref mut h) => h.match_depth(token, window_size, input),
        }
    }

    fn match_depth(
        &mut self,
        token: &PreflateTokenReference,
        window_size: u32,
        input: &PreflateInput,
    ) -> bool {
        let mdepth = self.invoke_match_depth(token, window_size, input);

        // remove element if the match was impossible due to matching the
        // content of references in fast mode, where we only add the beginning
        // of each reference to the hash table, not every subsequent byte.
        if mdepth != 0xffff {
            self.max_chain_found = std::cmp::max(self.max_chain_found, mdepth);

            if mdepth == 0 {
                self.longest_dist_at_hop_0 =
                    std::cmp::max(self.longest_dist_at_hop_0, token.dist());
            } else {
                self.longest_dist_at_hop_1_plus =
                    std::cmp::max(self.longest_dist_at_hop_1_plus, token.dist());
            }

            true
        } else {
            /*if input.pos() == 803428 {
                let mdepth = self.invoke_match_depth(token, window_size, input);
            }*/

            println!(
                "removed candidate sl={:?}, mask={}, pos={}, token={:?} hash={:?}, max_chain={}",
                self.skip_length,
                self.hash_mask,
                input.pos(),
                token,
                self.hash_algorithm(),
                self.max_chain_found,
            );
            false
        }
    }

    fn skip_or_update_hash(&mut self, len: u32, input: &PreflateInput) {
        if let Some(skip_length) = self.skip_length {
            if len <= skip_length {
                self.invoke_update_hash(len, input);
            } else {
                self.invoke_skip_hash(len, input);
            }
        } else {
            self.invoke_update_hash(len, input);
        }
    }

    fn max_chain_found(&self) -> u32 {
        self.max_chain_found
    }

    fn hash_mask(&self) -> u16 {
        self.hash_mask
    }

    fn hash_shift(&self) -> u32 {
        self.hash_shift
    }

    fn skip_length(&self) -> Option<u32> {
        self.skip_length
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        match self.hash_chain {
            HashChainType::Zlib(_) => HashAlgorithm::Zlib,
            HashChainType::MiniZ(_) => HashAlgorithm::MiniZFast,
            HashChainType::LibFlate4(_) => HashAlgorithm::Libdeflate4,
        }
    }
}

struct CompLevelEstimatorState<'a> {
    input: PreflateInput<'a>,

    // fast compressor candidates, depending on the hash shift and mask
    // and what length of matches we should skip adding to the hash table.
    // As we look at the data, we remove candidates that have impossible
    // matches, and at the end we pick the best candidate.
    candidates: Vec<Box<CandidateInfo>>,

    blocks: &'a Vec<PreflateTokenBlock>,
    wsize: u16,
    reference_count: u32,
    unfound_references: u32,
    match_to_start: bool,

    longest_len_3_dist: u32,
    min_len: u32,
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

        let mut hashparameters = vec![(5, 0x7fff), (4, 2047), (4, 4097)];

        if !hashparameters
            .iter()
            .any(|&(a, b)| a == mem_hash_shift && b == mem_hash_mask)
        {
            hashparameters.push((mem_hash_shift, mem_hash_mask));
        }

        let input = PreflateInput::new(plain_text);

        let mut candidates: Vec<Box<CandidateInfo>> = Vec::new();

        // add the ZlibRotatingHash candidates
        for config in &FAST_PREFLATE_PARSER_SETTINGS {
            for &(hash_shift, hash_mask) in hashparameters.iter() {
                candidates.push(Box::new(CandidateInfo {
                    skip_length: Some(config.max_lazy),
                    hash_mask,
                    hash_shift,
                    hash_chain: HashChainType::Zlib(HashChain::<ZlibRotatingHash>::new(
                        hash_shift, hash_mask, &input,
                    )),
                    max_chain_found: 0,
                    longest_dist_at_hop_0: 0,
                    longest_dist_at_hop_1_plus: 0,
                }));
            }
        }

        candidates.push(Box::new(CandidateInfo {
            skip_length: Some(2),
            hash_shift: 5,
            hash_mask: 32767,
            hash_chain: HashChainType::MiniZ(HashChain::<MiniZHash>::new(5, 32767, &input)),
            max_chain_found: 0,
            longest_dist_at_hop_0: 0,
            longest_dist_at_hop_1_plus: 0,
        }));

        // slow compressor candidates
        candidates.push(Box::new(CandidateInfo {
            skip_length: None,
            hash_shift: 0,
            hash_mask: 0x7fff,
            hash_chain: HashChainType::LibFlate4(HashChain::<LibdeflateRotatingHash>::new(
                0, 0x7fff, &input,
            )),
            max_chain_found: 0,
            longest_dist_at_hop_0: 0,
            longest_dist_at_hop_1_plus: 0,
        }));

        // slow compressor candidates
        for (hash_shift, hash_mask) in [(5, 32767), (4, 2047)] {
            candidates.push(Box::new(CandidateInfo {
                skip_length: None,
                hash_shift,
                hash_mask,
                hash_chain: HashChainType::Zlib(HashChain::<ZlibRotatingHash>::new(
                    hash_shift, hash_mask, &input,
                )),
                max_chain_found: 0,
                longest_dist_at_hop_0: 0,
                longest_dist_at_hop_1_plus: 0,
            }));
        }

        for (hash_shift, hash_mask) in [(5, 32767)] {
            candidates.push(Box::new(CandidateInfo {
                skip_length: None,
                hash_shift,
                hash_mask,
                hash_chain: HashChainType::Zlib(HashChain::<ZlibRotatingHash>::new(
                    hash_shift, hash_mask, &input,
                )),
                max_chain_found: 0,
                longest_dist_at_hop_0: 0,
                longest_dist_at_hop_1_plus: 0,
            }));
        }

        CompLevelEstimatorState {
            input,
            candidates,
            blocks,
            wsize: 1 << wbits,
            reference_count: 0,
            unfound_references: 0,
            match_to_start: false,
            longest_len_3_dist: 0,
            min_len: 258,
        }
    }

    fn update_hash(&mut self, len: u32) {
        for i in &mut self.candidates {
            i.invoke_update_hash(len, &self.input);
        }

        self.input.advance(len);
    }

    fn update_or_skip_hash(&mut self, len: u32) {
        for c in &mut self.candidates {
            c.skip_or_update_hash(len, &self.input);
        }

        self.input.advance(len);
    }

    fn check_match(&mut self, token: &PreflateTokenReference) {
        self.reference_count += 1;

        if self.input.pos() < token.dist() || self.candidates.is_empty() {
            self.unfound_references += 1;
            return;
        }

        let window_size = self.window_size();

        self.candidates
            .retain_mut(|c| c.match_depth(token, window_size, &self.input));

        if token.dist() == self.input.pos() {
            self.match_to_start = true;
        }

        self.min_len = std::cmp::min(self.min_len, token.len());

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

    fn recommend(&mut self) -> anyhow::Result<CompLevelInfo> {
        if self.candidates.is_empty() {
            return Err(anyhow::anyhow!("no candidates found"));
        }

        let candidate = self
            .candidates
            .iter()
            .min_by(|&a, &b| a.max_chain_found().cmp(&b.max_chain_found()))
            .unwrap();

        let mut good_length = 32;
        let mut max_lazy = 258;
        let mut nice_length = 258;

        let hash_mask = candidate.hash_mask();
        let hash_shift = candidate.hash_shift();
        let max_chain = candidate.max_chain_found() + 1;
        let hash_algorithm = candidate.hash_algorithm();
        let longest_dist_at_hop_0 = candidate.longest_dist_at_hop_0;
        let longest_dist_at_hop_1_plus = candidate.longest_dist_at_hop_1_plus;
        let fast_compressor;

        match candidate.skip_length() {
            Some(skip_length) => {
                max_lazy = skip_length;
                fast_compressor = true;

                for config in &FAST_PREFLATE_PARSER_SETTINGS {
                    if candidate.max_chain_found() < config.max_chain {
                        good_length = config.good_length;
                        nice_length = config.nice_length;
                        break;
                    }
                }
            }
            None => {
                fast_compressor = false;

                for config in &SLOW_PREFLATE_PARSER_SETTINGS {
                    if candidate.max_chain_found() < config.max_chain {
                        good_length = config.good_length;
                        max_lazy = config.max_lazy;
                        nice_length = config.nice_length;
                        break;
                    }
                }
            }
        }

        if candidate.max_chain_found() >= 4096 {
            return Err(anyhow::anyhow!(
                "max_chain_found too large: {}",
                candidate.max_chain_found()
            ));
        }

        let very_far_matches = longest_dist_at_hop_0
            > self.window_size() - preflate_constants::MIN_LOOKAHEAD
            || longest_dist_at_hop_1_plus >= self.window_size() - preflate_constants::MIN_LOOKAHEAD;

        Ok(CompLevelInfo {
            reference_count: self.reference_count,
            unfound_references: self.unfound_references,
            match_to_start: self.match_to_start,
            very_far_matches,
            max_dist_3_matches: self.longest_len_3_dist as u16,
            hash_mask,
            hash_shift,
            fast_compressor,
            good_length,
            max_lazy,
            nice_length,
            max_chain,
            min_len: self.min_len,
            hash_algorithm,
            zlib_compatible: !self.match_to_start
                && !very_far_matches
                && (self.longest_len_3_dist < 4096 || fast_compressor),
        })
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
) -> anyhow::Result<CompLevelInfo> {
    let mut state = CompLevelEstimatorState::new(wbits, mem_level, plain_text, blocks);
    state.check_dump();
    state.recommend()
}
