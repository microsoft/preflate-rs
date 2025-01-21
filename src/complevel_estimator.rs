/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

/// This module is design to detect the appropriate overall parameters for the preflate compressor.
/// Getting the parameters correct means that the resulting diff between the deflate stream
/// and the predicted deflate stream will be as small as possible.
use crate::{
    add_policy_estimator::DictionaryAddPolicy,
    depth_estimator::{new_depth_estimator, HashTableDepthEstimator},
    hash_algorithm::HashAlgorithm,
    preflate_constants,
    preflate_error::{err_exit_code, ExitCode, Result},
    preflate_input::PreflateInput,
    preflate_parse_config::{
        MatchingType, SLOW_PREFLATE_PARSER_SETTINGS, ZLIB_PREFLATE_PARSER_SETTINGS,
    },
    preflate_token::{PreflateToken, PreflateTokenBlock, PreflateTokenReference},
};

#[derive(Default)]
pub struct CompLevelInfo {
    pub zlib_compatible: bool,
    pub reference_count: u32,
    pub unfound_references: u32,
    pub matches_to_start_detected: bool,
    pub very_far_matches_detected: bool,
    pub max_dist_3_matches: u16,
    pub min_len: u32,
    pub add_policy: DictionaryAddPolicy,
    pub hash_algorithm: HashAlgorithm,
    pub match_type: MatchingType,
    pub nice_length: u32,
    pub max_chain: u32,
}

struct CandidateInfo {
    hash_algorithm: HashAlgorithm,
    depth_estimator: Box<dyn HashTableDepthEstimator>,

    longest_dist_at_hop_0: u32,
    longest_dist_at_hop_1_plus: u32,
    max_chain_found: u32,
}

impl CandidateInfo {
    fn new(hash_algorithm: HashAlgorithm) -> Self {
        Self {
            hash_algorithm,
            depth_estimator: new_depth_estimator(hash_algorithm),
            longest_dist_at_hop_0: 0,
            longest_dist_at_hop_1_plus: 0,
            max_chain_found: 0,
        }
    }

    fn match_depth(&mut self, token: PreflateTokenReference, input: &PreflateInput) -> bool {
        let mdepth = self.depth_estimator.match_depth(token, input);

        // remove element if the match was impossible due to matching the
        // the hash depth or because in fast mode we can't match partial words
        // added to the dictionary.
        if mdepth < 8196 {
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
            }

            if self.hash_algorithm() == HashAlgorithm::Libdeflate4 {
                println!("libflate4");
            }

            println!(
                "removed candidate sl={:?}, mask={}, pos={}, token={:?} hash={:?}, max_chain={}",
                self.skip_length,
                self.hash_mask,
                input.pos(),
                token,
                self.hash_algorithm(),
                self.max_chain_found,
            );*/
            false
        }
    }

    fn max_chain_found(&self) -> u32 {
        self.max_chain_found
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash_algorithm
    }
}

struct CompLevelEstimatorState<'a> {
    input: PreflateInput<'a>,

    /// candidates for checking for which hash algorithm to use
    candidates: Vec<Box<CandidateInfo>>,

    add_policy: DictionaryAddPolicy,

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
        add_policy: DictionaryAddPolicy,
        min_len: u32,
        blocks: &'a Vec<PreflateTokenBlock>,
    ) -> Self {
        let hash_bits = mem_level + 7;
        let mem_hash_shift = (hash_bits + 2) / 3;
        let mem_hash_mask = ((1u32 << hash_bits) - 1) as u16;

        let input = PreflateInput::new(plain_text);

        let mut candidates: Vec<Box<CandidateInfo>> = Vec::new();

        if min_len == 3 {
            let mut hashparameters = vec![(5, 0x7fff), (4, 2047), (4, 4095)];

            if !hashparameters
                .iter()
                .any(|&(a, b)| a == mem_hash_shift && b == mem_hash_mask)
            {
                hashparameters.push((mem_hash_shift, mem_hash_mask));
            }

            candidates.push(Box::new(CandidateInfo::new(HashAlgorithm::MiniZFast)));

            for (hash_shift, hash_mask) in [(5, 32767), (4, 2047)] {
                candidates.push(Box::new(CandidateInfo::new(HashAlgorithm::Zlib {
                    hash_mask,
                    hash_shift,
                })));
            }

            // LibFlate4 candidate
            candidates.push(Box::new(CandidateInfo::new(HashAlgorithm::Libdeflate4)));

            // RandomVector candidate
            candidates.push(Box::new(CandidateInfo::new(HashAlgorithm::RandomVector)));
        } else {
            // Libflate4 fast (only 4 bytes or more)
            candidates.push(Box::new(CandidateInfo::new(HashAlgorithm::Libdeflate4Fast)));

            // ZlibNG candidate
            candidates.push(Box::new(CandidateInfo::new(HashAlgorithm::ZlibNG)));

            // Crc32c candidate
            candidates.push(Box::new(CandidateInfo::new(HashAlgorithm::Crc32cHash)));
        }

        CompLevelEstimatorState {
            input,
            add_policy: add_policy,
            candidates,
            blocks,
            wsize: 1 << wbits,
            reference_count: 0,
            unfound_references: 0,
            match_to_start: false,
            longest_len_3_dist: 0,
            min_len: min_len,
        }
    }

    /// updates all the active candidates with the current hash and advance it
    fn update_candidate_hashes(&mut self, length: u32) {
        for i in &mut self.candidates {
            i.depth_estimator
                .update_hash(self.add_policy, &self.input, length);
        }

        self.input.advance(length);
    }

    fn check_match(&mut self, token: PreflateTokenReference) {
        self.reference_count += 1;

        if self.input.pos() < token.dist() || self.candidates.is_empty() {
            self.unfound_references += 1;
            return;
        }

        self.candidates
            .retain_mut(|c| c.match_depth(token, &self.input));

        if token.dist() == self.input.pos() {
            self.match_to_start = true;
        }

        if token.len() == 3 {
            self.longest_len_3_dist = std::cmp::max(self.longest_len_3_dist, token.dist());
        }
    }

    fn check_dump(&mut self) {
        for (_i, b) in self.blocks.iter().enumerate() {
            match b {
                PreflateTokenBlock::Stored { uncompressed, .. } => {
                    for _i in 0..uncompressed.len() {
                        self.update_candidate_hashes(1);
                    }
                }
                PreflateTokenBlock::Huffman { tokens, .. } => {
                    for (_j, t) in tokens.iter().enumerate() {
                        match t {
                            PreflateToken::Literal(_) => {
                                self.update_candidate_hashes(1);
                            }
                            &PreflateToken::Reference(r) => {
                                self.check_match(r);
                                self.update_candidate_hashes(r.len());
                            }
                        }
                    }
                }
            }
        }
    }

    fn recommend(&mut self) -> Result<CompLevelInfo> {
        if self.candidates.is_empty() {
            return err_exit_code(ExitCode::NoCompressionCandidates, "no candidates found");
        }

        let candidate = self
            .candidates
            .iter()
            .min_by(|&a, &b| a.max_chain_found().cmp(&b.max_chain_found()))
            .unwrap();

        let mut match_type = MatchingType::Greedy;
        let mut nice_length = 258;

        let max_chain = candidate.max_chain_found() + 1;
        let hash_algorithm = candidate.hash_algorithm();
        let longest_dist_at_hop_0 = candidate.longest_dist_at_hop_0;
        let longest_dist_at_hop_1_plus = candidate.longest_dist_at_hop_1_plus;

        match self.add_policy {
            DictionaryAddPolicy::AddFirst(_)
            | DictionaryAddPolicy::AddFirstAndLast(_)
            | DictionaryAddPolicy::AddFirstWith32KBoundary
            | DictionaryAddPolicy::AddFirstExcept4kBoundary => {
                for config in &ZLIB_PREFLATE_PARSER_SETTINGS {
                    if candidate.max_chain_found() < config.max_chain {
                        match_type = config.match_type;
                        nice_length = config.nice_length;
                        break;
                    }
                }
            }
            DictionaryAddPolicy::AddAll => {
                for config in &SLOW_PREFLATE_PARSER_SETTINGS {
                    if candidate.max_chain_found() < config.max_chain {
                        match_type = config.match_type;
                        nice_length = config.nice_length;
                        break;
                    }
                }
            }
        }

        if candidate.max_chain_found() >= 4096 {
            return err_exit_code(
                ExitCode::NoCompressionCandidates,
                format!("max_chain_found too large: {}", candidate.max_chain_found()).as_str(),
            );
        }

        let very_far_matches = longest_dist_at_hop_0
            > self.window_size() - preflate_constants::MIN_LOOKAHEAD
            || longest_dist_at_hop_1_plus >= self.window_size() - preflate_constants::MIN_LOOKAHEAD;

        Ok(CompLevelInfo {
            reference_count: self.reference_count,
            unfound_references: self.unfound_references,
            matches_to_start_detected: self.match_to_start,
            very_far_matches_detected: very_far_matches,
            max_dist_3_matches: self.longest_len_3_dist as u16,
            add_policy: self.add_policy,
            match_type,
            nice_length,
            max_chain,
            min_len: self.min_len,
            hash_algorithm,
            zlib_compatible: !self.match_to_start
                && !very_far_matches
                && (self.longest_len_3_dist < 4096
                    || self.add_policy != DictionaryAddPolicy::AddAll),
        })
    }

    fn window_size(&self) -> u32 {
        self.wsize.into()
    }
}

pub fn estimate_preflate_comp_level(
    wbits: u32,
    mem_level: u32,
    min_len: u32,
    plain_text: &[u8],
    add_policy: DictionaryAddPolicy,
    blocks: &Vec<PreflateTokenBlock>,
) -> Result<CompLevelInfo> {
    let mut state =
        CompLevelEstimatorState::new(wbits, mem_level, plain_text, add_policy, min_len, blocks);
    state.check_dump();
    state.recommend()
}
