/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

/// This module is design to detect the appropriate overall parameters for the preflate compressor.
/// Getting the parameters correct means that the resulting diff between the deflate stream
/// and the predicted deflate stream will be as small as possible.
use crate::{
    deflate::deflate_constants,
    deflate::deflate_token::{DeflateToken, DeflateTokenBlock, DeflateTokenReference},
    hash_algorithm::HashAlgorithm,
    preflate_error::{err_exit_code, ExitCode, Result},
    preflate_input::PreflateInput,
};

use super::{
    add_policy_estimator::DictionaryAddPolicy,
    depth_estimator::{new_depth_estimator, HashTableDepthEstimator},
    preflate_parse_config::{
        MatchingType, SLOW_PREFLATE_PARSER_SETTINGS, ZLIB_PREFLATE_PARSER_SETTINGS,
    },
};

#[derive(Default)]
pub struct CompLevelInfo {
    pub zlib_compatible: bool,
    pub reference_count: u32,
    pub unfound_references: u32,
    pub matches_to_start_detected: bool,
    pub very_far_matches_detected: bool,
    pub max_dist_3_matches: u32,
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

    fn match_depth(&mut self, token: DeflateTokenReference, input: &PreflateInput) -> bool {
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

pub fn estimate_preflate_comp_level(
    wbits: u32,
    mem_level: u32,
    min_len: u32,
    plain_text: &[u8],
    add_policy: DictionaryAddPolicy,
    blocks: &Vec<DeflateTokenBlock>,
) -> Result<CompLevelInfo> {
    fn update_candidate_hashes(
        length: u32,
        candidates: &mut Vec<Box<CandidateInfo>>,
        add_policy: DictionaryAddPolicy,
        input: &mut PreflateInput,
    ) {
        for i in candidates {
            i.depth_estimator.update_hash(add_policy, &input, length);
        }

        input.advance(length);
    }

    let hash_bits = mem_level + 7;
    let mem_hash_shift = (hash_bits + 2) / 3;
    let mem_hash_mask = ((1u32 << hash_bits) - 1) as u16;
    let wsize = 1 << wbits;

    let mut input = PreflateInput::new(plain_text);

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

    let mut reference_count = 0;
    let mut unfound_references = 0;
    let mut matches_to_start_detected = false;
    let mut max_dist_3_matches = 0;

    for (_i, b) in blocks.iter().enumerate() {
        match b {
            DeflateTokenBlock::Stored { uncompressed, .. } => {
                for _i in 0..uncompressed.len() {
                    update_candidate_hashes(1, &mut candidates, add_policy, &mut input);
                }
            }
            DeflateTokenBlock::Huffman { tokens, .. } => {
                for (_j, t) in tokens.iter().enumerate() {
                    match t {
                        DeflateToken::Literal(_) => {
                            update_candidate_hashes(1, &mut candidates, add_policy, &mut input);
                        }
                        &DeflateToken::Reference(token) => {
                            reference_count += 1;

                            if input.pos() < token.dist() || candidates.is_empty() {
                                unfound_references += 1;
                            }

                            candidates.retain_mut(|c| c.match_depth(token, &input));

                            if token.dist() == input.pos() {
                                // zlib doesn't match to the very first byte in order to reserve
                                // 0 as a sentinel for end-of-hashchain
                                matches_to_start_detected = true;
                            }

                            if token.len() == 3 {
                                max_dist_3_matches =
                                    std::cmp::max(max_dist_3_matches, token.dist());
                            }

                            update_candidate_hashes(
                                token.len(),
                                &mut candidates,
                                add_policy,
                                &mut input,
                            );
                        }
                    }
                }
            }
        }
    }

    if candidates.is_empty() {
        return err_exit_code(ExitCode::NoCompressionCandidates, "no candidates found");
    }

    let candidate = candidates
        .iter()
        .min_by(|&a, &b| a.max_chain_found().cmp(&b.max_chain_found()))
        .unwrap();

    let mut match_type = MatchingType::Greedy;
    let mut nice_length = 258;

    let max_chain = candidate.max_chain_found() + 1;
    let hash_algorithm = candidate.hash_algorithm();
    let longest_dist_at_hop_0 = candidate.longest_dist_at_hop_0;
    let longest_dist_at_hop_1_plus = candidate.longest_dist_at_hop_1_plus;

    match add_policy {
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

    let very_far_matches_detected = longest_dist_at_hop_0
        > wsize - deflate_constants::MIN_LOOKAHEAD
        || longest_dist_at_hop_1_plus >= wsize - deflate_constants::MIN_LOOKAHEAD;

    Ok(CompLevelInfo {
        reference_count,
        unfound_references,
        matches_to_start_detected,
        very_far_matches_detected,
        max_dist_3_matches,
        match_type,
        nice_length,
        max_chain,
        hash_algorithm,
        zlib_compatible: !matches_to_start_detected
            && !very_far_matches_detected
            && (max_dist_3_matches < 4096 || add_policy != DictionaryAddPolicy::AddAll),
    })
}
