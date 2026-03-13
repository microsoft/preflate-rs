/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

/// This module is design to detect the appropriate overall parameters for the preflate compressor.
/// Getting the parameters correct means that the resulting diff between the deflate stream
/// and the predicted deflate stream will be as small as possible.
use crate::{
    deflate::deflate_reader::DeflateContents,
    hash_algorithm::HashAlgorithm,
    preflate_error::{ExitCode, Result, err_exit_code},
    preflate_input::PlainText,
};

use super::{
    add_policy_estimator::DictionaryAddPolicy,
    depth_estimator::{HashTableDepthEstimator, new_depth_estimator, run_depth_candidates},
    preflate_parse_config::{
        MatchingType, SLOW_PREFLATE_PARSER_SETTINGS, ZLIB_PREFLATE_PARSER_SETTINGS,
    },
};

#[derive(Default)]
pub struct CompLevelInfo {
    pub very_far_matches_detected: bool,
    pub hash_algorithm: HashAlgorithm,
    pub match_type: MatchingType,
    pub nice_length: u32,
    pub max_chain: u32,
}

pub fn estimate_preflate_comp_level(
    wbits: u32,
    mem_level: u32,
    min_len: u32,
    deflate_contents: &DeflateContents,
    plain_text: &PlainText,
    add_policy: DictionaryAddPolicy,
) -> Result<CompLevelInfo> {
    let hash_bits = mem_level + 7;
    let mem_hash_shift = (hash_bits + 2) / 3;
    let mem_hash_mask = ((1u32 << hash_bits) - 1) as u16;
    let wsize = 1 << wbits;

    // Build the candidate list in priority order (most common first).
    // MiniZFast is last because it never self-eliminates during run_depth_candidates
    // and must be treated as a final fallback rather than an early winner.
    // Candidates are tried one at a time so we only allocate what we need.
    let mut algorithms: Vec<HashAlgorithm> = Vec::new();
    if min_len == 3 {
        algorithms.push(HashAlgorithm::Zlib {
            hash_mask: 32767,
            hash_shift: 5,
        });
        algorithms.push(HashAlgorithm::Zlib {
            hash_mask: 2047,
            hash_shift: 4,
        });
        // mem-level-derived variant; skip if identical to an already-queued algorithm
        let mem_algo = HashAlgorithm::Zlib {
            hash_mask: mem_hash_mask,
            hash_shift: mem_hash_shift,
        };
        if !algorithms.contains(&mem_algo) {
            algorithms.push(mem_algo);
        }
        algorithms.push(HashAlgorithm::Libdeflate4);
        algorithms.push(HashAlgorithm::RandomVector);
        algorithms.push(HashAlgorithm::MiniZFast);
    } else {
        algorithms.push(HashAlgorithm::Libdeflate4Fast);
        algorithms.push(HashAlgorithm::ZlibNG);
        algorithms.push(HashAlgorithm::Crc32cHash);
    }

    // Try each algorithm in turn, allocating only one estimator at a time.
    // On success the estimator is consumed immediately; on failure it is dropped
    // before the next one is allocated, keeping peak memory to one candidate.
    for algo in algorithms {
        let mut candidates: Vec<Box<dyn HashTableDepthEstimator>> =
            vec![new_depth_estimator(algo)];

        run_depth_candidates(add_policy, deflate_contents, plain_text, &mut candidates);

        let candidate = match candidates.into_iter().next() {
            Some(c) if c.max_chain_found() <= 4096 => c,
            _ => continue,
        };

        let mut match_type = MatchingType::Greedy;
        let mut nice_length = 258;
        let max_chain = candidate.max_chain_found() + 1;

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

        return Ok(CompLevelInfo {
            very_far_matches_detected: candidate.very_far_matches_detected(wsize),
            match_type,
            nice_length,
            max_chain,
            hash_algorithm: candidate.hash_algorithm(),
        });
    }

    err_exit_code(ExitCode::NoCompressionCandidates, "no candidates found")
}
