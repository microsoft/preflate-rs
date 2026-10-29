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
    preflate_stream_info::PreflateStreamInfo,
};

#[derive(Default)]
pub struct CompLevelInfo {
    pub very_far_matches_detected: bool,
    pub hash_algorithm: HashAlgorithm,
    pub match_type: MatchingType,
    pub nice_length: u32,
    pub max_chain: u32,
    pub greedy_parser_detected: bool,
}

fn select_depth_candidate<'a>(
    candidates: &'a [Box<dyn HashTableDepthEstimator>],
    add_policy: DictionaryAddPolicy,
    info: &PreflateStreamInfo,
) -> Option<&'a dyn HashTableDepthEstimator> {
    // Miniz shares zlib's hash, but permits length-three distances that rule out
    // normal zlib parsing. A surviving libdeflate signature vetoes this preference.
    let prefer_miniz_hash = add_policy == DictionaryAddPolicy::AddAll
        && info.max_dist_3_matches > 4096
        && !info.matches_to_start_detected
        && !candidates
            .iter()
            .any(|candidate| candidate.hash_algorithm() == HashAlgorithm::Libdeflate4);
    // A 16-bit bucket is a subset of its 15-bit bucket, so minimum depth alone
    // would favor the legacy hash even when the fastest fingerprint fits.
    candidates
        .iter()
        .find(|candidate| {
            candidate.hash_algorithm() == HashAlgorithm::Libdeflate4Fast15
                || prefer_miniz_hash
                    && candidate.hash_algorithm()
                        == HashAlgorithm::Zlib {
                            hash_mask: 32767,
                            hash_shift: 5,
                        }
        })
        .or_else(|| {
            candidates
                .iter()
                .min_by(|&a, &b| a.max_chain_found().cmp(&b.max_chain_found()))
        })
        .map(|candidate| candidate.as_ref())
}

pub fn estimate_preflate_comp_level(
    wbits: u32,
    mem_level: u32,
    info: &PreflateStreamInfo,
    deflate_contents: &DeflateContents,
    plain_text: &PlainText,
    add_policy: DictionaryAddPolicy,
) -> Result<CompLevelInfo> {
    let hash_bits = mem_level + 7;
    let mem_hash_shift = (hash_bits + 2) / 3;
    let mem_hash_mask = ((1u32 << hash_bits) - 1) as u16;
    let wsize = 1 << wbits;

    let mut candidates: Vec<Box<dyn HashTableDepthEstimator>> = Vec::new();

    if info.min_len == 3 {
        candidates.push(new_depth_estimator(HashAlgorithm::MiniZFast));

        for (hash_shift, hash_mask) in [(5, 32767), (4, 2047), (mem_hash_shift, mem_hash_mask)] {
            candidates.push(new_depth_estimator(HashAlgorithm::Zlib {
                hash_mask,
                hash_shift,
            }));
        }

        // LibFlate4 candidate
        candidates.push(new_depth_estimator(HashAlgorithm::Libdeflate4));

        // RandomVector candidate
        candidates.push(new_depth_estimator(HashAlgorithm::RandomVector));
    } else {
        // Check the two-entry 15-bit buckets while updating the legacy 16-bit candidate.
        if add_policy == DictionaryAddPolicy::AddAll {
            candidates.push(new_depth_estimator(HashAlgorithm::Libdeflate4Fast15));
        } else {
            candidates.push(new_depth_estimator(HashAlgorithm::Libdeflate4Fast));
        }

        // ZlibNG candidate
        candidates.push(new_depth_estimator(HashAlgorithm::ZlibNG));

        // Crc32c candidate
        candidates.push(new_depth_estimator(HashAlgorithm::Crc32cHash));
    }

    run_depth_candidates(add_policy, deflate_contents, plain_text, &mut candidates);

    let Some(candidate) = select_depth_candidate(&candidates, add_policy, info) else {
        return err_exit_code(ExitCode::NoCompressionCandidates, "no candidates found");
    };

    if candidate.max_chain_found() > 4096 {
        return err_exit_code(
            ExitCode::NoCompressionCandidates,
            "no candidate found with reasonable chain length",
        );
    }

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

    if candidate.max_chain_found() >= 4096 {
        return err_exit_code(
            ExitCode::NoCompressionCandidates,
            format!("max_chain_found too large: {}", candidate.max_chain_found()),
        );
    }

    Ok(CompLevelInfo {
        very_far_matches_detected: candidate.very_far_matches_detected(wsize),
        match_type,
        nice_length,
        max_chain,
        hash_algorithm: candidate.hash_algorithm(),
        greedy_parser_detected: candidate.greedy_parser_detected(),
    })
}

// Miniz's shared zlib hash needs guarded preference, not unconditional selection.
// Verify the distance, insertion-policy and start-position guards, plus libdeflate veto.
#[test]
fn miniz_fingerprint_preference_preserves_guards_and_fallback() {
    use super::preflate_stream_info::extract_preflate_info;

    let zlib = HashAlgorithm::Zlib {
        hash_mask: 32767,
        hash_shift: 5,
    };
    let fallback = HashAlgorithm::RandomVector;
    let mut candidates = vec![new_depth_estimator(fallback), new_depth_estimator(zlib)];
    let mut info = extract_preflate_info(&[]);
    for (add_policy, distance, matches_to_start, expected) in [
        (DictionaryAddPolicy::AddAll, 0, false, fallback),
        (DictionaryAddPolicy::AddAll, 4096, false, fallback),
        (DictionaryAddPolicy::AddAll, 4097, false, zlib),
        (DictionaryAddPolicy::AddAll, 4097, true, fallback),
        (DictionaryAddPolicy::AddFirst(4), 4097, false, fallback),
    ] {
        info.max_dist_3_matches = distance;
        info.matches_to_start_detected = matches_to_start;
        assert_eq!(
            select_depth_candidate(&candidates, add_policy, &info)
                .unwrap()
                .hash_algorithm(),
            expected
        );
    }
    candidates.push(new_depth_estimator(HashAlgorithm::Libdeflate4));
    assert_eq!(
        select_depth_candidate(&candidates, DictionaryAddPolicy::AddAll, &info)
            .unwrap()
            .hash_algorithm(),
        fallback
    );
}

// Minimum depth alone can hide a valid 15-bit fastest signature behind the legacy hash.
// Verify explicit preference, legacy-only fallback and the empty-candidate outcome.
#[test]
fn fastest_fingerprint_preference_preserves_legacy_and_empty_cases() {
    use super::preflate_stream_info::extract_preflate_info;

    let info = extract_preflate_info(&[]);
    let mut candidates = vec![new_depth_estimator(HashAlgorithm::Libdeflate4Fast)];
    assert_eq!(
        select_depth_candidate(&candidates, DictionaryAddPolicy::AddAll, &info)
            .unwrap()
            .hash_algorithm(),
        HashAlgorithm::Libdeflate4Fast
    );
    candidates.push(new_depth_estimator(HashAlgorithm::Libdeflate4Fast15));
    assert_eq!(
        select_depth_candidate(&candidates, DictionaryAddPolicy::AddAll, &info)
            .unwrap()
            .hash_algorithm(),
        HashAlgorithm::Libdeflate4Fast15
    );
    assert!(select_depth_candidate(&[], DictionaryAddPolicy::AddAll, &info).is_none());
}
